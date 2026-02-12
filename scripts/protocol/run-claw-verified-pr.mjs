#!/usr/bin/env node
/**
 * Claw Verified PR check (offline, fail-closed when required).
 *
 * Verifies:
 * - PoH proof bundles under artifacts/poh/**-bundle.json using the offline verifier CLI
 * - DID commit proofs under proofs/<branch>/commit.sig.json (did-work Protocol M message signature)
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { execFile, execFileSync } from 'node:child_process';

const ROOT = path.resolve(new URL('../..', import.meta.url).pathname);

function isoStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** RFC 8785 JSON Canonicalization Scheme (JCS) */
function jcsCanonicalize(value) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('Non-finite number not allowed in JCS');
      }
      return JSON.stringify(value);

    case 'string':
      return JSON.stringify(value);

    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map(jcsCanonicalize).join(',')}]`;
      }

      const obj = value;
      const keys = Object.keys(obj).sort();
      const parts = [];

      for (const k of keys) {
        parts.push(`${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`);
      }

      return `{${parts.join(',')}}`;
    }

    default:
      throw new Error(`Unsupported value type for JCS: ${typeof value}`);
  }
}

async function readJson(p) {
  const raw = await fs.readFile(p, 'utf8');
  return JSON.parse(raw);
}

async function fileExists(p) {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

function execFileText(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(
      cmd,
      args,
      { ...opts, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const exitCode =
          err && typeof err.code === 'number' ? err.code : err ? 1 : 0;

        resolve({
          ok: exitCode === 0,
          exitCode,
          stdout: String(stdout ?? ''),
          stderr: String(stderr ?? ''),
          err,
        });
      }
    );
  });
}

function parseLabelsFromEvent(event) {
  const labels = event?.pull_request?.labels;
  if (!Array.isArray(labels)) return [];
  return labels
    .map((l) => (isRecord(l) ? String(l.name ?? '') : ''))
    .filter((s) => s.length > 0);
}

function getBaseHeadShas(event) {
  const base = event?.pull_request?.base?.sha;
  const head = event?.pull_request?.head?.sha;
  return {
    baseSha: typeof base === 'string' && base.length > 0 ? base : null,
    headSha: typeof head === 'string' && head.length > 0 ? head : null,
  };
}

async function changedFilesFromGit(baseSha, headSha) {
  if (!baseSha || !headSha) {
    // Fallback for non-PR runs
    const out = await execFileText('git', ['diff', '--name-only', 'HEAD~1..HEAD'], { cwd: ROOT });
    if (!out.ok) return [];
    return out.stdout
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  const out = await execFileText('git', ['diff', '--name-only', `${baseSha}...${headSha}`], { cwd: ROOT });
  if (!out.ok) {
    // Try fetching base (in case checkout depth is shallow)
    await execFileText('git', ['fetch', '--no-tags', '--depth', '200', 'origin', baseSha], { cwd: ROOT });
    const out2 = await execFileText('git', ['diff', '--name-only', `${baseSha}...${headSha}`], { cwd: ROOT });
    if (!out2.ok) return [];
    return out2.stdout
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
  }

  return out.stdout
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function pickEvidenceFiles(changed) {
  const bundles = [];
  const commitSigs = [];

  for (const f of changed) {
    if (f.startsWith('artifacts/poh/') && f.endsWith('-bundle.json')) {
      bundles.push(f);
    }
    if (f.startsWith('proofs/') && f.endsWith('/commit.sig.json')) {
      commitSigs.push(f);
    }
  }

  return {
    bundlePaths: bundles.sort(),
    commitSigPaths: commitSigs.sort(),
  };
}

function toArrayBuffer(bytes) {
  const buf = bytes.buffer;
  if (buf instanceof ArrayBuffer) {
    return buf.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(str) {
  const bytes = [0];

  for (const char of str) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

    for (let i = 0; i < bytes.length; i++) {
      bytes[i] *= 58;
    }
    bytes[0] += value;

    let carry = 0;
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] += carry;
      carry = bytes[i] >> 8;
      bytes[i] &= 0xff;
    }

    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  for (const char of str) {
    if (char !== '1') break;
    bytes.push(0);
  }

  return new Uint8Array(bytes.reverse());
}

function extractEd25519PublicKeyFromDidKey(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) return null;
  try {
    const multibase = did.slice(9);
    const decoded = base58Decode(multibase);

    // 0xed01 multicodec prefix
    if (decoded[0] === 0xed && decoded[1] === 0x01) {
      return decoded.slice(2);
    }

    return null;
  } catch {
    return null;
  }
}

function extractCommitShaFromMessage(message) {
  const m = String(message ?? '').match(/^commit:([a-f0-9]{7,64})$/i);
  return m ? m[1] : null;
}

async function verifyCommitSigFile(relPath) {
  const full = path.join(ROOT, relPath);

  let json;
  try {
    json = await readJson(full);
  } catch (err) {
    return {
      path: relPath,
      ok: false,
      reason_code: 'INVALID_JSON',
      reason: err instanceof Error ? err.message : 'Invalid JSON',
    };
  }

  if (!isRecord(json)) {
    return {
      path: relPath,
      ok: false,
      reason_code: 'MALFORMED_ENVELOPE',
      reason: 'commit.sig.json must be an object',
    };
  }

  const version = json.version;
  const type = json.type;
  const algo = json.algo;
  const did = json.did;
  const message = json.message;
  const signature = json.signature;

  if (version !== 'm1') {
    return {
      path: relPath,
      ok: false,
      reason_code: 'UNKNOWN_VERSION',
      reason: `Unsupported commit signature version: ${String(version)}`,
    };
  }

  if (type !== 'message_signature') {
    return {
      path: relPath,
      ok: false,
      reason_code: 'UNKNOWN_TYPE',
      reason: `Unsupported commit signature type: ${String(type)}`,
    };
  }

  if (algo !== 'ed25519') {
    return {
      path: relPath,
      ok: false,
      reason_code: 'UNKNOWN_ALGO',
      reason: `Unsupported commit signature algo: ${String(algo)}`,
    };
  }

  const commitSha = extractCommitShaFromMessage(message);
  if (!commitSha) {
    return {
      path: relPath,
      ok: false,
      reason_code: 'COMMIT_MESSAGE_INVALID',
      reason: 'Invalid commit signature message format (expected "commit:<sha>")',
      signer_did: typeof did === 'string' ? did : undefined,
      message: typeof message === 'string' ? message : undefined,
    };
  }

  const publicKeyBytes = extractEd25519PublicKeyFromDidKey(did);
  if (!publicKeyBytes) {
    return {
      path: relPath,
      ok: false,
      reason_code: 'INVALID_DID_FORMAT',
      reason: 'Unsupported DID format (expected did:key with Ed25519 multicodec)',
      commit_sha: commitSha,
      signer_did: typeof did === 'string' ? did : undefined,
      message: typeof message === 'string' ? message : undefined,
    };
  }

  if (typeof signature !== 'string' || signature.length === 0) {
    return {
      path: relPath,
      ok: false,
      reason_code: 'MALFORMED_ENVELOPE',
      reason: 'Missing signature field',
      commit_sha: commitSha,
      signer_did: did,
    };
  }

  let sigBytes;
  try {
    sigBytes = new Uint8Array(Buffer.from(signature, 'base64'));
  } catch {
    sigBytes = null;
  }

  if (!sigBytes || sigBytes.length !== 64) {
    return {
      path: relPath,
      ok: false,
      reason_code: 'MALFORMED_ENVELOPE',
      reason: 'Invalid signature encoding (expected base64 Ed25519 signature)',
      commit_sha: commitSha,
      signer_did: did,
    };
  }

  // Optional repo binding: ensure commit exists in this checkout.
  let commitExists = true;
  try {
    execFileSync('git', ['cat-file', '-e', `${commitSha}^{commit}`], {
      cwd: ROOT,
      stdio: 'ignore',
    });
  } catch {
    commitExists = false;
  }

  if (!commitExists) {
    return {
      path: relPath,
      ok: false,
      reason_code: 'COMMIT_NOT_FOUND',
      reason: `Signed commit not found in this checkout: ${commitSha}`,
      commit_sha: commitSha,
      signer_did: did,
    };
  }

  let canonical;
  try {
    // did-work Protocol M signs the canonicalized envelope, with signature field set to "".
    const forSigning = { ...json, signature: '' };
    canonical = jcsCanonicalize(forSigning);
  } catch (err) {
    return {
      path: relPath,
      ok: false,
      reason_code: 'CANONICALIZATION_ERROR',
      reason: err instanceof Error ? err.message : 'Unable to canonicalize envelope',
      commit_sha: commitSha,
      signer_did: did,
    };
  }

  const msgBytes = new TextEncoder().encode(canonical);

  try {
    const publicKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(publicKeyBytes),
      { name: 'Ed25519' },
      false,
      ['verify']
    );

    const ok = await crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      toArrayBuffer(sigBytes),
      toArrayBuffer(msgBytes)
    );

    return {
      path: relPath,
      ok,
      reason_code: ok ? 'OK' : 'SIGNATURE_INVALID',
      reason: ok ? 'Commit signature verified' : 'Signature verification failed',
      commit_sha: commitSha,
      signer_did: did,
      message: String(message),
    };
  } catch (err) {
    return {
      path: relPath,
      ok: false,
      reason_code: 'CRYPTO_ERROR',
      reason: err instanceof Error ? err.message : 'Crypto verification error',
      commit_sha: commitSha,
      signer_did: did,
    };
  }
}

async function verifyBundleWithCli(relPath, cliPath, configPath) {
  const full = path.join(ROOT, relPath);

  const args = [
    cliPath,
    'verify',
    'proof-bundle',
    '--input',
    full,
    '--config',
    configPath,
  ];

  const run = await execFileText(process.execPath, args, { cwd: ROOT });

  let parsed = null;
  let parseError = null;
  try {
    parsed = JSON.parse(run.stdout);
  } catch (err) {
    parseError = err instanceof Error ? err.message : String(err);
  }

  const status = parsed?.status;
  const reasonCode = parsed?.reason_code;
  const reason = parsed?.reason;

  const ok = parseError === null && run.exitCode === 0 && status === 'PASS';

  return {
    path: relPath,
    ok,
    exit_code: run.exitCode,
    status: typeof status === 'string' ? status : 'ERROR',
    reason_code:
      parseError !== null
        ? 'PARSE_ERROR'
        : typeof reasonCode === 'string'
          ? reasonCode
          : 'PARSE_ERROR',
    reason:
      typeof reason === 'string' ? reason : parseError ?? 'cli parse error',
    stderr: run.stderr ? run.stderr.slice(0, 2000) : undefined,
  };
}

async function verifyCommitSigWithCli(relPath, cliPath) {
  const full = path.join(ROOT, relPath);

  const args = [cliPath, 'verify', 'commit-sig', '--input', full];
  const run = await execFileText(process.execPath, args, { cwd: ROOT });

  let parsed = null;
  let parseError = null;
  try { parsed = JSON.parse(run.stdout); } catch (err) {
    parseError = err instanceof Error ? err.message : String(err);
  }

  const status = parsed?.status;
  const reasonCode = parsed?.reason_code;
  const reason = parsed?.reason;
  const commitSha = parsed?.verification?.commit_sha;
  const signerDid = parsed?.verification?.signer_did;
  const message = parsed?.verification?.message;

  const ok = parseError === null && run.exitCode === 0 && status === 'PASS';

  // Also check commit exists in this checkout
  let commitExists = true;
  if (commitSha) {
    try {
      execFileSync('git', ['cat-file', '-e', `${commitSha}^{commit}`], { cwd: ROOT, stdio: 'ignore' });
    } catch { commitExists = false; }
  }

  if (ok && !commitExists) {
    return {
      path: relPath, ok: false,
      reason_code: 'COMMIT_NOT_FOUND',
      reason: `Signed commit not found in this checkout: ${commitSha}`,
      commit_sha: commitSha, signer_did: signerDid, message,
    };
  }

  return {
    path: relPath, ok,
    reason_code: parseError ? 'PARSE_ERROR' : (typeof reasonCode === 'string' ? reasonCode : 'PARSE_ERROR'),
    reason: typeof reason === 'string' ? reason : (parseError ?? 'cli parse error'),
    commit_sha: commitSha, signer_did: signerDid, message,
    stderr: run.stderr ? run.stderr.slice(0, 2000) : undefined,
  };
}

function mdRow(cols) {
  return `| ${cols.map((c) => String(c).replace(/\|/g, '\\|')).join(' | ')} |`;
}

async function writeStepSummary(markdown) {
  const p = process.env.GITHUB_STEP_SUMMARY;
  if (!p) return;
  await fs.appendFile(p, `${markdown}\n`, 'utf8');
}

async function main() {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  const event = eventPath ? await readJson(eventPath) : {};

  const labels = parseLabelsFromEvent(event);
  const labelEnforce = labels.includes('claw-verified');

  const { baseSha, headSha } = getBaseHeadShas(event);
  const changed = await changedFilesFromGit(baseSha, headSha);

  const { bundlePaths, commitSigPaths } = pickEvidenceFiles(changed);

  const enforce = labelEnforce || commitSigPaths.length > 0;

  const cliPath = path.join(ROOT, 'packages/clawverify-cli/dist/cli.js');
  const configPath = path.join(
    ROOT,
    'packages/schema/fixtures/clawverify.config.clawbureau.v1.json'
  );

  const cliExists = await fileExists(cliPath);
  const configExists = await fileExists(configPath);

  const bundleResults = [];
  const commitSigResults = [];

  if (bundlePaths.length > 0) {
    if (!cliExists) {
      for (const b of bundlePaths) {
        bundleResults.push({
          path: b,
          ok: false,
          status: 'ERROR',
          reason_code: 'DEPENDENCY_MISSING',
          reason: 'packages/clawverify-cli/dist/cli.js not found (build step missing)',
        });
      }
    } else if (!configExists) {
      for (const b of bundlePaths) {
        bundleResults.push({
          path: b,
          ok: false,
          status: 'ERROR',
          reason_code: 'CONFIG_ERROR',
          reason:
            'packages/schema/fixtures/clawverify.config.clawbureau.v1.json not found',
        });
      }
    } else {
      for (const b of bundlePaths) {
        bundleResults.push(await verifyBundleWithCli(b, cliPath, configPath));
      }
    }
  }

  for (const p of commitSigPaths) {
    if (cliExists) {
      commitSigResults.push(await verifyCommitSigWithCli(p, cliPath));
    } else {
      // Fallback to inline verification when CLI is unavailable
      commitSigResults.push(await verifyCommitSigFile(p));
    }
  }

  const missingEvidence = {
    bundles_required_missing: enforce && bundlePaths.length === 0,
    commit_sigs_required_missing: enforce && commitSigPaths.length === 0,
  };

  const bundlesOk = bundleResults.every((r) => r.ok);
  const commitSigsOk = commitSigResults.every((r) => r.ok);

  const wouldFail =
    missingEvidence.bundles_required_missing ||
    missingEvidence.commit_sigs_required_missing ||
    !bundlesOk ||
    !commitSigsOk;

  const ok = enforce ? !wouldFail : true;

  const summary = {
    mode: {
      enforce,
      reason: labelEnforce
        ? 'label:claw-verified'
        : commitSigPaths.length > 0
          ? 'proofs/**/commit.sig.json present'
          : 'observe',
      labels,
    },
    inputs: {
      changed_files: changed,
      bundles: bundlePaths,
      commit_sigs: commitSigPaths,
      config_path: 'packages/schema/fixtures/clawverify.config.clawbureau.v1.json',
      cli_path: 'packages/clawverify-cli/dist/cli.js',
    },
    results: {
      ok,
      would_fail: wouldFail,
      missing_evidence: missingEvidence,
      bundles_ok: bundlesOk,
      commit_sigs_ok: commitSigsOk,
    },
    bundles: bundleResults,
    commit_sigs: commitSigResults,
    finished_at: new Date().toISOString(),
  };

  const outDir = path.join(ROOT, 'artifacts/ops/claw-verified-pr', isoStamp());
  await fs.mkdir(outDir, { recursive: true });
  const outPath = path.join(outDir, 'summary.json');
  await fs.writeFile(outPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');

  // GitHub job summary
  const md = [];
  md.push(`# Claw Verified PR`);
  md.push('');
  md.push(`- Mode: **${enforce ? 'ENFORCE' : 'OBSERVE'}** (${summary.mode.reason})`);
  md.push(`- Config: \`${summary.inputs.config_path}\``);
  md.push(`- CLI: \`${summary.inputs.cli_path}\``);
  md.push(`- Summary artifact: \`${path.relative(ROOT, outPath)}\``);
  md.push('');

  if (missingEvidence.bundles_required_missing) {
    md.push(`- ❌ Missing required PoH bundles under \`artifacts/poh/**-bundle.json\``);
  }
  if (missingEvidence.commit_sigs_required_missing) {
    md.push(`- ❌ Missing required DID commit proofs under \`proofs/**/commit.sig.json\``);
  }

  md.push('');
  md.push('## Proof bundles');
  md.push('');
  md.push(mdRow(['path', 'ok', 'status', 'reason_code']));
  md.push(mdRow(['---', '---', '---', '---']));
  if (bundleResults.length === 0) {
    md.push(mdRow(['(none)', '-', '-', '-']));
  } else {
    for (const r of bundleResults) {
      md.push(mdRow([r.path, r.ok ? 'PASS' : 'FAIL', r.status, r.reason_code]));
    }
  }

  md.push('');
  md.push('## DID commit proofs');
  md.push('');
  md.push(mdRow(['path', 'ok', 'commit_sha', 'signer_did', 'reason_code']));
  md.push(mdRow(['---', '---', '---', '---', '---']));
  if (commitSigResults.length === 0) {
    md.push(mdRow(['(none)', '-', '-', '-', '-']));
  } else {
    for (const r of commitSigResults) {
      md.push(
        mdRow([
          r.path,
          r.ok ? 'PASS' : 'FAIL',
          r.commit_sha ?? '-',
          r.signer_did ?? '-',
          r.reason_code,
        ])
      );
    }
  }

  md.push('');
  md.push(`Result: **${ok ? 'OK' : 'FAIL'}**`);

  await writeStepSummary(md.join('\n'));

  process.stdout.write(`${JSON.stringify({ ok, outPath: path.relative(ROOT, outPath) }, null, 2)}\n`);

  if (!ok) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exitCode = 1;
});
