/**
 * CLI runner for clawproof-wrap.
 *
 * Orchestrates the full adapter lifecycle:
 *   1. Load/generate agent key pair
 *   2. Resolve adapter by harness ID
 *   3. Set proxy env vars
 *   4. Spawn the harness subprocess
 *   5. Parse output for tool events
 *   6. Record events + finalize proof bundle
 *   7. Write proof bundle + URM to output directory
 *
 * Usage:
 *   node cli.js <harness-id> -- <harness-command> [args...]
 *
 * Environment:
 *   CLAWPROOF_PROXY_URL   — clawproxy base URL (required)
 *   CLAWPROOF_PROXY_TOKEN — bearer token for proxy auth (optional)
 *   CLAWPROOF_KEY_FILE    — path to JWK key file (default: <repo>/.clawproof-key.json)
 *   CLAWPROOF_OUTPUT_DIR  — output directory for proof artifacts (default: <repo>/artifacts/poh/<branch>/)
 *
 *   # Optional: offline verification post-run (CPL-US-010)
 *   CLAWPROOF_VERIFY        — set to 1 to verify the generated proof bundle offline
 *   CLAWPROOF_VERIFY_CONFIG — path to clawverify config (default: packages/schema/fixtures/clawverify.config.clawbureau.v1.json if present)
 *   CLAWPROOF_VERIFY_STRICT — set to 1 to fail the wrapper when verification FAILs
 */

import { spawn, execFile } from 'node:child_process';
import { readFile, writeFile, mkdir, chmod, access } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createSession } from './session';
import { startShim } from './shim';
import { parseMarketplaceCstResponse } from './marketplace-cst';
import { getAdapter, listAdapters } from './adapters/index';
import {
  generateKeyPair,
  didFromPublicKey,
  exportKeyPairJWK,
  importKeyPairJWK,
  hashJsonB64u,
} from './crypto';
import { ENV } from './types';
import type { HarnessId, Ed25519KeyPair } from './types';

function isTruthyEnv(value: string | undefined): boolean {
  if (!value) return false;
  const v = value.trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

async function execFileText(
  command: string,
  args: string[],
  cwd: string
): Promise<string | null> {
  return await new Promise((resolve) => {
    execFile(command, args, { cwd }, (err, stdout) => {
      if (err) return resolve(null);
      const out = String(stdout ?? '').trim();
      resolve(out.length > 0 ? out : null);
    });
  });
}

async function detectGitRepoRoot(): Promise<string | null> {
  return execFileText('git', ['rev-parse', '--show-toplevel'], process.cwd());
}

async function detectBranchName(repoRoot: string | null): Promise<string> {
  const envBranch =
    process.env.GITHUB_HEAD_REF ??
    process.env.GITHUB_REF_NAME ??
    process.env.GIT_BRANCH ??
    process.env.BRANCH_NAME;

  const raw =
    (envBranch && envBranch.trim().length > 0 ? envBranch.trim() : null) ??
    (repoRoot
      ? await execFileText('git', ['rev-parse', '--abbrev-ref', 'HEAD'], repoRoot)
      : null);

  if (!raw) return 'unknown';
  return raw === 'HEAD' ? 'detached' : raw;
}

async function fileExists(p: string | undefined): Promise<boolean> {
  if (!p) return false;
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v) => typeof v === 'string' && v.trim().length > 0)
    .map((v) => (v as string).trim());
}

async function loadGatewayReceiptSignerAllowlist(
  configPath: string | undefined
): Promise<{ dids: string[]; error?: string }> {
  if (!configPath) return { dids: [] };

  let raw: string;
  try {
    raw = await readFile(configPath, 'utf8');
  } catch (err) {
    return {
      dids: [],
      error: `Could not read verify config at ${configPath}: ${
        err instanceof Error ? err.message : 'unknown error'
      }`,
    };
  }

  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (err) {
    return {
      dids: [],
      error: `Verify config is not valid JSON: ${
        err instanceof Error ? err.message : 'unknown error'
      }`,
    };
  }

  if (
    typeof json !== 'object' ||
    json === null ||
    (json as Record<string, unknown>).config_version !== '1'
  ) {
    return {
      dids: [],
      error: 'Verify config must be an object with {"config_version":"1", ... }',
    };
  }

  const allowlists =
    typeof (json as Record<string, unknown>).allowlists === 'object' &&
    (json as Record<string, unknown>).allowlists !== null
      ? ((json as Record<string, unknown>).allowlists as Record<string, unknown>)
      : {};

  return {
    dids: normalizeStringArray(allowlists.gateway_receipt_signer_dids),
  };
}

async function importClawverifyCore(repoRoot: string): Promise<any> {
  const distPath = join(repoRoot, 'packages', 'clawverify-core', 'dist', 'index.js');
  if (await fileExists(distPath)) {
    return await import(pathToFileURL(distPath).href);
  }

  const srcPath = join(repoRoot, 'packages', 'clawverify-core', 'src', 'index.ts');
  if (await fileExists(srcPath)) {
    return await import(pathToFileURL(srcPath).href);
  }

  throw new Error(
    'clawverify-core not available. Build it via: cd packages/clawverify-core && npm ci && npm run build'
  );
}

function countReceiptsFromEnvelope(envelope: unknown): number {
  if (typeof envelope !== 'object' || envelope === null) return 0;
  const e = envelope as Record<string, unknown>;
  const payload = e.payload;
  if (typeof payload !== 'object' || payload === null) return 0;
  const p = payload as Record<string, unknown>;
  const receipts = p.receipts;
  return Array.isArray(receipts) ? receipts.length : 0;
}

function toRepoRelativePath(repoRoot: string, p: string | undefined): string | undefined {
  if (!p) return undefined;
  const rel = relative(repoRoot, p);
  if (rel.length > 0 && !rel.startsWith('..')) return rel;
  return p;
}

async function offlineVerifyProofBundle(opts: {
  repoRoot: string;
  envelope: unknown;
  /** Optional materialized URM (required when bundle references a URM). */
  urm?: unknown;
  bundlePath: string;
  configPath?: string;
}): Promise<{ out: unknown; exitCode: number }> {
  const verifiedAt = new Date().toISOString();

  const input = {
    path: toRepoRelativePath(opts.repoRoot, opts.bundlePath) ?? opts.bundlePath,
    config_path: toRepoRelativePath(opts.repoRoot, opts.configPath),
  };

  // Load allowlist (fail-closed if config cannot be read/parsed)
  const allowlist = await loadGatewayReceiptSignerAllowlist(opts.configPath);
  if (allowlist.error) {
    return {
      out: {
        kind: 'proof_bundle',
        status: 'ERROR',
        verified_at: verifiedAt,
        reason_code: 'CONFIG_ERROR',
        reason: allowlist.error,
        input,
      },
      exitCode: 2,
    };
  }

  let core: any;
  try {
    core = await importClawverifyCore(opts.repoRoot);
  } catch (err) {
    return {
      out: {
        kind: 'proof_bundle',
        status: 'ERROR',
        verified_at: verifiedAt,
        reason_code: 'DEPENDENCY_MISSING',
        reason:
          err instanceof Error ? err.message : 'Unable to load clawverify-core',
        input,
      },
      exitCode: 2,
    };
  }

  const verification = await core.verifyProofBundle(opts.envelope, {
    allowlistedReceiptSignerDids: allowlist.dids,
    urm: opts.urm,
  });

  if (verification.result.status !== 'VALID') {
    return {
      out: {
        kind: 'proof_bundle',
        status: 'FAIL',
        verified_at: verifiedAt,
        reason_code: verification.error?.code ?? 'INVALID',
        reason: verification.error?.message ?? verification.result.reason,
        input,
        verification,
      },
      exitCode: 1,
    };
  }

  const receiptsCount = countReceiptsFromEnvelope(opts.envelope);

  // Strict receipt posture for PR evidence packs:
  // - If receipts are present, a signer allowlist MUST be configured.
  // - All receipts must be cryptographically verified AND bound to the event chain.
  if (receiptsCount > 0) {
    if (allowlist.dids.length === 0) {
      return {
        out: {
          kind: 'proof_bundle',
          status: 'FAIL',
          verified_at: verifiedAt,
          reason_code: 'DEPENDENCY_NOT_CONFIGURED',
          reason:
            'Gateway receipt signer allowlist not configured (required to verify receipts)',
          input,
          verification,
        },
        exitCode: 1,
      };
    }

    const cr = verification.result.component_results;
    const verified = cr?.receipts_verified_count ?? 0;
    const sigVerified = cr?.receipts_signature_verified_count ?? 0;

    if (verified !== receiptsCount) {
      const reason_code =
        sigVerified === receiptsCount
          ? 'RECEIPT_BINDING_MISMATCH'
          : 'RECEIPT_VERIFICATION_FAILED';

      return {
        out: {
          kind: 'proof_bundle',
          status: 'FAIL',
          verified_at: verifiedAt,
          reason_code,
          reason:
            reason_code === 'RECEIPT_BINDING_MISMATCH'
              ? 'One or more receipts are not bound to the proof bundle event chain'
              : 'One or more receipts failed cryptographic verification',
          input,
          verification,
        },
        exitCode: 1,
      };
    }
  }

  return {
    out: {
      kind: 'proof_bundle',
      status: 'PASS',
      verified_at: verifiedAt,
      reason_code: 'OK',
      reason: 'Proof bundle verified successfully',
      input,
      verification,
    },
    exitCode: 0,
  };
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

async function loadOrGenerateKeyPair(keyFile: string): Promise<Ed25519KeyPair> {
  try {
    const raw = await readFile(keyFile, 'utf-8');
    const jwk = JSON.parse(raw) as { publicKey: JsonWebKey; privateKey: JsonWebKey };
    return importKeyPairJWK(jwk);
  } catch {
    // Key file doesn't exist — generate a new key pair
    const kp = await generateKeyPair();
    const jwk = await exportKeyPairJWK(kp);
    await writeFile(keyFile, JSON.stringify(jwk, null, 2), {
      encoding: 'utf-8',
      mode: 0o600,
    });

    // Best-effort hardening in case the platform ignores the mode option
    try {
      await chmod(keyFile, 0o600);
    } catch {
      // ignore
    }
    const did = await didFromPublicKey(kp.publicKey);
    process.stderr.write(`clawproof: generated new key pair → ${did}\n`);
    process.stderr.write(`clawproof: saved to ${keyFile}\n`);
    return kp;
  }
}

// ---------------------------------------------------------------------------
// Marketplace CST auto-fetch (POH-US-021/POH-US-022)
// ---------------------------------------------------------------------------


async function fetchJobCstFromBounties(params: {
  baseUrl: string;
  bountyId: string;
  workerToken: string;
}): Promise<string> {
  const baseUrl = params.baseUrl.replace(/\/$/, '');
  const url = `${baseUrl}/v1/bounties/${encodeURIComponent(params.bountyId)}/cst`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${params.workerToken.trim()}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: '{}',
  });

  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!res.ok) {
    throw new Error(`clawbounties /cst failed: HTTP ${res.status}: ${text}`);
  }

  const parsed = parseMarketplaceCstResponse(json);
  return parsed.cst;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

export async function main(argv: string[]): Promise<void> {
  // Parse args: <harness-id> -- <command> [args...]
  const dashDash = argv.indexOf('--');
  if (dashDash === -1 || dashDash === 0) {
    process.stderr.write(
      `Usage: clawproof-wrap <harness-id> -- <command> [args...]\n\n` +
      `Supported harnesses: ${listAdapters().join(', ')}\n\n` +
      `Environment:\n` +
      `  ${ENV.CLAWPROXY_BASE_URL}   — clawproxy base URL (required)\n` +
      `  ${ENV.CLAWPROXY_TOKEN} — CST token for proxy auth (optional)\n` +
      `\n` +
      `  # Optional: marketplace job CST auto-fetch (POH-US-021/POH-US-022)\n` +
      `  ${ENV.CLAWBOUNTIES_BASE_URL} — clawbounties base URL (optional)\n` +
      `  ${ENV.CLAWBOUNTIES_BOUNTY_ID} — bounty id (bty_...)\n` +
      `  ${ENV.CLAWBOUNTIES_WORKER_TOKEN} — worker auth token (Bearer ...)\n` +
      `\n` +
      `  ${ENV.AGENT_KEY_FILE}    — JWK key file (default: <repo>/.clawproof-key.json)\n` +
      `  ${ENV.OUTPUT_DIR}  — output dir (default: <repo>/artifacts/poh/<branch>/)\n` +
      `\n` +
      `  # Optional: offline verification post-run (CPL-US-010)\n` +
      `  ${ENV.VERIFY} — verify the generated proof bundle offline and write *-verify.json\n` +
      `  ${ENV.VERIFY_CONFIG} — clawverify config path (defaults to packages/schema/fixtures/clawverify.config.clawbureau.v1.json if present)\n` +
      `  ${ENV.VERIFY_STRICT} — set to 1 to fail the wrapper when verification FAILs\n`,
    );
    process.exit(1);
    return;
  }

  const harnessId = argv[dashDash - 1] as HarnessId;
  const command = argv.slice(dashDash + 1);

  if (command.length === 0) {
    process.stderr.write('clawproof: no command specified after --\n');
    process.exit(1);
    return;
  }

  // Resolve adapter
  const adapter = getAdapter(harnessId);
  if (!adapter) {
    process.stderr.write(
      `clawproof: unknown harness "${harnessId}"\n` +
      `Supported: ${listAdapters().join(', ')}\n`,
    );
    process.exit(1);
    return;
  }

  // Read env vars
  const proxyUrl = process.env[ENV.CLAWPROXY_BASE_URL];
  if (!proxyUrl) {
    process.stderr.write(`clawproof: ${ENV.CLAWPROXY_BASE_URL} is required\n`);
    process.exit(1);
    return;
  }

  let proxyToken = process.env[ENV.CLAWPROXY_TOKEN];

  const bountiesBaseUrl = process.env[ENV.CLAWBOUNTIES_BASE_URL];
  const bountiesBountyId = process.env[ENV.CLAWBOUNTIES_BOUNTY_ID];
  const bountiesWorkerToken = process.env[ENV.CLAWBOUNTIES_WORKER_TOKEN];

  // POH-US-021: If no proxy token was provided, optionally fetch a job-scoped CST from clawbounties.
  if (!proxyToken && (bountiesBaseUrl || bountiesBountyId || bountiesWorkerToken)) {
    if (!bountiesBaseUrl || !bountiesBountyId || !bountiesWorkerToken) {
      process.stderr.write(
        `clawproof: marketplace CST auto-fetch requested but missing env vars. Need ${ENV.CLAWBOUNTIES_BASE_URL}, ${ENV.CLAWBOUNTIES_BOUNTY_ID}, ${ENV.CLAWBOUNTIES_WORKER_TOKEN}.\n`,
      );
      process.exit(1);
      return;
    }

    process.stderr.write(
      `clawproof: fetching job CST from clawbounties (${bountiesBaseUrl}, bounty=${bountiesBountyId})\n`,
    );

    try {
      proxyToken = await fetchJobCstFromBounties({
        baseUrl: bountiesBaseUrl,
        bountyId: bountiesBountyId,
        workerToken: bountiesWorkerToken,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      process.stderr.write(`clawproof: failed to fetch job CST: ${message}\n`);
      process.exit(1);
      return;
    }
  }

  const repoRoot = await detectGitRepoRoot();
  const branch = await detectBranchName(repoRoot);

  const keyFileDefault = repoRoot
    ? join(repoRoot, '.clawproof-key.json')
    : '.clawproof-key.json';

  const outputDirDefault = repoRoot
    ? join(repoRoot, 'artifacts', 'poh', branch)
    : '.clawproof';

  const keyFile = process.env[ENV.AGENT_KEY_FILE] ?? keyFileDefault;
  const outputDir = process.env[ENV.OUTPUT_DIR] ?? outputDirDefault;

  const verifyEnabled = isTruthyEnv(process.env[ENV.VERIFY]);
  const verifyStrict = isTruthyEnv(process.env[ENV.VERIFY_STRICT]);

  const defaultVerifyConfigPath = repoRoot
    ? join(
        repoRoot,
        'packages',
        'schema',
        'fixtures',
        'clawverify.config.clawbureau.v1.json'
      )
    : undefined;

  const verifyConfigPath =
    process.env[ENV.VERIFY_CONFIG] ??
    ((await fileExists(defaultVerifyConfigPath))
      ? defaultVerifyConfigPath
      : undefined);

  // Load or generate key pair
  const keyPair = await loadOrGenerateKeyPair(keyFile);
  const agentDid = await didFromPublicKey(keyPair.publicKey);

  // Create session
  const session = await createSession({
    proxyBaseUrl: proxyUrl,
    proxyToken,
    keyPair,
    agentDid,
    harness: adapter.HARNESS,
    outputDir,
  });

  process.stderr.write(`clawproof: session started (run=${session.runId}, did=${agentDid})\n`);
  process.stderr.write(`clawproof: harness=${adapter.HARNESS.id} v${adapter.HARNESS.version}\n`);

  // Record run_start event
  await session.recordEvent({
    eventType: 'run_start',
    payload: {
      harness: adapter.HARNESS,
      command: command.join(' '),
      timestamp: new Date().toISOString(),
    },
  });

  // Start a local shim server for provider-compatible base URL overrides.
  // The shim forwards requests to clawproxy via session.proxyLLMCall(), which:
  //   - records llm_call events into the event chain
  //   - injects PoH binding headers
  //   - extracts and stores canonical gateway receipt envelopes
  const shim = await startShim({
    session,
    log: (msg) => process.stderr.write(`clawproof: ${msg}\n`),
  });

  let exitCode: number;
  try {
    // Compute proxy env vars (point the harness at the local shim)
    const proxyEnv = adapter.getProxyEnv(shim.baseUrl, proxyToken);

    // Spawn the harness subprocess with shim env vars injected
    const childEnv = { ...process.env, ...proxyEnv };

    exitCode = await new Promise<number>((resolve) => {
      let stdout = '';
      const child = spawn(command[0], command.slice(1), {
        env: childEnv,
        stdio: ['inherit', 'pipe', 'inherit'],
      });

      child.stdout.on('data', (data: Buffer) => {
        const chunk = data.toString();
        stdout += chunk;
        process.stdout.write(chunk);
      });

      child.on('close', async (code: number | null) => {
        // Parse tool events from output
        const toolEvents = adapter.parseToolEvents(stdout);
        for (const te of toolEvents) {
          await session.recordEvent({
            eventType: 'tool_call',
            payload: te,
          });
        }

        resolve(code ?? 1);
      });

      child.on('error', (err: Error) => {
        process.stderr.write(`clawproof: failed to spawn "${command[0]}": ${err.message}\n`);
        resolve(127);
      });
    });
  } finally {
    try {
      await shim.close();
    } catch {
      // ignore
    }
  }

  // Record run_end event
  await session.recordEvent({
    eventType: 'run_end',
    payload: {
      exitCode,
      timestamp: new Date().toISOString(),
    },
  });

  // Hash the command string as a minimal input descriptor
  const commandHash = await hashJsonB64u(command.join(' '));

  // Finalize and produce proof bundle
  const result = await session.finalize({
    inputs: [
      {
        type: 'command',
        hashB64u: commandHash,
        metadata: { command: command.join(' ') },
      },
    ],
    outputs: [
      {
        type: 'exit_code',
        hashB64u: await hashJsonB64u(exitCode),
        metadata: { exitCode },
      },
    ],
  });

  // Write artifacts to output directory
  await mkdir(outputDir, { recursive: true });

  const bundlePath = join(outputDir, `${session.runId}-bundle.json`);
  const urmPath = join(outputDir, `${session.runId}-urm.json`);
  const trustPulsePath = join(outputDir, `${session.runId}-trust-pulse.json`);

  await writeFile(bundlePath, JSON.stringify(result.envelope, null, 2), 'utf-8');
  await writeFile(urmPath, JSON.stringify(result.urm, null, 2), 'utf-8');

  // Write the trust pulse in a canonical JSON form (no whitespace) so the hash is stable.
  await writeFile(trustPulsePath, JSON.stringify(result.trustPulse), 'utf-8');

  process.stderr.write(`\nclawproof: proof bundle → ${bundlePath}\n`);
  process.stderr.write(`clawproof: URM          → ${urmPath}\n`);
  process.stderr.write(`clawproof: trust pulse  → ${trustPulsePath}\n`);

  let finalExitCode = exitCode;

  if (verifyEnabled) {
    const verifyPath = join(outputDir, `${session.runId}-verify.json`);
    const verifierRoot = repoRoot ?? process.cwd();

    const { out, exitCode: verifyExitCode } = await offlineVerifyProofBundle({
      repoRoot: verifierRoot,
      envelope: result.envelope,
      urm: result.urm,
      bundlePath,
      configPath: verifyConfigPath,
    });

    // Canonical JSON (no whitespace) so hashes are stable.
    await writeFile(verifyPath, `${JSON.stringify(out)}\n`, 'utf-8');

    const status = (out as any)?.status;
    const reasonCode = (out as any)?.reason_code;

    process.stderr.write(`clawproof: verify       → ${verifyPath}\n`);
    process.stderr.write(
      `clawproof: verify status=${status} reason_code=${reasonCode}\n`,
    );

    if (verifyStrict && finalExitCode === 0 && verifyExitCode !== 0) {
      finalExitCode = verifyExitCode;
    }
  }

  process.stderr.write(
    `clawproof: run=${session.runId} events=${result.envelope.payload.event_chain?.length ?? 0} receipts=${result.envelope.payload.receipts?.length ?? 0}\n`,
  );

  process.exit(finalExitCode);
}

// Direct invocation
const args = process.argv.slice(2);
if (args.length > 0) {
  main(args).catch((err) => {
    process.stderr.write(`clawproof: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
    return;
  });
}
