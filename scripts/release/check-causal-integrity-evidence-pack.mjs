#!/usr/bin/env node
/**
 * Guardrail: validate causal-integrity burn-in evidence contract.
 *
 * Contract:
 * - summary exists (explicit --summary or latest under artifacts/ops/causal-integrity-burnin)
 * - summary freshness <= max-age-minutes
 * - summary.ok === true
 * - required mode + mutation_subset match requested values
 * - required burn-in steps are present and PASS (ok=true, exit_code=0)
 * - summary signature exists and verifies (offline) unless --require-signed=false
 * - signed summary hash + message binding must match summary bytes
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');

const MESSAGE_PREFIX = 'causal-integrity-evidence';

const REQUIRED_STEP_IDS = [
  'reason-code-parity',
  'causal-cldd-conformance',
  'causal-hardening-conformance',
  'causal-connectivity-conformance',
  'causal-clock-conformance',
  'aggregate-causal-conformance',
  'causal-mutation-guardrail',
];

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function parseArgs(argv) {
  const getValue = (flag) => {
    const idx = argv.indexOf(flag);
    return idx >= 0 ? argv[idx + 1] : undefined;
  };

  const getValueEq = (flag) => {
    const hit = argv.find((arg) => arg.startsWith(`${flag}=`));
    return hit ? hit.slice(flag.length + 1) : undefined;
  };

  const parseBoolean = (value, defaultValue) => {
    if (value === undefined) return defaultValue;
    const v = String(value).trim().toLowerCase();
    if (v === 'true' || v === '1' || v === 'yes') return true;
    if (v === 'false' || v === '0' || v === 'no') return false;
    return defaultValue;
  };

  const summary = getValue('--summary') ?? getValueEq('--summary');
  const signature = getValue('--signature') ?? getValueEq('--signature');
  const maxAgeRaw =
    getValue('--max-age-minutes') ?? getValueEq('--max-age-minutes');
  const requireMode =
    getValue('--require-mode') ?? getValueEq('--require-mode') ?? 'quick';
  const requireMutationSubset =
    getValue('--require-mutation-subset') ??
    getValueEq('--require-mutation-subset') ??
    'quick';

  const requireSigned = parseBoolean(
    getValue('--require-signed') ?? getValueEq('--require-signed'),
    true
  );

  const maxAgeMinutes =
    maxAgeRaw !== undefined && Number.isFinite(Number(maxAgeRaw))
      ? Number(maxAgeRaw)
      : 180;

  return {
    summary,
    signature,
    maxAgeMinutes,
    requireMode,
    requireMutationSubset,
    requireSigned,
  };
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.resolve(ROOT, relativePath), 'utf8'));
}

function findLatestSummaryPath() {
  const root = path.resolve(ROOT, 'artifacts/ops/causal-integrity-burnin');
  if (!fs.existsSync(root)) {
    return null;
  }

  const dirs = fs
    .readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  const latest = dirs.at(-1);
  if (!latest) return null;

  const summaryPath = path.join(
    'artifacts/ops/causal-integrity-burnin',
    latest,
    'summary.json'
  );

  return fs.existsSync(path.resolve(ROOT, summaryPath)) ? summaryPath : null;
}

function defaultSignaturePath(summaryPath) {
  if (summaryPath.endsWith('.json')) {
    return summaryPath.slice(0, -'.json'.length) + '.sig.json';
  }
  return `${summaryPath}.sig.json`;
}

function base64UrlEncode(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function toArrayBuffer(view) {
  if (view instanceof Uint8Array) {
    return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
  }
  if (view instanceof ArrayBuffer) {
    return view;
  }
  throw new TypeError('Expected Uint8Array or ArrayBuffer');
}

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
      const keys = Object.keys(value).sort();
      return `{${keys
        .map((k) => `${JSON.stringify(k)}:${jcsCanonicalize(value[k])}`)
        .join(',')}}`;
    }
    default:
      throw new Error(`Unsupported value type for JCS: ${typeof value}`);
  }
}

function base58Decode(str) {
  if (typeof str !== 'string' || str.length === 0) {
    return new Uint8Array();
  }

  const bytes = [0];

  for (const char of str) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value < 0) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

    let carry = value;
    for (let i = 0; i < bytes.length; i += 1) {
      const x = bytes[i] * 58 + carry;
      bytes[i] = x & 0xff;
      carry = x >> 8;
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
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    return null;
  }

  try {
    const decoded = base58Decode(did.slice('did:key:z'.length));
    if (decoded.length !== 34) return null;
    if (decoded[0] !== 0xed || decoded[1] !== 0x01) return null;
    return decoded.slice(2);
  } catch {
    return null;
  }
}

async function sha256FileB64u(relativePath) {
  const bytes = fs.readFileSync(path.resolve(ROOT, relativePath));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

async function verifyMessageSignatureEnvelope(envelope) {
  const failures = [];

  if (!envelope || typeof envelope !== 'object') {
    failures.push('message_signature must be an object');
    return { ok: false, failures };
  }

  const version = envelope.version;
  const type = envelope.type;
  const algo = envelope.algo;
  const did = envelope.did;
  const signature = envelope.signature;

  if (version !== 'm1') failures.push(`message_signature.version must be m1 (got ${String(version)})`);
  if (type !== 'message_signature') failures.push(`message_signature.type must be message_signature (got ${String(type)})`);
  if (algo !== 'ed25519') failures.push(`message_signature.algo must be ed25519 (got ${String(algo)})`);

  const publicKeyBytes = extractEd25519PublicKeyFromDidKey(did);
  if (!publicKeyBytes) {
    failures.push('message_signature.did must be did:key with Ed25519 multicodec prefix');
  }

  let signatureBytes = null;
  if (typeof signature !== 'string' || signature.length === 0) {
    failures.push('message_signature.signature must be a non-empty base64 string');
  } else {
    try {
      signatureBytes = new Uint8Array(Buffer.from(signature, 'base64'));
      if (signatureBytes.length !== 64) {
        failures.push('message_signature.signature must decode to 64-byte Ed25519 signature');
      }
    } catch {
      failures.push('message_signature.signature must be valid base64');
    }
  }

  if (failures.length > 0) {
    return { ok: false, failures };
  }

  let canonical;
  try {
    const forSigning = { ...envelope, signature: '' };
    canonical = jcsCanonicalize(forSigning);
  } catch (error) {
    return {
      ok: false,
      failures: [
        `failed to canonicalize message signature envelope: ${
          error instanceof Error ? error.message : String(error)
        }`,
      ],
    };
  }

  try {
    const publicKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(publicKeyBytes),
      { name: 'Ed25519' },
      false,
      ['verify']
    );

    const verified = await crypto.subtle.verify(
      { name: 'Ed25519' },
      publicKey,
      toArrayBuffer(signatureBytes),
      toArrayBuffer(new TextEncoder().encode(canonical))
    );

    if (!verified) {
      return {
        ok: false,
        failures: ['message signature verification failed'],
      };
    }

    return {
      ok: true,
      signer_did: did,
    };
  } catch (error) {
    return {
      ok: false,
      failures: [
        `crypto verification error: ${
          error instanceof Error ? error.message : String(error)
        }`,
      ],
    };
  }
}

async function validateSignatureContract(summaryPath, signaturePath, requireSigned) {
  const issues = [];
  const fullSignaturePath = path.resolve(ROOT, signaturePath);
  const signatureExists = fs.existsSync(fullSignaturePath);

  if (!signatureExists) {
    if (requireSigned) {
      issues.push(
        `missing signature file: ${signaturePath} (run scripts/release/sign-causal-integrity-evidence-pack.mjs)`
      );
    }

    return {
      ok: issues.length === 0,
      issues,
      signature_path: signaturePath,
      signature_present: false,
    };
  }

  let sigDoc;
  try {
    sigDoc = readJson(signaturePath);
  } catch (error) {
    issues.push(
      `signature file is not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`
    );

    return {
      ok: false,
      issues,
      signature_path: signaturePath,
      signature_present: true,
    };
  }

  if (sigDoc.evidence_signature_version !== '1') {
    issues.push(
      `evidence_signature_version must be "1" (got ${String(
        sigDoc.evidence_signature_version
      )})`
    );
  }

  const summaryPathNormalized = path.normalize(summaryPath);
  const signedSummaryPath =
    typeof sigDoc.summary_path === 'string' ? path.normalize(sigDoc.summary_path) : null;

  if (!signedSummaryPath || signedSummaryPath !== summaryPathNormalized) {
    issues.push(
      `signature summary_path mismatch (expected ${summaryPathNormalized}, got ${String(
        sigDoc.summary_path
      )})`
    );
  }

  const expectedSummaryHash = await sha256FileB64u(summaryPath);
  if (sigDoc.summary_sha256_b64u !== expectedSummaryHash) {
    issues.push(
      `summary_sha256_b64u mismatch (expected ${expectedSummaryHash}, got ${String(
        sigDoc.summary_sha256_b64u
      )})`
    );
  }

  const messagePrefix =
    typeof sigDoc.message_prefix === 'string' && sigDoc.message_prefix.length > 0
      ? sigDoc.message_prefix
      : MESSAGE_PREFIX;

  const expectedMessage = `${messagePrefix}:${expectedSummaryHash}`;
  const actualMessage = sigDoc?.message_signature?.message;
  if (actualMessage !== expectedMessage) {
    issues.push(
      `message signature binding mismatch (expected ${expectedMessage}, got ${String(actualMessage)})`
    );
  }

  const signatureVerification = await verifyMessageSignatureEnvelope(
    sigDoc.message_signature
  );

  if (!signatureVerification.ok) {
    for (const failure of signatureVerification.failures) {
      issues.push(failure);
    }
  }

  return {
    ok: issues.length === 0,
    issues,
    signature_path: signaturePath,
    signature_present: true,
    signing_mode:
      typeof sigDoc.signing_mode === 'string' ? sigDoc.signing_mode : undefined,
    signer_did: signatureVerification.signer_did,
  };
}

async function validateSummary(summaryPath, opts) {
  const issues = [];
  const summary = readJson(summaryPath);

  const fullSummaryPath = path.resolve(ROOT, summaryPath);
  const stat = fs.statSync(fullSummaryPath);
  const ageMs = Date.now() - stat.mtimeMs;
  const maxAgeMs = opts.maxAgeMinutes * 60_000;

  if (!Number.isFinite(opts.maxAgeMinutes) || opts.maxAgeMinutes <= 0) {
    issues.push('max-age-minutes must be a positive number');
  } else if (ageMs > maxAgeMs) {
    issues.push(
      `summary is stale: age ${Math.round(ageMs / 1000)}s exceeds max ${Math.round(maxAgeMs / 1000)}s`
    );
  }

  if (summary.ok !== true) {
    issues.push(`summary.ok must be true (got ${String(summary.ok)})`);
  }

  if (typeof opts.requireMode === 'string' && opts.requireMode.length > 0) {
    if (summary.mode !== opts.requireMode) {
      issues.push(`summary.mode must be ${opts.requireMode} (got ${String(summary.mode)})`);
    }
  }

  if (
    typeof opts.requireMutationSubset === 'string' &&
    opts.requireMutationSubset.length > 0
  ) {
    if (summary.mutation_subset !== opts.requireMutationSubset) {
      issues.push(
        `summary.mutation_subset must be ${opts.requireMutationSubset} (got ${String(
          summary.mutation_subset
        )})`
      );
    }
  }

  if (!Array.isArray(summary.steps)) {
    issues.push('summary.steps must be an array');
    return {
      ok: false,
      issues,
      summary,
      age_minutes: ageMs / 60_000,
      signature: {
        ok: false,
        signature_path: opts.signature ?? defaultSignaturePath(summaryPath),
        signature_present: false,
        issues: ['summary.steps must be an array'],
      },
    };
  }

  const byId = new Map(summary.steps.map((step) => [step?.id, step]));

  for (const stepId of REQUIRED_STEP_IDS) {
    const step = byId.get(stepId);
    if (!step) {
      issues.push(`missing required burn-in step: ${stepId}`);
      continue;
    }

    if (step.ok !== true) {
      issues.push(`required step ${stepId} did not pass (ok=${String(step.ok)})`);
    }

    if (step.exit_code !== 0) {
      issues.push(
        `required step ${stepId} exit_code must be 0 (got ${String(step.exit_code)})`
      );
    }
  }

  if (
    typeof summary.step_count_expected === 'number' &&
    summary.step_count_expected < REQUIRED_STEP_IDS.length
  ) {
    issues.push(
      `summary.step_count_expected must be >= ${REQUIRED_STEP_IDS.length} (got ${summary.step_count_expected})`
    );
  }

  const signaturePath = opts.signature ?? defaultSignaturePath(summaryPath);
  const signatureValidation = await validateSignatureContract(
    summaryPath,
    signaturePath,
    opts.requireSigned
  );

  for (const signatureIssue of signatureValidation.issues) {
    issues.push(signatureIssue);
  }

  return {
    ok: issues.length === 0,
    issues,
    summary,
    age_minutes: ageMs / 60_000,
    signature: signatureValidation,
  };
}

async function run() {
  const opts = parseArgs(process.argv.slice(2));
  const summaryPath = opts.summary ?? findLatestSummaryPath();

  if (!summaryPath) {
    const result = {
      ok: false,
      summary_path: null,
      signature_path: opts.signature ?? null,
      checked_steps: REQUIRED_STEP_IDS,
      require_signed: opts.requireSigned,
      issues: [
        'No causal-integrity burn-in summary found. Pass --summary <path> or generate artifacts/ops/causal-integrity-burnin/<timestamp>/summary.json',
      ],
    };
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = 1;
    return;
  }

  const validation = await validateSummary(summaryPath, opts);

  const result = {
    ok: validation.ok,
    summary_path: summaryPath,
    signature_path: validation.signature.signature_path,
    signature_present: validation.signature.signature_present,
    signature_ok: validation.signature.ok,
    signing_mode: validation.signature.signing_mode,
    signer_did: validation.signature.signer_did,
    max_age_minutes: opts.maxAgeMinutes,
    summary_age_minutes: Number(validation.age_minutes.toFixed(2)),
    required_mode: opts.requireMode,
    required_mutation_subset: opts.requireMutationSubset,
    require_signed: opts.requireSigned,
    checked_steps: REQUIRED_STEP_IDS,
    issues: validation.issues,
  };

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

  if (!result.ok) {
    process.exitCode = 1;
  }
}

run().catch((error) => {
  const result = {
    ok: false,
    summary_path: null,
    signature_path: null,
    issues: [error instanceof Error ? error.message : String(error)],
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = 1;
});
