#!/usr/bin/env node
/**
 * Guardrail: validate causal-integrity release evidence contract.
 *
 * Contract:
 * - burn-in summary exists (explicit --summary or latest under artifacts/ops/causal-integrity-burnin)
 * - burn-in summary freshness <= max-age-minutes
 * - burn-in summary.ok === true
 * - required burn-in mode + mutation subset match expected values
 * - required burn-in steps are present and PASS
 * - burn-in summary signature exists and verifies unless --require-signed=false
 * - signed burn-in summary hash + message binding matches summary bytes
 *
 * Additional causal evidence contract:
 * - service-core parity summary exists, is fresh, and ok=true
 * - reason-code stability summary exists, is fresh, and ok=true
 * - fixture-contract summary exists, is fresh, and ok=true
 * - cross-runtime determinism summary exists, is fresh, and ok=true
 * - each auxiliary summary is signed + verified unless explicitly disabled
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');

const BURNIN_MESSAGE_PREFIX = 'causal-integrity-evidence';
const PARITY_MESSAGE_PREFIX = 'causal-service-core-parity-evidence';
const STABILITY_MESSAGE_PREFIX = 'causal-reason-code-stability-evidence';
const FIXTURE_CONTRACT_MESSAGE_PREFIX = 'causal-fixture-contract-evidence';
const CROSS_RUNTIME_MESSAGE_PREFIX = 'causal-cross-runtime-determinism-evidence';

const REQUIRED_STEP_IDS = [
  'reason-code-parity',
  'causal-cldd-conformance',
  'causal-hardening-conformance',
  'causal-connectivity-conformance',
  'causal-clock-conformance',
  'service-core-causal-parity',
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

  const maxAgeRaw =
    getValue('--max-age-minutes') ?? getValueEq('--max-age-minutes');

  return {
    summary: getValue('--summary') ?? getValueEq('--summary') ?? null,
    signature: getValue('--signature') ?? getValueEq('--signature') ?? null,

    paritySummary:
      getValue('--parity-summary') ?? getValueEq('--parity-summary') ?? null,
    paritySignature:
      getValue('--parity-signature') ?? getValueEq('--parity-signature') ?? null,

    stabilitySummary:
      getValue('--stability-summary') ?? getValueEq('--stability-summary') ?? null,
    stabilitySignature:
      getValue('--stability-signature') ?? getValueEq('--stability-signature') ?? null,

    fixtureContractSummary:
      getValue('--fixture-contract-summary') ??
      getValueEq('--fixture-contract-summary') ??
      null,
    fixtureContractSignature:
      getValue('--fixture-contract-signature') ??
      getValueEq('--fixture-contract-signature') ??
      null,

    crossRuntimeSummary:
      getValue('--cross-runtime-summary') ??
      getValueEq('--cross-runtime-summary') ??
      null,
    crossRuntimeSignature:
      getValue('--cross-runtime-signature') ??
      getValueEq('--cross-runtime-signature') ??
      null,

    requireMode:
      getValue('--require-mode') ?? getValueEq('--require-mode') ?? 'quick',
    requireMutationSubset:
      getValue('--require-mutation-subset') ??
      getValueEq('--require-mutation-subset') ??
      'quick',

    requireSigned: parseBoolean(
      getValue('--require-signed') ?? getValueEq('--require-signed'),
      true
    ),
    requireSignedParity: parseBoolean(
      getValue('--require-signed-parity') ??
        getValueEq('--require-signed-parity'),
      true
    ),
    requireSignedStability: parseBoolean(
      getValue('--require-signed-stability') ??
        getValueEq('--require-signed-stability'),
      true
    ),
    requireSignedFixtureContract: parseBoolean(
      getValue('--require-signed-fixture-contract') ??
        getValueEq('--require-signed-fixture-contract'),
      true
    ),
    requireSignedCrossRuntime: parseBoolean(
      getValue('--require-signed-cross-runtime') ??
        getValueEq('--require-signed-cross-runtime'),
      true
    ),

    maxAgeMinutes:
      maxAgeRaw !== undefined && Number.isFinite(Number(maxAgeRaw))
        ? Number(maxAgeRaw)
        : 180,
  };
}

function readJson(relPath) {
  return JSON.parse(fs.readFileSync(path.resolve(ROOT, relPath), 'utf8'));
}

function findLatestSummaryPath(relativeRootDir) {
  const root = path.resolve(ROOT, relativeRootDir);
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

  const summaryPath = path.join(relativeRootDir, latest, 'summary.json');
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

async function validateSignatureContract({
  summaryPath,
  signaturePath,
  requireSigned,
  expectedMessagePrefix,
  signingHint,
}) {
  const issues = [];
  const fullSignaturePath = path.resolve(ROOT, signaturePath);
  const signatureExists = fs.existsSync(fullSignaturePath);

  if (!signatureExists) {
    if (requireSigned) {
      issues.push(`missing signature file: ${signaturePath} (run ${signingHint})`);
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

  if (sigDoc.message_prefix !== expectedMessagePrefix) {
    issues.push(
      `message_prefix must be ${expectedMessagePrefix} (got ${String(sigDoc.message_prefix)})`
    );
  }

  const expectedMessage = `${expectedMessagePrefix}:${expectedSummaryHash}`;
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

function validateSummaryFreshness(summaryPath, maxAgeMinutes) {
  const issues = [];

  const fullSummaryPath = path.resolve(ROOT, summaryPath);
  const stat = fs.statSync(fullSummaryPath);
  const ageMs = Date.now() - stat.mtimeMs;
  const maxAgeMs = maxAgeMinutes * 60_000;

  if (!Number.isFinite(maxAgeMinutes) || maxAgeMinutes <= 0) {
    issues.push('max-age-minutes must be a positive number');
  } else if (ageMs > maxAgeMs) {
    issues.push(
      `summary is stale: age ${Math.round(ageMs / 1000)}s exceeds max ${Math.round(maxAgeMs / 1000)}s`
    );
  }

  return {
    issues,
    age_minutes: ageMs / 60_000,
  };
}

function hasPositiveSuiteCount(summary) {
  const counts = [
    summary?.suite_count_executed,
    summary?.suite_count,
    Array.isArray(summary?.suites) ? summary.suites.length : null,
    Array.isArray(summary?.suite_comparisons)
      ? summary.suite_comparisons.length
      : null,
  ].filter((value) => typeof value === 'number');

  if (counts.length === 0) return false;
  return counts.some((value) => value > 0);
}

async function validateBurnInSummary(summaryPath, opts) {
  const issues = [];
  const summary = readJson(summaryPath);

  const freshness = validateSummaryFreshness(summaryPath, opts.maxAgeMinutes);
  issues.push(...freshness.issues);

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
  } else {
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
  }

  const signaturePath = opts.signature ?? defaultSignaturePath(summaryPath);
  const signatureValidation = await validateSignatureContract({
    summaryPath,
    signaturePath,
    requireSigned: opts.requireSigned,
    expectedMessagePrefix: BURNIN_MESSAGE_PREFIX,
    signingHint: 'scripts/release/sign-causal-integrity-evidence-pack.mjs',
  });

  issues.push(...signatureValidation.issues);

  return {
    ok: issues.length === 0,
    issues,
    summary,
    age_minutes: freshness.age_minutes,
    signature: signatureValidation,
  };
}

async function validateAuxSummary({
  summaryPath,
  signaturePath,
  maxAgeMinutes,
  requireSigned,
  expectedMessagePrefix,
  signingHint,
}) {
  const issues = [];
  const summary = readJson(summaryPath);

  const freshness = validateSummaryFreshness(summaryPath, maxAgeMinutes);
  issues.push(...freshness.issues);

  if (summary.ok !== true) {
    issues.push(`summary.ok must be true (got ${String(summary.ok)})`);
  }

  if (!Array.isArray(summary.suites) && !Array.isArray(summary.suite_comparisons)) {
    issues.push('summary must include suites[] or suite_comparisons[] evidence rows');
  }

  if (!hasPositiveSuiteCount(summary)) {
    issues.push('summary must include a positive suite count');
  }

  const signatureValidation = await validateSignatureContract({
    summaryPath,
    signaturePath,
    requireSigned,
    expectedMessagePrefix,
    signingHint,
  });

  issues.push(...signatureValidation.issues);

  return {
    ok: issues.length === 0,
    issues,
    summary,
    age_minutes: freshness.age_minutes,
    signature: signatureValidation,
  };
}

function prefixIssues(prefix, issues) {
  return issues.map((issue) => `${prefix}: ${issue}`);
}

async function run() {
  const opts = parseArgs(process.argv.slice(2));

  const burninSummaryPath =
    opts.summary ?? findLatestSummaryPath('artifacts/ops/causal-integrity-burnin');
  const paritySummaryPath =
    opts.paritySummary ??
    findLatestSummaryPath('artifacts/ops/causal-service-core-parity');
  const stabilitySummaryPath =
    opts.stabilitySummary ??
    findLatestSummaryPath('artifacts/ops/causal-reason-code-stability');
  const fixtureContractSummaryPath =
    opts.fixtureContractSummary ??
    findLatestSummaryPath('artifacts/ops/causal-fixture-contract');
  const crossRuntimeSummaryPath =
    opts.crossRuntimeSummary ??
    findLatestSummaryPath('artifacts/ops/causal-cross-runtime-determinism');

  const issues = [];

  if (!burninSummaryPath) {
    issues.push(
      'burnin: no causal-integrity burn-in summary found. Pass --summary <path> or generate artifacts/ops/causal-integrity-burnin/<timestamp>/summary.json'
    );
  }

  if (!paritySummaryPath) {
    issues.push(
      'parity: no service-core parity summary found. Pass --parity-summary <path> or generate artifacts/ops/causal-service-core-parity/<timestamp>/summary.json'
    );
  }

  if (!stabilitySummaryPath) {
    issues.push(
      'stability: no reason-code stability summary found. Pass --stability-summary <path> or generate artifacts/ops/causal-reason-code-stability/<timestamp>/summary.json'
    );
  }

  if (!fixtureContractSummaryPath) {
    issues.push(
      'fixture_contract: no causal fixture-contract summary found. Pass --fixture-contract-summary <path> or generate artifacts/ops/causal-fixture-contract/<timestamp>/summary.json'
    );
  }

  if (!crossRuntimeSummaryPath) {
    issues.push(
      'cross_runtime: no causal cross-runtime summary found. Pass --cross-runtime-summary <path> or generate artifacts/ops/causal-cross-runtime-determinism/<timestamp>/summary.json'
    );
  }

  let burninValidation = null;
  let parityValidation = null;
  let stabilityValidation = null;
  let fixtureContractValidation = null;
  let crossRuntimeValidation = null;

  if (burninSummaryPath) {
    burninValidation = await validateBurnInSummary(burninSummaryPath, opts);
    issues.push(...prefixIssues('burnin', burninValidation.issues));
  }

  if (paritySummaryPath) {
    const paritySignaturePath =
      opts.paritySignature ?? defaultSignaturePath(paritySummaryPath);
    parityValidation = await validateAuxSummary({
      summaryPath: paritySummaryPath,
      signaturePath: paritySignaturePath,
      maxAgeMinutes: opts.maxAgeMinutes,
      requireSigned: opts.requireSignedParity,
      expectedMessagePrefix: PARITY_MESSAGE_PREFIX,
      signingHint: 'scripts/release/sign-causal-parity-evidence-pack.mjs',
    });
    issues.push(...prefixIssues('parity', parityValidation.issues));
  }

  if (stabilitySummaryPath) {
    const stabilitySignaturePath =
      opts.stabilitySignature ?? defaultSignaturePath(stabilitySummaryPath);
    stabilityValidation = await validateAuxSummary({
      summaryPath: stabilitySummaryPath,
      signaturePath: stabilitySignaturePath,
      maxAgeMinutes: opts.maxAgeMinutes,
      requireSigned: opts.requireSignedStability,
      expectedMessagePrefix: STABILITY_MESSAGE_PREFIX,
      signingHint: 'scripts/release/sign-causal-parity-evidence-pack.mjs',
    });
    issues.push(...prefixIssues('stability', stabilityValidation.issues));
  }

  if (fixtureContractSummaryPath) {
    const fixtureContractSignaturePath =
      opts.fixtureContractSignature ??
      defaultSignaturePath(fixtureContractSummaryPath);
    fixtureContractValidation = await validateAuxSummary({
      summaryPath: fixtureContractSummaryPath,
      signaturePath: fixtureContractSignaturePath,
      maxAgeMinutes: opts.maxAgeMinutes,
      requireSigned: opts.requireSignedFixtureContract,
      expectedMessagePrefix: FIXTURE_CONTRACT_MESSAGE_PREFIX,
      signingHint: 'scripts/release/sign-causal-parity-evidence-pack.mjs',
    });
    issues.push(...prefixIssues('fixture_contract', fixtureContractValidation.issues));
  }

  if (crossRuntimeSummaryPath) {
    const crossRuntimeSignaturePath =
      opts.crossRuntimeSignature ?? defaultSignaturePath(crossRuntimeSummaryPath);
    crossRuntimeValidation = await validateAuxSummary({
      summaryPath: crossRuntimeSummaryPath,
      signaturePath: crossRuntimeSignaturePath,
      maxAgeMinutes: opts.maxAgeMinutes,
      requireSigned: opts.requireSignedCrossRuntime,
      expectedMessagePrefix: CROSS_RUNTIME_MESSAGE_PREFIX,
      signingHint: 'scripts/release/sign-causal-parity-evidence-pack.mjs',
    });
    issues.push(...prefixIssues('cross_runtime', crossRuntimeValidation.issues));
  }

  const result = {
    ok: issues.length === 0,
    summary_path: burninSummaryPath,
    signature_path: burninValidation?.signature.signature_path ?? null,
    signature_present: burninValidation?.signature.signature_present ?? false,
    signature_ok: burninValidation?.signature.ok ?? false,
    signing_mode: burninValidation?.signature.signing_mode,
    signer_did: burninValidation?.signature.signer_did,
    max_age_minutes: opts.maxAgeMinutes,
    summary_age_minutes: burninValidation
      ? Number(burninValidation.age_minutes.toFixed(2))
      : null,
    required_mode: opts.requireMode,
    required_mutation_subset: opts.requireMutationSubset,
    require_signed: opts.requireSigned,
    checked_steps: REQUIRED_STEP_IDS,

    parity_summary_path: paritySummaryPath,
    parity_signature_path: parityValidation?.signature.signature_path ?? null,
    parity_signature_present: parityValidation?.signature.signature_present ?? false,
    parity_signature_ok: parityValidation?.signature.ok ?? false,
    parity_signing_mode: parityValidation?.signature.signing_mode,
    parity_signer_did: parityValidation?.signature.signer_did,
    parity_summary_age_minutes: parityValidation
      ? Number(parityValidation.age_minutes.toFixed(2))
      : null,
    require_signed_parity: opts.requireSignedParity,

    stability_summary_path: stabilitySummaryPath,
    stability_signature_path: stabilityValidation?.signature.signature_path ?? null,
    stability_signature_present: stabilityValidation?.signature.signature_present ?? false,
    stability_signature_ok: stabilityValidation?.signature.ok ?? false,
    stability_signing_mode: stabilityValidation?.signature.signing_mode,
    stability_signer_did: stabilityValidation?.signature.signer_did,
    stability_summary_age_minutes: stabilityValidation
      ? Number(stabilityValidation.age_minutes.toFixed(2))
      : null,
    require_signed_stability: opts.requireSignedStability,

    fixture_contract_summary_path: fixtureContractSummaryPath,
    fixture_contract_signature_path:
      fixtureContractValidation?.signature.signature_path ?? null,
    fixture_contract_signature_present:
      fixtureContractValidation?.signature.signature_present ?? false,
    fixture_contract_signature_ok: fixtureContractValidation?.signature.ok ?? false,
    fixture_contract_signing_mode:
      fixtureContractValidation?.signature.signing_mode,
    fixture_contract_signer_did: fixtureContractValidation?.signature.signer_did,
    fixture_contract_summary_age_minutes: fixtureContractValidation
      ? Number(fixtureContractValidation.age_minutes.toFixed(2))
      : null,
    require_signed_fixture_contract: opts.requireSignedFixtureContract,

    cross_runtime_summary_path: crossRuntimeSummaryPath,
    cross_runtime_signature_path: crossRuntimeValidation?.signature.signature_path ?? null,
    cross_runtime_signature_present:
      crossRuntimeValidation?.signature.signature_present ?? false,
    cross_runtime_signature_ok: crossRuntimeValidation?.signature.ok ?? false,
    cross_runtime_signing_mode: crossRuntimeValidation?.signature.signing_mode,
    cross_runtime_signer_did: crossRuntimeValidation?.signature.signer_did,
    cross_runtime_summary_age_minutes: crossRuntimeValidation
      ? Number(crossRuntimeValidation.age_minutes.toFixed(2))
      : null,
    require_signed_cross_runtime: opts.requireSignedCrossRuntime,

    issues,
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
    parity_summary_path: null,
    parity_signature_path: null,
    stability_summary_path: null,
    stability_signature_path: null,
    fixture_contract_summary_path: null,
    fixture_contract_signature_path: null,
    cross_runtime_summary_path: null,
    cross_runtime_signature_path: null,
    issues: [error instanceof Error ? error.message : String(error)],
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = 1;
});
