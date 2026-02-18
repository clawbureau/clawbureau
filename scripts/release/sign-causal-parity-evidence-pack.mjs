#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');

const PARITY_MESSAGE_PREFIX = 'causal-service-core-parity-evidence';
const STABILITY_MESSAGE_PREFIX = 'causal-reason-code-stability-evidence';

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

  return {
    paritySummary:
      getValue('--parity-summary') ?? getValueEq('--parity-summary') ?? null,
    paritySignatureOut:
      getValue('--parity-signature-out') ??
      getValueEq('--parity-signature-out') ??
      null,
    stabilitySummary:
      getValue('--stability-summary') ??
      getValueEq('--stability-summary') ??
      null,
    stabilitySignatureOut:
      getValue('--stability-signature-out') ??
      getValueEq('--stability-signature-out') ??
      null,
    signingMode:
      getValue('--signing-mode') ?? getValueEq('--signing-mode') ?? 'auto',
  };
}

function findLatestSummaryPath(relativeRootDir) {
  const root = path.resolve(ROOT, relativeRootDir);
  if (!fs.existsSync(root)) return null;

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

function normalizeSummaryPath(summaryPath) {
  return path.relative(ROOT, path.resolve(ROOT, summaryPath));
}

function resolveOutputPath(summaryPath, explicitOut) {
  if (explicitOut) {
    return explicitOut;
  }

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

function base58Encode(bytes) {
  if (bytes.length === 0) return '';

  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      const x = digits[i] * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  for (let i = 0; i < bytes.length && bytes[i] === 0; i += 1) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d])
    .join('');
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

function didWorkPassphrasePresent() {
  const envPassphrase = process.env.DID_WORK_PASSPHRASE?.trim();
  if (envPassphrase) return true;

  const defaultPath = path.join(
    os.homedir(),
    '.openclaw',
    'did-work',
    'identity',
    'passphrase.txt'
  );

  return fs.existsSync(defaultPath);
}

function signWithDidWork(message) {
  const result = spawnSync(
    'node',
    ['scripts/did-work/sign-message.mjs', message],
    {
      cwd: ROOT,
      encoding: 'utf8',
      env: process.env,
      stdio: 'pipe',
    }
  );

  if ((result.status ?? 1) !== 0) {
    return {
      ok: false,
      reason: result.stderr?.trim() || 'did-work signing command failed',
    };
  }

  try {
    return {
      ok: true,
      envelope: JSON.parse(result.stdout),
    };
  } catch (error) {
    return {
      ok: false,
      reason:
        error instanceof Error
          ? error.message
          : 'failed to parse did-work signature envelope',
    };
  }
}

async function signEphemeral(message) {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', keypair.publicKey)
  );

  const multicodec = new Uint8Array(2 + publicKeyBytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(publicKeyBytes, 2);

  const envelope = {
    version: 'm1',
    type: 'message_signature',
    algo: 'ed25519',
    did: `did:key:z${base58Encode(multicodec)}`,
    message,
    createdAt: new Date().toISOString(),
    signature: '',
  };

  const canonical = jcsCanonicalize(envelope);
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign('Ed25519', keypair.privateKey, new TextEncoder().encode(canonical))
  );

  envelope.signature = Buffer.from(signatureBytes).toString('base64');
  return envelope;
}

async function signMessageEnvelope(message, mode) {
  const normalized = String(mode || 'auto').trim().toLowerCase();
  const allowDidWork = normalized === 'auto' || normalized === 'did-work';
  const allowEphemeral = normalized === 'auto' || normalized === 'ephemeral';

  if (!allowDidWork && !allowEphemeral) {
    throw new Error('signing-mode must be one of: auto, did-work, ephemeral');
  }

  if (allowDidWork && didWorkPassphrasePresent()) {
    const didWork = signWithDidWork(message);
    if (didWork.ok) {
      return {
        mode: 'did-work',
        envelope: didWork.envelope,
      };
    }

    if (normalized === 'did-work') {
      throw new Error(`did-work signing failed: ${didWork.reason}`);
    }
  } else if (normalized === 'did-work') {
    throw new Error('did-work signing requested but no passphrase is available');
  }

  if (!allowEphemeral) {
    throw new Error('no usable signing mode available');
  }

  return {
    mode: 'ephemeral',
    envelope: await signEphemeral(message),
  };
}

async function sha256FileB64u(absPath) {
  const bytes = fs.readFileSync(absPath);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

async function signSummary({
  label,
  summaryPath,
  signatureOut,
  messagePrefix,
  signingMode,
}) {
  if (!summaryPath) {
    throw new Error(`${label}: summary path is required`);
  }

  const normalizedSummaryPath = normalizeSummaryPath(summaryPath);
  const summaryAbs = path.resolve(ROOT, normalizedSummaryPath);

  if (!fs.existsSync(summaryAbs)) {
    throw new Error(`${label}: summary file does not exist: ${normalizedSummaryPath}`);
  }

  const summaryShaB64u = await sha256FileB64u(summaryAbs);
  const message = `${messagePrefix}:${summaryShaB64u}`;
  const signed = await signMessageEnvelope(message, signingMode);

  const signatureOutRel = resolveOutputPath(
    normalizedSummaryPath,
    signatureOut ? normalizeSummaryPath(signatureOut) : null
  );
  const signatureOutAbs = path.resolve(ROOT, signatureOutRel);

  const payload = {
    evidence_signature_version: '1',
    summary_path: normalizedSummaryPath,
    summary_sha256_b64u: summaryShaB64u,
    message_prefix: messagePrefix,
    signing_mode: signed.mode,
    signed_at: new Date().toISOString(),
    message_signature: signed.envelope,
  };

  fs.mkdirSync(path.dirname(signatureOutAbs), { recursive: true });
  fs.writeFileSync(signatureOutAbs, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');

  return {
    label,
    summary_path: normalizedSummaryPath,
    signature_path: signatureOutRel,
    summary_sha256_b64u: summaryShaB64u,
    signing_mode: signed.mode,
  };
}

async function run() {
  const opts = parseArgs(process.argv.slice(2));

  const paritySummaryPath =
    opts.paritySummary ??
    findLatestSummaryPath('artifacts/ops/causal-service-core-parity');
  const stabilitySummaryPath =
    opts.stabilitySummary ??
    findLatestSummaryPath('artifacts/ops/causal-reason-code-stability');

  if (!paritySummaryPath) {
    console.error('[sign-causal-parity-evidence-pack] FAIL');
    console.error('No service-core parity summary found. Pass --parity-summary <path>.');
    process.exit(1);
  }

  if (!stabilitySummaryPath) {
    console.error('[sign-causal-parity-evidence-pack] FAIL');
    console.error(
      'No reason-code stability summary found. Pass --stability-summary <path>.'
    );
    process.exit(1);
  }

  const parity = await signSummary({
    label: 'service-core-parity',
    summaryPath: paritySummaryPath,
    signatureOut: opts.paritySignatureOut,
    messagePrefix: PARITY_MESSAGE_PREFIX,
    signingMode: opts.signingMode,
  });

  const stability = await signSummary({
    label: 'reason-code-stability',
    summaryPath: stabilitySummaryPath,
    signatureOut: opts.stabilitySignatureOut,
    messagePrefix: STABILITY_MESSAGE_PREFIX,
    signingMode: opts.signingMode,
  });

  console.log('[sign-causal-parity-evidence-pack] PASS');
  console.log(
    JSON.stringify(
      {
        ok: true,
        parity,
        stability,
      },
      null,
      2
    )
  );
}

run().catch((error) => {
  console.error('[sign-causal-parity-evidence-pack] ERROR');
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
