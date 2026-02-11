#!/usr/bin/env node

/**
 * Smoke: witnessed web receipt verification
 *
 * - sends a valid witness-signed web_receipt envelope => VALID
 * - sends a tampered signature envelope => INVALID
 */

import process from 'node:process';
import { existsSync, readFileSync } from 'node:fs';

function parseArgs(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) {
      args.set(key, next);
      i++;
    } else {
      args.set(key, 'true');
    }
  }
  return args;
}

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERT_FAILED: ${msg}`);
}

function b64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function b64uDecode(str) {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }

  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = '';
  for (let i = 0; i < leadingZeros; i++) out += '1';
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]];
  return out;
}

function tryRead(path) {
  if (!existsSync(path)) return null;
  return readFileSync(path, 'utf8').trim();
}

async function sha256B64u(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return b64u(new Uint8Array(digest));
}

async function signerFromSeedB64u(seedB64u) {
  const seed = b64uDecode(seedB64u);
  assert(seed.length >= 32, 'ATTESTATION_SIGNER_SEED_B64U must decode to >= 32 bytes');
  const seed32 = seed.slice(0, 32);

  const pkcs8Header = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22,
    0x04, 0x20,
  ]);

  const pkcs8Key = new Uint8Array(pkcs8Header.length + seed32.length);
  pkcs8Key.set(pkcs8Header);
  pkcs8Key.set(seed32, pkcs8Header.length);

  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8Key, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);

  const pub = b64uDecode(jwk.x);
  const prefixed = new Uint8Array(2 + pub.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(pub, 2);

  return {
    did: `did:key:z${base58Encode(prefixed)}`,
    privateKey,
  };
}

async function signEnvelope(payload, signer) {
  const payloadHash = await sha256B64u(JSON.stringify(payload));
  const sig = await crypto.subtle.sign('Ed25519', signer.privateKey, new TextEncoder().encode(payloadHash));

  return {
    envelope_version: '1',
    envelope_type: 'web_receipt',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: b64u(new Uint8Array(sig)),
    algorithm: 'Ed25519',
    signer_did: signer.did,
    issued_at: new Date().toISOString(),
  };
}

function mutateB64u(value) {
  const first = value[0] === 'A' ? 'B' : 'A';
  return `${first}${value.slice(1)}`;
}

async function httpJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body),
  });

  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  return { status: res.status, text, json };
}

async function smoke() {
  const args = parseArgs(process.argv.slice(2));
  const envName = String(args.get('env') || 'staging').toLowerCase();

  const verifyBaseUrl =
    String(args.get('verify-base-url') || '') ||
    (envName === 'prod' || envName === 'production'
      ? 'https://clawverify.com'
      : 'https://staging.clawverify.com');

  const seedB64u =
    process.env.ATTESTATION_SIGNER_SEED_B64U ||
    tryRead('/Users/gfw/.claw-secrets/clawverify/attestation-signer/SEED.b64u');

  assert(seedB64u && seedB64u.length > 0, 'Missing ATTESTATION_SIGNER_SEED_B64U (or local secret file)');
  const signer = await signerFromSeedB64u(seedB64u);

  const payload = {
    receipt_version: '1',
    receipt_id: `web_rcpt_${envName}_${Date.now()}`,
    witness_id: 'witness_smoke_cluster',
    source: 'chatgpt_web',
    request_hash_b64u: await sha256B64u(`request-${envName}-${Date.now()}`),
    response_hash_b64u: await sha256B64u(`response-${envName}-${Date.now()}`),
    session_hash_b64u: await sha256B64u(`session-${envName}`),
    timestamp: new Date().toISOString(),
    binding: {
      run_id: `run_web_${envName}`,
      event_hash_b64u: await sha256B64u(`event-${envName}`),
      nonce: `nonce_web_${envName}`,
    },
  };

  const validEnvelope = await signEnvelope(payload, signer);
  const valid = await httpJson(`${verifyBaseUrl}/v1/verify/web-receipt`, { envelope: validEnvelope });
  assert(valid.status === 200, `valid expected 200, got ${valid.status}: ${valid.text}`);
  assert(valid.json?.result?.status === 'VALID', `valid expected VALID, got ${valid.text}`);

  const badEnvelope = {
    ...validEnvelope,
    signature_b64u: mutateB64u(validEnvelope.signature_b64u),
  };

  const invalid = await httpJson(`${verifyBaseUrl}/v1/verify/web-receipt`, { envelope: badEnvelope });
  assert(invalid.status === 422, `tampered expected 422, got ${invalid.status}: ${invalid.text}`);
  assert(invalid.json?.result?.status === 'INVALID', `tampered expected INVALID, got ${invalid.text}`);

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        verify_base_url: verifyBaseUrl,
        signer_did: signer.did,
        valid: {
          status: valid.status,
          result_status: valid.json?.result?.status,
          proof_tier: valid.json?.proof_tier,
          equivalent_to_gateway: valid.json?.equivalent_to_gateway,
        },
        tampered: {
          status: invalid.status,
          result_status: invalid.json?.result?.status,
          error_code: invalid.json?.error?.code,
        },
      },
      null,
      2,
    ),
  );
}

smoke().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
