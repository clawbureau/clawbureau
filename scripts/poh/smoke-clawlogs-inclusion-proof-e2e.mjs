#!/usr/bin/env node

/**
 * E2E smoke: clawlogs inclusion proof path
 *
 * Flow:
 * 1) append leaf to clawlogs
 * 2) fetch root + inclusion proof
 * 3) embed proof in derivation_attestation payload
 * 4) verify via clawverify => VALID
 * 5) tamper proof, resign, verify => INVALID
 */

import process from 'node:process';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';

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

async function sha256B64u(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return b64u(new Uint8Array(digest));
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

async function signerFromSeedB64u(seedB64u) {
  const seed = b64uDecode(seedB64u);
  assert(seed.length >= 32, 'ATTESTATION_SIGNER_SEED_B64U must decode to >=32 bytes');
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
  const did = `did:key:z${base58Encode(prefixed)}`;

  return { did, privateKey };
}

async function signEnvelope(payload, signer, envelopeType) {
  const payloadHash = await sha256B64u(JSON.stringify(payload));
  const sig = await crypto.subtle.sign('Ed25519', signer.privateKey, new TextEncoder().encode(payloadHash));

  return {
    envelope_version: '1',
    envelope_type: envelopeType,
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: b64u(new Uint8Array(sig)),
    algorithm: 'Ed25519',
    signer_did: signer.did,
    issued_at: new Date().toISOString(),
  };
}

function tryRead(path) {
  if (!existsSync(path)) return null;
  return readFileSync(path, 'utf8').trim();
}

function maybeMutateB64u(value) {
  const first = value[0] === 'A' ? 'B' : 'A';
  return `${first}${value.slice(1)}`;
}

function curlJson(url, { method = 'GET', headers = {}, body = undefined, resolveIp = undefined } = {}) {
  const u = new URL(url);
  const args = ['-sS', '-X', method, url];

  if (resolveIp && u.protocol === 'https:') {
    args.push('--resolve', `${u.hostname}:443:${resolveIp}`);
  }

  for (const [k, v] of Object.entries(headers)) {
    args.push('-H', `${k}: ${v}`);
  }

  if (body !== undefined) {
    args.push('--data', typeof body === 'string' ? body : JSON.stringify(body));
  }

  args.push('-w', '\n%{http_code}');

  const out = execFileSync('curl', args, { encoding: 'utf8' });
  const idx = out.lastIndexOf('\n');
  const text = idx >= 0 ? out.slice(0, idx) : out;
  const status = Number(idx >= 0 ? out.slice(idx + 1).trim() : '0');

  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  return { status, text, json };
}

async function smoke() {
  const args = parseArgs(process.argv.slice(2));
  const envName = String(args.get('env') || 'staging').toLowerCase();

  const clawlogsBaseUrl =
    String(args.get('clawlogs-base-url') || '') ||
    (envName === 'prod' || envName === 'production'
      ? 'https://clawlogs.com'
      : 'https://staging.clawlogs.com');

  const clawverifyBaseUrl =
    String(args.get('clawverify-base-url') || '') ||
    (envName === 'prod' || envName === 'production'
      ? 'https://clawverify.com'
      : 'https://staging.clawverify.com');

  const clawlogsResolveIp = String(args.get('clawlogs-resolve-ip') || '').trim() || undefined;
  const clawverifyResolveIp = String(args.get('clawverify-resolve-ip') || '').trim() || undefined;

  const adminToken =
    process.env.CLAWLOGS_ADMIN_TOKEN ||
    tryRead(`/Users/gfw/.claw-secrets/clawlogs/${envName === 'prod' || envName === 'production' ? 'production' : 'staging'}/ADMIN_TOKEN.txt`);

  assert(adminToken && adminToken.length > 0, 'Missing CLAWLOGS_ADMIN_TOKEN (or local secret file)');

  const seedB64u =
    process.env.ATTESTATION_SIGNER_SEED_B64U ||
    tryRead('/Users/gfw/.claw-secrets/clawverify/attestation-signer/SEED.b64u');

  assert(seedB64u && seedB64u.length > 0, 'Missing ATTESTATION_SIGNER_SEED_B64U (or local secret file)');
  const signer = await signerFromSeedB64u(seedB64u);

  const leafHash = await sha256B64u(`smoke-clawlogs-${envName}-${Date.now()}`);
  const logId = `smoke-${envName}`;

  const append = curlJson(`${clawlogsBaseUrl}/v1/logs/${encodeURIComponent(logId)}/append`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${adminToken}`,
    },
    body: { leaf_hash_b64u: leafHash },
    resolveIp: clawlogsResolveIp,
  });

  assert(append.status === 201, `append expected 201, got ${append.status}: ${append.text}`);
  assert(append.json?.ok === true, `append response not ok: ${append.text}`);

  const root = curlJson(`${clawlogsBaseUrl}/v1/logs/${encodeURIComponent(logId)}/root`, {
    resolveIp: clawlogsResolveIp,
  });
  assert(root.status === 200, `root expected 200, got ${root.status}: ${root.text}`);
  assert(root.json?.ok === true, `root response not ok: ${root.text}`);

  const proof = curlJson(
    `${clawlogsBaseUrl}/v1/logs/${encodeURIComponent(logId)}/proof/${encodeURIComponent(leafHash)}`,
    { resolveIp: clawlogsResolveIp },
  );
  assert(proof.status === 200, `proof expected 200, got ${proof.status}: ${proof.text}`);
  assert(proof.json?.proof_version === '1', `proof missing proof_version=1: ${proof.text}`);

  const payloadValid = {
    derivation_version: '1',
    derivation_id: `drv_${envName}_${Date.now()}`,
    issued_at: new Date().toISOString(),
    input_model: {
      model_identity_version: '1',
      tier: 'closed_opaque',
      model: { provider: 'openai', name: 'gpt-5.2' },
    },
    output_model: {
      model_identity_version: '1',
      tier: 'closed_opaque',
      model: { provider: 'openai', name: 'gpt-5.2' },
    },
    transform: { kind: 'other' },
    clawlogs: {
      inclusion_proof: proof.json,
    },
  };

  const envValid = await signEnvelope(payloadValid, signer, 'derivation_attestation');

  const verifyValid = curlJson(`${clawverifyBaseUrl}/v1/verify/derivation-attestation`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: { envelope: envValid },
    resolveIp: clawverifyResolveIp,
  });

  assert(
    verifyValid.status === 200,
    `verify valid expected 200, got ${verifyValid.status}: ${verifyValid.text}`,
  );
  assert(
    verifyValid.json?.result?.status === 'VALID',
    `verify valid expected VALID, got: ${verifyValid.text}`,
  );

  const badProof = JSON.parse(JSON.stringify(proof.json));
  if (Array.isArray(badProof.audit_path) && badProof.audit_path.length > 0) {
    badProof.audit_path[0] = maybeMutateB64u(badProof.audit_path[0]);
  } else {
    badProof.root_hash_b64u = maybeMutateB64u(String(badProof.root_hash_b64u));
  }

  const payloadBad = {
    ...payloadValid,
    derivation_id: `${payloadValid.derivation_id}_bad`,
    clawlogs: {
      inclusion_proof: badProof,
    },
  };
  const envBad = await signEnvelope(payloadBad, signer, 'derivation_attestation');

  const verifyBad = curlJson(`${clawverifyBaseUrl}/v1/verify/derivation-attestation`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: { envelope: envBad },
    resolveIp: clawverifyResolveIp,
  });

  assert(
    verifyBad.status === 422,
    `verify tampered expected 422, got ${verifyBad.status}: ${verifyBad.text}`,
  );
  assert(
    verifyBad.json?.result?.status === 'INVALID',
    `verify tampered expected INVALID, got: ${verifyBad.text}`,
  );

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        log_id: logId,
        clawlogs_base_url: clawlogsBaseUrl,
        clawverify_base_url: clawverifyBaseUrl,
        signer_did: signer.did,
        append: {
          status: append.status,
          leaf_hash_b64u: append.json?.leaf_hash_b64u,
          tree_size: append.json?.tree_size,
          root_hash_b64u: append.json?.root_hash_b64u,
        },
        root: {
          status: root.status,
          tree_size: root.json?.tree_size,
          root_hash_b64u: root.json?.root_hash_b64u,
          signer_did: root.json?.signature?.signer_did,
        },
        proof: {
          status: proof.status,
          tree_size: proof.json?.tree_size,
          leaf_hash_b64u: proof.json?.leaf_hash_b64u,
          root_hash_b64u: proof.json?.root_hash_b64u,
          audit_path_length: Array.isArray(proof.json?.audit_path) ? proof.json.audit_path.length : null,
        },
        verify_valid: {
          status: verifyValid.status,
          result_status: verifyValid.json?.result?.status,
          clawlogs_inclusion_proof_validated: verifyValid.json?.clawlogs_inclusion_proof_validated,
        },
        verify_tampered: {
          status: verifyBad.status,
          result_status: verifyBad.json?.result?.status,
          error_code: verifyBad.json?.error?.code,
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
