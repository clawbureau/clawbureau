#!/usr/bin/env node

/**
 * Smoke: export bundle verifier endpoint
 *
 * Builds a minimal export bundle in-memory and verifies:
 * - VALID bundle returns 200/VALID
 * - tampered manifest hash returns 422/INVALID
 * - tampered inclusion proof (resigned bundle) returns 422/INVALID
 */

import process from 'node:process';
import { readFileSync, existsSync } from 'node:fs';
import crypto from 'node:crypto';

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

function jcsCanonicalize(value) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new Error('Non-finite number not allowed in JCS');
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
      for (const k of keys) parts.push(`${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`);
      return `{${parts.join(',')}}`;
    }
    default:
      throw new Error(`Unsupported value type for JCS: ${typeof value}`);
  }
}

async function sha256B64u(input) {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return b64u(new Uint8Array(digest));
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

  return { did: `did:key:z${base58Encode(prefixed)}`, privateKey };
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
    issued_at: '2026-02-11T00:00:00.000Z',
  };
}

async function manifestEntry(path, value) {
  const canonical = jcsCanonicalize(value);
  return {
    path,
    sha256_b64u: await sha256B64u(canonical),
    content_type: 'application/json',
    size_bytes: new TextEncoder().encode(canonical).byteLength,
  };
}

function mutateB64u(value) {
  const first = value[0] === 'A' ? 'B' : 'A';
  return `${first}${value.slice(1)}`;
}

function tryRead(path) {
  if (!existsSync(path)) return null;
  return readFileSync(path, 'utf8').trim();
}

async function buildBundle(signer, inclusionProof, options = {}) {
  const eventPayloadHash = await sha256B64u(JSON.stringify({ type: 'run_start' }));
  const eventHeader = {
    event_id: 'evt_export_smoke_001',
    run_id: 'run_export_smoke_001',
    event_type: 'run_start',
    timestamp: '2026-02-11T00:00:00.000Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null,
  };
  const eventHash = await sha256B64u(JSON.stringify(eventHeader));

  const proofBundlePayload = {
    bundle_version: '1',
    bundle_id: 'bundle_export_smoke_001',
    agent_did: signer.did,
    event_chain: [{ ...eventHeader, event_hash_b64u: eventHash }],
  };
  const proofBundleEnvelope = await signEnvelope(proofBundlePayload, signer, 'proof_bundle');

  const proofClone = JSON.parse(JSON.stringify(inclusionProof));
  if (options.tamperInclusionProof) {
    proofClone.audit_path[0] = mutateB64u(proofClone.audit_path[0]);
  }

  const derivationPayload = {
    derivation_version: '1',
    derivation_id: 'drv_export_smoke_001',
    issued_at: '2026-02-11T00:00:00.000Z',
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
    clawlogs: { inclusion_proof: proofClone },
  };
  const derivationEnvelope = await signEnvelope(derivationPayload, signer, 'derivation_attestation');

  const artifacts = {
    proof_bundle_envelope: proofBundleEnvelope,
    derivation_attestation_envelopes: [derivationEnvelope],
  };

  const manifestEntries = [
    await manifestEntry('artifacts/proof_bundle_envelope.json', proofBundleEnvelope),
    await manifestEntry('artifacts/derivation_attestation_envelopes/0.json', derivationEnvelope),
  ];

  if (options.tamperManifestHash) {
    manifestEntries[0] = {
      ...manifestEntries[0],
      sha256_b64u: mutateB64u(manifestEntries[0].sha256_b64u),
    };
  }

  const bundle = {
    export_version: '1',
    export_id: options.exportId ?? 'exp_smoke_001',
    created_at: '2026-02-11T00:00:00.000Z',
    issuer_did: signer.did,
    manifest: {
      manifest_version: '1',
      generated_at: '2026-02-11T00:00:00.000Z',
      entries: manifestEntries,
    },
    artifacts,
    bundle_hash_b64u: '',
    hash_algorithm: 'SHA-256',
    signature_b64u: '',
    algorithm: 'Ed25519',
    issued_at: '2026-02-11T00:00:00.000Z',
  };

  const signable = {
    export_version: bundle.export_version,
    export_id: bundle.export_id,
    created_at: bundle.created_at,
    issuer_did: bundle.issuer_did,
    manifest: bundle.manifest,
    artifacts: bundle.artifacts,
    issued_at: bundle.issued_at,
  };

  bundle.bundle_hash_b64u = await sha256B64u(jcsCanonicalize(signable));
  const sig = await crypto.subtle.sign('Ed25519', signer.privateKey, new TextEncoder().encode(bundle.bundle_hash_b64u));
  bundle.signature_b64u = b64u(new Uint8Array(sig));

  return bundle;
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

  const inclusionFixture = JSON.parse(
    readFileSync('/Users/gfw/clawd/tmp/clawbureau-poh-vnext-pr0/packages/schema/fixtures/log_inclusion_proof_golden.v1.json', 'utf8'),
  );
  const inclusionProof = inclusionFixture.inclusion_proof_v1;

  const validBundle = await buildBundle(signer, inclusionProof, { exportId: `exp_${envName}_valid` });
  const valid = await httpJson(`${verifyBaseUrl}/v1/verify/export-bundle`, { bundle: validBundle });
  assert(valid.status === 200, `valid export bundle expected 200, got ${valid.status}: ${valid.text}`);
  assert(valid.json?.result?.status === 'VALID', `valid export bundle expected VALID, got ${valid.text}`);

  const badHashBundle = await buildBundle(signer, inclusionProof, {
    exportId: `exp_${envName}_bad_hash`,
    tamperManifestHash: true,
  });
  const badHash = await httpJson(`${verifyBaseUrl}/v1/verify/export-bundle`, { bundle: badHashBundle });
  assert(badHash.status === 422, `tampered manifest expected 422, got ${badHash.status}: ${badHash.text}`);
  assert(badHash.json?.result?.status === 'INVALID', `tampered manifest expected INVALID, got ${badHash.text}`);

  const badProofBundle = await buildBundle(signer, inclusionProof, {
    exportId: `exp_${envName}_bad_proof`,
    tamperInclusionProof: true,
  });
  const badProof = await httpJson(`${verifyBaseUrl}/v1/verify/export-bundle`, { bundle: badProofBundle });
  assert(badProof.status === 422, `tampered proof expected 422, got ${badProof.status}: ${badProof.text}`);
  assert(badProof.json?.result?.status === 'INVALID', `tampered proof expected INVALID, got ${badProof.text}`);

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
          export_id: valid.json?.export_id,
          manifest_entries_verified: valid.json?.manifest_entries_verified,
        },
        tampered_manifest: {
          status: badHash.status,
          result_status: badHash.json?.result?.status,
          error_code: badHash.json?.error?.code,
        },
        tampered_proof: {
          status: badProof.status,
          result_status: badProof.json?.result?.status,
          error_code: badProof.json?.error?.code,
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
