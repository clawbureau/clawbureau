import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyProofBundle } from '../src/verify-proof-bundle';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  const digits: number[] = [0];

  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i] * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  // Leading zeros
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d])
    .join('');
}

async function makeDidKeyEd25519(): Promise<{ did: string; privateKey: CryptoKey }> {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]);

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', keypair.publicKey)
  );

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  const did = `did:key:z${base58Encode(prefixed)}`;
  return { did, privateKey: keypair.privateKey };
}

describe('POH-US-015: URM materialization (hash-verified)', () => {
  it('fails closed when a URM reference is present but the URM document is not provided', async () => {
    const agent = await makeDidKeyEd25519();

    const runId = 'run_urm_001';
    const urmId = 'urm_001';

    const urmDoc: any = {
      urm_version: '1',
      urm_id: urmId,
      run_id: runId,
      agent_did: agent.did,
      issued_at: '2026-02-09T00:00:00Z',
      harness: { id: 'script', version: 'test' },
      inputs: [],
      outputs: [],
    };

    const urmHash = await computeHash(urmDoc, 'SHA-256');

    const bundlePayload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_urm_001',
      agent_did: agent.did,
      urm: {
        urm_version: '1',
        urm_id: urmId,
        resource_type: 'universal_run_manifest',
        resource_hash_b64u: urmHash,
      },
    };

    const bundlePayloadHash = await computeHash(bundlePayload, 'SHA-256');
    const bundleSigMsg = new TextEncoder().encode(bundlePayloadHash);
    const bundleSigBytes = new Uint8Array(
      await crypto.subtle.sign('Ed25519', agent.privateKey, bundleSigMsg)
    );

    const bundleEnvelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: bundlePayload,
      payload_hash_b64u: bundlePayloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(bundleSigBytes),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-09T00:00:01Z',
    };

    const out = await verifyProofBundle(bundleEnvelope);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('URM_MISSING');
    expect(out.error?.field).toBe('urm');
  });

  it('marks URM as valid when materialized URM is provided and hash matches reference', async () => {
    const agent = await makeDidKeyEd25519();

    const runId = 'run_urm_002';
    const urmId = 'urm_002';

    const urmDoc: any = {
      urm_version: '1',
      urm_id: urmId,
      run_id: runId,
      agent_did: agent.did,
      issued_at: '2026-02-09T00:00:00Z',
      harness: { id: 'script', version: 'test' },
      inputs: [],
      outputs: [],
    };

    const urmHash = await computeHash(urmDoc, 'SHA-256');

    const bundlePayload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_urm_002',
      agent_did: agent.did,
      urm: {
        urm_version: '1',
        urm_id: urmId,
        resource_type: 'universal_run_manifest',
        resource_hash_b64u: urmHash,
      },
    };

    const bundlePayloadHash = await computeHash(bundlePayload, 'SHA-256');
    const bundleSigMsg = new TextEncoder().encode(bundlePayloadHash);
    const bundleSigBytes = new Uint8Array(
      await crypto.subtle.sign('Ed25519', agent.privateKey, bundleSigMsg)
    );

    const bundleEnvelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: bundlePayload,
      payload_hash_b64u: bundlePayloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(bundleSigBytes),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-09T00:00:01Z',
    };

    const out = await verifyProofBundle(bundleEnvelope, { urm: urmDoc });

    expect(out.result.status).toBe('VALID');
    expect(out.result.component_results?.urm_valid).toBe(true);
  });

  it('fails closed when provided URM does not match the reference hash', async () => {
    const agent = await makeDidKeyEd25519();

    const runId = 'run_urm_003';
    const urmId = 'urm_003';

    const correctUrmDoc: any = {
      urm_version: '1',
      urm_id: urmId,
      run_id: runId,
      agent_did: agent.did,
      issued_at: '2026-02-09T00:00:00Z',
      harness: { id: 'script', version: 'test' },
      inputs: [],
      outputs: [],
    };

    const correctUrmHash = await computeHash(correctUrmDoc, 'SHA-256');

    const bundlePayload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_urm_003',
      agent_did: agent.did,
      urm: {
        urm_version: '1',
        urm_id: urmId,
        resource_type: 'universal_run_manifest',
        resource_hash_b64u: correctUrmHash,
      },
    };

    const bundlePayloadHash = await computeHash(bundlePayload, 'SHA-256');
    const bundleSigMsg = new TextEncoder().encode(bundlePayloadHash);
    const bundleSigBytes = new Uint8Array(
      await crypto.subtle.sign('Ed25519', agent.privateKey, bundleSigMsg)
    );

    const bundleEnvelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: bundlePayload,
      payload_hash_b64u: bundlePayloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(bundleSigBytes),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-09T00:00:01Z',
    };

    const wrongUrmDoc: any = {
      ...correctUrmDoc,
      outputs: [{ type: 'patch', hash_b64u: await computeHash({ nope: true }, 'SHA-256') }],
    };

    const out = await verifyProofBundle(bundleEnvelope, { urm: wrongUrmDoc });
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('HASH_MISMATCH');
    expect(out.error?.field).toBe('payload.urm.resource_hash_b64u');
  });
});
