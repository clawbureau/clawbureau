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

async function makeDidKeyEd25519(): Promise<{
  did: string;
  privateKey: CryptoKey;
}> {
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

function tamperB64u(b64u: string): string {
  if (b64u.length === 0) return 'A';
  const last = b64u[b64u.length - 1];
  const replacement = last !== 'A' ? 'A' : 'B';
  return b64u.slice(0, -1) + replacement;
}

describe('verifyProofBundle: CVF-US-021 recompute event_hash_b64u', () => {
  it('accepts a bundle where event_hash_b64u matches canonical header hash', async () => {
    const agent = await makeDidKeyEd25519();

    const runId = 'run_test_001';

    const e1PayloadHash = await computeHash({ type: 'run_start' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_001',
      run_id: runId,
      event_type: 'run_start',
      timestamp: '2026-02-07T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1Hash = await computeHash(e1Header, 'SHA-256');

    const e2PayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
    const e2Header = {
      event_id: 'evt_002',
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-02-07T00:00:01Z',
      payload_hash_b64u: e2PayloadHash,
      prev_hash_b64u: e1Hash,
    };
    const e2Hash = await computeHash(e2Header, 'SHA-256');

    const payload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_test_001',
      agent_did: agent.did,
      event_chain: [
        {
          ...e1Header,
          event_hash_b64u: e1Hash,
        },
        {
          ...e2Header,
          event_hash_b64u: e2Hash,
        },
      ],
    };

    const payloadHash = await computeHash(payload, 'SHA-256');
    const sigMsg = new TextEncoder().encode(payloadHash);

    const signature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', agent.privateKey, sigMsg)
    );

    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(signature),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-07T00:00:02Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('VALID');
    expect(out.result.trust_tier).toBe('verified');
    expect(out.result.proof_tier).toBe('self');
    expect(out.result.component_results?.event_chain_valid).toBe(true);
  });

  it('rejects a bundle if any event_hash_b64u is tampered (even if chain links)', async () => {
    const agent = await makeDidKeyEd25519();

    const runId = 'run_test_002';

    const e1PayloadHash = await computeHash({ type: 'run_start' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_101',
      run_id: runId,
      event_type: 'run_start',
      timestamp: '2026-02-07T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1HashCorrect = await computeHash(e1Header, 'SHA-256');
    const e1HashTampered = tamperB64u(e1HashCorrect);

    const e2PayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
    const e2Header = {
      event_id: 'evt_102',
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-02-07T00:00:01Z',
      payload_hash_b64u: e2PayloadHash,
      prev_hash_b64u: e1HashTampered,
    };
    const e2Hash = await computeHash(e2Header, 'SHA-256');

    // Chain still links (e2.prev_hash points to e1.event_hash), but e1.event_hash is wrong.
    const payload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_test_002',
      agent_did: agent.did,
      event_chain: [
        {
          ...e1Header,
          event_hash_b64u: e1HashTampered,
        },
        {
          ...e2Header,
          event_hash_b64u: e2Hash,
        },
      ],
    };

    const payloadHash = await computeHash(payload, 'SHA-256');
    const sigMsg = new TextEncoder().encode(payloadHash);

    const signature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', agent.privateKey, sigMsg)
    );

    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(signature),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-07T00:00:02Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('HASH_MISMATCH');
  });

  it('rejects if envelope.signer_did does not equal payload.agent_did (CVF-US-022)', async () => {
    const agent = await makeDidKeyEd25519();
    const signer = await makeDidKeyEd25519();

    const runId = 'run_test_003';

    const e1PayloadHash = await computeHash({ type: 'run_start' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_201',
      run_id: runId,
      event_type: 'run_start',
      timestamp: '2026-02-07T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1Hash = await computeHash(e1Header, 'SHA-256');

    const payload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_test_003',
      agent_did: agent.did,
      event_chain: [
        {
          ...e1Header,
          event_hash_b64u: e1Hash,
        },
      ],
    };

    const payloadHash = await computeHash(payload, 'SHA-256');
    const sigMsg = new TextEncoder().encode(payloadHash);

    const signature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', signer.privateKey, sigMsg)
    );

    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(signature),
      algorithm: 'Ed25519',
      signer_did: signer.did,
      issued_at: '2026-02-07T00:00:02Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('INVALID_DID_FORMAT');
  });
});
