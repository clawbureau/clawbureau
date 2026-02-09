import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { jcsCanonicalize } from '../src/jcs';
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

async function signProofBundleEnvelope(agent: {
  did: string;
  privateKey: CryptoKey;
}, payload: any) {
  const payloadHash = await computeHash(payload, 'SHA-256');
  const sigMsg = new TextEncoder().encode(payloadHash);
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign('Ed25519', agent.privateKey, sigMsg)
  );

  return {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: base64UrlEncode(signatureBytes),
    algorithm: 'Ed25519',
    signer_did: agent.did,
    issued_at: '2026-02-07T00:00:02Z',
  };
}

describe('verifyProofBundle: CVF-US-023 attestation signatures + allowlist', () => {
  it('does not uplift trust tier for shape-only/invalid attestations', async () => {
    const agent = await makeDidKeyEd25519();
    const attester = await makeDidKeyEd25519();

    const runId = 'run_att_001';

    const payloadHash = await computeHash({ type: 'run_start' }, 'SHA-256');
    const header = {
      event_id: 'evt_a1',
      run_id: runId,
      event_type: 'run_start',
      timestamp: '2026-02-07T00:00:00Z',
      payload_hash_b64u: payloadHash,
      prev_hash_b64u: null as string | null,
    };
    const eventHash = await computeHash(header, 'SHA-256');

    // Invalid signature (random bytes) — structurally correct but not verifiable
    const randomSig = crypto.getRandomValues(new Uint8Array(64));

    const payload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_att_001',
      agent_did: agent.did,
      event_chain: [
        {
          ...header,
          event_hash_b64u: eventHash,
        },
      ],
      attestations: [
        {
          attestation_id: 'att_001',
          attestation_type: 'third_party',
          attester_did: attester.did,
          subject_did: agent.did,
          signature_b64u: base64UrlEncode(randomSig),
        },
      ],
    };

    const envelope = await signProofBundleEnvelope(agent, payload);

    const out = await verifyProofBundle(envelope as any, {
      allowlistedAttesterDids: [attester.did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.trust_tier).toBe('verified');
    expect(out.result.proof_tier).toBe('self');

    expect(out.result.component_results?.attestations_count).toBe(1);
    expect(out.result.component_results?.attestations_signature_verified_count).toBe(0);
    expect(out.result.component_results?.attestations_verified_count).toBe(0);
    expect(out.result.component_results?.attestations_valid).toBe(false);
  });

  it('uplifts to attested when attestation signature verifies and attester is allowlisted', async () => {
    const agent = await makeDidKeyEd25519();
    const attester = await makeDidKeyEd25519();

    const runId = 'run_att_002';

    const payloadHash = await computeHash({ type: 'run_start' }, 'SHA-256');
    const header = {
      event_id: 'evt_b1',
      run_id: runId,
      event_type: 'run_start',
      timestamp: '2026-02-07T00:00:00Z',
      payload_hash_b64u: payloadHash,
      prev_hash_b64u: null as string | null,
    };
    const eventHash = await computeHash(header, 'SHA-256');

    const attestationUnsigned: any = {
      attestation_id: 'att_002',
      attestation_type: 'third_party',
      attester_did: attester.did,
      subject_did: agent.did,
      signature_b64u: '',
    };

    const canonical = jcsCanonicalize(attestationUnsigned);
    const msgBytes = new TextEncoder().encode(canonical);

    const signatureBytes = new Uint8Array(
      await crypto.subtle.sign('Ed25519', attester.privateKey, msgBytes)
    );

    const attestationSigned = {
      ...attestationUnsigned,
      signature_b64u: base64UrlEncode(signatureBytes),
    };

    const payload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_att_002',
      agent_did: agent.did,
      event_chain: [
        {
          ...header,
          event_hash_b64u: eventHash,
        },
      ],
      attestations: [attestationSigned],
    };

    const envelope = await signProofBundleEnvelope(agent, payload);

    const out = await verifyProofBundle(envelope as any, {
      allowlistedAttesterDids: [attester.did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.trust_tier).toBe('attested');
    expect(out.result.proof_tier).toBe('sandbox');

    expect(out.result.component_results?.attestations_count).toBe(1);
    expect(out.result.component_results?.attestations_signature_verified_count).toBe(1);
    expect(out.result.component_results?.attestations_verified_count).toBe(1);
    expect(out.result.component_results?.attestations_valid).toBe(true);
  });

  it('does not uplift when signature verifies but attester is not allowlisted', async () => {
    const agent = await makeDidKeyEd25519();
    const attester = await makeDidKeyEd25519();

    const runId = 'run_att_003';

    const payloadHash = await computeHash({ type: 'run_start' }, 'SHA-256');
    const header = {
      event_id: 'evt_c1',
      run_id: runId,
      event_type: 'run_start',
      timestamp: '2026-02-07T00:00:00Z',
      payload_hash_b64u: payloadHash,
      prev_hash_b64u: null as string | null,
    };
    const eventHash = await computeHash(header, 'SHA-256');

    const attestationUnsigned: any = {
      attestation_id: 'att_003',
      attestation_type: 'third_party',
      attester_did: attester.did,
      subject_did: agent.did,
      signature_b64u: '',
    };

    const canonical = jcsCanonicalize(attestationUnsigned);
    const msgBytes = new TextEncoder().encode(canonical);

    const signatureBytes = new Uint8Array(
      await crypto.subtle.sign('Ed25519', attester.privateKey, msgBytes)
    );

    const attestationSigned = {
      ...attestationUnsigned,
      signature_b64u: base64UrlEncode(signatureBytes),
    };

    const payload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_att_003',
      agent_did: agent.did,
      event_chain: [
        {
          ...header,
          event_hash_b64u: eventHash,
        },
      ],
      attestations: [attestationSigned],
    };

    const envelope = await signProofBundleEnvelope(agent, payload);

    const out = await verifyProofBundle(envelope as any, {
      allowlistedAttesterDids: [],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.trust_tier).toBe('verified');
    expect(out.result.proof_tier).toBe('self');

    expect(out.result.component_results?.attestations_signature_verified_count).toBe(1);
    expect(out.result.component_results?.attestations_verified_count).toBe(0);
    expect(out.result.component_results?.attestations_valid).toBe(false);
  });
});
