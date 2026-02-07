import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { jcsCanonicalize } from '../src/jcs';
import { verifyAgent } from '../src/verify-agent';

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
  publicKey: CryptoKey;
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

  return { did, publicKey: keypair.publicKey, privateKey: keypair.privateKey };
}

describe('verifyAgent: rotation-aware subject binding', () => {
  it('accepts an owner attestation for old DID when a valid rotation cert links old→new', async () => {
    const oldAgent = await makeDidKeyEd25519();
    const newAgent = await makeDidKeyEd25519();
    const attester = await makeDidKeyEd25519();

    // Rotation cert (old → new)
    const rotationCert: any = {
      rotation_version: '1',
      rotation_id: 'rot_agent_001',
      old_did: oldAgent.did,
      new_did: newAgent.did,
      issued_at: '2026-02-07T00:00:00Z',
      reason: 'operator_rotation',
      signature_old_b64u: '',
      signature_new_b64u: '',
    };

    const canonical = jcsCanonicalize({
      ...rotationCert,
      signature_old_b64u: '',
      signature_new_b64u: '',
    });
    const msg = new TextEncoder().encode(canonical);

    rotationCert.signature_old_b64u = base64UrlEncode(
      new Uint8Array(
        await crypto.subtle.sign('Ed25519', oldAgent.privateKey, msg)
      )
    );
    rotationCert.signature_new_b64u = base64UrlEncode(
      new Uint8Array(
        await crypto.subtle.sign('Ed25519', newAgent.privateKey, msg)
      )
    );

    // Owner attestation signed by attester, subject is *old* DID
    const ownerPayload: any = {
      attestation_version: '1',
      attestation_id: 'att_001',
      subject_did: oldAgent.did,
      provider_ref: 'ref_test',
    };

    const ownerEnvelope: any = {
      envelope_version: '1',
      envelope_type: 'owner_attestation',
      payload: ownerPayload,
      payload_hash_b64u: await computeHash(ownerPayload, 'SHA-256'),
      hash_algorithm: 'SHA-256',
      signature_b64u: '',
      algorithm: 'Ed25519',
      signer_did: attester.did,
      issued_at: '2026-02-07T00:00:00Z',
    };

    const ownerSigMsg = new TextEncoder().encode(ownerEnvelope.payload_hash_b64u);
    ownerEnvelope.signature_b64u = base64UrlEncode(
      new Uint8Array(
        await crypto.subtle.sign('Ed25519', attester.privateKey, ownerSigMsg)
      )
    );

    const res = await verifyAgent({
      agent_did: newAgent.did,
      owner_attestation_envelope: ownerEnvelope,
      did_rotation_certificates: [rotationCert],
    });

    expect(res.result.status).toBe('VALID');
    expect(res.owner_status).toBe('verified');
    expect(res.risk_flags ?? []).toContain('OWNER_ATTESTATION_SUBJECT_ROTATED');
  });

  it('fails closed if subject_did mismatches and no rotation cert is provided', async () => {
    const oldAgent = await makeDidKeyEd25519();
    const newAgent = await makeDidKeyEd25519();
    const attester = await makeDidKeyEd25519();

    const ownerPayload: any = {
      attestation_version: '1',
      attestation_id: 'att_002',
      subject_did: oldAgent.did,
      provider_ref: 'ref_test',
    };

    const ownerEnvelope: any = {
      envelope_version: '1',
      envelope_type: 'owner_attestation',
      payload: ownerPayload,
      payload_hash_b64u: await computeHash(ownerPayload, 'SHA-256'),
      hash_algorithm: 'SHA-256',
      signature_b64u: '',
      algorithm: 'Ed25519',
      signer_did: attester.did,
      issued_at: '2026-02-07T00:00:00Z',
    };

    const ownerSigMsg = new TextEncoder().encode(ownerEnvelope.payload_hash_b64u);
    ownerEnvelope.signature_b64u = base64UrlEncode(
      new Uint8Array(
        await crypto.subtle.sign('Ed25519', attester.privateKey, ownerSigMsg)
      )
    );

    const res = await verifyAgent({
      agent_did: newAgent.did,
      owner_attestation_envelope: ownerEnvelope,
    });

    expect(res.result.status).toBe('INVALID');
    expect(res.error?.code).toBe('INVALID_DID_FORMAT');
  });
});
