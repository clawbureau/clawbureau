import { describe, expect, it } from 'vitest';

import { base64UrlEncode } from '../src/crypto';
import { jcsCanonicalize } from '../src/jcs';
import { verifyDidRotation } from '../src/verify-did-rotation';

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
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}> {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]);

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', keypair.publicKey)
  );

  // did:key:z + base58btc(0xed01 || pub)
  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  const did = `did:key:z${base58Encode(prefixed)}`;

  return {
    did,
    publicKey: keypair.publicKey,
    privateKey: keypair.privateKey,
  };
}

describe('verifyDidRotation', () => {
  it('verifies a valid did_rotation certificate signed by both old and new DIDs', async () => {
    const oldIdentity = await makeDidKeyEd25519();
    const newIdentity = await makeDidKeyEd25519();

    const certificate: any = {
      rotation_version: '1',
      rotation_id: 'rot_test_001',
      old_did: oldIdentity.did,
      new_did: newIdentity.did,
      issued_at: '2026-02-07T00:00:00Z',
      reason: 'operator_rotation',
      signature_old_b64u: '',
      signature_new_b64u: '',
    };

    const canonical = jcsCanonicalize({
      ...certificate,
      signature_old_b64u: '',
      signature_new_b64u: '',
    });
    const msg = new TextEncoder().encode(canonical);

    const sigOld = new Uint8Array(
      await crypto.subtle.sign('Ed25519', oldIdentity.privateKey, msg)
    );
    const sigNew = new Uint8Array(
      await crypto.subtle.sign('Ed25519', newIdentity.privateKey, msg)
    );

    certificate.signature_old_b64u = base64UrlEncode(sigOld);
    certificate.signature_new_b64u = base64UrlEncode(sigNew);

    const out = await verifyDidRotation(certificate);
    expect(out.result.status).toBe('VALID');
    expect(out.old_did).toBe(oldIdentity.did);
    expect(out.new_did).toBe(newIdentity.did);
  });

  it('fails if the certificate is tampered after signing', async () => {
    const oldIdentity = await makeDidKeyEd25519();
    const newIdentity = await makeDidKeyEd25519();

    const certificate: any = {
      rotation_version: '1',
      rotation_id: 'rot_test_002',
      old_did: oldIdentity.did,
      new_did: newIdentity.did,
      issued_at: '2026-02-07T00:00:00Z',
      reason: 'operator_rotation',
      signature_old_b64u: '',
      signature_new_b64u: '',
    };

    const canonical = jcsCanonicalize({
      ...certificate,
      signature_old_b64u: '',
      signature_new_b64u: '',
    });
    const msg = new TextEncoder().encode(canonical);

    certificate.signature_old_b64u = base64UrlEncode(
      new Uint8Array(
        await crypto.subtle.sign('Ed25519', oldIdentity.privateKey, msg)
      )
    );
    certificate.signature_new_b64u = base64UrlEncode(
      new Uint8Array(
        await crypto.subtle.sign('Ed25519', newIdentity.privateKey, msg)
      )
    );

    certificate.reason = 'attacker_modified_reason';

    const out = await verifyDidRotation(certificate);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SIGNATURE_INVALID');
  });

  it('fails closed on unknown fields', async () => {
    const out = await verifyDidRotation({
      rotation_version: '1',
      rotation_id: 'rot_test_003',
      old_did: 'did:key:z6Mk...',
      new_did: 'did:key:z6Mk...',
      issued_at: '2026-02-07T00:00:00Z',
      reason: 'operator_rotation',
      signature_old_b64u: 'abc',
      signature_new_b64u: 'def',
      extra: 'nope',
    } as any);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('MALFORMED_ENVELOPE');
  });
});
