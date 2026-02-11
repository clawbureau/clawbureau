import { describe, expect, it } from 'vitest';

import fixture from '../../../packages/schema/fixtures/web_receipt_golden.v1.json';
import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyWebReceipt } from '../src/verify-web-receipt';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  const digits: number[] = [0];

  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i]! * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d]!)
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

async function signEnvelope(payload: unknown, signer: { did: string; privateKey: CryptoKey }) {
  const payloadHash = await computeHash(payload, 'SHA-256');
  const msg = new TextEncoder().encode(payloadHash);
  const sigBytes = new Uint8Array(await crypto.subtle.sign('Ed25519', signer.privateKey, msg));

  return {
    envelope_version: '1',
    envelope_type: 'web_receipt',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: base64UrlEncode(sigBytes),
    algorithm: 'Ed25519',
    signer_did: signer.did,
    issued_at: '2026-02-11T00:00:00Z',
  };
}

type WebReceiptFixture = {
  envelope: any;
};

const goldenEnvelope = (fixture as WebReceiptFixture).envelope;

describe('POH-US-018: witnessed web receipt verification', () => {
  it('verifies golden fixture envelope', async () => {
    const out = await verifyWebReceipt(goldenEnvelope, {
      allowlistedSignerDids: [goldenEnvelope.signer_did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.proof_tier).toBe('witnessed_web');
    expect(out.equivalent_to_gateway).toBe(false);
  });

  it('verifies a valid web receipt and keeps it distinct from gateway', async () => {
    const signer = await makeDidKeyEd25519();

    const payload = {
      receipt_version: '1',
      receipt_id: 'web_rcpt_001',
      witness_id: 'witness_cluster_a',
      source: 'chatgpt_web',
      request_hash_b64u: 'requestHASHb64u_12345678',
      response_hash_b64u: 'responseHASHb64u_12345678',
      session_hash_b64u: 'sessionHASHb64u_12345678',
      timestamp: '2026-02-11T00:00:00Z',
      binding: {
        run_id: 'run_web_001',
        event_hash_b64u: 'eventHASHb64u_12345678',
        nonce: 'nonce_web_001',
      },
    };

    const envelope = await signEnvelope(payload, signer);

    const out = await verifyWebReceipt(envelope, {
      allowlistedSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.witness_id).toBe('witness_cluster_a');
    expect(out.source).toBe('chatgpt_web');
    expect(out.proof_tier).toBe('witnessed_web');
    expect(out.equivalent_to_gateway).toBe(false);
  });

  it('fails closed when WEB_RECEIPT_SIGNER_DIDS is not configured', async () => {
    const signer = await makeDidKeyEd25519();

    const payload = {
      receipt_version: '1',
      receipt_id: 'web_rcpt_002',
      witness_id: 'witness_cluster_a',
      source: 'claude_web',
      request_hash_b64u: 'requestHASHb64u_ABCDEFGH',
      response_hash_b64u: 'responseHASHb64u_ABCDEFGH',
      timestamp: '2026-02-11T00:00:00Z',
    };

    const envelope = await signEnvelope(payload, signer);

    const out = await verifyWebReceipt(envelope, {
      allowlistedSignerDids: [],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('DEPENDENCY_NOT_CONFIGURED');
  });

  it('rejects tampered signature', async () => {
    const signer = await makeDidKeyEd25519();

    const payload = {
      receipt_version: '1',
      receipt_id: 'web_rcpt_003',
      witness_id: 'witness_cluster_a',
      source: 'gemini_web',
      request_hash_b64u: 'requestHASHb64u_XYZ12345',
      response_hash_b64u: 'responseHASHb64u_XYZ12345',
      timestamp: '2026-02-11T00:00:00Z',
    };

    const envelope: any = await signEnvelope(payload, signer);
    envelope.signature_b64u = base64UrlEncode(crypto.getRandomValues(new Uint8Array(64)));

    const out = await verifyWebReceipt(envelope, {
      allowlistedSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SIGNATURE_INVALID');
  });
});
