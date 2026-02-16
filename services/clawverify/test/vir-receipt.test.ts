import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyReceipt } from '../src/verify-receipt';

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

  return {
    did: `did:key:z${base58Encode(prefixed)}`,
    privateKey: keypair.privateKey,
  };
}

async function makeVirEnvelope(options?: { nonce?: string }) {
  const signer = await makeDidKeyEd25519();

  const payload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: 'vir_rcpt_001',
    source: 'tls_decrypt',
    provider: 'anthropic',
    model: 'claude-test',
    model_claimed: 'claude-test',
    model_observed: 'claude-test',
    request_hash_b64u: 'req_hash_001',
    response_hash_b64u: 'res_hash_001',
    tokens_input: 10,
    tokens_output: 20,
    latency_ms: 80,
    agent_did: signer.did,
    timestamp: '2026-02-16T00:00:00Z',
    binding: {
      run_id: 'run_vir_receipt',
      nonce: options?.nonce,
    },
    transport_attestation: {
      source: 'tls_decrypt',
      decrypted_match: true,
    },
  };

  const payloadHash = await computeHash(payload, 'SHA-256');
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign('Ed25519', signer.privateKey, new TextEncoder().encode(payloadHash))
  );

  return {
    envelope: {
      envelope_version: '1' as const,
      envelope_type: 'vir_receipt' as const,
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256' as const,
      signature_b64u: base64UrlEncode(sigBytes),
      algorithm: 'Ed25519' as const,
      signer_did: signer.did,
      issued_at: '2026-02-16T00:00:00Z',
    },
    signer,
  };
}

describe('VIR receipt verification', () => {
  it('verifies a valid vir_receipt envelope', async () => {
    const { envelope } = await makeVirEnvelope({ nonce: 'nonce_ok' });

    const out = await verifyReceipt(envelope);

    expect(out.result.status).toBe('VALID');
    expect(out.result.envelope_type).toBe('vir_receipt');
    expect(out.provider).toBe('anthropic');
    expect(out.model).toBe('claude-test');
  });

  it('enforces requiresJobBinding for VIR receipts', async () => {
    const { envelope } = await makeVirEnvelope();

    const out = await verifyReceipt(envelope, { requiresJobBinding: true });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('MISSING_NONCE');
  });
});
