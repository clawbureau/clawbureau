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

async function makeDidKeyEd25519(): Promise<{ did: string; privateKey: CryptoKey }> {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

  const publicKeyBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', keypair.publicKey),
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

async function signGatewayReceiptEnvelope(args: {
  signerDid: string;
  privateKey: CryptoKey;
  payload: Record<string, unknown>;
}) {
  const payloadHash = await computeHash(args.payload, 'SHA-256');
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', args.privateKey, new TextEncoder().encode(payloadHash)),
  );

  return {
    envelope_version: '1' as const,
    envelope_type: 'gateway_receipt' as const,
    payload: args.payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256' as const,
    signature_b64u: base64UrlEncode(signature),
    algorithm: 'Ed25519' as const,
    signer_did: args.signerDid,
    issued_at: '2026-02-17T00:00:00Z',
  };
}

function makeBasePayload() {
  return {
    receipt_version: '1',
    receipt_id: 'rcpt_x402_001',
    gateway_id: 'gw_x402_001',
    provider: 'openai',
    model: 'gpt-4.1',
    request_hash_b64u: 'req_hash_x402_001',
    response_hash_b64u: 'res_hash_x402_001',
    tokens_input: 100,
    tokens_output: 200,
    latency_ms: 250,
    timestamp: '2026-02-17T00:00:00Z',
    binding: {
      run_id: 'run_x402_001',
      event_hash_b64u: 'event_hash_x402_001',
    },
    metadata: {
      x402_payment_ref: '0xpaymentrefx402',
      x402_amount_minor: 1000,
      x402_currency: 'USDC',
      x402_network: 'base-sepolia',
      x402_payment_auth_hash_b64u: 'x402_payment_auth_hash_001',
    },
  };
}

describe('x402 receipt binding validation', () => {
  it('accepts valid x402 metadata + binding and surfaces deterministic reason code', async () => {
    const signer = await makeDidKeyEd25519();
    const envelope = await signGatewayReceiptEnvelope({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload: makeBasePayload(),
    });

    const out = await verifyReceipt(envelope, {
      allowlistedSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.x402_claimed).toBe(true);
    expect(out.x402_reason_code).toBe('X402_BOUND');
  });

  it('fails closed when x402 path is claimed but binding is missing', async () => {
    const signer = await makeDidKeyEd25519();
    const payload = makeBasePayload();
    delete (payload as Record<string, unknown>).binding;

    const envelope = await signGatewayReceiptEnvelope({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
    });

    const out = await verifyReceipt(envelope, {
      allowlistedSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.message).toBe('X402_BINDING_MISSING');
  });

  it('fails closed when x402 auth hash is malformed', async () => {
    const signer = await makeDidKeyEd25519();
    const payload = makeBasePayload();
    payload.metadata.x402_payment_auth_hash_b64u = '***';

    const envelope = await signGatewayReceiptEnvelope({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
    });

    const out = await verifyReceipt(envelope, {
      allowlistedSignerDids: [signer.did],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(out.error?.field).toBe('payload.metadata.x402_payment_auth_hash_b64u');
    expect(out.x402_reason_code).toBe('X402_PAYMENT_AUTH_HASH_INVALID');
  });
});
