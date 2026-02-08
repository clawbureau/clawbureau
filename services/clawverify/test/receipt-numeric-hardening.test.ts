import { describe, expect, it } from 'vitest';

import { verifyReceipt } from '../src/verify-receipt';

function b64u(len = 16): string {
  return 'a'.repeat(len);
}

describe('CVF-US-025: receipt numeric hardening', () => {
  it('rejects non-finite numeric fields (Infinity)', async () => {
    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'gateway_receipt',
      payload: {
        receipt_version: '1',
        receipt_id: 'rcpt_inf',
        gateway_id: 'gw_001',
        provider: 'anthropic',
        model: 'claude-test',
        request_hash_b64u: b64u(16),
        response_hash_b64u: b64u(16),
        tokens_input: Number.POSITIVE_INFINITY,
        tokens_output: 0,
        latency_ms: 1,
        timestamp: '2026-02-07T00:00:00Z',
      },
      payload_hash_b64u: b64u(16),
      hash_algorithm: 'SHA-256',
      signature_b64u: b64u(86),
      algorithm: 'Ed25519',
      signer_did: 'did:key:abc123',
      issued_at: '2026-02-07T00:00:01Z',
    };

    const out = await verifyReceipt(envelope, {
      allowlistedSignerDids: ['did:key:abc123'],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('MALFORMED_ENVELOPE');
  });

  it('rejects non-integer token counts', async () => {
    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'gateway_receipt',
      payload: {
        receipt_version: '1',
        receipt_id: 'rcpt_float',
        gateway_id: 'gw_001',
        provider: 'anthropic',
        model: 'claude-test',
        request_hash_b64u: b64u(16),
        response_hash_b64u: b64u(16),
        tokens_input: 1.5,
        tokens_output: 0,
        latency_ms: 1,
        timestamp: '2026-02-07T00:00:00Z',
      },
      payload_hash_b64u: b64u(16),
      hash_algorithm: 'SHA-256',
      signature_b64u: b64u(86),
      algorithm: 'Ed25519',
      signer_did: 'did:key:abc123',
      issued_at: '2026-02-07T00:00:01Z',
    };

    const out = await verifyReceipt(envelope, {
      allowlistedSignerDids: ['did:key:abc123'],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('MALFORMED_ENVELOPE');
  });
});
