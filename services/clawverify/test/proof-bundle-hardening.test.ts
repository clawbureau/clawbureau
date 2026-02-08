import { describe, expect, it } from 'vitest';

import { verifyProofBundle } from '../src/verify-proof-bundle';

function b64u(len = 16): string {
  return 'a'.repeat(len);
}

function makeEvent(overrides: Partial<any> = {}): any {
  return {
    event_id: overrides.event_id ?? 'evt_001',
    run_id: overrides.run_id ?? 'run_001',
    event_type: overrides.event_type ?? 'run_start',
    timestamp: overrides.timestamp ?? '2026-02-07T00:00:00Z',
    payload_hash_b64u: overrides.payload_hash_b64u ?? b64u(16),
    prev_hash_b64u:
      overrides.prev_hash_b64u === undefined ? null : overrides.prev_hash_b64u,
    event_hash_b64u: overrides.event_hash_b64u ?? b64u(16),
  };
}

function makeReceiptEnvelope(receiptId: string): any {
  return {
    envelope_version: '1',
    envelope_type: 'gateway_receipt',
    payload: {
      receipt_version: '1',
      receipt_id: receiptId,
      gateway_id: 'gw_001',
      provider: 'anthropic',
      model: 'claude-test',
      request_hash_b64u: b64u(16),
      response_hash_b64u: b64u(16),
      tokens_input: 0,
      tokens_output: 0,
      latency_ms: 1,
      timestamp: '2026-02-07T00:00:00Z',
    },
    payload_hash_b64u: b64u(16),
    hash_algorithm: 'SHA-256',
    signature_b64u: b64u(86),
    algorithm: 'Ed25519',
    signer_did: 'did:key:receiptSigner',
    issued_at: '2026-02-07T00:00:01Z',
  };
}

describe('CVF-US-025: proof bundle size/uniqueness hardening', () => {
  it('rejects duplicate event_id in payload.event_chain', async () => {
    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: {
        bundle_version: '1',
        bundle_id: 'bundle_dupe_event',
        agent_did: 'did:key:abc123',
        event_chain: [
          makeEvent({ event_id: 'evt_dupe', prev_hash_b64u: null }),
          makeEvent({
            event_id: 'evt_dupe',
            prev_hash_b64u: b64u(16),
            timestamp: '2026-02-07T00:00:01Z',
          }),
        ],
      },
      payload_hash_b64u: b64u(16),
      hash_algorithm: 'SHA-256',
      signature_b64u: b64u(86),
      algorithm: 'Ed25519',
      signer_did: 'did:key:abc123',
      issued_at: '2026-02-07T00:00:02Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('MALFORMED_ENVELOPE');
  });

  it('rejects duplicate receipt_id in payload.receipts', async () => {
    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: {
        bundle_version: '1',
        bundle_id: 'bundle_dupe_receipt',
        agent_did: 'did:key:abc123',
        receipts: [
          makeReceiptEnvelope('rcpt_dupe'),
          makeReceiptEnvelope('rcpt_dupe'),
        ],
      },
      payload_hash_b64u: b64u(16),
      hash_algorithm: 'SHA-256',
      signature_b64u: b64u(86),
      algorithm: 'Ed25519',
      signer_did: 'did:key:abc123',
      issued_at: '2026-02-07T00:00:02Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('MALFORMED_ENVELOPE');
  });

  it('rejects oversized payload.metadata', async () => {
    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: {
        bundle_version: '1',
        bundle_id: 'bundle_big_meta',
        agent_did: 'did:key:abc123',
        event_chain: [makeEvent({ event_id: 'evt_1', prev_hash_b64u: null })],
        metadata: {
          huge: 'a'.repeat(20_000),
        },
      },
      payload_hash_b64u: b64u(16),
      hash_algorithm: 'SHA-256',
      signature_b64u: b64u(86),
      algorithm: 'Ed25519',
      signer_did: 'did:key:abc123',
      issued_at: '2026-02-07T00:00:02Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('MALFORMED_ENVELOPE');
  });
});
