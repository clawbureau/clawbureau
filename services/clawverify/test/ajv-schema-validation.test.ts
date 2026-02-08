import { describe, expect, it } from 'vitest';

import { verifyProofBundle } from '../src/verify-proof-bundle';
import { verifyReceipt } from '../src/verify-receipt';

function b64u(len = 16): string {
  return 'a'.repeat(len);
}

describe('CVF-US-024: Ajv strict schema validation (fail-closed)', () => {
  it('rejects proof bundles with unknown fields (additionalProperties:false)', async () => {
    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: {
        bundle_version: '1',
        bundle_id: 'bundle_test_schema_001',
        agent_did: 'did:key:abc123',
        event_chain: [
          {
            event_id: 'evt_001',
            run_id: 'run_001',
            event_type: 'run_start',
            timestamp: '2026-02-07T00:00:00Z',
            payload_hash_b64u: b64u(16),
            prev_hash_b64u: null,
            event_hash_b64u: b64u(16),
            extra: 'nope',
          },
        ],
      },
      payload_hash_b64u: b64u(16),
      hash_algorithm: 'SHA-256',
      signature_b64u: b64u(86),
      algorithm: 'Ed25519',
      signer_did: 'did:key:abc123',
      issued_at: '2026-02-07T00:00:01Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(out.error?.field).toBe('payload.event_chain[0].extra');
  });

  it('rejects gateway receipt envelopes with unknown top-level fields (additionalProperties:false)', async () => {
    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'gateway_receipt',
      payload: {
        receipt_version: '1',
        receipt_id: 'rcpt_001',
        gateway_id: 'gw_001',
        provider: 'anthropic',
        model: 'claude-test',
        request_hash_b64u: b64u(16),
        response_hash_b64u: b64u(16),
        tokens_input: 1,
        tokens_output: 1,
        latency_ms: 1,
        timestamp: '2026-02-07T00:00:00Z',
      },
      payload_hash_b64u: b64u(16),
      hash_algorithm: 'SHA-256',
      signature_b64u: b64u(86),
      algorithm: 'Ed25519',
      signer_did: 'did:key:abc123',
      issued_at: '2026-02-07T00:00:01Z',
      extra: 'nope',
    };

    const out = await verifyReceipt(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(out.error?.field).toBe('extra');
  });
});
