import { describe, expect, it } from 'vitest';

import { verifyProofBundle } from '../src/verify-proof-bundle';

function b64u(len = 16): string {
  return 'a'.repeat(len);
}

function makeEvent(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    event_id: overrides.event_id ?? 'evt_policy_1',
    run_id: overrides.run_id ?? 'run_policy_1',
    event_type: overrides.event_type ?? 'llm_call',
    timestamp: overrides.timestamp ?? '2026-03-20T00:00:00Z',
    payload_hash_b64u: overrides.payload_hash_b64u ?? b64u(16),
    prev_hash_b64u: overrides.prev_hash_b64u === undefined ? null : overrides.prev_hash_b64u,
    event_hash_b64u: overrides.event_hash_b64u ?? b64u(16),
  };
}

describe('AF2-POL service verifier policy binding', () => {
  it('fails closed when policy_binding omits the signed policy bundle envelope', async () => {
    const event = makeEvent();
    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: {
        bundle_version: '1',
        bundle_id: 'bundle_policy_binding_missing_signed_bundle',
        agent_did: 'did:key:abc123',
        event_chain: [event],
        metadata: {
          policy_binding: {
            binding_version: '1',
            effective_policy_hash_b64u: b64u(32),
            effective_policy_snapshot: {
              snapshot_version: '1',
              resolver_version: 'org_project_task_exception.v1',
              context: { org_id: 'acme' },
              source_bundle: {
                bundle_id: 'bundle_policy_1',
                issuer_did: 'did:key:abc123',
                issued_at: '2026-03-20T00:00:00Z',
              },
              applied_layers: [
                {
                  layer_id: 'org',
                  scope_type: 'org',
                  org_id: 'acme',
                  priority: 0,
                  apply_mode: 'merge',
                  policy_hash_b64u: b64u(16),
                },
              ],
              effective_policy: {
                statements: [
                  {
                    sid: 'org.base',
                    effect: 'Allow',
                    actions: ['model:invoke'],
                    resources: ['*'],
                  },
                ],
              },
            },
          },
          sentinels: {
            interpose_active: true,
            egress_policy_receipt: {
              payload: {
                effective_policy_hash_b64u: b64u(32),
                binding: {
                  run_id: event.run_id,
                  event_hash_b64u: event.event_hash_b64u,
                },
              },
            },
          },
        },
      },
      payload_hash_b64u: b64u(16),
      hash_algorithm: 'SHA-256',
      signature_b64u: b64u(86),
      algorithm: 'Ed25519',
      signer_did: 'did:key:abc123',
      issued_at: '2026-03-20T00:00:01Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(out.error?.field).toBeTruthy();
  });
});
