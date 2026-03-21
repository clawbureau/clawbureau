import { describe, expect, it } from 'vitest';

import {
  didFromPublicKey,
  generateKeyPair,
  signEd25519,
} from '../../../packages/clawsig-sdk/dist/crypto.js';
import { computeHash } from '../src/crypto';
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

  it('fails closed when runner_measurement.manifest_hash_b64u does not match manifest', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);
    const eventHeader = makeEvent({
      event_id: 'evt_runner_measurement_1',
      run_id: 'run_runner_measurement_1',
      event_hash_b64u: undefined,
    });
    const { event_hash_b64u: _ignoredEventHash, ...eventBase } = eventHeader;
    const event = {
      ...eventBase,
      event_hash_b64u: await computeHash(eventBase, 'SHA-256'),
    };
    const payload = {
      bundle_version: '1',
      bundle_id: 'bundle_runner_measurement_hash_mismatch',
      agent_did: did,
      event_chain: [event],
      metadata: {
        runner_measurement: {
          binding_version: '1',
          hash_algorithm: 'SHA-256',
          manifest_hash_b64u: b64u(32),
          manifest: {
            manifest_version: '1',
            runtime: {
              platform: 'linux',
              arch: 'x64',
              node_version: 'v22.0.0',
            },
            proofed: {
              proofed_mode: true,
              clawproxy_url: 'https://clawproxy.example',
              allowed_proxy_destinations: ['clawproxy.example'],
              allowed_child_destinations: ['127.0.0.1'],
              sentinels: {
                shell_enabled: false,
                interpose_enabled: false,
                preload_enabled: true,
                fs_enabled: true,
                net_enabled: true,
              },
            },
            policy: {},
            artifacts: {
              preload_hash_b64u: b64u(43),
              node_preload_sentinel_hash_b64u: b64u(43),
              sentinel_shell_hash_b64u: null,
              sentinel_shell_policy_hash_b64u: null,
              interpose_library_hash_b64u: null,
            },
          },
        },
      },
    };
    const payloadHash = await computeHash(payload, 'SHA-256');
    const signature = await signEd25519(
      keyPair.privateKey,
      new TextEncoder().encode(payloadHash),
    );
    const envelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: signature,
      algorithm: 'Ed25519',
      signer_did: did,
      issued_at: '2026-03-20T00:00:01Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('HASH_MISMATCH');
    expect(out.error?.field).toBe(
      'payload.metadata.runner_measurement.manifest_hash_b64u',
    );
  });
});
