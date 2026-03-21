import { describe, expect, it } from 'vitest';

import {
  didFromPublicKey,
  generateKeyPair,
  signEd25519,
} from '../../../packages/clawsig-sdk/dist/crypto.js';
import {
  computeSignedPolicyBundlePayloadHashB64u,
  computeSignedPolicyLayerHashB64u,
} from '../../../packages/clawsig-sdk/dist/policy-resolution.js';
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

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((entry) => canonicalize(entry));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort((a, b) => a.localeCompare(b))) {
      out[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

async function buildSignedPolicyBundleEnvelope(args: {
  did: string;
  sign: (message: Uint8Array) => Promise<string>;
}) {
  const payload = {
    policy_bundle_version: '1' as const,
    bundle_id: 'bundle_runner_attestation_policy_1',
    issuer_did: args.did,
    issued_at: '2026-03-20T00:00:00.000Z',
    hash_algorithm: 'SHA-256' as const,
    layers: [
      {
        layer_id: 'org',
        scope: { scope_type: 'org', org_id: 'acme' as const },
        apply_mode: 'merge' as const,
        policy: {
          statements: [
            { sid: 'org.base', effect: 'Allow' as const, actions: ['model:invoke'], resources: ['*'] },
          ],
        },
        policy_hash_b64u: '',
      },
    ],
  };
  payload.layers[0]!.policy_hash_b64u = await computeSignedPolicyLayerHashB64u(
    payload.layers[0]!.policy,
  );
  const payloadHash = await computeSignedPolicyBundlePayloadHashB64u(payload);
  return {
    envelope_version: '1',
    envelope_type: 'policy_bundle',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: await args.sign(new TextEncoder().encode(payloadHash)),
    algorithm: 'Ed25519',
    signer_did: args.did,
    issued_at: payload.issued_at,
  };
}

async function buildSignedRunnerAttestationReceiptEnvelope(args: {
  did: string;
  sign: (message: Uint8Array) => Promise<string>;
  agentDid: string;
  runId: string;
  eventHashB64u: string;
  effectivePolicyHashB64u: string;
  manifest: {
    runtime: Record<string, unknown>;
    artifacts: {
      preload_hash_b64u: string | null;
      node_preload_sentinel_hash_b64u: string | null;
      sentinel_shell_hash_b64u: string | null;
      sentinel_shell_policy_hash_b64u: string | null;
      interpose_library_hash_b64u: string | null;
    };
  };
  manifestHashB64u: string;
  tamperSignature?: boolean;
}) {
  const payload = {
    receipt_version: '1',
    receipt_id: 'rar_service_policy_binding_1',
    hash_algorithm: 'SHA-256',
    agent_did: args.agentDid,
    timestamp: '2026-03-20T00:00:02.000Z',
    binding: {
      run_id: args.runId,
      event_hash_b64u: args.eventHashB64u,
    },
    runner_measurement: {
      manifest_hash_b64u: args.manifestHashB64u,
      runtime_hash_b64u: await computeHash(args.manifest.runtime, 'SHA-256'),
      artifacts: args.manifest.artifacts,
    },
    policy: {
      effective_policy_hash_b64u: args.effectivePolicyHashB64u,
    },
  };
  const payloadHash = await computeHash(payload, 'SHA-256');
  const signature = args.tamperSignature
    ? 'a'.repeat(86)
    : await args.sign(new TextEncoder().encode(payloadHash));
  return {
    envelope_version: '1',
    envelope_type: 'runner_attestation_receipt',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: args.did,
    issued_at: payload.timestamp,
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

  it('fails closed when runner_measurement is present but runner_attestation_receipt is missing', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);
    const eventHeader = makeEvent({
      event_id: 'evt_runner_attestation_missing_1',
      run_id: 'run_runner_attestation_missing_1',
      event_hash_b64u: undefined,
    });
    const { event_hash_b64u: _ignored, ...eventBase } = eventHeader;
    const event = {
      ...eventBase,
      event_hash_b64u: await computeHash(eventBase, 'SHA-256'),
    };
    const manifest = {
      manifest_version: '1',
      runtime: { platform: 'linux', arch: 'x64', node_version: 'v22.0.0' },
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
    };
    const payload = {
      bundle_version: '1',
      bundle_id: 'bundle_runner_attestation_missing_1',
      agent_did: did,
      event_chain: [event],
      metadata: {
        runner_measurement: {
          binding_version: '1',
          hash_algorithm: 'SHA-256',
          manifest_hash_b64u: await computeHash(manifest, 'SHA-256'),
          manifest,
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
    expect(out.error?.code).toBe('MISSING_REQUIRED_FIELD');
    expect(out.error?.field).toBe('payload.metadata.runner_attestation_receipt');
  });

  it('fails closed when runner_attestation_receipt is present without runner_measurement', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);
    const sign = (message: Uint8Array) => signEd25519(keyPair.privateKey, message);

    const eventHeader = makeEvent({
      event_id: 'evt_runner_attestation_requires_measurement_1',
      run_id: 'run_runner_attestation_requires_measurement_1',
      event_hash_b64u: undefined,
    });
    const { event_hash_b64u: _ignored, ...eventBase } = eventHeader;
    const event = {
      ...eventBase,
      event_hash_b64u: await computeHash(eventBase, 'SHA-256'),
    };

    const manifest = {
      runtime: { platform: 'linux', arch: 'x64', node_version: 'v22.0.0' },
      artifacts: {
        preload_hash_b64u: b64u(43),
        node_preload_sentinel_hash_b64u: b64u(43),
        sentinel_shell_hash_b64u: null,
        sentinel_shell_policy_hash_b64u: null,
        interpose_library_hash_b64u: null,
      },
    };
    const runnerAttestationEnvelope = await buildSignedRunnerAttestationReceiptEnvelope({
      did,
      sign,
      agentDid: did,
      runId: event.run_id,
      eventHashB64u: event.event_hash_b64u,
      effectivePolicyHashB64u: b64u(43),
      manifest,
      manifestHashB64u: await computeHash(manifest, 'SHA-256'),
    });

    const payload = {
      bundle_version: '1',
      bundle_id: 'bundle_runner_attestation_requires_measurement_1',
      agent_did: did,
      event_chain: [event],
      metadata: {
        runner_attestation_receipt: runnerAttestationEnvelope,
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
    expect(out.error?.code).toBe('MISSING_REQUIRED_FIELD');
    expect(out.error?.field).toBe('payload.metadata.runner_measurement');
  });

  it('fails closed when runner_attestation_receipt signature is forged', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);
    const sign = (message: Uint8Array) => signEd25519(keyPair.privateKey, message);

    const eventHeader = makeEvent({
      event_id: 'evt_runner_attestation_forged_1',
      run_id: 'run_runner_attestation_forged_1',
      event_hash_b64u: undefined,
    });
    const { event_hash_b64u: _ignored, ...eventBase } = eventHeader;
    const event = {
      ...eventBase,
      event_hash_b64u: await computeHash(eventBase, 'SHA-256'),
    };

    const signedPolicyBundleEnvelope = await buildSignedPolicyBundleEnvelope({
      did,
      sign,
    });
    const policySnapshot = {
      snapshot_version: '1',
      resolver_version: 'org_project_task_exception.v1',
      context: { org_id: 'acme' },
      source_bundle: {
        bundle_id: signedPolicyBundleEnvelope.payload.bundle_id,
        issuer_did: did,
        issued_at: signedPolicyBundleEnvelope.payload.issued_at,
      },
      applied_layers: [
        {
          layer_id: 'org',
          scope_type: 'org',
          org_id: 'acme',
          priority: 0,
          apply_mode: 'merge',
          policy_hash_b64u: signedPolicyBundleEnvelope.payload.layers[0]!.policy_hash_b64u,
        },
      ],
      effective_policy: {
        statements: [
          { sid: 'org.base', effect: 'Allow', actions: ['model:invoke'], resources: ['*'] },
        ],
      },
    };
    const effectivePolicyHash = await computeHash(canonicalize(policySnapshot), 'SHA-256');

    const egressPayload = {
      receipt_version: '1',
      receipt_id: 'epr_runner_attestation_1',
      policy_version: '1',
      policy_hash_b64u: await computeHash(
        {
          policy_version: '1',
          proofed_mode: true,
          clawproxy_url: 'https://clawproxy.example',
          allowed_proxy_destinations: ['clawproxy.example'],
          allowed_child_destinations: ['127.0.0.1'],
          direct_provider_access_blocked: true,
        },
        'SHA-256',
      ),
      effective_policy_hash_b64u: effectivePolicyHash,
      proofed_mode: true,
      clawproxy_url: 'https://clawproxy.example',
      allowed_proxy_destinations: ['clawproxy.example'],
      allowed_child_destinations: ['127.0.0.1'],
      direct_provider_access_blocked: true,
      blocked_attempt_count: 0,
      blocked_attempts_observed: false,
      hash_algorithm: 'SHA-256',
      agent_did: did,
      timestamp: '2026-03-20T00:00:02.000Z',
      binding: {
        run_id: event.run_id,
        event_hash_b64u: event.event_hash_b64u,
      },
    };
    const egressPayloadHash = await computeHash(egressPayload, 'SHA-256');
    const egressEnvelope = {
      envelope_version: '1',
      envelope_type: 'egress_policy_receipt',
      payload: egressPayload,
      payload_hash_b64u: egressPayloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await sign(new TextEncoder().encode(egressPayloadHash)),
      algorithm: 'Ed25519',
      signer_did: did,
      issued_at: egressPayload.timestamp,
    };

    const manifest = {
      manifest_version: '1',
      runtime: { platform: 'linux', arch: 'x64', node_version: 'v22.0.0' },
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
      policy: {
        effective_policy_hash_b64u: effectivePolicyHash,
      },
      artifacts: {
        preload_hash_b64u: b64u(43),
        node_preload_sentinel_hash_b64u: b64u(43),
        sentinel_shell_hash_b64u: null,
        sentinel_shell_policy_hash_b64u: null,
        interpose_library_hash_b64u: null,
      },
    };
    const runnerMeasurement = {
      binding_version: '1',
      hash_algorithm: 'SHA-256',
      manifest_hash_b64u: await computeHash(manifest, 'SHA-256'),
      manifest,
    };
    const runnerAttestationEnvelope = await buildSignedRunnerAttestationReceiptEnvelope({
      did,
      sign,
      agentDid: did,
      runId: event.run_id,
      eventHashB64u: event.event_hash_b64u,
      effectivePolicyHashB64u: effectivePolicyHash,
      manifest,
      manifestHashB64u: runnerMeasurement.manifest_hash_b64u,
      tamperSignature: true,
    });

    const payload = {
      bundle_version: '1',
      bundle_id: 'bundle_runner_attestation_forged_1',
      agent_did: did,
      event_chain: [event],
      metadata: {
        policy_binding: {
          binding_version: '1',
          effective_policy_hash_b64u: effectivePolicyHash,
          effective_policy_snapshot: policySnapshot,
          signed_policy_bundle_envelope: signedPolicyBundleEnvelope,
        },
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressEnvelope,
        },
        runner_measurement: runnerMeasurement,
        runner_attestation_receipt: runnerAttestationEnvelope,
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
      issued_at: '2026-03-20T00:00:03Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SIGNATURE_INVALID');
    expect(out.error?.field).toBe(
      'payload.metadata.runner_attestation_receipt.signature_b64u',
    );
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
