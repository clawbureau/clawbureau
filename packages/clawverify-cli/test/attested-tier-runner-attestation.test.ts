import { describe, expect, it } from 'vitest';

import {
  computeSignedPolicyBundlePayloadHashB64u,
  computeSignedPolicyLayerHashB64u,
} from '../../clawsig-sdk/src/policy-resolution.js';
import {
  didFromPublicKey,
  generateKeyPair,
  signEd25519,
} from '../../clawsig-sdk/src/crypto.js';
import { computeHash } from '../../clawverify-core/src/crypto.js';
import { verifyProofBundle } from '../../clawverify-core/src/verify-proof-bundle.js';

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

function b64u(len = 16): string {
  return 'a'.repeat(len);
}

async function buildSignedPolicyBundleEnvelope(args: {
  did: string;
  sign: (message: Uint8Array) => Promise<string>;
}) {
  const payload = {
    policy_bundle_version: '1' as const,
    bundle_id: 'bundle_core_runner_attestation_policy_1',
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
    receipt_id: 'rar_core_runner_attestation_1',
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

describe('AF2-ATT-003 core attested tier', () => {
  it('grants attested tier only when runner attestation is valid', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);
    const sign = (message: Uint8Array) => signEd25519(keyPair.privateKey, message);

    const eventHeader = {
      event_id: 'evt_core_runner_attested_1',
      run_id: 'run_core_runner_attested_1',
      event_type: 'llm_call',
      timestamp: '2026-03-20T00:00:01.000Z',
      payload_hash_b64u: b64u(16),
      prev_hash_b64u: null,
    };
    const eventHash = await computeHash(eventHeader, 'SHA-256');

    const signedPolicyBundleEnvelope = await buildSignedPolicyBundleEnvelope({ did, sign });
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

    const manifest = {
      manifest_version: '1' as const,
      runtime: { platform: 'linux', arch: 'x64', node_version: 'v22.0.0' },
      proofed: {
        proofed_mode: true as const,
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
    const runnerAttestationReceipt = await buildSignedRunnerAttestationReceiptEnvelope({
      did,
      sign,
      agentDid: did,
      runId: eventHeader.run_id,
      eventHashB64u: eventHash,
      effectivePolicyHashB64u: effectivePolicyHash,
      manifest,
      manifestHashB64u: runnerMeasurement.manifest_hash_b64u,
    });
    const egressPolicyDescriptor = {
      policy_version: '1',
      proofed_mode: true,
      clawproxy_url: 'https://clawproxy.example',
      allowed_proxy_destinations: ['clawproxy.example'],
      allowed_child_destinations: ['127.0.0.1'],
      direct_provider_access_blocked: true,
    };
    const egressPayload = {
      receipt_version: '1',
      receipt_id: 'epr_core_runner_attested_1',
      policy_version: '1',
      policy_hash_b64u: await computeHash(egressPolicyDescriptor, 'SHA-256'),
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
        run_id: eventHeader.run_id,
        event_hash_b64u: eventHash,
      },
    };
    const egressPayloadHash = await computeHash(egressPayload, 'SHA-256');
    const egressPolicyReceipt = {
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

    const payload = {
      bundle_version: '1',
      bundle_id: 'bundle_core_runner_attested_1',
      agent_did: did,
      event_chain: [{ ...eventHeader, event_hash_b64u: eventHash }],
      metadata: {
        policy_binding: {
          binding_version: '1',
          effective_policy_hash_b64u: effectivePolicyHash,
          effective_policy_snapshot: policySnapshot,
          signed_policy_bundle_envelope: signedPolicyBundleEnvelope,
        },
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: egressPolicyReceipt,
        },
        runner_measurement: runnerMeasurement,
        runner_attestation_receipt: runnerAttestationReceipt,
      },
    };

    const payloadHash = await computeHash(payload, 'SHA-256');
    const envelope = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await sign(new TextEncoder().encode(payloadHash)),
      algorithm: 'Ed25519',
      signer_did: did,
      issued_at: '2026-03-20T00:00:03.000Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('VALID');
    expect(out.result.trust_tier).toBe('attested');
    expect(out.result.component_results?.runner_attestation_present).toBe(true);
    expect(out.result.component_results?.runner_attestation_valid).toBe(true);
    expect(out.result.component_results?.attested_assurance_reason_code).toBe(
      'ATTESTED_TIER_GRANTED',
    );
  });

  it('keeps observed runs non-attested when runner attestation is missing', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);

    const eventHeader = {
      event_id: 'evt_core_observed_1',
      run_id: 'run_core_observed_1',
      event_type: 'llm_call',
      timestamp: '2026-03-20T00:00:01.000Z',
      payload_hash_b64u: b64u(16),
      prev_hash_b64u: null,
    };
    const eventHash = await computeHash(eventHeader, 'SHA-256');

    const payload = {
      bundle_version: '1',
      bundle_id: 'bundle_core_observed_1',
      agent_did: did,
      event_chain: [{ ...eventHeader, event_hash_b64u: eventHash }],
    };

    const payloadHash = await computeHash(payload, 'SHA-256');
    const envelope = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await signEd25519(keyPair.privateKey, new TextEncoder().encode(payloadHash)),
      algorithm: 'Ed25519',
      signer_did: did,
      issued_at: '2026-03-20T00:00:03.000Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('VALID');
    expect(out.result.trust_tier).toBe('verified');
    expect(out.result.component_results?.runner_attestation_present).toBe(false);
    expect(out.result.component_results?.runner_attestation_valid).toBe(false);
    expect(out.result.component_results?.attested_assurance_reason_code).toBe(
      'ATTESTED_TIER_NOT_GRANTED_NO_RUNNER_ATTESTATION',
    );
  });

  it('surfaces invalid attested-tier evidence when runner measurement is malformed', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);

    const eventHeader = {
      event_id: 'evt_core_runner_measurement_invalid_1',
      run_id: 'run_core_runner_measurement_invalid_1',
      event_type: 'llm_call',
      timestamp: '2026-03-20T00:00:01.000Z',
      payload_hash_b64u: b64u(16),
      prev_hash_b64u: null,
    };
    const eventHash = await computeHash(eventHeader, 'SHA-256');

    const payload = {
      bundle_version: '1',
      bundle_id: 'bundle_core_runner_measurement_invalid_1',
      agent_did: did,
      event_chain: [{ ...eventHeader, event_hash_b64u: eventHash }],
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
    const envelope = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: await signEd25519(keyPair.privateKey, new TextEncoder().encode(payloadHash)),
      algorithm: 'Ed25519',
      signer_did: did,
      issued_at: '2026-03-20T00:00:03.000Z',
    };

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('HASH_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.runner_measurement.manifest_hash_b64u');
    expect(out.result.component_results?.runner_attestation_present).toBe(false);
    expect(out.result.component_results?.attested_assurance_reason_code).toBe(
      'ATTESTED_TIER_NOT_GRANTED_INVALID_RUNNER_ATTESTATION',
    );
  });
});
