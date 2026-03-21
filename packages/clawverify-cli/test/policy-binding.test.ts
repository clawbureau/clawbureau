import { describe, expect, it } from 'vitest';

import {
  computeSignedPolicyBundlePayloadHashB64u,
  computeSignedPolicyLayerHashB64u,
  resolveEffectivePolicyFromSignedBundle,
} from '../../clawsig-sdk/src/policy-resolution.js';
import {
  hashJsonB64u,
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

async function buildSignedPolicyBundleEnvelope(
  payloadInput: Record<string, unknown>,
  did: string,
  sign: (message: Uint8Array) => Promise<string>,
): Promise<Record<string, unknown>> {
  const payload = structuredClone(payloadInput) as {
    layers: Array<{ policy: unknown; policy_hash_b64u?: string }>;
  };

  for (const layer of payload.layers) {
    layer.policy_hash_b64u = await computeSignedPolicyLayerHashB64u(
      layer.policy as { statements: unknown[] }
    );
  }

  const payloadHash = await computeSignedPolicyBundlePayloadHashB64u(
    payload as {
      policy_bundle_version: '1';
      bundle_id: string;
      issuer_did: string;
      issued_at: string;
      hash_algorithm: 'SHA-256';
      layers: unknown[];
    }
  );

  const signature = await sign(new TextEncoder().encode(payloadHash));
  return {
    envelope_version: '1',
    envelope_type: 'policy_bundle',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: did,
    issued_at: payloadInput['issued_at'],
  };
}

describe('AF2-POL deterministic effective policy resolution', () => {
  it('resolves org/project/task/exception layers deterministically regardless of input layer order', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);
    const sign = (message: Uint8Array) => signEd25519(keyPair.privateKey, message);

    const sharedPayload = {
      policy_bundle_version: '1' as const,
      bundle_id: 'bundle_policy_det_1',
      issuer_did: did,
      issued_at: '2026-03-20T00:00:00.000Z',
      hash_algorithm: 'SHA-256' as const,
      layers: [
        {
          layer_id: 'org',
          scope: { scope_type: 'org', org_id: 'acme' },
          apply_mode: 'merge',
          policy: {
            statements: [
              { sid: 'org.base', effect: 'Allow', actions: ['model:invoke'], resources: ['*'] },
            ],
          },
        },
        {
          layer_id: 'proj',
          scope: { scope_type: 'project', org_id: 'acme', project_id: 'proj-a' },
          apply_mode: 'merge',
          policy: {
            statements: [
              { sid: 'proj.guard', effect: 'Deny', actions: ['side_effect:network_egress'], resources: ['*'] },
            ],
          },
        },
        {
          layer_id: 'task',
          scope: { scope_type: 'task', org_id: 'acme', project_id: 'proj-a', task_id: 'task-9' },
          apply_mode: 'merge',
          policy: {
            statements: [
              { sid: 'task.tool', effect: 'Allow', actions: ['tool:execute'], resources: ['bash:*'] },
            ],
          },
        },
        {
          layer_id: 'exc-high',
          scope: {
            scope_type: 'exception',
            org_id: 'acme',
            project_id: 'proj-a',
            task_id: 'task-9',
            exception_id: 'exc-1',
            priority: 50,
          },
          apply_mode: 'merge',
          policy: {
            statements: [
              { sid: 'exc.high', effect: 'Allow', actions: ['side_effect:network_egress'], resources: ['api.openai.com'] },
            ],
          },
        },
        {
          layer_id: 'exc-low',
          scope: {
            scope_type: 'exception',
            org_id: 'acme',
            project_id: 'proj-a',
            task_id: 'task-9',
            exception_id: 'exc-2',
            priority: 10,
          },
          apply_mode: 'merge',
          policy: {
            statements: [
              { sid: 'exc.low', effect: 'Allow', actions: ['side_effect:network_egress'], resources: ['generativelanguage.googleapis.com'] },
            ],
          },
        },
      ],
    };

    const bundleA = await buildSignedPolicyBundleEnvelope(sharedPayload, did, sign);
    const bundleB = await buildSignedPolicyBundleEnvelope(
      {
        ...sharedPayload,
        layers: [...sharedPayload.layers].reverse(),
      },
      did,
      sign,
    );

    const context = { org_id: 'acme', project_id: 'proj-a', task_id: 'task-9' };
    const resolvedA = await resolveEffectivePolicyFromSignedBundle(bundleA, context);
    const resolvedB = await resolveEffectivePolicyFromSignedBundle(bundleB, context);

    expect(resolvedA.effective_policy_hash_b64u).toBe(resolvedB.effective_policy_hash_b64u);
    expect(resolvedA.effective_policy_snapshot.applied_layers.map((layer) => layer.layer_id)).toEqual([
      'org',
      'proj',
      'task',
      'exc-high',
      'exc-low',
    ]);
    expect(resolvedA.effective_policy_snapshot.effective_policy.statements.map((s) => s.sid)).toEqual([
      'exc.high',
      'exc.low',
      'org.base',
      'proj.guard',
      'task.tool',
    ]);
  });
});

describe('AF2-POL verifier policy binding fail-closed behavior', () => {
  it('rejects proof bundles when egress receipt policy hash does not match policy_binding hash', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);
    const sign = (message: Uint8Array) => signEd25519(keyPair.privateKey, message);

    const eventHeader = {
      event_id: 'evt_1',
      run_id: 'run_policy_1',
      event_type: 'llm_call',
      timestamp: '2026-03-20T00:00:01.000Z',
      payload_hash_b64u: 'evt_payload_hash_0001',
      prev_hash_b64u: null,
    };
    const eventHash = await computeHash(eventHeader, 'SHA-256');

    const policySnapshot = {
      snapshot_version: '1',
      resolver_version: 'org_project_task_exception.v1',
      context: { org_id: 'acme', project_id: 'proj-a', task_id: 'task-9' },
      source_bundle: {
        bundle_id: 'bundle_signed_policy_1',
        issuer_did: did,
        issued_at: '2026-03-20T00:00:00.000Z',
      },
      applied_layers: [
        {
          layer_id: 'org',
          scope_type: 'org',
          org_id: 'acme',
          priority: 0,
          apply_mode: 'merge',
          policy_hash_b64u: 'org_hash_1',
        },
      ],
      effective_policy: {
        statements: [
          { sid: 'org.base', effect: 'Allow', actions: ['model:invoke'], resources: ['*'] },
        ],
      },
    };

    const effectivePolicyHash = await computeHash(canonicalize(policySnapshot), 'SHA-256');
    const signedPolicyBundleEnvelope = await buildSignedPolicyBundleEnvelope(
      {
        policy_bundle_version: '1',
        bundle_id: 'bundle_signed_policy_1',
        issuer_did: did,
        issued_at: '2026-03-20T00:00:00.000Z',
        hash_algorithm: 'SHA-256',
        layers: [
          {
            layer_id: 'org',
            scope: { scope_type: 'org', org_id: 'acme' },
            apply_mode: 'merge',
            policy: {
              statements: [
                { sid: 'org.base', effect: 'Allow', actions: ['model:invoke'], resources: ['*'] },
              ],
            },
          },
        ],
      },
      did,
      sign,
    );
    policySnapshot.applied_layers[0]!.policy_hash_b64u = (
      signedPolicyBundleEnvelope.payload as {
        layers: Array<{ policy_hash_b64u: string }>;
      }
    ).layers[0]!.policy_hash_b64u;
    const boundEffectivePolicyHash = await computeHash(canonicalize(policySnapshot), 'SHA-256');

    const payload = {
      bundle_version: '1',
      bundle_id: 'bundle_policy_binding_fail_1',
      agent_did: did,
      event_chain: [
        {
          ...eventHeader,
          event_hash_b64u: eventHash,
        },
      ],
      metadata: {
        policy_binding: {
          binding_version: '1',
          effective_policy_hash_b64u: boundEffectivePolicyHash,
          effective_policy_snapshot: policySnapshot,
          signed_policy_bundle_envelope: signedPolicyBundleEnvelope,
        },
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: {
            envelope_version: '1',
            envelope_type: 'egress_policy_receipt',
            payload_hash_b64u: 'egress_payload_hash_1',
            hash_algorithm: 'SHA-256',
            signature_b64u: 'egress_signature_1',
            algorithm: 'Ed25519',
            signer_did: did,
            issued_at: '2026-03-20T00:00:02.000Z',
            payload: {
              receipt_version: '1',
              receipt_id: 'epr_1',
              policy_version: '1',
              policy_hash_b64u: 'descriptor_hash_1',
              effective_policy_hash_b64u: 'mismatch_hash',
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
                run_id: 'run_policy_1',
                event_hash_b64u: eventHash,
              },
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

    const envelope = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: signature,
      algorithm: 'Ed25519',
      signer_did: did,
      issued_at: '2026-03-20T00:00:03.000Z',
    };

    const verification = await verifyProofBundle(envelope);

    expect(verification.result.status).toBe('INVALID');
    expect(verification.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(verification.error?.field).toBe(
      'payload.metadata.sentinels.egress_policy_receipt.payload.effective_policy_hash_b64u',
    );
  });

  it('rejects proof bundles when policy_binding omits the signed policy bundle envelope', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);

    const eventHeader = {
      event_id: 'evt_2',
      run_id: 'run_policy_2',
      event_type: 'llm_call',
      timestamp: '2026-03-20T00:00:01.000Z',
      payload_hash_b64u: 'evt_payload_hash_0002',
      prev_hash_b64u: null,
    };
    const eventHash = await computeHash(eventHeader, 'SHA-256');

    const policySnapshot = {
      snapshot_version: '1',
      resolver_version: 'org_project_task_exception.v1',
      context: { org_id: 'acme' },
      source_bundle: {
        bundle_id: 'bundle_signed_policy_2',
        issuer_did: did,
        issued_at: '2026-03-20T00:00:00.000Z',
      },
      applied_layers: [
        {
          layer_id: 'org',
          scope_type: 'org',
          org_id: 'acme',
          priority: 0,
          apply_mode: 'merge',
          policy_hash_b64u: 'org_hash_2',
        },
      ],
      effective_policy: {
        statements: [
          { sid: 'org.base', effect: 'Allow', actions: ['model:invoke'], resources: ['*'] },
        ],
      },
    };

    const effectivePolicyHash = await computeHash(canonicalize(policySnapshot), 'SHA-256');

    const payload = {
      bundle_version: '1',
      bundle_id: 'bundle_policy_binding_fail_2',
      agent_did: did,
      event_chain: [
        {
          ...eventHeader,
          event_hash_b64u: eventHash,
        },
      ],
      metadata: {
        policy_binding: {
          binding_version: '1',
          effective_policy_hash_b64u: effectivePolicyHash,
          effective_policy_snapshot: policySnapshot,
        },
        sentinels: {
          interpose_active: true,
          egress_policy_receipt: {
            envelope_version: '1',
            envelope_type: 'egress_policy_receipt',
            payload_hash_b64u: 'egress_payload_hash_2',
            hash_algorithm: 'SHA-256',
            signature_b64u: 'egress_signature_2',
            algorithm: 'Ed25519',
            signer_did: did,
            issued_at: '2026-03-20T00:00:02.000Z',
            payload: {
              receipt_version: '1',
              receipt_id: 'epr_2',
              policy_version: '1',
              policy_hash_b64u: 'descriptor_hash_2',
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
              effective_policy_hash_b64u: effectivePolicyHash,
              binding: {
                run_id: 'run_policy_2',
                event_hash_b64u: eventHash,
              },
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

    const envelope = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: signature,
      algorithm: 'Ed25519',
      signer_did: did,
      issued_at: '2026-03-20T00:00:03.000Z',
    };

    const verification = await verifyProofBundle(envelope);

    expect(verification.result.status).toBe('INVALID');
    expect(verification.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(verification.error?.field).toBeTruthy();
  });
});

describe('AF2-ATT verifier runner measurement fail-closed behavior', () => {
  it('rejects proof bundles when runner_measurement.manifest_hash_b64u does not match manifest', async () => {
    const keyPair = await generateKeyPair();
    const did = await didFromPublicKey(keyPair.publicKey);
    const eventHeader = {
      event_id: 'evt_runner_measurement_1',
      run_id: 'run_runner_measurement_1',
      event_type: 'llm_call',
      timestamp: '2026-03-20T00:00:01.000Z',
      payload_hash_b64u: 'evt_payload_hash_runner_1',
      prev_hash_b64u: null,
    };
    const eventHash = await computeHash(eventHeader, 'SHA-256');

    const manifest = {
      manifest_version: '1' as const,
      runtime: {
        platform: process.platform,
        arch: process.arch,
        node_version: process.version,
      },
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
      policy: {},
      artifacts: {
        preload_hash_b64u: 'a'.repeat(43),
        node_preload_sentinel_hash_b64u: 'b'.repeat(43),
        sentinel_shell_hash_b64u: null,
        sentinel_shell_policy_hash_b64u: null,
        interpose_library_hash_b64u: null,
      },
    };

    const payload = {
      bundle_version: '1',
      bundle_id: 'bundle_runner_measurement_fail_1',
      agent_did: did,
      event_chain: [
        {
          ...eventHeader,
          event_hash_b64u: eventHash,
        },
      ],
      metadata: {
        runner_measurement: {
          binding_version: '1',
          hash_algorithm: 'SHA-256',
          manifest_hash_b64u: await hashJsonB64u({
            ...manifest,
            runtime: { ...manifest.runtime, node_version: `${manifest.runtime.node_version}-tampered` },
          }),
          manifest,
        },
      },
    };

    const payloadHash = await computeHash(payload, 'SHA-256');
    const signature = await signEd25519(
      keyPair.privateKey,
      new TextEncoder().encode(payloadHash),
    );

    const envelope = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: signature,
      algorithm: 'Ed25519',
      signer_did: did,
      issued_at: '2026-03-20T00:00:03.000Z',
    };

    const verification = await verifyProofBundle(envelope);

    expect(verification.result.status).toBe('INVALID');
    expect(verification.error?.code).toBe('HASH_MISMATCH');
    expect(verification.error?.field).toBe(
      'payload.metadata.runner_measurement.manifest_hash_b64u',
    );
  });
});
