import { describe, expect, it } from 'vitest';

import {
  base64UrlEncode,
  computeHash,
  verifyProofBundle,
  type ProofBundlePayload,
  type SignedEnvelope,
} from '@clawbureau/clawverify-core';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

type GatewayReceiptSpec = {
  receiptSuffix: string;
  receiptId?: string;
  responseHashB64u?: string;
  timestamp?: string;
  issuedAt?: string;
  bindingExtras?: Record<string, unknown>;
};

type ScenarioInput = {
  id: string;
  receiptSpecs: GatewayReceiptSpec[];
  options?: Record<string, unknown>;
  sideEffectReceipts?: unknown[];
  humanApprovalReceipts?: unknown[];
  metadata?: Record<string, unknown>;
  coverageMetrics?: {
    unmediated_connections: number;
    unmonitored_spawns: number;
    escapes_suspected: boolean;
  };
};

function replaceAgentPlaceholder(value: unknown, agentDid: string): unknown {
  if (value === '__AGENT__') return agentDid;

  if (Array.isArray(value)) {
    return value.map((entry) => replaceAgentPlaceholder(entry, agentDid));
  }

  if (typeof value === 'object' && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
      out[key] = replaceAgentPlaceholder(entry, agentDid);
    }
    return out;
  }

  return value;
}

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i]! * 256 + carry;
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
    .map((d) => BASE58_ALPHABET[d]!)
    .join('');
}

async function makeDidKeyEd25519(): Promise<{ did: string; privateKey: CryptoKey }> {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

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

async function signEnvelope<T extends Record<string, unknown>>(args: {
  payload: T;
  envelopeType: string;
  signerDid: string;
  privateKey: CryptoKey;
  issuedAt: string;
  expiresAt?: string;
}): Promise<SignedEnvelope<T>> {
  const payloadHash = await computeHash(args.payload, 'SHA-256');
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', args.privateKey, new TextEncoder().encode(payloadHash))
  );

  return {
    envelope_version: '1',
    envelope_type: args.envelopeType,
    payload: args.payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: base64UrlEncode(signature),
    algorithm: 'Ed25519',
    signer_did: args.signerDid,
    issued_at: args.issuedAt,
    ...(args.expiresAt ? { expires_at: args.expiresAt } : {}),
  };
}

async function makeGatewayReceiptEnvelope(args: {
  gatewayDid: string;
  gatewayKey: CryptoKey;
  runId: string;
  eventHash: string;
  spec: GatewayReceiptSpec;
}): Promise<SignedEnvelope<Record<string, unknown>>> {
  const receiptId = args.spec.receiptId ?? `rcpt_${args.runId}_${args.spec.receiptSuffix}`;

  return signEnvelope({
    payload: {
      receipt_version: '1',
      receipt_id: receiptId,
      gateway_id: 'gw_core_parity_001',
      provider: 'openai',
      model: 'gpt-4',
      request_hash_b64u: `req_${receiptId}`,
      response_hash_b64u: args.spec.responseHashB64u ?? `res_${receiptId}`,
      tokens_input: 10,
      tokens_output: 20,
      latency_ms: 50,
      timestamp: args.spec.timestamp ?? '2026-02-19T00:00:00.100Z',
      binding: {
        run_id: args.runId,
        event_hash_b64u: args.eventHash,
        ...(args.spec.bindingExtras ?? {}),
      },
    },
    envelopeType: 'gateway_receipt',
    signerDid: args.gatewayDid,
    privateKey: args.gatewayKey,
    issuedAt: args.spec.issuedAt ?? '2026-02-19T00:00:00.200Z',
  });
}

async function makeCoverageAttestationEnvelope(args: {
  sentinelDid: string;
  sentinelKey: CryptoKey;
  runId: string;
  agentDid: string;
  eventHash: string;
  metrics: {
    unmediated_connections: number;
    unmonitored_spawns: number;
    escapes_suspected: boolean;
  };
}): Promise<SignedEnvelope<Record<string, unknown>>> {
  return signEnvelope({
    payload: {
      attestation_version: '1',
      attestation_id: `cov_${args.runId}`,
      run_id: args.runId,
      agent_did: args.agentDid,
      sentinel_did: args.sentinelDid,
      issued_at: '2026-02-19T00:00:00.400Z',
      binding: {
        event_chain_root_hash_b64u: args.eventHash,
      },
      metrics: {
        lineage: {
          root_pid: 1000,
          processes_tracked: 8,
          unmonitored_spawns: args.metrics.unmonitored_spawns,
          escapes_suspected: args.metrics.escapes_suspected,
        },
        egress: {
          connections_total: 2,
          unmediated_connections: args.metrics.unmediated_connections,
        },
        liveness: {
          status: 'continuous',
          uptime_ms: 10000,
          heartbeat_interval_ms: 500,
          max_gap_ms: 200,
        },
      },
    },
    envelopeType: 'coverage_attestation',
    signerDid: args.sentinelDid,
    privateKey: args.sentinelKey,
    issuedAt: '2026-02-19T00:00:00.500Z',
  });
}

async function buildScenario(input: ScenarioInput): Promise<{
  envelope: SignedEnvelope<ProofBundlePayload>;
  options: Record<string, unknown>;
}> {
  const runId = `run_core_causal_${input.id}`;
  const agent = await makeDidKeyEd25519();
  const gateway = await makeDidKeyEd25519();

  const eventPayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
  const eventHeader = {
    event_id: `evt_${runId}`,
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-19T00:00:00.000Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };

  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const receipts = await Promise.all(
    input.receiptSpecs.map((spec) =>
      makeGatewayReceiptEnvelope({
        gatewayDid: gateway.did,
        gatewayKey: gateway.privateKey,
        runId,
        eventHash,
        spec,
      })
    )
  );

  const payload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: `bundle_${runId}`,
    agent_did: agent.did,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
    receipts,
  };

  if (input.sideEffectReceipts) {
    payload.side_effect_receipts = replaceAgentPlaceholder(
      input.sideEffectReceipts,
      agent.did
    );
  }

  if (input.humanApprovalReceipts) {
    payload.human_approval_receipts = replaceAgentPlaceholder(
      input.humanApprovalReceipts,
      agent.did
    );
  }

  if (input.metadata) {
    payload.metadata = input.metadata;
  }

  const options: Record<string, unknown> = {
    allowlistedReceiptSignerDids: [gateway.did],
    ...(input.options ?? {}),
  };

  if (input.coverageMetrics) {
    const sentinel = await makeDidKeyEd25519();
    payload.coverage_attestations = [
      await makeCoverageAttestationEnvelope({
        sentinelDid: sentinel.did,
        sentinelKey: sentinel.privateKey,
        runId,
        agentDid: agent.did,
        eventHash,
        metrics: input.coverageMetrics,
      }),
    ];

    options.allowlistedCoverageAttestationSignerDids = [sentinel.did];
  }

  const envelope = (await signEnvelope({
    payload,
    envelopeType: 'proof_bundle',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-19T00:00:01.000Z',
  })) as SignedEnvelope<ProofBundlePayload>;

  return { envelope, options };
}

describe('clawverify-core causal parity uplift', () => {
  it('enforces reference/cycle/phase/confidence fail-closed outcomes', async () => {
    const scenarios: Array<{
      input: ScenarioInput;
      expectedCode: string;
    }> = [
      {
        input: {
          id: 'dangling',
          receiptSpecs: [
            {
              receiptSuffix: 'dangling',
              bindingExtras: {
                span_id: 'span_child',
                parent_span_id: 'span_missing',
                phase: 'execution',
                attribution_confidence: 1,
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_REFERENCE_DANGLING',
      },
      {
        input: {
          id: 'cycle',
          receiptSpecs: [
            {
              receiptSuffix: 'cycle_a',
              bindingExtras: {
                span_id: 'span_cycle_a',
                parent_span_id: 'span_cycle_b',
                phase: 'execution',
                attribution_confidence: 1,
              },
            },
            {
              receiptSuffix: 'cycle_b',
              bindingExtras: {
                span_id: 'span_cycle_b',
                parent_span_id: 'span_cycle_a',
                phase: 'execution',
                attribution_confidence: 1,
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_CYCLE_DETECTED',
      },
      {
        input: {
          id: 'phase_invalid',
          receiptSpecs: [
            {
              receiptSuffix: 'phase_invalid',
              bindingExtras: {
                span_id: 'span_phase_invalid',
                phase: 'not-a-phase',
                attribution_confidence: 0.5,
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_PHASE_INVALID',
      },
      {
        input: {
          id: 'confidence_out_of_range',
          receiptSpecs: [
            {
              receiptSuffix: 'confidence_oor',
              bindingExtras: {
                span_id: 'span_confidence_oor',
                phase: 'execution',
                attribution_confidence: 1.5,
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_CONFIDENCE_OUT_OF_RANGE',
      },
      {
        input: {
          id: 'clock_parent_after_child',
          receiptSpecs: [
            {
              receiptSuffix: 'clock_parent',
              timestamp: '2026-02-19T00:00:03.000Z',
              issuedAt: '2026-02-19T00:00:03.500Z',
              bindingExtras: {
                span_id: 'span_parent_late',
                phase: 'setup',
                attribution_confidence: 1,
              },
            },
            {
              receiptSuffix: 'clock_child',
              timestamp: '2026-02-19T00:00:02.000Z',
              issuedAt: '2026-02-19T00:00:02.500Z',
              bindingExtras: {
                span_id: 'span_child_early',
                parent_span_id: 'span_parent_late',
                phase: 'planning',
                attribution_confidence: 1,
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_CLOCK_CONTRADICTION',
      },
      {
        input: {
          id: 'phase_transition_invalid',
          receiptSpecs: [
            {
              receiptSuffix: 'transition_parent',
              bindingExtras: {
                span_id: 'span_transition_parent',
                phase: 'teardown',
                attribution_confidence: 1,
              },
            },
            {
              receiptSuffix: 'transition_child',
              bindingExtras: {
                span_id: 'span_transition_child',
                parent_span_id: 'span_transition_parent',
                phase: 'planning',
                attribution_confidence: 1,
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_PHASE_TRANSITION_INVALID',
      },
      {
        input: {
          id: 'confidence_overclaim',
          receiptSpecs: [
            {
              receiptSuffix: 'confidence_overclaim',
              bindingExtras: {
                span_id: 'span_confidence_overclaim',
                phase: 'execution',
                attribution_confidence: 1,
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_CONFIDENCE_EVIDENCE_INCONSISTENT',
      },
    ];

    for (const scenario of scenarios) {
      const built = await buildScenario(scenario.input);
      const out = await verifyProofBundle(built.envelope, built.options as any);
      expect(out.result.status).toBe('INVALID');
      expect(out.error?.code).toBe(scenario.expectedCode);
    }
  });

  it('enforces connectivity/orphan/replay/span-reuse outcomes', async () => {
    const scenarios: Array<{
      input: ScenarioInput;
      expectedCode: string;
    }> = [
      {
        input: {
          id: 'receipt_replay',
          receiptSpecs: [
            {
              receiptSuffix: 'replay_a',
              receiptId: 'rcpt_replay_target',
              responseHashB64u: 'res_replay_a',
              bindingExtras: {
                span_id: 'span_replay',
                phase: 'execution',
                attribution_confidence: 0.5,
              },
            },
            {
              receiptSuffix: 'replay_b',
              receiptId: 'rcpt_replay_target',
              responseHashB64u: 'res_replay_b',
              bindingExtras: {
                span_id: 'span_replay',
                phase: 'execution',
                attribution_confidence: 0.5,
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_RECEIPT_REPLAY_DETECTED',
      },
      {
        input: {
          id: 'span_reuse_conflict',
          receiptSpecs: [
            {
              receiptSuffix: 'reuse_root',
              bindingExtras: {
                span_id: 'span_reuse',
                phase: 'execution',
                attribution_confidence: 0.5,
              },
            },
            {
              receiptSuffix: 'reuse_conflict',
              bindingExtras: {
                span_id: 'span_reuse',
                parent_span_id: 'span_parent_anchor',
                phase: 'planning',
                attribution_confidence: 0.5,
              },
            },
            {
              receiptSuffix: 'reuse_parent_anchor',
              bindingExtras: {
                span_id: 'span_parent_anchor',
                phase: 'execution',
                attribution_confidence: 0.5,
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_SPAN_REUSE_CONFLICT',
      },
      {
        input: {
          id: 'graph_disconnected',
          receiptSpecs: [
            {
              receiptSuffix: 'disc_root_a',
              bindingExtras: {
                span_id: 'span_disc_a',
                phase: 'execution',
                attribution_confidence: 0.5,
              },
            },
            {
              receiptSuffix: 'disc_root_b',
              bindingExtras: {
                span_id: 'span_disc_b',
                phase: 'execution',
                attribution_confidence: 0.5,
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_GRAPH_DISCONNECTED',
      },
      {
        input: {
          id: 'side_effect_orphan',
          receiptSpecs: [
            {
              receiptSuffix: 'side_effect_root',
              bindingExtras: {
                span_id: 'span_side_effect_root',
                phase: 'execution',
                attribution_confidence: 0.5,
              },
            },
          ],
          sideEffectReceipts: [
            {
              receipt_version: '1',
              receipt_id: 'se_orphan',
              effect_class: 'external_api_write',
              hash_algorithm: 'SHA-256',
              agent_did: '__AGENT__',
              timestamp: '2026-02-19T00:00:00.000Z',
              binding: {
                tool_span_id: 'span_missing_orphan',
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_SIDE_EFFECT_ORPHANED',
      },
      {
        input: {
          id: 'human_approval_orphan',
          receiptSpecs: [
            {
              receiptSuffix: 'human_root',
              bindingExtras: {
                span_id: 'span_human_root',
                phase: 'execution',
                attribution_confidence: 0.5,
              },
            },
          ],
          humanApprovalReceipts: [
            {
              receipt_version: '1',
              receipt_id: 'ha_orphan',
              approval_type: 'explicit_approve',
              hash_algorithm: 'SHA-256',
              agent_did: '__AGENT__',
              timestamp: '2026-02-19T00:00:00.000Z',
              binding: {
                parent_span_id: 'span_missing_human_orphan',
              },
            },
          ],
        },
        expectedCode: 'CAUSAL_HUMAN_APPROVAL_ORPHANED',
      },
    ];

    for (const scenario of scenarios) {
      const built = await buildScenario(scenario.input);
      const out = await verifyProofBundle(built.envelope, built.options as any);
      expect(out.result.status).toBe('INVALID');
      expect(out.error?.code).toBe(scenario.expectedCode);
    }
  });

  it('enforces policy-profile lock semantics and exposes snapshot', async () => {
    const compat = await buildScenario({
      id: 'policy_compat_override',
      receiptSpecs: [
        {
          receiptSuffix: 'compat_root_a',
          bindingExtras: {
            span_id: 'span_compat_a',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        },
        {
          receiptSuffix: 'compat_root_b',
          bindingExtras: {
            span_id: 'span_compat_b',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        },
      ],
      options: {
        causal_policy_profile: 'compat',
        causal_connectivity_mode: 'observe',
        coverage_enforcement_phase: 'warn',
      },
    });

    const compatOut = await verifyProofBundle(compat.envelope, compat.options as any);
    expect(compatOut.result.status).toBe('VALID');
    expect(compatOut.result.component_results?.causal_policy_profile).toBe('compat');
    expect(
      compatOut.result.component_results?.causal_policy_snapshot?.causal_connectivity_mode
    ).toBe('observe');
    expect(
      compatOut.result.component_results?.causal_policy_snapshot?.coverage_enforcement_phase
    ).toBe('warn');

    const strictDowngrade = await buildScenario({
      id: 'policy_strict_downgrade',
      receiptSpecs: [
        {
          receiptSuffix: 'strict_downgrade_root_a',
          bindingExtras: {
            span_id: 'span_strict_downgrade_a',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        },
        {
          receiptSuffix: 'strict_downgrade_root_b',
          bindingExtras: {
            span_id: 'span_strict_downgrade_b',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        },
      ],
      options: {
        causal_policy_profile: 'strict',
        causal_connectivity_mode: 'observe',
        coverage_enforcement_phase: 'warn',
      },
    });

    const strictDowngradeOut = await verifyProofBundle(
      strictDowngrade.envelope,
      strictDowngrade.options as any
    );
    expect(strictDowngradeOut.result.status).toBe('INVALID');
    expect(strictDowngradeOut.error?.code).toBe('CAUSAL_POLICY_PROFILE_DOWNGRADE');

    const strictInvalidProfile = await buildScenario({
      id: 'policy_invalid_profile',
      receiptSpecs: [
        {
          receiptSuffix: 'invalid_profile_root',
          bindingExtras: {
            span_id: 'span_invalid_profile_root',
            phase: 'execution',
            attribution_confidence: 0.5,
          },
        },
      ],
      options: {
        causal_policy_profile: 'strictish',
      },
    });

    const strictInvalidProfileOut = await verifyProofBundle(
      strictInvalidProfile.envelope,
      strictInvalidProfile.options as any
    );
    expect(strictInvalidProfileOut.result.status).toBe('INVALID');
    expect(strictInvalidProfileOut.error?.code).toBe('CAUSAL_POLICY_PROFILE_INVALID');

    const strictLock = await buildScenario({
      id: 'policy_strict_lock',
      receiptSpecs: [
        {
          receiptSuffix: 'strict_lock_root',
          bindingExtras: {
            span_id: 'span_strict_lock_root',
            phase: 'setup',
            attribution_confidence: 1,
          },
        },
        {
          receiptSuffix: 'strict_lock_child',
          bindingExtras: {
            span_id: 'span_strict_lock_child',
            parent_span_id: 'span_strict_lock_root',
            phase: 'planning',
            attribution_confidence: 1,
          },
        },
      ],
      options: {
        causal_policy_profile: 'strict',
      },
    });

    const strictLockOut = await verifyProofBundle(strictLock.envelope, strictLock.options as any);
    expect(strictLockOut.result.status).toBe('VALID');
    expect(strictLockOut.result.component_results?.causal_policy_profile).toBe('strict');
    expect(
      strictLockOut.result.component_results?.causal_policy_snapshot?.causal_connectivity_mode
    ).toBe('enforce');
    expect(
      strictLockOut.result.component_results?.causal_policy_snapshot?.coverage_enforcement_phase
    ).toBe('enforce');
  });

});
