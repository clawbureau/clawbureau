import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyProofBundle } from '../src/verify-proof-bundle';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

type FixtureExpected = {
  status: 'VALID' | 'INVALID';
  error_code?: string;
  policy_profile?: 'compat' | 'strict';
  causal_connectivity_mode?: 'observe' | 'warn' | 'enforce';
  coverage_enforcement_phase?: 'observe' | 'warn' | 'enforce';
};

type FixtureCase = {
  id: string;
  scenario:
    | 'valid_policy_profile_compat_override'
    | 'invalid_policy_profile_strict_downgrade'
    | 'invalid_policy_profile_invalid'
    | 'valid_policy_profile_strict_lock';
  expected: FixtureExpected;
};

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
}) {
  const payloadHash = await computeHash(args.payload, 'SHA-256');
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', args.privateKey, new TextEncoder().encode(payloadHash))
  );

  return {
    envelope_version: '1' as const,
    envelope_type: args.envelopeType,
    payload: args.payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256' as const,
    signature_b64u: base64UrlEncode(signature),
    algorithm: 'Ed25519' as const,
    signer_did: args.signerDid,
    issued_at: args.issuedAt,
  };
}

async function makeBaseBundleParts(agentDid: string, runId: string) {
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

  return {
    eventHash,
    payload: {
      bundle_version: '1',
      bundle_id: `bundle_${runId}`,
      agent_did: agentDid,
      event_chain: [
        {
          ...eventHeader,
          event_hash_b64u: eventHash,
        },
      ],
    } as Record<string, unknown>,
  };
}

async function makeGatewayReceiptEnvelope(args: {
  gatewayDid: string;
  gatewayKey: CryptoKey;
  runId: string;
  eventHash: string;
  receiptId: string;
  spanId: string;
  parentSpanId?: string;
  phase?: string;
}) {
  return signEnvelope({
    payload: {
      receipt_version: '1',
      receipt_id: args.receiptId,
      gateway_id: 'gw_policy_profile_001',
      provider: 'openai',
      model: 'gpt-4',
      request_hash_b64u: `req_${args.receiptId}`,
      response_hash_b64u: `res_${args.receiptId}`,
      tokens_input: 10,
      tokens_output: 20,
      latency_ms: 55,
      timestamp: '2026-02-19T00:00:00.100Z',
      binding: {
        run_id: args.runId,
        event_hash_b64u: args.eventHash,
        span_id: args.spanId,
        ...(args.parentSpanId ? { parent_span_id: args.parentSpanId } : {}),
        phase: args.phase ?? 'execution',
        attribution_confidence: 0.5,
      },
    },
    envelopeType: 'gateway_receipt',
    signerDid: args.gatewayDid,
    privateKey: args.gatewayKey,
    issuedAt: '2026-02-19T00:00:00.200Z',
  });
}

async function makeCoverageEnvelope(args: {
  runId: string;
  eventHash: string;
  agentDid: string;
  sentinelDid: string;
  sentinelKey: CryptoKey;
}) {
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
          processes_tracked: 4,
          unmonitored_spawns: 0,
          escapes_suspected: false,
        },
        egress: {
          connections_total: 1,
          unmediated_connections: 0,
        },
        liveness: {
          status: 'continuous',
          uptime_ms: 5000,
          heartbeat_interval_ms: 500,
          max_gap_ms: 100,
        },
      },
    },
    envelopeType: 'coverage_attestation',
    signerDid: args.sentinelDid,
    privateKey: args.sentinelKey,
    issuedAt: '2026-02-19T00:00:00.500Z',
  });
}

async function buildFixtureScenario(spec: FixtureCase) {
  const runId = `run_policy_profile_${spec.id.replace(/[^a-z0-9]+/gi, '_')}`;
  const agent = await makeDidKeyEd25519();
  const gateway = await makeDidKeyEd25519();
  const sentinel = await makeDidKeyEd25519();
  const { eventHash, payload } = await makeBaseBundleParts(agent.did, runId);

  const disconnectedReceipts = [
    await makeGatewayReceiptEnvelope({
      gatewayDid: gateway.did,
      gatewayKey: gateway.privateKey,
      runId,
      eventHash,
      receiptId: `rcpt_${runId}_a`,
      spanId: `span_${runId}_root_a`,
      phase: 'execution',
    }),
    await makeGatewayReceiptEnvelope({
      gatewayDid: gateway.did,
      gatewayKey: gateway.privateKey,
      runId,
      eventHash,
      receiptId: `rcpt_${runId}_b`,
      spanId: `span_${runId}_root_b`,
      phase: 'execution',
    }),
  ];

  const connectedReceipts = [
    await makeGatewayReceiptEnvelope({
      gatewayDid: gateway.did,
      gatewayKey: gateway.privateKey,
      runId,
      eventHash,
      receiptId: `rcpt_${runId}_root`,
      spanId: `span_${runId}_root`,
      phase: 'setup',
    }),
    await makeGatewayReceiptEnvelope({
      gatewayDid: gateway.did,
      gatewayKey: gateway.privateKey,
      runId,
      eventHash,
      receiptId: `rcpt_${runId}_child`,
      spanId: `span_${runId}_child`,
      parentSpanId: `span_${runId}_root`,
      phase: 'planning',
    }),
  ];

  if (spec.scenario === 'valid_policy_profile_compat_override') {
    const envelope = await signEnvelope({
      payload: {
        ...payload,
        receipts: disconnectedReceipts,
      },
      envelopeType: 'proof_bundle',
      signerDid: agent.did,
      privateKey: agent.privateKey,
      issuedAt: '2026-02-19T00:00:01.000Z',
    });

    return {
      envelope,
      options: {
        allowlistedReceiptSignerDids: [gateway.did],
        causal_policy_profile: 'compat' as const,
        causal_connectivity_mode: 'observe' as const,
        coverage_enforcement_phase: 'warn' as const,
      },
    };
  }

  if (spec.scenario === 'invalid_policy_profile_strict_downgrade') {
    const envelope = await signEnvelope({
      payload: {
        ...payload,
        receipts: disconnectedReceipts,
      },
      envelopeType: 'proof_bundle',
      signerDid: agent.did,
      privateKey: agent.privateKey,
      issuedAt: '2026-02-19T00:00:01.000Z',
    });

    return {
      envelope,
      options: {
        allowlistedReceiptSignerDids: [gateway.did],
        causal_policy_profile: 'strict' as const,
        causal_connectivity_mode: 'observe' as const,
        coverage_enforcement_phase: 'warn' as const,
      },
    };
  }

  if (spec.scenario === 'invalid_policy_profile_invalid') {
    const envelope = await signEnvelope({
      payload: {
        ...payload,
        receipts: connectedReceipts,
      },
      envelopeType: 'proof_bundle',
      signerDid: agent.did,
      privateKey: agent.privateKey,
      issuedAt: '2026-02-19T00:00:01.000Z',
    });

    return {
      envelope,
      options: {
        allowlistedReceiptSignerDids: [gateway.did],
        causal_policy_profile: 'strictish',
      } as any,
    };
  }

  const coverageAttestation = await makeCoverageEnvelope({
    runId,
    eventHash,
    agentDid: agent.did,
    sentinelDid: sentinel.did,
    sentinelKey: sentinel.privateKey,
  });

  const envelope = await signEnvelope({
    payload: {
      ...payload,
      receipts: connectedReceipts,
      coverage_attestations: [coverageAttestation],
    },
    envelopeType: 'proof_bundle',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-19T00:00:01.000Z',
  });

  return {
    envelope,
    options: {
      allowlistedReceiptSignerDids: [gateway.did],
      allowlistedCoverageAttestationSignerDids: [sentinel.did],
      causal_policy_profile: 'strict' as const,
    },
  };
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.resolve(
  __dirname,
  '../../../packages/schema/fixtures/protocol-conformance/clawverify-causal-policy-profile'
);

const manifest = JSON.parse(
  fs.readFileSync(path.join(FIXTURE_DIR, 'manifest.v1.json'), 'utf8')
) as {
  manifest_version: string;
  suite: string;
  cases: string[];
};

const fixtures: FixtureCase[] = manifest.cases.map((name) =>
  JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, name), 'utf8'))
);

describe(`clawverify causal policy profile conformance (${manifest.suite})`, () => {
  it.each(fixtures)('validates fixture: $id', async (spec) => {
    const scenario = await buildFixtureScenario(spec);
    const out = await verifyProofBundle(scenario.envelope, scenario.options as any);

    expect(out.result.status).toBe(spec.expected.status);

    if (spec.expected.error_code) {
      expect(out.error?.code).toBe(spec.expected.error_code);
    }

    if (spec.expected.policy_profile) {
      expect(out.result.component_results?.causal_policy_profile).toBe(
        spec.expected.policy_profile
      );
    }

    if (spec.expected.causal_connectivity_mode) {
      expect(out.result.component_results?.causal_policy_snapshot?.causal_connectivity_mode).toBe(
        spec.expected.causal_connectivity_mode
      );
    }

    if (spec.expected.coverage_enforcement_phase) {
      expect(out.result.component_results?.causal_policy_snapshot?.coverage_enforcement_phase).toBe(
        spec.expected.coverage_enforcement_phase
      );
    }
  });
});
