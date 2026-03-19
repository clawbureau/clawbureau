import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, describe, expect, it } from 'vitest';

import {
  base64UrlEncode,
  computeHash,
  jcsCanonicalize,
  verifyAggregateBundle,
  type AggregateBundleEnvelope,
  type ProofBundlePayload,
  type SignedEnvelope,
} from '@clawbureau/clawverify-core';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

type FixtureExpected = {
  status: 'VALID' | 'INVALID';
  error_code?: string;
};

type FixtureCase = {
  id: string;
  scenario:
    | 'valid_aggregate_causal_consistent'
    | 'invalid_aggregate_member_conflict'
    | 'invalid_aggregate_receipt_replay';
  expected: FixtureExpected;
};

const SECOND_MS = 1_000;
const HOUR_MS = 60 * 60 * SECOND_MS;
const DAY_MS = 24 * HOUR_MS;

function isoAtOffset(baseMs: number, offsetMs: number): string {
  return new Date(baseMs + offsetMs).toISOString();
}

type FixtureClock = {
  eventTimestamp: string;
  receiptTimestamp: string;
  receiptIssuedAt: string;
  memberIssuedAt: string;
  aggregateCreatedAt: string;
  manifestGeneratedAt: string;
  aggregateIssuedAt: string;
  aggregateExpiresAt: string;
};

function makeFixtureClock(nowMs = Date.now()): FixtureClock {
  const issuedBaseMs = nowMs - HOUR_MS;

  return {
    eventTimestamp: isoAtOffset(issuedBaseMs, -2_000),
    receiptTimestamp: isoAtOffset(issuedBaseMs, -1_500),
    receiptIssuedAt: isoAtOffset(issuedBaseMs, -1_000),
    memberIssuedAt: isoAtOffset(issuedBaseMs, -500),
    aggregateCreatedAt: isoAtOffset(nowMs, -30 * 60 * SECOND_MS),
    manifestGeneratedAt: isoAtOffset(nowMs, -29 * 60 * SECOND_MS),
    aggregateIssuedAt: isoAtOffset(nowMs, -28 * 60 * SECOND_MS),
    aggregateExpiresAt: isoAtOffset(nowMs, 30 * DAY_MS),
  };
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
    .map((d) => BASE58_ALPHABET[d])
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
    ...(args.expiresAt ? { expires_at: args.expiresAt } : {}),
  };
}

async function canonicalMemberDigest(value: unknown): Promise<{
  sha256_b64u: string;
  size_bytes: number;
}> {
  const canonical = jcsCanonicalize(value);
  const bytes = new TextEncoder().encode(canonical);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

  return {
    sha256_b64u: base64UrlEncode(digest),
    size_bytes: bytes.byteLength,
  };
}

function manifestEntryForMember(index: number, digest: {
  sha256_b64u: string;
  size_bytes: number;
}) {
  return {
    path: `artifacts/member_bundles/${index}.json`,
    sha256_b64u: digest.sha256_b64u,
    content_type: 'application/json' as const,
    size_bytes: digest.size_bytes,
  };
}

async function makeProofMember(args: {
  bundleId: string;
  runId: string;
  agentDid: string;
  agentKey: CryptoKey;
  gatewayDid: string;
  gatewayKey: CryptoKey;
  receiptId: string;
  responseHash: string;
  spanId: string;
  phase: string;
  attributionConfidence?: number;
  parentSpanId?: string;
  toolSpanId?: string;
  clock: FixtureClock;
}): Promise<SignedEnvelope<ProofBundlePayload>> {
  const eventPayloadHash = await computeHash(
    { type: 'llm_call', bundle_id: args.bundleId },
    'SHA-256'
  );

  const eventHeader = {
    event_id: `${args.bundleId}_evt_001`,
    run_id: args.runId,
    event_type: 'llm_call',
    timestamp: args.clock.eventTimestamp,
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };

  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const receiptEnvelope = await signEnvelope({
    payload: {
      receipt_version: '1',
      receipt_id: args.receiptId,
      gateway_id: 'gw_aggregate_causal_001',
      provider: 'openai',
      model: 'gpt-4',
      request_hash_b64u: `req_${args.bundleId}`,
      response_hash_b64u: args.responseHash,
      tokens_input: 25,
      tokens_output: 40,
      latency_ms: 45,
      timestamp: args.clock.receiptTimestamp,
      binding: {
        run_id: args.runId,
        event_hash_b64u: eventHash,
        span_id: args.spanId,
        ...(args.parentSpanId ? { parent_span_id: args.parentSpanId } : {}),
        ...(args.toolSpanId ? { tool_span_id: args.toolSpanId } : {}),
        phase: args.phase,
        attribution_confidence: args.attributionConfidence ?? 0.5,
      },
    },
    envelopeType: 'gateway_receipt',
    signerDid: args.gatewayDid,
    privateKey: args.gatewayKey,
    issuedAt: args.clock.receiptIssuedAt,
  });

  return (await signEnvelope({
    payload: {
      bundle_version: '1',
      bundle_id: args.bundleId,
      agent_did: args.agentDid,
      event_chain: [
        {
          ...eventHeader,
          event_hash_b64u: eventHash,
        },
      ],
      receipts: [receiptEnvelope],
    },
    envelopeType: 'proof_bundle',
    signerDid: args.agentDid,
    privateKey: args.agentKey,
    issuedAt: args.clock.memberIssuedAt,
  })) as SignedEnvelope<ProofBundlePayload>;
}

async function makeAggregateEnvelope(args: {
  aggregateId: string;
  issuerDid: string;
  issuerKey: CryptoKey;
  members: Array<SignedEnvelope<ProofBundlePayload>>;
  clock: FixtureClock;
}): Promise<AggregateBundleEnvelope> {
  const membersWithDigest = await Promise.all(
    args.members.map(async (member) => ({
      member,
      digest: await canonicalMemberDigest(member),
    }))
  );

  membersWithDigest.sort((a, b) => {
    if (a.digest.sha256_b64u < b.digest.sha256_b64u) return -1;
    if (a.digest.sha256_b64u > b.digest.sha256_b64u) return 1;
    return 0;
  });

  const sortedMembers = membersWithDigest.map((entry) => entry.member);
  const manifestEntries = membersWithDigest.map((entry, index) =>
    manifestEntryForMember(index, entry.digest)
  );

  const uniqueAgents = new Set(sortedMembers.map((m) => m.payload.agent_did));
  const uniqueRuns = new Set(
    sortedMembers.map((m) => m.payload.event_chain?.[0]?.run_id).filter(Boolean)
  );

  return (await signEnvelope({
    payload: {
      aggregate_version: '1',
      aggregate_id: args.aggregateId,
      created_at: args.clock.aggregateCreatedAt,
      issuer_did: args.issuerDid,
      manifest: {
        manifest_version: '1',
        generated_at: args.clock.manifestGeneratedAt,
        entries: manifestEntries,
      },
      artifacts: {
        member_bundles: sortedMembers,
      },
      metadata: {
        fleet_summary: {
          total_members: sortedMembers.length,
          unique_agents: uniqueAgents.size,
          total_runs: uniqueRuns.size,
          fleet_proof_tier: 'gateway',
        },
      },
    },
    envelopeType: 'aggregate_bundle',
    signerDid: args.issuerDid,
    privateKey: args.issuerKey,
    issuedAt: args.clock.aggregateIssuedAt,
    expiresAt: args.clock.aggregateExpiresAt,
  })) as AggregateBundleEnvelope;
}

async function buildFixtureScenario(spec: FixtureCase) {
  const clock = makeFixtureClock();
  const aggregateIssuer = await makeDidKeyEd25519();
  const gateway = await makeDidKeyEd25519();
  const agentA = await makeDidKeyEd25519();
  const agentB = await makeDidKeyEd25519();

  const namespace = 'run_ns_aggregate_causal';

  if (spec.scenario === 'valid_aggregate_causal_consistent') {
    const memberA = await makeProofMember({
      bundleId: 'bundle_aggregate_causal_valid_a',
      runId: `${namespace}::member_a`,
      agentDid: agentA.did,
      agentKey: agentA.privateKey,
      gatewayDid: gateway.did,
      gatewayKey: gateway.privateKey,
      receiptId: 'rcpt_aggregate_causal_valid_a',
      responseHash: 'res_aggregate_causal_valid_a',
      spanId: 'span_shared_aggregate_001',
      phase: 'execution',
      clock,
    });

    const memberB = await makeProofMember({
      bundleId: 'bundle_aggregate_causal_valid_b',
      runId: `${namespace}::member_b`,
      agentDid: agentB.did,
      agentKey: agentB.privateKey,
      gatewayDid: gateway.did,
      gatewayKey: gateway.privateKey,
      receiptId: 'rcpt_aggregate_causal_valid_b',
      responseHash: 'res_aggregate_causal_valid_b',
      spanId: 'span_shared_aggregate_001',
      phase: 'execution',
      clock,
    });

    return {
      envelope: await makeAggregateEnvelope({
        aggregateId: 'aggregate_causal_valid_001',
        issuerDid: aggregateIssuer.did,
        issuerKey: aggregateIssuer.privateKey,
        members: [memberA, memberB],
        clock,
      }),
      options: {
        allowlistedReceiptSignerDids: [gateway.did],
      },
    };
  }

  if (spec.scenario === 'invalid_aggregate_member_conflict') {
    const memberA = await makeProofMember({
      bundleId: 'bundle_aggregate_causal_conflict_a',
      runId: `${namespace}::member_conflict_a`,
      agentDid: agentA.did,
      agentKey: agentA.privateKey,
      gatewayDid: gateway.did,
      gatewayKey: gateway.privateKey,
      receiptId: 'rcpt_aggregate_causal_conflict_a',
      responseHash: 'res_aggregate_causal_conflict_a',
      spanId: 'span_conflict_aggregate_001',
      phase: 'execution',
      clock,
    });

    const memberB = await makeProofMember({
      bundleId: 'bundle_aggregate_causal_conflict_b',
      runId: `${namespace}::member_conflict_b`,
      agentDid: agentB.did,
      agentKey: agentB.privateKey,
      gatewayDid: gateway.did,
      gatewayKey: gateway.privateKey,
      receiptId: 'rcpt_aggregate_causal_conflict_b',
      responseHash: 'res_aggregate_causal_conflict_b',
      spanId: 'span_conflict_aggregate_001',
      phase: 'planning',
      clock,
    });

    return {
      envelope: await makeAggregateEnvelope({
        aggregateId: 'aggregate_causal_conflict_001',
        issuerDid: aggregateIssuer.did,
        issuerKey: aggregateIssuer.privateKey,
        members: [memberA, memberB],
        clock,
      }),
      options: {
        allowlistedReceiptSignerDids: [gateway.did],
      },
    };
  }

  const memberA = await makeProofMember({
    bundleId: 'bundle_aggregate_causal_replay_a',
    runId: 'run_aggregate_replay_a',
    agentDid: agentA.did,
    agentKey: agentA.privateKey,
    gatewayDid: gateway.did,
    gatewayKey: gateway.privateKey,
    receiptId: 'rcpt_aggregate_replay_target_001',
    responseHash: 'res_aggregate_replay_a',
    spanId: 'span_replay_aggregate_001',
    phase: 'execution',
    clock,
  });

  const memberB = await makeProofMember({
    bundleId: 'bundle_aggregate_causal_replay_b',
    runId: 'run_aggregate_replay_b',
    agentDid: agentB.did,
    agentKey: agentB.privateKey,
    gatewayDid: gateway.did,
    gatewayKey: gateway.privateKey,
    receiptId: 'rcpt_aggregate_replay_target_001',
    responseHash: 'res_aggregate_replay_b',
    spanId: 'span_replay_aggregate_002',
    phase: 'execution',
    clock,
  });

  return {
    envelope: await makeAggregateEnvelope({
      aggregateId: 'aggregate_causal_replay_001',
      issuerDid: aggregateIssuer.did,
      issuerKey: aggregateIssuer.privateKey,
      members: [memberA, memberB],
      clock,
    }),
    options: {
      allowlistedReceiptSignerDids: [gateway.did],
    },
  };
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.resolve(
  __dirname,
  '../../schema/fixtures/protocol-conformance/clawverify-aggregate-causal'
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

const summaryPath = process.env.CLAWVERIFY_AGGREGATE_CAUSAL_CONFORMANCE_SUMMARY_PATH?.trim();
const summaryRows: Array<{
  id: string;
  scenario: FixtureCase['scenario'];
  status: 'VALID' | 'INVALID';
  error_code: string;
  expected_status: 'VALID' | 'INVALID';
  expected_error_code: string;
}> = [];

afterAll(() => {
  if (!summaryPath) return;

  fs.mkdirSync(path.dirname(summaryPath), { recursive: true });
  fs.writeFileSync(
    summaryPath,
    `${JSON.stringify(
      {
        suite: manifest.suite,
        generated_at: new Date().toISOString(),
        fixtures: [...summaryRows].sort((a, b) => a.id.localeCompare(b.id)),
      },
      null,
      2
    )}\n`,
    'utf8'
  );
});

describe(`clawverify aggregate causal conformance (${manifest.suite})`, () => {
  it.each(fixtures)('validates fixture: $id', async (spec) => {
    const scenario = await buildFixtureScenario(spec);
    const out = await verifyAggregateBundle(scenario.envelope, scenario.options);

    summaryRows.push({
      id: spec.id,
      scenario: spec.scenario,
      status: out.result.status,
      error_code: out.error?.code ?? 'OK',
      expected_status: spec.expected.status,
      expected_error_code: spec.expected.error_code ?? 'OK',
    });

    expect(out.result.status).toBe(spec.expected.status);

    if (spec.expected.error_code) {
      expect(out.error?.code).toBe(spec.expected.error_code);
    }
  });
});
