import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyCoverageAttestation } from '../src/verify-coverage-attestation';
import { verifyProofBundle } from '../src/verify-proof-bundle';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i] * 256 + carry;
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

async function makeGatewayBundleWithCoverage(args?: {
  coverageRunId?: string;
  coverageChainRootHash?: string;
  livenessStatus?: 'continuous' | 'interrupted';
  livenessMaxGapMs?: number;
}) {
  const agent = await makeDidKeyEd25519();
  const gateway = await makeDidKeyEd25519();
  const sentinel = await makeDidKeyEd25519();

  const runId = 'run_cov_001';
  const eventPayloadHash = await computeHash({ type: 'llm_call_cov' }, 'SHA-256');
  const eventHeader = {
    event_id: 'evt_cov_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-17T00:00:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };
  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const gatewayReceiptPayload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: 'rcpt_cov_001',
    gateway_id: 'gw_cov_001',
    provider: 'openai',
    model: 'gpt-4.1',
    request_hash_b64u: 'req_cov_hash_001',
    response_hash_b64u: 'res_cov_hash_001',
    tokens_input: 10,
    tokens_output: 20,
    latency_ms: 50,
    timestamp: '2026-02-17T00:00:00Z',
    binding: {
      run_id: runId,
      event_hash_b64u: eventHash,
    },
  };

  const gatewayReceiptEnvelope = await signEnvelope({
    payload: gatewayReceiptPayload,
    envelopeType: 'gateway_receipt',
    signerDid: gateway.did,
    privateKey: gateway.privateKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });

  const coveragePayload: Record<string, unknown> = {
    attestation_version: '1',
    attestation_id: 'cov_att_001',
    run_id: args?.coverageRunId ?? runId,
    agent_did: agent.did,
    sentinel_did: sentinel.did,
    issued_at: '2026-02-17T00:00:00Z',
    binding: {
      event_chain_root_hash_b64u: args?.coverageChainRootHash ?? eventHash,
    },
    metrics: {
      lineage: {
        root_pid: 1000,
        processes_tracked: 12,
        unmonitored_spawns: 0,
        escapes_suspected: false,
      },
      egress: {
        connections_total: 3,
        unmediated_connections: 0,
      },
      liveness: {
        status: args?.livenessStatus ?? 'continuous',
        uptime_ms: 12_000,
        heartbeat_interval_ms: 500,
        max_gap_ms: args?.livenessMaxGapMs ?? 200,
      },
    },
  };

  const coverageEnvelope = await signEnvelope({
    payload: coveragePayload,
    envelopeType: 'coverage_attestation',
    signerDid: sentinel.did,
    privateKey: sentinel.privateKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });

  const bundlePayload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: 'bundle_cov_001',
    agent_did: agent.did,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
    receipts: [gatewayReceiptEnvelope],
    coverage_attestations: [coverageEnvelope],
  };

  const bundleEnvelope = await signEnvelope({
    payload: bundlePayload,
    envelopeType: 'proof_bundle',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-17T00:00:01Z',
  });

  return {
    coverageEnvelope,
    bundleEnvelope,
    agentDid: agent.did,
    gatewayDid: gateway.did,
    sentinelDid: sentinel.did,
  };
}

describe('coverage attestation verifier', () => {
  it('verifies valid coverage attestation envelope cryptographically', async () => {
    const { coverageEnvelope, sentinelDid } = await makeGatewayBundleWithCoverage();

    const out = await verifyCoverageAttestation(coverageEnvelope, {
      allowlistedSignerDids: [sentinelDid],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.error).toBeUndefined();
  });

  it('fails when signer is not allowlisted', async () => {
    const { coverageEnvelope } = await makeGatewayBundleWithCoverage();

    const out = await verifyCoverageAttestation(coverageEnvelope, {
      allowlistedSignerDids: ['did:key:zNotAllowlistedCoverageSigner'],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('CLAIM_NOT_FOUND');
  });
});

describe('proof bundle coverage runtime binding + phase gating', () => {
  it('valid attestation/binding passes with coverage counters', async () => {
    const { bundleEnvelope, gatewayDid, sentinelDid } = await makeGatewayBundleWithCoverage();

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedReceiptSignerDids: [gatewayDid],
      allowlistedCoverageAttestationSignerDids: [sentinelDid],
      coverage_enforcement_phase: 'enforce',
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('gateway');
    expect(out.result.component_results?.coverage_attestations_count).toBe(1);
    expect(out.result.component_results?.coverage_attestations_signature_verified_count).toBe(1);
    expect(out.result.component_results?.coverage_attestations_verified_count).toBe(1);
    expect(out.result.component_results?.coverage_attestations_valid).toBe(true);
  });

  it('fails coverage binding on chain-root mismatch', async () => {
    const { bundleEnvelope, gatewayDid, sentinelDid } = await makeGatewayBundleWithCoverage({
      coverageChainRootHash: 'chain_root_mismatch_cov_001',
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedReceiptSignerDids: [gatewayDid],
      allowlistedCoverageAttestationSignerDids: [sentinelDid],
      coverage_enforcement_phase: 'observe',
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.component_results?.coverage_attestations_verified_count).toBe(0);
    expect(out.result.component_results?.coverage_attestations_valid).toBe(false);
    expect(out.result.risk_flags).toContain('COVERAGE_ATTESTATION_CHAIN_ROOT_MISMATCH');
  });

  it('fails coverage binding on run_id mismatch', async () => {
    const { bundleEnvelope, gatewayDid, sentinelDid } = await makeGatewayBundleWithCoverage({
      coverageRunId: 'run_cov_mismatch_001',
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedReceiptSignerDids: [gatewayDid],
      allowlistedCoverageAttestationSignerDids: [sentinelDid],
      coverage_enforcement_phase: 'observe',
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.component_results?.coverage_attestations_verified_count).toBe(0);
    expect(out.result.component_results?.coverage_attestations_valid).toBe(false);
    expect(out.result.risk_flags).toContain('COVERAGE_ATTESTATION_RUN_ID_MISMATCH');
  });

  it('enforce phase downgrades on verified coverage invariant failure', async () => {
    const { bundleEnvelope, gatewayDid, sentinelDid } = await makeGatewayBundleWithCoverage({
      livenessMaxGapMs: 7_500,
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedReceiptSignerDids: [gatewayDid],
      allowlistedCoverageAttestationSignerDids: [sentinelDid],
      coverage_enforcement_phase: 'enforce',
      maxCoverageLivenessGapMs: 1_000,
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('self');
    expect(out.result.trust_tier).toBe('basic');
    expect(out.result.risk_flags).toContain('COVERAGE_LIVENESS_GAP_EXCEEDED');
    expect(out.result.risk_flags).toContain('COVERAGE_ENFORCEMENT_DOWNGRADE');
  });

  it.each(['observe', 'warn'] as const)(
    '%s phase does not downgrade on coverage invariant failure',
    async (phase) => {
      const { bundleEnvelope, gatewayDid, sentinelDid } = await makeGatewayBundleWithCoverage({
        livenessMaxGapMs: 8_000,
      });

      const out = await verifyProofBundle(bundleEnvelope, {
        allowlistedReceiptSignerDids: [gatewayDid],
        allowlistedCoverageAttestationSignerDids: [sentinelDid],
        coverage_enforcement_phase: phase,
        maxCoverageLivenessGapMs: 1_000,
      });

      expect(out.result.status).toBe('VALID');
      expect(out.result.proof_tier).toBe('gateway');
      expect(out.result.risk_flags).toContain('COVERAGE_LIVENESS_GAP_EXCEEDED');
      expect(out.result.risk_flags).not.toContain('COVERAGE_ENFORCEMENT_DOWNGRADE');
    }
  );
});
