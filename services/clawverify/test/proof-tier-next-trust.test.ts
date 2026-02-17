import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
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

  const did = `did:key:z${base58Encode(prefixed)}`;
  return { did, privateKey: keypair.privateKey };
}

async function signEnvelope<T extends Record<string, unknown>>(args: {
  payload: T;
  envelopeType: string;
  signerDid: string;
  privateKey: CryptoKey;
  issuedAt: string;
}) {
  const payloadHash = await computeHash(args.payload, 'SHA-256');
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign('Ed25519', args.privateKey, new TextEncoder().encode(payloadHash))
  );

  return {
    envelope_version: '1' as const,
    envelope_type: args.envelopeType,
    payload: args.payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256' as const,
    signature_b64u: base64UrlEncode(sigBytes),
    algorithm: 'Ed25519' as const,
    signer_did: args.signerDid,
    issued_at: args.issuedAt,
  };
}

async function makeWebOnlyBundle(args?: { replayMismatch?: boolean }) {
  const agent = await makeDidKeyEd25519();
  const witness = await makeDidKeyEd25519();

  const runId = 'run_web_001';
  const eventPayloadHash = await computeHash({ type: 'llm_call_web' }, 'SHA-256');
  const eventHeader = {
    event_id: 'evt_web_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-17T00:00:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };
  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const webReceiptPayload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: 'wr_001',
    witness_id: 'witness_runtime_001',
    source: 'chatgpt_web',
    request_hash_b64u: 'req_web_hash_001',
    response_hash_b64u: 'res_web_hash_001',
    timestamp: '2026-02-17T00:00:00Z',
    binding: {
      run_id: args?.replayMismatch ? 'run_other_001' : runId,
      event_hash_b64u: eventHash,
    },
  };

  const webReceiptEnvelope = await signEnvelope({
    payload: webReceiptPayload,
    envelopeType: 'web_receipt',
    signerDid: witness.did,
    privateKey: witness.privateKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });

  const bundlePayload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: 'bundle_web_001',
    agent_did: agent.did,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
    web_receipts: [webReceiptEnvelope],
  };

  const bundleEnvelope = await signEnvelope({
    payload: bundlePayload,
    envelopeType: 'proof_bundle',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-17T00:00:01Z',
  });

  return { bundleEnvelope, witnessDid: witness.did };
}

async function makeBundleWithTeeExecutionAttestation(args?: { revokedTcb?: boolean }) {
  const agent = await makeDidKeyEd25519();
  const attester = await makeDidKeyEd25519();

  const runId = 'run_tee_001';
  const eventPayloadHash = await computeHash({ type: 'llm_call_tee' }, 'SHA-256');
  const eventHeader = {
    event_id: 'evt_tee_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-17T00:00:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };
  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const bundlePayload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: 'bundle_tee_001',
    agent_did: agent.did,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
  };

  const bundlePayloadHash = await computeHash(bundlePayload, 'SHA-256');

  const tcbVersion = args?.revokedTcb ? 'tdx-1.2.3-revoked' : 'tdx-1.2.3-good';

  const executionAttestationPayload: Record<string, unknown> = {
    attestation_version: '1',
    attestation_id: 'ea_tee_001',
    execution_type: 'tee_execution',
    agent_did: agent.did,
    attester_did: attester.did,
    run_id: runId,
    proof_bundle_hash_b64u: bundlePayloadHash,
    runtime_metadata: {
      tee: {
        attestation_type: 'tdx_quote',
        root_id: 'intel-tdx-root-001',
        tcb_version: tcbVersion,
        evidence_ref: {
          resource_type: 'tee_quote',
          resource_hash_b64u: 'tee_quote_hash_001',
        },
        measurements: {
          measurement_hash_b64u: 'tee_measurement_hash_001',
        },
      },
    },
    issued_at: '2026-02-17T00:00:00Z',
  };

  const executionAttestationEnvelope = await signEnvelope({
    payload: executionAttestationPayload,
    envelopeType: 'execution_attestation',
    signerDid: attester.did,
    privateKey: attester.privateKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });

  const bundleEnvelope = await signEnvelope({
    payload: bundlePayload,
    envelopeType: 'proof_bundle',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-17T00:00:01Z',
  });

  return {
    bundleEnvelope,
    executionAttestationEnvelope,
    attesterDid: attester.did,
    tcbVersion,
  };
}

async function makeGatewayBundleWithCoverageInvariantFailure() {
  const agent = await makeDidKeyEd25519();
  const gateway = await makeDidKeyEd25519();
  const sentinel = await makeDidKeyEd25519();

  const runId = 'run_cov_phase_001';
  const eventPayloadHash = await computeHash({ type: 'llm_call_cov_phase' }, 'SHA-256');
  const eventHeader = {
    event_id: 'evt_cov_phase_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-17T00:00:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };
  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const receiptPayload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: 'rcpt_cov_phase_001',
    gateway_id: 'gw_cov_phase_001',
    provider: 'openai',
    model: 'gpt-4',
    request_hash_b64u: 'req_cov_phase_hash_001',
    response_hash_b64u: 'res_cov_phase_hash_001',
    tokens_input: 12,
    tokens_output: 24,
    latency_ms: 45,
    timestamp: '2026-02-17T00:00:00Z',
    binding: {
      run_id: runId,
      event_hash_b64u: eventHash,
    },
  };

  const receiptEnvelope = await signEnvelope({
    payload: receiptPayload,
    envelopeType: 'gateway_receipt',
    signerDid: gateway.did,
    privateKey: gateway.privateKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });

  const coveragePayload: Record<string, unknown> = {
    attestation_version: '1',
    attestation_id: 'cov_phase_001',
    run_id: runId,
    agent_did: agent.did,
    sentinel_did: sentinel.did,
    issued_at: '2026-02-17T00:00:00Z',
    binding: {
      event_chain_root_hash_b64u: eventHash,
    },
    metrics: {
      lineage: {
        root_pid: 1000,
        processes_tracked: 8,
        unmonitored_spawns: 0,
        escapes_suspected: false,
      },
      egress: {
        connections_total: 2,
        unmediated_connections: 0,
      },
      liveness: {
        status: 'continuous',
        uptime_ms: 10_000,
        heartbeat_interval_ms: 500,
        max_gap_ms: 9_000,
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
    bundle_id: 'bundle_cov_phase_001',
    agent_did: agent.did,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
    receipts: [receiptEnvelope],
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
    bundleEnvelope,
    gatewayDid: gateway.did,
    sentinelDid: sentinel.did,
  };
}

describe('P0 deterministic evidence firewall: web + tee core', () => {
  it('uplifts proof_tier to witnessed_web for valid allowlisted web receipts', async () => {
    const { bundleEnvelope, witnessDid } = await makeWebOnlyBundle();

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: [witnessDid],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('witnessed_web');
    expect(out.result.component_results?.web_receipts_verified_count).toBe(1);
  });

  it('rejects replayed web receipt binding and does not uplift to gateway', async () => {
    const { bundleEnvelope, witnessDid } = await makeWebOnlyBundle({
      replayMismatch: true,
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: [witnessDid],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('self');
    expect(out.result.component_results?.web_receipts_verified_count).toBe(0);
  });

  it('uplifts model_identity_tier to tee_measured only on valid bound tee evidence', async () => {
    const {
      bundleEnvelope,
      executionAttestationEnvelope,
      attesterDid,
      tcbVersion,
    } = await makeBundleWithTeeExecutionAttestation();

    const out = await verifyProofBundle(bundleEnvelope, {
      execution_attestations: [executionAttestationEnvelope],
      allowlistedExecutionAttestationSignerDids: [attesterDid],
      teeRootAllowlist: ['intel-tdx-root-001'],
      teeTcbAllowlist: [tcbVersion],
      teeRootRevoked: [],
      teeTcbRevoked: [],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('sandbox');
    expect(out.result.model_identity_tier).toBe('tee_measured');
    expect(out.result.component_results?.execution_attestations_verified_count).toBe(1);
    expect(out.result.component_results?.tee_execution_verified_count).toBe(1);
  });

  it('hard-fails on revoked TEE TCB claims', async () => {
    const {
      bundleEnvelope,
      executionAttestationEnvelope,
      attesterDid,
      tcbVersion,
    } = await makeBundleWithTeeExecutionAttestation({ revokedTcb: true });

    const out = await verifyProofBundle(bundleEnvelope, {
      execution_attestations: [executionAttestationEnvelope],
      allowlistedExecutionAttestationSignerDids: [attesterDid],
      teeRootAllowlist: ['intel-tdx-root-001'],
      teeTcbAllowlist: [tcbVersion],
      teeRootRevoked: [],
      teeTcbRevoked: [tcbVersion],
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('REVOKED');
  });

  it('enforce phase fails closed on coverage invariant failures', async () => {
    const { bundleEnvelope, gatewayDid, sentinelDid } =
      await makeGatewayBundleWithCoverageInvariantFailure();

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedReceiptSignerDids: [gatewayDid],
      allowlistedCoverageAttestationSignerDids: [sentinelDid],
      coverage_enforcement_phase: 'enforce',
      maxCoverageLivenessGapMs: 1_000,
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.result.risk_flags).toContain('COVERAGE_LIVENESS_GAP_EXCEEDED');
  });

  it.each(['observe', 'warn'] as const)(
    '%s phase does not downgrade proof tier on coverage invariant failures',
    async (phase) => {
      const { bundleEnvelope, gatewayDid, sentinelDid } =
        await makeGatewayBundleWithCoverageInvariantFailure();

      const out = await verifyProofBundle(bundleEnvelope, {
        allowlistedReceiptSignerDids: [gatewayDid],
        allowlistedCoverageAttestationSignerDids: [sentinelDid],
        coverage_enforcement_phase: phase,
        maxCoverageLivenessGapMs: 1_000,
      });

      expect(out.result.status).toBe('VALID');
      expect(out.result.proof_tier).toBe('gateway');
      expect(out.result.risk_flags).toContain('COVERAGE_LIVENESS_GAP_EXCEEDED');
    }
  );
});
