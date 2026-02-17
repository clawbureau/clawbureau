import { describe, expect, it } from 'vitest';

import { validateProofBundleEnvelopeV1 } from '../src/schema-validation';

function b64u(len = 16): string {
  return 'a'.repeat(len);
}

function makeBaseEventChain() {
  return [
    {
      event_id: 'evt_contract_001',
      run_id: 'run_contract_001',
      event_type: 'llm_call',
      timestamp: '2026-02-17T00:00:00Z',
      payload_hash_b64u: b64u(16),
      prev_hash_b64u: null,
      event_hash_b64u: b64u(16),
    },
  ];
}

function makeProofBundleEnvelope(payload: Record<string, unknown>) {
  return {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload,
    payload_hash_b64u: b64u(16),
    hash_algorithm: 'SHA-256',
    signature_b64u: b64u(86),
    algorithm: 'Ed25519',
    signer_did: 'did:key:zSchemaContractSigner0001',
    issued_at: '2026-02-17T00:00:01Z',
  };
}

function makeVirV2Envelope() {
  return {
    envelope_version: '1',
    envelope_type: 'vir_receipt',
    payload: {
      receipt_version: '2',
      receipt_id: 'vir_contract_001',
      source: 'gateway',
      provider: 'openai',
      model: 'gpt-4',
      model_claimed: 'gpt-4',
      model_observed: 'gpt-4',
      request_hash_b64u: b64u(16),
      response_hash_b64u: b64u(16),
      tokens_input: 10,
      tokens_output: 20,
      latency_ms: 30,
      agent_did: 'did:key:zSchemaContractSigner0001',
      timestamp: '2026-02-17T00:00:00Z',
      binding: {
        run_id: 'run_contract_001',
        event_hash_b64u: b64u(16),
        nonce: 'nonce_contract_001',
        subject_did: 'did:key:zSchemaContractSubject0001',
        scope_hash_b64u: b64u(16),
      },
      legal_binding: {
        nonce: 'nonce_contract_001',
        subject_did: 'did:key:zSchemaContractSubject0001',
        scope_hash_b64u: b64u(16),
      },
      selective_disclosure: {
        disclosure_algorithm: 'vir_v2_typed_lexicographical',
        merkle_root_b64u: b64u(16),
        redacted_leaf_hashes_b64u: [],
        disclosed_leaves: {
          model_observed: {
            type: 'string',
            value: 'gpt-4',
            salt_b64u: b64u(16),
          },
        },
      },
    },
    payload_hash_b64u: b64u(16),
    hash_algorithm: 'SHA-256',
    signature_b64u: b64u(86),
    algorithm: 'Ed25519',
    signer_did: 'did:key:zSchemaContractSigner0001',
    issued_at: '2026-02-17T00:00:00Z',
  };
}

function makeWebReceiptEnvelope() {
  return {
    envelope_version: '1',
    envelope_type: 'web_receipt',
    payload: {
      receipt_version: '1',
      receipt_id: 'web_contract_001',
      witness_id: 'witness_contract_001',
      source: 'chatgpt_web',
      request_hash_b64u: b64u(16),
      response_hash_b64u: b64u(16),
      timestamp: '2026-02-17T00:00:00Z',
      binding: {
        run_id: 'run_contract_001',
        event_hash_b64u: b64u(16),
      },
    },
    payload_hash_b64u: b64u(16),
    hash_algorithm: 'SHA-256',
    signature_b64u: b64u(86),
    algorithm: 'Ed25519',
    signer_did: 'did:key:zSchemaContractWitness0001',
    issued_at: '2026-02-17T00:00:00Z',
  };
}

function makeCoverageAttestationEnvelope() {
  return {
    envelope_version: '1',
    envelope_type: 'coverage_attestation',
    payload: {
      attestation_version: '1',
      attestation_id: 'coverage_contract_001',
      run_id: 'run_contract_001',
      agent_did: 'did:key:zSchemaContractSigner0001',
      sentinel_did: 'did:key:zSchemaContractSentinel0001',
      issued_at: '2026-02-17T00:00:00Z',
      binding: {
        event_chain_root_hash_b64u: b64u(16),
      },
      metrics: {
        lineage: {
          root_pid: 100,
          processes_tracked: 3,
          unmonitored_spawns: 0,
          escapes_suspected: false,
        },
        egress: {
          connections_total: 5,
          unmediated_connections: 0,
        },
        liveness: {
          status: 'continuous',
          uptime_ms: 1000,
          heartbeat_interval_ms: 100,
          max_gap_ms: 100,
        },
      },
    },
    payload_hash_b64u: b64u(16),
    hash_algorithm: 'SHA-256',
    signature_b64u: b64u(86),
    algorithm: 'Ed25519',
    signer_did: 'did:key:zSchemaContractSentinel0001',
    issued_at: '2026-02-17T00:00:00Z',
  };
}

describe('schema/runtime contract wiring', () => {
  it('accepts proof bundles with vir_receipts carrying VIR v2 envelopes', () => {
    const envelope = makeProofBundleEnvelope({
      bundle_version: '1',
      bundle_id: 'bundle_contract_vir_001',
      agent_did: 'did:key:zSchemaContractSigner0001',
      event_chain: makeBaseEventChain(),
      vir_receipts: [makeVirV2Envelope()],
    });

    const out = validateProofBundleEnvelopeV1(envelope);
    expect(out.valid).toBe(true);
  });

  it('accepts proof bundles with web_receipts field wired to schema refs', () => {
    const envelope = makeProofBundleEnvelope({
      bundle_version: '1',
      bundle_id: 'bundle_contract_web_001',
      agent_did: 'did:key:zSchemaContractSigner0001',
      event_chain: makeBaseEventChain(),
      web_receipts: [makeWebReceiptEnvelope()],
    });

    const out = validateProofBundleEnvelopeV1(envelope);
    expect(out.valid).toBe(true);
  });

  it('accepts proof bundles with coverage_attestations field wired to schema refs', () => {
    const envelope = makeProofBundleEnvelope({
      bundle_version: '1',
      bundle_id: 'bundle_contract_coverage_001',
      agent_did: 'did:key:zSchemaContractSigner0001',
      event_chain: makeBaseEventChain(),
      coverage_attestations: [makeCoverageAttestationEnvelope()],
    });

    const out = validateProofBundleEnvelopeV1(envelope);
    expect(out.valid).toBe(true);
  });
});
