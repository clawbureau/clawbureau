import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  type BinarySemanticEvidenceReasonCode,
  type BinarySemanticEvidenceVerdict,
} from '../src/types';
import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyProofBundle } from '../src/verify-proof-bundle';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

type FixtureExpected = {
  status: 'VALID' | 'INVALID';
  error_code?: string;
  policy_verdict: BinarySemanticEvidenceVerdict;
  reason_code: BinarySemanticEvidenceReasonCode;
  proof_tier?: string;
  trust_tier?: string;
};

type FixtureCase = {
  id: string;
  scenario:
    | 'valid_semantics_verified'
    | 'invalid_hash_mismatch'
    | 'invalid_chain_forgery_merkle_broken'
    | 'invalid_unattested_child_process'
    | 'invalid_capability_arbitrage'
    | 'invalid_analysis_exhaustion'
    | 'valid_inapplicable_unsupported_arch'
    | 'valid_inapplicable_sip_protected'
    | 'valid_partial_stripped_symbols'
    | 'invalid_precedence_causal_over_contradiction';
  expected: FixtureExpected;
};

type FixtureManifest = {
  manifest_version: '1';
  suite: string;
  cases: string[];
};

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

async function makeBaseBundleParts(agentDid: string, runId: string) {
  const eventPayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
  const eventHeader = {
    event_id: `evt_${runId}`,
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-17T00:00:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };

  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const bundlePayload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: `bundle_${runId}`,
    agent_did: agentDid,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
  };

  return { eventHash, bundlePayload };
}

async function makeGatewayReceiptEnvelope(args: {
  signerDid: string;
  signerKey: CryptoKey;
  runId: string;
  eventHash: string;
}) {
  const payload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: `gw_${args.runId}`,
    gateway_id: 'gw_binary_semantic_001',
    provider: 'openai',
    model: 'gpt-4.1',
    request_hash_b64u: 'req_hash_binary_semantic_001',
    response_hash_b64u: 'res_hash_binary_semantic_001',
    tokens_input: 120,
    tokens_output: 220,
    latency_ms: 240,
    timestamp: '2026-02-17T00:00:00Z',
    binding: {
      run_id: args.runId,
      event_hash_b64u: args.eventHash,
    },
  };

  return signEnvelope({
    payload,
    envelopeType: 'gateway_receipt',
    signerDid: args.signerDid,
    privateKey: args.signerKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });
}

function makeBaseBinarySemanticPayload() {
  return {
    evidence_version: '1' as const,
    binary_hash_b64u: 'binary_hash_semantic_001',
    binary_profile: {
      target_architecture: 'arm64' as const,
      linkage: 'DYNAMIC' as const,
      symbols: 'INTACT' as const,
      is_sip_protected: false,
    },
    extracted_claims: {
      network_egress: 'PRESENT' as const,
      dynamic_code_generation: 'ABSENT' as const,
    },
    causality_metrics: {
      merkle_chain_intact: true,
      unattested_children_spawned: false,
    },
    forensic_metrics: {
      static_analysis_budget_exhausted: false,
      parser_timeout: false,
      normalized_regions_scanned: 32,
    },
  };
}

async function makeBinarySemanticEnvelope(args: {
  signerDid: string;
  signerKey: CryptoKey;
  payload: ReturnType<typeof makeBaseBinarySemanticPayload>;
  tamperHash?: boolean;
}) {
  const envelope = await signEnvelope({
    payload: args.payload,
    envelopeType: 'binary_semantic_evidence',
    signerDid: args.signerDid,
    privateKey: args.signerKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });

  if (args.tamperHash) {
    return {
      ...envelope,
      payload_hash_b64u: 'tampered_binary_hash_001',
    };
  }

  return envelope;
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.resolve(
  __dirname,
  '../../../packages/schema/fixtures/protocol-conformance/clawverify-binary-semantic'
);

const manifest = JSON.parse(
  fs.readFileSync(path.join(fixtureDir, 'manifest.v1.json'), 'utf8')
) as FixtureManifest;

function loadFixture(filename: string): FixtureCase {
  return JSON.parse(fs.readFileSync(path.join(fixtureDir, filename), 'utf8')) as FixtureCase;
}

describe('CEC-US-006 binary semantic conformance', () => {
  it('has a valid fixture manifest', () => {
    expect(manifest.manifest_version).toBe('1');
    expect(manifest.suite).toBe('clawverify-binary-semantic');
    expect(Array.isArray(manifest.cases)).toBe(true);
    expect(manifest.cases.length).toBeGreaterThanOrEqual(10);
  });

  for (const fixtureFile of manifest.cases) {
    const fixture = loadFixture(fixtureFile);

    it(fixture.id, async () => {
      const agent = await makeDidKeyEd25519();
      const gateway = await makeDidKeyEd25519();
      const binaryWitness = await makeDidKeyEd25519();

      const runId = `run_${fixture.id.replace(/[^a-z0-9]+/gi, '_').toLowerCase()}`;
      const { eventHash, bundlePayload } = await makeBaseBundleParts(agent.did, runId);

      const binaryPayload = makeBaseBinarySemanticPayload();
      let includeGatewayReceipt = false;
      let tamperHash = false;

      switch (fixture.scenario) {
        case 'valid_semantics_verified':
          break;
        case 'invalid_hash_mismatch':
          tamperHash = true;
          break;
        case 'invalid_chain_forgery_merkle_broken':
          binaryPayload.causality_metrics.merkle_chain_intact = false;
          break;
        case 'invalid_unattested_child_process':
          binaryPayload.causality_metrics.unattested_children_spawned = true;
          break;
        case 'invalid_capability_arbitrage':
          binaryPayload.extracted_claims.network_egress = 'ABSENT';
          includeGatewayReceipt = true;
          break;
        case 'invalid_analysis_exhaustion':
          binaryPayload.forensic_metrics.static_analysis_budget_exhausted = true;
          break;
        case 'valid_inapplicable_unsupported_arch':
          binaryPayload.binary_profile.target_architecture = 'unknown';
          includeGatewayReceipt = true;
          break;
        case 'valid_inapplicable_sip_protected':
          binaryPayload.binary_profile.is_sip_protected = true;
          includeGatewayReceipt = true;
          break;
        case 'valid_partial_stripped_symbols':
          binaryPayload.binary_profile.symbols = 'STRIPPED';
          includeGatewayReceipt = true;
          break;
        case 'invalid_precedence_causal_over_contradiction':
          binaryPayload.causality_metrics.merkle_chain_intact = false;
          binaryPayload.extracted_claims.network_egress = 'ABSENT';
          includeGatewayReceipt = true;
          break;
      }

      const binaryEnvelope = await makeBinarySemanticEnvelope({
        signerDid: binaryWitness.did,
        signerKey: binaryWitness.privateKey,
        payload: binaryPayload,
        tamperHash,
      });

      bundlePayload.binary_semantic_evidence_attestations = [binaryEnvelope];

      if (includeGatewayReceipt) {
        const gatewayReceipt = await makeGatewayReceiptEnvelope({
          signerDid: gateway.did,
          signerKey: gateway.privateKey,
          runId,
          eventHash,
        });
        bundlePayload.receipts = [gatewayReceipt];
      }

      const bundleEnvelope = await signEnvelope({
        payload: bundlePayload,
        envelopeType: 'proof_bundle',
        signerDid: agent.did,
        privateKey: agent.privateKey,
        issuedAt: '2026-02-17T00:00:00Z',
      });

      const out = await verifyProofBundle(bundleEnvelope, {
        allowlistedReceiptSignerDids: [gateway.did],
        allowlistedBinarySemanticEvidenceSignerDids: [binaryWitness.did],
      });

      expect(out.result.status).toBe(fixture.expected.status);
      expect(out.result.component_results?.binary_semantic_evidence_policy_verdict).toBe(
        fixture.expected.policy_verdict,
      );
      expect(out.result.component_results?.binary_semantic_evidence_reason_code).toBe(
        fixture.expected.reason_code,
      );

      if (fixture.expected.error_code) {
        expect(out.error?.code).toBe(fixture.expected.error_code);
      }

      if (fixture.expected.proof_tier) {
        expect(out.result.proof_tier).toBe(fixture.expected.proof_tier);
      }

      if (fixture.expected.trust_tier) {
        expect(out.result.trust_tier).toBe(fixture.expected.trust_tier);
      }
    });
  }
});
