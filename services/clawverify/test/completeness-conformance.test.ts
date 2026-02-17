import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { CompletenessReasonCode, CompletenessVerdict } from '../src/types';
import { base64UrlEncode, computeHash } from '../src/crypto';
import { jcsCanonicalize } from '../src/jcs';
import { verifyProofBundle } from '../src/verify-proof-bundle';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

type FixtureExpected = {
  status: 'VALID' | 'INVALID';
  error_code?: string;
  completeness_verdict: CompletenessVerdict;
  completeness_reason_code: CompletenessReasonCode;
  proof_tier?: string;
  trust_tier?: string;
};

type FixtureCase = {
  id: string;
  scenario:
    | 'complete_evidence_bound'
    | 'partial_event_chain_only'
    | 'partial_envelope_only'
    | 'partial_attestation_class_unverified'
    | 'incomplete_receipt_class_unverified'
    | 'inconsistent_binding_context_missing'
    | 'inconsistent_receipt_binding_mismatch';
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
    await crypto.subtle.exportKey('raw', keypair.publicKey),
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
    await crypto.subtle.sign('Ed25519', args.privateKey, new TextEncoder().encode(payloadHash)),
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

async function makeBaseEventChain(runId: string) {
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

  return {
    eventHash,
    eventChain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
  };
}

async function makeGatewayReceiptEnvelope(args: {
  signerDid: string;
  signerKey: CryptoKey;
  runId: string;
  eventHash: string;
  tamperSignature?: boolean;
}) {
  const payload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: `gw_${args.runId}`,
    gateway_id: 'gw_completeness_001',
    provider: 'openai',
    model: 'gpt-4.1',
    request_hash_b64u: 'req_hash_completeness_001',
    response_hash_b64u: 'res_hash_completeness_001',
    tokens_input: 100,
    tokens_output: 200,
    latency_ms: 220,
    timestamp: '2026-02-17T00:00:00Z',
    binding: {
      run_id: args.runId,
      event_hash_b64u: args.eventHash,
    },
  };

  const signed = await signEnvelope({
    payload,
    envelopeType: 'gateway_receipt',
    signerDid: args.signerDid,
    privateKey: args.signerKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });

  if (!args.tamperSignature) {
    return signed;
  }

  return {
    ...signed,
    signature_b64u: base64UrlEncode(crypto.getRandomValues(new Uint8Array(64))),
  };
}

async function makeAttestationReference(args: {
  attesterDid: string;
  attesterKey: CryptoKey;
  subjectDid: string;
  tamperSignature?: boolean;
}) {
  const unsigned = {
    attestation_id: `att_${args.subjectDid.slice(-8)}`,
    attestation_type: 'third_party' as const,
    attester_did: args.attesterDid,
    subject_did: args.subjectDid,
    signature_b64u: '',
  };

  const canonical = jcsCanonicalize(unsigned);
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', args.attesterKey, new TextEncoder().encode(canonical)),
  );

  return {
    ...unsigned,
    signature_b64u: args.tamperSignature
      ? base64UrlEncode(crypto.getRandomValues(new Uint8Array(64)))
      : base64UrlEncode(signature),
  };
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.resolve(
  __dirname,
  '../../../packages/schema/fixtures/protocol-conformance/clawverify-completeness',
);

const manifest = JSON.parse(
  fs.readFileSync(path.join(fixtureDir, 'manifest.v1.json'), 'utf8'),
) as FixtureManifest;

function loadFixture(filename: string): FixtureCase {
  return JSON.parse(fs.readFileSync(path.join(fixtureDir, filename), 'utf8')) as FixtureCase;
}

describe('CVF-US-067 completeness conformance', () => {
  it('has a valid fixture manifest', () => {
    expect(manifest.manifest_version).toBe('1');
    expect(manifest.suite).toBe('clawverify-completeness');
    expect(Array.isArray(manifest.cases)).toBe(true);
    expect(manifest.cases.length).toBeGreaterThanOrEqual(7);
  });

  for (const fixtureFile of manifest.cases) {
    const fixture = loadFixture(fixtureFile);

    it(fixture.id, async () => {
      const agent = await makeDidKeyEd25519();
      const gateway = await makeDidKeyEd25519();
      const attester = await makeDidKeyEd25519();

      const runId = `run_${fixture.id.replace(/[^a-z0-9]+/gi, '_').toLowerCase()}`;
      const base = await makeBaseEventChain(runId);

      const bundlePayload: Record<string, unknown> = {
        bundle_version: '1',
        bundle_id: `bundle_${runId}`,
        agent_did: agent.did,
      };

      const options: {
        allowlistedReceiptSignerDids: string[];
        allowlistedAttesterDids: string[];
      } = {
        allowlistedReceiptSignerDids: [gateway.did],
        allowlistedAttesterDids: [attester.did],
      };

      switch (fixture.scenario) {
        case 'complete_evidence_bound': {
          bundlePayload.event_chain = base.eventChain;
          bundlePayload.receipts = [
            await makeGatewayReceiptEnvelope({
              signerDid: gateway.did,
              signerKey: gateway.privateKey,
              runId,
              eventHash: base.eventHash,
            }),
          ];
          break;
        }
        case 'partial_event_chain_only': {
          bundlePayload.event_chain = base.eventChain;
          break;
        }
        case 'partial_envelope_only': {
          bundlePayload.attestations = [
            await makeAttestationReference({
              attesterDid: attester.did,
              attesterKey: attester.privateKey,
              subjectDid: agent.did,
              tamperSignature: true,
            }),
          ];
          break;
        }
        case 'partial_attestation_class_unverified': {
          bundlePayload.event_chain = base.eventChain;
          bundlePayload.attestations = [
            await makeAttestationReference({
              attesterDid: attester.did,
              attesterKey: attester.privateKey,
              subjectDid: agent.did,
            }),
          ];
          options.allowlistedAttesterDids = [];
          break;
        }
        case 'incomplete_receipt_class_unverified': {
          bundlePayload.event_chain = base.eventChain;
          bundlePayload.receipts = [
            await makeGatewayReceiptEnvelope({
              signerDid: gateway.did,
              signerKey: gateway.privateKey,
              runId,
              eventHash: base.eventHash,
              tamperSignature: true,
            }),
          ];
          break;
        }
        case 'inconsistent_binding_context_missing': {
          bundlePayload.receipts = [
            await makeGatewayReceiptEnvelope({
              signerDid: gateway.did,
              signerKey: gateway.privateKey,
              runId,
              eventHash: base.eventHash,
            }),
          ];
          break;
        }
        case 'inconsistent_receipt_binding_mismatch': {
          bundlePayload.event_chain = base.eventChain;
          bundlePayload.receipts = [
            await makeGatewayReceiptEnvelope({
              signerDid: gateway.did,
              signerKey: gateway.privateKey,
              runId: `${runId}_wrong`,
              eventHash: base.eventHash,
            }),
          ];
          break;
        }
      }

      const bundleEnvelope = await signEnvelope({
        payload: bundlePayload,
        envelopeType: 'proof_bundle',
        signerDid: agent.did,
        privateKey: agent.privateKey,
        issuedAt: '2026-02-17T00:00:00Z',
      });

      const out = await verifyProofBundle(bundleEnvelope, options);

      expect(out.result.status).toBe(fixture.expected.status);
      expect(out.result.component_results?.completeness_verdict).toBe(
        fixture.expected.completeness_verdict,
      );
      expect(out.result.component_results?.completeness_reason_code).toBe(
        fixture.expected.completeness_reason_code,
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
