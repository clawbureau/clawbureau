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
  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', keypair.publicKey));

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  return {
    did: `did:key:z${base58Encode(prefixed)}`,
    privateKey: keypair.privateKey,
  };
}

async function sha256Utf8B64u(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

function stringifyLeafValue(type: string, value: unknown): string {
  if (type === 'string') return String(value);
  if (type === 'number') return `${value}`;
  if (type === 'boolean') return value ? 'true' : 'false';
  return 'null';
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

async function makeVirV2Bundle(args?: {
  modelClaimed?: string;
  modelObserved?: string;
  evidenceConflicts?: unknown[];
  tamperLeafValue?: boolean;
}) {
  const agent = await makeDidKeyEd25519();
  const runId = 'run_vir_v2_bundle_001';

  const eventPayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
  const eventHeader = {
    event_id: 'evt_vir_v2_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-17T00:00:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };
  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const modelClaimed = args?.modelClaimed ?? 'gpt-4';
  const modelObserved = args?.modelObserved ?? 'gpt-4';

  const disclosedLeaves: Record<string, { type: 'string' | 'number' | 'boolean' | 'null'; value: unknown; salt_b64u: string }> = {
    model_claimed: { type: 'string', value: modelClaimed, salt_b64u: 'salt_model_claimed_bundle_001' },
    model_observed: { type: 'string', value: modelObserved, salt_b64u: 'salt_model_observed_bundle_001' },
    tokens_input: { type: 'number', value: 111, salt_b64u: 'salt_tokens_input_bundle_001' },
    tokens_output: { type: 'number', value: 222, salt_b64u: 'salt_tokens_output_bundle_001' },
  };

  const disclosedLeafHashes: string[] = [];
  for (const key of Object.keys(disclosedLeaves).sort((a, b) => a.localeCompare(b))) {
    const leaf = disclosedLeaves[key]!;
    const value = args?.tamperLeafValue && key === 'tokens_input' ? 112 : leaf.value;
    disclosedLeafHashes.push(
      await sha256Utf8B64u(
        `vir_v2_leaf|${key}|${leaf.type}|${leaf.salt_b64u}|${stringifyLeafValue(leaf.type, value)}`
      )
    );
  }

  const merkleRoot = await sha256Utf8B64u(
    `vir_v2_root|${[...disclosedLeafHashes].sort((a, b) => a.localeCompare(b)).join('|')}`
  );

  const virPayload: Record<string, unknown> = {
    receipt_version: '2',
    receipt_id: 'vir_v2_bundle_001',
    source: 'gateway',
    provider: 'openai',
    model: modelObserved,
    model_claimed: modelClaimed,
    model_observed: modelObserved,
    request_hash_b64u: 'req_hash_vir_v2_bundle_001',
    response_hash_b64u: 'res_hash_vir_v2_bundle_001',
    tokens_input: 111,
    tokens_output: 222,
    latency_ms: 333,
    agent_did: agent.did,
    timestamp: '2026-02-17T00:00:00Z',
    binding: {
      run_id: runId,
      event_hash_b64u: eventHash,
      nonce: 'nonce_v2_bundle_001',
      subject_did: 'did:key:zSubjectBundle001',
      scope_hash_b64u: 'scope_hash_bundle_001',
    },
    legal_binding: {
      nonce: 'nonce_v2_bundle_001',
      subject_did: 'did:key:zSubjectBundle001',
      scope_hash_b64u: 'scope_hash_bundle_001',
    },
    evidence_conflicts: args?.evidenceConflicts,
    selective_disclosure: {
      disclosure_algorithm: 'vir_v2_typed_lexicographical',
      merkle_root_b64u: merkleRoot,
      redacted_leaf_hashes_b64u: [],
      disclosed_leaves: disclosedLeaves,
    },
  };

  const virEnvelope = await signEnvelope({
    payload: virPayload,
    envelopeType: 'vir_receipt',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });

  const bundlePayload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: 'bundle_vir_v2_001',
    agent_did: agent.did,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
    vir_receipts: [virEnvelope],
  };

  const bundleEnvelope = await signEnvelope({
    payload: bundlePayload,
    envelopeType: 'proof_bundle',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-17T00:00:01Z',
  });

  return { bundleEnvelope };
}

describe('VIR v2 proof-bundle fail-closed integrity', () => {
  it('hard-fails on unreported model divergence conflicts', async () => {
    const { bundleEnvelope } = await makeVirV2Bundle({
      modelClaimed: 'gpt-4',
      modelObserved: 'gpt-3.5',
      evidenceConflicts: [],
    });

    const out = await verifyProofBundle(bundleEnvelope);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.result.reason).toContain('unreported');
  });

  it('hard-fails on selective-disclosure merkle mismatches', async () => {
    const { bundleEnvelope } = await makeVirV2Bundle({ tamperLeafValue: true });

    const out = await verifyProofBundle(bundleEnvelope);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.result.reason).toContain('merkle_root mismatch');
  });

  it('accepts reported model divergence when conflict is explicit', async () => {
    const { bundleEnvelope } = await makeVirV2Bundle({
      modelClaimed: 'gpt-4',
      modelObserved: 'gpt-3.5',
      evidenceConflicts: [
        {
          field: 'model',
          authoritative_source: 'gateway',
          divergent_source: 'preload',
          authoritative_value: 'gpt-3.5',
          divergent_value: 'gpt-4',
        },
      ],
    });

    const out = await verifyProofBundle(bundleEnvelope);

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('gateway');
    expect(out.result.risk_flags).toContain('MODEL_SUBSTITUTION_DETECTED');
  });
});
