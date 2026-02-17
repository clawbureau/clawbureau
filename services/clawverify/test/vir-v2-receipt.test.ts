import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyReceipt } from '../src/verify-receipt';

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

async function makeVirV2Envelope(args?: {
  modelClaimed?: string;
  modelObserved?: string;
  nonce?: string;
  subjectDid?: string;
  scopeHash?: string;
  evidenceConflicts?: unknown[];
  tamperLeafValue?: boolean;
}) {
  const signer = await makeDidKeyEd25519();

  const nonce = args?.nonce ?? 'nonce_v2_001';
  const subjectDid = args?.subjectDid ?? 'did:key:zSubject0001';
  const scopeHash = args?.scopeHash ?? 'scope_hash_v2_001';
  const modelClaimed = args?.modelClaimed ?? 'gpt-4';
  const modelObserved = args?.modelObserved ?? 'gpt-4';

  const leaves: Record<string, { type: 'string' | 'number' | 'boolean' | 'null'; value: unknown; salt_b64u: string }> = {
    model_claimed: { type: 'string', value: modelClaimed, salt_b64u: 'salt_model_claimed_001' },
    model_observed: { type: 'string', value: modelObserved, salt_b64u: 'salt_model_observed_001' },
    tokens_input: { type: 'number', value: 120, salt_b64u: 'salt_tokens_input_001' },
    tokens_output: { type: 'number', value: 240, salt_b64u: 'salt_tokens_output_001' },
    nonce: { type: 'string', value: nonce, salt_b64u: 'salt_nonce_001' },
  };

  const leafHashes: string[] = [];
  for (const key of Object.keys(leaves).sort((a, b) => a.localeCompare(b))) {
    const leaf = leaves[key]!;
    const value = args?.tamperLeafValue && key === 'tokens_input' ? 121 : leaf.value;
    leafHashes.push(
      await sha256Utf8B64u(
        `vir_v2_leaf|${key}|${leaf.type}|${leaf.salt_b64u}|${stringifyLeafValue(leaf.type, value)}`
      )
    );
  }

  const root = await sha256Utf8B64u(`vir_v2_root|${[...leafHashes].sort((a, b) => a.localeCompare(b)).join('|')}`);

  const payload: Record<string, unknown> = {
    receipt_version: '2',
    receipt_id: 'vir_v2_001',
    source: 'gateway',
    provider: 'openai',
    model: modelObserved,
    model_claimed: modelClaimed,
    model_observed: modelObserved,
    request_hash_b64u: 'req_hash_v2_001',
    response_hash_b64u: 'res_hash_v2_001',
    tokens_input: 120,
    tokens_output: 240,
    latency_ms: 300,
    agent_did: signer.did,
    timestamp: '2026-02-17T00:00:00Z',
    binding: {
      run_id: 'run_v2_001',
      event_hash_b64u: 'event_hash_v2_001',
      nonce,
      subject_did: subjectDid,
      scope_hash_b64u: scopeHash,
    },
    legal_binding: {
      nonce,
      subject_did: subjectDid,
      scope_hash_b64u: scopeHash,
    },
    evidence_conflicts: args?.evidenceConflicts,
    selective_disclosure: {
      disclosure_algorithm: 'vir_v2_typed_lexicographical',
      merkle_root_b64u: root,
      redacted_leaf_hashes_b64u: [],
      disclosed_leaves: leaves,
    },
  };

  const payloadHash = await computeHash(payload, 'SHA-256');
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', signer.privateKey, new TextEncoder().encode(payloadHash))
  );

  return {
    envelope_version: '1' as const,
    envelope_type: 'vir_receipt' as const,
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256' as const,
    signature_b64u: base64UrlEncode(signature),
    algorithm: 'Ed25519' as const,
    signer_did: signer.did,
    issued_at: '2026-02-17T00:00:00Z',
  };
}

describe('VIR v2 receipt verification', () => {
  it('accepts valid v2 envelope and strict legal binding', async () => {
    const env = await makeVirV2Envelope();

    const out = await verifyReceipt(env, {
      requiresJobBinding: true,
      expectedNonce: 'nonce_v2_001',
      expectedSubject: 'did:key:zSubject0001',
      expectedScope: 'scope_hash_v2_001',
    });

    expect(out.result.status).toBe('VALID');
  });

  it('fails on merkle root mismatch', async () => {
    const env = await makeVirV2Envelope({ tamperLeafValue: true });

    const out = await verifyReceipt(env);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.message).toContain('ERR_MERKLE_ROOT_MISMATCH');
  });

  it('fails on expected nonce mismatch', async () => {
    const env = await makeVirV2Envelope();

    const out = await verifyReceipt(env, {
      expectedNonce: 'nonce_other',
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
  });

  it('fails when model divergence is not reported in evidence_conflicts', async () => {
    const env = await makeVirV2Envelope({
      modelClaimed: 'gpt-4',
      modelObserved: 'gpt-3.5',
      evidenceConflicts: [],
    });

    const out = await verifyReceipt(env);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.message).toContain('ERR_CONFLICT_UNREPORTED');
  });

  it('fails on precedence violation inside evidence_conflicts', async () => {
    const env = await makeVirV2Envelope({
      evidenceConflicts: [
        {
          field: 'model',
          authoritative_source: 'interpose',
          divergent_source: 'tls_decrypt',
          authoritative_value: 'gpt-4',
          divergent_value: 'gpt-3.5',
        },
      ],
    });

    const out = await verifyReceipt(env);

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.message).toContain('ERR_PRECEDENCE_VIOLATION');
  });
});
