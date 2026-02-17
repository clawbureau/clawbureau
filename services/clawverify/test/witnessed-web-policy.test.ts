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

async function computeWebReceiptLeafHash(payload: Record<string, unknown>): Promise<string> {
  const bindingRecord =
    typeof payload.binding === 'object' && payload.binding !== null
      ? (payload.binding as Record<string, unknown>)
      : null;

  return computeHash(
    {
      leaf_version: 'web_receipt_v1',
      receipt_version: payload.receipt_version,
      receipt_id: payload.receipt_id,
      witness_id: payload.witness_id,
      source: payload.source,
      request_hash_b64u: payload.request_hash_b64u,
      response_hash_b64u: payload.response_hash_b64u,
      session_hash_b64u: payload.session_hash_b64u ?? null,
      timestamp: payload.timestamp,
      binding: bindingRecord
        ? {
            run_id: bindingRecord.run_id ?? null,
            event_hash_b64u: bindingRecord.event_hash_b64u ?? null,
            nonce: bindingRecord.nonce ?? null,
            subject: bindingRecord.subject ?? bindingRecord.subject_did ?? null,
            scope: bindingRecord.scope ?? bindingRecord.scope_hash_b64u ?? null,
            job_id: bindingRecord.job_id ?? null,
            contract_id: bindingRecord.contract_id ?? null,
            jurisdiction: bindingRecord.jurisdiction ?? null,
            policy_hash: bindingRecord.policy_hash ?? null,
            token_scope_hash_b64u: bindingRecord.token_scope_hash_b64u ?? null,
          }
        : null,
    },
    'SHA-256'
  );
}

async function makeInclusionProof(args: {
  leafHashB64u: string;
  logSignerDid: string;
  logSignerKey: CryptoKey;
  corruptLeaf?: boolean;
}): Promise<Record<string, unknown>> {
  const leafHash = args.corruptLeaf ? `${args.leafHashB64u}x` : args.leafHashB64u;

  const sigBytes = new Uint8Array(
    await crypto.subtle.sign('Ed25519', args.logSignerKey, new TextEncoder().encode(leafHash))
  );

  return {
    proof_version: '1',
    log_id: 'clawlogs-web-test',
    tree_size: 1,
    leaf_hash_b64u: leafHash,
    root_hash_b64u: leafHash,
    audit_path: [],
    root_published_at: '2026-02-17T00:00:00Z',
    root_signature: {
      signer_did: args.logSignerDid,
      sig_b64u: base64UrlEncode(sigBytes),
    },
    metadata: {
      leaf_index: 0,
    },
  };
}

async function makeWebBundle(args: {
  responseHashes: string[];
  includeTransparencyProofs?: boolean;
  corruptTransparencyProof?: boolean;
}) {
  const agent = await makeDidKeyEd25519();
  const logSigner = await makeDidKeyEd25519();
  const witnesses = await Promise.all(args.responseHashes.map(() => makeDidKeyEd25519()));

  const runId = 'run_web_policy_001';
  const eventPayloadHash = await computeHash({ type: 'llm_call_web_policy' }, 'SHA-256');
  const eventHeader = {
    event_id: 'evt_web_policy_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-17T00:00:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };
  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const webReceipts: unknown[] = [];

  for (let i = 0; i < witnesses.length; i++) {
    const witness = witnesses[i]!;
    const responseHash = args.responseHashes[i]!;

    const payload: Record<string, unknown> = {
      receipt_version: '1',
      receipt_id: `wr_policy_${i + 1}`,
      witness_id: `witness_policy_${i + 1}`,
      source: 'chatgpt_web',
      request_hash_b64u: 'req_web_policy_hash_001',
      response_hash_b64u: responseHash,
      timestamp: '2026-02-17T00:00:00Z',
      binding: {
        run_id: runId,
        event_hash_b64u: eventHash,
      },
    };

    if (args.includeTransparencyProofs) {
      const leafHash = await computeWebReceiptLeafHash(payload);
      payload.transparency = {
        inclusion_proof: await makeInclusionProof({
          leafHashB64u: leafHash,
          logSignerDid: logSigner.did,
          logSignerKey: logSigner.privateKey,
          corruptLeaf: args.corruptTransparencyProof,
        }),
      };
    }

    const envelope = await signEnvelope({
      payload,
      envelopeType: 'web_receipt',
      signerDid: witness.did,
      privateKey: witness.privateKey,
      issuedAt: '2026-02-17T00:00:00Z',
    });

    webReceipts.push(envelope);
  }

  const bundlePayload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: 'bundle_web_policy_001',
    agent_did: agent.did,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
    web_receipts: webReceipts,
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
    witnessSignerDids: witnesses.map((w) => w.did),
  };
}

describe('CVF-US-062/063 witnessed-web quorum + transparency policy', () => {
  it('passes witnessed_web quorum when m-of-n is satisfied', async () => {
    const { bundleEnvelope, witnessSignerDids } = await makeWebBundle({
      responseHashes: ['res_web_hash_q_001', 'res_web_hash_q_001'],
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: witnessSignerDids,
      witnessed_web_quorum_m: 2,
      witnessed_web_quorum_n: 2,
      witnessed_web_policy_mode: 'warn',
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('witnessed_web');
    expect(out.result.component_results?.web_receipts_verified_count).toBe(2);
  });

  it('degrades to self on quorum failure in warn mode', async () => {
    const { bundleEnvelope, witnessSignerDids } = await makeWebBundle({
      responseHashes: ['res_web_hash_q_fail_001'],
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: witnessSignerDids,
      witnessed_web_quorum_m: 2,
      witnessed_web_quorum_n: 2,
      witnessed_web_policy_mode: 'warn',
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('self');
    expect(out.result.risk_flags ?? []).toContain('WITNESS_QUORUM_FAILED');
    expect(out.result.risk_flags ?? []).toContain('WITNESS_POLICY_DEGRADED');
  });

  it('fails closed on quorum failure in enforce mode', async () => {
    const { bundleEnvelope, witnessSignerDids } = await makeWebBundle({
      responseHashes: ['res_web_hash_q_fail_002'],
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: witnessSignerDids,
      witnessed_web_quorum_m: 2,
      witnessed_web_quorum_n: 2,
      witnessed_web_policy_mode: 'enforce',
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.message).toBe('WITNESS_QUORUM_FAILED');
  });

  it('detects split-view witness conflict and degrades in warn mode', async () => {
    const { bundleEnvelope, witnessSignerDids } = await makeWebBundle({
      responseHashes: ['res_web_hash_split_a', 'res_web_hash_split_b'],
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: witnessSignerDids,
      witnessed_web_policy_mode: 'warn',
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('self');
    expect(out.result.risk_flags ?? []).toContain('WITNESS_CONFLICT_SPLIT_VIEW');
  });

  it('fails closed on split-view witness conflict in enforce mode', async () => {
    const { bundleEnvelope, witnessSignerDids } = await makeWebBundle({
      responseHashes: ['res_web_hash_split_c', 'res_web_hash_split_d'],
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: witnessSignerDids,
      witnessed_web_policy_mode: 'enforce',
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.message).toBe('WITNESS_CONFLICT_SPLIT_VIEW');
  });

  it('degrades when transparency is required but missing in warn mode', async () => {
    const { bundleEnvelope, witnessSignerDids } = await makeWebBundle({
      responseHashes: ['res_web_hash_trans_warn_001'],
      includeTransparencyProofs: false,
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: witnessSignerDids,
      witnessed_web_transparency_mode: 'warn',
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('self');
    expect(out.result.risk_flags ?? []).toContain(
      'WITNESS_TRANSPARENCY_REQUIRED_MISSING'
    );
  });

  it('fails closed when transparency is required but missing in enforce mode', async () => {
    const { bundleEnvelope, witnessSignerDids } = await makeWebBundle({
      responseHashes: ['res_web_hash_trans_enforce_001'],
      includeTransparencyProofs: false,
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: witnessSignerDids,
      witnessed_web_transparency_mode: 'enforce',
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.message).toBe('WITNESS_TRANSPARENCY_REQUIRED');
  });

  it('accepts witnessed_web when required transparency proof verifies', async () => {
    const { bundleEnvelope, witnessSignerDids } = await makeWebBundle({
      responseHashes: ['res_web_hash_trans_ok_001'],
      includeTransparencyProofs: true,
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: witnessSignerDids,
      witnessed_web_transparency_mode: 'enforce',
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('witnessed_web');
  });

  it('fails closed when required transparency proof is malformed/badly bound', async () => {
    const { bundleEnvelope, witnessSignerDids } = await makeWebBundle({
      responseHashes: ['res_web_hash_trans_bad_001'],
      includeTransparencyProofs: true,
      corruptTransparencyProof: true,
    });

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedWitnessSignerDids: witnessSignerDids,
      witnessed_web_transparency_mode: 'enforce',
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.message).toBe('WITNESS_TRANSPARENCY_REQUIRED');
  });
});
