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

async function makeDidKeyEd25519(): Promise<{
  did: string;
  privateKey: CryptoKey;
}> {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, [
    'sign',
    'verify',
  ]);

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

async function signEnvelope<T extends Record<string, unknown>>(args: {
  payload: T;
  envelopeType: 'vir_receipt' | 'proof_bundle' | 'gateway_receipt';
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

async function makeVirBundle(args?: {
  nonce?: string;
  expectedBountyNonce?: string;
  modelClaimed?: string;
  modelObserved?: string;
  decryptedMatch?: boolean | null;
  virSource?: 'tls_decrypt' | 'gateway' | 'interpose' | 'preload' | 'sni';
  includeCorroboratingGatewayReceipt?: boolean;
}) {
  const agent = await makeDidKeyEd25519();
  const runId = 'run_vir_001';

  const eventPayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
  const e1Header = {
    event_id: 'evt_vir_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-16T00:00:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };
  const e1Hash = await computeHash(e1Header, 'SHA-256');

  const leaves: Record<string, string> = {
    request_hash: await sha256Utf8B64u('request_hash:req_hash_001'),
    response_hash: await sha256Utf8B64u('response_hash:res_hash_001'),
  };
  const leafHashes = Object.keys(leaves)
    .sort()
    .map((k) => leaves[k]!);
  const merkleRoot = await sha256Utf8B64u([...leafHashes].sort().join('|'));

  const virPayload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: 'vir_001',
    source: args?.virSource ?? 'tls_decrypt',
    provider: 'anthropic',
    model: args?.modelObserved ?? 'claude-test',
    model_claimed: args?.modelClaimed ?? 'claude-test',
    model_observed: args?.modelObserved ?? 'claude-test',
    request_hash_b64u: 'req_hash_001',
    response_hash_b64u: 'res_hash_001',
    tokens_input: 12,
    tokens_output: 34,
    latency_ms: 120,
    agent_did: agent.did,
    timestamp: '2026-02-16T00:00:00Z',
    binding: {
      run_id: runId,
      event_hash_b64u: e1Hash,
      nonce: args?.nonce ?? 'nonce_001',
    },
    transport_attestation: {
      source: args?.virSource ?? 'tls_decrypt',
      decrypted_match: args?.decryptedMatch ?? true,
    },
    selective_disclosure: {
      merkle_root_b64u: merkleRoot,
      leaf_hashes_b64u: leafHashes,
      disclosed_leaves: leaves,
      redacted_fields: ['tool_transcript'],
    },
  };

  const virEnvelope = await signEnvelope({
    payload: virPayload,
    envelopeType: 'vir_receipt',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-16T00:00:00Z',
  });

  let verificationOptions: Record<string, unknown> = {};
  let receipts: unknown[] | undefined;

  if (args?.includeCorroboratingGatewayReceipt) {
    const gatewaySigner = await makeDidKeyEd25519();
    const receiptPayload: Record<string, unknown> = {
      receipt_version: '1',
      receipt_id: 'rcpt_vir_001',
      gateway_id: 'gw_vir_test',
      provider: 'anthropic',
      model: 'claude-test',
      request_hash_b64u: 'req_hash_001',
      response_hash_b64u: 'res_hash_001',
      tokens_input: 12,
      tokens_output: 34,
      latency_ms: 120,
      timestamp: '2026-02-16T00:00:00Z',
      binding: {
        run_id: runId,
        event_hash_b64u: e1Hash,
      },
    };

    const receiptEnvelope = await signEnvelope({
      payload: receiptPayload,
      envelopeType: 'gateway_receipt',
      signerDid: gatewaySigner.did,
      privateKey: gatewaySigner.privateKey,
      issuedAt: '2026-02-16T00:00:00Z',
    });

    receipts = [receiptEnvelope];
    verificationOptions = {
      allowlistedReceiptSignerDids: [gatewaySigner.did],
    };
  }

  const bundlePayload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: 'bundle_vir_001',
    agent_did: agent.did,
    event_chain: [
      {
        ...e1Header,
        event_hash_b64u: e1Hash,
      },
    ],
    vir_receipts: [virEnvelope],
    ...(receipts ? { receipts } : {}),
    metadata: {
      ...(args?.expectedBountyNonce ? { bounty_nonce: args.expectedBountyNonce } : {}),
    },
  };

  const bundleEnvelope = await signEnvelope({
    payload: bundlePayload,
    envelopeType: 'proof_bundle',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-16T00:00:01Z',
  });

  return { bundleEnvelope, verificationOptions };
}

async function makeConflictingSameTierVirBundle() {
  const agent = await makeDidKeyEd25519();
  const runId = 'run_vir_conflict_001';

  const eventPayloadHash = await computeHash({ type: 'llm_call_conflict' }, 'SHA-256');
  const e1Header = {
    event_id: 'evt_vir_conflict_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-02-16T00:10:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };
  const e1Hash = await computeHash(e1Header, 'SHA-256');

  const baseVirPayload: Record<string, unknown> = {
    receipt_version: '1',
    source: 'gateway',
    provider: 'anthropic',
    request_hash_b64u: 'req_hash_conflict_001',
    response_hash_b64u: 'res_hash_conflict_001',
    tokens_input: 42,
    tokens_output: 84,
    latency_ms: 210,
    agent_did: agent.did,
    timestamp: '2026-02-16T00:10:00Z',
    binding: {
      run_id: runId,
      event_hash_b64u: e1Hash,
      nonce: 'nonce_conflict_001',
    },
  };

  const virEnvelopeA = await signEnvelope({
    payload: {
      ...baseVirPayload,
      receipt_id: 'vir_conflict_001',
      model: 'claude-a',
      model_observed: 'claude-a',
    },
    envelopeType: 'vir_receipt',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-16T00:10:00Z',
  });

  const virEnvelopeB = await signEnvelope({
    payload: {
      ...baseVirPayload,
      receipt_id: 'vir_conflict_002',
      model: 'claude-b',
      model_observed: 'claude-b',
    },
    envelopeType: 'vir_receipt',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-16T00:10:01Z',
  });

  const bundlePayload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: 'bundle_vir_conflict_001',
    agent_did: agent.did,
    event_chain: [
      {
        ...e1Header,
        event_hash_b64u: e1Hash,
      },
    ],
    vir_receipts: [virEnvelopeA, virEnvelopeB],
  };

  const bundleEnvelope = await signEnvelope({
    payload: bundlePayload,
    envelopeType: 'proof_bundle',
    signerDid: agent.did,
    privateKey: agent.privateKey,
    issuedAt: '2026-02-16T00:10:02Z',
  });

  return { bundleEnvelope };
}

describe('R43 VIR synthesis verification', () => {
  it('computes proof_tier=gateway from corroborated high-claim VIR receipt (tls_decrypt)', async () => {
    const { bundleEnvelope, verificationOptions } = await makeVirBundle({
      nonce: 'nonce_001',
      expectedBountyNonce: 'nonce_001',
      modelClaimed: 'claude-test',
      modelObserved: 'claude-test',
      decryptedMatch: true,
      includeCorroboratingGatewayReceipt: true,
    });

    const out = await verifyProofBundle(bundleEnvelope, verificationOptions);

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('gateway');
    expect(out.result.component_results?.vir_receipts_count).toBe(1);
    expect(out.result.component_results?.vir_receipts_verified_count).toBe(1);
    expect(out.result.component_results?.vir_best_source).toBe('tls_decrypt');
  });

  it('demotes uncorroborated high-claim VIR to self with explicit risk flags', async () => {
    const { bundleEnvelope } = await makeVirBundle({
      nonce: 'nonce_001',
      expectedBountyNonce: 'nonce_001',
      modelClaimed: 'claude-test',
      modelObserved: 'claude-test',
      decryptedMatch: true,
      virSource: 'gateway',
      includeCorroboratingGatewayReceipt: false,
    });

    const out = await verifyProofBundle(bundleEnvelope);

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('self');
    expect(out.result.component_results?.vir_receipts_verified_count).toBe(1);
    expect(out.result.component_results?.vir_best_source).toBe('sni');
    expect(out.result.risk_flags ?? []).toContain('VIR_HIGH_CLAIM_UNCORROBORATED');
  });

  it('does not uplift proof tier when VIR nonce mismatches expected bounty nonce', async () => {
    const { bundleEnvelope } = await makeVirBundle({
      nonce: 'nonce_other',
      expectedBountyNonce: 'nonce_expected',
      modelClaimed: 'claude-test',
      modelObserved: 'claude-test',
      decryptedMatch: true,
    });

    const out = await verifyProofBundle(bundleEnvelope);

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('self');
    expect(out.result.component_results?.vir_receipts_valid).toBe(false);
    expect(out.result.component_results?.vir_receipts_verified_count).toBe(0);
  });

  it('does not uplift proof tier when tls_decrypt VIR model evidence mismatches', async () => {
    const { bundleEnvelope } = await makeVirBundle({
      nonce: 'nonce_001',
      expectedBountyNonce: 'nonce_001',
      modelClaimed: 'claude-claimed',
      modelObserved: 'claude-observed',
      decryptedMatch: false,
    });

    const out = await verifyProofBundle(bundleEnvelope);

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('self');
    expect(out.result.component_results?.vir_receipts_valid).toBe(false);
    expect(out.result.component_results?.vir_receipts_verified_count).toBe(0);
  });

  it('fails closed on multiple VIR receipts bound to the same event hash', async () => {
    const { bundleEnvelope } = await makeConflictingSameTierVirBundle();

    const out = await verifyProofBundle(bundleEnvelope);

    expect(out.result.status).toBe('INVALID');
    expect(out.result.reason).toContain('event contradiction');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.message).toBe('ERR_VIR_EVENT_CONTRADICTION');
    expect(out.error?.field).toBe('payload.vir_receipts');
  });
});
