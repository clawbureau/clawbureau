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
  envelopeType: string;
  signerDid: string;
  privateKey: CryptoKey;
  payload: T;
  issuedAt?: string;
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
    issued_at: args.issuedAt ?? '2026-03-20T00:00:00Z',
  };
}

async function makeEventChain(runId: string) {
  const payloadHash = await computeHash({ prompt: 'hello' }, 'SHA-256');
  const eventHeader = {
    event_id: 'evt_dlp_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-03-20T00:00:01Z',
    payload_hash_b64u: payloadHash,
    prev_hash_b64u: null,
  };

  const eventHash = await computeHash(eventHeader, 'SHA-256');

  return [
    {
      ...eventHeader,
      event_hash_b64u: eventHash,
    },
  ];
}

async function makeDataHandlingReceipt(args: {
  signerDid: string;
  privateKey: CryptoKey;
  runId: string;
  overrides?: Partial<{
    action: 'allow' | 'redact' | 'block' | 'require_approval';
    reason_code: string;
    approval: {
      required: boolean;
      satisfied: boolean;
      mechanism: string;
      token_hash_b64u: string | null;
    };
    redaction: {
      applied: boolean;
      original_payload_hash_b64u: string;
      outbound_payload_hash_b64u: string | null;
    };
  }>;
}) {
  const originalPayloadHash = await computeHash({ raw: 'secret' }, 'SHA-256');
  const redactedPayloadHash = await computeHash({ raw: '[REDACTED_SECRET]' }, 'SHA-256');
  const payload = {
    receipt_version: '1' as const,
    receipt_id: 'dhr_001',
    policy_version: 'prv.dlp.v1' as const,
    run_id: args.runId,
    provider: 'openai',
    action: args.overrides?.action ?? ('redact' as const),
    reason_code: args.overrides?.reason_code ?? 'PRV_DLP_REDACTED',
    classes: [
      {
        class_id: 'secret',
        rule_id: 'prv.dlp.secret.api_key.v1',
        action: 'redact' as const,
        match_count: 1,
      },
    ],
    approval: args.overrides?.approval ?? {
      required: false,
      satisfied: false,
      mechanism: 'header_token',
      token_hash_b64u: null,
    },
    redaction: args.overrides?.redaction ?? {
      applied: true,
      original_payload_hash_b64u: originalPayloadHash,
      outbound_payload_hash_b64u: redactedPayloadHash,
    },
    timestamp: '2026-03-20T00:00:02Z',
  };

  return await signEnvelope({
    envelopeType: 'data_handling_receipt',
    signerDid: args.signerDid,
    privateKey: args.privateKey,
    payload,
    issuedAt: payload.timestamp,
  });
}

describe('proof bundle data handling evidence verification', () => {
  it('accepts valid signed data handling receipts in metadata', async () => {
    const signer = await makeDidKeyEd25519();
    const runId = 'run_dlp_valid_001';
    const eventChain = await makeEventChain(runId);
    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_valid_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        data_handling: {
          policy_version: 'prv.dlp.v1',
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('VALID');
  });

  it('fails closed when data handling receipt signature is tampered', async () => {
    const signer = await makeDidKeyEd25519();
    const runId = 'run_dlp_invalid_sig_001';
    const eventChain = await makeEventChain(runId);
    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
    });

    const tampered = {
      ...dataHandlingReceipt,
      signature_b64u: base64UrlEncode(crypto.getRandomValues(new Uint8Array(64))),
    };

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_invalid_sig_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        data_handling: {
          policy_version: 'prv.dlp.v1',
          receipts: [tampered],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SIGNATURE_INVALID');
    expect(out.error?.field).toBe('payload.metadata.data_handling.receipts[0].signature_b64u');
  });

  it('fails closed when redact evidence does not change the outbound payload hash', async () => {
    const signer = await makeDidKeyEd25519();
    const runId = 'run_dlp_same_hash_001';
    const eventChain = await makeEventChain(runId);
    const originalPayloadHash = await computeHash({ raw: 'secret' }, 'SHA-256');
    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
      overrides: {
        redaction: {
          applied: true,
          original_payload_hash_b64u: originalPayloadHash,
          outbound_payload_hash_b64u: originalPayloadHash,
        },
      },
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_same_hash_001',
      agent_did: signer.did,
      event_chain: eventChain,
      metadata: {
        data_handling: {
          policy_version: 'prv.dlp.v1',
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.data_handling.receipts[0].payload.redaction.outbound_payload_hash_b64u');
  });

  it('fails closed when data handling evidence is present without event-chain run binding', async () => {
    const signer = await makeDidKeyEd25519();
    const runId = 'run_dlp_unbound_001';
    const dataHandlingReceipt = await makeDataHandlingReceipt({
      signerDid: signer.did,
      privateKey: signer.privateKey,
      runId,
    });

    const payload = {
      bundle_version: '1' as const,
      bundle_id: 'bundle_dlp_unbound_001',
      agent_did: signer.did,
      attestations: [
        {
          attestation_id: 'att_dlp_unbound_001',
          attestation_type: 'owner' as const,
          attester_did: signer.did,
          subject_did: signer.did,
          signature_b64u: 'abcdefgh',
        },
      ],
      metadata: {
        data_handling: {
          policy_version: 'prv.dlp.v1',
          receipts: [dataHandlingReceipt],
        },
      },
    };

    const bundleEnvelope = await signEnvelope({
      envelopeType: 'proof_bundle',
      signerDid: signer.did,
      privateKey: signer.privateKey,
      payload,
      issuedAt: '2026-03-20T00:00:03Z',
    });

    const out = await verifyProofBundle(bundleEnvelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('EVIDENCE_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.data_handling');
  });
});
