import { describe, expect, it } from 'vitest';

import type { GatewayReceiptPayload } from '../src/types';
import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyAgent } from '../src/verify-agent';
import { verifyProofBundle } from '../src/verify-proof-bundle';
import {
  computeModelIdentityHashB64u,
  verifyModelIdentityFromReceiptPayload,
} from '../src/model-identity';

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

  // Leading zeros
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

describe('CVF-US-016: model identity tier', () => {
  it('verifies model_identity_hash_b64u when present and returns tier', async () => {
    const modelIdentity: any = {
      model_identity_version: '1',
      tier: 'closed_opaque',
      model: {
        provider: 'anthropic',
        name: 'claude-test',
      },
    };

    const modelIdentityHash = await computeModelIdentityHashB64u(modelIdentity);

    const payload: GatewayReceiptPayload = {
      receipt_version: '1',
      receipt_id: 'rcpt_001',
      gateway_id: 'gw_test',
      provider: 'anthropic',
      model: 'claude-test',
      request_hash_b64u: await computeHash({ req: 1 }, 'SHA-256'),
      response_hash_b64u: await computeHash({ res: 1 }, 'SHA-256'),
      tokens_input: 1,
      tokens_output: 1,
      latency_ms: 1,
      timestamp: '2026-02-10T00:00:00Z',
      metadata: {
        model_identity: modelIdentity,
        model_identity_hash_b64u: modelIdentityHash,
      },
    };

    const out = await verifyModelIdentityFromReceiptPayload(payload);
    expect(out.valid).toBe(true);
    expect(out.tier).toBe('closed_opaque');
    expect(out.risk_flags).toContain('MODEL_IDENTITY_OPAQUE');
    expect(out.computed_hash_b64u).toBe(modelIdentityHash);
  });

  it('fails closed on model_identity hash mismatch (axis only)', async () => {
    const modelIdentity: any = {
      model_identity_version: '1',
      tier: 'closed_opaque',
      model: {
        provider: 'anthropic',
        name: 'claude-test',
      },
    };

    const payload: GatewayReceiptPayload = {
      receipt_version: '1',
      receipt_id: 'rcpt_002',
      gateway_id: 'gw_test',
      provider: 'anthropic',
      model: 'claude-test',
      request_hash_b64u: await computeHash({ req: 2 }, 'SHA-256'),
      response_hash_b64u: await computeHash({ res: 2 }, 'SHA-256'),
      tokens_input: 1,
      tokens_output: 1,
      latency_ms: 1,
      timestamp: '2026-02-10T00:00:00Z',
      metadata: {
        model_identity: modelIdentity,
        model_identity_hash_b64u: 'AAAAAAAAAAAAAAAAAAAAAA',
      },
    };

    const out = await verifyModelIdentityFromReceiptPayload(payload);
    expect(out.valid).toBe(false);
    expect(out.tier).toBe('unknown');
    expect(out.risk_flags).toContain('MODEL_IDENTITY_HASH_MISMATCH');
  });

  it('surfaces model_identity_tier on /verify/bundle and /verify/agent outputs', async () => {
    const agent = await makeDidKeyEd25519();
    const gatewaySigner = await makeDidKeyEd25519();

    const runId = 'run_model_identity_001';

    // Minimal 1-event chain
    const e1PayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_001',
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-02-10T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1Hash = await computeHash(e1Header, 'SHA-256');

    const modelIdentity: any = {
      model_identity_version: '1',
      tier: 'closed_opaque',
      model: {
        provider: 'anthropic',
        name: 'claude-test',
      },
    };
    const modelIdentityHash = await computeModelIdentityHashB64u(modelIdentity);

    // Receipt bound to e1
    const receiptPayload: any = {
      receipt_version: '1',
      receipt_id: 'rcpt_003',
      gateway_id: 'gw_test',
      provider: 'anthropic',
      model: 'claude-test',
      request_hash_b64u: await computeHash({ req: 3 }, 'SHA-256'),
      response_hash_b64u: await computeHash({ res: 3 }, 'SHA-256'),
      tokens_input: 10,
      tokens_output: 20,
      latency_ms: 123,
      timestamp: '2026-02-10T00:00:00Z',
      binding: {
        run_id: runId,
        event_hash_b64u: e1Hash,
        nonce: 'nonce_003',
      },
      metadata: {
        model_identity: modelIdentity,
        model_identity_hash_b64u: modelIdentityHash,
      },
    };

    const receiptPayloadHash = await computeHash(receiptPayload, 'SHA-256');
    const receiptSigMsg = new TextEncoder().encode(receiptPayloadHash);
    const receiptSigBytes = new Uint8Array(
      await crypto.subtle.sign('Ed25519', gatewaySigner.privateKey, receiptSigMsg)
    );

    const receiptEnvelope: any = {
      envelope_version: '1',
      envelope_type: 'gateway_receipt',
      payload: receiptPayload,
      payload_hash_b64u: receiptPayloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(receiptSigBytes),
      algorithm: 'Ed25519',
      signer_did: gatewaySigner.did,
      issued_at: '2026-02-10T00:00:00Z',
    };

    const bundlePayload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_model_identity_001',
      agent_did: agent.did,
      event_chain: [
        {
          ...e1Header,
          event_hash_b64u: e1Hash,
        },
      ],
      receipts: [receiptEnvelope],
    };

    const bundlePayloadHash = await computeHash(bundlePayload, 'SHA-256');
    const bundleSigMsg = new TextEncoder().encode(bundlePayloadHash);
    const bundleSigBytes = new Uint8Array(
      await crypto.subtle.sign('Ed25519', agent.privateKey, bundleSigMsg)
    );

    const bundleEnvelope: any = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: bundlePayload,
      payload_hash_b64u: bundlePayloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(bundleSigBytes),
      algorithm: 'Ed25519',
      signer_did: agent.did,
      issued_at: '2026-02-10T00:00:01Z',
    };

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedReceiptSignerDids: [gatewaySigner.did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('gateway');
    expect(out.result.model_identity_tier).toBe('closed_opaque');
    expect(out.result.risk_flags).toContain('MODEL_IDENTITY_OPAQUE');

    const agentOut = await verifyAgent(
      {
        agent_did: agent.did,
        proof_bundle_envelope: bundleEnvelope,
      },
      {
        allowlistedReceiptSignerDids: [gatewaySigner.did],
      }
    );

    expect(agentOut.result.status).toBe('VALID');
    expect(agentOut.proof_tier).toBe('gateway');
    expect(agentOut.model_identity_tier).toBe('closed_opaque');
    expect(agentOut.risk_flags ?? []).toContain('MODEL_IDENTITY_OPAQUE');
  });
});
