import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyProofBundle } from '../src/verify-proof-bundle';
import { verifyAgent } from '../src/verify-agent';

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

describe('POH-US-013: canonical proof_tier (gateway)', () => {
  it('computes proof_tier=gateway when receipts verify and are bound', async () => {
    const agent = await makeDidKeyEd25519();
    const gatewaySigner = await makeDidKeyEd25519();

    const runId = 'run_gateway_001';

    // Build a minimal 1-event chain
    const e1PayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_001',
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-02-07T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1Hash = await computeHash(e1Header, 'SHA-256');

    // Create a valid gateway receipt envelope bound to e1
    const receiptPayload: any = {
      receipt_version: '1',
      receipt_id: 'rcpt_001',
      gateway_id: 'gw_test',
      provider: 'anthropic',
      model: 'claude-test',
      request_hash_b64u: await computeHash({ req: 1 }, 'SHA-256'),
      response_hash_b64u: await computeHash({ res: 1 }, 'SHA-256'),
      tokens_input: 10,
      tokens_output: 20,
      latency_ms: 123,
      timestamp: '2026-02-07T00:00:00Z',
      binding: {
        run_id: runId,
        event_hash_b64u: e1Hash,
        nonce: 'nonce_001',
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
      issued_at: '2026-02-07T00:00:00Z',
    };

    const bundlePayload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_gateway_001',
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
      issued_at: '2026-02-07T00:00:01Z',
    };

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedReceiptSignerDids: [gatewaySigner.did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('gateway');
    expect(out.result.component_results?.receipts_valid).toBe(true);

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
    expect(agentOut.poh_tier).toBe(2);
  });

  it('still uplifts to gateway if at least one receipt verifies (even if others fail)', async () => {
    const agent = await makeDidKeyEd25519();
    const gatewaySigner = await makeDidKeyEd25519();

    const runId = 'run_gateway_002';

    const e1PayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
    const e1Header = {
      event_id: 'evt_101',
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-02-07T00:00:00Z',
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null as string | null,
    };
    const e1Hash = await computeHash(e1Header, 'SHA-256');

    const mkReceipt = async (receiptId: string) => {
      const payload: any = {
        receipt_version: '1',
        receipt_id: receiptId,
        gateway_id: 'gw_test',
        provider: 'anthropic',
        model: 'claude-test',
        request_hash_b64u: await computeHash({ req: receiptId }, 'SHA-256'),
        response_hash_b64u: await computeHash({ res: receiptId }, 'SHA-256'),
        tokens_input: 10,
        tokens_output: 20,
        latency_ms: 123,
        timestamp: '2026-02-07T00:00:00Z',
        binding: {
          run_id: runId,
          event_hash_b64u: e1Hash,
          nonce: `nonce_${receiptId}`,
        },
      };

      const payloadHash = await computeHash(payload, 'SHA-256');
      const sigMsg = new TextEncoder().encode(payloadHash);
      const sigBytes = new Uint8Array(
        await crypto.subtle.sign('Ed25519', gatewaySigner.privateKey, sigMsg)
      );

      return {
        envelope_version: '1',
        envelope_type: 'gateway_receipt',
        payload,
        payload_hash_b64u: payloadHash,
        hash_algorithm: 'SHA-256',
        signature_b64u: base64UrlEncode(sigBytes),
        algorithm: 'Ed25519',
        signer_did: gatewaySigner.did,
        issued_at: '2026-02-07T00:00:00Z',
      };
    };

    const goodReceipt = await mkReceipt('rcpt_good');

    const badReceipt = {
      ...(await mkReceipt('rcpt_bad')),
      // keep base64url format, but signature should fail verification
      signature_b64u: base64UrlEncode(crypto.getRandomValues(new Uint8Array(64))),
    };

    const bundlePayload: any = {
      bundle_version: '1',
      bundle_id: 'bundle_gateway_002',
      agent_did: agent.did,
      event_chain: [
        {
          ...e1Header,
          event_hash_b64u: e1Hash,
        },
      ],
      receipts: [goodReceipt, badReceipt],
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
      issued_at: '2026-02-07T00:00:01Z',
    };

    const out = await verifyProofBundle(bundleEnvelope, {
      allowlistedReceiptSignerDids: [gatewaySigner.did],
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.proof_tier).toBe('gateway');
    expect(out.result.component_results?.receipts_count).toBe(2);
    expect(out.result.component_results?.receipts_verified_count).toBe(1);
    expect(out.result.component_results?.receipts_valid).toBe(false);

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
    expect(agentOut.poh_tier).toBe(2);
  });
});
