import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { X402BindingReasonCode } from '../src/types';
import { base64UrlEncode, computeHash } from '../src/crypto';
import { verifyProofBundle } from '../src/verify-proof-bundle';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

type FixtureExpected = {
  status: 'VALID' | 'INVALID';
  error_code?: string;
  x402_reason_code: X402BindingReasonCode;
  proof_tier?: string;
  trust_tier?: string;
};

type FixtureCase = {
  id: string;
  scenario:
    | 'x402_bound'
    | 'x402_metadata_partial'
    | 'x402_missing_binding'
    | 'x402_binding_mismatch'
    | 'x402_payment_auth_hash_invalid'
    | 'x402_payment_auth_replay';
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

type ReceiptOptions = {
  signerDid: string;
  signerKey: CryptoKey;
  runId: string;
  eventHash: string;
  receiptId?: string;
  includeBinding?: boolean;
  x402PaymentRef?: string;
  x402AmountMinor?: number;
  x402Currency?: string;
  x402Network?: string;
  x402PaymentAuthHashB64u?: string;
};

async function makeGatewayReceiptEnvelope(options: ReceiptOptions) {
  const payload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: options.receiptId ?? `gw_${options.runId}`,
    gateway_id: 'gw_x402_001',
    provider: 'openai',
    model: 'gpt-4.1',
    request_hash_b64u: 'req_hash_x402_001',
    response_hash_b64u: 'res_hash_x402_001',
    tokens_input: 120,
    tokens_output: 220,
    latency_ms: 240,
    timestamp: '2026-02-17T00:00:00Z',
  };

  if (options.includeBinding !== false) {
    payload.binding = {
      run_id: options.runId,
      event_hash_b64u: options.eventHash,
    };
  }

  payload.metadata = {
    x402_payment_ref: options.x402PaymentRef,
    x402_amount_minor: options.x402AmountMinor,
    x402_currency: options.x402Currency,
    x402_network: options.x402Network,
    x402_payment_auth_hash_b64u: options.x402PaymentAuthHashB64u,
  };

  return signEnvelope({
    payload,
    envelopeType: 'gateway_receipt',
    signerDid: options.signerDid,
    privateKey: options.signerKey,
    issuedAt: '2026-02-17T00:00:00Z',
  });
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixtureDir = path.resolve(
  __dirname,
  '../../../packages/schema/fixtures/protocol-conformance/clawverify-x402-binding',
);

const manifest = JSON.parse(
  fs.readFileSync(path.join(fixtureDir, 'manifest.v1.json'), 'utf8'),
) as FixtureManifest;

function loadFixture(filename: string): FixtureCase {
  return JSON.parse(fs.readFileSync(path.join(fixtureDir, filename), 'utf8')) as FixtureCase;
}

describe('CVF-US-068/069 x402 binding conformance', () => {
  it('has a valid fixture manifest', () => {
    expect(manifest.manifest_version).toBe('1');
    expect(manifest.suite).toBe('clawverify-x402-binding');
    expect(Array.isArray(manifest.cases)).toBe(true);
    expect(manifest.cases.length).toBeGreaterThanOrEqual(6);
  });

  for (const fixtureFile of manifest.cases) {
    const fixture = loadFixture(fixtureFile);

    it(fixture.id, async () => {
      const agent = await makeDidKeyEd25519();
      const gateway = await makeDidKeyEd25519();

      const runId = `run_${fixture.id.replace(/[^a-z0-9]+/gi, '_').toLowerCase()}`;
      const base = await makeBaseEventChain(runId);

      const bundlePayload: Record<string, unknown> = {
        bundle_version: '1',
        bundle_id: `bundle_${runId}`,
        agent_did: agent.did,
        event_chain: base.eventChain,
      };

      const baseReceiptOptions: ReceiptOptions = {
        signerDid: gateway.did,
        signerKey: gateway.privateKey,
        runId,
        eventHash: base.eventHash,
        x402PaymentRef: '0xpaymentrefx402',
        x402AmountMinor: 1000,
        x402Currency: 'USDC',
        x402Network: 'base-sepolia',
        x402PaymentAuthHashB64u: 'x402_payment_auth_hash_001',
      };

      switch (fixture.scenario) {
        case 'x402_bound': {
          bundlePayload.receipts = [await makeGatewayReceiptEnvelope(baseReceiptOptions)];
          break;
        }
        case 'x402_metadata_partial': {
          bundlePayload.receipts = [
            await makeGatewayReceiptEnvelope({
              ...baseReceiptOptions,
              x402Network: undefined,
            }),
          ];
          break;
        }
        case 'x402_missing_binding': {
          bundlePayload.receipts = [
            await makeGatewayReceiptEnvelope({
              ...baseReceiptOptions,
              includeBinding: false,
            }),
          ];
          break;
        }
        case 'x402_binding_mismatch': {
          bundlePayload.receipts = [
            await makeGatewayReceiptEnvelope({
              ...baseReceiptOptions,
              runId: `${runId}_wrong`,
            }),
          ];
          break;
        }
        case 'x402_payment_auth_hash_invalid': {
          bundlePayload.receipts = [
            await makeGatewayReceiptEnvelope({
              ...baseReceiptOptions,
              x402PaymentAuthHashB64u: '***',
            }),
          ];
          break;
        }
        case 'x402_payment_auth_replay': {
          bundlePayload.receipts = [
            await makeGatewayReceiptEnvelope({
              ...baseReceiptOptions,
              receiptId: `${runId}_a`,
              x402PaymentAuthHashB64u: 'x402_replay_hash_001',
            }),
            await makeGatewayReceiptEnvelope({
              ...baseReceiptOptions,
              receiptId: `${runId}_b`,
              x402PaymentAuthHashB64u: 'x402_replay_hash_001',
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

      const out = await verifyProofBundle(bundleEnvelope, {
        allowlistedReceiptSignerDids: [gateway.did],
      });

      expect(out.result.status).toBe(fixture.expected.status);
      expect(out.result.component_results?.x402_reason_code).toBe(
        fixture.expected.x402_reason_code,
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
