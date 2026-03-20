import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { validateProofBundleEnvelopeV1 } from '../src/schema-validation';
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

async function signEnvelope(args: {
  payload: Record<string, unknown>;
  envelopeType: string;
  signerDid: string;
  privateKey: CryptoKey;
  issuedAt: string;
}): Promise<Record<string, unknown>> {
  const payloadHash = await computeHash(args.payload, 'SHA-256');
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign(
      'Ed25519',
      args.privateKey,
      new TextEncoder().encode(payloadHash)
    )
  );

  return {
    envelope_version: '1',
    envelope_type: args.envelopeType,
    payload: args.payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: base64UrlEncode(sigBytes),
    algorithm: 'Ed25519',
    signer_did: args.signerDid,
    issued_at: args.issuedAt,
  };
}

async function makeBundle(args: {
  agentDid: string;
  agentKey: CryptoKey;
  runId: string;
  egressReceipt?: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const eventHeader = {
    event_id: `evt_${args.runId}`,
    run_id: args.runId,
    event_type: 'llm_call',
    timestamp: '2026-03-20T00:00:00.000Z',
    payload_hash_b64u: await computeHash({ run: args.runId }, 'SHA-256'),
    prev_hash_b64u: null as string | null,
  };
  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const bundlePayload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: `bundle_${args.runId}`,
    agent_did: args.agentDid,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
  };

  if (args.egressReceipt) {
    bundlePayload.metadata = {
      sentinels: {
        interpose_active: false,
        egress_policy_receipt: args.egressReceipt,
      },
    };
  }

  return signEnvelope({
    payload: bundlePayload,
    envelopeType: 'proof_bundle',
    signerDid: args.agentDid,
    privateKey: args.agentKey,
    issuedAt: '2026-03-20T00:00:01.000Z',
  });
}

async function makeEgressPolicyReceipt(args: {
  agentDid: string;
  agentKey: CryptoKey;
  runId: string;
  eventHashB64u?: string;
  forceWrongPolicyHash?: boolean;
}): Promise<Record<string, unknown>> {
  const allowedProxyDestinations = ['clawproxy.com'];
  const allowedChildDestinations = ['::1', '127.0.0.1', 'localhost'];
  const policyDescriptor = {
    policy_version: '1',
    proofed_mode: true,
    clawproxy_url: 'https://clawproxy.com/',
    allowed_proxy_destinations: allowedProxyDestinations,
    allowed_child_destinations: allowedChildDestinations,
    direct_provider_access_blocked: true,
  };
  const expectedPolicyHash = await computeHash(policyDescriptor, 'SHA-256');

  const payload: Record<string, unknown> = {
    receipt_version: '1',
    receipt_id: `epr_${args.runId}`,
    policy_version: '1',
    policy_hash_b64u: args.forceWrongPolicyHash
      ? await computeHash({ wrong: true }, 'SHA-256')
      : expectedPolicyHash,
    proofed_mode: true,
    clawproxy_url: 'https://clawproxy.com/',
    allowed_proxy_destinations: allowedProxyDestinations,
    allowed_child_destinations: allowedChildDestinations,
    direct_provider_access_blocked: true,
    blocked_attempt_count: 1,
    blocked_attempts_observed: true,
    hash_algorithm: 'SHA-256',
    agent_did: args.agentDid,
    timestamp: '2026-03-20T00:00:00.500Z',
    binding: {
      run_id: args.runId,
      ...(args.eventHashB64u ? { event_hash_b64u: args.eventHashB64u } : {}),
    },
  };

  return signEnvelope({
    payload,
    envelopeType: 'egress_policy_receipt',
    signerDid: args.agentDid,
    privateKey: args.agentKey,
    issuedAt: '2026-03-20T00:00:00.500Z',
  });
}

describe('PRV-EGR-003 egress policy receipt verification', () => {
  it('accepts a valid signed egress policy receipt when required', async () => {
    const agent = await makeDidKeyEd25519();
    const runId = 'run_egr_valid';

    const eventHeader = {
      event_id: `evt_${runId}`,
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-03-20T00:00:00.000Z',
      payload_hash_b64u: await computeHash({ run: runId }, 'SHA-256'),
      prev_hash_b64u: null as string | null,
    };
    const eventHash = await computeHash(eventHeader, 'SHA-256');
    const egressReceipt = await makeEgressPolicyReceipt({
      agentDid: agent.did,
      agentKey: agent.privateKey,
      runId,
      eventHashB64u: eventHash,
    });
    const bundle = await makeBundle({
      agentDid: agent.did,
      agentKey: agent.privateKey,
      runId,
      egressReceipt,
    });

    const schema = validateProofBundleEnvelopeV1(bundle);
    expect(schema.valid).toBe(true);

    const out = await verifyProofBundle(bundle, {
      requireEgressPolicyReceipt: true,
    });

    expect(out.result.status).toBe('VALID');
    expect(out.result.component_results?.egress_policy_receipt_present).toBe(true);
    expect(out.result.component_results?.egress_policy_receipt_signature_verified).toBe(true);
    expect(out.result.component_results?.egress_policy_receipt_valid).toBe(true);
  });

  it('fails closed when receipt is required but missing', async () => {
    const agent = await makeDidKeyEd25519();
    const runId = 'run_egr_missing';
    const bundle = await makeBundle({
      agentDid: agent.did,
      agentKey: agent.privateKey,
      runId,
    });

    const out = await verifyProofBundle(bundle, {
      requireEgressPolicyReceipt: true,
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('MISSING_REQUIRED_FIELD');
    expect(out.error?.field).toBe('payload.metadata.sentinels.egress_policy_receipt');
  });

  it('fails closed on malformed signed policy evidence when required', async () => {
    const agent = await makeDidKeyEd25519();
    const runId = 'run_egr_malformed';

    const eventHeader = {
      event_id: `evt_${runId}`,
      run_id: runId,
      event_type: 'llm_call',
      timestamp: '2026-03-20T00:00:00.000Z',
      payload_hash_b64u: await computeHash({ run: runId }, 'SHA-256'),
      prev_hash_b64u: null as string | null,
    };
    const eventHash = await computeHash(eventHeader, 'SHA-256');
    const egressReceipt = await makeEgressPolicyReceipt({
      agentDid: agent.did,
      agentKey: agent.privateKey,
      runId,
      eventHashB64u: eventHash,
      forceWrongPolicyHash: true,
    });
    const bundle = await makeBundle({
      agentDid: agent.did,
      agentKey: agent.privateKey,
      runId,
      egressReceipt,
    });

    const out = await verifyProofBundle(bundle, {
      requireEgressPolicyReceipt: true,
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('HASH_MISMATCH');
    expect(out.error?.field).toBe(
      'payload.metadata.sentinels.egress_policy_receipt.payload.policy_hash_b64u'
    );
  });

  it('fails closed when signed policy evidence omits event-hash binding', async () => {
    const agent = await makeDidKeyEd25519();
    const runId = 'run_egr_missing_event_hash';

    const egressReceipt = await makeEgressPolicyReceipt({
      agentDid: agent.did,
      agentKey: agent.privateKey,
      runId,
    });
    const bundle = await makeBundle({
      agentDid: agent.did,
      agentKey: agent.privateKey,
      runId,
      egressReceipt,
    });

    const out = await verifyProofBundle(bundle, {
      requireEgressPolicyReceipt: true,
    });

    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('SCHEMA_VALIDATION_FAILED');
    expect(out.error?.field).toBe(
      'payload.metadata.sentinels.egress_policy_receipt.payload.binding.event_hash_b64u'
    );
  });

  it('does not require egress policy receipt by default', async () => {
    const agent = await makeDidKeyEd25519();
    const runId = 'run_egr_optional';
    const bundle = await makeBundle({
      agentDid: agent.did,
      agentKey: agent.privateKey,
      runId,
    });

    const out = await verifyProofBundle(bundle);
    expect(out.result.status).toBe('VALID');
    expect(out.result.component_results?.egress_policy_receipt_present).toBe(false);
  });
});
