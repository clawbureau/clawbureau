import { describe, expect, it } from 'vitest';

import { base64UrlEncode, computeHash } from '../src/crypto';
import { jcsCanonicalize } from '../src/jcs';
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
    await crypto.subtle.exportKey('raw', keypair.publicKey),
  );

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  const did = `did:key:z${base58Encode(prefixed)}`;
  return { did, privateKey: keypair.privateKey };
}

async function makeSignedBundle(
  agent: { did: string; privateKey: CryptoKey },
  processorPolicyEvidence: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const runId = 'run_processor_policy_001';
  const eventPayloadHash = await computeHash({ type: 'llm_call' }, 'SHA-256');
  const eventHeader = {
    event_id: 'evt_001',
    run_id: runId,
    event_type: 'llm_call',
    timestamp: '2026-03-20T00:00:00Z',
    payload_hash_b64u: eventPayloadHash,
    prev_hash_b64u: null as string | null,
  };
  const eventHash = await computeHash(eventHeader, 'SHA-256');

  const payload = {
    bundle_version: '1',
    bundle_id: 'bundle_processor_policy_001',
    agent_did: agent.did,
    event_chain: [
      {
        ...eventHeader,
        event_hash_b64u: eventHash,
      },
    ],
    metadata: {
      processor_policy: processorPolicyEvidence,
    },
  };

  const payloadHash = await computeHash(payload, 'SHA-256');
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign(
      'Ed25519',
      agent.privateKey,
      new TextEncoder().encode(payloadHash),
    ),
  );

  return {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: base64UrlEncode(signatureBytes),
    algorithm: 'Ed25519',
    signer_did: agent.did,
    issued_at: '2026-03-20T00:00:01Z',
  };
}

async function sha256B64uCanonical(value: unknown): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(jcsCanonicalize(value)),
  );
  return base64UrlEncode(new Uint8Array(digest));
}

describe('PRV-POL-001: processor policy evidence verification', () => {
  it('accepts valid processor policy evidence and exposes verifier-usable fields', async () => {
    const agent = await makeDidKeyEd25519();
    const constraints = {
      allowed_providers: ['openai'],
      allowed_models: ['gpt-5-mini'],
      allowed_regions: ['eu'],
      allowed_retention_profiles: ['no_store'],
      default_region: 'eu',
      default_retention_profile: 'no_store',
    };
    const policyHash = await sha256B64uCanonical({
      policy_version: '1',
      profile_id: 'prv.pol.test-profile',
      enforce: true,
      ...constraints,
    });
    const eventChainRootHash = await computeHash(
      {
        event_id: 'evt_001',
        run_id: 'run_processor_policy_001',
        event_type: 'llm_call',
        timestamp: '2026-03-20T00:00:00Z',
        payload_hash_b64u: await computeHash({ type: 'llm_call' }, 'SHA-256'),
        prev_hash_b64u: null,
      },
      'SHA-256',
    );

    const envelope = await makeSignedBundle(agent, {
      receipt_version: '1',
      receipt_type: 'processor_policy',
      policy_version: '1',
      profile_id: 'prv.pol.test-profile',
      policy_hash_b64u: policyHash,
      enforce: true,
      binding: {
        run_id: 'run_processor_policy_001',
        event_chain_root_hash_b64u: eventChainRootHash,
      },
      constraints,
      counters: {
        allowed_routes: 1,
        denied_routes: 0,
      },
      used_processors: [
        {
          provider: 'openai',
          model: 'gpt-5-mini',
          region: 'eu',
          retention_profile: 'no_store',
          count: 1,
        },
      ],
      blocked_attempts: [],
    });

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('VALID');

    const component = out.result.component_results as Record<string, unknown>;
    expect(component['processor_policy_evidence_present']).toBe(true);
    expect(component['processor_policy_evidence_valid']).toBe(true);
    expect(component['processor_policy_binding_run_id']).toBe(
      'run_processor_policy_001',
    );
    expect(component['processor_policy_profile_id']).toBe('prv.pol.test-profile');
    expect(component['processor_policy_allowed_routes']).toBe(1);
    expect(component['processor_policy_denied_routes']).toBe(0);
    expect(component['processor_policy_used_processors_count']).toBe(1);
  });

  it('fails closed on malformed processor policy evidence', async () => {
    const agent = await makeDidKeyEd25519();
    const envelope = await makeSignedBundle(agent, {
      receipt_version: '1',
      receipt_type: 'processor_policy',
      policy_version: '1',
      profile_id: 'prv.pol.test-profile',
      policy_hash_b64u: 'not_base64url***',
      enforce: true,
      binding: {
        run_id: 'run_processor_policy_001',
      },
      constraints: {
        allowed_providers: ['openai'],
        allowed_models: ['gpt-5-mini'],
        allowed_regions: ['eu'],
        allowed_retention_profiles: ['no_store'],
        default_region: 'eu',
        default_retention_profile: 'no_store',
      },
      counters: {
        allowed_routes: 0,
        denied_routes: 1,
      },
      used_processors: [],
      blocked_attempts: [
        {
          route: {
            provider: 'openai',
            model: 'gpt-5-mini',
            region: 'eu',
            retention_profile: 'no_store',
          },
          reason_code: 'PRV_PROCESSOR_MODEL_DENIED',
          timestamp: '2026-03-20T00:00:02Z',
        },
      ],
    });

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('MALFORMED_ENVELOPE');
    expect(out.error?.field).toBe('payload.metadata.processor_policy.policy_hash_b64u');
  });

  it('fails closed when the processor policy hash does not match canonical constraints', async () => {
    const agent = await makeDidKeyEd25519();
    const envelope = await makeSignedBundle(agent, {
      receipt_version: '1',
      receipt_type: 'processor_policy',
      policy_version: '1',
      profile_id: 'prv.pol.test-profile',
      policy_hash_b64u: await sha256B64uCanonical({
        policy_version: '1',
        profile_id: 'prv.pol.other-profile',
        enforce: true,
        allowed_providers: ['openai'],
        allowed_models: ['gpt-5-mini'],
        allowed_regions: ['eu'],
        allowed_retention_profiles: ['no_store'],
        default_region: 'eu',
        default_retention_profile: 'no_store',
      }),
      enforce: true,
      binding: {
        run_id: 'run_processor_policy_001',
        event_chain_root_hash_b64u: await computeHash(
          {
            event_id: 'evt_001',
            run_id: 'run_processor_policy_001',
            event_type: 'llm_call',
            timestamp: '2026-03-20T00:00:00Z',
            payload_hash_b64u: await computeHash({ type: 'llm_call' }, 'SHA-256'),
            prev_hash_b64u: null,
          },
          'SHA-256',
        ),
      },
      constraints: {
        allowed_providers: ['openai'],
        allowed_models: ['gpt-5-mini'],
        allowed_regions: ['eu'],
        allowed_retention_profiles: ['no_store'],
        default_region: 'eu',
        default_retention_profile: 'no_store',
      },
      counters: {
        allowed_routes: 1,
        denied_routes: 0,
      },
      used_processors: [
        {
          provider: 'openai',
          model: 'gpt-5-mini',
          region: 'eu',
          retention_profile: 'no_store',
          count: 1,
        },
      ],
      blocked_attempts: [],
    });

    const out = await verifyProofBundle(envelope);
    expect(out.result.status).toBe('INVALID');
    expect(out.error?.code).toBe('HASH_MISMATCH');
    expect(out.error?.field).toBe('payload.metadata.processor_policy.policy_hash_b64u');
  });
});
