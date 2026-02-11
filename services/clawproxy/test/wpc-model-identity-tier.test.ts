import { afterEach, describe, expect, it, vi } from 'vitest';

import worker from '../src/index';
import { base64urlEncode } from '../src/crypto';
import { registerDemoPolicy } from '../src/policy';
import { computeWpcHashB64u, type WorkPolicyContractV1 } from '../src/wpc';

afterEach(() => {
  vi.restoreAllMocks();
});

function makeEnv(overrides: Record<string, unknown> = {}) {
  // Deterministic test key (32-byte seed)
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 7;

  return {
    PROXY_VERSION: '0.1.0-test',
    PROXY_SIGNING_KEY: base64urlEncode(seed),
    PROXY_RATE_LIMITER: {
      limit: async () => ({ success: true }),
    },
    IDEMPOTENCY: {} as unknown as DurableObjectNamespace,
    ...overrides,
  };
}

describe('POHVN-US-005: WPC minimum model identity tier enforcement', () => {
  it('fails closed when policy requires stronger tier than closed_opaque', async () => {
    const policy: WorkPolicyContractV1 = {
      policy_version: '1',
      policy_id: 'pol_min_tier',
      issuer_did: 'did:key:zIssuer',
      allowed_providers: ['openai'],
      minimum_model_identity_tier: 'openweights_hashable',
      receipt_privacy_mode: 'hash_only',
    };

    const policyHash = await computeWpcHashB64u(policy);
    registerDemoPolicy(policyHash, policy);

    const env = makeEnv();

    const res = await worker.fetch(
      new Request('https://clawproxy.test/v1/proxy/openai', {
        method: 'POST',
        headers: {
          'content-type': 'application/json; charset=utf-8',
          Authorization: 'sk_test',
          'X-Confidential-Mode': 'true',
          'X-Policy-Hash': policyHash,
        },
        body: JSON.stringify({
          model: 'gpt-5.2',
          messages: [{ role: 'user', content: 'hi' }],
          max_tokens: 1,
        }),
      }),
      env as any,
    );

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body?.error?.code).toBe('POLICY_MODEL_IDENTITY_TIER_TOO_LOW');
  });

  it('records a passing model identity tier decision in receipt metadata when requirement is met', async () => {
    const policy: WorkPolicyContractV1 = {
      policy_version: '1',
      policy_id: 'pol_min_tier_ok',
      issuer_did: 'did:key:zIssuer',
      allowed_providers: ['openai'],
      minimum_model_identity_tier: 'closed_opaque',
      receipt_privacy_mode: 'hash_only',
    };

    const policyHash = await computeWpcHashB64u(policy);
    registerDemoPolicy(policyHash, policy);

    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ ok: true, id: 'provider_resp_1' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      )
    );

    const env = makeEnv();

    const res = await worker.fetch(
      new Request('https://clawproxy.test/v1/proxy/openai', {
        method: 'POST',
        headers: {
          'content-type': 'application/json; charset=utf-8',
          Authorization: 'sk_test',
          'X-Confidential-Mode': 'true',
          'X-Policy-Hash': policyHash,
        },
        body: JSON.stringify({
          model: 'gpt-5.2',
          messages: [{ role: 'user', content: 'hi' }],
          max_tokens: 1,
        }),
      }),
      env as any,
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as any;

    const md = body?._receipt_envelope?.payload?.metadata;
    expect(md).toBeTruthy();

    // Model identity (CPX-US-016)
    expect(md.model_identity?.tier).toBe('closed_opaque');

    // POHVN-US-005 decision recording
    expect(md.wpc_minimum_model_identity_tier).toBe('closed_opaque');
    expect(md.wpc_model_identity_requirement_met).toBe(true);
  });
});
