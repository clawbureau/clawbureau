import { afterEach, describe, expect, it, vi } from 'vitest';

import worker from '../src/index';
import type { Env } from '../src/types';
import { base64urlEncode, sha256B64u } from '../src/crypto';
import { jcsCanonicalize } from '../src/jcs';

afterEach(() => {
  vi.restoreAllMocks();
});

function makeEnv(): Env {
  // Deterministic test key (32-byte seed)
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) seed[i] = i + 1;

  return {
    PROXY_VERSION: 'test',
    PROXY_SIGNING_KEY: base64urlEncode(seed),
    PROXY_RATE_LIMITER: {
      limit: async () => ({ success: true }),
    },
    IDEMPOTENCY: {} as unknown as DurableObjectNamespace,
  } as unknown as Env;
}

describe('CPX-US-016: model identity receipt metadata', () => {
  it('emits model_identity + model_identity_hash_b64u for standard OpenAI calls', async () => {
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

    const req = new Request('https://clawproxy.com/v1/proxy/openai', {
      method: 'POST',
      headers: {
        Authorization: 'sk_test',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-5.2',
        messages: [{ role: 'user', content: 'hi' }],
      }),
    });

    const res = await worker.fetch(req, env);
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    const md = body?._receipt_envelope?.payload?.metadata;
    expect(md).toBeTruthy();

    expect(md.model_identity).toEqual({
      model_identity_version: '1',
      tier: 'closed_opaque',
      model: {
        provider: 'openai',
        name: 'gpt-5.2',
      },
    });

    const expectedHash = await sha256B64u(jcsCanonicalize(md.model_identity));
    expect(md.model_identity_hash_b64u).toBe(expectedHash);
  });

  it('preserves upstream metadata when routing openrouter/* models via fal', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        new Response(JSON.stringify({ ok: true, id: 'provider_resp_2' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      )
    );

    const env = makeEnv();

    const req = new Request('https://clawproxy.com/v1/proxy/openai', {
      method: 'POST',
      headers: {
        Authorization: 'fal_test',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'openrouter/openai/gpt-4o-mini',
        messages: [{ role: 'user', content: 'hi' }],
      }),
    });

    const res = await worker.fetch(req, env);
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    const md = body?._receipt_envelope?.payload?.metadata;
    expect(md).toBeTruthy();

    expect(md.upstream).toBe('fal_openrouter');
    expect(md.upstream_model).toBe('openai/gpt-4o-mini');

    expect(md.model_identity.model.name).toBe('openrouter/openai/gpt-4o-mini');
    const expectedHash = await sha256B64u(jcsCanonicalize(md.model_identity));
    expect(md.model_identity_hash_b64u).toBe(expectedHash);
  });
});
