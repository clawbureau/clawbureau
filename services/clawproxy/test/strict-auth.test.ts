import { describe, expect, it } from 'vitest';

import worker from '../src/index';

function makeEnv(overrides: Record<string, unknown> = {}) {
  return {
    PROXY_VERSION: '0.1.0-test',
    PROXY_RATE_LIMITER: {
      limit: async () => ({ success: true }),
    },
    IDEMPOTENCY: {} as any,
    ...overrides,
  };
}

describe('CPX-US-032: strict auth header mode', () => {
  it('rejects Authorization header when STRICT_AUTH_HEADERS=true', async () => {
    const env = makeEnv({ STRICT_AUTH_HEADERS: 'true' });

    const res = await worker.fetch(
      new Request('https://clawproxy.test/v1/proxy/openai', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer sk-test',
        },
      }),
      env as any,
    );

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body?.error?.code).toBe('STRICT_AUTH_HEADERS');
  });

  it('rejects provider-compatible key headers when STRICT_AUTH_HEADERS=true', async () => {
    const env = makeEnv({ STRICT_AUTH_HEADERS: 'true' });

    const res = await worker.fetch(
      new Request('https://clawproxy.test/v1/proxy/openai', {
        method: 'POST',
        headers: {
          'x-api-key': 'sk-test',
        },
      }),
      env as any,
    );

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body?.error?.code).toBe('STRICT_AUTH_HEADERS');
  });

  it('rejects conflicting X-CST vs X-Scoped-Token when STRICT_AUTH_HEADERS=true', async () => {
    const env = makeEnv({ STRICT_AUTH_HEADERS: 'true' });

    const res = await worker.fetch(
      new Request('https://clawproxy.test/v1/proxy/openai', {
        method: 'POST',
        headers: {
          'X-CST': 'jwt_a',
          'X-Scoped-Token': 'jwt_b',
        },
      }),
      env as any,
    );

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body?.error?.code).toBe('STRICT_AUTH_HEADERS');
  });

  it('rejects legacy provider key headers (X-Provider-Key / X-Provider-Authorization) when STRICT_AUTH_HEADERS=true', async () => {
    const env = makeEnv({ STRICT_AUTH_HEADERS: 'true' });

    for (const header of ['X-Provider-Key', 'X-Provider-Authorization']) {
      const res = await worker.fetch(
        new Request('https://clawproxy.test/v1/proxy/openai', {
          method: 'POST',
          headers: {
            [header]: 'sk-test',
          },
        }),
        env as any,
      );

      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body?.error?.code).toBe('STRICT_AUTH_HEADERS');
    }
  });

  it('allows strict-mode canonical headers (request reaches signing gate)', async () => {
    const env = makeEnv({ STRICT_AUTH_HEADERS: 'true' });

    const res = await worker.fetch(
      new Request('https://clawproxy.test/v1/proxy/openai', {
        method: 'POST',
        headers: {
          'X-Provider-API-Key': 'sk-test',
        },
      }),
      env as any,
    );

    // Signing key is intentionally missing in this unit test.
    // We only assert strict-mode header checks didn't block the request.
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body?.error?.code).toBe('SIGNING_NOT_CONFIGURED');
  });
});
