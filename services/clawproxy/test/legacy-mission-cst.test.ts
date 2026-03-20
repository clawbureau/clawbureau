import { beforeEach, describe, expect, it, vi } from 'vitest';

const validateScopedTokenMock = vi.fn();

vi.mock('../src/scoped-token', () => ({
  validateScopedToken: validateScopedTokenMock,
}));

const { default: worker } = await import('../src/index');
const { computeTokenScopeHashB64uV1 } = await import('../src/token-scope-hash');

function makeEnv(overrides: Record<string, unknown> = {}) {
  return {
    PROXY_VERSION: '0.1.0-test',
    PROXY_RATE_LIMITER: {
      limit: async () => ({ success: true }),
    },
    IDEMPOTENCY: {} as any,
    STRICT_AUTH_HEADERS: 'true',
    PROXY_REQUIRE_CANONICAL_CST: 'true',
    ...overrides,
  };
}

describe('legacy mission-bound CST compatibility', () => {
  beforeEach(() => {
    validateScopedTokenMock.mockReset();
  });

  it('allows legacy mission-bound proxy CSTs to reach the signing gate', async () => {
    const claims = {
      sub: 'did:key:z6Mktestworker111111111111111111111111111111',
      aud: 'clawproxy.test',
      scope: ['proxy:call', 'clawproxy:call'],
      token_lane: 'legacy' as const,
      mission_id: 'bty_legacy_mission_test',
    };

    validateScopedTokenMock.mockResolvedValue({
      valid: true,
      token_hash: 'tok_hash_test',
      claims: {
        ...claims,
        token_scope_hash_b64u: await computeTokenScopeHashB64uV1(claims),
      },
    });

    const res = await worker.fetch(
      new Request('https://clawproxy.test/v1/proxy/openai', {
        method: 'POST',
        headers: {
          'X-CST': 'jwt_legacy',
          'X-Provider-API-Key': 'sk-test',
        },
      }),
      makeEnv() as any,
    );

    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body?.error?.code).toBe('SIGNING_NOT_CONFIGURED');
  });

  it('still rejects legacy CSTs that are not mission-bound', async () => {
    const claims = {
      sub: 'did:key:z6Mktestworker111111111111111111111111111111',
      aud: 'clawproxy.test',
      scope: ['proxy:call', 'clawproxy:call'],
      token_lane: 'legacy' as const,
    };

    validateScopedTokenMock.mockResolvedValue({
      valid: true,
      token_hash: 'tok_hash_test',
      claims: {
        ...claims,
        token_scope_hash_b64u: await computeTokenScopeHashB64uV1(claims),
      },
    });

    const res = await worker.fetch(
      new Request('https://clawproxy.test/v1/proxy/openai', {
        method: 'POST',
        headers: {
          'X-CST': 'jwt_legacy',
          'X-Provider-API-Key': 'sk-test',
        },
      }),
      makeEnv() as any,
    );

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body?.error?.code).toBe('TOKEN_CONTROL_CHAIN_MISSING');
  });
});
