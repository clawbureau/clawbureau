import { describe, expect, it } from 'vitest';

import worker from '../src/index';
import { base64urlEncode } from '../src/crypto';

function makeSigningSeed(offset: number): string {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) {
    seed[i] = (i + offset) % 256;
  }
  return base64urlEncode(seed);
}

function makeEnv(overrides: Record<string, unknown> = {}) {
  return {
    SCOPE_VERSION: '0.1.0-test',
    SCOPE_ADMIN_KEY: 'scope-admin-test',
    SCOPE_SIGNING_KEY: makeSigningSeed(23),
    SCOPE_LEGACY_EXCHANGE_MODE: 'migration',
    ...overrides,
  };
}

async function issueLegacyToken(env: Record<string, unknown>, sub: string) {
  const response = await worker.fetch(
    new Request('https://clawscope.test/v1/tokens/issue', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${String(env.SCOPE_ADMIN_KEY)}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        sub,
        aud: 'staging.clawbounties.com',
        scope: ['clawproxy:call'],
        ttl_sec: 600,
      }),
    }),
    env as any
  );

  const json = await response.json();
  return { response, json };
}

async function introspectToken(env: Record<string, unknown>, token: string) {
  const response = await worker.fetch(
    new Request('https://clawscope.test/v1/tokens/introspect', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token }),
    }),
    env as any
  );

  const json = await response.json();
  return { response, json };
}

describe('CSC-US-016/017 kid interoperability + overlap semantics', () => {
  it('accepts tokens from foreign kid when verify-only key is configured', async () => {
    const envA = makeEnv({ SCOPE_SIGNING_KEY: makeSigningSeed(23) });
    const envB = makeEnv({ SCOPE_SIGNING_KEY: makeSigningSeed(77) });

    const issued = await issueLegacyToken(envB, 'did:key:zKidInteropB');
    expect(issued.response.status).toBe(200);

    const token = String(issued.json.token);

    const unknownKid = await introspectToken(envA, token);
    expect(unknownKid.response.status).toBe(401);
    expect(unknownKid.json.error).toBe('TOKEN_UNKNOWN_KID');

    const jwksBRes = await worker.fetch(new Request('https://clawscope.test/v1/jwks'), envB as any);
    expect(jwksBRes.status).toBe(200);
    const jwksB = await jwksBRes.json();
    const keyB = jwksB.keys[0];

    const envAInterop = makeEnv({
      SCOPE_SIGNING_KEY: makeSigningSeed(23),
      SCOPE_VERIFY_PUBLIC_KEYS_JSON: JSON.stringify([
        {
          x: keyB.x,
          kid: keyB.kid,
          not_after_unix: Math.floor(Date.now() / 1000) + 3600,
          source_label: 'inter-env-overlap',
        },
      ]),
    });

    const accepted = await introspectToken(envAInterop, token);
    expect(accepted.response.status).toBe(200);
    expect(accepted.json.active).toBe(true);
    expect(accepted.json.kid).toBe(keyB.kid);
    expect(accepted.json.kid_source).toBe('header');
  });

  it('fails closed with TOKEN_KID_EXPIRED when overlap key is outside window', async () => {
    const envA = makeEnv({ SCOPE_SIGNING_KEY: makeSigningSeed(23) });
    const envB = makeEnv({ SCOPE_SIGNING_KEY: makeSigningSeed(91) });

    const issued = await issueLegacyToken(envB, 'did:key:zKidExpiredB');
    expect(issued.response.status).toBe(200);

    const token = String(issued.json.token);
    const jwksBRes = await worker.fetch(new Request('https://clawscope.test/v1/jwks'), envB as any);
    const jwksB = await jwksBRes.json();
    const keyB = jwksB.keys[0];

    const envExpired = makeEnv({
      SCOPE_SIGNING_KEY: makeSigningSeed(23),
      SCOPE_VERIFY_PUBLIC_KEYS_JSON: JSON.stringify([
        {
          x: keyB.x,
          kid: keyB.kid,
          not_after_unix: Math.floor(Date.now() / 1000) - 1,
          source_label: 'expired-overlap',
        },
      ]),
    });

    const expired = await introspectToken(envExpired, token);
    expect(expired.response.status).toBe(401);
    expect(expired.json.error).toBe('TOKEN_KID_EXPIRED');
  });

  it('publishes key overlap contract with verify-only and expiring key metadata', async () => {
    const envA = makeEnv({ SCOPE_SIGNING_KEY: makeSigningSeed(23) });
    const envB = makeEnv({ SCOPE_SIGNING_KEY: makeSigningSeed(39) });

    const jwksBRes = await worker.fetch(new Request('https://clawscope.test/v1/jwks'), envB as any);
    const jwksB = await jwksBRes.json();
    const keyB = jwksB.keys[0];

    const expiringAt = Math.floor(Date.now() / 1000) + 7200;
    const envOverlap = makeEnv({
      SCOPE_SIGNING_KEY: makeSigningSeed(23),
      SCOPE_VERIFY_PUBLIC_KEYS_JSON: JSON.stringify([
        {
          x: keyB.x,
          kid: keyB.kid,
          not_after_unix: expiringAt,
          source_label: 'rotation-overlap',
        },
      ]),
    });

    const contract = await worker.fetch(
      new Request('https://clawscope.test/v1/keys/rotation-contract'),
      envOverlap as any
    );

    expect(contract.status).toBe(200);
    const body = await contract.json();

    expect(body.contract_version).toBe('2');
    expect(Array.isArray(body.accepted_kids)).toBe(true);
    expect(Array.isArray(body.verify_only_kids)).toBe(true);
    expect(body.verify_only_kids).toContain(keyB.kid);
    expect(Array.isArray(body.expiring_kids)).toBe(true);
    expect(body.expiring_kids).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kid: keyB.kid, not_after_unix: expiringAt }),
      ])
    );
  });
});
