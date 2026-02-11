import { describe, expect, it } from 'vitest';

import worker from '../src/index';
import { base64urlEncode } from '../src/crypto';
import { computeTokenScopeHashB64u } from '../src/token-scope-hash';

function makeSigningSeed(): string {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) {
    seed[i] = (i + 11) % 256;
  }
  return base64urlEncode(seed);
}

function makeEnv(overrides: Record<string, unknown> = {}) {
  return {
    SCOPE_VERSION: '0.1.0-test',
    SCOPE_ADMIN_KEY: 'scope-admin-test',
    SCOPE_SIGNING_KEY: makeSigningSeed(),
    ...overrides,
  };
}

describe('MPY-US-005: CST payment_account_did claim support (clawscope)', () => {
  it('issues + introspects payment_account_did and binds it into token_scope_hash_b64u', async () => {
    const env = makeEnv();

    const withClaim = await worker.fetch(
      new Request('https://clawscope.test/v1/tokens/issue', {
        method: 'POST',
        headers: {
          authorization: 'Bearer scope-admin-test',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          sub: 'did:key:zAgent',
          aud: 'clawproxy.test',
          scope: ['proxy:call', 'clawproxy:call'],
          payment_account_did: 'did:key:zPaymentAccount',
          ttl_sec: 300,
        }),
      }),
      env as any
    );

    expect(withClaim.status).toBe(200);
    const withClaimBody = await withClaim.json();

    expect(withClaimBody.payment_account_did).toBe('did:key:zPaymentAccount');
    expect(typeof withClaimBody.token).toBe('string');
    expect(typeof withClaimBody.token_scope_hash_b64u).toBe('string');

    const expectedWithClaim = await computeTokenScopeHashB64u({
      sub: 'did:key:zAgent',
      aud: 'clawproxy.test',
      scope: ['proxy:call', 'clawproxy:call'],
      payment_account_did: 'did:key:zPaymentAccount',
    });

    expect(withClaimBody.token_scope_hash_b64u).toBe(expectedWithClaim);

    const introspect = await worker.fetch(
      new Request('https://clawscope.test/v1/tokens/introspect', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify({ token: withClaimBody.token }),
      }),
      env as any
    );

    expect(introspect.status).toBe(200);
    const introspectBody = await introspect.json();

    expect(introspectBody.active).toBe(true);
    expect(introspectBody.payment_account_did).toBe('did:key:zPaymentAccount');
    expect(introspectBody.token_scope_hash_b64u).toBe(expectedWithClaim);

    const withoutClaim = await worker.fetch(
      new Request('https://clawscope.test/v1/tokens/issue', {
        method: 'POST',
        headers: {
          authorization: 'Bearer scope-admin-test',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          sub: 'did:key:zAgent',
          aud: 'clawproxy.test',
          scope: ['proxy:call', 'clawproxy:call'],
          ttl_sec: 300,
        }),
      }),
      env as any
    );

    expect(withoutClaim.status).toBe(200);
    const withoutClaimBody = await withoutClaim.json();

    expect(withoutClaimBody.token_scope_hash_b64u).not.toBe(withClaimBody.token_scope_hash_b64u);
  });

  it('rejects invalid payment_account_did at issuance', async () => {
    const env = makeEnv();

    const res = await worker.fetch(
      new Request('https://clawscope.test/v1/tokens/issue', {
        method: 'POST',
        headers: {
          authorization: 'Bearer scope-admin-test',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          sub: 'did:key:zAgent',
          aud: 'clawproxy.test',
          scope: ['proxy:call', 'clawproxy:call'],
          payment_account_did: 'not-a-did',
          ttl_sec: 300,
        }),
      }),
      env as any
    );

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe('PAYMENT_ACCOUNT_CLAIM_INVALID');
  });
});
