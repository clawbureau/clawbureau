import { afterEach, describe, expect, it, vi } from 'vitest';

import worker from '../src/index';
import type { Env } from '../src/types';
import {
  base64urlEncode,
  importEd25519Key,
  signEd25519,
} from '../src/crypto';
import { computeTokenScopeHashB64uV1 } from '../src/token-scope-hash';

afterEach(() => {
  vi.restoreAllMocks();
});

async function issueCst(
  sub: string,
  options: { paymentAccountDid?: string } = {}
): Promise<{ token: string; issuerPublicKeyB64u: string }> {
  const issuerSeed = new Uint8Array(32);
  for (let i = 0; i < issuerSeed.length; i++) {
    issuerSeed[i] = (i + 91) % 256;
  }

  const issuer = await importEd25519Key(base64urlEncode(issuerSeed));

  const aud = 'clawproxy.test';
  const scope = ['proxy:call', 'clawproxy:call'];

  const now = Math.floor(Date.now() / 1000);
  const tokenScopeHash = await computeTokenScopeHashB64uV1({
    sub,
    aud,
    scope,
    payment_account_did: options.paymentAccountDid,
  });

  const claims = {
    token_version: '1',
    sub,
    aud,
    scope,
    iat: now,
    exp: now + 600,
    token_scope_hash_b64u: tokenScopeHash,
    payment_account_did: options.paymentAccountDid,
  };

  const sanitizedClaims = Object.fromEntries(
    Object.entries(claims).filter(([, value]) => value !== undefined)
  );

  const header = {
    alg: 'EdDSA',
    typ: 'JWT',
  };

  const headerB64u = base64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64u = base64urlEncode(
    new TextEncoder().encode(JSON.stringify(sanitizedClaims))
  );
  const signatureB64u = await signEd25519(
    issuer.privateKey,
    `${headerB64u}.${payloadB64u}`
  );

  return {
    token: `${headerB64u}.${payloadB64u}.${signatureB64u}`,
    issuerPublicKeyB64u: base64urlEncode(issuer.publicKeyBytes),
  };
}

function makeProxySigningKey(): string {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) {
    seed[i] = i + 1;
  }
  return base64urlEncode(seed);
}

function makeEnv(
  issuerPublicKeyB64u: string,
  overrides: Partial<Env> = {}
): Env {
  return {
    PROXY_VERSION: '0.1.0-test',
    PROXY_SIGNING_KEY: makeProxySigningKey(),
    PROXY_RATE_LIMITER: {
      limit: async () => ({ success: true }),
    },
    IDEMPOTENCY: {} as DurableObjectNamespace,

    CST_ISSUER_PUBLIC_KEY: issuerPublicKeyB64u,
    CST_AUDIENCE: 'clawproxy.test',

    PLATFORM_PAID_ENABLED: 'true',
    PLATFORM_OPENAI_API_KEY: 'sk-platform-test',
    LEDGER_BASE_URL: 'https://ledger.test',
    LEDGER_ADMIN_KEY: 'ledger-admin-test',
    PLATFORM_PAID_MIN_AVAILABLE_MINOR: '1',

    ...overrides,
  } as Env;
}

function makePlatformPaidRequest(
  did: string,
  token: string,
  options: { paymentAccountDid?: string } = {}
): Request {
  const headers = new Headers({
    'content-type': 'application/json',
    'x-cst': token,
    'x-client-did': did,
  });

  if (options.paymentAccountDid) {
    headers.set('x-payment-account-did', options.paymentAccountDid);
  }

  return new Request('https://clawproxy.test/v1/proxy/openai', {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'funding-check-smoke' }],
    }),
  });
}

describe('MPY-US-004/005: platform-paid funding + CST payment account binding', () => {
  it('returns deterministic 402 PAYMENT_REQUIRED when platform-paid account is unbound', async () => {
    const did = 'did:key:funding_unbound_test';
    const { token, issuerPublicKeyB64u } = await issueCst(did);
    const env = makeEnv(issuerPublicKeyB64u);

    const fetchMock = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

      if (url.startsWith('https://ledger.test/accounts/')) {
        return new Response(JSON.stringify({ error: 'not found' }), {
          status: 404,
          headers: { 'content-type': 'application/json' },
        });
      }

      throw new Error(`unexpected upstream call: ${url}`);
    });

    vi.stubGlobal('fetch', fetchMock);

    const res = await worker.fetch(
      makePlatformPaidRequest(did, token, { paymentAccountDid: did }),
      env
    );

    expect(res.status).toBe(402);

    const body = await res.json();
    expect(body?.error?.code).toBe('PAYMENT_REQUIRED');
    expect(body?.error?.message).toContain('not bound');

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('fails closed with PAYMENT_ACCOUNT_CLAIM_MISMATCH on claim/header mismatch', async () => {
    const did = 'did:key:claim_subject_test';
    const claimDid = 'did:key:claim_bound_account';
    const mismatchedHeaderDid = 'did:key:header_other_account';

    const { token, issuerPublicKeyB64u } = await issueCst(did, {
      paymentAccountDid: claimDid,
    });
    const env = makeEnv(issuerPublicKeyB64u);

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const res = await worker.fetch(
      makePlatformPaidRequest(did, token, { paymentAccountDid: mismatchedHeaderDid }),
      env
    );

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body?.error?.code).toBe('PAYMENT_ACCOUNT_CLAIM_MISMATCH');

    expect(fetchMock).toHaveBeenCalledTimes(0);
  });

  it('fails closed with PAYMENT_ACCOUNT_BINDING_REQUIRED when claim is required but missing', async () => {
    const did = 'did:key:claim_required_missing';
    const { token, issuerPublicKeyB64u } = await issueCst(did);

    const env = makeEnv(issuerPublicKeyB64u, {
      PLATFORM_PAID_REQUIRE_PAYMENT_ACCOUNT_CLAIM: 'true',
    });

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const res = await worker.fetch(
      makePlatformPaidRequest(did, token, { paymentAccountDid: did }),
      env
    );

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body?.error?.code).toBe('PAYMENT_ACCOUNT_BINDING_REQUIRED');

    expect(fetchMock).toHaveBeenCalledTimes(0);
  });

  it('fails closed with PAYMENT_ACCOUNT_CLAIM_INVALID when claim format is invalid', async () => {
    const did = 'did:key:claim_invalid_subject';
    const { token, issuerPublicKeyB64u } = await issueCst(did, {
      paymentAccountDid: 'not-a-did',
    });

    const env = makeEnv(issuerPublicKeyB64u);

    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const res = await worker.fetch(
      makePlatformPaidRequest(did, token, { paymentAccountDid: did }),
      env
    );

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body?.error?.code).toBe('PAYMENT_ACCOUNT_CLAIM_INVALID');

    expect(fetchMock).toHaveBeenCalledTimes(0);
  });

  it('allows matched+funded platform-paid call and emits binding+funding metadata in signed receipt context', async () => {
    const did = 'did:key:funding_ok_claim_test';
    const { token, issuerPublicKeyB64u } = await issueCst(did, {
      paymentAccountDid: did,
    });
    const env = makeEnv(issuerPublicKeyB64u);

    const fetchMock = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

      if (url.startsWith('https://ledger.test/accounts/')) {
        return new Response(
          JSON.stringify({
            id: 'acc_funded_test',
            did,
            balances: {
              available: '2500',
              held: '0',
              bonded: '0',
              feePool: '0',
              promo: '0',
            },
          }),
          {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }
        );
      }

      if (url.startsWith('https://api.openai.com/')) {
        return new Response(
          JSON.stringify({
            error: {
              message: 'invalid api key',
              type: 'invalid_request_error',
            },
          }),
          {
            status: 401,
            headers: { 'content-type': 'application/json' },
          }
        );
      }

      throw new Error(`unexpected upstream call: ${url}`);
    });

    vi.stubGlobal('fetch', fetchMock);

    const res = await worker.fetch(
      makePlatformPaidRequest(did, token, { paymentAccountDid: did }),
      env
    );

    // Provider can fail (e.g. invalid key), but binding+funding checks must have allowed routing and receipt emission.
    expect(res.status).toBe(401);

    const body = await res.json();

    expect(body?._receipt?.payment?.mode).toBe('platform');
    expect(body?._receipt?.payment?.paid).toBe(true);
    expect(body?._receipt?.payment?.accountBinding?.status).toBe('matched');
    expect(body?._receipt?.payment?.accountBinding?.claimPresent).toBe(true);
    expect(body?._receipt?.payment?.accountBinding?.claimAccountDid).toBe(did);
    expect(body?._receipt?.payment?.accountBinding?.effectiveAccountDidSource).toBe(
      'cst-payment-account-did'
    );

    expect(body?._receipt?.payment?.fundingCheck?.status).toBe('funded');
    expect(body?._receipt?.payment?.fundingCheck?.accountDid).toBe(did);
    expect(body?._receipt?.payment?.fundingCheck?.accountId).toBe('acc_funded_test');
    expect(body?._receipt?.payment?.fundingCheck?.availableMinor).toBe('2500');

    const md = body?._receipt_envelope?.payload?.metadata;
    expect(md?.payment_mode).toBe('platform');
    expect(md?.payment_account_binding?.claim_present).toBe(true);
    expect(md?.payment_account_binding?.claim_account_did).toBe(did);
    expect(md?.payment_account_binding?.effective_account_did_source).toBe(
      'cst-payment-account-did'
    );
    expect(md?.payment_funding_check?.account_did).toBe(did);
    expect(md?.payment_funding_check?.account_id).toBe('acc_funded_test');
    expect(md?.payment_funding_check?.available_minor).toBe('2500');

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('keeps BYOK path unchanged (no funding/binding precheck dependency)', async () => {
    const did = 'did:key:byok_unchanged_test';
    const { issuerPublicKeyB64u } = await issueCst(did);

    const env = makeEnv(issuerPublicKeyB64u, {
      LEDGER_BASE_URL: undefined,
      LEDGER_ADMIN_KEY: undefined,
      PLATFORM_PAID_REQUIRE_PAYMENT_ACCOUNT_CLAIM: 'true',
    });

    const fetchMock = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

      if (url.startsWith('https://api.openai.com/')) {
        return new Response(JSON.stringify({ id: 'resp_ok' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      throw new Error(`unexpected upstream call: ${url}`);
    });

    vi.stubGlobal('fetch', fetchMock);

    const res = await worker.fetch(
      new Request('https://clawproxy.test/v1/proxy/openai', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-provider-api-key': 'sk-user-byok',
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [{ role: 'user', content: 'byok path' }],
        }),
      }),
      env
    );

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body?._receipt?.payment?.mode).toBe('user');
    expect(body?._receipt?.payment?.accountBinding).toBeUndefined();
    expect(body?._receipt?.payment?.fundingCheck).toBeUndefined();

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
