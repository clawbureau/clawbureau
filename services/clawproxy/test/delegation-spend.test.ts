import { afterEach, describe, expect, it, vi } from 'vitest';

import worker from '../src/index';
import type { Env } from '../src/types';
import { base64urlEncode, importEd25519Key, signEd25519 } from '../src/crypto';
import { computeTokenScopeHashB64uV1 } from '../src/token-scope-hash';
import { IdempotencyDurableObject } from '../src/idempotency';

afterEach(() => {
  vi.restoreAllMocks();
});

async function issueDelegatedCst(params: {
  sub: string;
  delegation_id?: string;
  delegator_did?: string;
  delegate_did?: string;
  delegation_policy_hash_b64u?: string;
  delegation_spend_cap_minor?: string;
  delegation_expires_at?: number;
}): Promise<{ token: string; issuerPublicKeyB64u: string }> {
  const issuerSeed = new Uint8Array(32);
  for (let i = 0; i < issuerSeed.length; i++) {
    issuerSeed[i] = (i + 37) % 256;
  }

  const issuer = await importEd25519Key(base64urlEncode(issuerSeed));

  const aud = 'clawproxy.test';
  const scope = ['proxy:call', 'clawproxy:call'];

  const now = Math.floor(Date.now() / 1000);
  const tokenScopeHash = await computeTokenScopeHashB64uV1({
    sub: params.sub,
    aud,
    scope,
    owner_did: params.delegator_did,
    delegation_id: params.delegation_id,
    delegator_did: params.delegator_did,
    delegate_did: params.delegate_did,
    delegation_policy_hash_b64u: params.delegation_policy_hash_b64u,
    delegation_spend_cap_minor: params.delegation_spend_cap_minor,
    delegation_expires_at: params.delegation_expires_at,
  });

  const claims = {
    token_version: '1',
    sub: params.sub,
    aud,
    scope,
    iat: now,
    exp: now + 600,
    token_scope_hash_b64u: tokenScopeHash,
    delegation_id: params.delegation_id,
    delegator_did: params.delegator_did,
    delegate_did: params.delegate_did,
    delegation_policy_hash_b64u: params.delegation_policy_hash_b64u,
    delegation_spend_cap_minor: params.delegation_spend_cap_minor,
    delegation_expires_at: params.delegation_expires_at,
    owner_did: params.delegator_did,
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
    seed[i] = i + 11;
  }
  return base64urlEncode(seed);
}

class MockStorage {
  private readonly map = new Map<string, unknown>();

  async get(key: string): Promise<unknown> {
    return this.map.get(key);
  }

  async put(key: string, value: unknown, _opts?: unknown): Promise<void> {
    this.map.set(key, value);
  }

  async delete(_key: string): Promise<boolean> {
    // DurableObjectStorage.delete is not used by IdempotencyDurableObject.
    return false;
  }

  async deleteAll(): Promise<void> {
    this.map.clear();
  }
}

function makeIdempotencyNamespace(): DurableObjectNamespace {
  const objects = new Map<string, IdempotencyDurableObject>();

  const getDo = (id: string): IdempotencyDurableObject => {
    const existing = objects.get(id);
    if (existing) return existing;

    const storage = new MockStorage();
    const state: any = {
      storage,
      blockConcurrencyWhile: async (fn: () => Promise<Response>) => fn(),
    };

    const ido = new IdempotencyDurableObject(state as any, {});
    objects.set(id, ido);
    return ido;
  };

  return {
    idFromName(name: string) {
      return name as any;
    },
    get(id: any) {
      const ido = getDo(String(id));
      return {
        fetch: (input: RequestInfo | URL, init?: RequestInit) => {
          if (input instanceof Request) {
            return ido.fetch(input);
          }

          const url = typeof input === 'string' ? input : input.toString();
          return ido.fetch(new Request(url, init));
        },
      } as any;
    },
  } as any;
}

function makeEnv(issuerPublicKeyB64u: string, overrides: Partial<Env> = {}): Env {
  return {
    PROXY_VERSION: '0.1.0-test',
    PROXY_SIGNING_KEY: makeProxySigningKey(),
    PROXY_RATE_LIMITER: {
      limit: async () => ({ success: true }),
    },
    IDEMPOTENCY: makeIdempotencyNamespace(),

    CST_ISSUER_PUBLIC_KEY: issuerPublicKeyB64u,
    CST_AUDIENCE: 'clawproxy.test',

    CLAWDELEGATE_BASE_URL: 'https://clawdelegate.test',
    CLAWDELEGATE_PROXY_KEY: 'delegate-proxy-key',
    CLAWDELEGATE_DEFAULT_SPEND_MINOR: '5',

    ...overrides,
  } as Env;
}

function makeRequest(token: string): Request {
  return new Request('https://clawproxy.test/v1/proxy/openai', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-cst': token,
      'x-provider-api-key': 'sk-user-key',
      'x-delegation-spend-minor': '7',
      'x-idempotency-key': 'nonce-delegation-test-1',
    },
    body: JSON.stringify({
      model: 'gpt-4o-mini',
      messages: [{ role: 'user', content: 'delegation smoke' }],
    }),
  });
}

describe('delegated spend governance via clawdelegate', () => {
  it('authorizes delegated spend and emits payment delegation context in receipt', async () => {
    const subjectDid = 'did:key:z6Mkauthdelegate1';
    const delegatorDid = 'did:key:z6Mkdelegator1';
    const delegationId = 'dlg_11111111-1111-1111-1111-111111111111';

    const { token, issuerPublicKeyB64u } = await issueDelegatedCst({
      sub: subjectDid,
      delegation_id: delegationId,
      delegator_did: delegatorDid,
      delegate_did: subjectDid,
      delegation_spend_cap_minor: '100',
      delegation_expires_at: Math.floor(Date.now() / 1000) + 3600,
    });

    const env = makeEnv(issuerPublicKeyB64u);

    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url =
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

      if (url.startsWith('https://clawdelegate.test/')) {
        const body = JSON.parse(String(init?.body ?? '{}'));
        expect(body.actor_did).toBe(subjectDid);
        expect(body.amount_minor).toBe('7');
        expect(body.token_hash).toMatch(/^[a-f0-9]{64}$/);

        return new Response(
          JSON.stringify({
            schema_version: '1',
            result: {
              status: 'applied',
              operation: 'authorize',
              delegation_id: delegationId,
              idempotency_key: body.idempotency_key,
              amount_minor: '7',
              reserved_minor: '0',
              consumed_minor: '7',
              spend_cap_minor: '100',
              ledger_event_id: 'led_evt_1',
              decided_at: new Date().toISOString(),
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (url.startsWith('https://api.openai.com/')) {
        return new Response(
          JSON.stringify({
            id: 'chatcmpl-test',
            choices: [{ index: 0, message: { role: 'assistant', content: 'ok' } }],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      throw new Error(`unexpected upstream call: ${url}`);
    });

    vi.stubGlobal('fetch', fetchMock);

    const response = await worker.fetch(makeRequest(token), env);
    expect(response.status).toBe(200);

    const body = await response.json();
    expect(body?._receipt?.payment?.mode).toBe('user');
    expect(body?._receipt?.payment?.delegationSpend?.status).toBe('authorized');
    expect(body?._receipt?.payment?.delegationSpend?.delegationId).toBe(delegationId);
    expect(body?._receipt?.payment?.delegationSpend?.amountMinor).toBe('7');

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('fails closed when delegation claims are structurally invalid', async () => {
    const subjectDid = 'did:key:z6Mkauthdelegate2';

    const { token, issuerPublicKeyB64u } = await issueDelegatedCst({
      sub: subjectDid,
      delegation_id: 'dlg_22222222-2222-2222-2222-222222222222',
      delegator_did: 'did:key:z6Mkdelegator2',
      delegate_did: 'did:key:z6Mkanotherdelegate2',
      delegation_spend_cap_minor: '100',
      delegation_expires_at: Math.floor(Date.now() / 1000) + 3600,
    });

    const env = makeEnv(issuerPublicKeyB64u);
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const response = await worker.fetch(makeRequest(token), env);
    expect(response.status).toBe(401);

    const body = await response.json();
    expect(body?.error?.code).toBe('TOKEN_DELEGATION_BINDING_INVALID');
    expect(fetchMock).toHaveBeenCalledTimes(0);
  });
});
