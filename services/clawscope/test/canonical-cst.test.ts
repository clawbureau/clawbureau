import { afterEach, describe, expect, it } from 'vitest';

import worker from '../src/index';
import { base64urlEncode } from '../src/crypto';

function makeSigningSeed(): string {
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) {
    seed[i] = (i + 23) % 256;
  }
  return base64urlEncode(seed);
}

function makeEnv(overrides: Record<string, unknown> = {}) {
  return {
    SCOPE_VERSION: '0.1.0-test',
    SCOPE_ADMIN_KEY: 'scope-admin-test',
    SCOPE_SIGNING_KEY: makeSigningSeed(),
    SCOPE_LEGACY_EXCHANGE_MODE: 'migration',
    SCOPE_SENSITIVE_SCOPE_PREFIXES: 'control:',
    CLAIM_CONTROL_BASE_URL: 'https://clawclaim.test',
    ...overrides,
  };
}

function makeChainRecord() {
  return {
    status: 'ok',
    owner_did: 'did:key:zOwner',
    chain: {
      owner_did: 'did:key:zOwner',
      controller_did: 'did:key:zController',
      agent_did: 'did:key:zAgent',
      policy_hash_b64u: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      active: true,
    },
    controller: {
      controller_did: 'did:key:zController',
      owner_did: 'did:key:zOwner',
      active: true,
      policy: {
        policy_version: '1',
        mode: 'owner_bound',
        owner_did: 'did:key:zOwner',
        allowed_sensitive_scopes: ['control:token:issue_sensitive'],
        policy_hash_b64u: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        updated_at: 1,
        updated_at_iso: '2026-01-01T00:00:00.000Z',
      },
    },
    agent_binding: {
      binding_version: '1',
      controller_did: 'did:key:zController',
      agent_did: 'did:key:zAgent',
      owner_did: 'did:key:zOwner',
      active: true,
      policy_hash_b64u: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    },
  };
}

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe('CSC-US-014 canonical CST lane', () => {
  it('issues canonical tokens with control-chain binding and exposes transition matrix', async () => {
    const env = makeEnv();

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (
        url.includes(
          '/v1/control-plane/controllers/did%3Akey%3AzController/agents/did%3Akey%3AzAgent'
        )
      ) {
        return new Response(JSON.stringify(makeChainRecord()), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }

      throw new Error(`unexpected fetch call: ${url}`);
    }) as typeof fetch;

    const issue = await worker.fetch(
      new Request('https://clawscope.test/v1/tokens/issue/canonical', {
        method: 'POST',
        headers: {
          authorization: 'Bearer scope-admin-test',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          sub: 'did:key:zAgent',
          owner_did: 'did:key:zOwner',
          controller_did: 'did:key:zController',
          agent_did: 'did:key:zAgent',
          aud: 'staging.clawbounties.com',
          scope: ['control:token:issue_sensitive'],
          ttl_sec: 300,
        }),
      }),
      env as any
    );

    expect(issue.status).toBe(200);
    const issued = await issue.json();

    expect(issued.token_lane).toBe('canonical');
    expect(issued.controller_did).toBe('did:key:zController');
    expect(typeof issued.token).toBe('string');

    const matrix = await worker.fetch(
      new Request('https://clawscope.test/v1/tokens/introspect/matrix', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token: issued.token }),
      }),
      env as any
    );

    expect(matrix.status).toBe(200);
    const matrixBody = await matrix.json();

    expect(matrixBody.active).toBe(true);
    expect(matrixBody.matrix['token.issue.sensitive'].allowed).toBe(true);
    expect(matrixBody.matrix['key.rotate'].allowed).toBe(false);
    expect(matrixBody.matrix['key.rotate'].reason_code).toBe('TOKEN_SCOPE_MISSING');
  });

  it('keeps legacy lane as migration path and blocks sensitive scope issuance there', async () => {
    const env = makeEnv({ SCOPE_LEGACY_EXCHANGE_MODE: 'migration' });

    const legacySensitive = await worker.fetch(
      new Request('https://clawscope.test/v1/tokens/issue', {
        method: 'POST',
        headers: {
          authorization: 'Bearer scope-admin-test',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          sub: 'did:key:zAgent',
          aud: 'staging.clawbounties.com',
          scope: ['control:token:issue_sensitive'],
          ttl_sec: 300,
        }),
      }),
      env as any
    );

    expect(legacySensitive.status).toBe(403);
    const legacySensitiveBody = await legacySensitive.json();
    expect(legacySensitiveBody.error).toBe('LEGACY_SENSITIVE_SCOPE_FORBIDDEN');

    const legacyNonSensitive = await worker.fetch(
      new Request('https://clawscope.test/v1/tokens/issue', {
        method: 'POST',
        headers: {
          authorization: 'Bearer scope-admin-test',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          sub: 'did:key:zAgent',
          aud: 'staging.clawbounties.com',
          scope: ['clawproxy:call'],
          ttl_sec: 300,
        }),
      }),
      env as any
    );

    expect(legacyNonSensitive.status).toBe(200);
    const legacyNonSensitiveBody = await legacyNonSensitive.json();
    expect(legacyNonSensitiveBody.token_lane).toBe('legacy');
    expect(legacyNonSensitiveBody.legacy_exchange_mode).toBe('migration');
  });
});
