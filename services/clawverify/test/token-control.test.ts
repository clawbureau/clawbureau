import { describe, expect, it } from 'vitest';

import { verifyTokenControl } from '../src/verify-token-control';
import { jcsCanonicalize } from '../src/jcs';
import { base64UrlEncode } from '../src/crypto';

async function computeScopeHash(payload: {
  sub: string;
  aud: string | string[];
  scope: string[];
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  policy_hash_b64u?: string;
  control_plane_policy_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
}) {
  const aud = Array.isArray(payload.aud)
    ? Array.from(new Set(payload.aud.map((v) => v.trim()).filter((v) => v.length > 0))).sort()
    : [payload.aud.trim()];

  const scope = Array.from(new Set(payload.scope.map((v) => v.trim()).filter((v) => v.length > 0))).sort();

  const canonical: Record<string, unknown> = {
    token_version: '1',
    sub: payload.sub,
    aud,
    scope,
  };

  if (payload.owner_did) canonical.owner_did = payload.owner_did;
  if (payload.controller_did) canonical.controller_did = payload.controller_did;
  if (payload.agent_did) canonical.agent_did = payload.agent_did;
  if (payload.policy_hash_b64u) canonical.policy_hash_b64u = payload.policy_hash_b64u;
  if (payload.control_plane_policy_hash_b64u) {
    canonical.control_plane_policy_hash_b64u = payload.control_plane_policy_hash_b64u;
  }
  if (payload.payment_account_did) canonical.payment_account_did = payload.payment_account_did;
  if (typeof payload.spend_cap === 'number') canonical.spend_cap = payload.spend_cap;
  if (payload.mission_id) canonical.mission_id = payload.mission_id;

  const bytes = new TextEncoder().encode(jcsCanonicalize(canonical));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

describe('verifyTokenControl', () => {
  it('returns VALID when canonical token satisfies scope/audience/transitions matrix', async () => {
    const introspection = {
      active: true,
      token_hash: 'hash_1',
      sub: 'did:key:zAgent',
      aud: ['staging.clawbounties.com'],
      scope: ['control:token:issue_sensitive', 'control:key:rotate'],
      owner_did: 'did:key:zOwner',
      controller_did: 'did:key:zController',
      agent_did: 'did:key:zAgent',
      policy_hash_b64u: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      control_plane_policy_hash_b64u: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      token_lane: 'canonical' as const,
      kid: 'kid-test-1',
    };

    const tokenScopeHash = await computeScopeHash(introspection);

    const verification = await verifyTokenControl(
      {
        token: 'jwt-token',
        expected_owner_did: 'did:key:zOwner',
        expected_controller_did: 'did:key:zController',
        expected_agent_did: 'did:key:zAgent',
        required_scope: ['control:token:issue_sensitive'],
        required_audience: ['staging.clawbounties.com'],
        required_transitions: ['token.issue.sensitive'],
      },
      {
        clawscopeBaseUrl: 'https://clawscope.test',
        fetcher: (async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = String(input);

          if (url.endsWith('/v1/tokens/introspect')) {
            return new Response(
              JSON.stringify({
                ...introspection,
                token_scope_hash_b64u: tokenScopeHash,
              }),
              {
                status: 200,
                headers: { 'content-type': 'application/json' },
              }
            );
          }

          if (url.endsWith('/v1/tokens/introspect/matrix')) {
            const body = JSON.parse(String(init?.body ?? '{}')) as { token?: string };
            if (body.token !== 'jwt-token') {
              return new Response(JSON.stringify({ error: 'TOKEN_UNKNOWN' }), { status: 401 });
            }

            return new Response(
              JSON.stringify({
                active: true,
                revoked: false,
                matrix: {
                  'token.issue.sensitive': {
                    allowed: true,
                    reason_code: 'ALLOWED',
                    reason: 'Token satisfies canonical + scope requirements',
                  },
                },
              }),
              {
                status: 200,
                headers: { 'content-type': 'application/json' },
              }
            );
          }

          if (url.endsWith('/v1/keys/transparency/latest')) {
            return new Response(
              JSON.stringify({
                snapshot_id: 'snap-1',
                generated_at: Math.floor(Date.now() / 1000),
                generated_at_iso: new Date().toISOString(),
                active_kid: 'kid-test-1',
                accepted_kids: ['kid-test-1'],
                expiring_kids: [],
              }),
              {
                status: 200,
                headers: { 'content-type': 'application/json' },
              }
            );
          }

          throw new Error(`unexpected URL: ${url}`);
        }) as typeof fetch,
      }
    );

    expect(verification.result.status).toBe('VALID');
    expect(verification.token_lane).toBe('canonical');
    expect(verification.remediation_hints).toEqual([]);
  });

  it('returns TOKEN_CONTROL_CHAIN_MISSING for legacy lane tokens', async () => {
    const verification = await verifyTokenControl(
      {
        token: 'legacy-token',
      },
      {
        clawscopeBaseUrl: 'https://clawscope.test',
        fetcher: (async () =>
          new Response(
            JSON.stringify({
              active: true,
              token_hash: 'hash_legacy',
              sub: 'did:key:zAgent',
              aud: 'staging.clawbounties.com',
              scope: ['clawproxy:call'],
              token_scope_hash_b64u: 'ccccccccccccccccccccccccccccccccccccccccccc',
              token_lane: 'legacy',
            }),
            {
              status: 200,
              headers: { 'content-type': 'application/json' },
            }
          )) as typeof fetch,
      }
    );

    expect(verification.result.status).toBe('INVALID');
    expect(verification.error?.code).toBe('TOKEN_CONTROL_CHAIN_MISSING');
    expect(verification.remediation_hints?.[0]?.code).toBe('USE_CANONICAL_CST_LANE');
  });

  it('returns TOKEN_CONTROL_TRANSITION_FORBIDDEN when matrix denies required transition', async () => {
    const introspection = {
      active: true,
      token_hash: 'hash_2',
      sub: 'did:key:zAgent',
      aud: ['staging.clawbounties.com'],
      scope: ['control:token:issue_sensitive'],
      owner_did: 'did:key:zOwner',
      controller_did: 'did:key:zController',
      agent_did: 'did:key:zAgent',
      policy_hash_b64u: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      control_plane_policy_hash_b64u: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      token_lane: 'canonical' as const,
      kid: 'kid-test-2',
    };

    const tokenScopeHash = await computeScopeHash(introspection);

    const verification = await verifyTokenControl(
      {
        token: 'jwt-token',
        required_transitions: ['key.rotate'],
      },
      {
        clawscopeBaseUrl: 'https://clawscope.test',
        fetcher: (async (input: RequestInfo | URL) => {
          const url = String(input);

          if (url.endsWith('/v1/tokens/introspect')) {
            return new Response(
              JSON.stringify({
                ...introspection,
                token_scope_hash_b64u: tokenScopeHash,
              }),
              {
                status: 200,
                headers: { 'content-type': 'application/json' },
              }
            );
          }

          if (url.endsWith('/v1/tokens/introspect/matrix')) {
            return new Response(
              JSON.stringify({
                active: true,
                revoked: false,
                matrix: {
                  'key.rotate': {
                    allowed: false,
                    reason_code: 'TOKEN_SCOPE_MISSING',
                    reason: 'Token does not contain required scope control:key:rotate',
                  },
                },
              }),
              {
                status: 200,
                headers: { 'content-type': 'application/json' },
              }
            );
          }

          if (url.endsWith('/v1/keys/transparency/latest')) {
            return new Response(
              JSON.stringify({
                snapshot_id: 'snap-2',
                generated_at: Math.floor(Date.now() / 1000),
                generated_at_iso: new Date().toISOString(),
                active_kid: 'kid-test-2',
                accepted_kids: ['kid-test-2'],
                expiring_kids: [],
              }),
              {
                status: 200,
                headers: { 'content-type': 'application/json' },
              }
            );
          }

          throw new Error(`unexpected URL: ${url}`);
        }) as typeof fetch,
      }
    );

    expect(verification.result.status).toBe('INVALID');
    expect(verification.error?.code).toBe('TOKEN_CONTROL_TRANSITION_FORBIDDEN');
    expect(verification.transition_matrix?.['key.rotate']?.allowed).toBe(false);
  });

  it('maps TOKEN_UNKNOWN_KID from clawscope to TOKEN_CONTROL_KEY_UNKNOWN', async () => {
    const verification = await verifyTokenControl(
      {
        token: 'jwt-token',
      },
      {
        clawscopeBaseUrl: 'https://clawscope.test',
        fetcher: (async (input: RequestInfo | URL) => {
          const url = String(input);
          if (url.endsWith('/v1/tokens/introspect')) {
            return new Response(
              JSON.stringify({
                error: 'TOKEN_UNKNOWN_KID',
                message: 'Unknown token kid',
              }),
              {
                status: 401,
                headers: { 'content-type': 'application/json' },
              }
            );
          }

          throw new Error(`unexpected URL: ${url}`);
        }) as typeof fetch,
      }
    );

    expect(verification.result.status).toBe('INVALID');
    expect(verification.error?.code).toBe('TOKEN_CONTROL_KEY_UNKNOWN');
  });

  it('maps TOKEN_KID_EXPIRED from clawscope to TOKEN_CONTROL_KEY_EXPIRED', async () => {
    const verification = await verifyTokenControl(
      {
        token: 'jwt-token',
      },
      {
        clawscopeBaseUrl: 'https://clawscope.test',
        fetcher: (async (input: RequestInfo | URL) => {
          const url = String(input);
          if (url.endsWith('/v1/tokens/introspect')) {
            return new Response(
              JSON.stringify({
                error: 'TOKEN_KID_EXPIRED',
                message: 'Token kid is no longer within accepted overlap window',
              }),
              {
                status: 401,
                headers: { 'content-type': 'application/json' },
              }
            );
          }

          throw new Error(`unexpected URL: ${url}`);
        }) as typeof fetch,
      }
    );

    expect(verification.result.status).toBe('INVALID');
    expect(verification.error?.code).toBe('TOKEN_CONTROL_KEY_EXPIRED');
  });
});
