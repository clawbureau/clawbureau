import { describe, expect, it } from 'vitest';

import { verifyControlChain } from '../src/verify-control-chain';

function makeRecord() {
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
        owner_did: 'did:key:zOwner',
        policy_hash_b64u: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
    },
    agent_binding: {
      controller_did: 'did:key:zController',
      agent_did: 'did:key:zAgent',
      owner_did: 'did:key:zOwner',
      active: true,
      policy_hash_b64u: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    },
  };
}

describe('verifyControlChain', () => {
  it('returns VALID when owner/controller/agent chain is active and consistent', async () => {
    const verification = await verifyControlChain(
      {
        owner_did: 'did:key:zOwner',
        controller_did: 'did:key:zController',
        agent_did: 'did:key:zAgent',
      },
      {
        clawclaimBaseUrl: 'https://clawclaim.test',
        fetcher: (async () =>
          new Response(JSON.stringify(makeRecord()), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })) as typeof fetch,
      }
    );

    expect(verification.result.status).toBe('VALID');
    expect(verification.chain_active).toBe(true);
    expect(verification.policy_hash_b64u).toBe('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
    expect(verification.remediation_hints).toEqual([]);
  });

  it('returns CONTROL_CHAIN_NOT_FOUND with deterministic remediation hints on 404', async () => {
    const verification = await verifyControlChain(
      {
        owner_did: 'did:key:zOwner',
        controller_did: 'did:key:zController',
        agent_did: 'did:key:zAgent',
      },
      {
        clawclaimBaseUrl: 'https://clawclaim.test',
        fetcher: (async () =>
          new Response(JSON.stringify({ error: 'CONTROL_CHAIN_NOT_FOUND' }), {
            status: 404,
            headers: { 'content-type': 'application/json' },
          })) as typeof fetch,
      }
    );

    expect(verification.result.status).toBe('INVALID');
    expect(verification.error?.code).toBe('CONTROL_CHAIN_NOT_FOUND');
    expect(verification.remediation_hints?.map((h) => h.code)).toEqual([
      'REGISTER_CONTROLLER',
      'REGISTER_AGENT_UNDER_CONTROLLER',
    ]);
  });

  it('returns CONTROL_CHAIN_CONTEXT_MISMATCH when lookup owner differs from request owner', async () => {
    const verification = await verifyControlChain(
      {
        owner_did: 'did:key:zOwnerX',
        controller_did: 'did:key:zController',
        agent_did: 'did:key:zAgent',
      },
      {
        clawclaimBaseUrl: 'https://clawclaim.test',
        fetcher: (async () =>
          new Response(
            JSON.stringify({
              ...makeRecord(),
              owner_did: 'did:key:zOwner',
              chain: {
                ...makeRecord().chain,
                owner_did: 'did:key:zOwner',
              },
            }),
            {
              status: 200,
              headers: { 'content-type': 'application/json' },
            }
          )) as typeof fetch,
      }
    );

    expect(verification.result.status).toBe('INVALID');
    expect(verification.error?.code).toBe('CONTROL_CHAIN_CONTEXT_MISMATCH');
  });
});
