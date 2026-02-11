import { describe, expect, it } from 'vitest';

import { computeTokenScopeHashB64uV1 } from '../src/token-scope-hash';

const POLICY_HASH = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; // 43 chars (base64url-ish)

describe('token_scope_hash_b64u', () => {
  it('is deterministic under aud/scope reordering and duplicates', async () => {
    const h1 = await computeTokenScopeHashB64uV1({
      sub: 'did:key:zWorker',
      aud: ['clawproxy.com', 'staging.clawproxy.com'],
      scope: ['clawproxy:call:openai', 'clawproxy:call:anthropic'],
      policy_hash_b64u: POLICY_HASH,
      mission_id: 'mission_123',
      spend_cap: 1,
    });

    const h2 = await computeTokenScopeHashB64uV1({
      sub: 'did:key:zWorker',
      aud: ['staging.clawproxy.com', 'clawproxy.com', 'clawproxy.com'],
      scope: ['clawproxy:call:anthropic', 'clawproxy:call:openai', 'clawproxy:call:openai'],
      policy_hash_b64u: POLICY_HASH,
      mission_id: 'mission_123',
      spend_cap: 1,
    });

    expect(h1).toBe(h2);
  });

  it('changes when mission_id changes', async () => {
    const h1 = await computeTokenScopeHashB64uV1({
      sub: 'did:key:zWorker',
      aud: 'clawproxy.com',
      scope: ['clawproxy:call:openai'],
      policy_hash_b64u: POLICY_HASH,
      mission_id: 'mission_a',
    });

    const h2 = await computeTokenScopeHashB64uV1({
      sub: 'did:key:zWorker',
      aud: 'clawproxy.com',
      scope: ['clawproxy:call:openai'],
      policy_hash_b64u: POLICY_HASH,
      mission_id: 'mission_b',
    });

    expect(h1).not.toBe(h2);
  });

  it('changes when payment_account_did claim changes', async () => {
    const h1 = await computeTokenScopeHashB64uV1({
      sub: 'did:key:zWorker',
      aud: 'clawproxy.com',
      scope: ['clawproxy:call:openai'],
      policy_hash_b64u: POLICY_HASH,
    });

    const h2 = await computeTokenScopeHashB64uV1({
      sub: 'did:key:zWorker',
      aud: 'clawproxy.com',
      scope: ['clawproxy:call:openai'],
      policy_hash_b64u: POLICY_HASH,
      payment_account_did: 'did:key:zPaymentAccount',
    });

    const h3 = await computeTokenScopeHashB64uV1({
      sub: 'did:key:zWorker',
      aud: 'clawproxy.com',
      scope: ['clawproxy:call:openai'],
      policy_hash_b64u: POLICY_HASH,
      payment_account_did: '  did:key:zPaymentAccount  ',
    });

    expect(h1).not.toBe(h2);
    expect(h2).toBe(h3);
  });
});
