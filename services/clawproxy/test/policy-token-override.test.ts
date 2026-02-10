import { describe, expect, it } from 'vitest';

import type { Env } from '../src/types';
import { CONFIDENTIAL_MODE_HEADER, POLICY_HEADER, extractPolicyFromHeaders, registerDemoPolicy } from '../src/policy';

const env = {
  // not used for demo policy lookup
  PROXY_VERSION: 'test',
  PROXY_RATE_LIMITER: { limit: async () => ({ success: true }) },
  IDEMPOTENCY: {} as any,
} as Env;

describe('extractPolicyFromHeaders (token policy hash override)', () => {
  it('enforces policyHashOverride even when header is absent', async () => {
    const policyHash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; // 43 chars
    registerDemoPolicy(policyHash, {
      policy_version: '1',
      policy_id: 'demo',
      issuer_did: 'did:key:zIssuer',
      allowed_providers: ['openai'],
      allowed_models: ['gpt-*'],
      receipt_privacy_mode: 'hash_only',
    });

    const req = new Request('https://clawproxy.com/v1/proxy/openai', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: '{}',
    });

    const result = await extractPolicyFromHeaders(req, env, { policyHashOverride: policyHash });

    expect(result.error).toBeUndefined();
    expect(result.policyHash).toBe(policyHash);
    expect(result.policy?.policy_id).toBe('demo');
  });

  it('fails closed when X-Policy-Hash mismatches CST policy_hash_b64u', async () => {
    const policyHash = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const other = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

    registerDemoPolicy(policyHash, {
      policy_version: '1',
      policy_id: 'demo',
      issuer_did: 'did:key:zIssuer',
    });

    const req = new Request('https://clawproxy.com/v1/proxy/openai', {
      method: 'POST',
      headers: {
        [POLICY_HEADER]: other,
        'content-type': 'application/json',
      },
      body: '{}',
    });

    const result = await extractPolicyFromHeaders(req, env, { policyHashOverride: policyHash });

    expect(result.errorCode).toBe('POLICY_HASH_MISMATCH');
    expect(result.errorStatus).toBe(403);
  });

  it('does not require X-Policy-Hash in confidential mode when CST policy_hash_b64u is present', async () => {
    const policyHash = 'ccccccccccccccccccccccccccccccccccccccccccc';

    registerDemoPolicy(policyHash, {
      policy_version: '1',
      policy_id: 'demo2',
      issuer_did: 'did:key:zIssuer',
    });

    const req = new Request('https://clawproxy.com/v1/proxy/openai', {
      method: 'POST',
      headers: {
        [CONFIDENTIAL_MODE_HEADER]: 'true',
        'content-type': 'application/json',
      },
      body: '{}',
    });

    const result = await extractPolicyFromHeaders(req, env, { policyHashOverride: policyHash });

    expect(result.error).toBeUndefined();
    expect(result.confidentialMode).toBe(true);
    expect(result.policyHash).toBe(policyHash);
  });
});
