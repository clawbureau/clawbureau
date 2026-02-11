import { describe, expect, it } from 'vitest';

import { WpcRegistryDurableObject } from '../src/wpc-registry-do';

class MockStorage {
  private readonly map = new Map<string, unknown>();

  async get(key: string): Promise<unknown> {
    return this.map.get(key);
  }

  async put(key: string, value: unknown, _opts?: unknown): Promise<void> {
    this.map.set(key, value);
  }
}

function b64u(bytes: Uint8Array): string {
  const b64 = Buffer.from(bytes).toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function makeEnv(overrides: Record<string, unknown> = {}) {
  // Random-but-stable signing key for this test run.
  const seed = crypto.getRandomValues(new Uint8Array(32));

  return {
    SERVICE_VERSION: '0.1.0-test',
    CONTROLS_SIGNING_KEY: b64u(seed),
    ...overrides,
  };
}

function makeDo(storage: MockStorage, env: any): WpcRegistryDurableObject {
  const state: any = {
    storage,
    blockConcurrencyWhile: async (fn: () => Promise<Response>) => fn(),
  };

  return new WpcRegistryDurableObject(state as any, env);
}

function post(url: string, body: unknown): Request {
  return new Request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('CCO-US-021: WPC registry DO', () => {
  it('computes deterministic policy hash via JCS and is idempotent', async () => {
    const storage = new MockStorage();
    const env = makeEnv();
    const ido = makeDo(storage, env);

    const wpcA = {
      policy_version: '1',
      policy_id: 'pol_example',
      issuer_did: 'did:key:zExample',
      allowed_providers: ['openai'],
      allowed_models: ['gpt-5.*'],
      minimum_model_identity_tier: 'closed_opaque',
      required_audit_packs: ['packHASHb64u_12345678'],
      redaction_rules: [{ path: '$.messages[*].content', action: 'hash' }],
      receipt_privacy_mode: 'hash_only',
      egress_allowlist: [],
    };

    // Same fields, different insertion order.
    const wpcB = {
      issuer_did: 'did:key:zExample',
      policy_id: 'pol_example',
      policy_version: '1',
      allowed_models: ['gpt-5.*'],
      allowed_providers: ['openai'],
      required_audit_packs: ['packHASHb64u_12345678'],
      minimum_model_identity_tier: 'closed_opaque',
      receipt_privacy_mode: 'hash_only',
      egress_allowlist: [],
      redaction_rules: [{ action: 'hash', path: '$.messages[*].content' }],
    };

    const r1 = await ido.fetch(post('https://wpc.test/v1/wpc', { wpc: wpcA }));
    expect(r1.status).toBe(201);
    const j1 = await r1.json();
    expect(j1.ok).toBe(true);
    expect(typeof j1.policy_hash_b64u).toBe('string');
    expect(j1.envelope?.payload_hash_b64u).toBe(j1.policy_hash_b64u);

    const firstIssuedAt = j1.envelope.issued_at;

    // Second create returns the stored envelope (no new issued_at).
    const r2 = await ido.fetch(post('https://wpc.test/v1/wpc', { wpc: wpcB }));
    expect(r2.status).toBe(200);
    const j2 = await r2.json();
    expect(j2.ok).toBe(true);
    expect(j2.policy_hash_b64u).toBe(j1.policy_hash_b64u);
    expect(j2.envelope.issued_at).toBe(firstIssuedAt);

    // Fetch by hash.
    const r3 = await ido.fetch(new Request(`https://wpc.test/v1/wpc/${encodeURIComponent(j1.policy_hash_b64u)}`));
    expect(r3.status).toBe(200);
    const j3 = await r3.json();
    expect(j3.ok).toBe(true);
    expect(j3.policy_hash_b64u).toBe(j1.policy_hash_b64u);
    expect(j3.envelope.payload_hash_b64u).toBe(j1.policy_hash_b64u);
  });

  it('rejects unknown keys (strict shape)', async () => {
    const storage = new MockStorage();
    const env = makeEnv();
    const ido = makeDo(storage, env);

    const res = await ido.fetch(
      post('https://wpc.test/v1/wpc', {
        wpc: {
          policy_version: '1',
          policy_id: 'pol_example',
          issuer_did: 'did:key:zExample',
          allowed_providers: ['openai'],
          receipt_privacy_mode: 'hash_only',
          egress_allowlist: [],
          surprise: 'nope',
        },
      }),
    );

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body?.ok).toBe(false);
    expect(body?.error?.code).toBe('INVALID_WPC');
  });
});
