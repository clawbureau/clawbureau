import { afterEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import type { Env } from '../src/types';

function makeEnv(overrides: Partial<Env> = {}): Env {
  return {
    LEDGER_DB: {} as D1Database,
    BUNDLES: {} as R2Bucket,
    LEDGER_QUEUE: {
      send: vi.fn().mockResolvedValue(undefined),
    } as unknown as Queue,
    SERVICE_VERSION: 'test',
    CLAWLOGS_RT_URL: 'https://clawlogs.test',
    VAAS_API_KEY_HASH: 'test-hash',
    CLAWVERIFY_API_URL: 'https://clawverify.test',
    ...overrides,
  };
}

async function callVerify(env: Env, body: Record<string, unknown>) {
  const request = new Request('https://ledger.test/v1/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': 'test-key',
    },
    body: JSON.stringify(body),
  });

  const ctx = {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;

  return worker.fetch(request, env, ctx);
}

describe('POST /v1/verify', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('maps upstream VALID to PASS response', async () => {
    const upstreamFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          result: {
            status: 'VALID',
            proof_tier: 'gateway',
            agent_did: 'did:key:zValidAgent',
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    vi.stubGlobal('fetch', upstreamFetch as unknown as typeof fetch);

    const env = makeEnv();
    const response = await callVerify(env, {
      proof_bundle: { payload: { run_id: 'run_123' } },
      publish_to_ledger: false,
    });

    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(payload.status).toBe('PASS');
    expect(payload.tier).toBe('gateway');
    expect(payload.reason_code).toBe('OK');

    expect(upstreamFetch).toHaveBeenCalledTimes(1);
    expect(upstreamFetch.mock.calls[0]?.[0]).toBe(
      'https://clawverify.test/v1/verify/bundle'
    );
  });

  it('maps upstream INVALID to deterministic FAIL (422)', async () => {
    const upstreamFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          result: {
            status: 'INVALID',
            proof_tier: 'self',
          },
          error: {
            code: 'HASH_MISMATCH',
          },
        }),
        { status: 422, headers: { 'Content-Type': 'application/json' } }
      )
    );

    vi.stubGlobal('fetch', upstreamFetch as unknown as typeof fetch);

    const env = makeEnv();
    const response = await callVerify(env, {
      proof_bundle: { payload: { run_id: 'run_123' } },
      publish_to_ledger: false,
    });

    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(422);
    expect(payload.status).toBe('FAIL');
    expect(payload.reason_code).toBe('HASH_MISMATCH');
  });

  it('fails closed with 503 when verifier is unavailable', async () => {
    const upstreamFetch = vi
      .fn()
      .mockRejectedValue(new Error('network unreachable'));

    vi.stubGlobal('fetch', upstreamFetch as unknown as typeof fetch);

    const env = makeEnv();
    const response = await callVerify(env, {
      proof_bundle: { payload: { run_id: 'run_123' } },
      publish_to_ledger: false,
    });

    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(503);
    expect(payload.status).toBe('FAIL');
    expect(payload.reason_code).toBe('VERIFIER_UNAVAILABLE');
  });

  it('fails closed with 503 when verifier response is malformed', async () => {
    const upstreamFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ok: true,
          status: 'MAYBE',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    );

    vi.stubGlobal('fetch', upstreamFetch as unknown as typeof fetch);

    const env = makeEnv();
    const response = await callVerify(env, {
      proof_bundle: { payload: { run_id: 'run_123' } },
      publish_to_ledger: false,
    });

    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(503);
    expect(payload.status).toBe('FAIL');
    expect(payload.reason_code).toBe('VERIFIER_MALFORMED_RESPONSE');
  });
});
