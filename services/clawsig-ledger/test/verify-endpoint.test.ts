import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import type { Env } from '../src/types';

interface ExistingRunRow {
  run_id: string;
  status: string;
  proof_tier: string;
  reason_code: string | null;
  failure_class: string | null;
  verification_source: string | null;
  auth_mode: string | null;
}

function toBase64Url(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function sha256B64u(value: string): string {
  return toBase64Url(createHash('sha256').update(value).digest());
}

function computeBundleHash(bundle: Record<string, unknown>): string {
  return sha256B64u(JSON.stringify(bundle));
}

function hasLeadingZeroBits(hash: Buffer, difficulty: number): boolean {
  let remaining = difficulty;
  for (const byte of hash) {
    if (remaining <= 0) return true;

    if (remaining >= 8) {
      if (byte !== 0) return false;
      remaining -= 8;
      continue;
    }

    const mask = 0xff << (8 - remaining);
    return (byte & mask) === 0;
  }

  return remaining <= 0;
}

function findPowNonce(challenge: string, difficulty: number): string {
  for (let i = 0; i < 3_000_000; i++) {
    const nonce = `nonce-${i}`;
    const digest = createHash('sha256').update(`${challenge}:${nonce}`).digest();
    if (hasLeadingZeroBits(digest, difficulty)) {
      return nonce;
    }
  }
  throw new Error('failed to find pow nonce within test budget');
}

interface LedgerDbOptions {
  simulateRaceOnNextInsert?: boolean;
}

function makeLedgerDb(
  existingRuns: Map<string, ExistingRunRow>,
  options: LedgerDbOptions = {}
): D1Database {
  let raceOnNextInsert = options.simulateRaceOnNextInsert === true;

  return {
    prepare: vi.fn((query: string) => ({
      bind: vi.fn((...params: unknown[]) => ({
        first: vi.fn(async () => {
          if (query.includes('FROM runs WHERE bundle_hash_b64u = ?')) {
            return existingRuns.get(String(params[0])) ?? null;
          }
          return null;
        }),
        all: vi.fn(async () => ({ results: [] })),
        run: vi.fn(async () => {
          if (query.includes('INSERT OR IGNORE INTO runs')) {
            const runId = String(params[0] ?? 'run_unknown');
            const bundleHash = String(params[1] ?? 'hash_unknown');
            const proofTier = String(params[3] ?? 'self');
            const status = String(params[4] ?? 'FAIL');
            const reasonCodeRaw = params[5];
            const failureClassRaw = params[6];
            const verificationSourceRaw = params[7];
            const authModeRaw = params[8];

            const asNullableString = (value: unknown): string | null =>
              typeof value === 'string' ? value : null;

            if (raceOnNextInsert) {
              raceOnNextInsert = false;
              if (!existingRuns.has(bundleHash)) {
                existingRuns.set(bundleHash, makeExistingRunRow(runId, {
                  status,
                  proof_tier: proofTier,
                  reason_code: asNullableString(reasonCodeRaw),
                  failure_class: asNullableString(failureClassRaw),
                  verification_source: asNullableString(verificationSourceRaw),
                  auth_mode: asNullableString(authModeRaw),
                }));
              }
              return { meta: { changes: 0 } };
            }

            if (existingRuns.has(bundleHash)) {
              return { meta: { changes: 0 } };
            }

            existingRuns.set(bundleHash, makeExistingRunRow(runId, {
              status,
              proof_tier: proofTier,
              reason_code: asNullableString(reasonCodeRaw),
              failure_class: asNullableString(failureClassRaw),
              verification_source: asNullableString(verificationSourceRaw),
              auth_mode: asNullableString(authModeRaw),
            }));

            return { meta: { changes: 1 } };
          }

          if (query.includes('INSERT INTO agents')) {
            return { meta: { changes: 1 } };
          }

          return { meta: { changes: 0 } };
        }),
      })),
    })),
  } as unknown as D1Database;
}

function makeExistingRunRow(
  runId: string,
  overrides: Partial<ExistingRunRow> = {}
): ExistingRunRow {
  return {
    run_id: runId,
    status: 'PASS',
    proof_tier: 'gateway',
    reason_code: 'OK',
    failure_class: 'none',
    verification_source: 'clawverify_api',
    auth_mode: 'api_key',
    ...overrides,
  };
}

function makeEnv(
  overrides: Partial<Env> = {},
  options: LedgerDbOptions = {},
) {
  const existingRuns = new Map<string, ExistingRunRow>();
  const queueSend = vi.fn().mockResolvedValue(undefined);

  const env: Env = {
    LEDGER_DB: makeLedgerDb(existingRuns, options),
    BUNDLES: {} as R2Bucket,
    LEDGER_QUEUE: {
      send: queueSend,
    } as unknown as Queue,
    SERVICE_VERSION: 'test',
    CLAWLOGS_RT_URL: 'https://clawlogs.test',
    VAAS_API_KEY_HASH: sha256B64u('test-key'),
    VAAS_POW_DIFFICULTY: '8',
    CLAWVERIFY_API_URL: 'https://clawverify.test',
    ...overrides,
  };

  return { env, queueSend, existingRuns };
}

async function callVerify(
  env: Env,
  body: Record<string, unknown>,
  headers: Record<string, string> = {}
) {
  const request = new Request('https://ledger.test/v1/verify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: JSON.stringify(body),
  });

  const ctx = {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;

  return worker.fetch(request, env, ctx);
}

function stubUpstreamVerifyValid() {
  const upstreamFetch = vi.fn().mockImplementation(() =>
    Promise.resolve(
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
    )
  );

  vi.stubGlobal('fetch', upstreamFetch as unknown as typeof fetch);
  return upstreamFetch;
}

describe('POST /v1/verify', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('maps upstream VALID to PASS response', async () => {
    const upstreamFetch = stubUpstreamVerifyValid();

    const { env } = makeEnv();
    const response = await callVerify(
      env,
      {
        proof_bundle: { payload: { run_id: 'run_123' } },
        publish_to_ledger: false,
      },
      { 'X-API-Key': 'test-key' }
    );

    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(payload.status).toBe('PASS');
    expect(payload.tier).toBe('gateway');
    expect(payload.reason_code).toBe('OK');
    expect(payload.failure_class).toBe('none');
    expect(payload.verification_source).toBe('clawverify_api');
    expect(payload.auth_mode).toBe('api_key');

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

    const { env } = makeEnv();
    const response = await callVerify(
      env,
      {
        proof_bundle: { payload: { run_id: 'run_123' } },
        publish_to_ledger: false,
      },
      { 'X-API-Key': 'test-key' }
    );

    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(422);
    expect(payload.status).toBe('FAIL');
    expect(payload.reason_code).toBe('HASH_MISMATCH');
  });

  it('queues verdict diagnostics for persisted runs', async () => {
    const upstreamFetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          result: {
            status: 'INVALID',
            proof_tier: 'self',
            agent_did: 'did:key:zInvalidAgent',
          },
          error: {
            code: 'HASH_MISMATCH',
          },
        }),
        { status: 422, headers: { 'Content-Type': 'application/json' } }
      )
    );

    vi.stubGlobal('fetch', upstreamFetch as unknown as typeof fetch);

    const { env, queueSend } = makeEnv();
    const response = await callVerify(
      env,
      {
        proof_bundle: { payload: { run_id: 'run_invalid' } },
      },
      { 'X-API-Key': 'test-key' }
    );

    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(422);
    expect(payload.reason_code).toBe('HASH_MISMATCH');
    expect(payload.failure_class).toBe('none');
    expect(payload.verification_source).toBe('clawverify_api');
    expect(payload.auth_mode).toBe('api_key');

    expect(queueSend).toHaveBeenCalledTimes(1);
    expect(queueSend.mock.calls[0]?.[0]).toMatchObject({
      status: 'FAIL',
      reason_code: 'HASH_MISMATCH',
      failure_class: 'none',
      verification_source: 'clawverify_api',
      auth_mode: 'api_key',
    });
  });

  it('fails closed with 503 when verifier is unavailable', async () => {
    const upstreamFetch = vi
      .fn()
      .mockRejectedValue(new Error('network unreachable'));

    vi.stubGlobal('fetch', upstreamFetch as unknown as typeof fetch);

    const { env } = makeEnv();
    const response = await callVerify(
      env,
      {
        proof_bundle: { payload: { run_id: 'run_123' } },
        publish_to_ledger: false,
      },
      { 'X-API-Key': 'test-key' }
    );

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

    const { env } = makeEnv();
    const response = await callVerify(
      env,
      {
        proof_bundle: { payload: { run_id: 'run_123' } },
        publish_to_ledger: false,
      },
      { 'X-API-Key': 'test-key' }
    );

    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(503);
    expect(payload.status).toBe('FAIL');
    expect(payload.reason_code).toBe('VERIFIER_MALFORMED_RESPONSE');
  });

  it('rejects invalid API key with deterministic 401', async () => {
    const upstreamFetch = stubUpstreamVerifyValid();

    const { env } = makeEnv();
    const response = await callVerify(
      env,
      {
        proof_bundle: { payload: { run_id: 'run_unauthorized' } },
      },
      { 'X-API-Key': 'wrong-key' }
    );

    const payload = (await response.json()) as {
      error?: { code?: string };
    };

    expect(response.status).toBe(401);
    expect(payload.error?.code).toBe('UNAUTHORIZED');
    expect(upstreamFetch).toHaveBeenCalledTimes(0);
  });

  it('rejects unauthenticated request without PoW', async () => {
    const upstreamFetch = stubUpstreamVerifyValid();

    const { env } = makeEnv();
    const response = await callVerify(env, {
      proof_bundle: { payload: { run_id: 'run_pow_required' } },
    });

    const payload = (await response.json()) as {
      error?: { code?: string };
    };

    expect(response.status).toBe(401);
    expect(payload.error?.code).toBe('POW_REQUIRED');
    expect(response.headers.get('X-Hashcash-Challenge')).toBeTruthy();
    expect(response.headers.get('X-Hashcash-Difficulty')).toBe('8');
    expect(upstreamFetch).toHaveBeenCalledTimes(0);
  });

  it('accepts unauthenticated request with valid PoW nonce', async () => {
    const upstreamFetch = stubUpstreamVerifyValid();

    const { env, queueSend } = makeEnv();
    const body = {
      proof_bundle: { payload: { run_id: 'run_pow_ok' } },
    };

    const challengeResponse = await callVerify(env, body);
    const challenge = challengeResponse.headers.get('X-Hashcash-Challenge');
    const difficultyRaw = challengeResponse.headers.get('X-Hashcash-Difficulty');

    expect(challengeResponse.status).toBe(401);
    expect(challenge).toBeTruthy();
    expect(difficultyRaw).toBe('8');

    const nonce = findPowNonce(challenge ?? '', Number(difficultyRaw));

    const response = await callVerify(env, body, {
      'X-Hashcash-Nonce': nonce,
    });

    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(payload.status).toBe('PASS');
    expect(upstreamFetch).toHaveBeenCalledTimes(1);
    expect(queueSend).toHaveBeenCalledTimes(1);
  });

  it('returns existing run_id for duplicate bundle and avoids duplicate queue send', async () => {
    const upstreamFetch = stubUpstreamVerifyValid();

    const { env, queueSend, existingRuns } = makeEnv();

    const bundle = { payload: { run_id: 'run_dedupe' } };
    const bundleHash = computeBundleHash(bundle);

    const firstResponse = await callVerify(
      env,
      { proof_bundle: bundle },
      { 'X-API-Key': 'test-key' }
    );
    const firstPayload = (await firstResponse.json()) as Record<string, unknown>;
    const firstRunId = String(firstPayload.run_id);

    expect(existingRuns.get(bundleHash)?.run_id).toBe(firstRunId);

    const secondResponse = await callVerify(
      env,
      { proof_bundle: bundle },
      { 'X-API-Key': 'test-key' }
    );
    const secondPayload = (await secondResponse.json()) as Record<string, unknown>;

    expect(secondResponse.status).toBe(200);
    expect(secondPayload.run_id).toBe(firstRunId);
    expect(secondPayload.reason_code).toBe('OK');
    expect(secondPayload.failure_class).toBe('none');
    expect(secondPayload.verification_source).toBe('clawverify_api');
    expect(secondPayload.auth_mode).toBe('api_key');
    expect(queueSend).toHaveBeenCalledTimes(1);
    expect(upstreamFetch).toHaveBeenCalledTimes(1);
  });

  it('handles replay race window by returning deterministic existing run without requeue', async () => {
    const upstreamFetch = stubUpstreamVerifyValid();
    const { env, queueSend } = makeEnv({}, { simulateRaceOnNextInsert: true });

    const bundle = { payload: { run_id: 'run_race_window' } };
    const response = await callVerify(
      env,
      { proof_bundle: bundle },
      { 'X-API-Key': 'test-key' }
    );

    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(String(payload.run_id)).toBe(`run_${computeBundleHash(bundle).slice(0, 24)}`);
    expect(payload.reason_code).toBe('OK');
    expect(queueSend).toHaveBeenCalledTimes(0);
    expect(upstreamFetch).toHaveBeenCalledTimes(1);
  });
});
