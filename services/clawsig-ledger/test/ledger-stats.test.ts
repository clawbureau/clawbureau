import { describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import type { Env } from '../src/types';

interface StatsFixture {
  baseRow: Record<string, unknown>;
  topFailRows: Array<{ reason_code: string; count: number | string }>;
  diagnostics7dBase: Record<string, unknown>;
  topFailRows7d: Array<{ reason_code: string; count: number | string }>;
  dailyDiagnostics7d: Array<{ day: string; runs: number | string; fail_runs: number | string }>;
  recentRuns: Array<{
    run_id: string;
    agent_did: string;
    proof_tier: string;
    status: string;
    created_at: string;
  }>;
}

function makeLedgerDb(fixture: StatsFixture): D1Database {
  return {
    prepare: vi.fn((query: string) => {
      const statement = {
        bind: vi.fn(() => statement),
        first: vi.fn(async () => {
          if (query.includes('AS total_agents') && query.includes('AS fail_runs_24h')) {
            return fixture.baseRow;
          }

          if (query.includes('AS runs_7d') && query.includes('AS fail_runs_7d')) {
            return fixture.diagnostics7dBase;
          }

          return null;
        }),
        all: vi.fn(async () => {
          if (query.includes("created_at >= datetime('now', '-24 hours')")) {
            return { results: fixture.topFailRows };
          }

          if (query.includes("created_at >= datetime('now', '-7 days')") && query.includes('LIMIT 10')) {
            return { results: fixture.topFailRows7d };
          }

          if (query.includes('GROUP BY date(created_at)')) {
            return { results: fixture.dailyDiagnostics7d };
          }

          if (query.includes('SELECT run_id, agent_did, proof_tier, status, created_at')) {
            return { results: fixture.recentRuns };
          }

          return { results: [] };
        }),
        run: vi.fn(async () => ({})),
      };
      return statement;
    }),
  } as unknown as D1Database;
}

function makeEnv(fixture: StatsFixture): Env {
  return {
    LEDGER_DB: makeLedgerDb(fixture),
    BUNDLES: {} as R2Bucket,
    LEDGER_QUEUE: { send: vi.fn().mockResolvedValue(undefined) } as unknown as Queue,
    SERVICE_VERSION: 'test',
    CLAWLOGS_RT_URL: 'https://clawlogs.test',
  };
}

async function callStats(env: Env, path = '/v1/ledger/stats', init?: RequestInit): Promise<Response> {
  const request = new Request(`https://ledger.test${path}`, {
    method: 'GET',
    ...init,
  });

  const ctx = {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;

  return worker.fetch(request, env, ctx);
}

describe('GET /v1/ledger/stats', () => {
  it('returns deterministic zeros and empty reason-code list when dataset is empty', async () => {
    const env = makeEnv({
      baseRow: {
        total_agents: 0,
        total_runs: 0,
        total_gateway_runs: 0,
        total_violations: 0,
        runs_24h: 0,
        fail_runs_24h: 0,
      },
      topFailRows: [],
      diagnostics7dBase: {
        runs_7d: 0,
        fail_runs_7d: 0,
      },
      topFailRows7d: [],
      dailyDiagnostics7d: [],
      recentRuns: [],
    });

    const response = await callStats(env);
    const payload = (await response.json()) as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(payload.total_agents).toBe(0);
    expect(payload.total_runs).toBe(0);
    expect(payload.fail_runs_24h).toBe(0);
    expect(payload.fail_rate_24h).toBe(0);
    expect(payload.top_fail_reason_codes).toEqual([]);
    expect(payload.recent_runs).toEqual([]);
    expect(payload.diagnostics_7d).toEqual({
      runs_7d: 0,
      fail_runs_7d: 0,
      fail_rate_7d: 0,
      top_fail_reason_codes_7d: [],
      daily: [],
    });
  });

  it('returns fail-rate and diagnostics for populated dataset', async () => {
    const env = makeEnv({
      baseRow: {
        total_agents: 12,
        total_runs: 100,
        total_gateway_runs: 60,
        total_violations: 19,
        runs_24h: 40,
        fail_runs_24h: 10,
      },
      topFailRows: [
        { reason_code: 'HASH_MISMATCH', count: 6 },
        { reason_code: 'POW_INVALID', count: '3' },
        { reason_code: 'VERIFIER_UNAVAILABLE', count: 1 },
      ],
      diagnostics7dBase: {
        runs_7d: 140,
        fail_runs_7d: 21,
      },
      topFailRows7d: [
        { reason_code: 'HASH_MISMATCH', count: 12 },
        { reason_code: 'POW_INVALID', count: 6 },
      ],
      dailyDiagnostics7d: [
        { day: '2026-02-13', runs: 20, fail_runs: 4 },
        { day: '2026-02-14', runs: 30, fail_runs: 3 },
      ],
      recentRuns: [
        {
          run_id: 'run_latest',
          agent_did: 'did:key:agent-1',
          proof_tier: 'gateway',
          status: 'FAIL',
          created_at: '2026-02-19 11:00:00',
        },
      ],
    });

    const response = await callStats(env);
    const payload = (await response.json()) as {
      total_agents: number;
      total_runs: number;
      total_gateway_runs: number;
      total_violations: number;
      runs_24h: number;
      fail_runs_24h: number;
      fail_rate_24h: number;
      top_fail_reason_codes: Array<{ reason_code: string; count: number }>;
      recent_runs: Array<{
        run_id: string;
        agent_did: string;
        proof_tier: string;
        status: string;
        created_at: string;
      }>;
      diagnostics_7d: {
        runs_7d: number;
        fail_runs_7d: number;
        fail_rate_7d: number;
        top_fail_reason_codes_7d: Array<{ reason_code: string; count: number }>;
        daily: Array<{ day: string; runs: number; fail_runs: number; fail_rate: number }>;
      };
    };

    expect(response.status).toBe(200);
    expect(payload.total_agents).toBe(12);
    expect(payload.total_runs).toBe(100);
    expect(payload.total_gateway_runs).toBe(60);
    expect(payload.total_violations).toBe(19);
    expect(payload.runs_24h).toBe(40);
    expect(payload.fail_runs_24h).toBe(10);
    expect(payload.fail_rate_24h).toBe(0.25);
    expect(payload.top_fail_reason_codes).toEqual([
      { reason_code: 'HASH_MISMATCH', count: 6 },
      { reason_code: 'POW_INVALID', count: 3 },
      { reason_code: 'VERIFIER_UNAVAILABLE', count: 1 },
    ]);
    expect(payload.recent_runs).toEqual([
      {
        run_id: 'run_latest',
        agent_did: 'did:key:agent-1',
        proof_tier: 'gateway',
        status: 'FAIL',
        created_at: '2026-02-19 11:00:00',
      },
    ]);
    expect(payload.diagnostics_7d).toEqual({
      runs_7d: 140,
      fail_runs_7d: 21,
      fail_rate_7d: 0.15,
      top_fail_reason_codes_7d: [
        { reason_code: 'HASH_MISMATCH', count: 12 },
        { reason_code: 'POW_INVALID', count: 6 },
      ],
      daily: [
        { day: '2026-02-13', runs: 20, fail_runs: 4, fail_rate: 0.2 },
        { day: '2026-02-14', runs: 30, fail_runs: 3, fail_rate: 0.1 },
      ],
    });
  });

  it('returns cache headers and 304 for matching etag on stats endpoint', async () => {
    const env = makeEnv({
      baseRow: {
        total_agents: 0,
        total_runs: 0,
        total_gateway_runs: 0,
        total_violations: 0,
        runs_24h: 0,
        fail_runs_24h: 0,
      },
      topFailRows: [],
      diagnostics7dBase: { runs_7d: 0, fail_runs_7d: 0 },
      topFailRows7d: [],
      dailyDiagnostics7d: [],
      recentRuns: [],
    });

    const response = await callStats(env);
    const etag = response.headers.get('etag');
    const cacheControl = response.headers.get('cache-control');

    expect(response.status).toBe(200);
    expect(etag).toBeTruthy();
    expect(cacheControl).toContain('max-age=15');

    const notModified = await callStats(env, '/v1/ledger/stats', {
      headers: { 'If-None-Match': String(etag) },
    });

    expect(notModified.status).toBe(304);
  });

  it('rejects unsupported or abusive stats query strings deterministically', async () => {
    const env = makeEnv({
      baseRow: {
        total_agents: 0,
        total_runs: 0,
        total_gateway_runs: 0,
        total_violations: 0,
        runs_24h: 0,
        fail_runs_24h: 0,
      },
      topFailRows: [],
      diagnostics7dBase: { runs_7d: 0, fail_runs_7d: 0 },
      topFailRows7d: [],
      dailyDiagnostics7d: [],
      recentRuns: [],
    });

    const unsupported = await callStats(env, '/v1/ledger/stats?foo=bar');
    const unsupportedPayload = (await unsupported.json()) as { error: { code: string } };
    expect(unsupported.status).toBe(400);
    expect(unsupportedPayload.error.code).toBe('UNSUPPORTED_QUERY_PARAMETER');

    const abusive = await callStats(env, `/v1/ledger/stats?${'x='.concat('y'.repeat(1400))}`);
    const abusivePayload = (await abusive.json()) as { error: { code: string } };
    expect(abusive.status).toBe(414);
    expect(abusivePayload.error.code).toBe('QUERY_TOO_LONG');
  });
});
