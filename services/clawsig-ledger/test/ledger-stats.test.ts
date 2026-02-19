import { describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import type { Env } from '../src/types';

interface StatsFixture {
  baseRow: Record<string, unknown>;
  topFailRows: Array<{ reason_code: string; count: number | string }>;
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
          return null;
        }),
        all: vi.fn(async () => {
          if (query.includes('SELECT reason_code, COUNT(*) AS count')) {
            return { results: fixture.topFailRows };
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

async function callStats(env: Env): Promise<Response> {
  const request = new Request('https://ledger.test/v1/ledger/stats', {
    method: 'GET',
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
  });

  it('returns fail-rate and top reason codes for populated dataset', async () => {
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
  });
});
