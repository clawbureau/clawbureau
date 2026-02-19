import { describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import type { Env, RunRow } from '../src/types';

interface AgentFixture {
  did: string;
  first_seen_at: string;
  verified_runs: number;
  gateway_tier_runs: number;
  policy_violations: number;
}

interface Fixture {
  runs: RunRow[];
  agents: AgentFixture[];
}

function sortRuns(rows: RunRow[]): RunRow[] {
  return [...rows].sort((a, b) => {
    if (a.created_at === b.created_at) {
      return b.run_id.localeCompare(a.run_id);
    }
    return b.created_at.localeCompare(a.created_at);
  });
}

function applyRunsFeedQuery(query: string, params: unknown[], allRuns: RunRow[]): RunRow[] {
  let idx = 0;
  let rows = sortRuns(allRuns);

  if (query.includes('status = ?')) {
    const status = String(params[idx++] ?? '');
    rows = rows.filter((row) => row.status === status);
  }

  if (query.includes('proof_tier = ?')) {
    const tier = String(params[idx++] ?? '');
    rows = rows.filter((row) => row.proof_tier === tier);
  }

  if (query.includes('reason_code = ?')) {
    const reasonCode = String(params[idx++] ?? '');
    rows = rows.filter((row) => (row.reason_code ?? '') === reasonCode);
  }

  if (query.includes('agent_did = ?')) {
    const agentDid = String(params[idx++] ?? '');
    rows = rows.filter((row) => row.agent_did === agentDid);
  }

  if (query.includes('(created_at < ? OR (created_at = ? AND run_id < ?))')) {
    const cursorCreatedAt = String(params[idx++] ?? '');
    idx += 1; // repeated created_at bind
    const cursorRunId = String(params[idx++] ?? '');

    rows = rows.filter((row) => {
      if (row.created_at < cursorCreatedAt) return true;
      if (row.created_at === cursorCreatedAt && row.run_id < cursorRunId) return true;
      return false;
    });
  }

  const limit = Number(params[idx] ?? rows.length);
  return rows.slice(0, Number.isFinite(limit) ? limit : rows.length);
}

function makeLedgerDb(fixture: Fixture): D1Database {
  return {
    prepare: vi.fn((query: string) => {
      const statement = {
        bind: vi.fn((...params: unknown[]) => {
          const bound = {
            first: vi.fn(async () => {
              if (query.includes('SELECT * FROM agents WHERE did = ?')) {
                const did = String(params[0] ?? '');
                return fixture.agents.find((agent) => agent.did === did) ?? null;
              }

              if (query.includes('SELECT COUNT(*) AS total FROM runs WHERE agent_did = ?')) {
                const did = String(params[0] ?? '');
                const total = fixture.runs.filter((row) => row.agent_did === did).length;
                return { total };
              }

              return null;
            }),
            all: vi.fn(async () => {
              if (
                query.includes('FROM runs') &&
                query.includes('ORDER BY created_at DESC, run_id DESC') &&
                query.includes('LIMIT ? OFFSET ?')
              ) {
                const did = String(params[0] ?? '');
                const limit = Number(params[1] ?? 50);
                const offset = Number(params[2] ?? 0);
                const rows = sortRuns(fixture.runs)
                  .filter((row) => row.agent_did === did)
                  .slice(offset, offset + limit);
                return { results: rows };
              }

              if (
                query.includes('FROM runs') &&
                query.includes('ORDER BY created_at DESC, run_id DESC') &&
                query.includes('LIMIT ?') &&
                !query.includes('LIMIT ? OFFSET ?')
              ) {
                return { results: applyRunsFeedQuery(query, params, fixture.runs) };
              }

              return { results: [] };
            }),
            run: vi.fn(async () => ({})),
          };
          return bound;
        }),
      };

      return statement;
    }),
  } as unknown as D1Database;
}

function makeEnv(fixture: Fixture): Env {
  return {
    LEDGER_DB: makeLedgerDb(fixture),
    BUNDLES: {} as R2Bucket,
    LEDGER_QUEUE: { send: vi.fn().mockResolvedValue(undefined) } as unknown as Queue,
    SERVICE_VERSION: 'test',
    CLAWLOGS_RT_URL: 'https://clawlogs.test',
  };
}

async function call(path: string, env: Env): Promise<Response> {
  const request = new Request(`https://ledger.test${path}`, { method: 'GET' });
  const ctx = {
    waitUntil: vi.fn(),
    passThroughOnException: vi.fn(),
  } as unknown as ExecutionContext;
  return worker.fetch(request, env, ctx);
}

function makeRun(overrides: Partial<RunRow>): RunRow {
  return {
    run_id: 'run_default',
    bundle_hash_b64u: 'hash_default',
    agent_did: 'did:key:agent-default',
    proof_tier: 'gateway',
    status: 'PASS',
    reason_code: 'OK',
    failure_class: 'none',
    verification_source: 'clawverify_api',
    auth_mode: 'api_key',
    wpc_hash_b64u: null,
    rt_leaf_index: null,
    models_json: null,
    created_at: '2026-02-19 10:00:00',
    ...overrides,
  };
}

describe('ledger runs feed + agent contract alignment', () => {
  it('returns empty runs feed deterministically', async () => {
    const env = makeEnv({ runs: [], agents: [] });

    const response = await call('/v1/ledger/runs?limit=10', env);
    const payload = (await response.json()) as {
      runs: unknown[];
      limit: number;
      has_next: boolean;
      next_cursor: string | null;
      filters_echo: Record<string, unknown>;
    };

    expect(response.status).toBe(200);
    expect(payload.runs).toEqual([]);
    expect(payload.limit).toBe(10);
    expect(payload.has_next).toBe(false);
    expect(payload.next_cursor).toBeNull();
    expect(payload.filters_echo).toEqual({});
  });

  it('supports pagination via cursor and newest-first ordering', async () => {
    const runs = [
      makeRun({ run_id: 'run_c', created_at: '2026-02-19 10:03:00', bundle_hash_b64u: 'hash_c' }),
      makeRun({ run_id: 'run_b', created_at: '2026-02-19 10:02:00', bundle_hash_b64u: 'hash_b' }),
      makeRun({ run_id: 'run_a', created_at: '2026-02-19 10:01:00', bundle_hash_b64u: 'hash_a' }),
    ];

    const env = makeEnv({ runs, agents: [] });

    const page1Res = await call('/v1/ledger/runs?limit=2', env);
    const page1 = (await page1Res.json()) as {
      runs: RunRow[];
      has_next: boolean;
      next_cursor: string | null;
    };

    expect(page1Res.status).toBe(200);
    expect(page1.runs.map((r) => r.run_id)).toEqual(['run_c', 'run_b']);
    expect(page1.has_next).toBe(true);
    expect(page1.next_cursor).toBeTruthy();

    const page2Res = await call(
      `/v1/ledger/runs?limit=2&cursor=${encodeURIComponent(page1.next_cursor ?? '')}`,
      env,
    );
    const page2 = (await page2Res.json()) as {
      runs: RunRow[];
      has_next: boolean;
      next_cursor: string | null;
    };

    expect(page2Res.status).toBe(200);
    expect(page2.runs.map((r) => r.run_id)).toEqual(['run_a']);
    expect(page2.has_next).toBe(false);
    expect(page2.next_cursor).toBeNull();
  });

  it('supports status/tier/reason/agent filters', async () => {
    const runs = [
      makeRun({
        run_id: 'run_match',
        bundle_hash_b64u: 'hash_match',
        agent_did: 'did:key:agent-1',
        status: 'FAIL',
        proof_tier: 'gateway',
        reason_code: 'HASH_MISMATCH',
      }),
      makeRun({
        run_id: 'run_other_status',
        bundle_hash_b64u: 'hash_other_status',
        agent_did: 'did:key:agent-1',
        status: 'PASS',
        proof_tier: 'gateway',
        reason_code: 'OK',
      }),
      makeRun({
        run_id: 'run_other_reason',
        bundle_hash_b64u: 'hash_other_reason',
        agent_did: 'did:key:agent-2',
        status: 'FAIL',
        proof_tier: 'self',
        reason_code: 'POW_INVALID',
      }),
    ];

    const env = makeEnv({ runs, agents: [] });

    const response = await call(
      '/v1/ledger/runs?status=FAIL&tier=gateway&reason_code=HASH_MISMATCH&agent_did=did:key:agent-1&limit=10',
      env,
    );

    const payload = (await response.json()) as {
      runs: RunRow[];
      filters_echo: {
        status?: string;
        tier?: string;
        reason_code?: string;
        agent_did?: string;
      };
    };

    expect(response.status).toBe(200);
    expect(payload.runs).toHaveLength(1);
    expect(payload.runs[0]?.run_id).toBe('run_match');
    expect(payload.filters_echo).toEqual({
      status: 'FAIL',
      tier: 'gateway',
      reason_code: 'HASH_MISMATCH',
      agent_did: 'did:key:agent-1',
    });
  });

  it('aligns /v1/ledger/agents/:did contract with deterministic runs payload', async () => {
    const runs = [
      makeRun({ run_id: 'run_3', bundle_hash_b64u: 'hash_3', agent_did: 'did:key:agent-1', created_at: '2026-02-19 10:03:00' }),
      makeRun({ run_id: 'run_2', bundle_hash_b64u: 'hash_2', agent_did: 'did:key:agent-1', created_at: '2026-02-19 10:02:00' }),
      makeRun({ run_id: 'run_1', bundle_hash_b64u: 'hash_1', agent_did: 'did:key:agent-1', created_at: '2026-02-19 10:01:00' }),
      makeRun({ run_id: 'run_other', bundle_hash_b64u: 'hash_other', agent_did: 'did:key:agent-2', created_at: '2026-02-19 10:04:00' }),
    ];

    const agents: AgentFixture[] = [
      {
        did: 'did:key:agent-1',
        first_seen_at: '2026-02-01 00:00:00',
        verified_runs: 3,
        gateway_tier_runs: 2,
        policy_violations: 1,
      },
    ];

    const env = makeEnv({ runs, agents });

    const response = await call('/v1/ledger/agents/did%3Akey%3Aagent-1?page=1&limit=2', env);
    const payload = (await response.json()) as {
      runs: RunRow[];
      recent_runs: RunRow[];
      total: number;
      page: number;
      page_size: number;
      has_next: boolean;
    };

    expect(response.status).toBe(200);
    expect(payload.runs.map((row) => row.run_id)).toEqual(['run_3', 'run_2']);
    expect(payload.recent_runs.map((row) => row.run_id)).toEqual(['run_3', 'run_2']);
    expect(payload.total).toBe(3);
    expect(payload.page).toBe(1);
    expect(payload.page_size).toBe(2);
    expect(payload.has_next).toBe(true);
  });

  it('returns deterministic 400s for invalid query parameters', async () => {
    const env = makeEnv({ runs: [], agents: [] });

    const badCases = [
      { path: '/v1/ledger/runs?limit=0', code: 'INVALID_LIMIT' },
      { path: '/v1/ledger/runs?status=MAYBE', code: 'INVALID_STATUS_FILTER' },
      { path: '/v1/ledger/runs?tier=super', code: 'INVALID_TIER_FILTER' },
      { path: '/v1/ledger/runs?reason_code=bad-code!', code: 'INVALID_REASON_CODE_FILTER' },
      { path: '/v1/ledger/runs?agent_did=not-a-did', code: 'INVALID_AGENT_DID_FILTER' },
      { path: '/v1/ledger/runs?cursor=invalidcursor', code: 'INVALID_CURSOR' },
    ] as const;

    for (const badCase of badCases) {
      const response = await call(badCase.path, env);
      const payload = (await response.json()) as {
        error: { code: string; message: string };
      };

      expect(response.status).toBe(400);
      expect(payload.error.code).toBe(badCase.code);
      expect(payload.error.message.length).toBeGreaterThan(0);
    }
  });
});
