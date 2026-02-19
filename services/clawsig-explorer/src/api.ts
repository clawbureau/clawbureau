/**
 * VaaS API client for fetching run/agent/stats data.
 *
 * All fetches include a timeout and return typed data or null on error.
 * Uses Cache API aggressively to keep page renders under 100ms.
 */

import type { RunData } from './pages/run.js';
import type { AgentPassport, AgentRun } from './pages/agent.js';
import type { GlobalStats, RecentRun } from './pages/home.js';

const FETCH_TIMEOUT_MS = 5000;

interface FetchOptions {
  vaasBase: string;
  cache?: Cache;
  cacheTtl?: number;
}

async function fetchJson<T>(
  url: string,
  opts: FetchOptions,
): Promise<T | null> {
  const fullUrl = `${opts.vaasBase}${url}`;

  // Try cache first
  if (opts.cache) {
    const cached = await opts.cache.match(fullUrl);
    if (cached) {
      try {
        return await cached.json() as T;
      } catch {
        // Cache miss / corrupt entry -- fall through to fetch
      }
    }
  }

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const res = await fetch(fullUrl, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });

    clearTimeout(timer);

    if (!res.ok) return null;

    const data = await res.json() as T;

    // Store in cache
    if (opts.cache && data) {
      const ttl = opts.cacheTtl ?? 60;
      const cacheRes = new Response(JSON.stringify(data), {
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': `public, max-age=${ttl}`,
        },
      });
      opts.cache.put(fullUrl, cacheRes).catch(() => {});
    }

    return data;
  } catch {
    return null;
  }
}

function asNumber(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
}

function asString(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

// -- Run data --

interface VaaSRunPayload {
  run_id?: unknown;
  bundle_hash_b64u?: unknown;
  agent_did?: unknown;
  proof_tier?: unknown;
  status?: unknown;
  reason_code?: unknown;
  failure_class?: unknown;
  verification_source?: unknown;
  auth_mode?: unknown;
  wpc_hash_b64u?: unknown;
  rt_leaf_index?: unknown;
  created_at?: unknown;
  models?: Array<{ provider: string; model: string }>;
}

interface VaaSRunResponse extends VaaSRunPayload {
  run?: VaaSRunPayload;
  bundle_url?: unknown;
  receipt_count?: unknown;
  event_count?: unknown;
}

export async function fetchRun(
  runId: string,
  opts: FetchOptions,
): Promise<RunData | null> {
  const data = await fetchJson<VaaSRunResponse>(
    `/v1/ledger/runs/${encodeURIComponent(runId)}`,
    { ...opts, cacheTtl: 300 },
  );
  if (!data) return null;

  const run = data.run ?? data;

  const resolvedRunId = asString(run.run_id);
  const resolvedBundleHash = asString(run.bundle_hash_b64u);
  const resolvedAgentDid = asString(run.agent_did);
  const resolvedProofTier = asString(run.proof_tier);
  const resolvedStatus = asString(run.status);
  const resolvedCreatedAt = asString(run.created_at);

  if (
    !resolvedRunId ||
    !resolvedBundleHash ||
    !resolvedAgentDid ||
    !resolvedProofTier ||
    !resolvedStatus ||
    !resolvedCreatedAt
  ) {
    return null;
  }

  return {
    run_id: resolvedRunId,
    bundle_hash_b64u: resolvedBundleHash,
    agent_did: resolvedAgentDid,
    proof_tier: resolvedProofTier,
    status: resolvedStatus,
    reason_code: asString(run.reason_code),
    failure_class: asString(run.failure_class),
    verification_source: asString(run.verification_source),
    auth_mode: asString(run.auth_mode),
    wpc_hash_b64u: asString(run.wpc_hash_b64u),
    rt_leaf_index: run.rt_leaf_index === null ? null : asNumber(run.rt_leaf_index, 0),
    created_at: resolvedCreatedAt,
    models: Array.isArray(run.models) ? run.models : [],
    bundle_url: asString(data.bundle_url ?? null) ?? undefined,
    receipt_count: asNumber(data.receipt_count, 0),
    event_count: asNumber(data.event_count, 0),
  };
}

// -- Agent data --

interface VaaSAgentRunsResponse {
  runs: Array<{
    run_id: string;
    proof_tier: string;
    status: string;
    created_at: string;
    models?: Array<{ provider: string; model: string }>;
  }>;
  total: number;
  page: number;
  has_next: boolean;
}

export async function fetchAgentPassport(
  did: string,
  opts: FetchOptions,
): Promise<AgentPassport | null> {
  return fetchJson<AgentPassport>(
    `/v1/passports/${encodeURIComponent(did)}`,
    { ...opts, cacheTtl: 120 },
  );
}

export async function fetchAgentRuns(
  did: string,
  page: number,
  opts: FetchOptions,
): Promise<{ runs: AgentRun[]; total: number; page: number; has_next: boolean } | null> {
  const data = await fetchJson<VaaSAgentRunsResponse>(
    `/v1/ledger/agents/${encodeURIComponent(did)}?page=${page}&limit=20`,
    { ...opts, cacheTtl: 60 },
  );
  if (!data) return null;

  return {
    runs: data.runs.map(r => ({
      run_id: r.run_id,
      proof_tier: r.proof_tier,
      status: r.status,
      created_at: r.created_at,
      models: r.models ?? [],
    })),
    total: data.total,
    page: data.page,
    has_next: data.has_next,
  };
}

// -- Global stats --

interface VaaSStatsResponse {
  total_runs?: unknown;
  total_agents?: unknown;
  runs_24h?: unknown;
  fail_runs_24h?: unknown;
  fail_rate_24h?: unknown;
  top_fail_reason_codes?: Array<{
    reason_code?: unknown;
    count?: unknown;
  }>;
  recent_runs?: Array<{
    run_id?: unknown;
    agent_did?: unknown;
    proof_tier?: unknown;
    status?: unknown;
    created_at?: unknown;
  }>;
}

export async function fetchGlobalStats(
  opts: FetchOptions,
): Promise<{ stats: GlobalStats; recent_runs: RecentRun[] } | null> {
  const data = await fetchJson<VaaSStatsResponse>(
    '/v1/ledger/stats',
    { ...opts, cacheTtl: 30 },
  );
  if (!data) return null;

  const runs24h = asNumber(data.runs_24h, 0);
  const failRuns24h = asNumber(data.fail_runs_24h, 0);
  const failRate24hRaw = asNumber(data.fail_rate_24h, NaN);
  const failRate24h = Number.isFinite(failRate24hRaw)
    ? failRate24hRaw
    : (runs24h > 0 ? failRuns24h / runs24h : 0);

  const topFailReasonCodes = Array.isArray(data.top_fail_reason_codes)
    ? data.top_fail_reason_codes
      .map((row) => {
        const reasonCode = asString(row.reason_code);
        if (!reasonCode) return null;
        return {
          reason_code: reasonCode,
          count: asNumber(row.count, 0),
        };
      })
      .filter((row): row is { reason_code: string; count: number } => row !== null)
    : [];

  const recentRuns = Array.isArray(data.recent_runs)
    ? data.recent_runs
      .map((run) => {
        const runId = asString(run.run_id);
        const agentDid = asString(run.agent_did);
        const proofTier = asString(run.proof_tier);
        const status = asString(run.status);
        const createdAt = asString(run.created_at);

        if (!runId || !agentDid || !proofTier || !status || !createdAt) {
          return null;
        }

        return {
          run_id: runId,
          agent_did: agentDid,
          proof_tier: proofTier,
          status,
          created_at: createdAt,
        };
      })
      .filter((run): run is RecentRun => run !== null)
      .slice(0, 20)
    : [];

  return {
    stats: {
      total_runs: asNumber(data.total_runs, 0),
      total_agents: asNumber(data.total_agents, 0),
      runs_24h: runs24h,
      fail_runs_24h: failRuns24h,
      fail_rate_24h: failRate24h,
      top_fail_reason_codes: topFailReasonCodes,
    },
    recent_runs: recentRuns,
  };
}
