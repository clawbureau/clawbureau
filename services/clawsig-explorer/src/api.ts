/**
 * VaaS API client for fetching run/agent/stats data.
 *
 * All fetches include a timeout and return typed data or null on error.
 * Uses Cache API aggressively to keep page renders under 100ms.
 */

import type { RunData } from "./pages/run.js";
import type { AgentPassport, AgentRun } from "./pages/agent.js";
import type { GlobalStats, RecentRun } from "./pages/home.js";

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
      headers: { "Accept": "application/json" },
    });

    clearTimeout(timer);

    if (!res.ok) return null;

    const data = await res.json() as T;

    // Store in cache
    if (opts.cache && data) {
      const ttl = opts.cacheTtl ?? 60;
      const cacheRes = new Response(JSON.stringify(data), {
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": `public, max-age=${ttl}`,
        },
      });
      opts.cache.put(fullUrl, cacheRes).catch(() => {});
    }

    return data;
  } catch {
    return null;
  }
}

// -- Run data --

interface VaaSRunResponse {
  run_id: string;
  bundle_hash_b64u: string;
  agent_did: string;
  proof_tier: string;
  status: string;
  wpc_hash_b64u: string | null;
  rt_leaf_index: number | null;
  created_at: string;
  models?: Array<{ provider: string; model: string }>;
  bundle_url?: string;
  receipt_count?: number;
  event_count?: number;
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

  return {
    run_id: data.run_id,
    bundle_hash_b64u: data.bundle_hash_b64u,
    agent_did: data.agent_did,
    proof_tier: data.proof_tier,
    status: data.status,
    wpc_hash_b64u: data.wpc_hash_b64u,
    rt_leaf_index: data.rt_leaf_index,
    created_at: data.created_at,
    models: data.models ?? [],
    bundle_url: data.bundle_url,
    receipt_count: data.receipt_count,
    event_count: data.event_count,
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
  total_runs: number;
  total_agents: number;
  runs_24h: number;
  recent_runs?: Array<{
    run_id: string;
    agent_did: string;
    proof_tier: string;
    status: string;
    created_at: string;
  }>;
}

export async function fetchGlobalStats(
  opts: FetchOptions,
): Promise<{ stats: GlobalStats; recent_runs: RecentRun[] } | null> {
  const data = await fetchJson<VaaSStatsResponse>(
    "/v1/ledger/stats",
    { ...opts, cacheTtl: 30 },
  );
  if (!data) return null;

  return {
    stats: {
      total_runs: data.total_runs,
      total_agents: data.total_agents,
      runs_24h: data.runs_24h,
    },
    recent_runs: (data.recent_runs ?? []).slice(0, 20).map(r => ({
      run_id: r.run_id,
      agent_did: r.agent_did,
      proof_tier: r.proof_tier,
      status: r.status,
      created_at: r.created_at,
    })),
  };
}
