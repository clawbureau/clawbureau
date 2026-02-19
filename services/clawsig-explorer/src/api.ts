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
  arenaBase?: string;
  cache?: Cache;
  cacheTtl?: number;
}

export interface RunsFeedFilters {
  status?: string;
  tier?: string;
  reason_code?: string;
  agent_did?: string;
}

export interface RunsFeedRun {
  run_id: string;
  bundle_hash_b64u: string;
  agent_did: string;
  proof_tier: string;
  status: string;
  reason_code: string | null;
  failure_class: string | null;
  verification_source: string | null;
  auth_mode: string | null;
  created_at: string;
}

export interface RunsFeedPage {
  runs: RunsFeedRun[];
  limit: number;
  has_next: boolean;
  next_cursor: string | null;
  filters: RunsFeedFilters;
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

async function fetchArenaJson<T>(
  url: string,
  opts: FetchOptions,
): Promise<T | null> {
  const arenaBase = opts.arenaBase?.trim();
  const baseOpts: FetchOptions = {
    ...opts,
    vaasBase: arenaBase && arenaBase.length > 0 ? arenaBase : opts.vaasBase,
  };

  return fetchJson<T>(url, baseOpts);
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

interface VaaSRunsFeedResponse {
  runs?: VaaSRunPayload[];
  limit?: unknown;
  has_next?: unknown;
  next_cursor?: unknown;
  filters?: {
    status?: unknown;
    tier?: unknown;
    reason_code?: unknown;
    agent_did?: unknown;
  };
}

function parseRunsFeedRun(payload: VaaSRunPayload): RunsFeedRun | null {
  const runId = asString(payload.run_id);
  const bundleHash = asString(payload.bundle_hash_b64u);
  const agentDid = asString(payload.agent_did);
  const proofTier = asString(payload.proof_tier);
  const status = asString(payload.status);
  const createdAt = asString(payload.created_at);

  if (!runId || !bundleHash || !agentDid || !proofTier || !status || !createdAt) {
    return null;
  }

  return {
    run_id: runId,
    bundle_hash_b64u: bundleHash,
    agent_did: agentDid,
    proof_tier: proofTier,
    status,
    reason_code: asString(payload.reason_code),
    failure_class: asString(payload.failure_class),
    verification_source: asString(payload.verification_source),
    auth_mode: asString(payload.auth_mode),
    created_at: createdAt,
  };
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

  const baseRun = parseRunsFeedRun(run);
  if (!baseRun) return null;

  return {
    ...baseRun,
    wpc_hash_b64u: asString(run.wpc_hash_b64u),
    rt_leaf_index: run.rt_leaf_index === null ? null : asNumber(run.rt_leaf_index, 0),
    models: Array.isArray(run.models) ? run.models : [],
    bundle_url: asString(data.bundle_url ?? null) ?? undefined,
    receipt_count: asNumber(data.receipt_count, 0),
    event_count: asNumber(data.event_count, 0),
  };
}

export async function fetchRunsFeed(
  params: {
    limit?: number;
    cursor?: string;
    status?: string;
    tier?: string;
    reason_code?: string;
    agent_did?: string;
  },
  opts: FetchOptions,
): Promise<RunsFeedPage | null> {
  const search = new URLSearchParams();

  if (params.limit && Number.isFinite(params.limit)) {
    search.set('limit', String(params.limit));
  }
  if (params.cursor) search.set('cursor', params.cursor);
  if (params.status) search.set('status', params.status);
  if (params.tier) search.set('tier', params.tier);
  if (params.reason_code) search.set('reason_code', params.reason_code);
  if (params.agent_did) search.set('agent_did', params.agent_did);

  const qs = search.toString();
  const path = qs.length > 0 ? `/v1/ledger/runs?${qs}` : '/v1/ledger/runs';

  const data = await fetchJson<VaaSRunsFeedResponse>(path, {
    ...opts,
    cacheTtl: 15,
  });
  if (!data) return null;

  const rows = Array.isArray(data.runs)
    ? data.runs
      .map((row) => parseRunsFeedRun(row))
      .filter((row): row is RunsFeedRun => row !== null)
    : [];

  const filters: RunsFeedFilters = {
    status: asString(data.filters?.status) ?? undefined,
    tier: asString(data.filters?.tier) ?? undefined,
    reason_code: asString(data.filters?.reason_code) ?? undefined,
    agent_did: asString(data.filters?.agent_did) ?? undefined,
  };

  return {
    runs: rows,
    limit: Math.max(1, asNumber(data.limit, params.limit ?? 20)),
    has_next: Boolean(data.has_next),
    next_cursor: asString(data.next_cursor),
    filters,
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

interface VaaSAgentContractResponse {
  agent?: {
    did?: unknown;
    first_seen_at?: unknown;
    verified_runs?: unknown;
    gateway_tier_runs?: unknown;
    policy_violations?: unknown;
  };
}

export async function fetchAgentPassport(
  did: string,
  opts: FetchOptions,
): Promise<AgentPassport | null> {
  const primary = await fetchJson<AgentPassport>(
    `/v1/passports/${encodeURIComponent(did)}`,
    { ...opts, cacheTtl: 120 },
  );

  if (primary) {
    return primary;
  }

  const fallback = await fetchJson<VaaSAgentContractResponse>(
    `/v1/ledger/agents/${encodeURIComponent(did)}?page=1&limit=1`,
    { ...opts, cacheTtl: 30 },
  );

  const agentDid = asString(fallback?.agent?.did);
  const firstSeenAt = asString(fallback?.agent?.first_seen_at);
  if (!agentDid || !firstSeenAt) {
    return null;
  }

  return {
    did: agentDid,
    first_seen_at: firstSeenAt,
    verified_runs: asNumber(fallback?.agent?.verified_runs, 0),
    gateway_tier_runs: asNumber(fallback?.agent?.gateway_tier_runs, 0),
    policy_violations: asNumber(fallback?.agent?.policy_violations, 0),
  };
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
  diagnostics_7d?: {
    runs_7d?: unknown;
    fail_runs_7d?: unknown;
    fail_rate_7d?: unknown;
    top_fail_reason_codes_7d?: Array<{
      reason_code?: unknown;
      count?: unknown;
    }>;
    daily?: Array<{
      day?: unknown;
      runs?: unknown;
      fail_runs?: unknown;
      fail_rate?: unknown;
    }>;
  };
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

  const topFailReasonCodes7d = Array.isArray(data.diagnostics_7d?.top_fail_reason_codes_7d)
    ? data.diagnostics_7d.top_fail_reason_codes_7d
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

  const diagnosticsDaily = Array.isArray(data.diagnostics_7d?.daily)
    ? data.diagnostics_7d.daily
      .map((row) => {
        const day = asString(row.day);
        if (!day) return null;
        return {
          day,
          runs: asNumber(row.runs, 0),
          fail_runs: asNumber(row.fail_runs, 0),
          fail_rate: asNumber(row.fail_rate, 0),
        };
      })
      .filter((row): row is { day: string; runs: number; fail_runs: number; fail_rate: number } => row !== null)
    : [];

  return {
    stats: {
      total_runs: asNumber(data.total_runs, 0),
      total_agents: asNumber(data.total_agents, 0),
      runs_24h: runs24h,
      fail_runs_24h: failRuns24h,
      fail_rate_24h: failRate24h,
      top_fail_reason_codes: topFailReasonCodes,
      diagnostics_7d: {
        runs_7d: asNumber(data.diagnostics_7d?.runs_7d, 0),
        fail_runs_7d: asNumber(data.diagnostics_7d?.fail_runs_7d, 0),
        fail_rate_7d: asNumber(data.diagnostics_7d?.fail_rate_7d, 0),
        top_fail_reason_codes_7d: topFailReasonCodes7d,
        daily: diagnosticsDaily,
      },
    },
    recent_runs: recentRuns,
  };
}

export interface DomainHealthProbe {
  host: string;
  url: string;
  ok: boolean;
  status: number | null;
  latency_ms: number;
  reason_code: string;
}

export interface SyntheticWorkflowStatus {
  workflow: string;
  ok: boolean | null;
  status: string | null;
  conclusion: string | null;
  updated_at: string | null;
  html_url: string | null;
}

export interface WorkflowRunHistoryItem {
  workflow: string;
  run_id: number | null;
  status: string | null;
  conclusion: string | null;
  created_at: string | null;
  updated_at: string | null;
  html_url: string | null;
  head_sha: string | null;
  artifacts_url: string | null;
}

async function probeHealth(host: string): Promise<DomainHealthProbe> {
  const started = Date.now();
  const url = `https://${host}/health`;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });

    clearTimeout(timer);

    return {
      host,
      url,
      ok: response.ok,
      status: response.status,
      latency_ms: Date.now() - started,
      reason_code: response.ok ? 'OK' : 'HTTP_NON_2XX',
    };
  } catch {
    return {
      host,
      url,
      ok: false,
      status: null,
      latency_ms: Date.now() - started,
      reason_code: 'NETWORK_ERROR',
    };
  }
}

interface GitHubWorkflowRunsResponse {
  workflow_runs?: Array<{
    id?: unknown;
    status?: unknown;
    conclusion?: unknown;
    created_at?: unknown;
    updated_at?: unknown;
    html_url?: unknown;
    head_sha?: unknown;
  }>;
}

async function fetchWorkflowRuns(workflow: string, limit: number): Promise<GitHubWorkflowRunsResponse | null> {
  const url = `https://api.github.com/repos/clawbureau/clawbureau/actions/workflows/${encodeURIComponent(workflow)}/runs?per_page=${Math.max(1, Math.min(20, limit))}`;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'clawsig-explorer-ops',
      },
    });

    clearTimeout(timer);

    if (!response.ok) {
      return null;
    }

    return (await response.json()) as GitHubWorkflowRunsResponse;
  } catch {
    return null;
  }
}

async function fetchLatestWorkflowStatus(workflow: string): Promise<SyntheticWorkflowStatus> {
  const data = await fetchWorkflowRuns(workflow, 1);
  const latest = Array.isArray(data?.workflow_runs) ? data.workflow_runs[0] : null;

  if (!latest) {
    return {
      workflow,
      ok: null,
      status: null,
      conclusion: null,
      updated_at: null,
      html_url: null,
    };
  }

  const status = asString(latest.status);
  const conclusion = asString(latest.conclusion);
  const updatedAt = asString(latest.updated_at);
  const htmlUrl = asString(latest.html_url);

  return {
    workflow,
    ok: conclusion === 'success',
    status,
    conclusion,
    updated_at: updatedAt,
    html_url: htmlUrl,
  };
}

export async function fetchWorkflowRunHistory(workflow: string, limit = 8): Promise<WorkflowRunHistoryItem[]> {
  const data = await fetchWorkflowRuns(workflow, limit);
  const rows = Array.isArray(data?.workflow_runs) ? data.workflow_runs : [];

  return rows.map((row) => {
    const runIdRaw = row.id;
    const runId = typeof runIdRaw === 'number'
      ? runIdRaw
      : (typeof runIdRaw === 'string' ? Number.parseInt(runIdRaw, 10) : null);

    const htmlUrl = asString(row.html_url);

    return {
      workflow,
      run_id: Number.isFinite(runId) ? runId : null,
      status: asString(row.status),
      conclusion: asString(row.conclusion),
      created_at: asString(row.created_at),
      updated_at: asString(row.updated_at),
      html_url: htmlUrl,
      head_sha: asString(row.head_sha),
      artifacts_url: htmlUrl ? `${htmlUrl}#artifacts` : null,
    };
  });
}

export async function fetchOpsDomainHealth(): Promise<DomainHealthProbe[]> {
  const hosts = [
    'staging-api.clawverify.com',
    'api.clawverify.com',
    'staging-explorer.clawsig.com',
    'explorer.clawsig.com',
  ];

  return Promise.all(hosts.map((host) => probeHealth(host)));
}

export async function fetchSyntheticWorkflowStatuses(): Promise<SyntheticWorkflowStatus[]> {
  const workflows = [
    'clawsig-surface-synthetic-smoke.yml',
    'clawsig-canary-seed.yml',
  ];

  return Promise.all(workflows.map((workflow) => fetchLatestWorkflowStatus(workflow)));
}

export async function fetchRecentFailedRuns(
  opts: FetchOptions,
  limit = 8,
): Promise<RunsFeedRun[]> {
  const page = await fetchRunsFeed({
    status: 'FAIL',
    limit,
  }, {
    ...opts,
    cacheTtl: 20,
  });

  return page?.runs ?? [];
}

export interface ArenaCheckResult {
  criterion_id: string;
  required: boolean;
  status: 'PASS' | 'FAIL';
  reason_code: string;
}

export interface ArenaContenderView {
  contender_id: string;
  label: string;
  model: string;
  harness: string;
  tools: string[];
  skills: string[];
  plugins: string[];
  score: number;
  hard_gate_pass: boolean;
  mandatory_failed: number;
  metrics: {
    quality_score: number;
    risk_score: number;
    efficiency_score: number;
    latency_ms: number;
    cost_usd: number;
    autonomy_score: number;
  };
  check_results: ArenaCheckResult[];
  review_paste: string;
  manager_review_json: string;
}

export interface ArenaReportView {
  arena_id: string;
  generated_at: string;
  contract: {
    bounty_id: string;
    contract_id: string;
    contract_hash_b64u: string;
    task_fingerprint: string;
  };
  objective_profile: {
    name: string;
    weights: {
      quality: number;
      speed: number;
      cost: number;
      safety: number;
    };
    tie_breakers: string[];
  };
  contenders: ArenaContenderView[];
  winner: {
    contender_id: string;
    reason: string;
  };
  tradeoffs: string[];
  reason_codes: string[];
}

interface ArenaIndexResponse {
  arenas?: Array<{
    arena_id?: unknown;
    bounty_id?: unknown;
    contract_id?: unknown;
    generated_at?: unknown;
    winner_contender_id?: unknown;
    reason_code?: unknown;
  }>;
}

interface ArenaReportResponse {
  arena_id?: unknown;
  generated_at?: unknown;
  contract?: {
    bounty_id?: unknown;
    contract_id?: unknown;
    contract_hash_b64u?: unknown;
    task_fingerprint?: unknown;
  };
  objective_profile?: {
    name?: unknown;
    weights?: {
      quality?: unknown;
      speed?: unknown;
      cost?: unknown;
      safety?: unknown;
    };
    tie_breakers?: unknown;
  };
  contenders?: Array<{
    contender_id?: unknown;
    label?: unknown;
    model?: unknown;
    harness?: unknown;
    tools?: unknown;
    skills?: unknown;
    plugins?: unknown;
    score?: unknown;
    hard_gate_pass?: unknown;
    mandatory_failed?: unknown;
    metrics?: {
      quality_score?: unknown;
      risk_score?: unknown;
      efficiency_score?: unknown;
      latency_ms?: unknown;
      cost_usd?: unknown;
      autonomy_score?: unknown;
    };
    check_results?: unknown;
    review_paste?: unknown;
    manager_review_json?: unknown;
  }>;
  winner?: {
    contender_id?: unknown;
    reason?: unknown;
  };
  tradeoffs?: unknown;
  reason_codes?: unknown;
}

function parseArenaContender(row: NonNullable<ArenaReportResponse['contenders']>[number]): ArenaContenderView | null {
  const contenderId = asString(row.contender_id);
  const label = asString(row.label);

  if (!contenderId || !label) return null;

  const checkResultsRaw = Array.isArray(row.check_results) ? row.check_results : [];
  const checkResults = checkResultsRaw
    .map((check) => {
      if (!check || typeof check !== 'object') return null;
      const rec = check as Record<string, unknown>;
      const criterionId = asString(rec.criterion_id);
      const required = rec.required === true;
      const status = asString(rec.status);
      const reasonCode = asString(rec.reason_code);
      if (!criterionId || !status || !reasonCode) return null;
      if (status !== 'PASS' && status !== 'FAIL') return null;
      return {
        criterion_id: criterionId,
        required,
        status,
        reason_code: reasonCode,
      } as ArenaCheckResult;
    })
    .filter((check): check is ArenaCheckResult => check !== null);

  const managerReviewRaw = row.manager_review_json;
  const managerReviewJson = typeof managerReviewRaw === 'string'
    ? managerReviewRaw
    : JSON.stringify(managerReviewRaw ?? {}, null, 2);

  return {
    contender_id: contenderId,
    label,
    model: asString(row.model) ?? 'unknown-model',
    harness: asString(row.harness) ?? 'unknown-harness',
    tools: Array.isArray(row.tools) ? row.tools.filter((v): v is string => typeof v === 'string') : [],
    skills: Array.isArray(row.skills) ? row.skills.filter((v): v is string => typeof v === 'string') : [],
    plugins: Array.isArray(row.plugins) ? row.plugins.filter((v): v is string => typeof v === 'string') : [],
    score: asNumber(row.score, 0),
    hard_gate_pass: row.hard_gate_pass === true,
    mandatory_failed: asNumber(row.mandatory_failed, 0),
    metrics: {
      quality_score: asNumber(row.metrics?.quality_score, 0),
      risk_score: asNumber(row.metrics?.risk_score, 0),
      efficiency_score: asNumber(row.metrics?.efficiency_score, 0),
      latency_ms: asNumber(row.metrics?.latency_ms, 0),
      cost_usd: asNumber(row.metrics?.cost_usd, 0),
      autonomy_score: asNumber(row.metrics?.autonomy_score, 0),
    },
    check_results: checkResults,
    review_paste: asString(row.review_paste) ?? '',
    manager_review_json: managerReviewJson,
  };
}

export async function fetchArenaIndex(
  opts: FetchOptions,
): Promise<Array<{
  arena_id: string;
  bounty_id: string;
  contract_id: string;
  generated_at: string;
  winner_contender_id: string;
  reason_code: string;
}> | null> {
  const data = await fetchArenaJson<ArenaIndexResponse>('/v1/arena?limit=20', {
    ...opts,
    cacheTtl: 20,
  });

  if (!data) return null;

  const rows = Array.isArray(data.arenas) ? data.arenas : [];

  return rows
    .map((row) => {
      const arenaId = asString(row.arena_id);
      const bountyId = asString(row.bounty_id);
      const contractId = asString(row.contract_id);
      const generatedAt = asString(row.generated_at);
      const winner = asString(row.winner_contender_id);
      const reasonCode = asString(row.reason_code) ?? 'UNKNOWN';
      if (!arenaId || !bountyId || !contractId || !generatedAt || !winner) return null;
      return {
        arena_id: arenaId,
        bounty_id: bountyId,
        contract_id: contractId,
        generated_at: generatedAt,
        winner_contender_id: winner,
        reason_code: reasonCode,
      };
    })
    .filter((row): row is {
      arena_id: string;
      bounty_id: string;
      contract_id: string;
      generated_at: string;
      winner_contender_id: string;
      reason_code: string;
    } => row !== null);
}

export async function fetchArenaReport(
  arenaId: string,
  opts: FetchOptions,
): Promise<ArenaReportView | null> {
  const data = await fetchArenaJson<ArenaReportResponse>(`/v1/arena/${encodeURIComponent(arenaId)}`, {
    ...opts,
    cacheTtl: 20,
  });

  if (!data) return null;

  const contenders = Array.isArray(data.contenders)
    ? data.contenders
      .map((row) => parseArenaContender(row))
      .filter((row): row is ArenaContenderView => row !== null)
    : [];

  const contract = data.contract;
  const winner = data.winner;
  const objectiveProfile = data.objective_profile;

  const arena_id = asString(data.arena_id);
  const generated_at = asString(data.generated_at);
  const bounty_id = asString(contract?.bounty_id);
  const contract_id = asString(contract?.contract_id);
  const contract_hash_b64u = asString(contract?.contract_hash_b64u);
  const task_fingerprint = asString(contract?.task_fingerprint);
  const winner_contender_id = asString(winner?.contender_id);
  const winner_reason = asString(winner?.reason);
  const objective_name = asString(objectiveProfile?.name) ?? 'balanced';

  if (
    !arena_id ||
    !generated_at ||
    !bounty_id ||
    !contract_id ||
    !contract_hash_b64u ||
    !task_fingerprint ||
    !winner_contender_id ||
    !winner_reason
  ) {
    return null;
  }

  return {
    arena_id,
    generated_at,
    contract: {
      bounty_id,
      contract_id,
      contract_hash_b64u,
      task_fingerprint,
    },
    objective_profile: {
      name: objective_name,
      weights: {
        quality: asNumber(objectiveProfile?.weights?.quality, 0.35),
        speed: asNumber(objectiveProfile?.weights?.speed, 0.25),
        cost: asNumber(objectiveProfile?.weights?.cost, 0.2),
        safety: asNumber(objectiveProfile?.weights?.safety, 0.2),
      },
      tie_breakers: Array.isArray(objectiveProfile?.tie_breakers)
        ? objectiveProfile.tie_breakers.filter((entry): entry is string => typeof entry === 'string')
        : [],
    },
    contenders,
    winner: {
      contender_id: winner_contender_id,
      reason: winner_reason,
    },
    tradeoffs: Array.isArray(data.tradeoffs)
      ? data.tradeoffs.filter((entry): entry is string => typeof entry === 'string')
      : [],
    reason_codes: Array.isArray(data.reason_codes)
      ? data.reason_codes.filter((entry): entry is string => typeof entry === 'string')
      : [],
  };
}
