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

export interface ArenaScoreExplainLink {
  label: string;
  url: string;
  source?: string;
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
  score_explain: {
    final_score: number;
    reason_codes: string[];
    evidence_links: ArenaScoreExplainLink[];
  };
  review_paste: string;
  manager_review_json: string;
}

export interface ArenaDelegationInsights {
  winner_hints: string[];
  winner_bottlenecks: string[];
  bottlenecks: string[];
  contract_improvements: string[];
  next_delegation_hints: string[];
  manager_routing: {
    default_contender_id: string | null;
    backup_contenders: string[];
  };
}

export interface ArenaReviewThreadEntryView {
  thread_entry_id: string;
  contender_id: string;
  recommendation: 'APPROVE' | 'REQUEST_CHANGES' | 'REJECT';
  confidence: number;
  body_markdown: string;
  links: Array<{ label: string; url: string }>;
  source: string;
  created_at: string;
}

export interface ArenaOutcomeView {
  outcome_id: string;
  contender_id: string;
  outcome_status: 'ACCEPTED' | 'OVERRIDDEN' | 'REWORK' | 'REJECTED' | 'DISPUTED';
  review_time_minutes: number;
  time_to_accept_minutes: number | null;
  predicted_confidence: number;
  recommendation: 'APPROVE' | 'REQUEST_CHANGES' | 'REJECT';
  reviewer_decision: 'approve' | 'request_changes' | 'reject';
  rework_required: boolean;
  override_reason_code: string | null;
  reviewer_rationale: string | null;
  decision_taxonomy_tags: string[];
  created_at: string;
}

export interface ArenaCalibrationView {
  totals: {
    samples: number;
    accepted: number;
    overridden: number;
    rework: number;
    disputed: number;
    review_time_avg_minutes: number;
    time_to_accept_avg_minutes: number;
    cost_per_accepted_bounty_usd: number;
    override_rate: number;
    rework_rate: number;
    reviewer_decisions: {
      approve: number;
      request_changes: number;
      reject: number;
    };
  };
  reviewer_decision_capture?: {
    decision_breakdown: Array<{
      reviewer_decision: 'approve' | 'request_changes' | 'reject';
      count: number;
      share: number;
    }>;
    decision_taxonomy_tags: Array<{
      tag: string;
      count: number;
      share: number;
    }>;
  };
}

export interface ArenaAutopilotView {
  status: string;
  task_fingerprint: string | null;
  default_contender_id: string | null;
  backup_contenders: string[];
  reason_codes: string[];
  violations: string[];
  metrics: {
    override_rate: number;
    rework_rate: number;
    winner_stability_ratio: number;
  };
}

export interface ArenaContractLanguageSuggestionView {
  suggestion_id: string;
  scope: 'global' | 'contender';
  contender_id: string | null;
  reason_code: string;
  failures: number;
  overrides: number;
  share: number;
  priority_score: number;
  contract_rewrite: string;
  prompt_rewrite: string;
  contract_language_patch: string;
  prompt_language_patch: string;
  sample_notes: string[];
  top_tags: string[];
}

export interface ArenaContractLanguageOptimizerView {
  status: string;
  task_fingerprint: string | null;
  global_suggestions: ArenaContractLanguageSuggestionView[];
  contender_suggestions: ArenaContractLanguageSuggestionView[];
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
  delegation_insights?: ArenaDelegationInsights;
  review_thread: ArenaReviewThreadEntryView[];
  outcomes: ArenaOutcomeView[];
  calibration?: ArenaCalibrationView;
  autopilot?: ArenaAutopilotView;
  contract_language_optimizer?: ArenaContractLanguageOptimizerView;
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
    score_explain?: {
      derived?: {
        final_score?: unknown;
      };
      reason_codes?: unknown;
      evidence_links?: unknown;
    };
    review_paste?: unknown;
    manager_review_json?: unknown;
  }>;
  winner?: {
    contender_id?: unknown;
    reason?: unknown;
  };
  tradeoffs?: unknown;
  reason_codes?: unknown;
  delegation_insights?: unknown;
  review_thread?: Array<{
    thread_entry_id?: unknown;
    contender_id?: unknown;
    recommendation?: unknown;
    confidence?: unknown;
    body_markdown?: unknown;
    links?: unknown;
    source?: unknown;
    created_at?: unknown;
  }>;
  outcomes?: Array<{
    outcome_id?: unknown;
    contender_id?: unknown;
    outcome_status?: unknown;
    review_time_minutes?: unknown;
    time_to_accept_minutes?: unknown;
    predicted_confidence?: unknown;
    recommendation?: unknown;
    reviewer_decision?: unknown;
    rework_required?: unknown;
    override_reason_code?: unknown;
    reviewer_rationale?: unknown;
    decision_taxonomy_tags?: unknown;
    created_at?: unknown;
  }>;
  calibration?: {
    totals?: {
      samples?: unknown;
      accepted?: unknown;
      overridden?: unknown;
      rework?: unknown;
      disputed?: unknown;
      review_time_avg_minutes?: unknown;
      time_to_accept_avg_minutes?: unknown;
      cost_per_accepted_bounty_usd?: unknown;
      override_rate?: unknown;
      rework_rate?: unknown;
      reviewer_decisions?: {
        approve?: unknown;
        request_changes?: unknown;
        reject?: unknown;
      };
    };
    reviewer_decision_capture?: {
      decision_breakdown?: unknown;
      decision_taxonomy_tags?: unknown;
    };
  };
  autopilot?: {
    status?: unknown;
    task_fingerprint?: unknown;
    default_contender_id?: unknown;
    backup_contenders?: unknown;
    reason_codes?: unknown;
    violations?: unknown;
    metrics?: {
      override_rate?: unknown;
      rework_rate?: unknown;
      winner_stability_ratio?: unknown;
    };
  };
  contract_language_optimizer?: {
    status?: unknown;
    task_fingerprint?: unknown;
    global_suggestions?: unknown;
    contender_suggestions?: unknown;
  };
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

  const evidenceLinksRaw = row.score_explain?.evidence_links;
  const evidenceLinks = Array.isArray(evidenceLinksRaw)
    ? evidenceLinksRaw
      .map((entry) => {
        if (!entry || typeof entry !== 'object') return null;
        const rec = entry as Record<string, unknown>;
        const label = asString(rec.label);
        const url = asString(rec.url);
        const source = asString(rec.source) ?? undefined;
        if (!label || !url) return null;
        return { label, url, source } as ArenaScoreExplainLink;
      })
      .filter((entry): entry is ArenaScoreExplainLink => entry !== null)
    : [];

  const reasonCodesRaw = row.score_explain?.reason_codes;
  const scoreReasonCodes = Array.isArray(reasonCodesRaw)
    ? reasonCodesRaw.filter((entry): entry is string => typeof entry === 'string')
    : [];

  const finalScore = asNumber(row.score_explain?.derived?.final_score, asNumber(row.score, 0));

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
    score_explain: {
      final_score: finalScore,
      reason_codes: scoreReasonCodes,
      evidence_links: evidenceLinks,
    },
    review_paste: asString(row.review_paste) ?? '',
    manager_review_json: managerReviewJson,
  };
}

function parseDelegationInsights(input: unknown): ArenaDelegationInsights | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const rec = input as Record<string, unknown>;
  const routingRaw = rec.manager_routing;
  const routing = routingRaw && typeof routingRaw === 'object'
    ? (routingRaw as Record<string, unknown>)
    : {};

  return {
    winner_hints: Array.isArray(rec.winner_hints)
      ? rec.winner_hints.filter((entry): entry is string => typeof entry === 'string')
      : [],
    winner_bottlenecks: Array.isArray(rec.winner_bottlenecks)
      ? rec.winner_bottlenecks.filter((entry): entry is string => typeof entry === 'string')
      : [],
    bottlenecks: Array.isArray(rec.bottlenecks)
      ? rec.bottlenecks.filter((entry): entry is string => typeof entry === 'string')
      : [],
    contract_improvements: Array.isArray(rec.contract_improvements)
      ? rec.contract_improvements.filter((entry): entry is string => typeof entry === 'string')
      : [],
    next_delegation_hints: Array.isArray(rec.next_delegation_hints)
      ? rec.next_delegation_hints.filter((entry): entry is string => typeof entry === 'string')
      : [],
    manager_routing: {
      default_contender_id: asString(routing.default_contender_id),
      backup_contenders: Array.isArray(routing.backup_contenders)
        ? routing.backup_contenders.filter((entry): entry is string => typeof entry === 'string')
        : [],
    },
  };
}

function parseReviewThreadEntries(input: unknown): ArenaReviewThreadEntryView[] {
  if (!Array.isArray(input)) return [];

  return input
    .map((raw) => {
      if (!raw || typeof raw !== 'object') return null;
      const rec = raw as Record<string, unknown>;
      const threadEntryId = asString(rec.thread_entry_id);
      const contenderId = asString(rec.contender_id);
      const recommendation = asString(rec.recommendation);
      const confidence = asNumber(rec.confidence, 0);
      const bodyMarkdown = asString(rec.body_markdown);
      const source = asString(rec.source);
      const createdAt = asString(rec.created_at);

      if (!threadEntryId || !contenderId || !recommendation || !bodyMarkdown || !source || !createdAt) return null;
      if (recommendation !== 'APPROVE' && recommendation !== 'REQUEST_CHANGES' && recommendation !== 'REJECT') return null;

      const links = Array.isArray(rec.links)
        ? rec.links
          .map((entry) => {
            if (!entry || typeof entry !== 'object') return null;
            const link = entry as Record<string, unknown>;
            const label = asString(link.label);
            const url = asString(link.url);
            if (!label || !url) return null;
            return { label, url };
          })
          .filter((entry): entry is { label: string; url: string } => entry !== null)
        : [];

      return {
        thread_entry_id: threadEntryId,
        contender_id: contenderId,
        recommendation,
        confidence,
        body_markdown: bodyMarkdown,
        links,
        source,
        created_at: createdAt,
      } as ArenaReviewThreadEntryView;
    })
    .filter((entry): entry is ArenaReviewThreadEntryView => entry !== null);
}

function parseOutcomeEntries(input: unknown): ArenaOutcomeView[] {
  if (!Array.isArray(input)) return [];

  return input
    .map((raw) => {
      if (!raw || typeof raw !== 'object') return null;
      const rec = raw as Record<string, unknown>;
      const outcomeId = asString(rec.outcome_id);
      const contenderId = asString(rec.contender_id);
      const outcomeStatus = asString(rec.outcome_status);
      const recommendation = asString(rec.recommendation);
      const reviewerDecision = asString(rec.reviewer_decision);
      const createdAt = asString(rec.created_at);
      if (!outcomeId || !contenderId || !outcomeStatus || !recommendation || !createdAt) return null;
      if (
        outcomeStatus !== 'ACCEPTED' &&
        outcomeStatus !== 'OVERRIDDEN' &&
        outcomeStatus !== 'REWORK' &&
        outcomeStatus !== 'REJECTED' &&
        outcomeStatus !== 'DISPUTED'
      ) return null;
      if (recommendation !== 'APPROVE' && recommendation !== 'REQUEST_CHANGES' && recommendation !== 'REJECT') return null;

      const normalizedReviewerDecision = reviewerDecision === 'approve' || reviewerDecision === 'request_changes' || reviewerDecision === 'reject'
        ? reviewerDecision
        : recommendation === 'APPROVE'
          ? 'approve'
          : recommendation === 'REQUEST_CHANGES'
            ? 'request_changes'
            : 'reject';

      return {
        outcome_id: outcomeId,
        contender_id: contenderId,
        outcome_status: outcomeStatus,
        review_time_minutes: asNumber(rec.review_time_minutes, 0),
        time_to_accept_minutes: rec.time_to_accept_minutes === null ? null : asNumber(rec.time_to_accept_minutes, 0),
        predicted_confidence: asNumber(rec.predicted_confidence, 0),
        recommendation,
        reviewer_decision: normalizedReviewerDecision,
        rework_required: rec.rework_required === true,
        override_reason_code: asString(rec.override_reason_code),
        reviewer_rationale: asString(rec.reviewer_rationale),
        decision_taxonomy_tags: Array.isArray(rec.decision_taxonomy_tags)
          ? rec.decision_taxonomy_tags.filter((entry): entry is string => typeof entry === 'string')
          : [],
        created_at: createdAt,
      } as ArenaOutcomeView;
    })
    .filter((entry): entry is ArenaOutcomeView => entry !== null);
}

function parseCalibration(input: unknown): ArenaCalibrationView | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const rec = input as Record<string, unknown>;
  const totalsRaw = rec.totals;
  if (!totalsRaw || typeof totalsRaw !== 'object') return undefined;
  const totals = totalsRaw as Record<string, unknown>;
  const reviewerDecisionsRaw = totals.reviewer_decisions;
  const reviewerDecisions = reviewerDecisionsRaw && typeof reviewerDecisionsRaw === 'object'
    ? reviewerDecisionsRaw as Record<string, unknown>
    : {};

  const captureRaw = rec.reviewer_decision_capture;
  const capture = captureRaw && typeof captureRaw === 'object'
    ? captureRaw as Record<string, unknown>
    : null;

  const decisionBreakdown = Array.isArray(capture?.decision_breakdown)
    ? capture?.decision_breakdown
      .map((entry) => {
        if (!entry || typeof entry !== 'object') return null;
        const row = entry as Record<string, unknown>;
        const decision = asString(row.reviewer_decision);
        if (decision !== 'approve' && decision !== 'request_changes' && decision !== 'reject') return null;
        return {
          reviewer_decision: decision,
          count: asNumber(row.count, 0),
          share: asNumber(row.share, 0),
        };
      })
      .filter((entry): entry is { reviewer_decision: 'approve' | 'request_changes' | 'reject'; count: number; share: number } => entry !== null)
    : [];

  const taxonomyTags = Array.isArray(capture?.decision_taxonomy_tags)
    ? capture?.decision_taxonomy_tags
      .map((entry) => {
        if (!entry || typeof entry !== 'object') return null;
        const row = entry as Record<string, unknown>;
        const tag = asString(row.tag);
        if (!tag) return null;
        return {
          tag,
          count: asNumber(row.count, 0),
          share: asNumber(row.share, 0),
        };
      })
      .filter((entry): entry is { tag: string; count: number; share: number } => entry !== null)
    : [];

  return {
    totals: {
      samples: asNumber(totals.samples, 0),
      accepted: asNumber(totals.accepted, 0),
      overridden: asNumber(totals.overridden, 0),
      rework: asNumber(totals.rework, 0),
      disputed: asNumber(totals.disputed, 0),
      review_time_avg_minutes: asNumber(totals.review_time_avg_minutes, 0),
      time_to_accept_avg_minutes: asNumber(totals.time_to_accept_avg_minutes, 0),
      cost_per_accepted_bounty_usd: asNumber(totals.cost_per_accepted_bounty_usd, 0),
      override_rate: asNumber(totals.override_rate, 0),
      rework_rate: asNumber(totals.rework_rate, 0),
      reviewer_decisions: {
        approve: asNumber(reviewerDecisions.approve, 0),
        request_changes: asNumber(reviewerDecisions.request_changes, 0),
        reject: asNumber(reviewerDecisions.reject, 0),
      },
    },
    reviewer_decision_capture: capture
      ? {
        decision_breakdown: decisionBreakdown,
        decision_taxonomy_tags: taxonomyTags,
      }
      : undefined,
  };
}

function parseAutopilot(input: unknown): ArenaAutopilotView | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const rec = input as Record<string, unknown>;

  return {
    status: asString(rec.status) ?? 'unknown',
    task_fingerprint: asString(rec.task_fingerprint),
    default_contender_id: asString(rec.default_contender_id),
    backup_contenders: Array.isArray(rec.backup_contenders)
      ? rec.backup_contenders.filter((entry): entry is string => typeof entry === 'string')
      : [],
    reason_codes: Array.isArray(rec.reason_codes)
      ? rec.reason_codes.filter((entry): entry is string => typeof entry === 'string')
      : [],
    violations: Array.isArray(rec.violations)
      ? rec.violations.filter((entry): entry is string => typeof entry === 'string')
      : [],
    metrics: {
      override_rate: asNumber((rec.metrics as Record<string, unknown> | undefined)?.override_rate, 0),
      rework_rate: asNumber((rec.metrics as Record<string, unknown> | undefined)?.rework_rate, 0),
      winner_stability_ratio: asNumber((rec.metrics as Record<string, unknown> | undefined)?.winner_stability_ratio, 0),
    },
  };
}

function parseContractLanguageSuggestion(input: unknown): ArenaContractLanguageSuggestionView | null {
  if (!input || typeof input !== 'object') return null;
  const rec = input as Record<string, unknown>;

  const suggestionId = asString(rec.suggestion_id);
  const scope = asString(rec.scope);
  const reasonCode = asString(rec.reason_code);

  if (!suggestionId || !scope || !reasonCode) return null;
  if (scope !== 'global' && scope !== 'contender') return null;

  return {
    suggestion_id: suggestionId,
    scope,
    contender_id: asString(rec.contender_id),
    reason_code: reasonCode,
    failures: asNumber(rec.failures, 0),
    overrides: asNumber(rec.overrides, 0),
    share: asNumber(rec.share, 0),
    priority_score: asNumber(rec.priority_score, 0),
    contract_rewrite: asString(rec.contract_rewrite) ?? '',
    prompt_rewrite: asString(rec.prompt_rewrite) ?? '',
    contract_language_patch: asString(rec.contract_language_patch) ?? '',
    prompt_language_patch: asString(rec.prompt_language_patch) ?? '',
    sample_notes: Array.isArray(rec.sample_notes)
      ? rec.sample_notes.filter((entry): entry is string => typeof entry === 'string')
      : [],
    top_tags: Array.isArray(rec.top_tags)
      ? rec.top_tags.filter((entry): entry is string => typeof entry === 'string')
      : [],
  };
}

function parseContractLanguageOptimizer(input: unknown): ArenaContractLanguageOptimizerView | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const rec = input as Record<string, unknown>;

  const globalSuggestions = Array.isArray(rec.global_suggestions)
    ? rec.global_suggestions
      .map((entry) => parseContractLanguageSuggestion(entry))
      .filter((entry): entry is ArenaContractLanguageSuggestionView => entry !== null)
    : [];

  const contenderSuggestions = Array.isArray(rec.contender_suggestions)
    ? rec.contender_suggestions
      .map((entry) => parseContractLanguageSuggestion(entry))
      .filter((entry): entry is ArenaContractLanguageSuggestionView => entry !== null)
    : [];

  return {
    status: asString(rec.status) ?? 'unknown',
    task_fingerprint: asString(rec.task_fingerprint),
    global_suggestions: globalSuggestions,
    contender_suggestions: contenderSuggestions,
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
    delegation_insights: parseDelegationInsights(data.delegation_insights),
    review_thread: parseReviewThreadEntries(data.review_thread),
    outcomes: parseOutcomeEntries(data.outcomes),
    calibration: parseCalibration(data.calibration),
    autopilot: parseAutopilot(data.autopilot),
    contract_language_optimizer: parseContractLanguageOptimizer(data.contract_language_optimizer),
  };
}
