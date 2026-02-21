/**
 * clawsig-explorer -- Public Explorer for the Clawsig Protocol
 *
 * Cloudflare Worker that serves HTML pages for:
 * - GET /                  -> Home / global stats + recent runs
 * - GET /run/:run_id       -> Run detail with client-side verification
 * - GET /agent/:did        -> Agent profile with run history
 * - GET /stats             -> Network statistics
 * - GET /inspect           -> Proof bundle inspector (client-side upload/verify)
 * - GET /ops               -> Operator dashboard
 * - GET /health            -> Health check
 * - GET /robots.txt        -> Robots
 *
 * Design:
 * - Server-rendered HTML (no React, no SPA)
 * - Dark theme, monospace hashes, green/red indicators
 * - Client-side verification via WebCrypto
 * - Cache API for sub-100ms renders
 */

import { layout, type PageMeta } from "./layout.js";
import {
  fetchRun,
  fetchAgentPassport,
  fetchAgentRuns,
  fetchGlobalStats,
  fetchRunsFeed,
  fetchOpsDomainHealth,
  fetchSyntheticWorkflowStatuses,
  fetchWorkflowRunHistory,
  fetchRecentFailedRuns,
  fetchArenaIndex,
  fetchArenaMissionSummary,
  fetchArenaReport,
  fetchArenaRoiDashboard,
  fetchDuelLeague,
} from './api.js';
import { runDetailPage, runNotFoundPage } from './pages/run.js';
import { agentProfilePage, agentNotFoundPage } from './pages/agent.js';
import { homePage, statsPage } from './pages/home.js';
import { runsFeedPage } from './pages/runs.js';
import { opsDashboardPage } from './pages/ops.js';
import { inspectPage } from './pages/inspect.js';
import {
  arenaComparePage,
  arenaIndexPage,
  arenaMissionPage,
  arenaNotFoundPage,
  sampleArenaMissionSummary,
  sampleArenaReport,
} from './pages/arena.js';
import { arenaRoiPage, arenaRoiUnavailablePage } from './pages/arena-roi.js';
import { arenaLeaguePage, arenaLeagueUnavailablePage } from './pages/arena-league.js';
import { deriveOpsSloHealth } from './slo.js';

export interface Env {
  ENVIRONMENT: string;
  VAAS_API_BASE: string;
  ARENA_API_BASE?: string;
  ARENA_ADMIN_KEY?: string;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function html(body: string, status = 200, cacheSeconds = 60): Response {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/html;charset=utf-8',
      'Cache-Control': `public, max-age=${cacheSeconds}, s-maxage=${cacheSeconds * 10}`,
    },
  });
}

function normalizeQueryValue(raw: string | null): string | undefined {
  if (!raw) return undefined;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function parseRunsLimit(raw: string | null): number {
  const parsed = Number.parseInt(raw ?? '', 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return 20;
  return Math.min(parsed, 100);
}

function parseCursorHistory(raw: string | null): string[] {
  if (!raw) return [];

  return raw
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
    .slice(0, 50);
}

async function loadOpsDashboardData(apiOpts: { vaasBase: string; cache: Cache }) {
  const [
    statsData,
    domainHealth,
    syntheticStatuses,
    syntheticHistory,
    canaryHistory,
    guardedDeployHistory,
    recentFailedRuns,
  ] = await Promise.all([
    fetchGlobalStats(apiOpts),
    fetchOpsDomainHealth(),
    fetchSyntheticWorkflowStatuses(),
    fetchWorkflowRunHistory('clawsig-surface-synthetic-smoke.yml', 8),
    fetchWorkflowRunHistory('clawsig-canary-seed.yml', 8),
    fetchWorkflowRunHistory('clawsig-guarded-deploy.yml', 8),
    fetchRecentFailedRuns(apiOpts, 8),
  ]);

  if (!statsData) {
    return null;
  }

  const sloHealth = deriveOpsSloHealth({
    stats: statsData.stats,
    domainHealth,
    syntheticStatuses,
  });

  return {
    stats: statsData.stats,
    domain_health: domainHealth,
    synthetic_statuses: syntheticStatuses,
    synthetic_history: syntheticHistory,
    canary_history: canaryHistory,
    guarded_deploy_history: guardedDeployHistory,
    recent_failed_runs: recentFailedRuns,
    slo_health: sloHealth,
  };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // Cache API instance
    const cache = await caches.open("clawsig-explorer");
    const bountiesBase = env.ARENA_API_BASE ?? 'https://clawbounties.com';
    const apiOpts = {
      vaasBase: env.VAAS_API_BASE,
      arenaBase: bountiesBase,
      arenaAdminKey: env.ARENA_ADMIN_KEY ?? '',
      bountiesBase,
      cache,
    };

    // -- Health --
    if (path === "/health") {
      return json({ ok: true, service: "clawsig-explorer", ts: new Date().toISOString() });
    }

    // -- Robots --
    if (path === "/robots.txt") {
      return new Response(
        [
          "User-agent: *",
          "Allow: /",
          "Disallow: /api/",
          "",
          "Sitemap: https://explorer.clawsig.com/sitemap.xml",
        ].join("\n"),
        { headers: { "Content-Type": "text/plain", "Cache-Control": "public, max-age=86400" } },
      );
    }

    // -- Home --
    if (path === "/") {
      const data = await fetchGlobalStats(apiOpts);
      if (!data) {
        return html(fallbackHomePage(), 200, 10);
      }
      return html(homePage(data), 200, 30);
    }

    // -- Stats --
    if (path === "/stats") {
      const data = await fetchGlobalStats(apiOpts);
      if (!data) {
        return html(fallbackHomePage(), 200, 10);
      }
      return html(statsPage(data), 200, 30);
    }

    // -- Proof Inspector --
    if (path === "/inspect") {
      return html(inspectPage(), 200, 3600);
    }

    // -- Ops SLO health JSON --
    if (path === '/ops/slo-health.json') {
      const opsData = await loadOpsDashboardData(apiOpts);
      if (!opsData) {
        return json({
          error: {
            code: 'OPS_DATA_UNAVAILABLE',
            message: 'Unable to compute SLO health because stats data is unavailable.',
          },
        }, 503);
      }

      return json(opsData.slo_health, 200);
    }

    // -- Ops dashboard --
    if (path === '/ops') {
      const opsData = await loadOpsDashboardData(apiOpts);

      if (!opsData) {
        return html(fallbackHomePage(), 200, 10);
      }

      return html(opsDashboardPage(opsData), 200, 15);
    }

    // -- Runs feed / triage mode --
    if (path === '/runs') {
      const limit = parseRunsLimit(url.searchParams.get('limit'));
      const cursor = normalizeQueryValue(url.searchParams.get('cursor'));
      const cursorHistory = parseCursorHistory(url.searchParams.get('history'));

      const filters = {
        status: normalizeQueryValue(url.searchParams.get('status')),
        tier: normalizeQueryValue(url.searchParams.get('tier')),
        reason_code: normalizeQueryValue(url.searchParams.get('reason_code')),
        agent_did: normalizeQueryValue(url.searchParams.get('agent_did')),
      };

      const data = await fetchRunsFeed(
        {
          limit,
          cursor,
          status: filters.status,
          tier: filters.tier,
          reason_code: filters.reason_code,
          agent_did: filters.agent_did,
        },
        apiOpts,
      );

      if (!data) {
        return html(runsFeedPage({
          runs: [],
          filters,
          limit,
          has_next: false,
          next_cursor: null,
          current_cursor: cursor,
          cursor_history: cursorHistory,
          fetch_error: 'Runs feed is temporarily unavailable. Retry in a moment.',
        }), 200, 5);
      }

      return html(runsFeedPage({
        ...data,
        current_cursor: cursor,
        cursor_history: cursorHistory,
      }), 200, 20);
    }

    // -- Agents listing (redirect to runs feed for now) --
    if (path === '/agents') {
      return Response.redirect(url.origin + '/runs', 302);
    }

    // -- Arena duel league (AGP-US-087) --
    if (path === '/arena/league') {
      const leagueData = await fetchDuelLeague(apiOpts);
      if (!leagueData) {
        return html(arenaLeagueUnavailablePage(), 200, 30);
      }
      return html(arenaLeaguePage(leagueData), 200, 30);
    }

    // -- Arena ROI dashboard (AGP-US-084) --
    if (path === '/arena/roi') {
      const roiData = await fetchArenaRoiDashboard(apiOpts);
      if (!roiData) {
        return html(arenaRoiUnavailablePage(), 200, 30);
      }
      return html(arenaRoiPage(roiData), 200, 30);
    }

    // -- Arena mission control --
    if (path === '/arena/mission') {
      const mission = await fetchArenaMissionSummary(apiOpts, {
        workerDid: 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
        windowHours: 24,
      });

      return html(arenaMissionPage(mission ?? sampleArenaMissionSummary()), 200, 20);
    }

    // -- Arena index --
    if (path === '/arena') {
      const remoteArenaIndex = await fetchArenaIndex(apiOpts);

      const fallbackArenaIndex = [
        {
          arena_id: 'arena_bty_arena_001',
          bounty_id: 'bty_arena_001',
          contract_id: 'contract_arena_001',
          generated_at: '2026-02-19T15:10:00.000Z',
          winner_contender_id: 'contender_codex_pi',
          reason_code: 'ARENA_WINNER_SELECTED',
        },
      ];

      return html(arenaIndexPage(remoteArenaIndex ?? fallbackArenaIndex), 200, 20);
    }

    // -- Arena compare detail --
    const arenaMatch = path.match(/^\/arena\/([^/]+)$/);
    if (arenaMatch) {
      const arenaId = decodeURIComponent(arenaMatch[1]);
      const report = await fetchArenaReport(arenaId, apiOpts);
      const fallbackReport = sampleArenaReport(arenaId);

      if (!report && !fallbackReport) {
        return html(arenaNotFoundPage(arenaId), 404, 20);
      }

      // Construct artifacts base URL from the bounties API origin
      const bountiesBase = apiOpts.bountiesBase?.replace(/\/$/, '') ?? null;
      const artifactsUrl = bountiesBase ? `${bountiesBase}/v1/arena/artifacts` : null;
      return html(arenaComparePage(report ?? fallbackReport!, artifactsUrl), 200, 20);
    }

    // -- Run detail --
    const runMatch = path.match(/^\/run\/([^/]+)$/);
    if (runMatch) {
      const runId = decodeURIComponent(runMatch[1]);
      const run = await fetchRun(runId, apiOpts);
      if (!run) {
        return html(runNotFoundPage(runId), 404, 30);
      }
      return html(runDetailPage(run), 200, 300);
    }

    // -- Agent profile --
    const agentMatch = path.match(/^\/agent\/(.+)$/);
    if (agentMatch) {
      const did = decodeURIComponent(agentMatch[1]);
      const page = Math.max(1, parseInt(url.searchParams.get("page") ?? "1", 10) || 1);

      const [passport, runsData] = await Promise.all([
        fetchAgentPassport(did, apiOpts),
        fetchAgentRuns(did, page, apiOpts),
      ]);

      if (!passport) {
        return html(agentNotFoundPage(did), 404, 30);
      }

      return html(agentProfilePage({
        passport,
        runs: runsData?.runs ?? [],
        page: runsData?.page ?? 1,
        total_runs: runsData?.total ?? 0,
        has_next: runsData?.has_next ?? false,
      }), 200, 60);
    }

    // -- 404 --
    return html(notFoundPage(), 404, 30);
  },
} satisfies ExportedHandler<Env>;

// -- Fallback pages --

function fallbackHomePage(): string {
  const meta: PageMeta = {
    title: 'Clawsig Explorer',
    description: 'Explore the public ledger of verified AI agent executions.',
    path: '/',
  };

  return layout(meta, `
    <div class="hero">
      <h1>Cryptographic Proof for Every Agent Run</h1>
      <p>
        Ledger telemetry is temporarily unavailable. Explorer stays in safe degraded mode until API fetch succeeds.
      </p>
      <div class="cta-box">
        <span class="prompt">$</span> <span class="cmd">npx clawsig wrap -- your-agent</span>
      </div>
    </div>
    <div class="card" style="text-align: center; border-color: rgba(255, 170, 0, 0.45)">
      <p class="warn" style="margin-bottom:0.4rem">Data source unavailable</p>
      <p class="dim" style="font-size:0.875rem">Retry soon or confirm API health from the reliability feed.</p>
      <div style="margin-top:0.75rem; display:flex; justify-content:center; gap:1rem; flex-wrap:wrap">
        <a href="/runs?status=FAIL">Open fail feed</a>
        <a href="https://api.clawverify.com/health" target="_blank" rel="noopener">API health &rarr;</a>
      </div>
    </div>
  `);
}

function notFoundPage(): string {
  const meta: PageMeta = {
    title: "Page Not Found",
    description: "The requested page was not found.",
    path: "/404",
  };

  return layout(meta, `
    <div style="text-align: center; padding: 4rem 0">
      <h1 class="page-title">404</h1>
      <p class="dim" style="margin-bottom: 2rem">The page you are looking for does not exist.</p>
      <p><a href="/">Back to Explorer &rarr;</a></p>
    </div>
  `);
}
