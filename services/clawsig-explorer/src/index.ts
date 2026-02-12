/**
 * clawsig-explorer -- Public Explorer for the Clawsig Protocol
 *
 * Cloudflare Worker that serves HTML pages for:
 * - GET /                  -> Home / global stats + recent runs
 * - GET /run/:run_id       -> Run detail with client-side verification
 * - GET /agent/:did        -> Agent profile with run history
 * - GET /stats             -> Network statistics
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
import { fetchRun, fetchAgentPassport, fetchAgentRuns, fetchGlobalStats } from "./api.js";
import { runDetailPage, runNotFoundPage } from "./pages/run.js";
import { agentProfilePage, agentNotFoundPage } from "./pages/agent.js";
import { homePage, statsPage } from "./pages/home.js";

export interface Env {
  ENVIRONMENT: string;
  VAAS_API_BASE: string;
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
      "Content-Type": "text/html;charset=utf-8",
      "Cache-Control": `public, max-age=${cacheSeconds}, s-maxage=${cacheSeconds * 10}`,
    },
  });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    // Cache API instance
    const cache = await caches.open("clawsig-explorer");
    const apiOpts = { vaasBase: env.VAAS_API_BASE, cache };

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

    // -- Agents listing (redirect to home for now) --
    if (path === "/agents") {
      return Response.redirect(url.origin + "/", 302);
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
    title: "Clawsig Explorer",
    description: "Explore the public ledger of verified AI agent executions.",
    path: "/",
  };

  return layout(meta, `
    <div class="hero">
      <h1>Cryptographic Proof for Every Agent Run</h1>
      <p>
        Explore the public ledger of verified AI agent executions.
        Every proof is independently verifiable in your browser.
      </p>
      <div class="cta-box">
        <span class="prompt">$</span> <span class="cmd">npx clawsig wrap -- your-agent</span>
      </div>
    </div>
    <div class="card" style="text-align: center">
      <p class="dim">Ledger data is currently loading. Check back shortly.</p>
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
