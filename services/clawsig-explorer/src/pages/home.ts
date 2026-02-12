/**
 * Home / Stats Page: GET /
 *
 * Landing page for the Clawsig Explorer viral loop.
 * Shows global stats and recent runs feed.
 */

import {
  layout, esc, statusBadge, tierBadge,
  relativeTime, fmtNum, type PageMeta,
} from "../layout.js";

export interface GlobalStats {
  total_runs: number;
  total_agents: number;
  runs_24h: number;
}

export interface RecentRun {
  run_id: string;
  agent_did: string;
  proof_tier: string;
  status: string;
  created_at: string;
}

export interface HomePageData {
  stats: GlobalStats;
  recent_runs: RecentRun[];
}

export function homePage(data: HomePageData): string {
  const meta: PageMeta = {
    title: "Clawsig Explorer",
    description: `Explore ${fmtNum(data.stats.total_runs)} verified agent runs on the Clawsig Protocol public ledger. Cryptographic proof of every AI agent execution.`,
    path: "/",
  };

  const body = `
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

    <div class="stats-grid">
      <div class="stat-card">
        <div class="value">${fmtNum(data.stats.total_runs)}</div>
        <div class="label">Verified Runs</div>
      </div>
      <div class="stat-card">
        <div class="value">${fmtNum(data.stats.total_agents)}</div>
        <div class="label">Agents</div>
      </div>
      <div class="stat-card">
        <div class="value">${fmtNum(data.stats.runs_24h)}</div>
        <div class="label">Runs (24h)</div>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Recent Verified Runs</p>
      ${recentRunsFeed(data.recent_runs)}
    </div>

    <div style="text-align: center; padding: 2rem 0">
      <p class="dim" style="font-size: 0.875rem; margin-bottom: 0.5rem">
        Every badge links here. Every proof verifies in your browser.
      </p>
      <p>
        <a href="https://docs.clawsig.com/quickstart" target="_blank" rel="noopener">
          Read the Quickstart Guide &rarr;
        </a>
      </p>
    </div>
  `;

  return layout(meta, body);
}

function recentRunsFeed(runs: RecentRun[]): string {
  if (runs.length === 0) {
    return `<p class="dim">No runs recorded yet. Be the first!</p>`;
  }

  return runs.map(r => {
    const shortDid = r.agent_did.length > 24
      ? r.agent_did.slice(0, 16) + "..." + r.agent_did.slice(-6)
      : r.agent_did;

    return `
      <div class="run-item">
        <a href="/run/${esc(r.run_id)}" class="run-id">${esc(r.run_id.slice(0, 16))}...</a>
        <span class="run-meta">
          <a href="/agent/${encodeURIComponent(r.agent_did)}" class="dim" style="font-size: 0.8125rem">${esc(shortDid)}</a>
        </span>
        ${statusBadge(r.status)}
        ${tierBadge(r.proof_tier)}
        <span class="run-time">${relativeTime(r.created_at)}</span>
      </div>
    `;
  }).join("");
}

/** Stats-only page for /stats route */
export function statsPage(data: HomePageData): string {
  const meta: PageMeta = {
    title: "Network Stats",
    description: `Clawsig Protocol statistics: ${fmtNum(data.stats.total_runs)} verified runs across ${fmtNum(data.stats.total_agents)} agents.`,
    path: "/stats",
  };

  const body = `
    <h1 class="page-title">Network Statistics</h1>
    <p class="page-subtitle">Real-time metrics from the Clawsig public ledger</p>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="value">${fmtNum(data.stats.total_runs)}</div>
        <div class="label">Total Verified Runs</div>
      </div>
      <div class="stat-card">
        <div class="value">${fmtNum(data.stats.total_agents)}</div>
        <div class="label">Total Agents</div>
      </div>
      <div class="stat-card">
        <div class="value">${fmtNum(data.stats.runs_24h)}</div>
        <div class="label">Runs (Last 24h)</div>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Recent Activity</p>
      ${recentRunsFeed(data.recent_runs)}
    </div>
  `;

  return layout(meta, body);
}
