/**
 * Home / Stats Page: GET /
 *
 * Landing page for the Clawsig Explorer viral loop.
 * Shows global stats and recent runs feed.
 */

import {
  layout,
  esc,
  statusBadge,
  tierBadge,
  relativeTime,
  fmtNum,
  type PageMeta,
} from '../layout.js';

export interface FailReasonCode {
  reason_code: string;
  count: number;
}

export interface Diagnostics7dDaily {
  day: string;
  runs: number;
  fail_runs: number;
  fail_rate: number;
}

export interface Diagnostics7d {
  runs_7d: number;
  fail_runs_7d: number;
  fail_rate_7d: number;
  top_fail_reason_codes_7d: FailReasonCode[];
  daily: Diagnostics7dDaily[];
}

export interface GlobalStats {
  total_runs: number;
  total_agents: number;
  runs_24h: number;
  fail_runs_24h: number;
  fail_rate_24h: number;
  top_fail_reason_codes: FailReasonCode[];
  diagnostics_7d: Diagnostics7d;
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

interface ReliabilityState {
  label: string;
  tone: 'pass' | 'warn' | 'fail';
  summary: string;
}

function reliabilityState(failRate: number): ReliabilityState {
  if (failRate <= 0.02) {
    return {
      label: 'Stable',
      tone: 'pass',
      summary: 'Failure rate is below 2% in the past 24h.',
    };
  }

  if (failRate <= 0.08) {
    return {
      label: 'Watch',
      tone: 'warn',
      summary: 'Failure rate is elevated. Triage top reason codes.',
    };
  }

  return {
    label: 'Degraded',
    tone: 'fail',
    summary: 'Failure rate is high. Prioritize remediation now.',
  };
}

function formatPct(value: number): string {
  return `${(value * 100).toFixed(2)}%`;
}

function quickstartCard(title: string, description: string): string {
  const command = 'npx clawsig wrap -- your-agent-command';
  const commandLiteral = JSON.stringify(command);

  return `
    <div class="runs-empty" style="display:grid; gap:0.6rem">
      <p style="font-weight:600">${esc(title)}</p>
      <p class="dim" style="font-size:0.875rem">${esc(description)}</p>
      <pre class="mono" style="background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:0.6rem; overflow-x:auto">${esc(command)}</pre>
      <div style="display:flex; gap:0.75rem; flex-wrap:wrap; align-items:center">
        <button class="copy-btn" onclick="navigator.clipboard.writeText(${commandLiteral}); this.textContent='Copied';">Copy quickstart command</button>
        <a href="https://docs.clawsig.com/quickstart" target="_blank" rel="noopener">Open quickstart docs &rarr;</a>
        <a href="/runs">Browse runs feed &rarr;</a>
      </div>
    </div>
  `;
}

function runsFeed(runs: RecentRun[], options?: { title?: string; empty?: string }): string {
  if (runs.length === 0) {
    return quickstartCard(
      options?.title ?? 'No runs yet',
      options?.empty ?? 'No runs recorded yet.'
    );
  }

  return runs.map((r) => {
    const shortDid = r.agent_did.length > 24
      ? `${r.agent_did.slice(0, 16)}...${r.agent_did.slice(-6)}`
      : r.agent_did;

    const rowClass = r.status === 'FAIL' ? 'run-item run-item-fail' : 'run-item';

    return `
      <div class="${rowClass}">
        <a href="/run/${esc(r.run_id)}" class="run-id">${esc(r.run_id.slice(0, 16))}...</a>
        <span class="run-meta">
          <a href="/agent/${encodeURIComponent(r.agent_did)}" class="dim" style="font-size: 0.8125rem">${esc(shortDid)}</a>
        </span>
        ${statusBadge(r.status)}
        ${tierBadge(r.proof_tier)}
        <span class="run-time">${relativeTime(r.created_at)}</span>
      </div>
    `;
  }).join('');
}

function failReasonRows(rows: FailReasonCode[], failRuns24h: number): string {
  if (rows.length === 0) {
    return `<p class="dim">No failed runs in the last 24 hours.</p>`;
  }

  return rows
    .map((row) => {
      const pct = failRuns24h > 0 ? (row.count / failRuns24h) * 100 : 0;
      return `
      <div class="run-item" style="align-items:center">
        <span class="hash">${esc(row.reason_code)}</span>
        <span class="run-meta dim">${fmtNum(row.count)} run(s)</span>
        <span class="run-time">${pct.toFixed(1)}%</span>
        <a href="/runs?status=FAIL&reason_code=${encodeURIComponent(row.reason_code)}" style="margin-left:auto; font-size:0.8125rem">Open triage &rarr;</a>
      </div>
    `;
    })
    .join('');
}

function operationsSnapshot(data: HomePageData): string {
  const state = reliabilityState(data.stats.fail_rate_24h);
  const topReason = data.stats.top_fail_reason_codes[0] ?? null;

  return `
    <div class="card" style="margin-bottom:1rem">
      <p class="section-title">Reliability Ops Snapshot</p>
      <div style="display:grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap:0.75rem">
        <div style="border:1px solid var(--border); border-radius:8px; padding:0.9rem">
          <p class="dim" style="font-size:0.75rem; text-transform:uppercase; letter-spacing:0.08em">Current posture</p>
          <p class="${state.tone}" style="font-size:1.1rem; font-weight:700; margin-top:0.2rem">${esc(state.label)}</p>
          <p class="dim" style="font-size:0.8125rem; margin-top:0.35rem">${esc(state.summary)}</p>
        </div>

        <div style="border:1px solid var(--border); border-radius:8px; padding:0.9rem">
          <p class="dim" style="font-size:0.75rem; text-transform:uppercase; letter-spacing:0.08em">Fail rate (24h)</p>
          <p style="font-size:1.1rem; font-weight:700; margin-top:0.2rem">${formatPct(data.stats.fail_rate_24h)}</p>
          <p class="dim" style="font-size:0.8125rem; margin-top:0.35rem">${fmtNum(data.stats.fail_runs_24h)} failures / ${fmtNum(data.stats.runs_24h)} runs</p>
        </div>

        <div style="border:1px solid var(--border); border-radius:8px; padding:0.9rem">
          <p class="dim" style="font-size:0.75rem; text-transform:uppercase; letter-spacing:0.08em">Top fail reason</p>
          ${topReason
            ? `<p style="font-size:1rem; font-weight:700; margin-top:0.2rem">${esc(topReason.reason_code)}</p>
               <p class="dim" style="font-size:0.8125rem; margin-top:0.35rem">${fmtNum(topReason.count)} run(s)</p>
               <a href="/runs?status=FAIL&reason_code=${encodeURIComponent(topReason.reason_code)}" style="font-size:0.8125rem">Open filtered feed &rarr;</a>`
            : '<p class="pass" style="font-size:1rem; font-weight:700; margin-top:0.2rem">No active fail cluster</p>'}
        </div>
      </div>
    </div>
  `;
}

export function homePage(data: HomePageData): string {
  const meta: PageMeta = {
    title: 'Clawsig Explorer',
    description: `Explore ${fmtNum(data.stats.total_runs)} verified agent runs on the Clawsig Protocol public ledger. Cryptographic proof of every AI agent execution.`,
    path: '/',
  };

  const recentFailures = data.recent_runs.filter((run) => run.status === 'FAIL').slice(0, 8);

  const body = `
    <div class="hero">
      <h1>Cryptographic Proof for Every Agent Run</h1>
      <p>
        Public ledger visibility for reliability and trust.
        Filter failures, inspect diagnostics, and verify proofs independently.
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
      <div class="stat-card">
        <div class="value" style="color: var(--fail)">${fmtNum(data.stats.fail_runs_24h)}</div>
        <div class="label">Fails (24h)</div>
      </div>
      <div class="stat-card">
        <div class="value">${formatPct(data.stats.fail_rate_24h)}</div>
        <div class="label">Fail Rate (24h)</div>
      </div>
    </div>

    ${data.stats.total_runs === 0
      ? quickstartCard(
          'Ledger is live, but no public runs are indexed yet',
          'Operational truth: the runs table is currently empty. Seed a canary run or publish your first wrapped execution to activate /run and /agent drilldowns.'
        )
      : ''}

    ${operationsSnapshot(data)}

    <div class="card">
      <p class="section-title">Recent Failures</p>
      ${runsFeed(recentFailures, {
        title: 'No recent failures',
        empty: 'No recent failures. Great stability signal.',
      })}
      <div style="margin-top:0.75rem; display:flex; justify-content:flex-end">
        <a href="/runs?status=FAIL" style="font-size:0.875rem">Open failure triage feed &rarr;</a>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Recent Verified Runs</p>
      ${runsFeed(data.recent_runs, {
        title: 'No recent runs yet',
        empty: 'No runs recorded yet. Be the first.',
      })}
      <div style="margin-top:0.75rem; display:flex; justify-content:flex-end">
        <a href="/runs" style="font-size:0.875rem">Open full runs feed &rarr;</a>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Top Failure Reason Codes (24h)</p>
      ${failReasonRows(data.stats.top_fail_reason_codes, data.stats.fail_runs_24h)}
    </div>

    <div style="text-align: center; padding: 1.5rem 0 0.5rem">
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

/** Stats-only page for /stats route */
export function statsPage(data: HomePageData): string {
  const meta: PageMeta = {
    title: 'Network Stats',
    description: `Clawsig Protocol statistics: ${fmtNum(data.stats.total_runs)} verified runs across ${fmtNum(data.stats.total_agents)} agents.`,
    path: '/stats',
  };

  const state = reliabilityState(data.stats.fail_rate_24h);
  const recentFailures = data.recent_runs.filter((run) => run.status === 'FAIL').slice(0, 8);

  const body = `
    <h1 class="page-title">Network Statistics</h1>
    <p class="page-subtitle">Reliability-first view of the Clawsig public ledger</p>

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
      <div class="stat-card">
        <div class="value" style="color: var(--fail)">${fmtNum(data.stats.fail_runs_24h)}</div>
        <div class="label">Fails (Last 24h)</div>
      </div>
      <div class="stat-card">
        <div class="value">${formatPct(data.stats.fail_rate_24h)}</div>
        <div class="label">Fail Rate (Last 24h)</div>
      </div>
    </div>

    ${data.stats.total_runs === 0
      ? quickstartCard(
          'No network activity captured yet',
          'Stats are truthful and currently empty. Use the quickstart command below to produce the first verifiable run.'
        )
      : ''}

    <div class="card">
      <p class="section-title">Reliability Status</p>
      <p class="${state.tone}" style="font-size:1.15rem; font-weight:700">${esc(state.label)}</p>
      <p class="dim" style="margin-top:0.35rem">${esc(state.summary)}</p>
      <div style="margin-top:0.75rem; display:flex; flex-wrap:wrap; gap:0.75rem">
        <a href="/runs?status=FAIL">Open failure feed</a>
        <a href="/runs">Open full runs feed</a>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Recent Failures</p>
      ${runsFeed(recentFailures, {
        title: 'No failures in recent feed window',
        empty: 'No failed runs in the recent feed window.',
      })}
    </div>

    <div class="card">
      <p class="section-title">Top Failure Reason Codes (24h)</p>
      ${failReasonRows(data.stats.top_fail_reason_codes, data.stats.fail_runs_24h)}
    </div>

    <div class="card">
      <p class="section-title">Recent Activity</p>
      ${runsFeed(data.recent_runs, {
        title: 'No recent activity',
        empty: 'No recent activity.',
      })}
    </div>
  `;

  return layout(meta, body);
}
