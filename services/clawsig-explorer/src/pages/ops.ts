import { layout, esc, fmtNum, type PageMeta } from '../layout.js';
import type { GlobalStats, FailReasonCode } from './home.js';
import type {
  DomainHealthProbe,
  SyntheticWorkflowStatus,
  WorkflowRunHistoryItem,
  RunsFeedRun,
} from '../api.js';
import type { OpsSloHealth } from '../slo.js';

export interface OpsPageData {
  stats: GlobalStats;
  domain_health: DomainHealthProbe[];
  synthetic_statuses: SyntheticWorkflowStatus[];
  synthetic_history: WorkflowRunHistoryItem[];
  canary_history: WorkflowRunHistoryItem[];
  guarded_deploy_history: WorkflowRunHistoryItem[];
  recent_failed_runs: RunsFeedRun[];
  slo_health: OpsSloHealth;
}

function healthBadge(ok: boolean): string {
  return ok
    ? '<span class="status-badge pass"><span class="dot"></span>healthy</span>'
    : '<span class="status-badge fail"><span class="dot"></span>degraded</span>';
}

function syntheticBadge(status: SyntheticWorkflowStatus): string {
  if (status.ok === true) {
    return '<span class="status-badge pass"><span class="dot"></span>pass</span>';
  }
  if (status.ok === false) {
    return '<span class="status-badge fail"><span class="dot"></span>fail</span>';
  }
  return '<span class="status-badge warn"><span class="dot"></span>unknown</span>';
}

function sloSeverityBadge(sloHealth: OpsSloHealth): string {
  if (sloHealth.severity === 'critical') {
    return '<span class="status-badge fail"><span class="dot"></span>critical</span>';
  }
  if (sloHealth.severity === 'warn') {
    return '<span class="status-badge warn"><span class="dot"></span>warn</span>';
  }
  return '<span class="status-badge pass"><span class="dot"></span>healthy</span>';
}

function formatPct(value: number): string {
  return `${(value * 100).toFixed(2)}%`;
}

function formatBurnRate(value: number): string {
  return `${value.toFixed(2)}x`;
}

function reasonsList(
  rows: FailReasonCode[],
  label: string,
  baseRuns: number,
): string {
  if (rows.length === 0) {
    return `<p class="dim">No ${esc(label)} failures recorded.</p>`;
  }

  return rows
    .map((row) => {
      const pct = baseRuns > 0 ? (row.count / baseRuns) * 100 : 0;
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

function syntheticRows(rows: SyntheticWorkflowStatus[]): string {
  return rows
    .map((row) => {
      const label = row.workflow;
      const updated = row.updated_at ? row.updated_at : 'unknown';
      const statusText = row.conclusion ?? row.status ?? 'unknown';
      return `
      <div class="run-item" style="align-items:center; flex-wrap:wrap">
        <span class="hash">${esc(label)}</span>
        ${syntheticBadge(row)}
        <span class="run-meta dim" style="font-size:0.8125rem">${esc(statusText)} · ${esc(updated)}</span>
        ${row.html_url
          ? `<a href="${esc(row.html_url)}" target="_blank" rel="noopener" style="margin-left:auto; font-size:0.8125rem">Open run &rarr;</a>`
          : '<span class="dim" style="margin-left:auto; font-size:0.8125rem">No run metadata</span>'}
      </div>
    `;
    })
    .join('');
}

function historyDotClass(conclusion: string | null): 'pass' | 'fail' | 'warn' {
  if (conclusion === 'success') return 'pass';
  if (conclusion === 'failure' || conclusion === 'cancelled' || conclusion === 'timed_out') return 'fail';
  return 'warn';
}

function historyTrend(rows: WorkflowRunHistoryItem[]): string {
  if (rows.length === 0) {
    return '<span class="dim" style="font-size:0.8125rem">No workflow trend data available.</span>';
  }

  const dots = rows
    .slice(0, 12)
    .map((row) => {
      const cls = historyDotClass(row.conclusion);
      const title = `${row.conclusion ?? row.status ?? 'unknown'} · ${row.updated_at ?? 'n/a'}`;
      return `<span title="${esc(title)}" style="width:10px;height:10px;border-radius:999px;display:inline-block;background:var(--${cls});opacity:0.9"></span>`;
    })
    .join('');

  return `<span style="display:inline-flex;gap:0.35rem;align-items:center">${dots}</span>`;
}

function workflowHistoryRows(rows: WorkflowRunHistoryItem[], emptyLabel: string): string {
  if (rows.length === 0) {
    return `<p class="dim">${esc(emptyLabel)}</p>`;
  }

  return rows
    .slice(0, 8)
    .map((row) => {
      const statusText = row.conclusion ?? row.status ?? 'unknown';
      const shaShort = row.head_sha ? row.head_sha.slice(0, 8) : 'n/a';
      return `
      <div class="run-item" style="align-items:center; flex-wrap:wrap">
        <span class="hash">${esc(statusText)}</span>
        <span class="run-meta dim" style="font-size:0.8125rem">${esc(row.updated_at ?? 'unknown')} · ${esc(shaShort)}</span>
        ${row.html_url
          ? `<a href="${esc(row.html_url)}" target="_blank" rel="noopener" style="margin-left:auto; font-size:0.8125rem">Open run &rarr;</a>`
          : '<span class="dim" style="margin-left:auto; font-size:0.8125rem">No run metadata</span>'}
      </div>
    `;
    })
    .join('');
}

function recentFailedRunsRows(rows: RunsFeedRun[]): string {
  if (rows.length === 0) {
    return '<p class="dim">No failed runs available for drilldown.</p>';
  }

  return rows
    .slice(0, 10)
    .map((run) => {
      const reasonCode = run.reason_code ?? 'UNKNOWN_REASON';
      return `
      <div class="run-item" style="align-items:center; flex-wrap:wrap">
        <a class="mono" href="/run/${encodeURIComponent(run.run_id)}">${esc(run.run_id)}</a>
        <a class="hash" href="/runs?status=FAIL&reason_code=${encodeURIComponent(reasonCode)}">${esc(reasonCode)}</a>
        <span class="run-meta dim" style="font-size:0.8125rem">${esc(run.agent_did)} · ${esc(run.created_at)}</span>
        <a href="/runs?status=FAIL&agent_did=${encodeURIComponent(run.agent_did)}" style="margin-left:auto; font-size:0.8125rem">Agent fail route &rarr;</a>
      </div>
    `;
    })
    .join('');
}

function latestArtifactLinks(data: OpsPageData): string {
  const latest = [
    ['Synthetic smoke', data.synthetic_history[0]],
    ['Canary seed', data.canary_history[0]],
    ['Guarded deploy', data.guarded_deploy_history[0]],
  ] as const;

  const links = latest
    .filter(([, row]) => Boolean(row?.artifacts_url))
    .map(([label, row]) => `<a href="${esc(row!.artifacts_url!)}" target="_blank" rel="noopener">${esc(label)} artifacts &rarr;</a>`);

  if (links.length === 0) {
    return '<p class="dim">No workflow artifact links available.</p>';
  }

  return `<div style="display:flex; gap:0.75rem; flex-wrap:wrap">${links.join('')}</div>`;
}

export function opsDashboardPage(data: OpsPageData): string {
  const meta: PageMeta = {
    title: 'Ops Dashboard',
    description: 'Operator view for health, synthetic monitors, and diagnostics trends.',
    path: '/ops',
  };

  const failRate24h = data.stats.fail_rate_24h;
  const failRate7d = data.stats.diagnostics_7d.fail_rate_7d;

  const body = `
    <h1 class="page-title">Operations Dashboard</h1>
    <p class="page-subtitle">Domain health, synthetic checks, and fail diagnostics in one place.</p>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="value">${formatPct(failRate24h)}</div>
        <div class="label">Fail Rate (24h)</div>
      </div>
      <div class="stat-card">
        <div class="value">${formatPct(failRate7d)}</div>
        <div class="label">Fail Rate (7d)</div>
      </div>
      <div class="stat-card">
        <div class="value">${fmtNum(data.stats.fail_runs_24h)}</div>
        <div class="label">Fail Runs (24h)</div>
      </div>
      <div class="stat-card">
        <div class="value">${fmtNum(data.stats.diagnostics_7d.fail_runs_7d)}</div>
        <div class="label">Fail Runs (7d)</div>
      </div>
    </div>

    <div class="card">
      <p class="section-title">SLO Burn-Rate Guardrails</p>
      <div style="display:flex; gap:0.7rem; align-items:center; flex-wrap:wrap; margin-bottom:0.75rem">
        ${sloSeverityBadge(data.slo_health)}
        <span class="hash">${esc(data.slo_health.reason_code)}</span>
        <a href="/ops/slo-health.json" target="_blank" rel="noopener" style="font-size:0.8125rem">Machine-readable JSON &rarr;</a>
      </div>
      <div class="stats-grid" style="margin-bottom:0.75rem">
        <div class="stat-card">
          <div class="value">${formatBurnRate(data.slo_health.windows.window_24h.burn_rate)}</div>
          <div class="label">Burn Rate (24h)</div>
        </div>
        <div class="stat-card">
          <div class="value">${formatBurnRate(data.slo_health.windows.window_7d.burn_rate)}</div>
          <div class="label">Burn Rate (7d)</div>
        </div>
        <div class="stat-card">
          <div class="value">${formatPct(data.slo_health.windows.window_24h.error_budget_fraction)}</div>
          <div class="label">Error Budget</div>
        </div>
        <div class="stat-card">
          <div class="value">${formatPct(data.slo_health.target_success_rate)}</div>
          <div class="label">SLO Target</div>
        </div>
      </div>
      <p class="dim" style="font-size:0.8125rem">Thresholds: warn(24h ${data.slo_health.thresholds.warn_burn_rate_24h.toFixed(2)}x / 7d ${data.slo_health.thresholds.warn_burn_rate_7d.toFixed(2)}x), critical(24h ${data.slo_health.thresholds.critical_burn_rate_24h.toFixed(2)}x / 7d ${data.slo_health.thresholds.critical_burn_rate_7d.toFixed(2)}x).</p>
    </div>

    <div class="card">
      <p class="section-title">Domain Health</p>
      ${data.domain_health.map((row) => `
        <div class="run-item" style="align-items:center; flex-wrap:wrap">
          <span class="hash">${esc(row.host)}</span>
          ${healthBadge(row.ok)}
          <span class="run-meta dim" style="font-size:0.8125rem">${row.status ?? 'n/a'} · ${row.latency_ms}ms · ${esc(row.reason_code)}</span>
          <a href="${esc(row.url)}" target="_blank" rel="noopener" style="margin-left:auto; font-size:0.8125rem">Open health &rarr;</a>
        </div>
      `).join('')}
    </div>

    <div class="card">
      <p class="section-title">Latest Synthetic Status</p>
      ${syntheticRows(data.synthetic_statuses)}
      <div style="margin-top:0.75rem; display:flex; gap:0.75rem; flex-wrap:wrap">
        <a href="https://github.com/clawbureau/clawbureau/actions/workflows/clawsig-surface-synthetic-smoke.yml" target="_blank" rel="noopener">Synthetic workflow history &rarr;</a>
        <a href="https://github.com/clawbureau/clawbureau/actions/workflows/clawsig-canary-seed.yml" target="_blank" rel="noopener">Canary seeding workflow &rarr;</a>
        <a href="https://github.com/clawbureau/clawbureau/actions/workflows/clawsig-guarded-deploy.yml" target="_blank" rel="noopener">Guarded deploy workflow &rarr;</a>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Synthetic Trend (latest runs)</p>
      <div style="display:grid; gap:0.7rem">
        <div>
          <p class="dim" style="font-size:0.75rem; margin-bottom:0.35rem">Surface smoke</p>
          ${historyTrend(data.synthetic_history)}
        </div>
        <div>
          <p class="dim" style="font-size:0.75rem; margin-bottom:0.35rem">Canary seed</p>
          ${historyTrend(data.canary_history)}
        </div>
        <div>
          <p class="dim" style="font-size:0.75rem; margin-bottom:0.35rem">Guarded deploy</p>
          ${historyTrend(data.guarded_deploy_history)}
        </div>
      </div>
    </div>

    <div class="card">
      <p class="section-title">Synthetic Run History</p>
      ${workflowHistoryRows(data.synthetic_history, 'No synthetic workflow history available.')}
    </div>

    <div class="card">
      <p class="section-title">Canary Seed History</p>
      ${workflowHistoryRows(data.canary_history, 'No canary history available.')}
    </div>

    <div class="card">
      <p class="section-title">Guarded Deploy History</p>
      ${workflowHistoryRows(data.guarded_deploy_history, 'No guarded deploy history available.')}
    </div>

    <div class="card">
      <p class="section-title">Recent Failed Routes + Reason Codes</p>
      ${recentFailedRunsRows(data.recent_failed_runs)}
    </div>

    <div class="card">
      <p class="section-title">Latest Artifact Bundles</p>
      ${latestArtifactLinks(data)}
    </div>

    <div class="card">
      <p class="section-title">Top Fail Reasons (24h)</p>
      ${reasonsList(data.stats.top_fail_reason_codes, '24h', data.stats.fail_runs_24h)}
    </div>

    <div class="card">
      <p class="section-title">Top Fail Reasons (7d)</p>
      ${reasonsList(
        data.stats.diagnostics_7d.top_fail_reason_codes_7d,
        '7d',
        data.stats.diagnostics_7d.fail_runs_7d,
      )}
    </div>

    <div class="card">
      <p class="section-title">Triage Entry Points</p>
      <div style="display:flex; gap:0.75rem; flex-wrap:wrap">
        <a href="/runs?status=FAIL">Open fail feed</a>
        <a href="/runs">Open all runs</a>
        <a href="/stats">Open network stats</a>
      </div>
    </div>
  `;

  return layout(meta, body);
}
