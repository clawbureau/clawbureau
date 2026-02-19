import { layout, esc, fmtNum, type PageMeta } from '../layout.js';
import type { GlobalStats, FailReasonCode } from './home.js';
import type { DomainHealthProbe, SyntheticWorkflowStatus } from '../api.js';

export interface OpsPageData {
  stats: GlobalStats;
  domain_health: DomainHealthProbe[];
  synthetic_statuses: SyntheticWorkflowStatus[];
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
        <div class="value">${(failRate24h * 100).toFixed(2)}%</div>
        <div class="label">Fail Rate (24h)</div>
      </div>
      <div class="stat-card">
        <div class="value">${(failRate7d * 100).toFixed(2)}%</div>
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
      </div>
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
