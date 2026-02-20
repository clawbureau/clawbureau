import { esc, layout, type PageMeta } from '../layout.js';
import type { ArenaRoiEnhancedDashboardView } from '../api.js';

function pct(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}

function usd(value: number): string {
  return `$${value.toFixed(4)}`;
}

function num(value: number): string {
  return value.toFixed(2);
}

function metricChip(label: string, value: string, status?: 'good' | 'warn' | 'bad'): string {
  const colorClass = status === 'good' ? 'style="color:#4ade80"'
    : status === 'bad' ? 'style="color:#f87171"'
    : status === 'warn' ? 'style="color:#fbbf24"'
    : '';
  return `
    <div class="diag-chip">
      <span class="diag-chip-label">${esc(label)}</span>
      <span class="diag-chip-value" ${colorClass}>${esc(value)}</span>
    </div>`;
}

function renderPercentilesTable(p: ArenaRoiEnhancedDashboardView['cycle_time_percentiles']): string {
  if (!p) return '<p class="dim">No cycle time data available.</p>';
  return `
    <table class="runs-table">
      <thead><tr>
        <th>Min</th><th>p50</th><th>p75</th><th>p90</th><th>p95</th><th>Max</th><th>Samples</th>
      </tr></thead>
      <tbody><tr>
        <td>${num(p.min)}</td><td>${num(p.p50)}</td><td>${num(p.p75)}</td>
        <td>${num(p.p90)}</td><td>${num(p.p95)}</td><td>${num(p.max)}</td>
        <td>${p.count}</td>
      </tr></tbody>
    </table>`;
}

function renderDailyBuckets(buckets: ArenaRoiEnhancedDashboardView['daily_buckets']): string {
  if (buckets.length === 0) return '<p class="dim">No daily data available.</p>';
  const rows = buckets.map((b) => `
    <tr>
      <td>${esc(b.date)}</td>
      <td>${b.outcomes}</td>
      <td>${b.accepted}</td>
      <td>${pct(b.accept_rate)}</td>
      <td>${b.cycle_time_p50 !== null ? num(b.cycle_time_p50) : '—'}</td>
    </tr>`).join('');

  return `
    <table class="runs-table">
      <thead><tr>
        <th>Date</th><th>Outcomes</th><th>Accepted</th><th>Accept Rate</th><th>Cycle p50 (min)</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderContenderCosts(costs: ArenaRoiEnhancedDashboardView['contender_costs']): string {
  if (costs.length === 0) return '<p class="dim">No contender cost data available.</p>';
  const rows = costs.map((c) => `
    <tr>
      <td><code>${esc(c.contender_id)}</code></td>
      <td>${c.outcomes}</td>
      <td>${c.accepted}</td>
      <td>${c.wins}</td>
      <td>${usd(c.total_cost_usd)}</td>
      <td>${c.cost_per_accepted_usd !== null ? usd(c.cost_per_accepted_usd) : '—'}</td>
    </tr>`).join('');

  return `
    <table class="runs-table">
      <thead><tr>
        <th>Contender</th><th>Outcomes</th><th>Accepted</th><th>Wins</th><th>Total Cost</th><th>Cost/Accepted</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderReasonDrilldown(drilldown: ArenaRoiEnhancedDashboardView['reason_code_drilldown']): string {
  if (drilldown.length === 0) return '<p class="dim">No failure reason codes recorded.</p>';
  const rows = drilldown.map((r) => `
    <tr>
      <td><code>${esc(r.reason_code)}</code></td>
      <td>${r.count}</td>
      <td>${pct(r.share)}</td>
    </tr>`).join('');

  return `
    <table class="runs-table">
      <thead><tr>
        <th>Reason Code</th><th>Count</th><th>Share</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderWindowMetrics(label: string, w: ArenaRoiEnhancedDashboardView['trends']['window_7d']): string {
  if (w.status !== 'available' || !w.metrics) {
    return `
      <div class="card" style="padding:0.8rem">
        <h4 style="margin:0 0 0.3rem">${esc(label)}</h4>
        <p class="dim">${esc(w.status)} (${w.sample_count} samples)</p>
      </div>`;
  }
  const m = w.metrics;
  return `
    <div class="card" style="padding:0.8rem">
      <h4 style="margin:0 0 0.5rem">${esc(label)} <span class="dim">(${w.sample_count} samples)</span></h4>
      <div class="diag-chips">
        ${metricChip('Accept Rate', pct(m.first_pass_accept_rate), m.first_pass_accept_rate >= 0.7 ? 'good' : m.first_pass_accept_rate >= 0.4 ? 'warn' : 'bad')}
        ${metricChip('Override Rate', pct(m.override_rate), m.override_rate <= 0.1 ? 'good' : m.override_rate <= 0.3 ? 'warn' : 'bad')}
        ${metricChip('Rework Rate', pct(m.rework_rate), m.rework_rate <= 0.1 ? 'good' : m.rework_rate <= 0.25 ? 'warn' : 'bad')}
        ${metricChip('Cost/Accepted', usd(m.cost_per_accepted_bounty_usd))}
        ${metricChip('Cycle Time', num(m.cycle_time_minutes) + ' min')}
        ${metricChip('Winner Stability', pct(m.winner_stability))}
      </div>
    </div>`;
}

export function arenaRoiPage(dashboard: ArenaRoiEnhancedDashboardView): string {
  const m = dashboard.metrics;
  const statusColor = dashboard.status === 'available' ? '#4ade80' : '#fbbf24';

  const content = `
    <div style="margin-bottom:1.5rem">
      <h2 style="margin:0 0 0.3rem">Arena ROI Dashboard</h2>
      <p class="dim" style="margin:0">
        Status: <span style="color:${statusColor};font-weight:600">${esc(dashboard.status)}</span>
        &mdash; computed ${esc(dashboard.computed_at.replace('T', ' ').slice(0, 19))} UTC
      </p>
      <p class="dim" style="margin:0.2rem 0 0">
        ${dashboard.totals.sample_count} outcomes across ${dashboard.totals.arena_count} arenas
        (${dashboard.totals.available_runs} available runs)
      </p>
    </div>

    ${m ? `
    <section style="margin-bottom:1.5rem">
      <h3>Key Metrics</h3>
      <div class="diag-chips">
        ${metricChip('First-Pass Accept', pct(m.first_pass_accept_rate), m.first_pass_accept_rate >= 0.7 ? 'good' : m.first_pass_accept_rate >= 0.4 ? 'warn' : 'bad')}
        ${metricChip('Override Rate', pct(m.override_rate), m.override_rate <= 0.1 ? 'good' : m.override_rate <= 0.3 ? 'warn' : 'bad')}
        ${metricChip('Rework Rate', pct(m.rework_rate), m.rework_rate <= 0.1 ? 'good' : m.rework_rate <= 0.25 ? 'warn' : 'bad')}
        ${metricChip('Cost/Accepted', usd(m.cost_per_accepted_bounty_usd))}
        ${metricChip('Median Review', num(m.median_review_time_minutes) + ' min')}
        ${metricChip('Cycle Time', num(m.cycle_time_minutes) + ' min')}
        ${metricChip('Winner Stability', pct(m.winner_stability))}
        ${metricChip('Accepted Outcomes', String((m as unknown as Record<string, unknown>).accepted_outcomes ?? 0))}
      </div>
    </section>` : '<p class="dim">Metrics unavailable (insufficient samples).</p>'}

    <section style="margin-bottom:1.5rem">
      <h3>Cycle Time Distribution (minutes)</h3>
      ${renderPercentilesTable(dashboard.cycle_time_percentiles)}
    </section>

    <section style="margin-bottom:1.5rem">
      <h3>Trend Windows</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
        ${renderWindowMetrics('Last 7 Days', dashboard.trends.window_7d)}
        ${renderWindowMetrics('Last 30 Days', dashboard.trends.window_30d)}
      </div>
    </section>

    <section style="margin-bottom:1.5rem">
      <h3>Daily Throughput</h3>
      ${renderDailyBuckets(dashboard.daily_buckets)}
    </section>

    <section style="margin-bottom:1.5rem">
      <h3>Contender Cost Comparison</h3>
      ${renderContenderCosts(dashboard.contender_costs)}
    </section>

    <section style="margin-bottom:1.5rem">
      <h3>Failure Reason Drilldown</h3>
      ${renderReasonDrilldown(dashboard.reason_code_drilldown)}
    </section>

    <div style="margin-top:1rem">
      <a href="/arena" style="color:#60a5fa">&larr; Back to Arena</a>
      &nbsp;|&nbsp;
      <a href="/arena/mission" style="color:#60a5fa">Mission Dashboard</a>
    </div>
  `;

  const meta: PageMeta = {
    title: 'Arena ROI Dashboard',
    description: 'Real-time ROI metrics for arena bounty operations',
    path: '/arena/roi',
  };

  return layout(meta, content);
}

export function arenaRoiUnavailablePage(): string {
  const content = `
    <h2>Arena ROI Dashboard</h2>
    <p class="dim">ROI dashboard data is currently unavailable. The upstream bounties service may be unreachable or has no outcome data.</p>
    <a href="/arena" style="color:#60a5fa">&larr; Back to Arena</a>
  `;
  const meta: PageMeta = { title: 'Arena ROI Dashboard', description: 'ROI unavailable', path: '/arena/roi' };
  return layout(meta, content);
}
