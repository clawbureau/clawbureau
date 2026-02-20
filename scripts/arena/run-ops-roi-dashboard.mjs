#!/usr/bin/env node
/**
 * AGP-US-084: Ops ROI Dashboard Reporter
 *
 * Fetches enhanced ROI dashboard data from clawbounties
 * and outputs a structured summary suitable for ops reporting.
 *
 * Usage:
 *   ADMIN_KEY=... BASE_URL=... node scripts/arena/run-ops-roi-dashboard.mjs
 *
 * Environment:
 *   ADMIN_KEY   - Admin key for clawbounties
 *   BASE_URL    - Service base URL (default: https://staging.clawbounties.com)
 *   OUT_DIR     - Output directory for artifacts (optional)
 */

const BASE_URL = process.env.BASE_URL || 'https://staging.clawbounties.com';
const ADMIN_KEY = process.env.ADMIN_KEY || '';

import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';

async function fetchRoiDashboard() {
  const res = await fetch(`${BASE_URL}/v1/arena/roi-dashboard`, {
    headers: {
      'x-admin-key': ADMIN_KEY,
      'Accept': 'application/json',
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`ROI dashboard fetch failed: ${res.status} ${text.slice(0, 200)}`);
  }

  return res.json();
}

function assessHealth(dashboard) {
  const alerts = [];
  const m = dashboard.metrics;
  if (!m) return { status: 'NO_METRICS', alerts: ['No metrics available — insufficient data'] };

  if (m.first_pass_accept_rate < 0.3) {
    alerts.push(`CRITICAL: First-pass accept rate ${(m.first_pass_accept_rate * 100).toFixed(1)}% < 30%`);
  } else if (m.first_pass_accept_rate < 0.5) {
    alerts.push(`WARN: First-pass accept rate ${(m.first_pass_accept_rate * 100).toFixed(1)}% < 50%`);
  }

  if (m.override_rate > 0.4) {
    alerts.push(`CRITICAL: Override rate ${(m.override_rate * 100).toFixed(1)}% > 40%`);
  } else if (m.override_rate > 0.25) {
    alerts.push(`WARN: Override rate ${(m.override_rate * 100).toFixed(1)}% > 25%`);
  }

  if (m.rework_rate > 0.3) {
    alerts.push(`CRITICAL: Rework rate ${(m.rework_rate * 100).toFixed(1)}% > 30%`);
  }

  if (m.cost_per_accepted_bounty_usd > 1.0) {
    alerts.push(`WARN: Cost per accepted bounty $${m.cost_per_accepted_bounty_usd.toFixed(4)} > $1.00`);
  }

  const p = dashboard.cycle_time_percentiles;
  if (p && p.p95 > 60) {
    alerts.push(`WARN: p95 cycle time ${p.p95.toFixed(1)} min > 60 min`);
  }

  const status = alerts.some((a) => a.startsWith('CRITICAL')) ? 'CRITICAL'
    : alerts.length > 0 ? 'WARN'
    : 'HEALTHY';

  return { status, alerts };
}

async function main() {
  if (!ADMIN_KEY) {
    console.error('ADMIN_KEY is required');
    process.exit(1);
  }

  console.log(`Fetching ROI dashboard from ${BASE_URL}...`);
  const dashboard = await fetchRoiDashboard();

  const health = assessHealth(dashboard);

  const summary = {
    schema_version: 'arena_ops_roi_report.v1',
    generated_at: new Date().toISOString(),
    base_url: BASE_URL,
    dashboard_status: dashboard.status,
    health_status: health.status,
    alerts: health.alerts,
    totals: dashboard.totals ?? null,
    metrics: dashboard.metrics ?? null,
    cycle_time_percentiles: dashboard.cycle_time_percentiles ?? null,
    daily_bucket_count: (dashboard.daily_buckets ?? []).length,
    contender_count: (dashboard.contender_costs ?? []).length,
    contender_costs: dashboard.contender_costs ?? [],
    reason_code_drilldown: dashboard.reason_code_drilldown ?? [],
    trends: {
      window_7d_status: dashboard.trends?.window_7d?.status ?? 'unavailable',
      window_30d_status: dashboard.trends?.window_30d?.status ?? 'unavailable',
    },
  };

  console.log(JSON.stringify(summary, null, 2));

  const outDir = process.env.OUT_DIR;
  if (outDir) {
    await mkdir(outDir, { recursive: true });
    await writeFile(join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));
    await writeFile(join(outDir, 'full-dashboard.json'), JSON.stringify(dashboard, null, 2));
    console.log(`\nArtifacts written to ${outDir}`);
  }

  // Exit code reflects health
  if (health.status === 'CRITICAL') {
    console.error(`\nHEALTH: CRITICAL — ${health.alerts.length} alert(s)`);
    process.exit(2);
  }
  if (health.status === 'WARN') {
    console.warn(`\nHEALTH: WARN — ${health.alerts.length} alert(s)`);
    process.exit(0); // Warn is non-fatal
  }
  console.log('\nHEALTH: HEALTHY');
  process.exit(0);
}

main().catch((err) => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
