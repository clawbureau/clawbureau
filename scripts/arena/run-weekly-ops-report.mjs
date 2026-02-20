#!/usr/bin/env node
/**
 * AGP-US-086: Weekly Ops Report Generator
 *
 * Aggregates ROI dashboard, fleet health, and duel league data
 * into a single weekly ops report.
 *
 * Usage:
 *   ADMIN_KEY=... BASE_URL=... node scripts/arena/run-weekly-ops-report.mjs
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

async function fetchJson(path) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'x-admin-key': ADMIN_KEY, 'Accept': 'application/json' },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    return { _error: true, status: res.status, body: text.slice(0, 200) };
  }
  return res.json();
}

function deriveWeekRange() {
  const now = new Date();
  const weekEnd = now.toISOString().slice(0, 10);
  const weekStart = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  return { weekStart, weekEnd, generatedAt: now.toISOString() };
}

function extractRoiSummary(roi) {
  if (roi._error) return { available: false, error: `${roi.status}: ${roi.body}` };
  const m = roi.metrics;
  if (!m) return { available: false, reason: roi.status };
  return {
    available: true,
    status: roi.status,
    sample_count: roi.totals?.sample_count ?? 0,
    arena_count: roi.totals?.arena_count ?? 0,
    first_pass_accept_rate: m.first_pass_accept_rate,
    override_rate: m.override_rate,
    rework_rate: m.rework_rate,
    cost_per_accepted_bounty_usd: m.cost_per_accepted_bounty_usd,
    cycle_time_median_minutes: m.cycle_time_minutes,
    winner_stability: m.winner_stability,
    cycle_time_percentiles: roi.cycle_time_percentiles ?? null,
    contender_costs: roi.contender_costs ?? [],
    daily_buckets: roi.daily_buckets ?? [],
    trend_7d: roi.trends?.window_7d ?? null,
  };
}

function extractHealthSummary(health) {
  if (health._error) return { available: false, error: `${health.status}: ${health.body}` };
  return {
    available: true,
    status: health.status,
    alert_count: health.alert_count,
    critical_count: health.critical_count,
    warning_count: health.warning_count,
    alerts: (health.alerts ?? []).map((a) => ({ code: a.code, severity: a.severity })),
    fleet_summary: health.fleet_summary ?? {},
  };
}

function extractLeagueSummary(league) {
  if (league._error) return { available: false, error: `${league.status}: ${league.body}` };
  const entries = Array.isArray(league.league) ? league.league : [];
  return {
    available: true,
    total_contenders: entries.length,
    leader: entries.length > 0 ? {
      contender_id: entries[0].contender_id,
      win_rate: entries[0].win_rate,
      total_runs: entries[0].total_runs,
    } : null,
    standings: entries.slice(0, 5).map((e) => ({
      contender_id: e.contender_id,
      wins: e.wins,
      losses: e.losses,
      draws: e.draws,
      win_rate: e.win_rate,
    })),
  };
}

function deriveOverallGrade(roi, health) {
  if (!roi.available || !health.available) return 'INCOMPLETE';
  if (health.critical_count > 0) return 'CRITICAL';
  if (health.warning_count > 0 || roi.first_pass_accept_rate < 0.5) return 'NEEDS_ATTENTION';
  if (roi.first_pass_accept_rate >= 0.7 && roi.override_rate <= 0.1) return 'EXCELLENT';
  return 'GOOD';
}

async function main() {
  if (!ADMIN_KEY) {
    console.error('ADMIN_KEY is required');
    process.exit(1);
  }

  console.log(`Generating weekly ops report from ${BASE_URL}...`);
  const { weekStart, weekEnd, generatedAt } = deriveWeekRange();

  // Fetch all data sources in parallel
  const [roi, health, league] = await Promise.all([
    fetchJson('/v1/arena/roi-dashboard'),
    fetchJson('/v1/arena/desk/fleet-health'),
    fetchJson('/v1/arena/duel-league'),
  ]);

  const roiSummary = extractRoiSummary(roi);
  const healthSummary = extractHealthSummary(health);
  const leagueSummary = extractLeagueSummary(league);
  const grade = deriveOverallGrade(roiSummary, healthSummary);

  const report = {
    schema_version: 'arena_weekly_ops_report.v1',
    generated_at: generatedAt,
    base_url: BASE_URL,
    week: { start: weekStart, end: weekEnd },
    overall_grade: grade,
    roi: roiSummary,
    fleet_health: healthSummary,
    duel_league: leagueSummary,
    recommendations: generateRecommendations(roiSummary, healthSummary, leagueSummary),
  };

  console.log(JSON.stringify(report, null, 2));

  const outDir = process.env.OUT_DIR;
  if (outDir) {
    await mkdir(outDir, { recursive: true });
    await writeFile(join(outDir, 'weekly-report.json'), JSON.stringify(report, null, 2));
    await writeFile(join(outDir, 'raw-roi.json'), JSON.stringify(roi, null, 2));
    await writeFile(join(outDir, 'raw-health.json'), JSON.stringify(health, null, 2));
    await writeFile(join(outDir, 'raw-league.json'), JSON.stringify(league, null, 2));
    console.log(`\nArtifacts written to ${outDir}`);
  }

  process.exit(grade === 'CRITICAL' ? 2 : 0);
}

function generateRecommendations(roi, health, league) {
  const recs = [];
  if (!roi.available) {
    recs.push({ priority: 'high', action: 'Investigate ROI data availability — ensure outcome seeder is running' });
  } else {
    if (roi.first_pass_accept_rate < 0.5) {
      recs.push({ priority: 'high', action: `Improve first-pass accept rate (currently ${(roi.first_pass_accept_rate * 100).toFixed(1)}%) — review contract language and calibration` });
    }
    if (roi.override_rate > 0.25) {
      recs.push({ priority: 'medium', action: `Reduce override rate (currently ${(roi.override_rate * 100).toFixed(1)}%) — investigate top failure reason codes` });
    }
    if (roi.rework_rate > 0.2) {
      recs.push({ priority: 'medium', action: `Reduce rework rate (currently ${(roi.rework_rate * 100).toFixed(1)}%)` });
    }
    if (roi.cost_per_accepted_bounty_usd > 1.0) {
      recs.push({ priority: 'low', action: `Cost per accepted bounty ($${roi.cost_per_accepted_bounty_usd.toFixed(4)}) is above $1.00 — evaluate contender efficiency` });
    }
  }

  if (health.available) {
    for (const alert of health.alerts ?? []) {
      if (alert.severity === 'critical') {
        recs.push({ priority: 'high', action: `Resolve critical alert: ${alert.code}` });
      }
    }
  }

  if (league.available && league.total_contenders < 2) {
    recs.push({ priority: 'medium', action: 'Register additional contenders — competition improves quality' });
  }

  if (recs.length === 0) {
    recs.push({ priority: 'info', action: 'All metrics within normal range. Continue monitoring.' });
  }

  return recs;
}

main().catch((err) => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
