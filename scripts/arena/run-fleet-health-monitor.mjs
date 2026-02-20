#!/usr/bin/env node
/**
 * AGP-US-085: Fleet Health Monitor
 *
 * Fetches fleet health status from clawbounties and reports alerts.
 * Designed for cron / CI / ops dashboard consumption.
 *
 * Usage:
 *   ADMIN_KEY=... BASE_URL=... node scripts/arena/run-fleet-health-monitor.mjs
 *
 * Exit codes:
 *   0 = healthy or degraded (warnings only)
 *   2 = critical alerts present
 *   1 = fetch failure
 */

const BASE_URL = process.env.BASE_URL || 'https://staging.clawbounties.com';
const ADMIN_KEY = process.env.ADMIN_KEY || '';

import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';

async function fetchFleetHealth() {
  const res = await fetch(`${BASE_URL}/v1/arena/desk/fleet-health`, {
    headers: {
      'x-admin-key': ADMIN_KEY,
      'Accept': 'application/json',
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Fleet health fetch failed: ${res.status} ${text.slice(0, 200)}`);
  }

  return res.json();
}

async function main() {
  if (!ADMIN_KEY) {
    console.error('ADMIN_KEY is required');
    process.exit(1);
  }

  console.log(`Fetching fleet health from ${BASE_URL}...`);
  const health = await fetchFleetHealth();

  const summary = {
    schema_version: 'arena_fleet_health_report.v1',
    generated_at: new Date().toISOString(),
    base_url: BASE_URL,
    fleet_status: health.status,
    alert_count: health.alert_count,
    critical_count: health.critical_count,
    warning_count: health.warning_count,
    alerts: health.alerts ?? [],
    fleet_summary: health.fleet_summary ?? {},
  };

  console.log(JSON.stringify(summary, null, 2));

  const outDir = process.env.OUT_DIR;
  if (outDir) {
    await mkdir(outDir, { recursive: true });
    await writeFile(join(outDir, 'summary.json'), JSON.stringify(summary, null, 2));
    await writeFile(join(outDir, 'full-health.json'), JSON.stringify(health, null, 2));
    console.log(`\nArtifacts written to ${outDir}`);
  }

  if (health.status === 'critical') {
    console.error(`\nFLEET STATUS: CRITICAL — ${health.critical_count} critical alert(s)`);
    for (const a of (health.alerts ?? []).filter((a) => a.severity === 'critical')) {
      console.error(`  [${a.code}] ${a.message}`);
    }
    process.exit(2);
  }

  if (health.status === 'degraded') {
    console.warn(`\nFLEET STATUS: DEGRADED — ${health.warning_count} warning(s)`);
    for (const a of (health.alerts ?? []).filter((a) => a.severity === 'warning')) {
      console.warn(`  [${a.code}] ${a.message}`);
    }
  } else {
    console.log(`\nFLEET STATUS: HEALTHY`);
  }

  process.exit(0);
}

main().catch((err) => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
