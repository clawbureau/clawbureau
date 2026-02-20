#!/usr/bin/env node
/**
 * AGP-US-081: Monitor continuous resolver cron status.
 * Polls resolver-cron-status endpoint and captures pending backlog metrics.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    cycles: 3,
    intervalMs: 60_000,
    dryRun: false,
    outputPath: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--bounties-base') { args.bountiesBase = argv[++i] ?? args.bountiesBase; continue; }
    if (arg === '--admin-key') { args.adminKey = argv[++i] ?? ''; continue; }
    if (arg === '--cycles') { args.cycles = Number.parseInt(argv[++i] ?? '3', 10); continue; }
    if (arg === '--interval-ms') { args.intervalMs = Number.parseInt(argv[++i] ?? '60000', 10); continue; }
    if (arg === '--dry-run') { args.dryRun = true; continue; }
    if (arg === '--output') { args.outputPath = argv[++i] ?? null; continue; }
  }
  if (!args.adminKey) throw new Error('Missing admin key. Pass --admin-key or set BOUNTIES_ADMIN_KEY.');
  return args;
}

function nowLabel() { return new Date().toISOString().replace(/[:.]/g, '-'); }

function defaultOutputPath() {
  return path.join(process.cwd(), 'artifacts', 'ops', 'arena-productization',
    `${nowLabel()}-agp-us-081-resolver-cron-monitor`, 'summary.json');
}

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

async function fetchCronStatus(base, adminKey) {
  const url = `${base.replace(/\/$/, '')}/v1/arena/desk/resolver-cron-status`;
  const res = await fetch(url, { headers: { 'x-admin-key': adminKey } });
  const text = await res.text();
  let payload;
  try { payload = JSON.parse(text); } catch { payload = { raw: text }; }
  return { status: res.status, payload };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.dryRun) {
    const preview = {
      ok: true, story: 'AGP-US-081', dry_run: true,
      generated_at: new Date().toISOString(),
      endpoint: `${args.bountiesBase}/v1/arena/desk/resolver-cron-status`,
      cycles: args.cycles, interval_ms: args.intervalMs,
    };
    const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, JSON.stringify(preview, null, 2) + '\n');
    process.stdout.write(`ARENA_RESOLVER_CRON_MONITOR_RESULT ${outputPath}\n`);
    process.stdout.write(JSON.stringify({ dry_run: true }) + '\n');
    return;
  }

  const snapshots = [];
  for (let cycle = 0; cycle < args.cycles; cycle += 1) {
    if (cycle > 0) await sleep(args.intervalMs);
    const result = await fetchCronStatus(args.bountiesBase, args.adminKey);
    const snapshot = {
      cycle: cycle + 1,
      captured_at: new Date().toISOString(),
      http_status: result.status,
      cron_enabled: result.payload?.cron_enabled ?? null,
      pending_total: result.payload?.pending_backlog?.pending_count ?? result.payload?.pending_backlog?.total ?? null,
      pending_oldest_age_minutes: result.payload?.pending_backlog?.oldest_age_minutes ?? null,
      pending_p95_age_minutes: result.payload?.pending_backlog?.p95_pending_age_minutes ?? result.payload?.pending_backlog?.p95_age_minutes ?? null,
    };
    snapshots.push(snapshot);
    process.stdout.write(`cycle=${cycle + 1} pending=${snapshot.pending_total} oldest=${snapshot.pending_oldest_age_minutes}\n`);
  }

  const drainedToZero = snapshots.some((s) => s.pending_total === 0);
  const allCronEnabled = snapshots.every((s) => s.cron_enabled === true);
  const pendingDecreasing = snapshots.length >= 2 &&
    (snapshots[snapshots.length - 1].pending_total ?? Infinity) <=
    (snapshots[0].pending_total ?? Infinity);

  const summary = {
    ok: allCronEnabled && (drainedToZero || pendingDecreasing),
    story: 'AGP-US-081',
    generated_at: new Date().toISOString(),
    endpoint_base: args.bountiesBase,
    cycles_captured: snapshots.length,
    drained_to_zero: drainedToZero,
    pending_decreasing: pendingDecreasing,
    all_cron_enabled: allCronEnabled,
    snapshots,
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(summary, null, 2) + '\n');
  process.stdout.write(`ARENA_RESOLVER_CRON_MONITOR_RESULT ${outputPath}\n`);
  process.stdout.write(JSON.stringify({ ok: summary.ok, drained_to_zero: drainedToZero, pending_decreasing: pendingDecreasing }) + '\n');
  if (!summary.ok) process.exitCode = 2;
}

main().catch((err) => {
  process.stderr.write(`run-resolver-cron-monitor failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
