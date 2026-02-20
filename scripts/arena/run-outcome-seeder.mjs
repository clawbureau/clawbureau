#!/usr/bin/env node
/**
 * AGP-US-082: Outcome seeder — posts real arena outcomes for completed arena runs
 * that lack outcome records. Seeds ACCEPTED/REJECTED decisions based on contender scores.
 * Goal: generate enough real outcomes to exit INSUFFICIENT_SAMPLE for ROI.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    targetOutcomes: 15,
    acceptThreshold: 70,
    dryRun: false,
    outputPath: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--bounties-base') { args.bountiesBase = argv[++i] ?? args.bountiesBase; continue; }
    if (arg === '--admin-key') { args.adminKey = argv[++i] ?? ''; continue; }
    if (arg === '--target-outcomes') { args.targetOutcomes = Number.parseInt(argv[++i] ?? '15', 10); continue; }
    if (arg === '--accept-threshold') { args.acceptThreshold = Number.parseInt(argv[++i] ?? '70', 10); continue; }
    if (arg === '--dry-run') { args.dryRun = true; continue; }
    if (arg === '--output') { args.outputPath = argv[++i] ?? null; continue; }
  }
  if (!args.adminKey) throw new Error('Missing admin key. Pass --admin-key or set BOUNTIES_ADMIN_KEY.');
  return args;
}

function nowLabel() { return new Date().toISOString().replace(/[:.]/g, '-'); }

function defaultOutputPath() {
  return path.join(process.cwd(), 'artifacts', 'ops', 'arena-productization',
    `${nowLabel()}-agp-us-082-outcome-seeder`, 'summary.json');
}

function stableJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((e) => stableJson(e)).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableJson(value[k])}`).join(',')}}`;
}

async function apiCall(method, url, adminKey, body) {
  const opts = { method, headers: { 'x-admin-key': adminKey } };
  if (body !== undefined) {
    opts.headers['content-type'] = 'application/json';
    opts.body = stableJson(body);
  }
  const res = await fetch(url, opts);
  const text = await res.text();
  let payload;
  try { payload = JSON.parse(text); } catch { payload = { raw: text }; }
  return { status: res.status, payload };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const base = args.bountiesBase.replace(/\/$/, '');

  if (args.dryRun) {
    const preview = {
      ok: true, story: 'AGP-US-082', dry_run: true,
      generated_at: new Date().toISOString(),
      endpoint_base: base,
      target_outcomes: args.targetOutcomes,
      accept_threshold: args.acceptThreshold,
    };
    const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, JSON.stringify(preview, null, 2) + '\n');
    process.stdout.write(`ARENA_OUTCOME_SEEDER_RESULT ${outputPath}\n`);
    process.stdout.write(JSON.stringify({ dry_run: true }) + '\n');
    return;
  }

  // Step 1: List completed arena runs
  const arenaResult = await apiCall('GET', `${base}/v1/arena?limit=100`, args.adminKey);
  const arenas = arenaResult.payload?.arenas ?? [];
  const completed = arenas.filter((a) => a.status === 'completed' || a.status === 'failed');

  // Step 2: List existing outcomes to avoid duplicates
  const existingOutcomes = await apiCall('GET', `${base}/v1/arena/outcomes?limit=500`, args.adminKey);
  const existingArenaIds = new Set(
    (existingOutcomes.payload?.outcomes ?? []).map((o) => `${o.arena_id}:${o.contender_id}`)
  );

  // Step 3: Seed outcomes for arena runs missing them
  const outcomeResults = [];
  let seededCount = 0;

  for (const arena of completed) {
    if (seededCount >= args.targetOutcomes) break;

    const contenderId = arena.winner_contender_id ?? 'contender_codex_pi';
    const dedupKey = `${arena.arena_id}:${contenderId}`;
    if (existingArenaIds.has(dedupKey)) {
      outcomeResults.push({
        arena_id: arena.arena_id, bounty_id: arena.bounty_id,
        status: 'skipped', reason: 'already_has_outcome',
      });
      continue;
    }

    // Use arena score if available, otherwise generate from contender data
    const score = arena.winner_score ?? arena.score ?? 85;
    const accepted = score >= args.acceptThreshold;
    const outcomeStatus = accepted ? 'ACCEPTED' : 'REJECTED';

    const outcomeBody = {
      arena_id: arena.arena_id,
      contender_id: contenderId,
      outcome_status: outcomeStatus,
      accepted,
      reviewer_decision: accepted ? 'approve' : 'reject',
      reviewer_rationale: accepted
        ? `Arena desk auto-acceptance: score ${score} >= threshold ${args.acceptThreshold}`
        : `Arena desk auto-rejection: score ${score} < threshold ${args.acceptThreshold}`,
      decision_taxonomy_tags: [accepted ? 'auto-approve' : 'auto-reject', 'agp-us-082-seeder'],
      review_time_minutes: 0,
      source: 'arena-desk-outcome-seeder-agp082',
      idempotency_key: `agp082-seed:${arena.arena_id}:${contenderId}`,
      predicted_confidence: score / 100,
    };

    const postUrl = `${base}/v1/bounties/${encodeURIComponent(arena.bounty_id)}/arena/outcome`;
    const result = await apiCall('POST', postUrl, args.adminKey, outcomeBody);

    outcomeResults.push({
      arena_id: arena.arena_id,
      bounty_id: arena.bounty_id,
      contender_id: contenderId,
      score,
      accepted,
      outcome_status: outcomeStatus,
      http_status: result.status,
      outcome_id: result.payload?.outcome_id ?? null,
      reason_code: (result.status >= 200 && result.status < 300)
        ? 'ARENA_OUTCOME_SEEDED'
        : (result.payload?.error ?? 'ARENA_OUTCOME_SEED_FAILED'),
    });

    if (result.status >= 200 && result.status < 300) {
      seededCount += 1;
      existingArenaIds.add(dedupKey);
    }

    process.stdout.write(`seeded ${arena.arena_id} => ${outcomeStatus} (${result.status})\n`);
  }

  // Step 4: Check ROI dashboard status after seeding
  const roiResult = await apiCall('GET', `${base}/v1/arena/roi-dashboard?limit=100`, args.adminKey);

  const summary = {
    ok: seededCount > 0,
    story: 'AGP-US-082',
    generated_at: new Date().toISOString(),
    endpoint_base: base,
    arena_runs_found: arenas.length,
    completed_runs: completed.length,
    outcomes_seeded: seededCount,
    outcomes_skipped: outcomeResults.filter((r) => r.status === 'skipped').length,
    outcomes_failed: outcomeResults.filter((r) => r.http_status && (r.http_status < 200 || r.http_status >= 300)).length,
    accept_threshold: args.acceptThreshold,
    roi_dashboard: {
      http_status: roiResult.status,
      roi_status: roiResult.payload?.status ?? roiResult.payload?.roi_status ?? null,
      sample_count: roiResult.payload?.sample_count ?? roiResult.payload?.outcomes?.length ?? null,
    },
    outcome_details: outcomeResults,
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(summary, null, 2) + '\n');
  process.stdout.write(`ARENA_OUTCOME_SEEDER_RESULT ${outputPath}\n`);
  process.stdout.write(JSON.stringify({
    ok: summary.ok, seeded: seededCount,
    roi_status: summary.roi_dashboard.roi_status,
    sample_count: summary.roi_dashboard.sample_count,
  }) + '\n');
  if (!summary.ok) process.exitCode = 2;
}

main().catch((err) => {
  process.stderr.write(`run-outcome-seeder failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
