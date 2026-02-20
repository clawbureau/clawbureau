#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_BOUNTIES_BASE = 'https://staging.clawbounties.com';
const DEFAULT_OUTPUT_ROOT = 'artifacts/ops/arena-productization';

function parseArgs(argv) {
  const args = {
    bountiesBase: DEFAULT_BOUNTIES_BASE,
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    taskFingerprint: null,
    objectiveProfileName: null,
    contenderId: null,
    experimentId: null,
    experimentArm: null,
    minSamples: 5,
    limit: 2000,
    outputRoot: DEFAULT_OUTPUT_ROOT,
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--bounties-base') {
      args.bountiesBase = argv[i + 1] ?? DEFAULT_BOUNTIES_BASE;
      i += 1;
      continue;
    }
    if (arg === '--admin-key') {
      args.adminKey = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--task-fingerprint') {
      args.taskFingerprint = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--objective-profile-name') {
      args.objectiveProfileName = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--contender-id') {
      args.contenderId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--experiment-id') {
      args.experimentId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--experiment-arm') {
      args.experimentArm = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--min-samples') {
      args.minSamples = Number(argv[i + 1] ?? 5);
      i += 1;
      continue;
    }
    if (arg === '--limit') {
      args.limit = Number(argv[i + 1] ?? 2000);
      i += 1;
      continue;
    }
    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? DEFAULT_OUTPUT_ROOT;
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
  }

  if (!args.taskFingerprint || !String(args.taskFingerprint).trim()) {
    throw new Error('--task-fingerprint is required');
  }

  if (!Number.isFinite(args.minSamples) || args.minSamples <= 0) {
    throw new Error('--min-samples must be a positive number');
  }

  if (!Number.isFinite(args.limit) || args.limit <= 0) {
    throw new Error('--limit must be a positive number');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function slugify(value) {
  return String(value ?? 'unknown')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'unknown';
}

function asRecord(value) {
  return value && typeof value === 'object' ? value : null;
}

function asString(value) {
  return typeof value === 'string' ? value : null;
}

function asNumber(value, fallback = 0) {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function asStringArray(value) {
  return Array.isArray(value) ? value.filter((entry) => typeof entry === 'string') : [];
}

async function requestJson(url, { adminKey } = {}) {
  const headers = { Accept: 'application/json' };
  if (adminKey) headers['x-admin-key'] = adminKey;

  const response = await fetch(url, { method: 'GET', headers });
  const raw = await response.text();

  let json;
  try {
    json = JSON.parse(raw);
  } catch {
    json = { raw };
  }

  if (!response.ok) {
    const error = new Error(`GET ${url} failed with ${response.status}`);
    error.status = response.status;
    error.response = json;
    throw error;
  }

  return json;
}

function buildSummary({ args, endpointBase, payload, outputDir }) {
  const rec = asRecord(payload) ?? {};
  const status = asString(rec.status) ?? 'unknown';
  const metrics = asRecord(rec.metrics);
  const totals = asRecord(rec.totals) ?? {};
  const reasonCodes = asStringArray(rec.reason_codes);

  const requiredMetricKeys = [
    'median_review_time_minutes',
    'first_pass_accept_rate',
    'override_rate',
    'rework_rate',
    'cost_per_accepted_bounty_usd',
    'cycle_time_minutes',
    'winner_stability',
  ];

  const metricsPresent = metrics
    ? requiredMetricKeys.every((key) => Number.isFinite(asNumber(metrics[key], Number.NaN)))
    : false;

  const checks = {
    status_available_or_insufficient: status === 'available' || status === 'INSUFFICIENT_SAMPLE',
    metrics_present_when_available: status !== 'available' || metricsPresent,
    sample_count_positive_when_available: status !== 'available' || asNumber(totals.sample_count, 0) > 0,
    insufficient_sample_reason_codes_when_insufficient:
      status !== 'INSUFFICIENT_SAMPLE' || reasonCodes.some((code) => code.startsWith('ARENA_ROI_INSUFFICIENT_') || code === 'ARENA_ROI_INSUFFICIENT_SAMPLE'),
  };

  const allChecksPassed = Object.values(checks).every(Boolean);

  return {
    ok: allChecksPassed,
    generated_at: new Date().toISOString(),
    story: 'AGP-US-057',
    endpoint_base: endpointBase,
    output_dir: outputDir,
    task_fingerprint: args.taskFingerprint,
    status,
    reason_codes: reasonCodes,
    totals: {
      sample_count: asNumber(totals.sample_count, 0),
      arena_count: asNumber(totals.arena_count, 0),
      available_runs: asNumber(totals.available_runs, 0),
    },
    checks,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const endpointBase = args.bountiesBase.replace(/\/$/, '');
  const slug = slugify(args.taskFingerprint);
  const outputDir = path.join(args.outputRoot, `${nowLabel()}-agp-us-057-roi-dashboard-${slug}`);

  const query = new URLSearchParams();
  query.set('task_fingerprint', args.taskFingerprint);
  query.set('min_samples', String(Math.trunc(args.minSamples)));
  query.set('limit', String(Math.trunc(args.limit)));
  if (args.objectiveProfileName) query.set('objective_profile_name', args.objectiveProfileName);
  if (args.contenderId) query.set('contender_id', args.contenderId);
  if (args.experimentId) query.set('experiment_id', args.experimentId);
  if (args.experimentArm) query.set('experiment_arm', args.experimentArm);

  const endpoint = `${endpointBase}/v1/arena/roi-dashboard?${query.toString()}`;

  if (args.dryRun) {
    console.log(JSON.stringify({
      ok: true,
      mode: 'dry-run',
      output_dir: outputDir,
      endpoint,
    }, null, 2));
    return;
  }

  if (!args.adminKey.trim()) {
    throw new Error('admin key is required unless --dry-run is set (provide --admin-key or BOUNTIES_ADMIN_KEY env)');
  }

  mkdirSync(outputDir, { recursive: true });

  const payload = await requestJson(endpoint, {
    adminKey: args.adminKey.trim(),
  });

  const summary = buildSummary({
    args,
    endpointBase,
    payload,
    outputDir,
  });

  const reportPath = path.join(outputDir, 'roi-dashboard.json');
  const summaryPath = path.join(outputDir, 'summary.json');

  writeFileSync(reportPath, `${stableJson(payload)}\n`);
  writeFileSync(summaryPath, `${stableJson(summary)}\n`);

  console.log(JSON.stringify({
    ...summary,
    artifacts: {
      report: reportPath,
      summary: summaryPath,
    },
  }, null, 2));

  if (!summary.ok) {
    process.exitCode = 2;
  }
}

main().catch((err) => {
  console.error(JSON.stringify({
    ok: false,
    error: err instanceof Error ? err.message : String(err),
    status: err && typeof err === 'object' && 'status' in err ? err.status : undefined,
    details: err && typeof err === 'object' && 'response' in err ? err.response : undefined,
  }, null, 2));
  process.exit(1);
});
