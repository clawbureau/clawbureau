#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_BOUNTIES_BASE = 'https://staging.clawbounties.com';
const DEFAULT_OUTPUT_ROOT = 'artifacts/arena-backtesting';

function parseArgs(argv) {
  const args = {
    bountiesBase: DEFAULT_BOUNTIES_BASE,
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    taskFingerprint: null,
    limit: 200,
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
    if (arg === '--limit') {
      args.limit = Number(argv[i + 1] ?? 200);
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

  if (!Number.isFinite(args.limit) || args.limit <= 0) {
    throw new Error('--limit must be a positive integer');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function slugify(value) {
  return String(value ?? 'all')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'all';
}

async function requestJson(url, { adminKey } = {}) {
  const headers = { Accept: 'application/json' };
  if (adminKey) headers['x-admin-key'] = adminKey;

  const response = await fetch(url, { method: 'GET', headers });
  const text = await response.text();

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }

  if (!response.ok) {
    const error = new Error(`GET ${url} failed with ${response.status}`);
    error.status = response.status;
    error.response = parsed;
    throw error;
  }

  return parsed;
}

function buildMarkdown(report) {
  const totals = report?.totals ?? {};
  const drift = report?.calibration_drift ?? {};
  const reasons = Array.isArray(report?.top_miss_reasons) ? report.top_miss_reasons : [];
  const suggestions = Array.isArray(report?.weight_update_suggestions) ? report.weight_update_suggestions : [];

  const lines = [
    '# Arena Historical Backtesting Report',
    '',
    `Generated at: ${new Date().toISOString()}`,
    `Task fingerprint: ${report?.task_fingerprint ?? 'all'}`,
    '',
    '## Summary',
    `- runs considered: ${totals.runs_considered ?? 0}`,
    `- evaluated runs: ${totals.evaluated_runs ?? 0}`,
    `- hits: ${totals.hits ?? 0}`,
    `- misses: ${totals.misses ?? 0}`,
    `- hit rate: ${totals.hit_rate ?? 0}`,
    `- avg absolute calibration drift: ${drift.avg_absolute_drift ?? 0}`,
    '',
    '## Top miss reasons',
  ];

  if (reasons.length === 0) {
    lines.push('- No miss reasons recorded.');
  } else {
    for (const reason of reasons) {
      lines.push(`- ${reason.reason_code} (count=${reason.count}, share=${reason.share})`);
    }
  }

  lines.push('', '## Weight update suggestions');
  if (suggestions.length === 0) {
    lines.push('- No weight updates suggested.');
  } else {
    for (const suggestion of suggestions) {
      const delta = suggestion.recommended_weight_delta ?? {};
      lines.push(
        `- ${suggestion.reason_code} (priority=${suggestion.priority_score}, count=${suggestion.count}, share=${suggestion.share})`,
        `  - delta: quality=${delta.quality ?? 0}, speed=${delta.speed ?? 0}, cost=${delta.cost ?? 0}, safety=${delta.safety ?? 0}`,
        `  - rationale: ${suggestion.rationale}`,
      );
    }
  }

  return `${lines.join('\n')}\n`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const query = new URLSearchParams();
  query.set('limit', String(Math.trunc(args.limit)));
  if (args.taskFingerprint) query.set('task_fingerprint', args.taskFingerprint);

  const endpoint = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/backtesting?${query.toString()}`;
  const outputDir = path.join(args.outputRoot, `${nowLabel()}-${slugify(args.taskFingerprint ?? 'all')}`);

  if (args.dryRun) {
    console.log(JSON.stringify({
      ok: true,
      mode: 'dry-run',
      endpoint,
      output_dir: outputDir,
    }, null, 2));
    return;
  }

  if (!args.adminKey.trim()) {
    throw new Error('admin key is required unless --dry-run is set (provide --admin-key or BOUNTIES_ADMIN_KEY env)');
  }

  const report = await requestJson(endpoint, { adminKey: args.adminKey.trim() });
  const markdown = buildMarkdown(report);

  mkdirSync(outputDir, { recursive: true });

  const jsonPath = path.join(outputDir, 'backtesting.json');
  const mdPath = path.join(outputDir, 'backtesting.md');
  const summaryPath = path.join(outputDir, 'backtesting.summary.json');

  writeFileSync(jsonPath, `${stableJson(report)}\n`);
  writeFileSync(mdPath, markdown);

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    endpoint,
    output_dir: outputDir,
    json_path: jsonPath,
    markdown_path: mdPath,
    task_fingerprint: report?.task_fingerprint ?? args.taskFingerprint ?? null,
    evaluated_runs: report?.totals?.evaluated_runs ?? 0,
    hit_rate: report?.totals?.hit_rate ?? 0,
  };

  writeFileSync(summaryPath, `${stableJson(summary)}\n`);
  console.log(JSON.stringify(summary, null, 2));
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
