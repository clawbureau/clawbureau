#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_BOUNTIES_BASE = 'https://staging.clawbounties.com';
const DEFAULT_OUTPUT_ROOT = 'artifacts/arena-policy-learning';

function parseArgs(argv) {
  const args = {
    bountiesBase: DEFAULT_BOUNTIES_BASE,
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    taskFingerprint: null,
    limit: 500,
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
      args.limit = Number(argv[i + 1] ?? 500);
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

function buildMarkdown(report) {
  const totals = report?.totals ?? {};
  const recommendations = Array.isArray(report?.recommendations) ? report.recommendations : [];
  const contenderProfiles = Array.isArray(report?.contender_profiles) ? report.contender_profiles : [];

  const lines = [
    '# Arena Policy Learning Report',
    '',
    `Generated at: ${new Date().toISOString()}`,
    `Task fingerprint: ${report?.task_fingerprint ?? 'all'}`,
    '',
    '## Totals',
    `- outcomes: ${totals.outcomes ?? 0}`,
    `- overrides: ${totals.overrides ?? 0}`,
    `- override_rate: ${totals.override_rate ?? 0}`,
    '',
    '## Recommended contract + prompt rewrites',
  ];

  if (recommendations.length === 0) {
    lines.push('- No override-driven recommendations yet.');
  } else {
    for (const rec of recommendations) {
      lines.push(
        `- ${rec.reason_code} (count=${rec.count}, share=${rec.share}, priority=${rec.priority_score})`,
        `  - contract: ${rec.contract_rewrite}`,
        `  - prompt: ${rec.prompt_rewrite}`,
      );
    }
  }

  lines.push('', '## Contender override profiles');
  if (contenderProfiles.length === 0) {
    lines.push('- No contender override profiles available.');
  } else {
    for (const profile of contenderProfiles.slice(0, 10)) {
      lines.push(
        `- ${profile.contender_id}: overrides=${profile.overrides}, top_reason=${profile.top_reason_code ?? 'none'}`,
      );
      if (profile.top_contract_rewrite) {
        lines.push(`  - contract: ${profile.top_contract_rewrite}`);
      }
      if (profile.top_prompt_rewrite) {
        lines.push(`  - prompt: ${profile.top_prompt_rewrite}`);
      }
    }
  }

  return `${lines.join('\n')}\n`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const query = new URLSearchParams();
  query.set('limit', String(Math.trunc(args.limit)));
  if (args.taskFingerprint) query.set('task_fingerprint', args.taskFingerprint);

  const endpoint = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/policy-learning?${query.toString()}`;
  const slug = slugify(args.taskFingerprint ?? 'all');
  const outputDir = path.join(args.outputRoot, `${nowLabel()}-${slug}`);

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

  const jsonPath = path.join(outputDir, 'policy-learning.json');
  const mdPath = path.join(outputDir, 'policy-learning.md');
  const summaryPath = path.join(outputDir, 'policy-learning.summary.json');

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
    recommendations: Array.isArray(report?.recommendations) ? report.recommendations.length : 0,
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
