#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_BOUNTIES_BASE = 'https://staging.clawbounties.com';
const DEFAULT_OUTPUT_ROOT = 'artifacts/arena-contract-language-optimizer';

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

async function requestJson(url, { adminKey, body }) {
  const headers = {
    Accept: 'application/json',
    'content-type': 'application/json',
  };
  if (adminKey) headers['x-admin-key'] = adminKey;

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body ?? {}),
  });

  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }

  if (!response.ok) {
    const error = new Error(`POST ${url} failed with ${response.status}`);
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
  const globalSuggestions = Array.isArray(report?.global_suggestions) ? report.global_suggestions : [];
  const contenderSuggestions = Array.isArray(report?.contender_suggestions) ? report.contender_suggestions : [];

  const lines = [
    '# Arena Contract Language Optimizer',
    '',
    `Generated at: ${new Date().toISOString()}`,
    `Task fingerprint: ${report?.task_fingerprint ?? 'unknown'}`,
    '',
    '## Totals',
    `- outcomes: ${totals.outcomes ?? 0}`,
    `- failed_or_overridden_outcomes: ${totals.failed_or_overridden_outcomes ?? 0}`,
    `- overridden_outcomes: ${totals.overridden_outcomes ?? 0}`,
    `- suggestions: ${totals.suggestions ?? 0}`,
    '',
    '## Global contract rewrites',
  ];

  if (globalSuggestions.length === 0) {
    lines.push('- No global contract rewrite suggestions generated.');
  } else {
    for (const suggestion of globalSuggestions) {
      lines.push(
        `- ${suggestion.reason_code} (failures=${suggestion.failures}, share=${suggestion.share}, priority=${suggestion.priority_score})`,
        `  - contract patch: ${suggestion.contract_language_patch}`,
        `  - prompt patch: ${suggestion.prompt_language_patch}`,
      );
    }
  }

  lines.push('', '## Contender prompt rewrites');
  if (contenderSuggestions.length === 0) {
    lines.push('- No contender-specific rewrite suggestions generated.');
  } else {
    for (const suggestion of contenderSuggestions.slice(0, 12)) {
      lines.push(
        `- ${suggestion.contender_id ?? 'n/a'} :: ${suggestion.reason_code} (failures=${suggestion.failures}, share=${suggestion.share}, priority=${suggestion.priority_score})`,
        `  - contract patch: ${suggestion.contract_language_patch}`,
        `  - prompt patch: ${suggestion.prompt_language_patch}`,
      );
    }
  }

  return `${lines.join('\n')}\n`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const endpoint = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/contract-language-optimizer`;
  const slug = slugify(args.taskFingerprint ?? 'all');
  const outputDir = path.join(args.outputRoot, `${nowLabel()}-${slug}`);

  const body = {
    task_fingerprint: args.taskFingerprint,
    limit: Math.trunc(args.limit),
  };

  if (args.dryRun) {
    console.log(JSON.stringify({
      ok: true,
      mode: 'dry-run',
      endpoint,
      body,
      output_dir: outputDir,
    }, null, 2));
    return;
  }

  if (!args.taskFingerprint || !String(args.taskFingerprint).trim()) {
    throw new Error('task fingerprint is required unless --dry-run is set (provide --task-fingerprint)');
  }

  if (!args.adminKey.trim()) {
    throw new Error('admin key is required unless --dry-run is set (provide --admin-key or BOUNTIES_ADMIN_KEY env)');
  }

  const report = await requestJson(endpoint, {
    adminKey: args.adminKey.trim(),
    body,
  });

  const markdown = buildMarkdown(report);

  mkdirSync(outputDir, { recursive: true });

  const jsonPath = path.join(outputDir, 'contract-language-optimizer.json');
  const mdPath = path.join(outputDir, 'contract-language-optimizer.md');
  const summaryPath = path.join(outputDir, 'contract-language-optimizer.summary.json');

  writeFileSync(jsonPath, `${stableJson(report)}\n`);
  writeFileSync(mdPath, markdown);

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    endpoint,
    output_dir: outputDir,
    json_path: jsonPath,
    markdown_path: mdPath,
    task_fingerprint: report?.task_fingerprint ?? args.taskFingerprint,
    suggestions: Number(report?.totals?.suggestions ?? 0),
    persisted_rows: Number(report?.persistence?.rows_written ?? 0),
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
