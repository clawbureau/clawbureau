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
    minOutcomes: 10,
    minArenas: 3,
    maxSuggestions: 12,
    limit: 1200,
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
    if (arg === '--min-outcomes') {
      args.minOutcomes = Number(argv[i + 1] ?? 10);
      i += 1;
      continue;
    }
    if (arg === '--min-arenas') {
      args.minArenas = Number(argv[i + 1] ?? 3);
      i += 1;
      continue;
    }
    if (arg === '--max-suggestions') {
      args.maxSuggestions = Number(argv[i + 1] ?? 12);
      i += 1;
      continue;
    }
    if (arg === '--limit') {
      args.limit = Number(argv[i + 1] ?? 1200);
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

  if (!Number.isFinite(args.minOutcomes) || args.minOutcomes <= 0) {
    throw new Error('--min-outcomes must be a positive number');
  }

  if (!Number.isFinite(args.minArenas) || args.minArenas <= 0) {
    throw new Error('--min-arenas must be a positive number');
  }

  if (!Number.isFinite(args.maxSuggestions) || args.maxSuggestions <= 0) {
    throw new Error('--max-suggestions must be a positive number');
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

async function requestJson(url, { adminKey, method = 'GET', body } = {}) {
  const headers = {
    Accept: 'application/json',
  };

  if (adminKey) headers['x-admin-key'] = adminKey;
  if (method !== 'GET') headers['content-type'] = 'application/json';

  const response = await fetch(url, {
    method,
    headers,
    body: body ? stableJson(body) : undefined,
  });

  const raw = await response.text();
  let json;
  try {
    json = JSON.parse(raw);
  } catch {
    json = { raw };
  }

  if (!response.ok) {
    const error = new Error(`${method} ${url} failed with ${response.status}`);
    error.status = response.status;
    error.response = json;
    throw error;
  }

  return json;
}

function buildSummary({ args, endpointBase, postPayload, getPayload, outputDir }) {
  const postRec = asRecord(postPayload) ?? {};
  const getRec = asRecord(getPayload) ?? {};

  const status = asString(postRec.status) ?? asString(getRec.status) ?? 'unknown';
  const reasonCodes = asStringArray(postRec.reason_codes);
  const totals = asRecord(postRec.totals) ?? {};

  const postSuggestions = Array.isArray(postRec.suggestions) ? postRec.suggestions : [];
  const getSuggestions = Array.isArray(getRec.suggestions) ? getRec.suggestions : [];
  const suggestions = postSuggestions.length > 0 ? postSuggestions : getSuggestions;

  const evidenceRows = suggestions
    .flatMap((suggestion) => {
      const rec = asRecord(suggestion);
      const evidence = Array.isArray(rec?.source_evidence) ? rec.source_evidence : [];
      return evidence
        .map((row) => asRecord(row))
        .filter((row) => row !== null);
    });

  const uniqueArenas = new Set(
    evidenceRows
      .map((row) => asString(row.arena_id))
      .filter((value) => Boolean(value)),
  );

  const uniqueOutcomes = new Set(
    evidenceRows
      .map((row) => asString(row.outcome_id))
      .filter((value) => Boolean(value)),
  );

  const validEvidenceRows = evidenceRows.filter((row) => {
    const arenaId = asString(row.arena_id);
    const outcomeId = asString(row.outcome_id);
    const contenderId = asString(row.contender_id);
    const criterionId = asString(row.criterion_id);
    const reasonCode = asString(row.reason_code);
    return Boolean(arenaId && outcomeId && contenderId && criterionId && reasonCode);
  });

  const checks = {
    status_available_or_insufficient: status === 'available' || status === 'INSUFFICIENT_SAMPLE',
    suggestions_at_least_three_when_available: status !== 'available' || suggestions.length >= 3,
    evidence_rows_linked_when_available: status !== 'available' || (evidenceRows.length > 0 && validEvidenceRows.length === evidenceRows.length),
    outcomes_at_least_minimum_when_available: status !== 'available' || asNumber(totals.outcomes, 0) >= args.minOutcomes,
    arenas_at_least_minimum_when_available: status !== 'available' || uniqueArenas.size >= args.minArenas,
    insufficient_sample_reason_codes_when_insufficient:
      status !== 'INSUFFICIENT_SAMPLE' || reasonCodes.some((code) => code.startsWith('ARENA_CONTRACT_COPILOT_INSUFFICIENT_') || code === 'ARENA_CONTRACT_COPILOT_NO_FAILURE_SIGNAL'),
  };

  const allChecksPassed = Object.values(checks).every(Boolean);

  return {
    ok: allChecksPassed,
    generated_at: new Date().toISOString(),
    story: 'AGP-US-056',
    endpoint_base: endpointBase,
    output_dir: outputDir,
    task_fingerprint: args.taskFingerprint,
    status,
    reason_codes: reasonCodes,
    totals: {
      outcomes: asNumber(totals.outcomes, 0),
      arenas: asNumber(totals.arenas, uniqueArenas.size),
      failed_outcomes: asNumber(totals.failed_outcomes, uniqueOutcomes.size),
      suggestions: suggestions.length,
    },
    evidence: {
      linked_rows: validEvidenceRows.length,
      total_rows: evidenceRows.length,
      unique_arenas: uniqueArenas.size,
      unique_outcomes: uniqueOutcomes.size,
    },
    checks,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const endpointBase = args.bountiesBase.replace(/\/$/, '');
  const slug = slugify(args.taskFingerprint);
  const outputDir = path.join(args.outputRoot, `${nowLabel()}-agp-us-056-contract-copilot-${slug}`);

  const postBody = {
    task_fingerprint: args.taskFingerprint,
    min_outcomes: Math.trunc(args.minOutcomes),
    min_arenas: Math.trunc(args.minArenas),
    max_suggestions: Math.trunc(args.maxSuggestions),
    limit: Math.trunc(args.limit),
  };

  const query = new URLSearchParams();
  query.set('task_fingerprint', args.taskFingerprint);
  query.set('limit', String(Math.trunc(args.maxSuggestions)));

  const postEndpoint = `${endpointBase}/v1/arena/contract-copilot/generate`;
  const getEndpoint = `${endpointBase}/v1/arena/contract-copilot?${query.toString()}`;

  if (args.dryRun) {
    console.log(JSON.stringify({
      ok: true,
      mode: 'dry-run',
      output_dir: outputDir,
      post_endpoint: postEndpoint,
      get_endpoint: getEndpoint,
      post_body: postBody,
    }, null, 2));
    return;
  }

  if (!args.adminKey.trim()) {
    throw new Error('admin key is required unless --dry-run is set (provide --admin-key or BOUNTIES_ADMIN_KEY env)');
  }

  mkdirSync(outputDir, { recursive: true });

  const postPayload = await requestJson(postEndpoint, {
    adminKey: args.adminKey.trim(),
    method: 'POST',
    body: postBody,
  });

  const getPayload = await requestJson(getEndpoint, {
    adminKey: args.adminKey.trim(),
    method: 'GET',
  });

  const summary = buildSummary({
    args,
    endpointBase,
    postPayload,
    getPayload,
    outputDir,
  });

  const postPath = path.join(outputDir, 'contract-copilot.post.json');
  const getPath = path.join(outputDir, 'contract-copilot.get.json');
  const summaryPath = path.join(outputDir, 'summary.json');

  writeFileSync(postPath, `${stableJson(postPayload)}\n`);
  writeFileSync(getPath, `${stableJson(getPayload)}\n`);
  writeFileSync(summaryPath, `${stableJson(summary)}\n`);

  console.log(JSON.stringify({
    ...summary,
    artifacts: {
      post: postPath,
      get: getPath,
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
