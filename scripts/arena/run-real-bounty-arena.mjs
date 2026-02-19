#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { runArena } from './lib/arena-runner.mjs';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_BOUNTIES_BASE = 'https://staging.clawbounties.com';
const DEFAULT_OUTPUT_ROOT = 'artifacts/arena';

function parseArgs(argv) {
  const args = {
    bountyId: null,
    contractPath: null,
    contendersPath: null,
    outputRoot: DEFAULT_OUTPUT_ROOT,
    arenaId: null,
    generatedAt: null,
    bountiesBase: DEFAULT_BOUNTIES_BASE,
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    startIdempotencyKey: null,
    resultIdempotencyKey: null,
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--bounty-id') {
      args.bountyId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--contract') {
      args.contractPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--contenders') {
      args.contendersPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? DEFAULT_OUTPUT_ROOT;
      i += 1;
      continue;
    }
    if (arg === '--arena-id') {
      args.arenaId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--generated-at') {
      args.generatedAt = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
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
    if (arg === '--start-idempotency-key') {
      args.startIdempotencyKey = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--result-idempotency-key') {
      args.resultIdempotencyKey = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
  }

  if (!args.bountyId || !args.contractPath || !args.contendersPath) {
    throw new Error('Usage: node scripts/arena/run-real-bounty-arena.mjs --bounty-id <bty_...> --contract <json> --contenders <json> [--output-root <dir>] [--arena-id <id>] [--generated-at <iso>] [--bounties-base <url>] [--admin-key <key>] [--start-idempotency-key <key>] [--result-idempotency-key <key>] [--dry-run]');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function sha256b64u(input) {
  return createHash('sha256').update(input).digest('base64url');
}

function buildDefaultIdempotencyKey(prefix, parts) {
  const digest = sha256b64u(parts.join('|'));
  return `${prefix}:${digest}`;
}

function loadJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

async function requestJson(url, { method = 'GET', adminKey, body } = {}) {
  const headers = {
    Accept: 'application/json',
  };

  if (adminKey) {
    headers['x-admin-key'] = adminKey;
  }

  const init = {
    method,
    headers,
  };

  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const response = await fetch(url, init);
  const text = await response.text();

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }

  if (!response.ok) {
    const error = new Error(`${method} ${url} failed with ${response.status}`);
    error.response = parsed;
    error.status = response.status;
    throw error;
  }

  return parsed;
}

function readContenderArtifacts(report) {
  const artifacts = [];

  for (const contender of report.contenders) {
    const proofPack = loadJson(contender.proof_pack_path);
    const managerReview = loadJson(contender.manager_review_path);
    const reviewPaste = readFileSync(contender.review_paste_path, 'utf8').trim();

    artifacts.push({
      contender_id: contender.contender_id,
      proof_pack: proofPack,
      manager_review: managerReview,
      review_paste: reviewPaste,
    });
  }

  return artifacts;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.dryRun && (!args.adminKey || !args.adminKey.trim())) {
    throw new Error('admin key is required unless --dry-run is set (provide --admin-key or BOUNTIES_ADMIN_KEY env)');
  }

  const contract = loadJson(args.contractPath);
  const contenders = loadJson(args.contendersPath);

  if (String(contract.bounty_id ?? '').trim() !== args.bountyId.trim()) {
    throw new Error(`Contract bounty_id (${contract.bounty_id}) does not match --bounty-id (${args.bountyId})`);
  }

  const arenaId = args.arenaId ?? `arena_${args.bountyId}_${nowLabel()}`;
  const outputDir = path.join(args.outputRoot, arenaId);
  mkdirSync(outputDir, { recursive: true });

  const report = runArena({
    contract,
    contenders,
    outputDir,
    generatedAt: args.generatedAt ?? undefined,
    arenaIdOverride: arenaId,
  });

  const startIdempotencyKey = args.startIdempotencyKey
    ?? buildDefaultIdempotencyKey('arena-start', [report.arena_id, report.contract.bounty_id, report.contract.contract_hash_b64u]);

  const resultIdempotencyKey = args.resultIdempotencyKey
    ?? buildDefaultIdempotencyKey('arena-result', [report.arena_id, report.winner.contender_id, String(report.generated_at)]);

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    mode: args.dryRun ? 'dry-run' : 'live',
    bounties_base: args.bountiesBase,
    bounty_id: args.bountyId,
    arena_id: report.arena_id,
    output_dir: outputDir,
    winner: report.winner,
    start_idempotency_key: startIdempotencyKey,
    result_idempotency_key: resultIdempotencyKey,
  };

  if (args.dryRun) {
    writeFileSync(path.join(outputDir, 'real-bounty-launch.summary.json'), `${stableJson(summary)}\n`);
    console.log(JSON.stringify(summary, null, 2));
    return;
  }

  const adminKey = args.adminKey.trim();

  const bountyRead = await requestJson(
    `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(args.bountyId)}`,
    {
      method: 'GET',
      adminKey,
    },
  );

  const startPayload = {
    idempotency_key: startIdempotencyKey,
    arena_id: report.arena_id,
    contract: report.contract,
    objective_profile: report.objective_profile,
  };

  const startResponse = await requestJson(
    `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(args.bountyId)}/arena/start`,
    {
      method: 'POST',
      adminKey,
      body: startPayload,
    },
  );

  const contenderArtifacts = readContenderArtifacts(report);

  const resultPayload = {
    idempotency_key: resultIdempotencyKey,
    arena_report: report,
    contender_artifacts: contenderArtifacts,
  };

  const resultResponse = await requestJson(
    `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(args.bountyId)}/arena/result`,
    {
      method: 'POST',
      adminKey,
      body: resultPayload,
    },
  );

  const arenaRead = await requestJson(
    `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(args.bountyId)}/arena`,
    {
      method: 'GET',
      adminKey,
    },
  );

  const fullSummary = {
    ...summary,
    bounty_status: bountyRead.status ?? null,
    start_response: startResponse,
    result_response: resultResponse,
    arena_response: arenaRead,
  };

  writeFileSync(path.join(outputDir, 'real-bounty-launch.summary.json'), `${stableJson(fullSummary)}\n`);
  console.log(JSON.stringify(fullSummary, null, 2));
}

main().catch((err) => {
  const out = {
    ok: false,
    error: err instanceof Error ? err.message : String(err),
    details: err && typeof err === 'object' && 'response' in err ? err.response : undefined,
    status: err && typeof err === 'object' && 'status' in err ? err.status : undefined,
  };
  console.error(JSON.stringify(out, null, 2));
  process.exit(1);
});
