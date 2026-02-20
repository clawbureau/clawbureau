#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    decisionMode: 'approve_valid',
    limit: 120,
    targetDecisions: 20,
    bountyIds: [],
    requireClaimed: true,
    rejectReason: 'Arena desk auto-rejection',
    loopId: null,
    dryRun: false,
    outputPath: null,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--bounties-base') {
      args.bountiesBase = argv[i + 1] ?? args.bountiesBase;
      i += 1;
      continue;
    }
    if (arg === '--admin-key') {
      args.adminKey = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--decision-mode') {
      args.decisionMode = argv[i + 1] ?? args.decisionMode;
      i += 1;
      continue;
    }
    if (arg === '--limit') {
      args.limit = Number.parseInt(argv[i + 1] ?? String(args.limit), 10);
      i += 1;
      continue;
    }
    if (arg === '--target-decisions') {
      args.targetDecisions = Number.parseInt(argv[i + 1] ?? String(args.targetDecisions), 10);
      i += 1;
      continue;
    }
    if (arg === '--bounty-ids') {
      const raw = argv[i + 1] ?? '';
      args.bountyIds = raw
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
      i += 1;
      continue;
    }
    if (arg === '--require-claimed') {
      args.requireClaimed = true;
      continue;
    }
    if (arg === '--allow-unclaimed') {
      args.requireClaimed = false;
      continue;
    }
    if (arg === '--reject-reason') {
      args.rejectReason = argv[i + 1] ?? args.rejectReason;
      i += 1;
      continue;
    }
    if (arg === '--loop-id') {
      args.loopId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
    if (arg === '--output') {
      args.outputPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
  }

  if (!args.adminKey) {
    throw new Error('Missing admin key. Pass --admin-key or set BOUNTIES_ADMIN_KEY.');
  }

  if (!Number.isFinite(args.limit) || args.limit <= 0) {
    throw new Error('--limit must be a positive integer');
  }

  if (!Number.isFinite(args.targetDecisions) || args.targetDecisions <= 0) {
    throw new Error('--target-decisions must be a positive integer');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function defaultOutputPath() {
  const root = path.join(
    process.cwd(),
    'artifacts',
    'ops',
    'arena-productization',
    `${nowLabel()}-agp-us-067-068-autonomous-decision-loop`,
  );
  return path.join(root, 'summary.json');
}

function stableJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
}

async function postJson(url, adminKey, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-admin-key': adminKey,
    },
    body: stableJson(body),
  });

  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = { raw: text };
  }

  if (!response.ok) {
    throw new Error(`Request failed (${response.status}): ${JSON.stringify(payload)}`);
  }

  return payload;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const endpoint = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/desk/decision-loop`;

  const requestBody = {
    decision_mode: args.decisionMode,
    limit: args.limit,
    target_decisions: args.targetDecisions,
    bounty_ids: args.bountyIds,
    require_claimed: args.requireClaimed,
    reject_reason: args.rejectReason,
    loop_id: args.loopId,
    dry_run: args.dryRun,
  };

  const loopResult = args.dryRun
    ? {
        schema_version: 'arena_desk_decision_loop.v1',
        dry_run: true,
        preview: {
          endpoint,
          request: requestBody,
        },
      }
    : await postJson(endpoint, args.adminKey, requestBody);

  const summary = {
    ok: true,
    story: 'AGP-US-067-068',
    generated_at: new Date().toISOString(),
    endpoint,
    dry_run: args.dryRun,
    request: requestBody,
    loop_result: loopResult,
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`ARENA_AUTONOMOUS_DECISION_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify(loopResult.totals ?? { dry_run: true }, null, 2)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
