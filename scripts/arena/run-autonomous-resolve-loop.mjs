#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    limit: 150,
    targetResolved: 80,
    minPendingAgeMinutes: 30,
    finalizeUnresolved: true,
    dryRun: false,
    arenaIds: [],
    loopId: null,
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

    if (arg === '--limit') {
      args.limit = Number.parseInt(argv[i + 1] ?? String(args.limit), 10);
      i += 1;
      continue;
    }

    if (arg === '--target-resolved') {
      args.targetResolved = Number.parseInt(argv[i + 1] ?? String(args.targetResolved), 10);
      i += 1;
      continue;
    }

    if (arg === '--min-pending-age-minutes') {
      args.minPendingAgeMinutes = Number.parseFloat(argv[i + 1] ?? String(args.minPendingAgeMinutes));
      i += 1;
      continue;
    }

    if (arg === '--finalize-unresolved') {
      args.finalizeUnresolved = true;
      continue;
    }

    if (arg === '--keep-unresolved-pending') {
      args.finalizeUnresolved = false;
      continue;
    }

    if (arg === '--arena-ids') {
      const raw = argv[i + 1] ?? '';
      args.arenaIds = raw
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
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

  if (!Number.isFinite(args.targetResolved) || args.targetResolved <= 0) {
    throw new Error('--target-resolved must be a positive integer');
  }

  if (!Number.isFinite(args.minPendingAgeMinutes) || args.minPendingAgeMinutes < 0) {
    throw new Error('--min-pending-age-minutes must be >= 0');
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
    `${nowLabel()}-agp-us-075-pending-arena-resolver`,
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
  const endpoint = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/desk/resolve-loop`;

  const requestBody = {
    limit: args.limit,
    target_resolved: args.targetResolved,
    min_pending_age_minutes: args.minPendingAgeMinutes,
    finalize_unresolved: args.finalizeUnresolved,
    arena_ids: args.arenaIds,
    loop_id: args.loopId,
    dry_run: args.dryRun,
  };

  const loopResult = args.dryRun
    ? {
      schema_version: 'arena_desk_resolve_loop.v1',
      dry_run: true,
      preview: {
        endpoint,
        request: requestBody,
      },
    }
    : await postJson(endpoint, args.adminKey, requestBody);

  const summary = {
    ok: true,
    story: 'AGP-US-075',
    generated_at: new Date().toISOString(),
    endpoint,
    dry_run: args.dryRun,
    request: requestBody,
    loop_result: loopResult,
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`ARENA_AUTONOMOUS_RESOLVE_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify(loopResult.totals ?? { dry_run: true })}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
