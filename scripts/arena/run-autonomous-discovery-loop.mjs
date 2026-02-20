#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    targetOpenBounties: 25,
    seedLimit: 25,
    seedRewardMinor: '25',
    seedRequesterDids: [],
    seedTags: ['arena', 'autonomous', 'seed'],
    seedTitlePrefix: 'Arena autonomous task',
    seedDescription: 'Autonomous arena-seeded bounty for desk throughput operations.',
    objectiveProfileName: 'arena-autonomous',
    discoverId: null,
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
    if (arg === '--target-open-bounties') {
      args.targetOpenBounties = Number.parseInt(argv[i + 1] ?? String(args.targetOpenBounties), 10);
      i += 1;
      continue;
    }
    if (arg === '--seed-limit') {
      args.seedLimit = Number.parseInt(argv[i + 1] ?? String(args.seedLimit), 10);
      i += 1;
      continue;
    }
    if (arg === '--seed-reward-minor') {
      args.seedRewardMinor = argv[i + 1] ?? args.seedRewardMinor;
      i += 1;
      continue;
    }
    if (arg === '--seed-requester-dids') {
      const raw = argv[i + 1] ?? '';
      args.seedRequesterDids = raw
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
      i += 1;
      continue;
    }
    if (arg === '--seed-tags') {
      const raw = argv[i + 1] ?? '';
      args.seedTags = raw
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
      i += 1;
      continue;
    }
    if (arg === '--seed-title-prefix') {
      args.seedTitlePrefix = argv[i + 1] ?? args.seedTitlePrefix;
      i += 1;
      continue;
    }
    if (arg === '--seed-description') {
      args.seedDescription = argv[i + 1] ?? args.seedDescription;
      i += 1;
      continue;
    }
    if (arg === '--objective-profile-name') {
      args.objectiveProfileName = argv[i + 1] ?? args.objectiveProfileName;
      i += 1;
      continue;
    }
    if (arg === '--discover-id') {
      args.discoverId = argv[i + 1] ?? null;
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

  if (!Number.isFinite(args.targetOpenBounties) || args.targetOpenBounties <= 0) {
    throw new Error('--target-open-bounties must be a positive integer');
  }

  if (!Number.isFinite(args.seedLimit) || args.seedLimit <= 0) {
    throw new Error('--seed-limit must be a positive integer');
  }

  if (!/^[0-9]+$/.test(args.seedRewardMinor) || args.seedRewardMinor === '0') {
    throw new Error('--seed-reward-minor must be a positive integer string');
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
    `${nowLabel()}-agp-us-064-autonomous-discovery-loop`,
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
  const endpoint = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/desk/discover-loop`;

  const requestBody = {
    target_open_bounties: args.targetOpenBounties,
    seed_limit: args.seedLimit,
    seed_reward_minor: args.seedRewardMinor,
    seed_requester_dids: args.seedRequesterDids,
    seed_tags: args.seedTags,
    seed_title_prefix: args.seedTitlePrefix,
    seed_description: args.seedDescription,
    objective_profile_name: args.objectiveProfileName,
    discover_id: args.discoverId,
    dry_run: args.dryRun,
  };

  const loopResult = args.dryRun
    ? {
        schema_version: 'arena_desk_discovery_loop.v1',
        dry_run: true,
        preview: {
          endpoint,
          request: requestBody,
        },
      }
    : await postJson(endpoint, args.adminKey, requestBody);

  const summary = {
    ok: true,
    story: 'AGP-US-064',
    generated_at: new Date().toISOString(),
    endpoint,
    dry_run: args.dryRun,
    request: requestBody,
    loop_result: loopResult,
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`ARENA_AUTONOMOUS_DISCOVERY_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify(loopResult.totals ?? { dry_run: true }, null, 2)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
