#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    limit: 24,
    targetClaims: 10,
    budgetMinor: '250000',
    objectiveProfileName: null,
    maxFleetCostTier: null,
    maxFleetRiskTier: null,
    bountyIds: [],
    requestedWorkerDid: null,
    allowRouteFallback: true,
    includeCodeBounties: false,
    dryRun: false,
    outputPath: null,
    loopId: null,
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
    if (arg === '--target-claims') {
      args.targetClaims = Number.parseInt(argv[i + 1] ?? String(args.targetClaims), 10);
      i += 1;
      continue;
    }
    if (arg === '--budget-minor') {
      args.budgetMinor = argv[i + 1] ?? args.budgetMinor;
      i += 1;
      continue;
    }
    if (arg === '--objective-profile-name') {
      args.objectiveProfileName = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--max-fleet-cost-tier') {
      args.maxFleetCostTier = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--max-fleet-risk-tier') {
      args.maxFleetRiskTier = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--loop-id') {
      args.loopId = argv[i + 1] ?? null;
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
    if (arg === '--requested-worker-did') {
      args.requestedWorkerDid = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--allow-route-fallback') {
      args.allowRouteFallback = true;
      continue;
    }
    if (arg === '--no-route-fallback') {
      args.allowRouteFallback = false;
      continue;
    }
    if (arg === '--include-code-bounties') {
      args.includeCodeBounties = true;
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

  if (!Number.isFinite(args.targetClaims) || args.targetClaims <= 0) {
    throw new Error('--target-claims must be a positive integer');
  }

  if (args.bountyIds.some((entry) => !entry.startsWith('bty_'))) {
    throw new Error('--bounty-ids must contain bounty IDs (bty_*)');
  }

  if (args.requestedWorkerDid !== null && !args.requestedWorkerDid.startsWith('did:')) {
    throw new Error('--requested-worker-did must be a DID string');
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
    `${nowLabel()}-agp-us-059-auto-bounty-grabber`,
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

async function getJson(url, adminKey) {
  const response = await fetch(url, {
    headers: { 'x-admin-key': adminKey },
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
  const claimLoopUrl = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/desk/claim-loop`;
  const claimsUrl = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/desk/claims?limit=100`;

  const claimPayload = {
    limit: args.limit,
    target_claims: args.targetClaims,
    budget_minor: args.budgetMinor,
    objective_profile_name: args.objectiveProfileName,
    max_fleet_cost_tier: args.maxFleetCostTier,
    max_fleet_risk_tier: args.maxFleetRiskTier,
    bounty_ids: args.bountyIds,
    requested_worker_did: args.requestedWorkerDid,
    allow_route_fallback: args.allowRouteFallback,
    include_code_bounties: args.includeCodeBounties,
    dry_run: args.dryRun,
    loop_id: args.loopId,
  };

  const loopResult = args.dryRun
    ? {
        schema_version: 'arena_auto_claim_loop.v1',
        dry_run: true,
        preview: {
          endpoint: claimLoopUrl,
          request: claimPayload,
        },
      }
    : await postJson(claimLoopUrl, args.adminKey, claimPayload);

  const claimLocks = args.dryRun
    ? {
        schema_version: 'arena_auto_claim_locks.v1',
        dry_run: true,
        preview: {
          endpoint: claimsUrl,
        },
      }
    : await getJson(claimsUrl, args.adminKey);

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    dry_run: args.dryRun,
    endpoint: claimLoopUrl,
    request: claimPayload,
    loop_result: loopResult,
    claim_locks_snapshot: claimLocks,
  };

  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`AUTO_BOUNTY_GRABBER_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify(loopResult, null, 2)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
