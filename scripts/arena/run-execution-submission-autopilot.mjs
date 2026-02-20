#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    workerDid: 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    targetSubmissions: 10,
    limit: 40,
    bountyIdsFile: null,
    outputPath: null,
    dryRun: false,
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
    if (arg === '--worker-did') {
      args.workerDid = argv[i + 1] ?? args.workerDid;
      i += 1;
      continue;
    }
    if (arg === '--target-submissions') {
      args.targetSubmissions = Number.parseInt(argv[i + 1] ?? String(args.targetSubmissions), 10);
      i += 1;
      continue;
    }
    if (arg === '--limit') {
      args.limit = Number.parseInt(argv[i + 1] ?? String(args.limit), 10);
      i += 1;
      continue;
    }
    if (arg === '--bounty-ids-file') {
      args.bountyIdsFile = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--output') {
      args.outputPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
  }

  if (!Number.isFinite(args.targetSubmissions) || args.targetSubmissions <= 0) {
    throw new Error('--target-submissions must be a positive integer');
  }

  if (!Number.isFinite(args.limit) || args.limit <= 0) {
    throw new Error('--limit must be a positive integer');
  }

  if (!args.adminKey) {
    throw new Error('Missing admin key. Pass --admin-key or set BOUNTIES_ADMIN_KEY.');
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
    `${nowLabel()}-agp-us-060-execution-submission-autopilot`,
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

function parseBountyIdsFile(filePath) {
  if (!filePath) return [];
  const text = readFileSync(filePath, 'utf8');
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
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
    headers: {
      'x-admin-key': adminKey,
    },
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
  const baseUrl = args.bountiesBase.replace(/\/$/, '');
  const bountyIds = parseBountyIdsFile(args.bountyIdsFile);
  const endpoint = `${baseUrl}/v1/arena/desk/submit-loop`;

  const requestBody = {
    worker_did: args.workerDid,
    target_submissions: args.targetSubmissions,
    limit: args.limit,
    bounty_ids: bountyIds,
    dry_run: args.dryRun,
  };

  const loopResult = args.dryRun
    ? {
        schema_version: 'arena_execution_submission_autopilot.v1',
        dry_run: true,
        preview: {
          endpoint,
          request: requestBody,
        },
      }
    : await postJson(endpoint, args.adminKey, requestBody);

  const submissionsSnapshot = args.dryRun
    ? {
        schema_version: 'arena_submissions_snapshot.v1',
        dry_run: true,
        preview: {
          endpoint: `${baseUrl}/v1/submissions/{id}`,
        },
      }
    : await getJson(`${baseUrl}/v1/arena/desk/claims?limit=200`, args.adminKey);

  const summary = {
    ok: true,
    story: 'AGP-US-060',
    generated_at: new Date().toISOString(),
    dry_run: args.dryRun,
    endpoint,
    request: requestBody,
    loop_result: loopResult,
    claims_snapshot: submissionsSnapshot,
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`ARENA_EXEC_SUBMISSION_AUTOPILOT_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify(loopResult.totals ?? { dry_run: true }, null, 2)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
