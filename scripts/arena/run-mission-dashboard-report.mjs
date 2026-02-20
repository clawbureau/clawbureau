#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    workerDid: 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    windowHours: 24,
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
    if (arg === '--worker-did') {
      args.workerDid = argv[i + 1] ?? args.workerDid;
      i += 1;
      continue;
    }
    if (arg === '--window-hours') {
      args.windowHours = Number.parseInt(argv[i + 1] ?? String(args.windowHours), 10);
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

  if (!Number.isFinite(args.windowHours) || args.windowHours <= 0) {
    throw new Error('--window-hours must be a positive integer');
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
    `${nowLabel()}-agp-us-061-mission-ui`,
  );
  return path.join(root, 'summary.json');
}

async function getJson(url) {
  const response = await fetch(url, {
    headers: { accept: 'application/json' },
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
  const missionUrl = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/mission?worker_did=${encodeURIComponent(args.workerDid)}&window_hours=${args.windowHours}`;

  const mission = args.dryRun
    ? {
        schema_version: 'arena_mission_summary.v1',
        dry_run: true,
        preview: { endpoint: missionUrl },
      }
    : await getJson(missionUrl);

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    dry_run: args.dryRun,
    endpoint: missionUrl,
    mission,
  };

  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);
  process.stdout.write(`ARENA_MISSION_REPORT_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify(mission, null, 2)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
