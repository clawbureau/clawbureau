#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { runArena } from './lib/arena-runner.mjs';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_OUTPUT_ROOT = 'artifacts/arena';

function parseArgs(argv) {
  const args = {
    contractPath: null,
    contendersPath: null,
    outputRoot: DEFAULT_OUTPUT_ROOT,
    arenaId: null,
    generatedAt: null,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

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
  }

  if (!args.contractPath || !args.contendersPath) {
    throw new Error('Usage: node scripts/arena/run-bounty-arena.mjs --contract <json> --contenders <json> [--output-root <dir>] [--arena-id <id>] [--generated-at <iso>]');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const contract = JSON.parse(readFileSync(args.contractPath, 'utf8'));
  const contenders = JSON.parse(readFileSync(args.contendersPath, 'utf8'));

  const outputDir = path.join(args.outputRoot, args.arenaId || nowLabel());
  mkdirSync(outputDir, { recursive: true });

  const report = runArena({
    contract,
    contenders,
    outputDir,
    generatedAt: args.generatedAt || undefined,
    arenaIdOverride: args.arenaId || undefined,
  });

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    output_dir: outputDir,
    arena_id: report.arena_id,
    contenders_count: report.contenders.length,
    winner: report.winner,
    reason_codes: report.reason_codes,
  };

  writeFileSync(path.join(outputDir, 'summary.json'), `${stableJson(summary)}\n`);
  console.log(JSON.stringify(summary, null, 2));
}

main();
