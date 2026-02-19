#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { runArena } from './lib/arena-runner.mjs';
import { loadContenderRegistry, resolveRegistryArenaInput } from './lib/contender-registry.mjs';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_OUTPUT_ROOT = 'artifacts/arena';

function parseArgs(argv) {
  const args = {
    contractPath: null,
    contendersPath: null,
    outputRoot: DEFAULT_OUTPUT_ROOT,
    arenaId: null,
    generatedAt: null,
    registryPath: null,
    objectiveProfileName: null,
    experimentId: null,
    experimentArm: null,
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

    if (arg === '--registry') {
      args.registryPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }

    if (arg === '--objective-profile-name') {
      args.objectiveProfileName = argv[i + 1] ?? null;
      i += 1;
      continue;
    }

    if (arg === '--experiment-id') {
      args.experimentId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }

    if (arg === '--experiment-arm') {
      args.experimentArm = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
  }

  if (!args.contractPath || !args.contendersPath) {
    throw new Error('Usage: node scripts/arena/run-bounty-arena.mjs --contract <json> --contenders <json> [--output-root <dir>] [--arena-id <id>] [--generated-at <iso>] [--registry <json>] [--objective-profile-name <name>] [--experiment-id <id>] [--experiment-arm <arm>]');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  let contract = JSON.parse(readFileSync(args.contractPath, 'utf8'));
  const baseContenders = JSON.parse(readFileSync(args.contendersPath, 'utf8'));

  let contenders = baseContenders;
  let registryContext = null;

  if (args.registryPath) {
    const registry = loadContenderRegistry(args.registryPath);
    const resolved = resolveRegistryArenaInput({
      registry,
      baseContenders,
      taskFingerprint: contract?.task_fingerprint ?? null,
      objectiveProfileName: args.objectiveProfileName,
      experimentId: args.experimentId,
      experimentArm: args.experimentArm,
      arenaSeed: args.arenaId ?? contract?.contract_id ?? contract?.bounty_id ?? nowLabel(),
    });

    contenders = resolved.contenders;
    registryContext = resolved.registry_context;

    if (resolved.objective_profile) {
      contract = {
        ...contract,
        objective_profile: resolved.objective_profile,
      };
    }
  }

  const outputDir = path.join(args.outputRoot, args.arenaId || nowLabel());
  mkdirSync(outputDir, { recursive: true });

  const report = runArena({
    contract,
    contenders,
    outputDir,
    generatedAt: args.generatedAt || undefined,
    arenaIdOverride: args.arenaId || undefined,
    registryContext,
  });

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    output_dir: outputDir,
    arena_id: report.arena_id,
    contenders_count: report.contenders.length,
    winner: report.winner,
    reason_codes: report.reason_codes,
    registry: registryContext
      ? {
        registry_version: registryContext.registry_version,
        objective_profile_name: registryContext.objective_profile_name,
        selected_contenders: registryContext.selected_contenders,
      }
      : null,
    experiment: registryContext
      ? {
        experiment_id: registryContext.experiment_id,
        arm: registryContext.experiment_arm,
      }
      : null,
    contender_versions: report.contenders.map((row) => ({
      contender_id: row.contender_id,
      version_pin: row.version_pin ?? null,
      experiment_arm: row.experiment_arm ?? null,
    })),
  };

  writeFileSync(path.join(outputDir, 'summary.json'), `${stableJson(summary)}\n`);
  console.log(JSON.stringify(summary, null, 2));
}

main();
