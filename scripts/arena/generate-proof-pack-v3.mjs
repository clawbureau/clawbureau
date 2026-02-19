#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  buildProofPackV3,
  stableJson,
  validateProofPackV3Shape,
  writeProofPackArtifacts,
} from './lib/proof-pack-v3.mjs';

function parseArgs(argv) {
  const args = {
    input: null,
    outputDir: null,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--input') {
      args.input = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--output-dir') {
      args.outputDir = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
  }

  if (!args.input || !args.outputDir) {
    throw new Error('Usage: node scripts/arena/generate-proof-pack-v3.mjs --input <json> --output-dir <dir>');
  }

  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const raw = readFileSync(args.input, 'utf8');
  const input = JSON.parse(raw);

  const proofPack = buildProofPackV3(input);
  const validation = validateProofPackV3Shape(proofPack);

  if (!validation.valid) {
    const outDir = path.join(args.outputDir, 'invalid');
    mkdirSync(outDir, { recursive: true });
    writeFileSync(path.join(outDir, 'proof-pack.invalid.json'), `${stableJson(proofPack)}\n`);
    throw new Error(`proof-pack.v3 validation failed: ${validation.errors.join('; ')}`);
  }

  const outputs = writeProofPackArtifacts(args.outputDir, proofPack);

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    schema_version: proofPack.schema_version,
    arena_id: proofPack.arena_id,
    output_dir: args.outputDir,
    outputs,
  };

  writeFileSync(path.join(args.outputDir, 'summary.json'), `${stableJson(summary)}\n`);
  console.log(JSON.stringify(summary, null, 2));
}

main();
