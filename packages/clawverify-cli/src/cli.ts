#!/usr/bin/env node

import { resolveVerifierConfig, CliConfigError } from './config.js';
import { CliUsageError } from './errors.js';
import {
  exitCodeForOutput,
  kindForSubcommand,
  verifyCommitSigFromFile,
  verifyExportBundleFromFile,
  verifyProofBundleFromFile,
} from './verify.js';
import { runComplianceReport } from './compliance-cmd.js';
import { hintForReasonCode, explainReasonCode } from './hints.js';
import { runInit } from './init.js';
import { runMigratePolicy } from './migrate-policy.js';
import type { CliOutput, CliKind } from './types.js';

function nowIso(): string {
  return new Date().toISOString();
}

function usageText(): string {
  return [
    'clawverify — offline verifier CLI for the Clawsig Protocol',
    '',
    'Usage:',
    '  clawverify verify proof-bundle --input <path> [--urm <path>] [--config <path>]',
    '  clawverify verify export-bundle --input <path> [--config <path>]',
    '  clawverify verify commit-sig   --input <path>',
    '  clawverify compliance <bundle.json> [--framework soc2|iso27001|eu-ai-act] [--output <file>]',
    '  clawverify migrate-policy      <v1-policy.json>',
    '  clawverify init [--dir <path>] [--force]',
    '  clawverify explain <REASON_CODE>',
    '  clawverify version',
    '',
    'Exit codes:',
    '  0 = PASS (valid)',
    '  1 = FAIL (invalid)',
    '  2 = USAGE/CONFIG error',
    '',
    'Examples:',
    '  clawverify verify proof-bundle --input bundle.json --config clawverify.config.v1.json',
    '  clawverify compliance bundle.json --framework soc2',
    '  clawverify init',
    '  clawverify explain HASH_MISMATCH',
    '',
    'Docs: https://clawsig.com',
  ].join('\n');
}

function readFlag(args: string[], name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1) return undefined;
  const value = args[idx + 1];
  if (!value || value.startsWith('--')) return undefined;
  return value;
}

function hasFlag(args: string[], name: string): boolean {
  return args.includes(name);
}

type ParsedArgs =
  | { command: 'verify'; kind: CliKind; inputPath: string; configPath?: string; urmPath?: string }
  | { command: 'compliance'; inputPath: string; framework: string; outputPath?: string }
  | { command: 'init'; targetDir?: string; force: boolean }
  | { command: 'explain'; code: string }
  | { command: 'migrate-policy'; inputPath: string }
  | { command: 'version' };

function parseCliArgs(argv: string[]): ParsedArgs {
  if (argv.length === 0 || hasFlag(argv, '--help') || hasFlag(argv, '-h')) {
    throw new CliUsageError(usageText());
  }

  if (argv[0] === 'version' || hasFlag(argv, '--version')) {
    return { command: 'version' };
  }

  if (argv[0] === 'compliance') {
    const inputPath = argv[1];
    if (!inputPath || inputPath.startsWith('--')) {
      throw new CliUsageError('Usage: clawverify compliance <bundle.json> [--framework soc2|iso27001|eu-ai-act] [--output <file>]');
    }
    const framework = readFlag(argv, '--framework') ?? 'soc2';
    const outputPath = readFlag(argv, '--output');
    return { command: 'compliance', inputPath, framework, outputPath };
  }

  if (argv[0] === 'migrate-policy') {
    const inputPath = argv[1];
    if (!inputPath) throw new CliUsageError('Usage: clawverify migrate-policy <v1-policy.json>');
    return { command: 'migrate-policy', inputPath };
  }

  if (argv[0] === 'explain') {
    const code = argv[1];
    if (!code) throw new CliUsageError('Usage: clawverify explain <REASON_CODE>');
    return { command: 'explain', code: code.toUpperCase() };
  }

  if (argv[0] === 'init') {
    const targetDir = readFlag(argv, '--dir');
    const force = hasFlag(argv, '--force');
    return { command: 'init', targetDir, force };
  }

  if (argv[0] !== 'verify') {
    throw new CliUsageError(usageText());
  }

  const kind = kindForSubcommand(argv[1] ?? '');
  if (!kind) {
    throw new CliUsageError(usageText());
  }

  const inputPath = readFlag(argv, '--input');
  if (!inputPath) {
    throw new CliUsageError('Missing required flag: --input <path>\n\nRun: clawverify --help');
  }

  const urmPath = readFlag(argv, '--urm');
  const configPath = readFlag(argv, '--config');

  return { command: 'verify', kind, inputPath, configPath, urmPath };
}

/** Attach a hint to a CLI output if applicable. */
function attachHint(out: CliOutput): CliOutput {
  if (out.status !== 'PASS' && out.reason_code) {
    const hint = hintForReasonCode(out.reason_code);
    if (hint) {
      return { ...out, hint };
    }
  }
  return out;
}

function output(out: CliOutput): void {
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
}

async function main() {
  const parsed = parseCliArgs(process.argv.slice(2));

  if (parsed.command === 'version') {
    process.stdout.write('clawverify 0.1.1\n');
    return;
  }

  if (parsed.command === 'explain') {
    process.stdout.write(`${explainReasonCode(parsed.code)}\n`);
    return;
  }

  if (parsed.command === 'compliance') {
    await runComplianceReport(parsed.inputPath, parsed.framework, parsed.outputPath);
    return;
  }

  if (parsed.command === 'migrate-policy') {
    runMigratePolicy(parsed.inputPath);
    return;
  }

  if (parsed.command === 'init') {
    const result = runInit({
      targetDir: parsed.targetDir,
      force: parsed.force,
    });

    process.stdout.write(`Initialized .clawsig/ in ${result.dir}\n`);

    if (result.created.length > 0) {
      process.stdout.write(`  Created: ${result.created.join(', ')}\n`);
    }
    if (result.skipped.length > 0) {
      process.stdout.write(`  Skipped (already exists): ${result.skipped.join(', ')}\n`);
      process.stdout.write('  Use --force to overwrite existing files.\n');
    }

    process.stdout.write('\nNext steps:\n');
    process.stdout.write('  1. Edit .clawsig/policy.json to configure your policy\n');
    process.stdout.write('  2. Install the Claw Verified GitHub App\n');
    process.stdout.write('  3. Have an AI agent open a PR with a proof bundle\n');
    process.stdout.write('\nDocs: https://clawprotocol.org/github-app\n');
    return;
  }

  const { kind, inputPath, configPath, urmPath } = parsed;
  const config = await resolveVerifierConfig({ configPath });

  let out: CliOutput =
    kind === 'commit_sig'
      ? await verifyCommitSigFromFile({ inputPath })
      : kind === 'proof_bundle'
        ? await verifyProofBundleFromFile({
            inputPath,
            configPath,
            urmPath,
            config,
          })
        : await verifyExportBundleFromFile({ inputPath, configPath, config });

  out = attachHint(out);
  output(out);
  process.exitCode = exitCodeForOutput(out);
}

main().catch((err: unknown) => {
  const verifiedAt = nowIso();

  if (err instanceof CliUsageError) {
    output({
      status: 'ERROR',
      verified_at: verifiedAt,
      reason_code: 'USAGE_ERROR',
      reason: err.message,
      hint: hintForReasonCode('USAGE_ERROR'),
    });
    process.exitCode = 2;
    return;
  }

  if (err instanceof CliConfigError) {
    output({
      status: 'ERROR',
      verified_at: verifiedAt,
      reason_code: 'CONFIG_ERROR',
      reason: err.message,
      hint: hintForReasonCode('CONFIG_ERROR'),
    });
    process.exitCode = 2;
    return;
  }

  output({
    status: 'ERROR',
    verified_at: verifiedAt,
    reason_code: 'INTERNAL_ERROR',
    reason: err instanceof Error ? err.message : 'unknown error',
    hint: hintForReasonCode('INTERNAL_ERROR'),
  });
  process.exitCode = 2;
});
