#!/usr/bin/env node

import { resolveVerifierConfig, CliConfigError } from './config.js';
import { CliUsageError } from './errors.js';
import {
  exitCodeForOutput,
  kindForSubcommand,
  verifyExportBundleFromFile,
  verifyProofBundleFromFile,
} from './verify.js';
import type { CliOutput, CliKind } from './types.js';

function nowIso(): string {
  return new Date().toISOString();
}

function usageText(): string {
  return [
    'clawverify (offline verifier CLI)',
    '',
    'Usage:',
    '  clawverify verify proof-bundle --input <path> [--config <path>]',
    '  clawverify verify export-bundle --input <path> [--config <path>]',
    '',
    'Exit codes:',
    '  0 = PASS (valid)',
    '  1 = FAIL (invalid)',
    '  2 = USAGE/CONFIG error',
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

function parseCliArgs(argv: string[]): {
  kind: CliKind;
  inputPath: string;
  configPath?: string;
} {
  if (argv.length === 0 || hasFlag(argv, '--help') || hasFlag(argv, '-h')) {
    throw new CliUsageError(usageText());
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
    throw new CliUsageError('Missing required flag: --input');
  }

  const configPath = readFlag(argv, '--config');

  return { kind, inputPath, configPath };
}

function output(out: CliOutput): void {
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
}

async function main() {
  const { kind, inputPath, configPath } = parseCliArgs(process.argv.slice(2));

  const config = await resolveVerifierConfig({ configPath });

  const out =
    kind === 'proof_bundle'
      ? await verifyProofBundleFromFile({ inputPath, configPath, config })
      : await verifyExportBundleFromFile({ inputPath, configPath, config });

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
    });
    process.exitCode = 2;
    return;
  }

  output({
    status: 'ERROR',
    verified_at: verifiedAt,
    reason_code: 'INTERNAL_ERROR',
    reason: err instanceof Error ? err.message : 'unknown error',
  });
  process.exitCode = 2;
});
