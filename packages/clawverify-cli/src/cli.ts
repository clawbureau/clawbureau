#!/usr/bin/env node

import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';

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
import { hintForReasonCode, explainReasonCode, explainReasonCodeJson } from './hints.js';
import { runInit } from './init.js';
import { runMigratePolicy } from './migrate-policy.js';
import { wrap } from './wrap.js';
import { runWorkInit } from './work-cmd.js';
import { CLI_VERSION, formatCliVersion } from './version.js';
import { isJsonMode, stripJsonFlag, printJson, printJsonError } from './json-output.js';
import { rotateIdentity, RotationError } from './identity-rotation.js';
import { VALID_VISIBILITY_MODES } from './epv-crypto.js';
import type { VisibilityMode } from './epv-crypto.js';
import type { CliOutput, CliKind, CliVerifyOutput } from './types.js';

function nowIso(): string {
  return new Date().toISOString();
}

function usageText(): string {
  return [
    'clawverify / clawsig — CLI for the Clawsig Protocol',
    '',
    'Usage:',
    '  clawsig wrap [--json] [--verbose] [--no-publish] [--output <path>]',
    '               [--visibility public|owner|requester|auditor]',
    '               [--viewer-did <did>]... -- <command> [args...]',
    '  clawverify verify proof-bundle --input <path> [--urm <path>] [--config <path>] [--json]',
    '  clawverify verify export-bundle|aggregate-bundle --input <path> [--config <path>] [--json]',
    '  clawverify verify commit-sig   --input <path> [--json]',
    '  clawverify compliance <bundle.json> [--framework soc2|iso27001|eu-ai-act] [--output <file>] [--json]',
    '  clawverify migrate-policy      <v1-policy.json> [--json]',
    '  clawverify init [--dir <path>] [--force] [--global] [--json]',
    '  clawsig identity rotate [--dir <path>] [--global] [--json]',
    '  clawsig work init [--marketplace <url>] [--register] [--json]',
    '  clawverify explain <REASON_CODE> [--json]',
    '  clawverify version [--json]',
    '',
    'Global flags:',
    '  --json    Machine-parseable JSON output (no ANSI, no colors)',
    '            Works in any position before the -- separator.',
    '',
    'Exit codes:',
    '  0 = PASS (valid)',
    '  1 = FAIL (invalid)',
    '  2 = USAGE/CONFIG error',
    '',
    'Examples:',
    '  clawsig wrap -- python my_agent.py',
    '  clawsig wrap --json -- node agent.js',
    '  clawsig wrap --output bundle.json -- node agent.js',
    '  clawsig wrap --no-publish -- npx my-agent',
    '  clawverify verify proof-bundle --input bundle.json --config clawverify.config.v1.json',
    '  clawverify verify proof-bundle --input bundle.json --json',
    '  clawverify compliance bundle.json --framework soc2',
    '  clawverify init',
    '  clawsig work init',
    '  clawsig work init --marketplace https://clawbounties.clawea.workers.dev --register',
    '  clawverify explain HASH_MISMATCH',
    '  clawverify explain HASH_MISMATCH --json',
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

function readAllFlags(args: string[], name: string): string[] {
  const values: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === name && args[i + 1] && !args[i + 1]!.startsWith('--')) {
      values.push(args[i + 1]!);
    }
  }
  return values;
}

type ParsedArgs =
  | { command: 'verify'; kind: CliKind; inputPath: string; configPath?: string; urmPath?: string }
  | { command: 'compliance'; inputPath: string; framework: string; outputPath?: string }
  | { command: 'init'; targetDir?: string; force: boolean; global: boolean }
  | { command: 'work-init'; marketplace?: string; register: boolean }
  | { command: 'explain'; code: string }
  | { command: 'migrate-policy'; inputPath: string }
  | { command: 'wrap'; wrapCommand: string; wrapArgs: string[]; publish: boolean; outputPath?: string; verbose: boolean; visibility: VisibilityMode; viewerDids: string[] }
  | { command: 'identity-rotate'; targetDir?: string; global: boolean }
  | { command: 'version' };

function parseCliArgs(argv: string[]): ParsedArgs {
  if (argv.length === 0 || hasFlag(argv, '--help') || hasFlag(argv, '-h')) {
    throw new CliUsageError(usageText());
  }

  if (argv[0] === 'version' || hasFlag(argv, '--version')) {
    return { command: 'version' };
  }

  if (argv[0] === 'wrap') {
    // clawsig wrap [--no-publish] [--output <path>] -- <command> [args...]
    const dashDashIdx = argv.indexOf('--');
    if (dashDashIdx === -1 || dashDashIdx >= argv.length - 1) {
      throw new CliUsageError(
        'Usage: clawsig wrap [--no-publish] [--output <path>] -- <command> [args...]\n\n' +
        'The -- separator and a command are required.',
      );
    }

    const flagArgs = argv.slice(1, dashDashIdx);
    const publish = !flagArgs.includes('--no-publish');
    const verboseFlag = flagArgs.includes('--verbose') || flagArgs.includes('-v');
    const outputPath = readFlag(flagArgs, '--output');

    // EPV-002: visibility mode + viewer DIDs
    const visibilityRaw = readFlag(flagArgs, '--visibility') ?? 'public';
    if (!VALID_VISIBILITY_MODES.includes(visibilityRaw as VisibilityMode)) {
      throw new CliUsageError(
        `Invalid --visibility value: '${visibilityRaw}'. ` +
        `Allowed values: ${VALID_VISIBILITY_MODES.join(', ')}`,
      );
    }
    const visibility = visibilityRaw as VisibilityMode;
    const viewerDids = readAllFlags(flagArgs, '--viewer-did');

    if ((visibility === 'requester' || visibility === 'auditor') && viewerDids.length === 0) {
      throw new CliUsageError(
        `--visibility=${visibility} requires at least one --viewer-did.`,
      );
    }

    const wrapCommand = argv[dashDashIdx + 1]!;
    const wrapArgs = argv.slice(dashDashIdx + 2);

    return { command: 'wrap', wrapCommand, wrapArgs, publish, outputPath, verbose: verboseFlag, visibility, viewerDids };
  }

  if (argv[0] === 'work') {
    if (argv[1] !== 'init') {
      throw new CliUsageError(
        'Usage: clawsig work init [--marketplace <url>] [--register] [--json]\n\n' +
        'Available work subcommands: init',
      );
    }
    const marketplace = readFlag(argv, '--marketplace');
    const register = hasFlag(argv, '--register');
    return { command: 'work-init', marketplace, register };
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

  if (argv[0] === 'identity' && argv[1] === 'rotate') {
    const rest = argv.slice(2);
    const targetDir = readFlag(rest, '--dir');
    const global = hasFlag(rest, '--global');
    return { command: 'identity-rotate', targetDir, global };
  }

  if (argv[0] === 'init') {
    const targetDir = readFlag(argv, '--dir');
    const force = hasFlag(argv, '--force');
    const global = hasFlag(argv, '--global');
    return { command: 'init', targetDir, force, global };
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

/** Classify a receipt for the --json receipt_counts summary. */
function classifyReceiptType(raw: unknown): string {
  if (!raw || typeof raw !== 'object') return 'unknown';
  const r = raw as Record<string, unknown>;
  const envType = r.envelope_type as string | undefined;
  const rcptType = r.receipt_type as string | undefined;
  if (envType === 'gateway_receipt' || rcptType?.includes('gateway')) return 'gateway';
  if (envType === 'tool_receipt' || rcptType?.includes('tool')) return 'tool_call';
  if (envType === 'side_effect_receipt' || rcptType?.includes('side_effect')) return 'side_effect';
  if (envType === 'human_approval_receipt' || rcptType?.includes('human_approval')) return 'human_approval';
  return envType ?? rcptType ?? 'unknown';
}

/** Derive wrap coverage tier from receipt counts. */
function determineWrapCoverage(receiptCounts: Record<string, number>): string {
  if (receiptCounts['gateway']) return 'gateway';
  return 'self';
}

async function main() {
  const rawArgs = process.argv.slice(2);
  const jsonMode = isJsonMode(rawArgs);
  const parsed = parseCliArgs(stripJsonFlag(rawArgs));

  if (parsed.command === 'version') {
    if (jsonMode) {
      printJson({ version: CLI_VERSION, name: 'clawverify' });
    } else {
      process.stdout.write(`${formatCliVersion()}\n`);
    }
    return;
  }

  if (parsed.command === 'explain') {
    if (jsonMode) {
      printJson(explainReasonCodeJson(parsed.code));
    } else {
      process.stdout.write(`${explainReasonCode(parsed.code)}\n`);
    }
    return;
  }

  if (parsed.command === 'compliance') {
    if (jsonMode) {
      // Compliance already outputs JSON; suppress any stderr decoration
      const origStderrWrite = process.stderr.write.bind(process.stderr);
      process.stderr.write = (() => true) as typeof process.stderr.write;
      try {
        await runComplianceReport(parsed.inputPath, parsed.framework, parsed.outputPath);
      } finally {
        process.stderr.write = origStderrWrite;
      }
    } else {
      await runComplianceReport(parsed.inputPath, parsed.framework, parsed.outputPath);
    }
    return;
  }

  if (parsed.command === 'migrate-policy') {
    if (jsonMode) {
      // migrate-policy already outputs JSON to stdout; suppress stderr messages
      const origStderrWrite = process.stderr.write.bind(process.stderr);
      process.stderr.write = (() => true) as typeof process.stderr.write;
      try {
        runMigratePolicy(parsed.inputPath);
      } finally {
        process.stderr.write = origStderrWrite;
      }
    } else {
      runMigratePolicy(parsed.inputPath);
    }
    return;
  }

  if (parsed.command === 'identity-rotate') {
    try {
      const result = await rotateIdentity({
        dir: parsed.targetDir,
        global: parsed.global,
      });

      if (jsonMode) {
        printJson({
          status: 'OK',
          old_did: result.old_did,
          new_did: result.new_did,
          identity_path: result.identity_path,
          continuity_proof_path: result.continuity_proof_path,
          continuity_proof: result.continuity_proof,
        });
      } else {
        process.stdout.write('Identity rotated successfully.\n\n');
        process.stdout.write(`  Old DID: ${result.old_did}\n`);
        process.stdout.write(`  New DID: ${result.new_did}\n\n`);
        process.stdout.write(`  Identity:        ${result.identity_path}\n`);
        process.stdout.write(`  Continuity proof: ${result.continuity_proof_path}\n`);
      }
    } catch (err) {
      process.exitCode = 2;
      const message = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        printJsonError({
          code: err instanceof RotationError ? err.code : 'INTERNAL_ERROR',
          message,
        });
      } else {
        process.stderr.write(`Error: ${message}\n`);
      }
    }
    return;
  }

  if (parsed.command === 'wrap') {
    if (jsonMode) {
      // Suppress all human-readable output during wrap
      const origStdoutWrite = process.stdout.write.bind(process.stdout);
      const origStderrWrite = process.stderr.write.bind(process.stderr);
      process.stdout.write = (() => true) as typeof process.stdout.write;
      process.stderr.write = (() => true) as typeof process.stderr.write;

      const startTime = Date.now();
      let exitCode: number;
      try {
        exitCode = await wrap(parsed.wrapCommand, parsed.wrapArgs, {
          publish: parsed.publish,
          outputPath: parsed.outputPath,
          verbose: parsed.verbose,
          visibility: parsed.visibility,
          viewerDids: parsed.viewerDids,
        });
      } finally {
        process.stdout.write = origStdoutWrite;
        process.stderr.write = origStderrWrite;
      }

      const durationMs = Date.now() - startTime;

      // Read the bundle file to build a structured summary
      let bundleSummary: Record<string, unknown> = {};
      try {
        const bundleFullPath = join(process.cwd(), '.clawsig', 'proof_bundle.json');
        const bundleRaw = await readFile(bundleFullPath, 'utf-8');
        const bundle = JSON.parse(bundleRaw) as Record<string, unknown>;
        const payload = bundle.payload as Record<string, unknown> | undefined;

        const receipts = Array.isArray(payload?.receipts) ? payload.receipts : [];
        const executionReceipts = Array.isArray(payload?.execution_receipts)
          ? payload.execution_receipts
          : [];
        const networkReceipts = Array.isArray(payload?.network_receipts)
          ? payload.network_receipts
          : [];

        const receiptCounts: Record<string, number> = {};
        for (const r of receipts) {
          const type = classifyReceiptType(r);
          receiptCounts[type] = (receiptCounts[type] ?? 0) + 1;
        }
        if (executionReceipts.length > 0) {
          receiptCounts['execution'] = executionReceipts.length;
        }
        if (networkReceipts.length > 0) {
          receiptCounts['network'] = networkReceipts.length;
        }

        const bundleStat = await stat(bundleFullPath);

        bundleSummary = {
          agent_did: payload?.agent_did ?? bundle.signer_did ?? null,
          bundle_path: '.clawsig/proof_bundle.json',
          bundle_size_bytes: bundleStat.size,
          coverage: determineWrapCoverage(receiptCounts),
          receipt_counts: receiptCounts,
        };
      } catch {
        // Bundle file may not exist if wrap failed early
      }

      printJson({
        status: exitCode === 0 ? 'PASS' : 'FAIL',
        exit_code: exitCode,
        ...bundleSummary,
        duration_ms: durationMs,
      });

      process.exitCode = exitCode;
    } else {
      const exitCode = await wrap(parsed.wrapCommand, parsed.wrapArgs, {
        publish: parsed.publish,
        outputPath: parsed.outputPath,
        verbose: parsed.verbose,
        visibility: parsed.visibility,
        viewerDids: parsed.viewerDids,
      });
      process.exitCode = exitCode;
    }
    return;
  }

  if (parsed.command === 'work-init') {
    await runWorkInit({
      marketplace: parsed.marketplace,
      register: parsed.register,
      json: jsonMode,
    });
    return;
  }

  if (parsed.command === 'init') {
    const result = await runInit({
      targetDir: parsed.targetDir,
      force: parsed.force,
      global: parsed.global,
    });

    if (jsonMode) {
      const policyCreated = result.created.includes('policy.json');
      const policyExists = policyCreated || result.skipped.includes('policy.json');
      printJson({
        identity_created: false,
        identity_did: null,
        identity_path: null,
        policy_created: policyCreated,
        policy_path: policyExists ? join(result.dir, 'policy.json') : null,
        dir: result.dir,
        created: result.created,
        skipped: result.skipped,
      });
    } else {
      process.stdout.write(`Initialized .clawsig/ in ${result.dir}\n`);

      if (result.created.length > 0) {
        process.stdout.write(`  Created: ${result.created.join(', ')}\n`);
      }
      if (result.skipped.length > 0) {
        process.stdout.write(`  Skipped (already exists): ${result.skipped.join(', ')}\n`);
        process.stdout.write('  Use --force to overwrite existing files.\n');
      }

      if (result.did) {
        process.stdout.write(`\n  Agent DID: ${result.did}\n`);
      }

      process.stdout.write('\nNext steps:\n');
      process.stdout.write('  1. Edit .clawsig/policy.json to configure your policy\n');
      process.stdout.write('  2. Install the Claw Verified GitHub App\n');
      process.stdout.write('  3. Have an AI agent open a PR with a proof bundle\n');
      process.stdout.write('\nDocs: https://clawprotocol.org/github-app\n');
    }
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

  if (jsonMode) {
    if (kind === 'commit_sig') {
      const v = (out as CliVerifyOutput).verification as
        | Record<string, unknown>
        | undefined;
      printJson({
        result: out.status,
        signer_did: v?.signer_did ?? null,
        commit_sha: v?.commit_sha ?? null,
        message: v?.message ?? null,
      });
    } else if (kind === 'proof_bundle') {
      let agentDid: string | null = null;
      let receiptCount = 0;
      try {
        const raw = JSON.parse(await readFile(inputPath, 'utf-8')) as Record<
          string,
          unknown
        >;
        const envelope = (raw.envelope ?? raw) as Record<string, unknown>;
        const payload = (envelope.payload ?? envelope) as Record<
          string,
          unknown
        >;
        agentDid =
          (payload.agent_did as string) ??
          (envelope.signer_did as string) ??
          null;
        receiptCount = Array.isArray(payload.receipts)
          ? payload.receipts.length
          : 0;
      } catch {
        /* input already validated by verify */
      }

      printJson({
        result: out.status,
        tier: 'gateway',
        schema_version: 'proof_bundle.v1',
        agent_did: agentDid,
        reason_codes: out.status === 'PASS' ? [] : [out.reason_code],
        receipt_count: receiptCount,
        warnings: out.hint ? [out.hint] : [],
      });
    } else {
      // export-bundle / aggregate-bundle
      printJson({
        result: out.status,
        schema_version: kind.replace('_', '-') + '.v1',
        reason_codes: out.status === 'PASS' ? [] : [out.reason_code],
        warnings: out.hint ? [out.hint] : [],
      });
    }
  } else {
    output(out);
  }

  process.exitCode = exitCodeForOutput(out);
}

main().catch((err: unknown) => {
  const jsonModeOnError = isJsonMode(process.argv.slice(2));
  process.exitCode = 2;

  let code: string;
  let message: string;

  if (err instanceof CliUsageError) {
    code = 'USAGE_ERROR';
    message = err.message;
  } else if (err instanceof CliConfigError) {
    code = 'CONFIG_ERROR';
    message = err.message;
  } else if (err instanceof RotationError) {
    code = err.code;
    message = err.message;
  } else {
    code = 'INTERNAL_ERROR';
    message = err instanceof Error ? err.message : 'unknown error';
  }

  if (jsonModeOnError) {
    printJsonError({ code, message });
  } else {
    output({
      status: 'ERROR',
      verified_at: nowIso(),
      reason_code: code,
      reason: message,
      hint: hintForReasonCode(code),
    });
  }
});
