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
import { runConfigSet } from './config-cmd.js';
import { hintForReasonCode, explainReasonCode, explainReasonCodeJson } from './hints.js';
import { runInit } from './init.js';
import { runMigratePolicy } from './migrate-policy.js';
import { wrap } from './wrap.js';
import { runWorkInit } from './work-cmd.js';
import { runWorkList } from './work-list.js';
import { runWorkClaim } from './work-claim.js';
import { runWorkSubmit } from './work-submit.js';
import { runWorkStatus } from './work-status.js';
import { CLI_VERSION, formatCliVersion } from './version.js';
import { isJsonMode, stripJsonFlag, printJson, printJsonError } from './json-output.js';
import { rotateIdentity, RotationError } from './identity-rotation.js';
import { runInspect, InspectError } from './inspect-cmd.js';
import { addFleetAgent, listFleetAgents, revokeFleetAgent, FleetError } from './fleet.js';
import { linkGithubIdentity, showGithubIdentity, GithubBindingError } from './identity-github.js';
import { VALID_VISIBILITY_MODES } from './epv-crypto.js';
import { signCommitProofEnvelopeForCurrentIdentity } from './commit-proof.js';
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
    '  clawsig sign-commit <sha> [--repo-claim-id <claim_id>] [--json]',
    '  clawverify compliance <bundle.json> [--framework soc2|iso27001|eu-ai-act] [--output <file>] [--json]',
    '  clawverify migrate-policy      <v1-policy.json> [--json]',
    '  clawverify init [--dir <path>] [--force] [--global] [--json]',
    '  clawsig inspect --input <bundle.json> [--decrypt] [--json]',
    '  clawsig identity show [--json]',
    '  clawsig identity link-github --github <username> [--json]',
    '  clawsig identity rotate [--dir <path>] [--global] [--json]',
    '  clawsig config set marketplace.enabled <true|false> [--json]',
    '  clawsig fleet add <name> [--json]',
    '  clawsig fleet list [--json]',
    '  clawsig fleet revoke <name> [--json]',
    '  clawsig work init [--marketplace <url>] [--register] [--json]',
    '  clawsig work list [--json] [--skills <csv>] [--budget-min <n>] [--repo <owner/repo>] [--marketplace <url>]',
    '  clawsig work claim --bounty <bty_id> [--idempotency-key <key>] [--cwc-worker-envelope <path>] [--marketplace <url>] [--json]',
    '  clawsig work submit --proof-bundle <path> [--bounty <bty_id>] [--commit-proof <path>] [--urm <path>] [--idempotency-key <key>] [--marketplace <url>] [--json]',
    '  clawsig work status [submission_id] [--watch] [--interval <seconds>] [--marketplace <url>] [--json]',
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
    '  clawsig fleet add codex-worker',
    '  clawsig fleet list --json',
    '  clawsig fleet revoke codex-worker',
    '  clawsig work init',
    '  clawsig config set marketplace.enabled false',
    '  clawsig work init --marketplace https://clawbounties.clawea.workers.dev --register',
    '  clawsig work list',
    '  clawsig work list --json --skills typescript,rust --budget-min 100',
    '  clawsig work list --repo clawbureau/clawsig-sdk',
    '  clawsig work claim --bounty bty_1234abcd',
    '  clawsig work claim --bounty bty_1234abcd --cwc-worker-envelope ./cwc-worker-envelope.json',
    '  clawsig work submit --proof-bundle .clawsig/proof_bundle.json',
    '  clawsig work submit --bounty bty_1234abcd --proof-bundle .clawsig/proof_bundle.json --commit-proof proofs/commit.sig.json',
    '  clawsig work status',
    '  clawsig work status sub_1234abcd --watch --interval 5',
    '  clawsig inspect --input bundle.json',
    '  clawsig inspect --input bundle.json --decrypt --json',
    '  clawsig identity show --json',
    '  clawsig identity link-github --github octocat --json',
    '  clawsig sign-commit $(git rev-parse HEAD)',
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
  | { command: 'config-set'; key: string; value: string }
  | { command: 'init'; targetDir?: string; force: boolean; global: boolean }
  | { command: 'work-init'; marketplace?: string; register: boolean }
  | { command: 'work-list'; marketplace?: string; skills?: string; budgetMin?: number; repo?: string }
  | { command: 'work-claim'; bountyId: string; marketplace?: string; idempotencyKey?: string; cwcWorkerEnvelopePath?: string }
  | { command: 'work-submit'; proofBundlePath: string; bountyId?: string; commitProofPath?: string; urmPath?: string; idempotencyKey?: string; marketplace?: string; resultSummary?: string }
  | { command: 'work-status'; submissionId?: string; watch: boolean; intervalSeconds?: number; marketplace?: string }
  | { command: 'explain'; code: string }
  | { command: 'migrate-policy'; inputPath: string }
  | { command: 'wrap'; wrapCommand: string; wrapArgs: string[]; publish: boolean; outputPath?: string; verbose: boolean; visibility: VisibilityMode; viewerDids: string[] }
  | { command: 'inspect'; inputPath: string; decrypt: boolean }
  | { command: 'identity-show' }
  | { command: 'identity-link-github'; githubUsername: string }
  | { command: 'identity-rotate'; targetDir?: string; global: boolean }
  | { command: 'fleet-add'; name: string }
  | { command: 'fleet-list' }
  | { command: 'fleet-revoke'; name: string }
  | { command: 'sign-commit'; commitSha: string; repoClaimId?: string }
  | { command: 'version' };

function parseCliArgs(argv: string[]): ParsedArgs {
  if (argv.length === 0 || hasFlag(argv, '--help') || hasFlag(argv, '-h')) {
    throw new CliUsageError(usageText());
  }

  if (argv[0] === 'version' || hasFlag(argv, '--version')) {
    return { command: 'version' };
  }

  if (argv[0] === 'sign-commit') {
    const commitSha = argv[1];
    if (!commitSha || commitSha.startsWith('--')) {
      throw new CliUsageError(
        'Usage: clawsig sign-commit <sha> [--repo-claim-id <claim_id>] [--json]',
      );
    }
    const repoClaimId = readFlag(argv, '--repo-claim-id');
    return { command: 'sign-commit', commitSha, repoClaimId };
  }

  if (argv[0] === 'inspect') {
    const inputPath = readFlag(argv, '--input');
    if (!inputPath) {
      throw new CliUsageError(
        'Usage: clawsig inspect --input <bundle.json> [--decrypt] [--json]\n\n' +
        'The --input flag is required.',
      );
    }
    const decrypt = hasFlag(argv, '--decrypt');
    return { command: 'inspect', inputPath, decrypt };
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

    if (visibility === 'auditor' && viewerDids.length === 0) {
      throw new CliUsageError(
        `--visibility=${visibility} requires at least one --viewer-did.`,
      );
    }

    const wrapCommand = argv[dashDashIdx + 1]!;
    const wrapArgs = argv.slice(dashDashIdx + 2);

    return { command: 'wrap', wrapCommand, wrapArgs, publish, outputPath, verbose: verboseFlag, visibility, viewerDids };
  }

  if (argv[0] === 'work') {
    if (argv[1] === 'init') {
      const marketplace = readFlag(argv, '--marketplace');
      const register = hasFlag(argv, '--register');
      return { command: 'work-init', marketplace, register };
    }

    if (argv[1] === 'list') {
      const marketplace = readFlag(argv, '--marketplace');
      const skills = readFlag(argv, '--skills');
      const budgetMinRaw = readFlag(argv, '--budget-min');
      const budgetMin = budgetMinRaw !== undefined ? Number(budgetMinRaw) : undefined;
      if (budgetMin !== undefined && (isNaN(budgetMin) || budgetMin < 0)) {
        throw new CliUsageError('--budget-min must be a non-negative number.');
      }
      const repo = readFlag(argv, '--repo');
      return { command: 'work-list', marketplace, skills, budgetMin, repo };
    }

    if (argv[1] === 'claim') {
      const bountyId = readFlag(argv, '--bounty');
      if (!bountyId) {
        throw new CliUsageError(
          'Usage: clawsig work claim --bounty <bty_id> [--idempotency-key <key>] [--cwc-worker-envelope <path>] [--marketplace <url>] [--json]\n\n' +
          'The --bounty flag is required.',
        );
      }
      const marketplace = readFlag(argv, '--marketplace');
      const idempotencyKey = readFlag(argv, '--idempotency-key');
      const cwcWorkerEnvelopePath = readFlag(argv, '--cwc-worker-envelope');
      return { command: 'work-claim', bountyId, marketplace, idempotencyKey, cwcWorkerEnvelopePath };
    }

    if (argv[1] === 'submit') {
      const proofBundlePath = readFlag(argv, '--proof-bundle');
      if (!proofBundlePath) {
        throw new CliUsageError(
          'Usage: clawsig work submit --proof-bundle <path> [--bounty <bty_id>] [--commit-proof <path>] [--urm <path>] [--idempotency-key <key>] [--marketplace <url>] [--json]\n\n' +
          'The --proof-bundle flag is required.',
        );
      }

      const bountyId = readFlag(argv, '--bounty');
      const commitProofPath = readFlag(argv, '--commit-proof');
      const urmPath = readFlag(argv, '--urm');
      const idempotencyKey = readFlag(argv, '--idempotency-key');
      const marketplace = readFlag(argv, '--marketplace');
      const resultSummary = readFlag(argv, '--result-summary');

      return {
        command: 'work-submit',
        proofBundlePath,
        bountyId,
        commitProofPath,
        urmPath,
        idempotencyKey,
        marketplace,
        resultSummary,
      };
    }

    if (argv[1] === 'status') {
      const statusArgs = argv.slice(2);
      let submissionId: string | undefined;
      for (let i = 0; i < statusArgs.length; i++) {
        const arg = statusArgs[i]!;
        if (arg === '--watch') continue;
        if (arg === '--interval' || arg === '--marketplace') {
          i += 1;
          continue;
        }
        if (arg.startsWith('--')) continue;

        if (submissionId) {
          throw new CliUsageError(
            'Usage: clawsig work status [submission_id] [--watch] [--interval <seconds>] [--marketplace <url>] [--json]\n\n' +
            'Only one optional submission_id positional argument is supported.',
          );
        }
        submissionId = arg;
      }

      const watch = hasFlag(argv, '--watch');
      const intervalRaw = readFlag(argv, '--interval');
      const intervalSeconds = intervalRaw !== undefined ? Number(intervalRaw) : undefined;
      if (intervalSeconds !== undefined && (!Number.isFinite(intervalSeconds) || intervalSeconds <= 0)) {
        throw new CliUsageError('--interval must be a positive number.');
      }
      const marketplace = readFlag(argv, '--marketplace');
      return { command: 'work-status', submissionId, watch, intervalSeconds, marketplace };
    }

    throw new CliUsageError(
      'Usage: clawsig work <subcommand> [options]\n\n' +
      'Available work subcommands: init, list, claim, submit, status',
    );
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

  if (argv[0] === 'config') {
    if (argv[1] === 'set') {
      const key = argv[2];
      const value = argv[3];
      if (!key || !value || argv.length !== 4) {
        throw new CliUsageError(
          'Usage: clawsig config set marketplace.enabled <true|false> [--json]',
        );
      }
      return { command: 'config-set', key, value };
    }
    throw new CliUsageError(
      'Usage: clawsig config set marketplace.enabled <true|false> [--json]',
    );
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

  if (argv[0] === 'identity' && argv[1] === 'show') {
    return { command: 'identity-show' };
  }

  if (argv[0] === 'identity' && argv[1] === 'link-github') {
    const rest = argv.slice(2);
    const githubUsername = readFlag(rest, '--github');
    if (!githubUsername) {
      throw new CliUsageError(
        'Usage: clawsig identity link-github --github <username> [--json]\n\n' +
        'The --github flag is required.',
      );
    }
    return { command: 'identity-link-github', githubUsername };
  }

  if (argv[0] === 'identity' && argv[1] === 'rotate') {
    const rest = argv.slice(2);
    const targetDir = readFlag(rest, '--dir');
    const global = hasFlag(rest, '--global');
    return { command: 'identity-rotate', targetDir, global };
  }

  if (argv[0] === 'fleet') {
    if (argv[1] === 'add') {
      const name = argv[2];
      if (!name || name.startsWith('--')) {
        throw new CliUsageError('Usage: clawsig fleet add <name> [--json]');
      }
      return { command: 'fleet-add', name };
    }

    if (argv[1] === 'list') {
      return { command: 'fleet-list' };
    }

    if (argv[1] === 'revoke') {
      const name = argv[2];
      if (!name || name.startsWith('--')) {
        throw new CliUsageError('Usage: clawsig fleet revoke <name> [--json]');
      }
      return { command: 'fleet-revoke', name };
    }

    throw new CliUsageError(
      'Usage: clawsig fleet <subcommand> [options]\n\n' +
      'Available fleet subcommands: add, list, revoke',
    );
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
  const nestedPayload =
    envType === 'gateway_receipt' && r.payload && typeof r.payload === 'object'
      ? (r.payload as Record<string, unknown>)
      : undefined;
  const rcptType =
    (r.receipt_type as string | undefined) ??
    (nestedPayload?.receipt_type as string | undefined);
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

  if (parsed.command === 'sign-commit') {
    const envelope = await signCommitProofEnvelopeForCurrentIdentity(parsed.commitSha, undefined, {
      repoClaimId: parsed.repoClaimId,
    });
    if (jsonMode) {
      printJson(envelope);
    } else {
      process.stdout.write(`${JSON.stringify(envelope, null, 2)}\n`);
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

  if (parsed.command === 'identity-show') {
    try {
      const result = await showGithubIdentity();
      if (jsonMode) {
        printJson(result);
      } else {
        process.stdout.write('Identity summary:\n');
        process.stdout.write(`  DID: ${result.identity_did ?? '(none)'}\n`);

        if (!result.github_binding) {
          process.stdout.write('  GitHub binding: not linked\n');
          process.stdout.write('\nRun: clawsig identity link-github --github <username>\n');
        } else {
          process.stdout.write(
            `  GitHub: ${result.github_binding.github_username} (id: ${result.github_binding.github_user_id})\n`,
          );
          process.stdout.write(`  Profile: ${result.github_binding.profile_url}\n`);
          process.stdout.write(`  Binding file: ${result.github_binding.binding_path}\n`);
          process.stdout.write(`  Updated at: ${result.github_binding.updated_at}\n`);
          process.stdout.write('  Linked DIDs:\n');
          for (const did of result.github_binding.linked_dids) {
            process.stdout.write(`    - ${did}\n`);
          }
        }
      }
    } catch (err) {
      const code = err instanceof GithubBindingError ? err.code : 'INTERNAL_ERROR';
      process.exitCode = 1;
      const message = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        printJsonError({ code, message });
      } else {
        process.stderr.write(`Error: ${message}\n`);
      }
    }
    return;
  }

  if (parsed.command === 'identity-link-github') {
    try {
      const result = await linkGithubIdentity({
        githubUsername: parsed.githubUsername,
        json: jsonMode,
      });

      if (jsonMode) {
        printJson(result);
      } else {
        process.stdout.write('GitHub identity linked.\n\n');
        process.stdout.write(`  GitHub: ${result.github_username} (id: ${result.github_user_id})\n`);
        process.stdout.write(`  DID: ${result.did}\n`);
        process.stdout.write(`  Binding file: ${result.binding_path}\n`);
        process.stdout.write('  Linked DIDs:\n');
        for (const did of result.linked_dids) {
          process.stdout.write(`    - ${did}\n`);
        }

        if (result.published) {
          process.stdout.write('  Ledger publish: yes\n');
          if (result.ledger_url) {
            process.stdout.write(`  Ledger URL: ${result.ledger_url}\n`);
          }
        } else if (result.publish_error) {
          process.stdout.write(`  Ledger publish: no (${result.publish_error.message})\n`);
        } else {
          process.stdout.write('  Ledger publish: skipped (not configured)\n');
        }
      }
    } catch (err) {
      const code = err instanceof GithubBindingError ? err.code : 'INTERNAL_ERROR';
      process.exitCode =
        code === 'IDENTITY_MISSING' || code === 'GITHUB_CLIENT_ID_MISSING' ? 2 : 1;
      const message = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        printJsonError({ code, message });
      } else {
        process.stderr.write(`Error: ${message}\n`);
      }
    }
    return;
  }

  if (parsed.command === 'inspect') {
    try {
      await runInspect({
        inputPath: parsed.inputPath,
        decrypt: parsed.decrypt,
        json: jsonMode,
      });
    } catch (err) {
      process.exitCode = 1;
      const message = err instanceof Error ? err.message : String(err);
      const code = err instanceof InspectError ? err.code : 'INTERNAL_ERROR';
      if (jsonMode) {
        printJsonError({ code, message });
      } else {
        process.stderr.write(`Error: ${message}\n`);
      }
    }
    return;
  }

  if (parsed.command === 'config-set') {
    await runConfigSet({
      key: parsed.key,
      value: parsed.value,
      json: jsonMode,
    });
    return;
  }

  if (parsed.command === 'fleet-add') {
    try {
      const result = await addFleetAgent(parsed.name);
      if (jsonMode) {
        printJson({
          status: 'OK',
          name: result.name,
          did: result.did,
          agent_status: result.status,
          key_path: result.keyPath,
          registry_path: result.registryPath,
        });
      } else {
        process.stdout.write('Fleet agent added.\n');
        process.stdout.write(`  Name: ${result.name}\n`);
        process.stdout.write(`  DID: ${result.did}\n`);
        process.stdout.write(`  Status: ${result.status}\n`);
      }
    } catch (err) {
      process.exitCode = 2;
      const message = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        printJsonError({
          code: err instanceof FleetError ? err.code : 'INTERNAL_ERROR',
          message,
        });
      } else {
        process.stderr.write(`Error: ${message}\n`);
      }
    }
    return;
  }

  if (parsed.command === 'fleet-list') {
    try {
      const agents = await listFleetAgents();
      if (jsonMode) {
        printJson({
          agents: agents.map((agent) => ({
            name: agent.name,
            did: agent.did,
            status: agent.status,
          })),
        });
      } else if (agents.length === 0) {
        process.stdout.write('No fleet agents registered.\n');
      } else {
        process.stdout.write('Fleet agents:\n');
        for (const agent of agents) {
          process.stdout.write(`  ${agent.name}  ${agent.did}  ${agent.status}\n`);
        }
      }
    } catch (err) {
      process.exitCode = 2;
      const message = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        printJsonError({
          code: err instanceof FleetError ? err.code : 'INTERNAL_ERROR',
          message,
        });
      } else {
        process.stderr.write(`Error: ${message}\n`);
      }
    }
    return;
  }

  if (parsed.command === 'fleet-revoke') {
    try {
      const result = await revokeFleetAgent(parsed.name);
      if (jsonMode) {
        printJson({
          status: 'OK',
          name: result.name,
          did: result.did,
          agent_status: result.status,
        });
      } else {
        process.stdout.write('Fleet agent revoked.\n');
        process.stdout.write(`  Name: ${result.name}\n`);
        process.stdout.write(`  DID: ${result.did}\n`);
        process.stdout.write(`  Status: ${result.status}\n`);
      }
    } catch (err) {
      process.exitCode = 2;
      const message = err instanceof Error ? err.message : String(err);
      if (jsonMode) {
        printJsonError({
          code: err instanceof FleetError ? err.code : 'INTERNAL_ERROR',
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

  if (parsed.command === 'work-list') {
    await runWorkList({
      marketplace: parsed.marketplace,
      skills: parsed.skills,
      budgetMin: parsed.budgetMin,
      repo: parsed.repo,
      json: jsonMode,
    });
    return;
  }

  if (parsed.command === 'work-claim') {
    await runWorkClaim({
      bountyId: parsed.bountyId,
      marketplace: parsed.marketplace,
      idempotencyKey: parsed.idempotencyKey,
      cwcWorkerEnvelopePath: parsed.cwcWorkerEnvelopePath,
      json: jsonMode,
    });
    return;
  }

  if (parsed.command === 'work-submit') {
    await runWorkSubmit({
      proofBundlePath: parsed.proofBundlePath,
      bountyId: parsed.bountyId,
      commitProofPath: parsed.commitProofPath,
      urmPath: parsed.urmPath,
      idempotencyKey: parsed.idempotencyKey,
      marketplace: parsed.marketplace,
      resultSummary: parsed.resultSummary,
      json: jsonMode,
    });
    return;
  }

  if (parsed.command === 'work-status') {
    await runWorkStatus({
      submissionId: parsed.submissionId,
      watch: parsed.watch,
      intervalSeconds: parsed.intervalSeconds,
      marketplace: parsed.marketplace,
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
  } else if (err instanceof FleetError) {
    code = err.code;
    message = err.message;
  } else if (err instanceof GithubBindingError) {
    code = err.code;
    message = err.message;
  } else if (err instanceof InspectError) {
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
