/**
 * `clawsig work status` — Poll current status for a submitted bounty result.
 *
 * Resolves submission id from:
 *   1) explicit positional argument
 *   2) .clawsig/active-bounty.json (legacy local context)
 *   3) .clawsig/work.json activeBounty.submissionId
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';

import { loadIdentity } from './identity.js';
import {
  DEFAULT_MARKETPLACE_URL,
  loadWorkConfig,
  resolveWorkerAuthToken,
  workConfigPath,
} from './work-config.js';
import { getSubmissionStatus, type SubmissionStatusResponse } from './work-api.js';
import { printJson, printJsonError } from './json-output.js';

interface ActiveBountyFileContext {
  submissionId?: string;
  marketplaceUrl?: string;
}

export interface WorkStatusOptions {
  /** Optional explicit submission id (sub_...). */
  submissionId?: string;
  /** Marketplace base URL override. */
  marketplace?: string;
  /** JSON output mode. */
  json?: boolean;
  /** Keep polling until interrupted. */
  watch?: boolean;
  /** Watch interval in seconds (default: 10). */
  intervalSeconds?: number;
  /** Project directory (defaults to cwd). */
  projectDir?: string;
  /** Internal test hook to stop watch after N polls. */
  maxPolls?: number;
}

export interface WorkStatusResult {
  status: 'ok' | 'error';
  submissionId: string;
  marketplace: string;
  workerDid: string;
  watch: boolean;
  intervalSeconds: number;
  submission?: SubmissionStatusResponse;
  reasonCodes: string[];
  nextActions: string[];
  configPath: string;
  error?: { code: string; message: string; details?: unknown };
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return !!input && typeof input === 'object';
}

function asNonEmptyString(input: unknown): string | undefined {
  return typeof input === 'string' && input.trim().length > 0 ? input.trim() : undefined;
}

function asStringArray(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return input
    .filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
    .map((entry) => entry.trim());
}

async function loadActiveBountyFileContext(projectDir?: string): Promise<ActiveBountyFileContext | null> {
  const path = join(projectDir ?? process.cwd(), '.clawsig', 'active-bounty.json');
  try {
    const raw = await readFile(path, 'utf-8');
    const parsed = JSON.parse(raw) as unknown;
    if (!isRecord(parsed)) return null;

    const source = isRecord(parsed.active_bounty) ? parsed.active_bounty : parsed;
    const submissionId =
      asNonEmptyString(source.submission_id)
      ?? asNonEmptyString(source.submissionId);
    const marketplaceUrl =
      asNonEmptyString(source.marketplace_url)
      ?? asNonEmptyString(source.marketplaceUrl);

    if (!submissionId && !marketplaceUrl) return null;
    return {
      ...(submissionId ? { submissionId } : {}),
      ...(marketplaceUrl ? { marketplaceUrl } : {}),
    };
  } catch {
    return null;
  }
}

function extractReasonCodes(submission: SubmissionStatusResponse): string[] {
  const reasonCodes = new Set<string>();
  for (const code of asStringArray(submission.reason_codes)) {
    reasonCodes.add(code);
  }

  const verificationRaw = submission.verification_result;
  if (isRecord(verificationRaw)) {
    for (const code of asStringArray(verificationRaw.reason_codes)) {
      reasonCodes.add(code);
    }
  }

  return Array.from(reasonCodes);
}

function extractNextActions(submission: SubmissionStatusResponse, submissionId: string): string[] {
  const out: string[] = [];
  if (Array.isArray(submission.next_actions)) {
    out.push(...asStringArray(submission.next_actions));
  }

  if (out.length === 0) {
    if (submission.status === 'pending_review') {
      out.push(`clawsig work status ${submissionId} --watch`);
    } else if (submission.status === 'approved') {
      out.push('clawsig work list --json');
    } else if (submission.status === 'rejected' || submission.status === 'invalid') {
      out.push('clawsig work submit --proof-bundle <path>');
    } else {
      out.push(`clawsig work status ${submissionId}`);
    }
  }

  return Array.from(new Set(out));
}

function formatVerificationResult(verificationResult: unknown): string {
  if (typeof verificationResult === 'string' && verificationResult.trim().length > 0) {
    return verificationResult.trim();
  }
  if (isRecord(verificationResult)) {
    const status =
      asNonEmptyString(verificationResult.status)
      ?? asNonEmptyString(verificationResult.result)
      ?? asNonEmptyString(verificationResult.verdict);
    if (status) return status;
  }
  return '-';
}

function formatPayout(payoutRaw: unknown): string {
  if (!isRecord(payoutRaw)) return '-';

  const workerNetMinor = asNonEmptyString(payoutRaw.worker_net_minor);
  const amountMinor = asNonEmptyString(payoutRaw.amount_minor);
  const amount = asNonEmptyString(payoutRaw.amount);
  const currency = asNonEmptyString(payoutRaw.currency);

  if (workerNetMinor) return `${workerNetMinor}${currency ? ` ${currency}` : ''}`;
  if (amountMinor) return `${amountMinor}${currency ? ` ${currency}` : ''}`;
  if (amount) return `${amount}${currency ? ` ${currency}` : ''}`;

  return JSON.stringify(payoutRaw);
}

function emitError(
  jsonMode: boolean,
  code: string,
  message: string,
  nextActions: string[],
  details?: unknown,
): void {
  if (jsonMode) {
    printJsonError({
      code,
      message,
      details: {
        ...(details !== undefined ? { api: details } : {}),
        next_actions: nextActions,
      },
    });
  } else {
    process.stderr.write(`Error: ${message}\n`);
    process.stderr.write('\nNext actions:\n');
    for (const action of nextActions) {
      process.stderr.write(`  ${action}\n`);
    }
  }
}

function makeErrorResult(input: {
  submissionId: string;
  marketplace: string;
  workerDid: string;
  watch: boolean;
  intervalSeconds: number;
  reasonCodes?: string[];
  nextActions: string[];
  configPath: string;
  code: string;
  message: string;
  details?: unknown;
}): WorkStatusResult {
  return {
    status: 'error',
    submissionId: input.submissionId,
    marketplace: input.marketplace,
    workerDid: input.workerDid,
    watch: input.watch,
    intervalSeconds: input.intervalSeconds,
    reasonCodes: input.reasonCodes ?? [],
    nextActions: input.nextActions,
    configPath: input.configPath,
    error: {
      code: input.code,
      message: input.message,
      ...(input.details !== undefined ? { details: input.details } : {}),
    },
  };
}

function emitStatusSnapshot(input: {
  jsonMode: boolean;
  watch: boolean;
  marketplace: string;
  workerDid: string;
  submissionId: string;
  intervalSeconds: number;
  configPath: string;
  submission: SubmissionStatusResponse;
  reasonCodes: string[];
  nextActions: string[];
}): void {
  const polledAt = new Date().toISOString();
  if (input.jsonMode) {
    printJson({
      status: 'ok',
      marketplace: input.marketplace,
      worker_did: input.workerDid,
      submission_id: input.submissionId,
      watch: input.watch,
      interval_seconds: input.intervalSeconds,
      polled_at: polledAt,
      submission: input.submission,
      verification_result: input.submission.verification_result ?? null,
      approval_status: input.submission.approval_status ?? null,
      payout: input.submission.payout ?? null,
      reason_codes: input.reasonCodes,
      next_actions: input.nextActions,
      config_path: input.configPath,
    });
    return;
  }

  if (input.watch) {
    process.stdout.write(`[${polledAt}] Submission ${input.submissionId}\n`);
  } else {
    process.stdout.write(`Submission ${input.submissionId}\n`);
  }
  process.stdout.write(`  Status: ${input.submission.status || '-'}\n`);
  process.stdout.write(`  Verification: ${formatVerificationResult(input.submission.verification_result)}\n`);
  process.stdout.write(`  Approval: ${input.submission.approval_status ?? '-'}\n`);
  process.stdout.write(`  Payout: ${formatPayout(input.submission.payout)}\n`);
  process.stdout.write(`  Reason codes: ${input.reasonCodes.length > 0 ? input.reasonCodes.join(', ') : '-'}\n`);
  process.stdout.write(`  Marketplace: ${input.marketplace}\n`);
  if (input.nextActions.length > 0) {
    process.stdout.write('  Next actions:\n');
    for (const action of input.nextActions) {
      process.stdout.write(`    ${action}\n`);
    }
  }
  if (input.watch) {
    process.stdout.write('\n');
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export async function runWorkStatus(options: WorkStatusOptions = {}): Promise<WorkStatusResult> {
  const jsonMode = !!options.json;
  const projectDir = options.projectDir;
  const configPath = workConfigPath(projectDir);
  const watch = !!options.watch;
  const intervalSeconds = options.intervalSeconds ?? 10;

  if (!Number.isFinite(intervalSeconds) || intervalSeconds <= 0) {
    const code = 'USAGE_ERROR';
    const message = '--interval must be a positive number.';
    const nextActions = ['clawsig work status [submission_id] [--watch] [--interval <seconds>]'];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      submissionId: options.submissionId?.trim() ?? '',
      marketplace: options.marketplace ?? DEFAULT_MARKETPLACE_URL,
      workerDid: '',
      watch,
      intervalSeconds,
      nextActions,
      configPath,
      code,
      message,
    });
  }

  const identity = await loadIdentity(projectDir);
  if (!identity) {
    const code = 'IDENTITY_MISSING';
    const message = 'No persistent identity found. Run `clawsig init` first.';
    const nextActions = ['clawsig init', 'clawsig init --global'];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      submissionId: options.submissionId?.trim() ?? '',
      marketplace: options.marketplace ?? DEFAULT_MARKETPLACE_URL,
      workerDid: '',
      watch,
      intervalSeconds,
      nextActions,
      configPath,
      code,
      message,
    });
  }

  const workConfig = await loadWorkConfig(projectDir);
  if (workConfig && workConfig.workerDid !== identity.did) {
    const code = 'IDENTITY_MISMATCH';
    const message = `Identity DID (${identity.did}) does not match work config worker DID (${workConfig.workerDid}).`;
    const nextActions = ['clawsig work init --register'];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      submissionId: options.submissionId?.trim() ?? '',
      marketplace: options.marketplace ?? workConfig.marketplaceUrl ?? DEFAULT_MARKETPLACE_URL,
      workerDid: identity.did,
      watch,
      intervalSeconds,
      nextActions,
      configPath,
      code,
      message,
    });
  }

  const activeBountyFile = await loadActiveBountyFileContext(projectDir);
  const submissionId = options.submissionId?.trim()
    || activeBountyFile?.submissionId
    || workConfig?.activeBounty?.submissionId
    || '';

  if (!submissionId) {
    const code = 'SUBMISSION_MISSING';
    const message = 'No submission found. Pass a submission_id or submit work first.';
    const nextActions = [
      'clawsig work submit --proof-bundle <path>',
      'clawsig work status <submission_id>',
    ];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      submissionId: '',
      marketplace: options.marketplace ?? workConfig?.marketplaceUrl ?? DEFAULT_MARKETPLACE_URL,
      workerDid: identity.did,
      watch,
      intervalSeconds,
      nextActions,
      configPath,
      code,
      message,
    });
  }

  const marketplace = options.marketplace
    ?? activeBountyFile?.marketplaceUrl
    ?? workConfig?.activeBounty?.marketplaceUrl
    ?? workConfig?.marketplaceUrl
    ?? DEFAULT_MARKETPLACE_URL;

  const workerDid = identity.did;
  const authToken = resolveWorkerAuthToken(workConfig);

  const pollOnce = async (): Promise<WorkStatusResult> => {
    const response = await getSubmissionStatus(marketplace, submissionId, {
      workerDid,
      ...(authToken ? { authToken } : {}),
    });

    if (!response.ok) {
      const nextActions = [
        `clawsig work status ${submissionId}`,
        'clawsig work list --json',
      ];
      process.exitCode = 1;
      emitError(jsonMode, response.code, response.message, nextActions, response.details);
      return makeErrorResult({
        submissionId,
        marketplace,
        workerDid,
        watch,
        intervalSeconds,
        nextActions,
        configPath,
        code: response.code,
        message: response.message,
        details: response.details,
      });
    }

    const submission = response.submission;
    const reasonCodes = extractReasonCodes(submission);
    const nextActions = extractNextActions(submission, submissionId);

    emitStatusSnapshot({
      jsonMode,
      watch,
      marketplace,
      workerDid,
      submissionId,
      intervalSeconds,
      configPath,
      submission,
      reasonCodes,
      nextActions,
    });

    return {
      status: 'ok',
      submissionId,
      marketplace,
      workerDid,
      watch,
      intervalSeconds,
      submission,
      reasonCodes,
      nextActions,
      configPath,
    };
  };

  if (!watch) {
    return pollOnce();
  }

  if (!jsonMode) {
    process.stdout.write(`Watching submission ${submissionId} every ${intervalSeconds}s (Ctrl+C to stop)\n\n`);
  }

  let stopRequested = false;
  const onSignal = () => {
    stopRequested = true;
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);

  const intervalMs = Math.max(100, Math.round(intervalSeconds * 1000));
  let lastResult: WorkStatusResult | null = null;
  let pollCount = 0;

  try {
    while (!stopRequested) {
      const result = await pollOnce();
      lastResult = result;
      pollCount += 1;

      if (result.status === 'error') {
        return result;
      }

      if (options.maxPolls && pollCount >= options.maxPolls) {
        break;
      }

      if (stopRequested) {
        break;
      }

      await sleep(intervalMs);
    }
  } finally {
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
  }

  if (!lastResult) {
    return makeErrorResult({
      submissionId,
      marketplace,
      workerDid,
      watch,
      intervalSeconds,
      nextActions: [`clawsig work status ${submissionId}`],
      configPath,
      code: 'INTERNAL_ERROR',
      message: 'No status poll was executed.',
    });
  }

  return lastResult;
}
