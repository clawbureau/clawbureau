import type {
  RequiredProofTier,
  TaskDeliverable,
  TaskSpecV1,
} from './task-spec.generated.js';

const REPO_RE = /^[^/\s]+\/[^/\s]+$/;
const MAX_OBJECTIVE_LENGTH = 20_000;
const MAX_BASE_REF_LENGTH = 256;
const MAX_FILES_HINT_LENGTH = 1_024;
const MAX_COMMAND_LENGTH = 512;
const MAX_TIMEOUT_SECONDS = 86_400;
const MAX_FILES_CHANGED = 100_000;
const MAX_FORBIDDEN_PATTERN_LENGTH = 256;
const REQUIRED_PROOF_TIERS: ReadonlySet<RequiredProofTier> = new Set(['self', 'gateway', 'sandbox']);
const DELIVERABLES: ReadonlySet<TaskDeliverable> = new Set(['pr', 'proof_bundle', 'did_signature']);

export interface TaskSpecValidationIssue {
  path: string;
  message: string;
}

export type TaskSpecValidationResult =
  | { ok: true; taskSpec: TaskSpecV1 }
  | { ok: false; issues: TaskSpecValidationIssue[] };

function isRecord(input: unknown): input is Record<string, unknown> {
  return !!input && typeof input === 'object' && !Array.isArray(input);
}

function pushIssue(issues: TaskSpecValidationIssue[], path: string, message: string): void {
  issues.push({ path, message });
}

function rejectUnknownKeys(
  issues: TaskSpecValidationIssue[],
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  path: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      pushIssue(issues, path, `unexpected property: ${key}`);
    }
  }
}

function parseNonEmptyString(
  value: unknown,
  path: string,
  issues: TaskSpecValidationIssue[],
  opts?: { maxLength?: number },
): string | undefined {
  if (typeof value !== 'string') {
    pushIssue(issues, path, 'must be a string');
    return undefined;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    pushIssue(issues, path, 'must not be empty');
    return undefined;
  }

  if (opts?.maxLength !== undefined && trimmed.length > opts.maxLength) {
    pushIssue(issues, path, `must be at most ${opts.maxLength} characters`);
    return undefined;
  }

  return trimmed;
}

function parseStringArray(
  value: unknown,
  path: string,
  issues: TaskSpecValidationIssue[],
  opts?: { minItems?: number; maxItemLength?: number },
): string[] | undefined {
  if (!Array.isArray(value)) {
    pushIssue(issues, path, 'must be an array');
    return undefined;
  }

  if ((opts?.minItems ?? 0) > value.length) {
    pushIssue(issues, path, `must have at least ${opts?.minItems ?? 0} item(s)`);
  }

  const out: string[] = [];
  for (let i = 0; i < value.length; i += 1) {
    const itemPath = `${path}[${i}]`;
    if (typeof value[i] !== 'string') {
      pushIssue(issues, itemPath, 'must be a string');
      continue;
    }

    const trimmed = value[i].trim();
    if (!trimmed) {
      pushIssue(issues, itemPath, 'must not be empty');
      continue;
    }

    if (opts?.maxItemLength !== undefined && trimmed.length > opts.maxItemLength) {
      pushIssue(issues, itemPath, `must be at most ${opts.maxItemLength} characters`);
      continue;
    }

    out.push(trimmed);
  }

  return out;
}

function parsePositiveInteger(
  value: unknown,
  path: string,
  issues: TaskSpecValidationIssue[],
  opts?: { maximum?: number },
): number | undefined {
  if (!Number.isInteger(value)) {
    pushIssue(issues, path, 'must be an integer');
    return undefined;
  }

  const parsed = value as number;
  if (parsed <= 0) {
    pushIssue(issues, path, 'must be greater than 0');
    return undefined;
  }

  if (opts?.maximum !== undefined && parsed > opts.maximum) {
    pushIssue(issues, path, `must be less than or equal to ${opts.maximum}`);
    return undefined;
  }

  return parsed;
}

export function parseTaskSpecV1(input: unknown): TaskSpecValidationResult {
  const issues: TaskSpecValidationIssue[] = [];
  if (!isRecord(input)) {
    pushIssue(issues, 'task_spec', 'must be an object');
    return { ok: false, issues };
  }

  rejectUnknownKeys(
    issues,
    input,
    new Set([
      'version',
      'objective',
      'repo',
      'base_ref',
      'files_hint',
      'validation',
      'constraints',
      'deliverables',
    ]),
    'task_spec',
  );

  const version = input.version;
  if (version !== '1') {
    pushIssue(issues, 'task_spec.version', 'must be "1"');
  }

  const objective = parseNonEmptyString(
    input.objective,
    'task_spec.objective',
    issues,
    { maxLength: MAX_OBJECTIVE_LENGTH },
  );
  const repo = parseNonEmptyString(input.repo, 'task_spec.repo', issues);
  if (repo && !REPO_RE.test(repo)) {
    pushIssue(issues, 'task_spec.repo', 'must match owner/repo format');
  }

  const baseRef = parseNonEmptyString(
    input.base_ref,
    'task_spec.base_ref',
    issues,
    { maxLength: MAX_BASE_REF_LENGTH },
  );
  const filesHint = parseStringArray(
    input.files_hint,
    'task_spec.files_hint',
    issues,
    { maxItemLength: MAX_FILES_HINT_LENGTH },
  ) ?? [];

  let commands: string[] = [];
  let timeoutSeconds: number | undefined;
  if (!isRecord(input.validation)) {
    pushIssue(issues, 'task_spec.validation', 'must be an object');
  } else {
    rejectUnknownKeys(
      issues,
      input.validation,
      new Set(['commands', 'timeout_seconds']),
      'task_spec.validation',
    );

    commands = parseStringArray(
      input.validation.commands,
      'task_spec.validation.commands',
      issues,
      { minItems: 1, maxItemLength: MAX_COMMAND_LENGTH },
    ) ?? [];

    timeoutSeconds = parsePositiveInteger(
      input.validation.timeout_seconds,
      'task_spec.validation.timeout_seconds',
      issues,
      { maximum: MAX_TIMEOUT_SECONDS },
    );
  }

  let maxFilesChanged: number | undefined;
  let forbiddenPatterns: string[] = [];
  let requiredProofTier: RequiredProofTier | undefined;
  if (!isRecord(input.constraints)) {
    pushIssue(issues, 'task_spec.constraints', 'must be an object');
  } else {
    rejectUnknownKeys(
      issues,
      input.constraints,
      new Set(['max_files_changed', 'forbidden_patterns', 'required_proof_tier']),
      'task_spec.constraints',
    );

    maxFilesChanged = parsePositiveInteger(
      input.constraints.max_files_changed,
      'task_spec.constraints.max_files_changed',
      issues,
      { maximum: MAX_FILES_CHANGED },
    );

    forbiddenPatterns = parseStringArray(
      input.constraints.forbidden_patterns,
      'task_spec.constraints.forbidden_patterns',
      issues,
      { maxItemLength: MAX_FORBIDDEN_PATTERN_LENGTH },
    ) ?? [];

    const proofTierRaw = input.constraints.required_proof_tier;
    if (typeof proofTierRaw !== 'string') {
      pushIssue(issues, 'task_spec.constraints.required_proof_tier', 'must be a string');
    } else if (!REQUIRED_PROOF_TIERS.has(proofTierRaw as RequiredProofTier)) {
      pushIssue(
        issues,
        'task_spec.constraints.required_proof_tier',
        'must be one of: self, gateway, sandbox',
      );
    } else {
      requiredProofTier = proofTierRaw as RequiredProofTier;
    }
  }

  let deliverables: TaskDeliverable[] = [];
  if (!Array.isArray(input.deliverables)) {
    pushIssue(issues, 'task_spec.deliverables', 'must be an array');
  } else {
    if (input.deliverables.length === 0) {
      pushIssue(issues, 'task_spec.deliverables', 'must have at least 1 item');
    }

    const seen = new Set<TaskDeliverable>();
    for (let i = 0; i < input.deliverables.length; i += 1) {
      const itemPath = `task_spec.deliverables[${i}]`;
      const raw = input.deliverables[i];
      if (typeof raw !== 'string') {
        pushIssue(issues, itemPath, 'must be a string');
        continue;
      }

      const trimmed = raw.trim();
      if (!DELIVERABLES.has(trimmed as TaskDeliverable)) {
        pushIssue(issues, itemPath, 'must be one of: pr, proof_bundle, did_signature');
        continue;
      }

      const typed = trimmed as TaskDeliverable;
      if (seen.has(typed)) {
        pushIssue(issues, itemPath, `duplicate deliverable: ${typed}`);
        continue;
      }

      seen.add(typed);
      deliverables.push(typed);
    }
  }

  if (
    issues.length > 0
    || !objective
    || !repo
    || !baseRef
    || timeoutSeconds === undefined
    || maxFilesChanged === undefined
    || !requiredProofTier
  ) {
    return { ok: false, issues };
  }

  return {
    ok: true,
    taskSpec: {
      version: '1',
      objective,
      repo,
      base_ref: baseRef,
      files_hint: filesHint,
      validation: {
        commands,
        timeout_seconds: timeoutSeconds,
      },
      constraints: {
        max_files_changed: maxFilesChanged,
        forbidden_patterns: forbiddenPatterns,
        required_proof_tier: requiredProofTier,
      },
      deliverables,
    },
  };
}

export function hasDeliverable(taskSpec: TaskSpecV1, deliverable: TaskDeliverable): boolean {
  return taskSpec.deliverables.includes(deliverable);
}
