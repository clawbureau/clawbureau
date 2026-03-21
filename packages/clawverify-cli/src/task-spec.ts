import type {
  AssuranceApprovalPolicy,
  AssurancePrivacyPosture,
  AssuranceRequiredLevel,
  AssuranceRequirementsV1,
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
const MAX_REQUIRED_PROCESSORS = 32;
const MAX_REQUIRED_PROCESSOR_LENGTH = 120;
const REQUIRED_PROOF_TIERS: ReadonlySet<RequiredProofTier> = new Set(['self', 'gateway', 'sandbox']);
const DELIVERABLES: ReadonlySet<TaskDeliverable> = new Set(['pr', 'proof_bundle', 'did_signature']);
const ASSURANCE_REQUIRED_LEVELS: ReadonlySet<AssuranceRequiredLevel> = new Set(['none', 'gateway', 'sandbox']);
const ASSURANCE_PRIVACY_POSTURES: ReadonlySet<AssurancePrivacyPosture> = new Set(['good', 'caution', 'action']);
const ASSURANCE_APPROVAL_POLICIES: ReadonlySet<AssuranceApprovalPolicy> = new Set(['none', 'human_approval_receipt']);
const ASSURANCE_REQUIRED_PROCESSOR_RE = /^[a-z0-9][a-z0-9._:-]{0,119}$/;

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

function parseAssuranceRequirementsV1(
  value: unknown,
  path: string,
  issues: TaskSpecValidationIssue[],
): AssuranceRequirementsV1 | undefined {
  if (!isRecord(value)) {
    pushIssue(issues, path, 'must be an object');
    return undefined;
  }

  rejectUnknownKeys(
    issues,
    value,
    new Set([
      'version',
      'required_assurance_level',
      'required_privacy_posture',
      'required_processors',
      'approval_policy',
    ]),
    path,
  );

  if (value.version !== '1') {
    pushIssue(issues, `${path}.version`, 'must be "1"');
  }

  let requiredAssuranceLevel: AssuranceRequiredLevel | undefined;
  if (value.required_assurance_level !== undefined) {
    const levelRaw = value.required_assurance_level;
    if (typeof levelRaw !== 'string') {
      pushIssue(issues, `${path}.required_assurance_level`, 'must be a string');
    } else if (!ASSURANCE_REQUIRED_LEVELS.has(levelRaw as AssuranceRequiredLevel)) {
      pushIssue(issues, `${path}.required_assurance_level`, 'must be one of: none, gateway, sandbox');
    } else {
      requiredAssuranceLevel = levelRaw as AssuranceRequiredLevel;
    }
  }

  let requiredPrivacyPosture: AssurancePrivacyPosture | undefined;
  if (value.required_privacy_posture !== undefined) {
    const postureRaw = value.required_privacy_posture;
    if (typeof postureRaw !== 'string') {
      pushIssue(issues, `${path}.required_privacy_posture`, 'must be a string');
    } else if (!ASSURANCE_PRIVACY_POSTURES.has(postureRaw as AssurancePrivacyPosture)) {
      pushIssue(issues, `${path}.required_privacy_posture`, 'must be one of: good, caution, action');
    } else {
      requiredPrivacyPosture = postureRaw as AssurancePrivacyPosture;
    }
  }

  let requiredProcessors: string[] | undefined;
  if (value.required_processors !== undefined) {
    if (!Array.isArray(value.required_processors)) {
      pushIssue(issues, `${path}.required_processors`, 'must be an array');
    } else {
      if (value.required_processors.length === 0) {
        pushIssue(issues, `${path}.required_processors`, 'must have at least 1 item');
      }
      if (value.required_processors.length > MAX_REQUIRED_PROCESSORS) {
        pushIssue(
          issues,
          `${path}.required_processors`,
          `must have at most ${MAX_REQUIRED_PROCESSORS} items`,
        );
      }

      const parsed: string[] = [];
      const seen = new Set<string>();
      for (let i = 0; i < value.required_processors.length; i += 1) {
        const itemPath = `${path}.required_processors[${i}]`;
        const raw = value.required_processors[i];
        if (typeof raw !== 'string') {
          pushIssue(issues, itemPath, 'must be a string');
          continue;
        }

        const trimmed = raw.trim();
        if (!trimmed) {
          pushIssue(issues, itemPath, 'must not be empty');
          continue;
        }
        if (trimmed.length > MAX_REQUIRED_PROCESSOR_LENGTH) {
          pushIssue(issues, itemPath, `must be at most ${MAX_REQUIRED_PROCESSOR_LENGTH} characters`);
          continue;
        }
        if (!ASSURANCE_REQUIRED_PROCESSOR_RE.test(trimmed)) {
          pushIssue(issues, itemPath, 'must match ^[a-z0-9][a-z0-9._:-]{0,119}$');
          continue;
        }
        if (seen.has(trimmed)) {
          pushIssue(issues, itemPath, `duplicate processor: ${trimmed}`);
          continue;
        }
        seen.add(trimmed);
        parsed.push(trimmed);
      }

      requiredProcessors = parsed;
    }
  }

  let approvalPolicy: AssuranceApprovalPolicy | undefined;
  if (value.approval_policy !== undefined) {
    const policyRaw = value.approval_policy;
    if (typeof policyRaw !== 'string') {
      pushIssue(issues, `${path}.approval_policy`, 'must be a string');
    } else if (!ASSURANCE_APPROVAL_POLICIES.has(policyRaw as AssuranceApprovalPolicy)) {
      pushIssue(issues, `${path}.approval_policy`, 'must be one of: none, human_approval_receipt');
    } else {
      approvalPolicy = policyRaw as AssuranceApprovalPolicy;
    }
  }

  if (
    requiredAssuranceLevel === undefined
    && requiredPrivacyPosture === undefined
    && requiredProcessors === undefined
    && approvalPolicy === undefined
  ) {
    pushIssue(
      issues,
      path,
      'must declare at least one requirement: required_assurance_level, required_privacy_posture, required_processors, approval_policy',
    );
  }

  if (issues.length > 0) return undefined;

  return {
    version: '1',
    ...(requiredAssuranceLevel ? { required_assurance_level: requiredAssuranceLevel } : {}),
    ...(requiredPrivacyPosture ? { required_privacy_posture: requiredPrivacyPosture } : {}),
    ...(requiredProcessors ? { required_processors: requiredProcessors } : {}),
    ...(approvalPolicy ? { approval_policy: approvalPolicy } : {}),
  };
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
  let assuranceRequirements: AssuranceRequirementsV1 | undefined;
  if (!isRecord(input.constraints)) {
    pushIssue(issues, 'task_spec.constraints', 'must be an object');
  } else {
    rejectUnknownKeys(
      issues,
      input.constraints,
      new Set(['max_files_changed', 'forbidden_patterns', 'required_proof_tier', 'assurance_requirements']),
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

    if (input.constraints.assurance_requirements !== undefined) {
      assuranceRequirements = parseAssuranceRequirementsV1(
        input.constraints.assurance_requirements,
        'task_spec.constraints.assurance_requirements',
        issues,
      );
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
        ...(assuranceRequirements ? { assurance_requirements: assuranceRequirements } : {}),
      },
      deliverables,
    },
  };
}

export function hasDeliverable(taskSpec: TaskSpecV1, deliverable: TaskDeliverable): boolean {
  return taskSpec.deliverables.includes(deliverable);
}
