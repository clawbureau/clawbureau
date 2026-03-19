/**
 * `clawsig work submit` — Submit a completed bounty with proof bundle binding.
 *
 * Requires:
 * - persistent identity (`clawsig init`)
 * - work config with worker registration token (`clawsig work init --register`)
 * - proof bundle envelope JSON
 */

import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

import { loadIdentity } from './identity.js';
import { normalizeCommitProofEnvelope } from './commit-proof.js';
import {
  DEFAULT_MARKETPLACE_URL,
  loadWorkConfig,
  resolveWorkerAuthToken,
  saveWorkConfig,
  workConfigPath,
  type ActiveBountyContext,
  type WorkConfig,
} from './work-config.js';
import {
  activeBountyPath,
  loadActiveBounty,
  saveActiveBounty,
  type ActiveBountyRecord,
} from './active-bounty.js';
import { isMarketplaceEnabled } from './runtime-config.js';
import { submitBounty } from './work-api.js';
import type { SubmitBountyResponse } from './work-api.js';
import { printJson, printJsonError } from './json-output.js';
import { hasDeliverable, parseTaskSpecV1 } from './task-spec.js';
import type { TaskDeliverable, TaskSpecV1 } from './task-spec.generated.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WorkSubmitOptions {
  /** Path to proof bundle envelope JSON (required). */
  proofBundlePath: string;
  /** Optional explicit bounty id; otherwise uses active work context. */
  bountyId?: string;
  /** Optional URM JSON path. */
  urmPath?: string;
  /** Optional commit proof envelope JSON path. */
  commitProofPath?: string;
  /** Optional custom idempotency key. */
  idempotencyKey?: string;
  /** Marketplace base URL override. */
  marketplace?: string;
  /** Optional result summary text. */
  resultSummary?: string;
  /** JSON output mode. */
  json?: boolean;
  /** Project directory (defaults to cwd). */
  projectDir?: string;
}

export interface WorkSubmitResult {
  status: 'ok' | 'error';
  submission?: SubmitBountyResponse;
  bountyId: string;
  marketplace: string;
  workerDid: string;
  idempotencyKey: string;
  configPath: string;
  taskSpec?: TaskSpecV1;
  validatedDeliverables?: TaskDeliverable[];
  nextActions: string[];
  error?: { code: string; message: string; details?: unknown };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function isRecord(input: unknown): input is Record<string, unknown> {
  return !!input && typeof input === 'object' && !Array.isArray(input);
}

async function loadJsonObject(path: string): Promise<Record<string, unknown>> {
  const raw = await readFile(path, 'utf-8');
  const parsed = JSON.parse(raw) as unknown;
  if (!isRecord(parsed)) {
    throw new Error('JSON document must be an object');
  }
  return parsed;
}

function deriveSubmitIdempotencyKey(
  bountyId: string,
  workerDid: string,
  proofBundleEnvelope: Record<string, unknown>,
  commitProofEnvelope: Record<string, unknown> | undefined,
): string {
  const digest = createHash('sha256')
    .update(
      JSON.stringify({
        schema: 'clawsig.work.submit.v1',
        bounty_id: bountyId,
        worker_did: workerDid,
        proof_bundle_envelope: proofBundleEnvelope,
        commit_proof_envelope: commitProofEnvelope ?? null,
      }),
    )
    .digest('hex');

  // Leave room under marketplace's 200-char cap.
  return `submit:auto:${digest}`.slice(0, 200);
}

function extractReceiptMissionIds(proofBundleEnvelope: Record<string, unknown>): string[] {
  const receiptsRaw = proofBundleEnvelope.receipts;
  if (!Array.isArray(receiptsRaw)) return [];

  const missionIds = new Set<string>();

  for (const item of receiptsRaw) {
    if (!isRecord(item)) continue;
    const payload = item.payload;
    if (!isRecord(payload)) continue;
    const binding = payload.binding;
    if (!isRecord(binding)) continue;
    const missionId = binding.mission_id;
    if (typeof missionId === 'string' && missionId.trim().length > 0) {
      missionIds.add(missionId.trim());
    }
  }

  return Array.from(missionIds);
}

function extractProofBundlePayload(
  proofBundleEnvelope: Record<string, unknown>,
): Record<string, unknown> {
  const payload = proofBundleEnvelope.payload;
  if (isRecord(payload)) {
    return payload;
  }
  return proofBundleEnvelope;
}

function unwrapProofBundleEnvelope(input: Record<string, unknown>): Record<string, unknown> {
  return isRecord(input.envelope) ? input.envelope : input;
}

function extractRequesterDid(
  bountyId: string,
  workerDid: string,
  activeBounty: ActiveBountyContext | undefined,
  activeBountyFile: ActiveBountyRecord | null,
): string | undefined {
  const fromWorkConfig = activeBounty?.bountyId === bountyId && activeBounty.workerDid === workerDid
    ? activeBounty.requesterDid
    : undefined;
  if (typeof fromWorkConfig === 'string' && fromWorkConfig.trim().length > 0) {
    return fromWorkConfig.trim();
  }

  const fromActiveFile = activeBountyFile?.bountyId === bountyId && activeBountyFile.workerDid === workerDid
    ? activeBountyFile.requesterDid
    : undefined;
  if (typeof fromActiveFile === 'string' && fromActiveFile.trim().length > 0) {
    return fromActiveFile.trim();
  }

  return undefined;
}

function extractViewerDids(bundlePayload: Record<string, unknown>): string[] {
  const viewerKeysRaw = bundlePayload.viewer_keys;
  if (!Array.isArray(viewerKeysRaw)) return [];

  const dids = new Set<string>();
  for (const entry of viewerKeysRaw) {
    if (!isRecord(entry)) continue;
    const did = entry.viewer_did;
    if (typeof did === 'string' && did.trim().length > 0) {
      dids.add(did.trim());
    }
  }
  return Array.from(dids);
}

function containsPrReference(value: string): boolean {
  if (value.includes('/pull/')) return true;
  if (/#\d+\b/.test(value)) return true;
  if (/\bpr\s*[:#-]?\s*\d+\b/i.test(value)) return true;
  return false;
}

function validateTaskSpecDeliverables(input: {
  taskSpec: TaskSpecV1;
  commitProofPath?: string;
  resultSummary?: string;
}): {
  ok: true;
  validatedDeliverables: TaskDeliverable[];
} | {
  ok: false;
  missing: Array<{ deliverable: TaskDeliverable; message: string }>;
} {
  const missing: Array<{ deliverable: TaskDeliverable; message: string }> = [];
  const validatedDeliverables = input.taskSpec.deliverables.slice();

  if (hasDeliverable(input.taskSpec, 'did_signature')) {
    if (!input.commitProofPath || input.commitProofPath.trim().length === 0) {
      missing.push({
        deliverable: 'did_signature',
        message: 'Missing commit signature deliverable: pass --commit-proof <path>.',
      });
    }
  }

  if (hasDeliverable(input.taskSpec, 'pr')) {
    const summary = input.resultSummary?.trim() ?? '';
    if (!summary) {
      missing.push({
        deliverable: 'pr',
        message: 'Missing PR deliverable: pass --result-summary with a PR URL or reference.',
      });
    } else if (!containsPrReference(summary)) {
      missing.push({
        deliverable: 'pr',
        message: 'PR deliverable is invalid: --result-summary must include a PR URL or #<number>.',
      });
    }
  }

  if (missing.length > 0) {
    return { ok: false, missing };
  }

  return { ok: true, validatedDeliverables };
}

function submitErrorNextActions(code: string, bountyId: string, proofBundlePath: string): string[] {
  switch (code) {
    case 'INVALID_STATUS':
    case 'BOUNTY_NOT_ASSIGNED':
      return [
        `clawsig work claim --bounty ${bountyId}`,
        'clawsig work list --json',
      ];
    case 'UNAUTHORIZED':
    case 'WORKER_AUTH_MISSING':
      return [
        'clawsig work init --register',
        `clawsig work submit --bounty ${bountyId} --proof-bundle ${proofBundlePath}`,
      ];
    case 'REPLAY_RUN_ID_REUSED':
    case 'REPLAY_RECEIPT_ID_REUSED':
      return [
        'Re-run your agent to produce a fresh run_id / receipt set.',
        `clawsig wrap --output ${proofBundlePath} -- <agent-command>`,
      ];
    default:
      return [
        `clawverify verify proof-bundle --input ${proofBundlePath} --json`,
      ];
  }
}

function buildSubmitSuccessNextActions(input: {
  response: SubmitBountyResponse;
  proofBundlePath: string;
  commitProofPath?: string;
}): string[] {
  const out: string[] = [];

  if (Array.isArray(input.response.next_actions)) {
    for (const action of input.response.next_actions) {
      if (typeof action === 'string' && action.trim().length > 0) {
        out.push(action.trim());
      }
    }
  }

  const proofStatus = input.response.verification?.proof_bundle?.status;
  const commitStatus = input.response.verification?.commit_proof?.status;

  if (input.response.status === 'pending_review') {
    out.push('clawsig work list --json');
  }

  if (proofStatus === 'invalid' || input.response.status === 'invalid') {
    out.push(`clawverify verify proof-bundle --input ${input.proofBundlePath} --json`);
    out.push(`clawsig wrap --output ${input.proofBundlePath} -- <agent-command>`);
  }

  if (commitStatus === 'invalid' && input.commitProofPath) {
    out.push(`clawverify verify commit-sig --input ${input.commitProofPath} --json`);
  }

  if (out.length === 0) {
    out.push('clawsig work list --json');
  }

  return Array.from(new Set(out));
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
  bountyId: string;
  marketplace: string;
  workerDid: string;
  idempotencyKey: string;
  configPath: string;
  code: string;
  message: string;
  nextActions: string[];
  details?: unknown;
}): WorkSubmitResult {
  return {
    status: 'error',
    bountyId: input.bountyId,
    marketplace: input.marketplace,
    workerDid: input.workerDid,
    idempotencyKey: input.idempotencyKey,
    configPath: input.configPath,
    nextActions: input.nextActions,
    error: {
      code: input.code,
      message: input.message,
      ...(input.details !== undefined ? { details: input.details } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

export async function runWorkSubmit(options: WorkSubmitOptions): Promise<WorkSubmitResult> {
  const jsonMode = !!options.json;
  const projectDir = options.projectDir;
  const configPath = workConfigPath(projectDir);
  const marketplaceEnabled = await isMarketplaceEnabled(projectDir);

  if (!marketplaceEnabled) {
    const code = 'MARKETPLACE_DISABLED';
    const message =
      'Marketplace integration is disabled (.clawsig/runtime.json: marketplace.enabled=false). ' +
      '`clawsig work submit` requires marketplace access.';
    const nextActions = [
      'clawsig config set marketplace.enabled true',
      'Use standalone mode commands: clawsig init, clawsig wrap, clawverify verify, clawsig inspect',
    ];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      bountyId: options.bountyId ?? '',
      marketplace: options.marketplace ?? DEFAULT_MARKETPLACE_URL,
      workerDid: '',
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
    });
  }

  if (!options.proofBundlePath || options.proofBundlePath.trim().length === 0) {
    const code = 'USAGE_ERROR';
    const message = '--proof-bundle is required.';
    const nextActions = ['clawsig work submit --proof-bundle <path> [--bounty <bty_id>]'];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      bountyId: options.bountyId ?? '',
      marketplace: options.marketplace ?? DEFAULT_MARKETPLACE_URL,
      workerDid: '',
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
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
      bountyId: options.bountyId ?? '',
      marketplace: options.marketplace ?? DEFAULT_MARKETPLACE_URL,
      workerDid: '',
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
    });
  }

  const workConfig = await loadWorkConfig(projectDir);
  if (!workConfig) {
    const code = 'WORK_CONFIG_MISSING';
    const message = 'No work config found. Run `clawsig work init --register` first.';
    const nextActions = ['clawsig work init --register'];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      bountyId: options.bountyId ?? '',
      marketplace: options.marketplace ?? DEFAULT_MARKETPLACE_URL,
      workerDid: identity.did,
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
    });
  }

  if (workConfig.workerDid !== identity.did) {
    const code = 'IDENTITY_MISMATCH';
    const message = `Identity DID (${identity.did}) does not match work config worker DID (${workConfig.workerDid}).`;
    const nextActions = ['clawsig work init --register'];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      bountyId: options.bountyId ?? '',
      marketplace: options.marketplace ?? workConfig.marketplaceUrl,
      workerDid: identity.did,
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
    });
  }

  const workerDid = workConfig.workerDid;
  const activeBounty = workConfig.activeBounty;
  let taskSpec: TaskSpecV1 | undefined;
  const taskSpecRaw = activeBounty?.taskSpec;
  if (taskSpecRaw !== undefined) {
    const parsedTaskSpec = parseTaskSpecV1(taskSpecRaw);
    if (!parsedTaskSpec.ok) {
      const code = 'TASK_SPEC_INVALID';
      const message = 'Stored active bounty task_spec is invalid.';
      const nextActions = [
        `clawsig work claim --bounty ${activeBounty?.bountyId ?? '<bty_id>'}`,
        'Update local active bounty context with a valid task_spec.v1 payload.',
      ];
      process.exitCode = 2;
      emitError(jsonMode, code, message, nextActions, { issues: parsedTaskSpec.issues });
      return makeErrorResult({
        bountyId: options.bountyId ?? activeBounty?.bountyId ?? '',
        marketplace: options.marketplace ?? workConfig.marketplaceUrl,
        workerDid,
        idempotencyKey: options.idempotencyKey ?? '',
        configPath,
        code,
        message,
        nextActions,
        details: { issues: parsedTaskSpec.issues },
      });
    }
    taskSpec = parsedTaskSpec.taskSpec;
  }

  let bountyId = options.bountyId?.trim();
  if (!bountyId && activeBounty?.bountyId) {
    bountyId = activeBounty.bountyId;
  }

  if (!bountyId) {
    const code = 'BOUNTY_MISSING';
    const message = 'No bounty specified. Pass --bounty or claim a bounty first.';
    const nextActions = [
      'clawsig work claim --bounty <bty_id>',
      `clawsig work submit --bounty <bty_id> --proof-bundle ${options.proofBundlePath}`,
    ];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      bountyId: '',
      marketplace: options.marketplace ?? workConfig.marketplaceUrl,
      workerDid,
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
    });
  }

  if (activeBounty?.bountyId && options.bountyId && activeBounty.bountyId !== bountyId) {
    const code = 'ACTIVE_BOUNTY_MISMATCH';
    const message = `Active bounty is ${activeBounty.bountyId}, but --bounty requested ${bountyId}.`;
    const nextActions = [
      `Use active bounty: clawsig work submit --proof-bundle ${options.proofBundlePath}`,
      `Or claim the target bounty first: clawsig work claim --bounty ${bountyId}`,
    ];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      bountyId,
      marketplace: options.marketplace ?? workConfig.marketplaceUrl,
      workerDid,
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
    });
  }

  const authToken = resolveWorkerAuthToken(workConfig);
  if (!authToken) {
    const code = 'WORKER_AUTH_MISSING';
    const message = 'No worker auth token found in work config. Re-run `clawsig work init --register`.';
    const nextActions = ['clawsig work init --register'];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      bountyId,
      marketplace: options.marketplace ?? workConfig.marketplaceUrl,
      workerDid,
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
    });
  }

  const marketplace = options.marketplace
    ?? activeBounty?.marketplaceUrl
    ?? workConfig.marketplaceUrl
    ?? DEFAULT_MARKETPLACE_URL;
  let validatedDeliverables: TaskDeliverable[] | undefined;

  let rawProofBundleEnvelope: Record<string, unknown>;
  try {
    rawProofBundleEnvelope = await loadJsonObject(options.proofBundlePath);
  } catch (err) {
    const code = 'PROOF_BUNDLE_INVALID';
    const message = err instanceof Error ? err.message : 'Could not parse proof bundle JSON';
    const nextActions = [`Check JSON file: ${options.proofBundlePath}`];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      bountyId,
      marketplace,
      workerDid,
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
    });
  }

  const proofBundleEnvelope = unwrapProofBundleEnvelope(rawProofBundleEnvelope);
  const proofBundlePayload = extractProofBundlePayload(proofBundleEnvelope);

  const proofAgentDid = proofBundlePayload.agent_did ?? proofBundleEnvelope.agent_did;
  if (typeof proofAgentDid === 'string' && proofAgentDid.trim().length > 0 && proofAgentDid.trim() !== workerDid) {
    const code = 'PROOF_AGENT_DID_MISMATCH';
    const message = `proof bundle agent_did (${proofAgentDid.trim()}) does not match worker DID (${workerDid}).`;
    const nextActions = [
      `clawsig wrap --output ${options.proofBundlePath} -- <agent-command>`,
    ];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeErrorResult({
      bountyId,
      marketplace,
      workerDid,
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
    });
  }

  const missionIds = extractReceiptMissionIds(proofBundlePayload);
  if (missionIds.length > 0 && missionIds.some((id) => id !== bountyId)) {
    const code = 'PROOF_BOUNTY_BINDING_MISMATCH';
    const message = `Receipt binding mission_id does not match target bounty ${bountyId}.`;
    const nextActions = [
      `Re-run with the correct claimed bounty: clawsig work claim --bounty ${bountyId}`,
      `Recreate proof bundle: clawsig wrap --output ${options.proofBundlePath} -- <agent-command>`,
    ];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions, { mission_ids: missionIds });
    return makeErrorResult({
      bountyId,
      marketplace,
      workerDid,
      idempotencyKey: options.idempotencyKey ?? '',
      configPath,
      code,
      message,
      nextActions,
      details: { mission_ids: missionIds },
    });
  }

  const proofVisibility = proofBundlePayload.visibility;
  let activeBountyFile: ActiveBountyRecord | null = null;
  if (!activeBounty?.requesterDid || taskSpec === undefined) {
    try {
      activeBountyFile = await loadActiveBounty(projectDir, {
        strict: proofVisibility === 'requester',
      });
    } catch (err) {
      const code = 'ACTIVE_BOUNTY_INVALID';
      const message = err instanceof Error ? err.message : 'Could not load active bounty context.';
      const nextActions = [
        `Inspect ${activeBountyPath(projectDir)}`,
        `Recreate active context: clawsig work claim --bounty ${bountyId}`,
      ];
      process.exitCode = 2;
      emitError(jsonMode, code, message, nextActions);
      return makeErrorResult({
        bountyId,
        marketplace,
        workerDid,
        idempotencyKey: options.idempotencyKey ?? '',
        configPath,
        code,
        message,
        nextActions,
      });
    }
  }

  if (taskSpec === undefined && activeBountyFile?.taskSpec !== undefined) {
    const parsedTaskSpec = parseTaskSpecV1(activeBountyFile.taskSpec);
    if (!parsedTaskSpec.ok) {
      const code = 'TASK_SPEC_INVALID';
      const message = 'Stored active bounty task_spec is invalid.';
      const nextActions = [
        `clawsig work claim --bounty ${activeBounty?.bountyId ?? activeBountyFile.bountyId ?? '<bty_id>'}`,
        'Update local active bounty context with a valid task_spec.v1 payload.',
      ];
      process.exitCode = 2;
      emitError(jsonMode, code, message, nextActions, { issues: parsedTaskSpec.issues });
      return makeErrorResult({
        bountyId,
        marketplace,
        workerDid,
        idempotencyKey: options.idempotencyKey ?? '',
        configPath,
        code,
        message,
        nextActions,
        details: { issues: parsedTaskSpec.issues },
      });
    }
    taskSpec = parsedTaskSpec.taskSpec;
  }

  const requesterDid = extractRequesterDid(bountyId, workerDid, activeBounty, activeBountyFile);
  if (proofVisibility === 'requester') {
    if (!isRecord(proofBundlePayload.encrypted_payload)) {
      const code = 'PROOF_BUNDLE_REQUESTER_ENCRYPTION_INVALID';
      const message = 'proof bundle visibility=requester requires encrypted_payload.';
      const nextActions = [
        `Recreate proof bundle: clawsig wrap --visibility requester --output ${options.proofBundlePath} -- <agent-command>`,
      ];
      process.exitCode = 2;
      emitError(jsonMode, code, message, nextActions);
      return makeErrorResult({
        bountyId,
        marketplace,
        workerDid,
        idempotencyKey: options.idempotencyKey ?? '',
        configPath,
        code,
        message,
        nextActions,
      });
    }

    if (!requesterDid) {
      const code = 'PROOF_BUNDLE_REQUESTER_DID_UNKNOWN';
      const message =
        'proof bundle visibility=requester requires requester DID from the active bounty context.';
      const nextActions = [
        `Claim the bounty first: clawsig work claim --bounty ${bountyId}`,
        `Recreate proof bundle after claim: clawsig wrap --visibility requester --output ${options.proofBundlePath} -- <agent-command>`,
      ];
      process.exitCode = 2;
      emitError(jsonMode, code, message, nextActions);
      return makeErrorResult({
        bountyId,
        marketplace,
        workerDid,
        idempotencyKey: options.idempotencyKey ?? '',
        configPath,
        code,
        message,
        nextActions,
      });
    }

    const viewerDids = extractViewerDids(proofBundlePayload);
    if (!viewerDids.includes(requesterDid)) {
      const code = 'PROOF_BUNDLE_REQUESTER_VIEWER_MISSING';
      const message = `proof bundle visibility=requester is missing requester DID in viewer_keys (${requesterDid}).`;
      const nextActions = [
        `Recreate proof bundle: clawsig wrap --visibility requester --output ${options.proofBundlePath} -- <agent-command>`,
        'Or provide requester DID explicitly: --viewer-did <requester_did>',
      ];
      process.exitCode = 2;
      emitError(jsonMode, code, message, nextActions);
      return makeErrorResult({
        bountyId,
        marketplace,
        workerDid,
        idempotencyKey: options.idempotencyKey ?? '',
        configPath,
        code,
        message,
        nextActions,
      });
    }
  }

  if (taskSpec) {
    const deliverableValidation = validateTaskSpecDeliverables({
      taskSpec,
      commitProofPath: options.commitProofPath,
      resultSummary: options.resultSummary,
    });

    if (!deliverableValidation.ok) {
      const code = 'TASK_SPEC_DELIVERABLES_MISSING';
      const message = 'Submission is missing required task_spec deliverables.';
      const nextActions = deliverableValidation.missing.map((item) => {
        if (item.deliverable === 'did_signature') {
          return `clawsig work submit --proof-bundle ${options.proofBundlePath} --bounty ${bountyId} --commit-proof proofs/<branch>/commit.sig.json`;
        }
        if (item.deliverable === 'pr') {
          return `clawsig work submit --proof-bundle ${options.proofBundlePath} --bounty ${bountyId} --result-summary "PR: https://github.com/${taskSpec.repo}/pull/<number>"`;
        }
        return `clawsig work submit --proof-bundle ${options.proofBundlePath} --bounty ${bountyId}`;
      });
      process.exitCode = 2;
      emitError(
        jsonMode,
        code,
        message,
        nextActions,
        { missing_deliverables: deliverableValidation.missing, task_spec: taskSpec },
      );
      return makeErrorResult({
        bountyId,
        marketplace,
        workerDid,
        idempotencyKey: options.idempotencyKey ?? '',
        configPath,
        code,
        message,
        nextActions,
        details: {
          missing_deliverables: deliverableValidation.missing,
          task_spec: taskSpec,
        },
      });
    }

    validatedDeliverables = deliverableValidation.validatedDeliverables;
  }

  let urm: Record<string, unknown> | undefined;
  if (options.urmPath) {
    try {
      urm = await loadJsonObject(options.urmPath);
    } catch (err) {
      const code = 'URM_INVALID';
      const message = err instanceof Error ? err.message : 'Could not parse URM JSON';
      const nextActions = [`Check JSON file: ${options.urmPath}`];
      process.exitCode = 2;
      emitError(jsonMode, code, message, nextActions);
      return makeErrorResult({
        bountyId,
        marketplace,
        workerDid,
        idempotencyKey: options.idempotencyKey ?? '',
        configPath,
        code,
        message,
        nextActions,
      });
    }
  }

  let commitProofEnvelope: Record<string, unknown> | undefined;
  if (options.commitProofPath) {
    try {
      const rawCommitProof = await loadJsonObject(options.commitProofPath);
      commitProofEnvelope = await normalizeCommitProofEnvelope(rawCommitProof, identity) as unknown as Record<string, unknown>;
    } catch (err) {
      const code = 'COMMIT_PROOF_INVALID';
      const message = err instanceof Error ? err.message : 'Could not parse commit proof JSON';
      const nextActions = [`Check JSON file: ${options.commitProofPath}`];
      process.exitCode = 2;
      emitError(jsonMode, code, message, nextActions);
      return makeErrorResult({
        bountyId,
        marketplace,
        workerDid,
        idempotencyKey: options.idempotencyKey ?? '',
        configPath,
        code,
        message,
        nextActions,
      });
    }
  }

  const idempotencyKey = (options.idempotencyKey?.trim() || deriveSubmitIdempotencyKey(
    bountyId,
    workerDid,
    proofBundleEnvelope,
    commitProofEnvelope,
  )).slice(0, 200);

  const submitResult = await submitBounty(marketplace, bountyId, {
    workerDid,
    authToken,
    proofBundleEnvelope,
    idempotencyKey,
    ...(urm ? { urm } : {}),
    ...(commitProofEnvelope ? { commitProofEnvelope } : {}),
    ...(options.resultSummary && options.resultSummary.trim().length > 0
      ? { resultSummary: options.resultSummary.trim() }
      : {}),
  });

  if (!submitResult.ok) {
    const nextActions = submitErrorNextActions(submitResult.code, bountyId, options.proofBundlePath);
    process.exitCode = 1;
    emitError(jsonMode, submitResult.code, submitResult.message, nextActions, submitResult.details);
    return makeErrorResult({
      bountyId,
      marketplace,
      workerDid,
      idempotencyKey,
      configPath,
      code: submitResult.code,
      message: submitResult.message,
      nextActions,
      details: submitResult.details,
    });
  }

  const response = submitResult.submission;
  const nextActions = buildSubmitSuccessNextActions({
    response,
    proofBundlePath: options.proofBundlePath,
    commitProofPath: options.commitProofPath,
  });

  const now = new Date().toISOString();
  const updatedActiveBounty: ActiveBountyContext = {
    bountyId,
    workerDid,
    marketplaceUrl: marketplace,
    status: response.status,
    claimedAt: activeBounty?.claimedAt ?? now,
    idempotencyKey: activeBounty?.idempotencyKey ?? idempotencyKey,
    ...(requesterDid ? { requesterDid } : {}),
    ...(activeBounty?.escrowId ? { escrowId: activeBounty.escrowId } : {}),
    ...(taskSpec ? { taskSpec } : {}),
    ...(response.submission_id ? { submissionId: response.submission_id } : {}),
    submittedAt: now,
  };

  const updatedConfig: WorkConfig = {
    ...workConfig,
    workerDid,
    marketplaceUrl: marketplace,
    activeBounty: updatedActiveBounty,
  };
  const savedConfigPath = await saveWorkConfig(updatedConfig, projectDir);
  await saveActiveBounty(updatedActiveBounty, projectDir);

  if (jsonMode) {
    printJson({
      status: 'ok',
      marketplace,
      worker_did: workerDid,
      bounty_id: bountyId,
      idempotency_key: idempotencyKey,
      submission: response,
      ...(taskSpec ? { task_spec: taskSpec } : {}),
      ...(validatedDeliverables ? { validated_deliverables: validatedDeliverables } : {}),
      next_actions: nextActions,
      config_path: savedConfigPath,
    });
  } else {
    process.stdout.write(`Submitted bounty ${bountyId}\n`);
    process.stdout.write(`  Submission ID: ${response.submission_id || '(unknown)'}\n`);
    process.stdout.write(`  Status: ${response.status}\n`);
    process.stdout.write(`  Marketplace: ${marketplace}\n`);
    process.stdout.write(`  Saved context: ${savedConfigPath}\n`);
    process.stdout.write('\nNext actions:\n');
    for (const action of nextActions) {
      process.stdout.write(`  ${action}\n`);
    }
  }

  return {
    status: 'ok',
    submission: response,
    bountyId,
    marketplace,
    workerDid,
    idempotencyKey,
    configPath: savedConfigPath,
    ...(taskSpec ? { taskSpec } : {}),
    ...(validatedDeliverables ? { validatedDeliverables } : {}),
    nextActions,
  };
}
