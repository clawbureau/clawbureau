/**
 * `clawsig work claim` — Claim a specific bounty and persist active context.
 *
 * Requires:
 * - persistent identity (`clawsig init`)
 * - work config with worker registration token (`clawsig work init --register`)
 */

import { readFile } from 'node:fs/promises';

import { loadIdentity } from './identity.js';
import { acceptBounty } from './work-api.js';
import type { AcceptBountyResponse } from './work-api.js';
import {
  DEFAULT_MARKETPLACE_URL,
  loadWorkConfig,
  resolveWorkerAuthToken,
  saveWorkConfig,
  workConfigPath,
  type ActiveBountyContext,
  type WorkConfig,
} from './work-config.js';
import { saveActiveBounty } from './active-bounty.js';
import { printJson, printJsonError } from './json-output.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WorkClaimOptions {
  /** Bounty ID (bty_...). */
  bountyId: string;
  /** Marketplace base URL override. */
  marketplace?: string;
  /** Optional custom idempotency key. */
  idempotencyKey?: string;
  /** Optional path to CWC worker envelope JSON. */
  cwcWorkerEnvelopePath?: string;
  /** JSON output mode. */
  json?: boolean;
  /** Project directory (defaults to cwd). */
  projectDir?: string;
}

export interface WorkClaimResult {
  status: 'ok' | 'error';
  bountyId: string;
  marketplace: string;
  workerDid: string;
  idempotencyKey: string;
  claim?: AcceptBountyResponse;
  activeBounty?: ActiveBountyContext;
  configPath: string;
  nextActions: string[];
  error?: { code: string; message: string; details?: unknown };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function defaultClaimIdempotencyKey(bountyId: string, workerDid: string): string {
  const key = `claim:${bountyId}:${workerDid}`;
  return key.length > 200 ? key.slice(0, 200) : key;
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return !!input && typeof input === 'object';
}

async function loadJsonObject(path: string): Promise<Record<string, unknown>> {
  const raw = await readFile(path, 'utf-8');
  const parsed = JSON.parse(raw) as unknown;
  if (!isRecord(parsed)) {
    throw new Error('JSON document must be an object');
  }
  return parsed;
}

function claimNextActions(code: string, bountyId: string): string[] {
  switch (code) {
    case 'CWC_COUNTERSIGN_REQUIRED':
      return [
        `clawsig work claim --bounty ${bountyId} --cwc-worker-envelope ./cwc-worker-envelope.json`,
      ];
    case 'WORKER_AUTH_MISSING':
    case 'UNAUTHORIZED':
      return [
        'clawsig work init --register',
        `clawsig work claim --bounty ${bountyId}`,
      ];
    case 'BOUNTY_ALREADY_ACCEPTED':
    case 'FORBIDDEN':
    case 'INVALID_STATUS':
      return [
        'clawsig work list --json',
      ];
    default:
      return [
        `clawsig work claim --bounty ${bountyId}`,
      ];
  }
}

function extractRequesterDid(claim: AcceptBountyResponse): string | undefined {
  const requesterDidRaw =
    (typeof claim['requester_did'] === 'string' ? claim['requester_did'] : undefined)
    ?? (typeof claim['requesterDid'] === 'string' ? claim['requesterDid'] : undefined);

  if (!requesterDidRaw) return undefined;
  const requesterDid = requesterDidRaw.trim();
  if (requesterDid.length === 0 || !requesterDid.startsWith('did:')) {
    return undefined;
  }
  return requesterDid;
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

function makeResultError(input: {
  bountyId: string;
  marketplace: string;
  workerDid: string;
  idempotencyKey: string;
  configPath: string;
  code: string;
  message: string;
  nextActions: string[];
  details?: unknown;
}): WorkClaimResult {
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

export async function runWorkClaim(options: WorkClaimOptions): Promise<WorkClaimResult> {
  const jsonMode = !!options.json;
  const projectDir = options.projectDir;
  const bountyId = options.bountyId.trim();
  const configPath = workConfigPath(projectDir);

  if (!bountyId) {
    const code = 'USAGE_ERROR';
    const message = '--bounty is required.';
    const nextActions = ['clawsig work claim --bounty <bty_id>'];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeResultError({
      bountyId: '',
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
    return makeResultError({
      bountyId,
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
    return makeResultError({
      bountyId,
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
    const nextActions = [
      'clawsig work init --register',
    ];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeResultError({
      bountyId,
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
  const marketplace = options.marketplace ?? workConfig.marketplaceUrl ?? DEFAULT_MARKETPLACE_URL;
  const idempotencyKey = (options.idempotencyKey?.trim() || defaultClaimIdempotencyKey(bountyId, workerDid)).slice(0, 200);

  const authToken = resolveWorkerAuthToken(workConfig);
  if (!authToken) {
    const code = 'WORKER_AUTH_MISSING';
    const message = 'No worker auth token found in work config. Re-run `clawsig work init --register`.';
    const nextActions = ['clawsig work init --register'];
    process.exitCode = 2;
    emitError(jsonMode, code, message, nextActions);
    return makeResultError({
      bountyId,
      marketplace,
      workerDid,
      idempotencyKey,
      configPath,
      code,
      message,
      nextActions,
    });
  }

  let cwcWorkerEnvelope: Record<string, unknown> | undefined;
  if (options.cwcWorkerEnvelopePath) {
    try {
      cwcWorkerEnvelope = await loadJsonObject(options.cwcWorkerEnvelopePath);
    } catch (err) {
      const code = 'CWC_ENVELOPE_INVALID';
      const message = err instanceof Error ? err.message : 'Could not parse CWC worker envelope JSON';
      const nextActions = [`Check JSON file: ${options.cwcWorkerEnvelopePath}`];
      process.exitCode = 2;
      emitError(jsonMode, code, message, nextActions);
      return makeResultError({
        bountyId,
        marketplace,
        workerDid,
        idempotencyKey,
        configPath,
        code,
        message,
        nextActions,
      });
    }
  }

  const claimResult = await acceptBounty(marketplace, bountyId, {
    workerDid,
    idempotencyKey,
    authToken,
    ...(cwcWorkerEnvelope ? { cwcWorkerEnvelope } : {}),
  });

  if (!claimResult.ok) {
    const nextActions = claimNextActions(claimResult.code, bountyId);
    process.exitCode = 1;
    emitError(jsonMode, claimResult.code, claimResult.message, nextActions, claimResult.details);
    return makeResultError({
      bountyId,
      marketplace,
      workerDid,
      idempotencyKey,
      configPath,
      code: claimResult.code,
      message: claimResult.message,
      nextActions,
      details: claimResult.details,
    });
  }

  const claim = claimResult.claim;
  const requesterDid = extractRequesterDid(claim);
  const now = new Date().toISOString();
  const activeBounty: ActiveBountyContext = {
    bountyId: claim.bounty_id || bountyId,
    workerDid,
    marketplaceUrl: marketplace,
    status: claim.status || 'accepted',
    claimedAt: now,
    idempotencyKey,
    ...(requesterDid ? { requesterDid } : {}),
    ...(typeof claim.escrow_id === 'string' && claim.escrow_id.trim().length > 0 ? { escrowId: claim.escrow_id.trim() } : {}),
  };

  const updatedConfig: WorkConfig = {
    ...workConfig,
    workerDid,
    marketplaceUrl: marketplace,
    activeBounty,
  };

  const savedConfigPath = await saveWorkConfig(updatedConfig, projectDir);
  await saveActiveBounty(activeBounty, projectDir);
  const nextActions = [
    `clawsig work submit --proof-bundle .clawsig/proof_bundle.json --bounty ${activeBounty.bountyId}`,
    'clawsig wrap --output .clawsig/proof_bundle.json -- <agent-command>',
  ];

  if (jsonMode) {
    printJson({
      status: 'ok',
      marketplace,
      worker_did: workerDid,
      bounty_id: activeBounty.bountyId,
      idempotency_key: idempotencyKey,
      config_path: savedConfigPath,
      claim,
      active_bounty: activeBounty,
      next_actions: nextActions,
    });
  } else {
    process.stdout.write(`Claimed bounty ${activeBounty.bountyId}\n`);
    process.stdout.write(`  Worker DID: ${workerDid}\n`);
    process.stdout.write(`  Marketplace: ${marketplace}\n`);
    process.stdout.write(`  Status: ${claim.status}\n`);
    process.stdout.write(`  Saved context: ${savedConfigPath}\n`);
    process.stdout.write('\nNext actions:\n');
    for (const action of nextActions) {
      process.stdout.write(`  ${action}\n`);
    }
  }

  return {
    status: 'ok',
    bountyId: activeBounty.bountyId,
    marketplace,
    workerDid,
    idempotencyKey,
    claim,
    activeBounty,
    configPath: savedConfigPath,
    nextActions,
  };
}
