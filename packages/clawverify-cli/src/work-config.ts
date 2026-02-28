/**
 * Work-loop configuration for `clawsig work`.
 *
 * Manages the `.clawsig/work.json` file that stores marketplace URL,
 * worker DID, registration metadata, and creation timestamp.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Registration metadata returned by clawbounties POST /v1/workers/register. */
export interface WorkerRegistration {
  /** Worker ID assigned by the marketplace. */
  workerId: string;
  /** Timestamp of registration (ISO 8601). */
  registeredAt: string;
  /** Any additional marketplace-assigned metadata. */
  [key: string]: unknown;
}

/** Local persisted context for the currently active bounty claim. */
export interface ActiveBountyContext {
  /** Claimed bounty identifier (bty_...). */
  bountyId: string;
  /** Worker DID used to claim. */
  workerDid: string;
  /** Marketplace base URL used for the claim. */
  marketplaceUrl: string;
  /** Marketplace status returned from claim (normally "accepted"). */
  status: string;
  /** ISO timestamp when the claim context was created locally. */
  claimedAt: string;
  /** Idempotency key used for the claim call. */
  idempotencyKey: string;
  /** Optional escrow id from claim response. */
  escrowId?: string;
  /** Last submission id produced for this bounty (if any). */
  submissionId?: string;
  /** ISO timestamp of the last submit operation (if any). */
  submittedAt?: string;
}

/** On-disk format of .clawsig/work.json. */
export interface WorkConfig {
  /** Schema version for forward compatibility. */
  configVersion: '1';
  /** Worker DID (did:key:z6Mk...). */
  workerDid: string;
  /** Marketplace base URL. */
  marketplaceUrl: string;
  /** ISO 8601 timestamp of when work config was created. */
  createdAt: string;
  /** Registration metadata, present only after successful registration. */
  registration?: WorkerRegistration;
  /** Active claim context, present after `clawsig work claim`. */
  activeBounty?: ActiveBountyContext;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CLAWSIG_DIR = '.clawsig';
const WORK_CONFIG_FILENAME = 'work.json';

export const DEFAULT_MARKETPLACE_URL = 'https://clawbounties-staging.clawea.workers.dev';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Resolve the path to the work config file.
 */
export function workConfigPath(projectDir?: string): string {
  const dir = projectDir ?? process.cwd();
  return join(dir, CLAWSIG_DIR, WORK_CONFIG_FILENAME);
}

/**
 * Load an existing work config from disk.
 * Returns null if the file does not exist or is invalid.
 */
export async function loadWorkConfig(projectDir?: string): Promise<WorkConfig | null> {
  const path = workConfigPath(projectDir);
  try {
    const raw = await readFile(path, 'utf-8');
    const parsed = JSON.parse(raw) as Record<string, unknown>;

    if (
      parsed.configVersion !== '1' ||
      typeof parsed.workerDid !== 'string' ||
      typeof parsed.marketplaceUrl !== 'string' ||
      typeof parsed.createdAt !== 'string'
    ) {
      return null;
    }

    return parsed as unknown as WorkConfig;
  } catch {
    return null;
  }
}

/**
 * Write work config to disk.
 * Creates the .clawsig/ directory if it does not exist.
 */
export async function saveWorkConfig(config: WorkConfig, projectDir?: string): Promise<string> {
  const path = workConfigPath(projectDir);
  await mkdir(dirname(path), { recursive: true });
  const content = JSON.stringify(config, null, 2) + '\n';
  await writeFile(path, content, { encoding: 'utf-8' });
  return path;
}

/**
 * Check whether a work config already exists on disk.
 */
export function workConfigExists(projectDir?: string): boolean {
  return existsSync(workConfigPath(projectDir));
}

/**
 * Best-effort extraction of a worker auth token from registration metadata.
 *
 * Supports canonical shape returned by clawbounties register API:
 *   { auth: { mode: "token", token: "..." } }
 *
 * Also accepts legacy/fallback flat token fields if present.
 */
export function resolveWorkerAuthToken(config: WorkConfig | null | undefined): string | null {
  const registration = config?.registration;
  if (!registration) return null;

  const authRaw = registration['auth'];
  if (authRaw && typeof authRaw === 'object') {
    const auth = authRaw as Record<string, unknown>;
    const token = typeof auth.token === 'string' ? auth.token.trim() : '';
    if (token.length > 0) return token;
  }

  const fallbackKeys = ['token', 'auth_token', 'worker_token', 'worker_auth_token'] as const;
  for (const key of fallbackKeys) {
    const value = registration[key];
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim();
    }
  }

  return null;
}
