/**
 * Active bounty context for requester-aware proof visibility.
 *
 * Persists `.clawsig/active-bounty.json` so `clawsig wrap --visibility requester`
 * can discover the requester's DID without requiring manual --viewer-did input.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';

const CLAWSIG_DIR = '.clawsig';
const ACTIVE_BOUNTY_FILENAME = 'active-bounty.json';

export interface ActiveBountyRecord {
  bountyId: string;
  workerDid: string;
  marketplaceUrl: string;
  status: string;
  claimedAt: string;
  idempotencyKey: string;
  requesterDid?: string;
  escrowId?: string;
  submissionId?: string;
  submittedAt?: string;
}

export interface LoadActiveBountyOptions {
  /**
   * When true, missing files still return null, but corrupt / invalid files throw.
   */
  strict?: boolean;
}

export class ActiveBountyLoadError extends Error {
  readonly code = 'ACTIVE_BOUNTY_INVALID';
  readonly path: string;

  constructor(path: string, message: string) {
    super(message);
    this.name = 'ActiveBountyLoadError';
    this.path = path;
  }
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return !!input && typeof input === 'object' && !Array.isArray(input);
}

function readStringField(
  input: Record<string, unknown>,
  ...keys: string[]
): string | undefined {
  for (const key of keys) {
    const value = input[key];
    if (typeof value === 'string' && value.trim().length > 0) {
      return value.trim();
    }
  }
  return undefined;
}

function readRequiredStringField(
  input: Record<string, unknown>,
  path: string,
  ...keys: string[]
): string {
  const value = readStringField(input, ...keys);
  if (value) return value;
  throw new ActiveBountyLoadError(
    path,
    `Invalid active bounty file at ${path}: missing required field '${keys[0]}'.`,
  );
}

function validateDidField(
  fieldName: string,
  value: string | undefined,
  path: string,
): string | undefined {
  if (!value) return undefined;
  if (!value.startsWith('did:')) {
    throw new ActiveBountyLoadError(
      path,
      `Invalid active bounty file at ${path}: '${fieldName}' must start with 'did:'.`,
    );
  }
  return value;
}

function parseActiveBountyRecord(
  parsed: unknown,
  path: string,
): ActiveBountyRecord {
  if (!isRecord(parsed)) {
    throw new ActiveBountyLoadError(
      path,
      `Invalid active bounty file at ${path}: JSON document must be an object.`,
    );
  }

  const bountyId = readRequiredStringField(parsed, path, 'bountyId', 'bounty_id');
  const workerDid = validateDidField(
    'worker_did',
    readRequiredStringField(parsed, path, 'workerDid', 'worker_did'),
    path,
  );
  const marketplaceUrl = readRequiredStringField(parsed, path, 'marketplaceUrl', 'marketplace_url');
  const status = readRequiredStringField(parsed, path, 'status');
  const claimedAt = readRequiredStringField(parsed, path, 'claimedAt', 'claimed_at');
  const idempotencyKey = readRequiredStringField(parsed, path, 'idempotencyKey', 'idempotency_key');
  const requesterDid = validateDidField(
    'requester_did',
    readStringField(parsed, 'requesterDid', 'requester_did'),
    path,
  );
  const escrowId = readStringField(parsed, 'escrowId', 'escrow_id');
  const submissionId = readStringField(parsed, 'submissionId', 'submission_id');
  const submittedAt = readStringField(parsed, 'submittedAt', 'submitted_at');

  return {
    bountyId,
    workerDid: workerDid!,
    marketplaceUrl,
    status,
    claimedAt,
    idempotencyKey,
    ...(requesterDid ? { requesterDid } : {}),
    ...(escrowId ? { escrowId } : {}),
    ...(submissionId ? { submissionId } : {}),
    ...(submittedAt ? { submittedAt } : {}),
  };
}

/**
 * Resolve `.clawsig/active-bounty.json` path.
 */
export function activeBountyPath(projectDir?: string): string {
  const dir = projectDir ?? process.cwd();
  return join(dir, CLAWSIG_DIR, ACTIVE_BOUNTY_FILENAME);
}

/**
 * Load active bounty context from disk.
 * Returns null when file is missing.
 * In strict mode, corrupt / invalid files throw ActiveBountyLoadError.
 */
export async function loadActiveBounty(
  projectDir?: string,
  options?: LoadActiveBountyOptions,
): Promise<ActiveBountyRecord | null> {
  const path = activeBountyPath(projectDir);
  try {
    const raw = await readFile(path, 'utf-8');
    const parsed = JSON.parse(raw) as unknown;
    return parseActiveBountyRecord(parsed, path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    if (code === 'ENOENT') {
      return null;
    }
    if (options?.strict) {
      if (err instanceof ActiveBountyLoadError) {
        throw err;
      }
      if (err instanceof SyntaxError) {
        throw new ActiveBountyLoadError(
          path,
          `Invalid active bounty file at ${path}: could not parse JSON.`,
        );
      }
      if (err instanceof Error) {
        throw new ActiveBountyLoadError(path, err.message);
      }
      throw new ActiveBountyLoadError(
        path,
        `Invalid active bounty file at ${path}.`,
      );
    }
    return null;
  }
}

/**
 * Persist active bounty context to `.clawsig/active-bounty.json`.
 */
export async function saveActiveBounty(
  activeBounty: ActiveBountyRecord,
  projectDir?: string,
): Promise<string> {
  const path = activeBountyPath(projectDir);
  await mkdir(dirname(path), { recursive: true });

  const content = {
    schema_version: '1',
    bounty_id: activeBounty.bountyId,
    worker_did: activeBounty.workerDid,
    marketplace_url: activeBounty.marketplaceUrl,
    status: activeBounty.status,
    claimed_at: activeBounty.claimedAt,
    idempotency_key: activeBounty.idempotencyKey,
    ...(activeBounty.requesterDid ? { requester_did: activeBounty.requesterDid } : {}),
    ...(activeBounty.escrowId ? { escrow_id: activeBounty.escrowId } : {}),
    ...(activeBounty.submissionId ? { submission_id: activeBounty.submissionId } : {}),
    ...(activeBounty.submittedAt ? { submitted_at: activeBounty.submittedAt } : {}),
  };

  await writeFile(path, JSON.stringify(content, null, 2) + '\n', 'utf-8');
  return path;
}
