/**
 * `clawsig work list` — List available bounties from the marketplace.
 *
 * Fetches bounties via GET /v1/bounties, applies local filters,
 * and renders as either a compact human-readable table or JSON.
 */

import { loadIdentity } from './identity.js';
import {
  DEFAULT_MARKETPLACE_URL,
  loadWorkConfig,
} from './work-config.js';
import { listBounties } from './work-api.js';
import type { Bounty } from './work-api.js';
import { printJson, printJsonError } from './json-output.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WorkListOptions {
  /** JSON output mode. */
  json?: boolean;
  /** Comma-separated skills filter. */
  skills?: string;
  /** Minimum budget filter. */
  budgetMin?: number;
  /** Repository filter (owner/repo). */
  repo?: string;
  /** Override marketplace URL. */
  marketplace?: string;
  /** Project directory (defaults to cwd). */
  projectDir?: string;
}

export interface WorkListResult {
  status: 'ok' | 'error';
  bounties: Bounty[];
  total: number;
  filtered: number;
  marketplace: string;
  workerDid: string | null;
  error?: { code: string; message: string };
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

/**
 * Parse a comma-separated skills string into a normalised set.
 * Trims whitespace and lowercases for case-insensitive matching.
 */
export function parseSkillsCsv(csv: string): string[] {
  return csv
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
}

/**
 * Apply local filters to a bounty list.
 * All filters are AND-combined.
 */
export function filterBounties(
  bounties: Bounty[],
  options: { skills?: string[]; budgetMin?: number; repo?: string },
): Bounty[] {
  let result = bounties;

  if (options.skills && options.skills.length > 0) {
    const wanted = new Set(options.skills);
    result = result.filter((b) => {
      if (!Array.isArray(b.skills) || b.skills.length === 0) return false;
      return b.skills.some((s) => wanted.has(s.toLowerCase()));
    });
  }

  if (options.budgetMin !== undefined && options.budgetMin > 0) {
    const min = options.budgetMin;
    result = result.filter((b) => {
      if (typeof b.budget !== 'number') return false;
      return b.budget >= min;
    });
  }

  if (options.repo) {
    const target = options.repo.toLowerCase();
    result = result.filter((b) => {
      if (typeof b.repo !== 'string') return false;
      return b.repo.toLowerCase() === target;
    });
  }

  return result;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + '\u2026';
}

function pad(s: string, len: number): string {
  return s.length >= len ? s : s + ' '.repeat(len - s.length);
}

export function renderTable(bounties: Bounty[]): string {
  if (bounties.length === 0) {
    return 'No bounties found.';
  }

  const lines: string[] = [];

  // Header
  const hId = pad('ID', 14);
  const hBudget = pad('BUDGET', 10);
  const hRepo = pad('REPO', 28);
  const hTitle = 'TITLE';
  lines.push(`${hId} ${hBudget} ${hRepo} ${hTitle}`);
  lines.push('-'.repeat(78));

  for (const b of bounties) {
    const id = pad(truncate(b.id, 13), 14);
    const budget =
      typeof b.budget === 'number'
        ? pad(`${b.budget}${b.currency ? ' ' + b.currency : ''}`, 10)
        : pad('-', 10);
    const repo = pad(truncate(b.repo ?? '-', 27), 28);
    const title = truncate(b.title || '(untitled)', 40);
    lines.push(`${id} ${budget} ${repo} ${title}`);
  }

  return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Command implementation
// ---------------------------------------------------------------------------

export async function runWorkList(options: WorkListOptions = {}): Promise<WorkListResult> {
  const jsonMode = !!options.json;

  // 1. Resolve marketplace URL: flag > work config > default.
  let marketplaceUrl = options.marketplace;
  let workerDid: string | null = null;

  // Best-effort: read work config for marketplace + DID context.
  const workConfig = await loadWorkConfig(options.projectDir);
  if (workConfig) {
    if (!marketplaceUrl) {
      marketplaceUrl = workConfig.marketplaceUrl;
    }
    workerDid = workConfig.workerDid;
  }

  // If still no marketplace, try identity for DID context, then use default.
  if (!workerDid) {
    const identity = await loadIdentity(options.projectDir);
    if (identity) {
      workerDid = identity.did;
    }
  }

  marketplaceUrl = marketplaceUrl ?? DEFAULT_MARKETPLACE_URL;

  // 2. Fetch bounties.
  const result = await listBounties(marketplaceUrl, workerDid ?? undefined);

  if (!result.ok) {
    const errResult: WorkListResult = {
      status: 'error',
      bounties: [],
      total: 0,
      filtered: 0,
      marketplace: marketplaceUrl,
      workerDid,
      error: { code: result.code, message: result.message },
    };

    if (jsonMode) {
      process.exitCode = 1;
      printJsonError({ code: result.code, message: result.message });
    } else {
      process.exitCode = 1;
      process.stderr.write(`Error: ${result.message}\n`);
    }

    return errResult;
  }

  // 3. Apply local filters.
  const skills = options.skills ? parseSkillsCsv(options.skills) : undefined;
  const filtered = filterBounties(result.bounties, {
    skills,
    budgetMin: options.budgetMin,
    repo: options.repo,
  });

  // 4. Output.
  if (jsonMode) {
    printJson({
      status: 'ok',
      marketplace: marketplaceUrl,
      worker_did: workerDid,
      total: result.bounties.length,
      filtered: filtered.length,
      bounties: filtered,
    });
  } else {
    if (workerDid) {
      process.stdout.write(`Worker: ${workerDid}\n`);
    }
    process.stdout.write(`Marketplace: ${marketplaceUrl}\n`);
    process.stdout.write(`Showing ${filtered.length} of ${result.bounties.length} bounties\n\n`);
    process.stdout.write(renderTable(filtered) + '\n');
  }

  return {
    status: 'ok',
    bounties: filtered,
    total: result.bounties.length,
    filtered: filtered.length,
    marketplace: marketplaceUrl,
    workerDid,
  };
}
