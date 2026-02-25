/**
 * Clawbounties marketplace API client.
 *
 * Handles worker registration with the clawbounties service.
 * All network errors are surfaced as structured results (never thrown)
 * so callers can produce clean JSON output.
 */

import type { WorkerRegistration } from './work-config.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RegisterWorkerRequest {
  workerDid: string;
}

export type RegisterWorkerResult =
  | { ok: true; registration: WorkerRegistration }
  | { ok: false; code: string; message: string };

/** A single bounty as returned by GET /v1/bounties. */
export interface Bounty {
  id: string;
  title: string;
  repo?: string;
  skills?: string[];
  budget?: number;
  currency?: string;
  status?: string;
  created_at?: string;
  /** Catch-all for extra marketplace fields. */
  [key: string]: unknown;
}

export type ListBountiesResult =
  | { ok: true; bounties: Bounty[] }
  | { ok: false; code: string; message: string };

// ---------------------------------------------------------------------------
// Internal: pluggable fetch for testability
// ---------------------------------------------------------------------------

type FetchFn = typeof globalThis.fetch;

let _fetch: FetchFn = globalThis.fetch;

/**
 * Override the fetch implementation (for testing).
 * Returns a restore function.
 */
export function __setFetch(fn: FetchFn): () => void {
  const prev = _fetch;
  _fetch = fn;
  return () => {
    _fetch = prev;
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * List bounties from the clawbounties marketplace.
 *
 * GET {marketplaceUrl}/v1/bounties
 *
 * Optional headers:
 *   X-Worker-DID: <did>  (when identity is available)
 *
 * Expected success response (200):
 *   { "bounties": [ ... ] }  or  [ ... ]
 */
export async function listBounties(
  marketplaceUrl: string,
  workerDid?: string,
): Promise<ListBountiesResult> {
  const url = `${marketplaceUrl.replace(/\/+$/, '')}/v1/bounties`;

  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  if (workerDid) {
    headers['X-Worker-DID'] = workerDid;
  }

  let response: Response;
  try {
    response = await _fetch(url, { method: 'GET', headers });
  } catch (err) {
    return {
      ok: false,
      code: 'NETWORK_ERROR',
      message: err instanceof Error ? err.message : 'fetch failed',
    };
  }

  if (!response.ok) {
    let detail = '';
    try {
      const body = await response.text();
      detail = body.slice(0, 500);
    } catch {
      // ignore read errors
    }
    return {
      ok: false,
      code: 'LIST_FAILED',
      message: `HTTP ${response.status}${detail ? ': ' + detail : ''}`,
    };
  }

  try {
    const body = await response.json();
    // Accept both { bounties: [...] } and bare array.
    const raw: unknown[] = Array.isArray(body)
      ? body
      : Array.isArray((body as Record<string, unknown>).bounties)
        ? (body as Record<string, unknown>).bounties as unknown[]
        : [];

    const bounties: Bounty[] = raw.map((item) => {
      const r = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>;
      return {
        id: typeof r.id === 'string' ? r.id : '',
        title: typeof r.title === 'string' ? r.title : '',
        ...(typeof r.repo === 'string' ? { repo: r.repo } : {}),
        ...(Array.isArray(r.skills) ? { skills: r.skills.filter((s: unknown) => typeof s === 'string') as string[] } : {}),
        ...(typeof r.budget === 'number' ? { budget: r.budget } : {}),
        ...(typeof r.currency === 'string' ? { currency: r.currency } : {}),
        ...(typeof r.status === 'string' ? { status: r.status } : {}),
        ...(typeof r.created_at === 'string' ? { created_at: r.created_at } : {}),
      } satisfies Bounty;
    });

    return { ok: true, bounties };
  } catch {
    return {
      ok: false,
      code: 'LIST_PARSE_ERROR',
      message: 'Could not parse bounty list response as JSON',
    };
  }
}

/**
 * Register a worker DID with the clawbounties marketplace.
 *
 * POST {marketplaceUrl}/v1/workers/register
 * Body: { "worker_did": "<did>" }
 *
 * Expected success response (200):
 *   { "worker_id": "...", "registered_at": "...", ... }
 */
export async function registerWorker(
  marketplaceUrl: string,
  request: RegisterWorkerRequest,
): Promise<RegisterWorkerResult> {
  const url = `${marketplaceUrl.replace(/\/+$/, '')}/v1/workers/register`;

  let response: Response;
  try {
    response = await _fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ worker_did: request.workerDid }),
    });
  } catch (err) {
    return {
      ok: false,
      code: 'NETWORK_ERROR',
      message: err instanceof Error ? err.message : 'fetch failed',
    };
  }

  if (!response.ok) {
    let detail = '';
    try {
      const body = await response.text();
      detail = body.slice(0, 500);
    } catch {
      // ignore read errors
    }
    return {
      ok: false,
      code: 'REGISTRATION_FAILED',
      message: `HTTP ${response.status}${detail ? ': ' + detail : ''}`,
    };
  }

  try {
    const body = (await response.json()) as Record<string, unknown>;
    const registration: WorkerRegistration = {
      workerId: (body.worker_id as string) ?? '',
      registeredAt: (body.registered_at as string) ?? new Date().toISOString(),
    };

    // Preserve any extra fields the marketplace returns.
    for (const [k, v] of Object.entries(body)) {
      if (k !== 'worker_id' && k !== 'registered_at') {
        registration[k] = v;
      }
    }

    return { ok: true, registration };
  } catch {
    return {
      ok: false,
      code: 'REGISTRATION_PARSE_ERROR',
      message: 'Could not parse registration response as JSON',
    };
  }
}
