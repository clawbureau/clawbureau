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
