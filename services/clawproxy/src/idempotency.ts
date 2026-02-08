/**
 * Idempotency enforcement for receipt issuance
 *
 * CPX-US-031: Durable idempotency across instances/deploys.
 *
 * Design:
 * - A request may include `X-Idempotency-Key` (nonce).
 * - The proxy computes a *request fingerprint* for that nonce.
 * - If the same nonce is reused:
 *   - same fingerprint => return the previously stored response/receipt
 *   - different fingerprint => fail closed
 *
 * Storage:
 * - Implemented with a per-nonce Durable Object, providing strong consistency.
 */

import type { Env, ReceiptBinding } from './types';
import { sha256B64u } from './crypto';

/**
 * Headers used for binding receipts to runs/events
 */
export const BINDING_HEADERS = {
  RUN_ID: 'X-Run-Id',
  EVENT_HASH: 'X-Event-Hash',
  NONCE: 'X-Idempotency-Key',
} as const;

/**
 * Extract binding fields from request headers
 */
export function extractBindingFromHeaders(
  request: Request
): ReceiptBinding | undefined {
  const runId = request.headers.get(BINDING_HEADERS.RUN_ID);
  const eventHash = request.headers.get(BINDING_HEADERS.EVENT_HASH);
  const nonce = request.headers.get(BINDING_HEADERS.NONCE);

  // Return undefined if no binding fields are present
  if (!runId && !eventHash && !nonce) {
    return undefined;
  }

  const binding: ReceiptBinding = {};
  if (runId) binding.runId = runId;
  if (eventHash) binding.eventHash = eventHash;
  if (nonce) binding.nonce = nonce;

  return binding;
}

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

export interface IdempotencyFingerprintInput {
  provider: string;
  provider_url: string;
  model: string | null;
  request_body: string;
  binding: {
    run_id: string | null;
    event_hash_b64u: string | null;
    policy_hash: string | null;
    token_scope_hash_b64u: string | null;
  };
  payment: {
    mode: string | null;
  };
}

/**
 * Compute a stable request fingerprint for idempotency.
 *
 * Security note: include binding fields (run_id/event_hash) so a nonce cannot be
 * reused across runs/events without being detected.
 */
export async function computeIdempotencyFingerprint(
  input: IdempotencyFingerprintInput
): Promise<string> {
  // Stable key order via explicit object literal construction.
  const canonical = {
    provider: input.provider,
    provider_url: input.provider_url,
    model: input.model,
    request_body: input.request_body,
    binding: {
      run_id: input.binding.run_id,
      event_hash_b64u: input.binding.event_hash_b64u,
      policy_hash: input.binding.policy_hash,
      token_scope_hash_b64u: input.binding.token_scope_hash_b64u,
    },
    payment: {
      mode: input.payment.mode,
    },
  };

  return sha256B64u(JSON.stringify(canonical));
}

// ---------------------------------------------------------------------------
// Durable Object protocol (internal)
// ---------------------------------------------------------------------------

const IDEMPOTENCY_TTL_MS = 5 * 60 * 1000;

type StoredEntry =
  | {
      status: 'inflight';
      fingerprint: string;
      created_at: string;
      updated_at: string;
      expires_at_ms: number;
    }
  | {
      status: 'complete';
      fingerprint: string;
      created_at: string;
      updated_at: string;
      expires_at_ms: number;
      receipt: unknown;
    };

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json',
    },
  });
}

function isNonEmptyString(x: unknown): x is string {
  return typeof x === 'string' && x.trim().length > 0;
}

export class IdempotencyDurableObject {
  private readonly state: DurableObjectState;

  constructor(state: DurableObjectState, _env: unknown) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method !== 'POST') {
      return json({ ok: false, error: 'method not allowed' }, 405);
    }

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ ok: false, error: 'invalid JSON' }, 400);
    }

    if (!body || typeof body !== 'object') {
      return json({ ok: false, error: 'body must be an object' }, 400);
    }

    if (url.pathname === '/check') {
      return this.handleCheck(body as Record<string, unknown>);
    }

    if (url.pathname === '/commit') {
      return this.handleCommit(body as Record<string, unknown>);
    }

    if (url.pathname === '/release') {
      return this.handleRelease(body as Record<string, unknown>);
    }

    return json({ ok: false, error: 'not found' }, 404);
  }

  private async handleCheck(body: Record<string, unknown>): Promise<Response> {
    const fingerprint = body.fingerprint;
    if (!isNonEmptyString(fingerprint)) {
      return json({ ok: false, error: 'fingerprint is required' }, 400);
    }

    const nowIso = new Date().toISOString();

    return this.state.blockConcurrencyWhile(async () => {
      const nowMs = Date.now();

      let existing = (await this.state.storage.get('entry')) as
        | StoredEntry
        | undefined;

      // Expire stale entries (Durable Object storage put options are not typed
      // with TTL/expiration in workers-types; expire manually).
      if (existing && existing.expires_at_ms <= nowMs) {
        await this.state.storage.delete('entry');
        existing = undefined;
      }

      if (!existing) {
        const entry: StoredEntry = {
          status: 'inflight',
          fingerprint,
          created_at: nowIso,
          updated_at: nowIso,
          expires_at_ms: nowMs + IDEMPOTENCY_TTL_MS,
        };

        await this.state.storage.put('entry', entry);

        return json({ ok: true, kind: 'new' } as const);
      }

      if (existing.fingerprint !== fingerprint) {
        return json({ ok: true, kind: 'mismatch' } as const);
      }

      if (existing.status === 'complete') {
        return json({ ok: true, kind: 'replay', receipt: existing.receipt } as const);
      }

      return json({ ok: true, kind: 'inflight' } as const);
    });
  }

  private async handleCommit(body: Record<string, unknown>): Promise<Response> {
    const fingerprint = body.fingerprint;
    if (!isNonEmptyString(fingerprint)) {
      return json({ ok: false, error: 'fingerprint is required' }, 400);
    }

    const receipt = body.receipt;

    const nowIso = new Date().toISOString();

    return this.state.blockConcurrencyWhile(async () => {
      const nowMs = Date.now();

      let existing = (await this.state.storage.get('entry')) as
        | StoredEntry
        | undefined;

      if (existing && existing.expires_at_ms <= nowMs) {
        await this.state.storage.delete('entry');
        existing = undefined;
      }

      if (!existing) {
        return json({ ok: true, kind: 'missing' } as const);
      }

      if (existing.fingerprint !== fingerprint) {
        return json({ ok: true, kind: 'mismatch' } as const);
      }

      if (existing.status === 'complete') {
        return json({ ok: true, kind: 'already_committed' } as const);
      }

      const entry: StoredEntry = {
        status: 'complete',
        fingerprint,
        created_at: existing.created_at,
        updated_at: nowIso,
        expires_at_ms: nowMs + IDEMPOTENCY_TTL_MS,
        receipt,
      };

      await this.state.storage.put('entry', entry);

      return json({ ok: true, kind: 'committed' } as const);
    });
  }

  private async handleRelease(body: Record<string, unknown>): Promise<Response> {
    const fingerprint = body.fingerprint;
    if (!isNonEmptyString(fingerprint)) {
      return json({ ok: false, error: 'fingerprint is required' }, 400);
    }

    return this.state.blockConcurrencyWhile(async () => {
      const nowMs = Date.now();

      let existing = (await this.state.storage.get('entry')) as
        | StoredEntry
        | undefined;

      if (existing && existing.expires_at_ms <= nowMs) {
        await this.state.storage.delete('entry');
        existing = undefined;
      }

      if (!existing) {
        return json({ ok: true, kind: 'missing' } as const);
      }

      if (existing.fingerprint !== fingerprint) {
        return json({ ok: true, kind: 'mismatch' } as const);
      }

      if (existing.status === 'complete') {
        return json({ ok: true, kind: 'already_committed' } as const);
      }

      await this.state.storage.delete('entry');
      return json({ ok: true, kind: 'released' } as const);
    });
  }
}

export type IdempotencyCheckResult =
  | { kind: 'new' }
  | { kind: 'replay'; receipt: unknown }
  | { kind: 'inflight' }
  | { kind: 'mismatch' };

function getIdempotencyStub(env: Env, nonce: string): DurableObjectStub {
  if (!env.IDEMPOTENCY) {
    throw new Error('IDEMPOTENCY binding is missing');
  }

  const id = env.IDEMPOTENCY.idFromName(nonce);
  return env.IDEMPOTENCY.get(id);
}

export async function checkIdempotencyAndLock(
  env: Env,
  nonce: string,
  fingerprint: string
): Promise<IdempotencyCheckResult> {
  const stub = getIdempotencyStub(env, nonce);

  const res = await stub.fetch('https://idempotency/check', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ fingerprint }),
  });

  const data = (await res.json()) as any;
  const kind = data?.kind;

  if (kind === 'new') return { kind: 'new' };
  if (kind === 'replay') return { kind: 'replay', receipt: data.receipt };
  if (kind === 'inflight') return { kind: 'inflight' };
  return { kind: 'mismatch' };
}

export async function commitIdempotency(
  env: Env,
  nonce: string,
  fingerprint: string,
  receipt: unknown
): Promise<void> {
  const stub = getIdempotencyStub(env, nonce);

  const res = await stub.fetch('https://idempotency/commit', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ fingerprint, receipt }),
  });

  const data = (await res.json()) as any;
  const kind = data?.kind;

  if (kind === 'committed' || kind === 'already_committed') return;
  if (kind === 'mismatch') throw new Error('Idempotency commit fingerprint mismatch');
  throw new Error(`Idempotency commit failed: ${kind ?? 'unknown'}`);
}

export async function releaseIdempotency(
  env: Env,
  nonce: string,
  fingerprint: string
): Promise<void> {
  const stub = getIdempotencyStub(env, nonce);

  const res = await stub.fetch('https://idempotency/release', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ fingerprint }),
  });

  const data = (await res.json()) as any;
  const kind = data?.kind;

  if (kind === 'released' || kind === 'missing' || kind === 'already_committed') return;
  if (kind === 'mismatch') throw new Error('Idempotency release fingerprint mismatch');
  throw new Error(`Idempotency release failed: ${kind ?? 'unknown'}`);
}
