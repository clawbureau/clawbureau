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

/**
 * Stored replay response for an idempotency nonce.
 *
 * NOTE: `body` is expected to be the full clawproxy response (provider response
 * object + _receipt + _receipt_envelope). When storage size limits are exceeded,
 * we fall back to a compact response that preserves the receipt envelope.
 */
export interface IdempotencyStoredResponse {
  status: number;
  body: unknown;
  /** True when the stored response had to be compacted for storage safety. */
  truncated?: boolean;
}

const IDEMPOTENCY_TTL_MS = 5 * 60 * 1000;

// Durable Object storage limits are ~128KB per value. Store receipts as
// chunked JSON bytes to avoid single-value size failures.
const MAX_STORED_RESPONSE_BYTES = 512 * 1024;
const RECEIPT_CHUNK_BYTES = 64 * 1024;

const ENTRY_KEY = 'entry';
const RECEIPT_CHUNK_PREFIX = 'receipt:';

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
      receipt_bytes: number;
      receipt_chunks: number;
      receipt_truncated: boolean;
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

function encodeJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function coerceStoredResponse(value: unknown): IdempotencyStoredResponse | null {
  if (!value || typeof value !== 'object') return null;
  const v = value as Record<string, unknown>;
  if (typeof v.status !== 'number') return null;
  if (!('body' in v)) return null;

  return {
    status: v.status,
    body: v.body,
    truncated: typeof v.truncated === 'boolean' ? v.truncated : undefined,
  };
}

function buildCompactStoredResponse(value: unknown): IdempotencyStoredResponse {
  const coerced = coerceStoredResponse(value);

  const status = coerced?.status ?? 200;
  const body = coerced?.body;

  const compactBody: Record<string, unknown> = {};

  if (body && typeof body === 'object') {
    const b = body as Record<string, unknown>;

    // Preserve the canonical receipt envelope (small, verifier-friendly).
    if ('_receipt_envelope' in b) {
      compactBody._receipt_envelope = b._receipt_envelope;
    }

    // Preserve a *sanitized* legacy receipt without encrypted payloads.
    // (Encrypted request/response blobs can easily exceed DO storage limits.)
    if ('_receipt' in b && b._receipt && typeof b._receipt === 'object') {
      const r = b._receipt as Record<string, unknown>;
      const sanitized: Record<string, unknown> = {};
      const keep = [
        'version',
        'proxyDid',
        'provider',
        'model',
        'requestHash',
        'responseHash',
        'timestamp',
        'latencyMs',
        'signature',
        'kid',
        'binding',
        'payment',
        'privacyMode',
      ];
      for (const k of keep) {
        if (k in r) sanitized[k] = r[k];
      }
      compactBody._receipt = sanitized;
    }
  }

  compactBody.error = {
    code: 'IDEMPOTENCY_REPLAY_UNAVAILABLE',
    message:
      'Original response was too large to store for replay. Receipt retained; rerun the call with a new idempotency key if you need the provider response again.',
  };

  return { status, body: compactBody, truncated: true };
}

function encodeReceiptForStorage(value: unknown): {
  bytes: Uint8Array;
  truncated: boolean;
} {
  let bytes = encodeJsonBytes(value);
  if (bytes.byteLength <= MAX_STORED_RESPONSE_BYTES) {
    return { bytes, truncated: false };
  }

  // Fail safe: store a compact form that preserves the receipt envelope.
  const compact = buildCompactStoredResponse(value);
  bytes = encodeJsonBytes(compact);

  if (bytes.byteLength <= MAX_STORED_RESPONSE_BYTES) {
    return { bytes, truncated: true };
  }

  // Final fallback: extremely compact error marker.
  // Preserve `_receipt_envelope` if present (even if legacy receipt is too large).
  const ultraBody: Record<string, unknown> = {
    error: {
      code: 'IDEMPOTENCY_REPLAY_UNAVAILABLE',
      message:
        'Original response was too large to store for replay (compact marker only).',
    },
  };

  if (compact.body && typeof compact.body === 'object') {
    const cb = compact.body as Record<string, unknown>;
    if ('_receipt_envelope' in cb) {
      ultraBody._receipt_envelope = cb._receipt_envelope;
    }
  }

  const ultraCompact: IdempotencyStoredResponse = {
    status: compact.status,
    body: ultraBody,
    truncated: true,
  };

  bytes = encodeJsonBytes(ultraCompact);
  return { bytes, truncated: true };
}

async function readStoredReceipt(
  storage: DurableObjectStorage,
  entry: Extract<StoredEntry, { status: 'complete' }>
): Promise<unknown> {
  if (entry.receipt_chunks <= 0 || entry.receipt_bytes <= 0) {
    throw new Error('stored receipt metadata is invalid');
  }

  const parts = await Promise.all(
    Array.from({ length: entry.receipt_chunks }, (_, i) =>
      storage.get(`${RECEIPT_CHUNK_PREFIX}${i}`)
    )
  );

  const out = new Uint8Array(entry.receipt_bytes);
  let offset = 0;

  for (let i = 0; i < parts.length; i++) {
    const p = parts[i];
    if (!(p instanceof Uint8Array)) {
      throw new Error(`missing receipt chunk ${i}`);
    }

    out.set(p, offset);
    offset += p.byteLength;
  }

  try {
    const text = new TextDecoder('utf-8').decode(out);
    return JSON.parse(text);
  } catch {
    throw new Error('stored receipt JSON is corrupted');
  }
}

async function writeStoredReceipt(
  storage: DurableObjectStorage,
  receipt: unknown
): Promise<{ receipt_bytes: number; receipt_chunks: number; receipt_truncated: boolean }> {
  const encoded = encodeReceiptForStorage(receipt);

  const chunks = Math.ceil(encoded.bytes.byteLength / RECEIPT_CHUNK_BYTES);

  for (let i = 0; i < chunks; i++) {
    const start = i * RECEIPT_CHUNK_BYTES;
    const end = Math.min(encoded.bytes.byteLength, start + RECEIPT_CHUNK_BYTES);
    await storage.put(`${RECEIPT_CHUNK_PREFIX}${i}`, encoded.bytes.slice(start, end));
  }

  return {
    receipt_bytes: encoded.bytes.byteLength,
    receipt_chunks: chunks,
    receipt_truncated: encoded.truncated,
  };
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

      let existing = (await this.state.storage.get(ENTRY_KEY)) as
        | StoredEntry
        | undefined;

      // Expire stale entries (workers-types doesn't type storage TTL options; expire manually).
      if (existing && existing.expires_at_ms <= nowMs) {
        await this.state.storage.deleteAll();
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

        await this.state.storage.put(ENTRY_KEY, entry);
        return json({ ok: true, kind: 'new' } as const);
      }

      if (existing.fingerprint !== fingerprint) {
        return json({ ok: true, kind: 'mismatch' } as const);
      }

      if (existing.status === 'complete') {
        try {
          const receipt = await readStoredReceipt(
            this.state.storage,
            existing
          );
          return json({ ok: true, kind: 'replay', receipt } as const);
        } catch (err) {
          const message = err instanceof Error ? err.message : 'unknown error';
          return json({ ok: false, error: `failed to read stored receipt: ${message}` }, 500);
        }
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

      let existing = (await this.state.storage.get(ENTRY_KEY)) as
        | StoredEntry
        | undefined;

      if (existing && existing.expires_at_ms <= nowMs) {
        await this.state.storage.deleteAll();
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

      const inflightEntry: StoredEntry = {
        status: 'inflight',
        fingerprint,
        created_at: existing.created_at,
        updated_at: nowIso,
        expires_at_ms: nowMs + IDEMPOTENCY_TTL_MS,
      };

      // Rewrite the entire storage contents atomically under the DO lock.
      // Fail-closed: if storage fails, restore the inflight lock to prevent
      // duplicate processing for this nonce.
      try {
        await this.state.storage.deleteAll();

        const storedReceiptMeta = await writeStoredReceipt(
          this.state.storage,
          receipt
        );

        const entry: StoredEntry = {
          status: 'complete',
          fingerprint,
          created_at: existing.created_at,
          updated_at: nowIso,
          expires_at_ms: nowMs + IDEMPOTENCY_TTL_MS,
          ...storedReceiptMeta,
        };

        await this.state.storage.put(ENTRY_KEY, entry);

        return json({ ok: true, kind: 'committed' } as const);
      } catch (err) {
        const message = err instanceof Error ? err.message : 'unknown error';

        try {
          await this.state.storage.deleteAll();
          await this.state.storage.put(ENTRY_KEY, inflightEntry);
        } catch {
          // Best-effort restore; if this fails, callers will see a store error.
        }

        return json({ ok: false, error: `failed to store receipt: ${message}` }, 500);
      }
    });
  }

  private async handleRelease(body: Record<string, unknown>): Promise<Response> {
    const fingerprint = body.fingerprint;
    if (!isNonEmptyString(fingerprint)) {
      return json({ ok: false, error: 'fingerprint is required' }, 400);
    }

    return this.state.blockConcurrencyWhile(async () => {
      const nowMs = Date.now();

      let existing = (await this.state.storage.get(ENTRY_KEY)) as
        | StoredEntry
        | undefined;

      if (existing && existing.expires_at_ms <= nowMs) {
        await this.state.storage.deleteAll();
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

      await this.state.storage.deleteAll();
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

  // Treat non-2xx responses as store errors, not as fingerprint mismatches.
  if (!res.ok) {
    throw new Error(`Idempotency check failed with status ${res.status}`);
  }

  let data: any;
  try {
    data = await res.json();
  } catch {
    throw new Error('Idempotency check returned a non-JSON response');
  }

  if (data?.ok !== true) {
    throw new Error(`Idempotency check failed: ${String(data?.error ?? 'unknown error')}`);
  }

  const kind = data?.kind;

  if (kind === 'new') return { kind: 'new' };
  if (kind === 'replay') return { kind: 'replay', receipt: data.receipt };
  if (kind === 'inflight') return { kind: 'inflight' };
  if (kind === 'mismatch') return { kind: 'mismatch' };

  throw new Error(`Unexpected idempotency check response kind: ${String(kind)}`);
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

  if (!res.ok) {
    throw new Error(`Idempotency commit failed with status ${res.status}`);
  }

  let data: any;
  try {
    data = await res.json();
  } catch {
    throw new Error('Idempotency commit returned a non-JSON response');
  }

  if (data?.ok !== true) {
    throw new Error(`Idempotency commit failed: ${String(data?.error ?? 'unknown error')}`);
  }

  const kind = data?.kind;

  if (kind === 'committed' || kind === 'already_committed') return;
  if (kind === 'mismatch') throw new Error('Idempotency commit fingerprint mismatch');

  throw new Error(`Idempotency commit failed: ${String(kind ?? 'unknown')}`);
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

  if (!res.ok) {
    throw new Error(`Idempotency release failed with status ${res.status}`);
  }

  let data: any;
  try {
    data = await res.json();
  } catch {
    throw new Error('Idempotency release returned a non-JSON response');
  }

  if (data?.ok !== true) {
    throw new Error(`Idempotency release failed: ${String(data?.error ?? 'unknown error')}`);
  }

  const kind = data?.kind;

  if (kind === 'released' || kind === 'missing' || kind === 'already_committed') return;
  if (kind === 'mismatch') throw new Error('Idempotency release fingerprint mismatch');

  throw new Error(`Idempotency release failed: ${String(kind ?? 'unknown')}`);
}
