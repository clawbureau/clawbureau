/**
 * Idempotency enforcement for receipt issuance
 * Prevents duplicate receipt generation for the same nonce
 */

import type { ReceiptBinding } from './types';

/**
 * Headers used for binding receipts to runs/events
 */
export const BINDING_HEADERS = {
  RUN_ID: 'X-Run-Id',
  EVENT_HASH: 'X-Event-Hash',
  NONCE: 'X-Idempotency-Key',
} as const;

/**
 * Result of idempotency check
 */
export interface IdempotencyCheckResult {
  /** Whether this is a duplicate request */
  isDuplicate: boolean;
  /** Previously issued receipt for duplicate requests */
  existingReceipt?: unknown;
}

/**
 * In-memory nonce cache with TTL (for demo/MVP)
 * In production, this should use Durable Objects or KV for distributed state
 */
const nonceCache = new Map<string, { timestamp: number; receipt: unknown }>();
const NONCE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Extract binding fields from request headers
 * @param request - Incoming request with optional binding headers
 * @returns Binding fields if any are present, undefined otherwise
 */
export function extractBindingFromHeaders(request: Request): ReceiptBinding | undefined {
  const runId = request.headers.get(BINDING_HEADERS.RUN_ID);
  const eventHash = request.headers.get(BINDING_HEADERS.EVENT_HASH);
  const nonce = request.headers.get(BINDING_HEADERS.NONCE);

  // Return undefined if no binding fields are present
  if (!runId && !eventHash && !nonce) {
    return undefined;
  }

  const binding: ReceiptBinding = {};
  if (runId) {
    binding.runId = runId;
  }
  if (eventHash) {
    binding.eventHash = eventHash;
  }
  if (nonce) {
    binding.nonce = nonce;
  }

  return binding;
}

/**
 * Check if a nonce has already been used (idempotency check)
 * @param nonce - The idempotency nonce to check
 * @returns Result indicating if this is a duplicate request
 */
export function checkIdempotency(nonce: string | undefined): IdempotencyCheckResult {
  if (!nonce) {
    // No nonce provided, allow request (no idempotency enforcement)
    return { isDuplicate: false };
  }

  // Clean expired entries
  const now = Date.now();
  for (const [key, value] of nonceCache.entries()) {
    if (now - value.timestamp > NONCE_TTL_MS) {
      nonceCache.delete(key);
    }
  }

  // Check if nonce exists
  const existing = nonceCache.get(nonce);
  if (existing) {
    return {
      isDuplicate: true,
      existingReceipt: existing.receipt,
    };
  }

  return { isDuplicate: false };
}

/**
 * Record a nonce as used (after successful receipt generation)
 * @param nonce - The idempotency nonce to record
 * @param receipt - The receipt issued for this nonce
 */
export function recordNonce(nonce: string | undefined, receipt: unknown): void {
  if (!nonce) {
    return;
  }

  nonceCache.set(nonce, {
    timestamp: Date.now(),
    receipt,
  });
}

/**
 * Get the number of cached nonces (for testing/monitoring)
 */
export function getNonceCacheSize(): number {
  return nonceCache.size;
}
