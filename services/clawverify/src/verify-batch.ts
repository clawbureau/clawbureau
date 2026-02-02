/**
 * Batch Verification
 * CVF-US-004: Batch verification for scale verification
 */

import type {
  BatchItem,
  BatchItemResult,
  VerifyBatchResponse,
  EnvelopeType,
} from './types';
import { BATCH_SIZE_LIMIT } from './types';
import { verifyArtifact } from './verify-artifact';
import { verifyMessage } from './verify-message';
import { verifyReceipt } from './verify-receipt';

/**
 * Validate batch request structure
 */
function validateBatchRequest(
  body: unknown
): { items: BatchItem[] } | { error: string } {
  if (typeof body !== 'object' || body === null) {
    return { error: 'Request body must be an object' };
  }

  const b = body as Record<string, unknown>;

  if (!('items' in b) || !Array.isArray(b.items)) {
    return { error: 'Request must contain an "items" array' };
  }

  if (b.items.length === 0) {
    return { error: 'Batch must contain at least one item' };
  }

  if (b.items.length > BATCH_SIZE_LIMIT) {
    return {
      error: `Batch size exceeds limit of ${BATCH_SIZE_LIMIT} items`,
    };
  }

  // Validate each item has an envelope
  for (let i = 0; i < b.items.length; i++) {
    const item = b.items[i];
    if (typeof item !== 'object' || item === null || !('envelope' in item)) {
      return { error: `Item at index ${i} must contain an "envelope" field` };
    }
  }

  return { items: b.items as BatchItem[] };
}

/**
 * Detect envelope type from the envelope
 */
function detectEnvelopeType(envelope: unknown): EnvelopeType | null {
  if (typeof envelope !== 'object' || envelope === null) {
    return null;
  }
  const e = envelope as Record<string, unknown>;
  if (typeof e.envelope_type !== 'string') {
    return null;
  }
  return e.envelope_type as EnvelopeType;
}

/**
 * Verify a single item based on its envelope type
 */
async function verifyItem(
  item: BatchItem,
  index: number
): Promise<BatchItemResult> {
  const itemId = item.id ?? index.toString();
  const envelopeType = detectEnvelopeType(item.envelope);

  // Route to appropriate verifier based on envelope type
  switch (envelopeType) {
    case 'artifact_signature': {
      const result = await verifyArtifact(item.envelope);
      return {
        id: itemId,
        envelope_type: envelopeType,
        result: result.result,
        error: result.error,
        signer_did: result.result.signer_did,
      };
    }

    case 'message_signature': {
      const result = await verifyMessage(item.envelope);
      return {
        id: itemId,
        envelope_type: envelopeType,
        result: result.result,
        error: result.error,
        signer_did: result.signer_did,
      };
    }

    case 'gateway_receipt': {
      const result = await verifyReceipt(item.envelope);
      return {
        id: itemId,
        envelope_type: envelopeType,
        result: result.result,
        error: result.error,
        signer_did: result.result.signer_did,
        provider: result.provider,
        model: result.model,
        gateway_id: result.gateway_id,
      };
    }

    default: {
      // Unknown or missing envelope type - fail closed
      const now = new Date().toISOString();
      return {
        id: itemId,
        envelope_type: envelopeType ?? undefined,
        result: {
          status: 'INVALID',
          reason: envelopeType
            ? `Unsupported envelope type for batch verification: ${envelopeType}`
            : 'Missing or invalid envelope_type',
          verified_at: now,
        },
        error: {
          code: 'UNKNOWN_ENVELOPE_TYPE',
          message: envelopeType
            ? `Envelope type "${envelopeType}" is not supported for batch verification`
            : 'Envelope must have a valid envelope_type field',
          field: 'envelope_type',
        },
      };
    }
  }
}

/**
 * Verify a batch of envelopes
 *
 * Acceptance Criteria:
 * - POST /v1/verify/batch
 * - Return per-item results
 * - Limit batch size to prevent abuse
 */
export async function verifyBatch(
  body: unknown
): Promise<VerifyBatchResponse | { error: string }> {
  // Validate request structure
  const validation = validateBatchRequest(body);
  if ('error' in validation) {
    return { error: validation.error };
  }

  const { items } = validation;
  const now = new Date().toISOString();

  // Verify all items concurrently
  const results = await Promise.all(
    items.map((item, index) => verifyItem(item, index))
  );

  // Calculate summary counts
  const validCount = results.filter((r) => r.result.status === 'VALID').length;
  const invalidCount = results.length - validCount;

  return {
    total: results.length,
    valid_count: validCount,
    invalid_count: invalidCount,
    results,
    verified_at: now,
  };
}
