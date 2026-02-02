/**
 * Event Chain Verification
 * CVF-US-008: Verify event chains for tamper-evident logs
 *
 * Validates:
 * - Hash chain integrity (each event links to previous via prev_hash)
 * - run_id consistency (all events must have same run_id)
 * - Returns chain_root_hash (the first event's hash)
 */

import type {
  SignedEnvelope,
  EventChainPayload,
  EventChainVerificationResult,
  VerificationError,
  EventChainEntry,
} from './types';
import {
  isAllowedVersion,
  isAllowedType,
  isAllowedAlgorithm,
  isAllowedHashAlgorithm,
  isValidDidFormat,
  isValidBase64Url,
  isValidIsoDate,
} from './schema-registry';
import {
  computeHash,
  base64UrlDecode,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto';

/**
 * Error codes specific to event chain validation
 */
export type EventChainErrorCode =
  | 'EMPTY_CHAIN'
  | 'INCONSISTENT_RUN_ID'
  | 'HASH_CHAIN_BREAK'
  | 'INVALID_ROOT'
  | 'MISSING_EVENT_FIELD';

/**
 * Validate envelope structure for event chain
 */
function validateEnvelopeStructure(
  envelope: unknown
): envelope is SignedEnvelope<EventChainPayload> {
  if (typeof envelope !== 'object' || envelope === null) {
    return false;
  }

  const e = envelope as Record<string, unknown>;

  return (
    'envelope_version' in e &&
    'envelope_type' in e &&
    'payload' in e &&
    'payload_hash_b64u' in e &&
    'hash_algorithm' in e &&
    'signature_b64u' in e &&
    'algorithm' in e &&
    'signer_did' in e &&
    'issued_at' in e
  );
}

/**
 * Validate event chain payload structure
 */
function validateChainPayload(payload: unknown): payload is EventChainPayload {
  if (typeof payload !== 'object' || payload === null) {
    return false;
  }

  const p = payload as Record<string, unknown>;

  // Required fields
  if (p.chain_version !== '1') return false;
  if (typeof p.chain_id !== 'string' || p.chain_id.length === 0) return false;
  if (typeof p.run_id !== 'string' || p.run_id.length === 0) return false;
  if (!Array.isArray(p.events)) return false;

  return true;
}

/**
 * Validate a single event entry structure
 */
function validateEventEntry(
  event: unknown,
  index: number
): { valid: boolean; error?: string } {
  if (typeof event !== 'object' || event === null) {
    return { valid: false, error: `Event ${index}: invalid structure` };
  }

  const e = event as Record<string, unknown>;

  if (typeof e.event_id !== 'string' || e.event_id.length === 0) {
    return { valid: false, error: `Event ${index}: missing event_id` };
  }
  if (typeof e.run_id !== 'string' || e.run_id.length === 0) {
    return { valid: false, error: `Event ${index}: missing run_id` };
  }
  if (typeof e.event_type !== 'string' || e.event_type.length === 0) {
    return { valid: false, error: `Event ${index}: missing event_type` };
  }
  if (!isValidIsoDate(e.timestamp)) {
    return { valid: false, error: `Event ${index}: invalid timestamp format` };
  }
  if (!isValidBase64Url(e.payload_hash_b64u)) {
    return { valid: false, error: `Event ${index}: invalid payload_hash_b64u` };
  }
  if (!isValidBase64Url(e.event_hash_b64u)) {
    return { valid: false, error: `Event ${index}: invalid event_hash_b64u` };
  }

  return { valid: true };
}

/**
 * Validate event chain integrity
 *
 * Checks:
 * 1. Chain is not empty
 * 2. All events have consistent run_id
 * 3. Hash chain is intact (prev_hash links correctly)
 * 4. First event has null prev_hash (or empty string for compatibility)
 */
function validateEventChain(
  events: EventChainEntry[],
  expectedRunId: string
): {
  valid: boolean;
  chain_root_hash?: string;
  error?: string;
  error_code?: EventChainErrorCode;
} {
  if (events.length === 0) {
    return {
      valid: false,
      error: 'Event chain is empty',
      error_code: 'EMPTY_CHAIN',
    };
  }

  let prevHash: string | null = null;
  let chainRootHash: string | null = null;

  for (let i = 0; i < events.length; i++) {
    const event = events[i];

    // Validate event structure
    const entryValidation = validateEventEntry(event, i);
    if (!entryValidation.valid) {
      return {
        valid: false,
        error: entryValidation.error,
        error_code: 'MISSING_EVENT_FIELD',
      };
    }

    // Enforce run_id consistency
    if (event.run_id !== expectedRunId) {
      return {
        valid: false,
        error: `Event ${i}: inconsistent run_id (expected "${expectedRunId}", got "${event.run_id}")`,
        error_code: 'INCONSISTENT_RUN_ID',
      };
    }

    // Validate hash chain linkage
    if (i === 0) {
      // First event should have null or empty prev_hash
      if (
        event.prev_hash_b64u !== null &&
        event.prev_hash_b64u !== '' &&
        event.prev_hash_b64u !== undefined
      ) {
        return {
          valid: false,
          error: 'First event must have null or empty prev_hash_b64u',
          error_code: 'INVALID_ROOT',
        };
      }
      // Capture the chain root hash (first event's hash)
      chainRootHash = event.event_hash_b64u;
    } else {
      // Subsequent events must link to previous event's hash
      if (event.prev_hash_b64u !== prevHash) {
        return {
          valid: false,
          error: `Event ${i}: hash chain break detected (expected prev_hash "${prevHash}", got "${event.prev_hash_b64u}")`,
          error_code: 'HASH_CHAIN_BREAK',
        };
      }
    }

    // Update prev hash for next iteration
    prevHash = event.event_hash_b64u;
  }

  return {
    valid: true,
    chain_root_hash: chainRootHash ?? undefined,
  };
}

/**
 * Verify an event chain envelope
 *
 * Acceptance Criteria:
 * - Validate hash chain and root
 * - Enforce run_id consistency
 * - Return chain_root_hash and error codes
 */
export async function verifyEventChain(
  envelope: unknown
): Promise<{ result: EventChainVerificationResult; error?: VerificationError }> {
  const now = new Date().toISOString();

  // 1. Validate envelope structure
  if (!validateEnvelopeStructure(envelope)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Malformed envelope: missing required fields',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'Envelope is missing required fields or has invalid structure',
      },
    };
  }

  // 2. Fail-closed: reject unknown envelope version
  if (!isAllowedVersion(envelope.envelope_version)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown envelope version: ${envelope.envelope_version}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_VERSION',
        message: `Envelope version "${envelope.envelope_version}" is not in the allowlist`,
        field: 'envelope_version',
      },
    };
  }

  // 3. Fail-closed: reject unknown envelope type
  if (!isAllowedType(envelope.envelope_type)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown envelope type: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: `Envelope type "${envelope.envelope_type}" is not in the allowlist`,
        field: 'envelope_type',
      },
    };
  }

  // 4. Verify this is an event_chain envelope
  if (envelope.envelope_type !== 'event_chain') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected event_chain envelope, got: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: 'This endpoint only accepts event_chain envelopes',
        field: 'envelope_type',
      },
    };
  }

  // 5. Fail-closed: reject unknown signature algorithm
  if (!isAllowedAlgorithm(envelope.algorithm)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown signature algorithm: ${envelope.algorithm}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ALGORITHM',
        message: `Signature algorithm "${envelope.algorithm}" is not in the allowlist`,
        field: 'algorithm',
      },
    };
  }

  // 6. Fail-closed: reject unknown hash algorithm
  if (!isAllowedHashAlgorithm(envelope.hash_algorithm)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown hash algorithm: ${envelope.hash_algorithm}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_HASH_ALGORITHM',
        message: `Hash algorithm "${envelope.hash_algorithm}" is not in the allowlist`,
        field: 'hash_algorithm',
      },
    };
  }

  // 7. Validate DID format
  if (!isValidDidFormat(envelope.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Invalid DID format: ${envelope.signer_did}`,
        verified_at: now,
      },
      error: {
        code: 'INVALID_DID_FORMAT',
        message:
          'Signer DID does not match expected format (did:key:... or did:web:...)',
        field: 'signer_did',
      },
    };
  }

  // 8. Validate issued_at format
  if (!isValidIsoDate(envelope.issued_at)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid issued_at date format',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'issued_at must be a valid ISO 8601 date string',
        field: 'issued_at',
      },
    };
  }

  // 9. Validate base64url fields
  if (!isValidBase64Url(envelope.payload_hash_b64u)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid payload_hash_b64u format',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'payload_hash_b64u must be a valid base64url string',
        field: 'payload_hash_b64u',
      },
    };
  }

  if (!isValidBase64Url(envelope.signature_b64u)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid signature_b64u format',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'signature_b64u must be a valid base64url string',
        field: 'signature_b64u',
      },
    };
  }

  // 10. Validate event chain payload structure
  if (!validateChainPayload(envelope.payload)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid event chain payload structure',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message:
          'Event chain payload is missing required fields (chain_version, chain_id, run_id, events)',
        field: 'payload',
      },
    };
  }

  // 11. Recompute hash and verify it matches
  try {
    const computedHash = await computeHash(
      envelope.payload,
      envelope.hash_algorithm
    );

    if (computedHash !== envelope.payload_hash_b64u) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Payload hash mismatch: envelope may have been tampered with',
          verified_at: now,
        },
        error: {
          code: 'HASH_MISMATCH',
          message: 'Computed payload hash does not match envelope hash',
        },
      };
    }
  } catch (err) {
    return {
      result: {
        status: 'INVALID',
        reason: `Hash computation failed: ${err instanceof Error ? err.message : 'unknown error'}`,
        verified_at: now,
      },
      error: {
        code: 'HASH_MISMATCH',
        message: 'Failed to compute payload hash',
      },
    };
  }

  // 12. Extract public key from DID
  const publicKeyBytes = extractPublicKeyFromDidKey(envelope.signer_did);
  if (!publicKeyBytes) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Could not extract public key from signer DID',
        verified_at: now,
      },
      error: {
        code: 'INVALID_DID_FORMAT',
        message:
          'Unable to extract Ed25519 public key from did:key. Ensure the DID uses the Ed25519 multicodec prefix.',
        field: 'signer_did',
      },
    };
  }

  // 13. Verify envelope signature
  try {
    const signatureBytes = base64UrlDecode(envelope.signature_b64u);
    const messageBytes = new TextEncoder().encode(envelope.payload_hash_b64u);

    const isValid = await verifySignature(
      envelope.algorithm,
      publicKeyBytes,
      signatureBytes,
      messageBytes
    );

    if (!isValid) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Signature verification failed',
          verified_at: now,
        },
        error: {
          code: 'SIGNATURE_INVALID',
          message: 'The Ed25519 signature does not match the payload hash',
        },
      };
    }
  } catch (err) {
    return {
      result: {
        status: 'INVALID',
        reason: `Signature verification error: ${err instanceof Error ? err.message : 'unknown error'}`,
        verified_at: now,
      },
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'Failed to verify signature',
      },
    };
  }

  // 14. Validate event chain integrity
  const payload = envelope.payload;
  const chainValidation = validateEventChain(payload.events, payload.run_id);

  if (!chainValidation.valid) {
    return {
      result: {
        status: 'INVALID',
        reason: chainValidation.error ?? 'Event chain validation failed',
        verified_at: now,
        chain_id: payload.chain_id,
        run_id: payload.run_id,
        signer_did: envelope.signer_did,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: chainValidation.error ?? 'Event chain is invalid',
        field: 'payload.events',
      },
    };
  }

  // 15. Return success with chain root hash
  return {
    result: {
      status: 'VALID',
      reason: 'Event chain verified successfully',
      verified_at: now,
      chain_id: payload.chain_id,
      run_id: payload.run_id,
      chain_root_hash: chainValidation.chain_root_hash,
      events_count: payload.events.length,
      signer_did: envelope.signer_did,
    },
  };
}
