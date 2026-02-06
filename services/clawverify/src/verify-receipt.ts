/**
 * Gateway Receipt Verification
 * CVF-US-003: Verify gateway receipts for proof-of-harness
 */

import type {
  SignedEnvelope,
  GatewayReceiptPayload,
  VerificationResult,
  VerificationError,
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

export interface ReceiptVerifierOptions {
  /**
   * Allowlisted gateway signer DIDs (did:key:...).
   * Fail-closed: if empty or missing, receipts are treated as INVALID.
   */
  allowlistedSignerDids?: readonly string[];
}


/**
 * Validate envelope structure before cryptographic verification
 * Fail-closed: reject any unknown or missing fields
 */
function validateEnvelopeStructure(
  envelope: unknown
): envelope is SignedEnvelope<GatewayReceiptPayload> {
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
 * Validate gateway receipt payload structure
 */
function validateReceiptPayload(
  payload: unknown
): payload is GatewayReceiptPayload {
  if (typeof payload !== 'object' || payload === null) {
    return false;
  }

  const p = payload as Record<string, unknown>;

  // Required fields
  if (p.receipt_version !== '1') return false;
  if (typeof p.receipt_id !== 'string' || p.receipt_id.length === 0)
    return false;
  if (typeof p.gateway_id !== 'string' || p.gateway_id.length === 0)
    return false;
  if (typeof p.provider !== 'string' || p.provider.length === 0) return false;
  if (typeof p.model !== 'string' || p.model.length === 0) return false;
  if (
    typeof p.request_hash_b64u !== 'string' ||
    !isValidBase64Url(p.request_hash_b64u)
  )
    return false;
  if (
    typeof p.response_hash_b64u !== 'string' ||
    !isValidBase64Url(p.response_hash_b64u)
  )
    return false;
  if (typeof p.tokens_input !== 'number' || p.tokens_input < 0) return false;
  if (typeof p.tokens_output !== 'number' || p.tokens_output < 0) return false;
  if (typeof p.latency_ms !== 'number' || p.latency_ms < 0) return false;
  if (!isValidIsoDate(p.timestamp)) return false;

  return true;
}

/**
 * Verify a gateway receipt signature envelope
 *
 * Acceptance Criteria:
 * - Validate receipt signature
 * - Check receipt schema
 * - Return verified provider/model
 */
export async function verifyReceipt(
  envelope: unknown,
  options: ReceiptVerifierOptions = {}
): Promise<{
  result: VerificationResult;
  provider?: string;
  model?: string;
  gateway_id?: string;
  error?: VerificationError;
}> {
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

  // 4. Verify this is a gateway_receipt envelope
  if (envelope.envelope_type !== 'gateway_receipt') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected gateway_receipt envelope, got: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: 'This endpoint only accepts gateway_receipt envelopes',
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

  // 7.5 Fail-closed: require allowlisted gateway signer DID(s)
  if (!options.allowlistedSignerDids || options.allowlistedSignerDids.length === 0) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Gateway receipt signer allowlist not configured',
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      error: {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message:
          'Gateway receipt signer allowlist is not configured. Set GATEWAY_RECEIPT_SIGNER_DIDS to enable receipt verification.',
        field: 'env.GATEWAY_RECEIPT_SIGNER_DIDS',
      },
    };
  }

  if (!options.allowlistedSignerDids.includes(envelope.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Receipt signer DID is not allowlisted',
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      error: {
        code: 'CLAIM_NOT_FOUND',
        message: `Signer DID '${envelope.signer_did}' is not in the allowlisted gateway signer list`,
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

  // 10. Validate receipt payload structure
  if (!validateReceiptPayload(envelope.payload)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid receipt payload structure',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message:
          'Receipt payload is missing required fields or has invalid types',
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

  // 13. Verify signature
  try {
    const signatureBytes = base64UrlDecode(envelope.signature_b64u);

    // The signed message is the payload hash
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

  // 14. All checks passed - receipt is valid
  return {
    result: {
      status: 'VALID',
      reason: 'Gateway receipt verified successfully',
      envelope_type: envelope.envelope_type,
      signer_did: envelope.signer_did,
      verified_at: now,
    },
    provider: envelope.payload.provider,
    model: envelope.payload.model,
    gateway_id: envelope.payload.gateway_id,
  };
}
