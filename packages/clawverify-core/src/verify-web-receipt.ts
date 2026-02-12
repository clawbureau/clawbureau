/**
 * Witnessed Web Receipt Verification
 * POH-US-018
 */

import type {
  SignedEnvelope,
  WebReceiptPayload,
  VerificationResult,
  VerificationError,
} from './types.js';
import {
  isAllowedVersion,
  isAllowedType,
  isAllowedAlgorithm,
  isAllowedHashAlgorithm,
  isValidDidFormat,
  isValidBase64Url,
  isValidIsoDate,
} from './schema-registry.js';
import {
  computeHash,
  base64UrlDecode,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto.js';
import { validateWebReceiptEnvelopeV1 } from './schema-validation.js';

export interface WebReceiptVerifierOptions {
  /**
   * Allowlisted witness signer DIDs (did:key:...).
   * Fail-closed: if empty or missing, web receipts are treated as INVALID.
   */
  allowlistedSignerDids?: readonly string[];
}

function validateEnvelopeStructure(
  envelope: unknown,
): envelope is SignedEnvelope<WebReceiptPayload> {
  if (typeof envelope !== 'object' || envelope === null) return false;
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

function validatePayload(payload: unknown): payload is WebReceiptPayload {
  if (typeof payload !== 'object' || payload === null) return false;
  const p = payload as Record<string, unknown>;

  if (p.receipt_version !== '1') return false;
  if (typeof p.receipt_id !== 'string' || p.receipt_id.length === 0) return false;
  if (typeof p.witness_id !== 'string' || p.witness_id.length === 0) return false;
  if (p.source !== 'chatgpt_web' && p.source !== 'claude_web' && p.source !== 'gemini_web' && p.source !== 'other') {
    return false;
  }

  if (typeof p.request_hash_b64u !== 'string' || !isValidBase64Url(p.request_hash_b64u)) return false;
  if (typeof p.response_hash_b64u !== 'string' || !isValidBase64Url(p.response_hash_b64u)) return false;

  if (p.session_hash_b64u !== undefined) {
    if (typeof p.session_hash_b64u !== 'string' || !isValidBase64Url(p.session_hash_b64u)) {
      return false;
    }
  }

  if (!isValidIsoDate(p.timestamp)) return false;
  return true;
}

export async function verifyWebReceipt(
  envelope: unknown,
  options: WebReceiptVerifierOptions = {},
): Promise<{
  result: VerificationResult;
  witness_id?: string;
  source?: WebReceiptPayload['source'];
  proof_tier?: 'witnessed_web';
  equivalent_to_gateway?: boolean;
  error?: VerificationError;
}> {
  const now = new Date().toISOString();

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

  if (envelope.envelope_type !== 'web_receipt') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected web_receipt envelope, got: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: 'This endpoint only accepts web_receipt envelopes',
        field: 'envelope_type',
      },
    };
  }

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

  const schemaResult = validateWebReceiptEnvelopeV1(envelope);
  if (!schemaResult.valid) {
    return {
      result: {
        status: 'INVALID',
        reason: schemaResult.message,
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: schemaResult.message,
        field: schemaResult.field,
      },
    };
  }

  if (!isValidDidFormat(envelope.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Invalid DID format: ${envelope.signer_did}`,
        verified_at: now,
      },
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'Signer DID does not match expected format (did:key:... or did:web:...)',
        field: 'signer_did',
      },
    };
  }

  if (!options.allowlistedSignerDids || options.allowlistedSignerDids.length === 0) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Web receipt signer allowlist not configured',
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      error: {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message: 'Web receipt signer allowlist is not configured. Set WEB_RECEIPT_SIGNER_DIDS to enable web receipt verification.',
        field: 'env.WEB_RECEIPT_SIGNER_DIDS',
      },
    };
  }

  if (!options.allowlistedSignerDids.includes(envelope.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Web receipt signer DID is not allowlisted',
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      error: {
        code: 'CLAIM_NOT_FOUND',
        message: `Signer DID '${envelope.signer_did}' is not in the allowlisted web receipt signer list`,
        field: 'signer_did',
      },
    };
  }

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

  if (!validatePayload(envelope.payload)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid web receipt payload structure',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'Web receipt payload is malformed or missing required fields',
        field: 'payload',
      },
    };
  }

  try {
    const computedHash = await computeHash(envelope.payload, envelope.hash_algorithm);
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
  } catch {
    return {
      result: {
        status: 'INVALID',
        reason: 'Hash computation failed',
        verified_at: now,
      },
      error: {
        code: 'HASH_MISMATCH',
        message: 'Failed to compute payload hash',
      },
    };
  }

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
        message: 'Unable to extract Ed25519 public key from did:key DID',
        field: 'signer_did',
      },
    };
  }

  try {
    const sigBytes = base64UrlDecode(envelope.signature_b64u);
    const msgBytes = new TextEncoder().encode(envelope.payload_hash_b64u);

    const ok = await verifySignature('Ed25519', publicKeyBytes, sigBytes, msgBytes);
    if (!ok) {
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
  } catch {
    return {
      result: {
        status: 'INVALID',
        reason: 'Signature verification error',
        verified_at: now,
      },
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'Failed to verify signature',
      },
    };
  }

  return {
    result: {
      status: 'VALID',
      reason: 'Web receipt verified successfully',
      envelope_type: envelope.envelope_type,
      signer_did: envelope.signer_did,
      verified_at: now,
    },
    witness_id: envelope.payload.witness_id,
    source: envelope.payload.source,
    proof_tier: 'witnessed_web',
    equivalent_to_gateway: false,
  };
}
