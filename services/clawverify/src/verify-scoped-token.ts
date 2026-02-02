/**
 * Scoped Token Introspection
 * CVF-US-013: Validate token signature + expiry and return claims.
 */

import type {
  ScopedTokenPayload,
  SignedEnvelope,
  VerificationError,
  VerificationResult,
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
 * Validate envelope structure before cryptographic verification
 */
function validateEnvelopeStructure(
  envelope: unknown
): envelope is SignedEnvelope<ScopedTokenPayload> {
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

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Validate scoped token payload structure
 */
function validateScopedTokenPayload(payload: unknown): payload is ScopedTokenPayload {
  if (typeof payload !== 'object' || payload === null) {
    return false;
  }

  const p = payload as Record<string, unknown>;

  if (p.token_version !== '1') return false;
  if (!isNonEmptyString(p.token_id)) return false;

  if (!Array.isArray(p.scope) || p.scope.length === 0) return false;
  if (!p.scope.every((s) => typeof s === 'string' && s.trim().length > 0)) return false;

  if (!isNonEmptyString(p.audience)) return false;

  if ('owner_ref' in p && p.owner_ref !== undefined && typeof p.owner_ref !== 'string') {
    return false;
  }

  if (!isNonEmptyString(p.expires_at)) return false;
  if (!isValidIsoDate(p.expires_at)) return false;

  return true;
}

export async function verifyScopedToken(
  envelope: unknown
): Promise<{
  result: VerificationResult;
  token_id?: string;
  token_hash_b64u?: string;
  scope?: string[];
  audience?: string;
  owner_ref?: string;
  expires_at?: string;
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
        envelope_type: 'scoped_token',
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
        envelope_type: 'scoped_token',
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_VERSION',
        message: `Envelope version "${envelope.envelope_version}" is not in the allowlist`,
        field: 'envelope_version',
      },
    };
  }

  // 3. Fail-closed: reject unknown envelope type
  if (!isAllowedType(envelope.envelope_type) || envelope.envelope_type !== 'scoped_token') {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown or unsupported envelope type: ${envelope.envelope_type}`,
        verified_at: now,
        envelope_type: 'scoped_token',
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: `Envelope type "${envelope.envelope_type}" is not supported for token introspection`,
        field: 'envelope_type',
      },
    };
  }

  // 4. Fail-closed: reject unknown signature algorithm
  if (!isAllowedAlgorithm(envelope.algorithm)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown algorithm: ${envelope.algorithm}`,
        verified_at: now,
        envelope_type: 'scoped_token',
      },
      error: {
        code: 'UNKNOWN_ALGORITHM',
        message: `Algorithm "${envelope.algorithm}" is not in the allowlist`,
        field: 'algorithm',
      },
    };
  }

  // 5. Fail-closed: reject unknown hash algorithm
  if (!isAllowedHashAlgorithm(envelope.hash_algorithm)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown hash algorithm: ${envelope.hash_algorithm}`,
        verified_at: now,
        envelope_type: 'scoped_token',
      },
      error: {
        code: 'UNKNOWN_HASH_ALGORITHM',
        message: `Hash algorithm "${envelope.hash_algorithm}" is not in the allowlist`,
        field: 'hash_algorithm',
      },
    };
  }

  // 6. Validate base64url fields
  if (!isValidBase64Url(envelope.payload_hash_b64u)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid payload hash format',
        verified_at: now,
        envelope_type: 'scoped_token',
      },
      error: {
        code: 'HASH_MISMATCH',
        message: 'payload_hash_b64u must be a base64url string',
        field: 'payload_hash_b64u',
      },
    };
  }

  if (!isValidBase64Url(envelope.signature_b64u)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid signature format',
        verified_at: now,
        envelope_type: 'scoped_token',
      },
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'signature_b64u must be a base64url string',
        field: 'signature_b64u',
      },
    };
  }

  // 7. Validate signer DID format
  if (!isValidDidFormat(envelope.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid signer DID format',
        verified_at: now,
        envelope_type: 'scoped_token',
      },
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'signer_did must be a valid DID (did:key:... or did:web:...)',
        field: 'signer_did',
      },
    };
  }

  // 8. Validate issued_at
  if (!isValidIsoDate(envelope.issued_at)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid issued_at timestamp',
        verified_at: now,
        envelope_type: 'scoped_token',
      },
      error: {
        code: 'MISSING_REQUIRED_FIELD',
        message: 'issued_at must be a valid ISO 8601 timestamp',
        field: 'issued_at',
      },
    };
  }

  // 9. Validate payload structure
  if (!validateScopedTokenPayload(envelope.payload)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid scoped token payload',
        verified_at: now,
        envelope_type: 'scoped_token',
        signer_did: envelope.signer_did,
      },
      error: {
        code: 'MISSING_REQUIRED_FIELD',
        message: 'Scoped token payload is missing required fields or has invalid types',
        field: 'payload',
      },
    };
  }

  // 10. Expiry check
  const expiresAtMs = Date.parse(envelope.payload.expires_at);
  if (Number.isNaN(expiresAtMs)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid expires_at timestamp',
        verified_at: now,
        envelope_type: 'scoped_token',
        signer_did: envelope.signer_did,
      },
      token_id: envelope.payload.token_id,
      token_hash_b64u: envelope.payload_hash_b64u,
      scope: envelope.payload.scope,
      audience: envelope.payload.audience,
      owner_ref: envelope.payload.owner_ref,
      expires_at: envelope.payload.expires_at,
      error: {
        code: 'MISSING_REQUIRED_FIELD',
        message: 'expires_at must be a valid ISO 8601 timestamp',
        field: 'payload.expires_at',
      },
    };
  }

  if (expiresAtMs < Date.now()) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Token has expired',
        verified_at: now,
        envelope_type: 'scoped_token',
        signer_did: envelope.signer_did,
      },
      token_id: envelope.payload.token_id,
      token_hash_b64u: envelope.payload_hash_b64u,
      scope: envelope.payload.scope,
      audience: envelope.payload.audience,
      owner_ref: envelope.payload.owner_ref,
      expires_at: envelope.payload.expires_at,
      error: {
        code: 'EXPIRED',
        message: `Token expired at ${envelope.payload.expires_at}`,
        field: 'payload.expires_at',
      },
    };
  }

  // 11. Recompute hash and verify it matches
  try {
    const computedHash = await computeHash(envelope.payload, envelope.hash_algorithm);
    if (computedHash !== envelope.payload_hash_b64u) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Payload hash mismatch: token may have been tampered with',
          verified_at: now,
          envelope_type: 'scoped_token',
          signer_did: envelope.signer_did,
        },
        token_id: envelope.payload.token_id,
        token_hash_b64u: envelope.payload_hash_b64u,
        scope: envelope.payload.scope,
        audience: envelope.payload.audience,
        owner_ref: envelope.payload.owner_ref,
        expires_at: envelope.payload.expires_at,
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
        envelope_type: 'scoped_token',
        signer_did: envelope.signer_did,
      },
      token_id: envelope.payload.token_id,
      token_hash_b64u: envelope.payload_hash_b64u,
      scope: envelope.payload.scope,
      audience: envelope.payload.audience,
      owner_ref: envelope.payload.owner_ref,
      expires_at: envelope.payload.expires_at,
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
        envelope_type: 'scoped_token',
        signer_did: envelope.signer_did,
      },
      token_id: envelope.payload.token_id,
      token_hash_b64u: envelope.payload_hash_b64u,
      scope: envelope.payload.scope,
      audience: envelope.payload.audience,
      owner_ref: envelope.payload.owner_ref,
      expires_at: envelope.payload.expires_at,
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'Unable to extract Ed25519 public key from did:key',
        field: 'signer_did',
      },
    };
  }

  // 13. Verify signature
  try {
    const signatureBytes = base64UrlDecode(envelope.signature_b64u);
    const messageBytes = new TextEncoder().encode(envelope.payload_hash_b64u);

    const ok = await verifySignature(
      envelope.algorithm,
      publicKeyBytes,
      signatureBytes,
      messageBytes
    );

    if (!ok) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Signature verification failed',
          verified_at: now,
          envelope_type: 'scoped_token',
          signer_did: envelope.signer_did,
        },
        token_id: envelope.payload.token_id,
        token_hash_b64u: envelope.payload_hash_b64u,
        scope: envelope.payload.scope,
        audience: envelope.payload.audience,
        owner_ref: envelope.payload.owner_ref,
        expires_at: envelope.payload.expires_at,
        error: {
          code: 'SIGNATURE_INVALID',
          message: 'Signature does not match payload hash',
        },
      };
    }
  } catch (err) {
    return {
      result: {
        status: 'INVALID',
        reason: `Signature verification error: ${err instanceof Error ? err.message : 'unknown error'}`,
        verified_at: now,
        envelope_type: 'scoped_token',
        signer_did: envelope.signer_did,
      },
      token_id: envelope.payload.token_id,
      token_hash_b64u: envelope.payload_hash_b64u,
      scope: envelope.payload.scope,
      audience: envelope.payload.audience,
      owner_ref: envelope.payload.owner_ref,
      expires_at: envelope.payload.expires_at,
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'Signature verification failed',
      },
    };
  }

  return {
    result: {
      status: 'VALID',
      reason: 'Scoped token is valid',
      verified_at: now,
      envelope_type: 'scoped_token',
      signer_did: envelope.signer_did,
    },
    token_id: envelope.payload.token_id,
    token_hash_b64u: envelope.payload_hash_b64u,
    scope: envelope.payload.scope,
    audience: envelope.payload.audience,
    owner_ref: envelope.payload.owner_ref,
    expires_at: envelope.payload.expires_at,
  };
}
