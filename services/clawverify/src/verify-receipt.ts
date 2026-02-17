/**
 * Gateway Receipt Verification
 * CVF-US-003: Verify gateway receipts for proof-of-harness
 */

import type {
  SignedEnvelope,
  GatewayReceiptPayload,
  VirReceiptPayload,
  ModelIdentityTier,
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
import {
  validateGatewayReceiptEnvelopeV1,
  validateVirEnvelopeV1,
  validateVirEnvelopeV2,
} from './schema-validation';
import { verifyModelIdentityFromReceiptPayload } from './model-identity';
import {
  type VirFailureCode,
  validateVirReceiptCore,
} from './vir-core';

export interface ReceiptVerifierOptions {
  /**
   * Allowlisted gateway signer DIDs (did:key:...).
   * Fail-closed: if empty or missing, receipts are treated as INVALID.
   */
  allowlistedSignerDids?: readonly string[];

  /**
   * Require nonce binding for VIR receipts.
   * Useful for bounty/job non-transferability policy checks.
   */
  requiresJobBinding?: boolean;

  /**
   * Optional strict binding checks for VIR receipts.
   * When set, the verifier requires matching binding.subject and binding.scope.
   */
  expectedSubject?: string;
  expectedScope?: string;
  expectedNonce?: string;
}

// CVF-US-025: Receipt numeric hardening (finite numbers + reasonable upper bounds)
const MAX_RECEIPT_TOKENS = 10_000_000;
const MAX_RECEIPT_LATENCY_MS = 60 * 60 * 1000; // 1 hour

/**
 * Validate envelope structure before cryptographic verification
 * Fail-closed: reject any unknown or missing fields
 */
function validateEnvelopeStructure(
  envelope: unknown
): envelope is SignedEnvelope<GatewayReceiptPayload | VirReceiptPayload> {
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
  if (
    typeof p.tokens_input !== 'number' ||
    !Number.isFinite(p.tokens_input) ||
    !Number.isInteger(p.tokens_input) ||
    p.tokens_input < 0 ||
    p.tokens_input > MAX_RECEIPT_TOKENS
  )
    return false;

  if (
    typeof p.tokens_output !== 'number' ||
    !Number.isFinite(p.tokens_output) ||
    !Number.isInteger(p.tokens_output) ||
    p.tokens_output < 0 ||
    p.tokens_output > MAX_RECEIPT_TOKENS
  )
    return false;

  if (
    typeof p.latency_ms !== 'number' ||
    !Number.isFinite(p.latency_ms) ||
    !Number.isInteger(p.latency_ms) ||
    p.latency_ms < 0 ||
    p.latency_ms > MAX_RECEIPT_LATENCY_MS
  )
    return false;
  if (!isValidIsoDate(p.timestamp)) return false;

  return true;
}

/**
 * Validate VIR payload structure.
 */
function validateVirPayload(payload: unknown): payload is VirReceiptPayload {
  if (typeof payload !== 'object' || payload === null) {
    return false;
  }

  const p = payload as Record<string, unknown>;

  if (p.receipt_version !== '1' && p.receipt_version !== '2') return false;
  if (typeof p.receipt_id !== 'string' || p.receipt_id.length === 0) return false;
  if (
    p.source !== 'tls_decrypt' &&
    p.source !== 'gateway' &&
    p.source !== 'interpose' &&
    p.source !== 'preload' &&
    p.source !== 'sni'
  ) {
    return false;
  }
  if (typeof p.provider !== 'string' || p.provider.length === 0) return false;
  if (typeof p.model !== 'string' || p.model.length === 0) return false;
  if (typeof p.request_hash_b64u !== 'string' || p.request_hash_b64u.length === 0) return false;
  if (typeof p.response_hash_b64u !== 'string' || p.response_hash_b64u.length === 0) return false;

  if (
    typeof p.tokens_input !== 'number' ||
    !Number.isFinite(p.tokens_input) ||
    p.tokens_input < 0 ||
    p.tokens_input > MAX_RECEIPT_TOKENS
  ) {
    return false;
  }

  if (
    typeof p.tokens_output !== 'number' ||
    !Number.isFinite(p.tokens_output) ||
    p.tokens_output < 0 ||
    p.tokens_output > MAX_RECEIPT_TOKENS
  ) {
    return false;
  }

  if (
    typeof p.latency_ms !== 'number' ||
    !Number.isFinite(p.latency_ms) ||
    p.latency_ms < 0 ||
    p.latency_ms > MAX_RECEIPT_LATENCY_MS
  ) {
    return false;
  }

  if (typeof p.agent_did !== 'string' || !isValidDidFormat(p.agent_did)) return false;
  if (!isValidIsoDate(p.timestamp)) return false;

  const modelClaimed = p.model_claimed;
  const modelObserved = p.model_observed;
  if (
    p.receipt_version === '1' &&
    p.source === 'tls_decrypt' &&
    typeof modelClaimed === 'string' &&
    typeof modelObserved === 'string' &&
    modelClaimed.length > 0 &&
    modelObserved.length > 0 &&
    modelClaimed !== modelObserved
  ) {
    return false;
  }

  return true;
}

function mapVirFailureToReceiptError(
  failureCode: VirFailureCode | undefined,
  failureMessage: string | undefined,
  options: ReceiptVerifierOptions,
  payload: VirReceiptPayload
): VerificationError {
  const message = failureMessage ?? failureCode ?? 'VIR validation failed';

  const nonce = payload.binding?.nonce ?? payload.legal_binding?.nonce;
  const subject =
    payload.binding?.subject ??
    payload.binding?.subject_did ??
    payload.legal_binding?.subject_did;
  const scope =
    payload.binding?.scope ??
    payload.binding?.scope_hash_b64u ??
    payload.legal_binding?.scope_hash_b64u;

  switch (failureCode) {
    case 'ERR_MERKLE_ROOT_MISMATCH':
      return {
        code: 'EVIDENCE_MISMATCH',
        message: 'ERR_MERKLE_ROOT_MISMATCH',
        field: 'payload.selective_disclosure.merkle_root_b64u',
      };
    case 'ERR_CONFLICT_UNREPORTED':
      return {
        code: 'EVIDENCE_MISMATCH',
        message: 'ERR_CONFLICT_UNREPORTED',
        field: 'payload.evidence_conflicts',
      };
    case 'ERR_PRECEDENCE_VIOLATION':
      return {
        code: 'EVIDENCE_MISMATCH',
        message: 'ERR_PRECEDENCE_VIOLATION',
        field: 'payload.evidence_conflicts',
      };
    case 'ERR_LEGAL_BINDING_REQUIRED':
      return {
        code: 'MISSING_REQUIRED_FIELD',
        message,
        field: 'payload.legal_binding',
      };
    case 'ERR_BINDING_NONCE_MISMATCH': {
      const expectsSpecificNonce =
        typeof options.expectedNonce === 'string' && options.expectedNonce.trim().length > 0;

      if (!expectsSpecificNonce && options.requiresJobBinding && (!nonce || nonce.trim().length === 0)) {
        return {
          code: 'MISSING_NONCE',
          message,
          field: 'payload.binding.nonce',
        };
      }

      return {
        code: 'EVIDENCE_MISMATCH',
        message,
        field: 'payload.binding.nonce',
      };
    }
    case 'ERR_BINDING_SUBJECT_MISMATCH': {
      const missing =
        typeof options.expectedSubject === 'string' &&
        options.expectedSubject.trim().length > 0 &&
        (!subject || subject.trim().length === 0);

      return {
        code: missing ? 'MISSING_REQUIRED_FIELD' : 'EVIDENCE_MISMATCH',
        message,
        field: 'payload.binding.subject',
      };
    }
    case 'ERR_BINDING_SCOPE_MISMATCH': {
      const missing =
        typeof options.expectedScope === 'string' &&
        options.expectedScope.trim().length > 0 &&
        (!scope || scope.trim().length === 0);

      return {
        code: missing ? 'MISSING_REQUIRED_FIELD' : 'EVIDENCE_MISMATCH',
        message,
        field: 'payload.binding.scope',
      };
    }
    case 'ERR_BINDING_EVENT_HASH_INVALID':
      return {
        code: 'EVIDENCE_MISMATCH',
        message,
        field: 'payload.binding.event_hash_b64u',
      };
    case 'ERR_BINDING_RUN_ID_MISMATCH':
      return {
        code: 'EVIDENCE_MISMATCH',
        message,
        field: 'payload.binding.run_id',
      };
    default:
      return {
        code: 'EVIDENCE_MISMATCH',
        message,
        field: 'payload',
      };
  }
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
  model_identity_tier?: ModelIdentityTier;
  risk_flags?: string[];
  error?: VerificationError;
}> {
  const now = new Date().toISOString();
  const virRiskFlags = new Set<string>();

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
  if (!isAllowedType(envelope.envelope_type) && envelope.envelope_type !== 'vir_receipt') {
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

  // 4. Verify this is a gateway_receipt or vir_receipt envelope
  if (envelope.envelope_type !== 'gateway_receipt' && envelope.envelope_type !== 'vir_receipt') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected gateway_receipt or vir_receipt envelope, got: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: 'This endpoint only accepts gateway_receipt or vir_receipt envelopes',
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

  // 6.5 Strict JSON schema validation (Ajv) for envelope + payload
  // CVF-US-024: Fail closed on schema violations (additionalProperties:false, missing fields, etc.)
  const schemaResult = (() => {
    if (envelope.envelope_type === 'gateway_receipt') {
      return validateGatewayReceiptEnvelopeV1(envelope);
    }

    const virV2 = validateVirEnvelopeV2(envelope);
    if (virV2.valid) return virV2;

    return validateVirEnvelopeV1(envelope);
  })();

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

  // 7.5 Fail-closed: require allowlisted signer DIDs for gateway_receipt only.
  if (envelope.envelope_type === 'gateway_receipt') {
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
  if (envelope.envelope_type === 'gateway_receipt') {
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
  } else {
    if (!validateVirPayload(envelope.payload)) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Invalid VIR payload structure',
          verified_at: now,
        },
        error: {
          code: 'MALFORMED_ENVELOPE',
          message: 'VIR payload is missing required fields or has invalid types',
          field: 'payload',
        },
      };
    }

    const virPayload = envelope.payload as VirReceiptPayload;
    const virValidation = await validateVirReceiptCore({
      payload: virPayload,
      expected: {
        requireNonce: options.requiresJobBinding === true,
        nonce:
          typeof options.expectedNonce === 'string' && options.expectedNonce.trim().length > 0
            ? options.expectedNonce
            : null,
        subject:
          typeof options.expectedSubject === 'string' && options.expectedSubject.trim().length > 0
            ? options.expectedSubject
            : null,
        scope:
          typeof options.expectedScope === 'string' && options.expectedScope.trim().length > 0
            ? options.expectedScope
            : null,
      },
    });

    if (!virValidation.valid) {
      const mappedError = mapVirFailureToReceiptError(
        virValidation.code,
        virValidation.message,
        options,
        virPayload
      );

      return {
        result: {
          status: 'INVALID',
          reason: virValidation.message ?? virValidation.code ?? 'VIR validation failed',
          verified_at: now,
        },
        error: mappedError,
      };
    }

    for (const flag of virValidation.riskFlags) {
      virRiskFlags.add(flag);
    }
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
  let modelIdentityTier: ModelIdentityTier = 'unknown';
  let modelIdentityRiskFlags: string[] = [];

  if (envelope.envelope_type === 'gateway_receipt') {
    try {
      const modelIdentity = await verifyModelIdentityFromReceiptPayload(
        envelope.payload as GatewayReceiptPayload
      );
      modelIdentityTier = modelIdentity.tier;
      modelIdentityRiskFlags = modelIdentity.risk_flags;
    } catch {
      modelIdentityRiskFlags = ['MODEL_IDENTITY_VERIFY_FAILED'];
      // Fail closed on the model identity axis only; do not break receipt verification.
    }
  }

  const payload = envelope.payload as GatewayReceiptPayload | VirReceiptPayload;

  return {
    result: {
      status: 'VALID',
      reason: envelope.envelope_type === 'vir_receipt'
        ? 'VIR receipt verified successfully'
        : 'Gateway receipt verified successfully',
      envelope_type: envelope.envelope_type,
      signer_did: envelope.signer_did,
      verified_at: now,
    },
    provider: payload.provider,
    model: envelope.envelope_type === 'vir_receipt'
      ? (payload as VirReceiptPayload).model_observed ?? payload.model
      : payload.model,
    gateway_id: envelope.envelope_type === 'vir_receipt'
      ? (payload as VirReceiptPayload).receipt_id
      : (payload as GatewayReceiptPayload).gateway_id,
    model_identity_tier: modelIdentityTier,
    risk_flags: (() => {
      const merged = [...modelIdentityRiskFlags, ...Array.from(virRiskFlags)];
      return merged.length > 0 ? [...new Set(merged)].sort() : undefined;
    })(),
  };
}
