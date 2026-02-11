/**
 * Derivation Attestation Verification
 * CVF-US-017: Verify derivation attestations (Prepare analogue)
 */

import type {
  SignedEnvelope,
  DerivationAttestationPayload,
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
import { validateDerivationAttestationEnvelopeV1 } from './schema-validation';

export interface DerivationAttestationVerifierOptions {
  /**
   * Allowlisted signer DIDs (did:key:...).
   * Fail-closed: if empty or missing, attestations are treated as INVALID.
   */
  allowlistedSignerDids?: readonly string[];
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function normalizeModelIdentityTier(tier: unknown): ModelIdentityTier {
  if (tier === 'closed_opaque') return 'closed_opaque';
  if (tier === 'closed_provider_manifest') return 'closed_provider_manifest';
  if (tier === 'openweights_hashable') return 'openweights_hashable';
  if (tier === 'tee_measured') return 'tee_measured';
  return 'unknown';
}

function extractModelSummary(identity: unknown): {
  provider?: string;
  name?: string;
  tier?: ModelIdentityTier;
} {
  if (!isRecord(identity)) return {};
  const tier = normalizeModelIdentityTier(identity.tier);

  const model = isRecord(identity.model) ? identity.model : null;
  const provider = model && typeof model.provider === 'string' ? model.provider : undefined;
  const name = model && typeof model.name === 'string' ? model.name : undefined;

  return { provider, name, tier };
}

function validateEnvelopeStructure(
  envelope: unknown
): envelope is SignedEnvelope<DerivationAttestationPayload> {
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

export async function verifyDerivationAttestation(
  envelope: unknown,
  options: DerivationAttestationVerifierOptions = {}
): Promise<{
  result: VerificationResult;
  derivation_id?: string;
  transform_kind?: string;
  input_model?: { provider?: string; name?: string; tier?: ModelIdentityTier };
  output_model?: { provider?: string; name?: string; tier?: ModelIdentityTier };
  error?: VerificationError;
}> {
  const now = new Date().toISOString();

  // 1) Envelope structure
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

  // 2) Allowlisted version
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

  // 3) Allowlisted type
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

  // 4) Correct endpoint type
  if (envelope.envelope_type !== 'derivation_attestation') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected derivation_attestation envelope, got: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: 'This endpoint only accepts derivation_attestation envelopes',
        field: 'envelope_type',
      },
    };
  }

  // 5) Allowlisted algorithms
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

  // 6) Strict JSON schema validation (Ajv standalone)
  const schemaResult = validateDerivationAttestationEnvelopeV1(envelope);
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

  // 7) DID format
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

  // 8) Fail-closed allowlist
  if (!options.allowlistedSignerDids || options.allowlistedSignerDids.length === 0) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Derivation attestation signer allowlist not configured',
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      error: {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message:
          'Derivation attestation signer allowlist is not configured. Set DERIVATION_ATTESTATION_SIGNER_DIDS to enable verification.',
        field: 'env.DERIVATION_ATTESTATION_SIGNER_DIDS',
      },
    };
  }

  if (!options.allowlistedSignerDids.includes(envelope.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Attestation signer DID is not allowlisted',
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      error: {
        code: 'CLAIM_NOT_FOUND',
        message: `Signer DID '${envelope.signer_did}' is not in the allowlisted derivation attester list`,
        field: 'signer_did',
      },
    };
  }

  // 9) issued_at
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

  // 10) base64url fields
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

  // 11) Hash recompute
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

  // 12) Key extraction (did:key only)
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

  // 13) Signature verify
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

  // 14) Summary extraction
  const payloadRec = envelope.payload as unknown as Record<string, unknown>;
  const derivationId = typeof payloadRec.derivation_id === 'string' ? payloadRec.derivation_id : undefined;

  let transformKind: string | undefined;
  if (isRecord(payloadRec.transform) && typeof payloadRec.transform.kind === 'string') {
    transformKind = payloadRec.transform.kind;
  }

  const inputSummary = extractModelSummary(payloadRec.input_model);
  const outputSummary = extractModelSummary(payloadRec.output_model);

  return {
    result: {
      status: 'VALID',
      reason: 'Derivation attestation verified successfully',
      envelope_type: envelope.envelope_type,
      signer_did: envelope.signer_did,
      verified_at: now,
    },
    derivation_id: derivationId,
    transform_kind: transformKind,
    input_model: inputSummary,
    output_model: outputSummary,
  };
}
