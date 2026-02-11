/**
 * Execution Attestation Verification
 * CEA-US-010: Verify sandbox execution attestations
 */

import type {
  SignedEnvelope,
  ExecutionAttestationPayload,
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

export interface ExecutionAttestationVerifierOptions {
  /** Allowlisted execution attestation signer DIDs (did:key:...). */
  allowlistedSignerDids?: readonly string[];
}

function validateEnvelopeStructure(
  envelope: unknown
): envelope is SignedEnvelope<ExecutionAttestationPayload> {
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

function validatePayload(
  payload: unknown
): payload is ExecutionAttestationPayload {
  if (typeof payload !== 'object' || payload === null) return false;
  const p = payload as Record<string, unknown>;

  if (p.attestation_version !== '1') return false;
  if (typeof p.attestation_id !== 'string' || p.attestation_id.trim().length === 0)
    return false;

  if (p.execution_type !== 'sandbox_execution' && p.execution_type !== 'tee_execution')
    return false;

  if (!isValidDidFormat(p.agent_did)) return false;
  if (!isValidDidFormat(p.attester_did)) return false;

  // CEA-US-010: require run binding + proof bundle binding
  if (typeof p.run_id !== 'string' || p.run_id.trim().length === 0) return false;
  if (
    typeof p.proof_bundle_hash_b64u !== 'string' ||
    p.proof_bundle_hash_b64u.trim().length < 8 ||
    !isValidBase64Url(p.proof_bundle_hash_b64u)
  )
    return false;

  if (!isValidIsoDate(p.issued_at)) return false;
  if ('expires_at' in p && p.expires_at !== undefined && !isValidIsoDate(p.expires_at))
    return false;

  return true;
}

export async function verifyExecutionAttestation(
  envelope: unknown,
  options: ExecutionAttestationVerifierOptions = {}
): Promise<{
  result: VerificationResult;
  attestation_id?: string;
  execution_type?: ExecutionAttestationPayload['execution_type'];
  agent_did?: string;
  attester_did?: string;
  run_id?: string;
  proof_bundle_hash_b64u?: string;
  signer_did?: string;
  allowlisted?: boolean;
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

  // 2) Version/type allowlist
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

  if (envelope.envelope_type !== 'execution_attestation') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected execution_attestation envelope, got: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: 'This endpoint only accepts execution_attestation envelopes',
        field: 'envelope_type',
      },
    };
  }

  // 3) Algorithm allowlist
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

  // 4) Signer DID validation
  if (!isValidDidFormat(envelope.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Invalid DID format: ${envelope.signer_did}`,
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'Signer DID does not match expected format (did:key:... or did:web:...)',
        field: 'signer_did',
      },
    };
  }

  // 5) Fail-closed: require allowlisted signer DID(s)
  if (!options.allowlistedSignerDids || options.allowlistedSignerDids.length === 0) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Execution attestation signer allowlist not configured',
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      error: {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message: 'Execution attestation signer allowlist is not configured. Set EXECUTION_ATTESTATION_SIGNER_DIDS to enable verification.',
        field: 'env.EXECUTION_ATTESTATION_SIGNER_DIDS',
      },
    };
  }

  const allowlisted = options.allowlistedSignerDids.includes(envelope.signer_did);
  if (!allowlisted) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Execution attestation signer DID is not allowlisted',
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'CLAIM_NOT_FOUND',
        message: `Signer DID '${envelope.signer_did}' is not in the allowlisted execution attestation signer list`,
        field: 'signer_did',
      },
    };
  }

  // 6) Validate issued_at + base64url fields
  if (!isValidIsoDate(envelope.issued_at)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid issued_at date format',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
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
      signer_did: envelope.signer_did,
      allowlisted,
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
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'signature_b64u must be a valid base64url string',
        field: 'signature_b64u',
      },
    };
  }

  // 7) Payload validation
  if (!validatePayload(envelope.payload)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid execution attestation payload structure',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'Payload does not match execution_attestation.v1 constraints',
        field: 'payload',
      },
    };
  }

  const payload = envelope.payload;

  // 8) Internal consistency: payload.attester_did must match signer_did
  if (payload.attester_did !== envelope.signer_did) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Payload attester_did does not match envelope signer_did',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      attester_did: payload.attester_did,
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'payload.attester_did must equal envelope.signer_did',
        field: 'payload.attester_did',
      },
    };
  }

  // 9) Verify payload hash
  let computedHash: string;
  try {
    computedHash = await computeHash(payload, envelope.hash_algorithm);
  } catch (err) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Failed to compute payload hash',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'HASH_MISMATCH',
        message: `Failed to compute hash: ${err instanceof Error ? err.message : 'unknown error'}`,
        field: 'payload',
      },
    };
  }

  if (computedHash !== envelope.payload_hash_b64u) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Payload hash mismatch',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'HASH_MISMATCH',
        message: 'Computed payload hash does not match payload_hash_b64u',
        field: 'payload_hash_b64u',
      },
    };
  }

  // 10) Verify signature over payload_hash_b64u
  const pub = extractPublicKeyFromDidKey(envelope.signer_did);
  if (!pub) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Unable to extract public key from signer_did',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'INVALID_DID_FORMAT',
        message:
          'Unable to extract Ed25519 public key from signer_did (expected did:key with 0xed01 multicodec prefix)',
        field: 'signer_did',
      },
    };
  }

  try {
    const sigBytes = base64UrlDecode(envelope.signature_b64u);
    if (sigBytes.length !== 64) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Invalid signature length',
          verified_at: now,
        },
        signer_did: envelope.signer_did,
        allowlisted,
        error: {
          code: 'SIGNATURE_INVALID',
          message: 'Invalid signature length (expected 64 bytes for Ed25519)',
          field: 'signature_b64u',
        },
      };
    }

    const msgBytes = new TextEncoder().encode(envelope.payload_hash_b64u);
    const signatureOk = await verifySignature(
      envelope.algorithm,
      pub,
      sigBytes,
      msgBytes
    );

    if (!signatureOk) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Signature verification failed',
          verified_at: now,
        },
        signer_did: envelope.signer_did,
        allowlisted,
        error: {
          code: 'SIGNATURE_INVALID',
          message: 'Signature verification failed',
          field: 'signature_b64u',
        },
      };
    }
  } catch (err) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Signature verification error',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'SIGNATURE_INVALID',
        message: `Signature verification error: ${err instanceof Error ? err.message : 'unknown error'}`,
        field: 'signature_b64u',
      },
    };
  }

  return {
    result: {
      status: 'VALID',
      reason: 'Execution attestation verified successfully',
      verified_at: now,
      envelope_type: envelope.envelope_type,
      signer_did: envelope.signer_did,
    },
    signer_did: envelope.signer_did,
    allowlisted,
    attestation_id: payload.attestation_id,
    execution_type: payload.execution_type,
    agent_did: payload.agent_did,
    attester_did: payload.attester_did,
    run_id: payload.run_id,
    proof_bundle_hash_b64u: payload.proof_bundle_hash_b64u,
  };
}
