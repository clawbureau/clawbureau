/**
 * Commit Proof Verification
 * CVF-US-011: Verify commit proofs
 */

import type {
  SignedEnvelope,
  CommitProofPayload,
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

export interface CommitProofVerifierOptions {
  /**
   * Allowlisted repo claim IDs.
   * This represents the clawclaim registry (fail-closed if missing).
   */
  allowlistedRepoClaimIds?: readonly string[];
}

/**
 * Validate envelope structure before cryptographic verification
 */
function validateEnvelopeStructure(
  envelope: unknown
): envelope is SignedEnvelope<CommitProofPayload> {
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
 * Validate commit proof payload structure
 */
function validateCommitProofPayload(
  payload: unknown
): payload is CommitProofPayload {
  if (typeof payload !== 'object' || payload === null) {
    return false;
  }

  const p = payload as Record<string, unknown>;

  if (p.proof_version !== '1') return false;
  if (!isNonEmptyString(p.repo_claim_id)) return false;
  if (!isNonEmptyString(p.commit_sha)) return false;
  if (!isNonEmptyString(p.repository)) return false;

  // Optional
  if ('branch' in p && p.branch !== undefined && typeof p.branch !== 'string') return false;

  // Git SHA (allow short or full)
  if (!/^[a-f0-9]{7,64}$/i.test(p.commit_sha)) return false;

  return true;
}

function isRepoClaimAllowlisted(
  repoClaimId: string,
  allowlist: readonly string[] | undefined
): boolean {
  if (!allowlist || allowlist.length === 0) return false;
  return allowlist.includes(repoClaimId);
}

/**
 * Verify a commit proof envelope
 *
 * Acceptance Criteria:
 * - Validate commit proof envelope
 * - Ensure repo claim exists in clawclaim
 * - Return repo + commit + signer DID
 */
export async function verifyCommitProof(
  envelope: unknown,
  options: CommitProofVerifierOptions = {}
): Promise<{
  result: VerificationResult;
  repository?: string;
  commit_sha?: string;
  signer_did?: string;
  repo_claim_id?: string;
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

  // 4. Verify this is a commit_proof envelope
  if (envelope.envelope_type !== 'commit_proof') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected commit_proof envelope, got: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: 'This endpoint only accepts commit_proof envelopes',
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

  // 7. Validate signer DID format
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

  // 10. Validate commit proof payload
  if (!validateCommitProofPayload(envelope.payload)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid commit proof payload structure',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'Commit proof payload is missing required fields or has invalid types',
        field: 'payload',
      },
    };
  }

  // 11. Ensure repo claim exists in clawclaim (represented by allowlist)
  if (!options.allowlistedRepoClaimIds || options.allowlistedRepoClaimIds.length === 0) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Repo claim registry not configured (cannot verify repo_claim_id)',
        verified_at: now,
      },
      repository: envelope.payload.repository,
      commit_sha: envelope.payload.commit_sha,
      signer_did: envelope.signer_did,
      repo_claim_id: envelope.payload.repo_claim_id,
      error: {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message:
          'Repo claim allowlist is not configured. Set CLAWCLAIM_REPO_CLAIM_ALLOWLIST to enable commit proof verification.',
        field: 'env.CLAWCLAIM_REPO_CLAIM_ALLOWLIST',
      },
    };
  }

  if (!isRepoClaimAllowlisted(envelope.payload.repo_claim_id, options.allowlistedRepoClaimIds)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Repo claim not found in clawclaim',
        verified_at: now,
      },
      repository: envelope.payload.repository,
      commit_sha: envelope.payload.commit_sha,
      signer_did: envelope.signer_did,
      repo_claim_id: envelope.payload.repo_claim_id,
      error: {
        code: 'CLAIM_NOT_FOUND',
        message: `Repo claim '${envelope.payload.repo_claim_id}' was not found in the allowlisted clawclaim registry`,
        field: 'payload.repo_claim_id',
      },
    };
  }

  // 12. Recompute hash and verify it matches
  try {
    const computedHash = await computeHash(envelope.payload, envelope.hash_algorithm);

    if (computedHash !== envelope.payload_hash_b64u) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Payload hash mismatch: envelope may have been tampered with',
          verified_at: now,
        },
        repository: envelope.payload.repository,
        commit_sha: envelope.payload.commit_sha,
        signer_did: envelope.signer_did,
        repo_claim_id: envelope.payload.repo_claim_id,
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
      repository: envelope.payload.repository,
      commit_sha: envelope.payload.commit_sha,
      signer_did: envelope.signer_did,
      repo_claim_id: envelope.payload.repo_claim_id,
      error: {
        code: 'HASH_MISMATCH',
        message: 'Failed to compute payload hash',
      },
    };
  }

  // 13. Extract public key from DID
  const publicKeyBytes = extractPublicKeyFromDidKey(envelope.signer_did);
  if (!publicKeyBytes) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Could not extract public key from signer DID',
        verified_at: now,
      },
      repository: envelope.payload.repository,
      commit_sha: envelope.payload.commit_sha,
      signer_did: envelope.signer_did,
      repo_claim_id: envelope.payload.repo_claim_id,
      error: {
        code: 'INVALID_DID_FORMAT',
        message:
          'Unable to extract Ed25519 public key from did:key. Ensure the DID uses the Ed25519 multicodec prefix.',
        field: 'signer_did',
      },
    };
  }

  // 14. Verify signature
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
        repository: envelope.payload.repository,
        commit_sha: envelope.payload.commit_sha,
        signer_did: envelope.signer_did,
        repo_claim_id: envelope.payload.repo_claim_id,
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
      repository: envelope.payload.repository,
      commit_sha: envelope.payload.commit_sha,
      signer_did: envelope.signer_did,
      repo_claim_id: envelope.payload.repo_claim_id,
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'Failed to verify signature',
      },
    };
  }

  // 15. All checks passed
  return {
    result: {
      status: 'VALID',
      reason: 'Commit proof verified successfully',
      envelope_type: envelope.envelope_type,
      signer_did: envelope.signer_did,
      verified_at: now,
    },
    repository: envelope.payload.repository,
    commit_sha: envelope.payload.commit_sha,
    signer_did: envelope.signer_did,
    repo_claim_id: envelope.payload.repo_claim_id,
  };
}
