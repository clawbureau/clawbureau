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
  base64UrlEncode,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto';
import { jcsCanonicalize } from './jcs';

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
/**
 * Detect legacy message_signature format and normalize to signed-envelope.
 * This mirrors the normalization in the bounties service so the clawverify
 * endpoint can accept commit proofs produced by skill-did-work/sign-message.mjs
 * (which outputs the legacy format).
 */
async function normalizeLegacyCommitProof(input: unknown): Promise<unknown> {
  if (typeof input !== 'object' || input === null) return input;
  const obj = input as Record<string, unknown>;

  // Already looks like a signed envelope — pass through
  if ('envelope_version' in obj && 'envelope_type' in obj) return input;

  // Legacy message_signature: { version, type: 'message_signature', algo, did, message: 'commit:<sha>', createdAt, signature }
  if (obj.type === 'message_signature' && typeof obj.message === 'string') {
    const match = (obj.message as string).trim().match(/^commit:([a-f0-9]{7,64})$/i);
    if (!match) return input; // not a commit proof message_signature

    const commitSha = match[1]!.toLowerCase();
    const signerDid = typeof obj.did === 'string' ? (obj.did as string).trim() : '';
    const issuedAt = typeof obj.createdAt === 'string' ? (obj.createdAt as string).trim() : new Date().toISOString();
    const signatureRaw = typeof obj.signature === 'string' ? (obj.signature as string).trim() : '';

    // Convert base64 standard to base64url
    const signatureB64u = signatureRaw
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const payload = {
      proof_version: '1',
      commit_sha: commitSha,
      repo_claim_id: 'legacy',
      repository: 'unknown',
      message: obj.message,
    };

    let payloadHashB64u: string;
    try {
      const encoded = new TextEncoder().encode(jcsCanonicalize(payload));
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
      payloadHashB64u = base64UrlEncode(new Uint8Array(hashBuffer));
    } catch {
      return input; // fail open to let the normal validator produce a precise error
    }

    return {
      envelope_version: '1',
      envelope_type: 'commit_proof',
      payload,
      payload_hash_b64u: payloadHashB64u,
      hash_algorithm: 'SHA-256',
      signature_b64u: signatureB64u,
      algorithm: 'Ed25519',
      signer_did: signerDid,
      issued_at: issuedAt,
    };
  }

  // Legacy commit_proof envelope (has envelope_type but missing some fields)
  if (obj.envelope_type === 'commit_proof' && !('payload_hash_b64u' in obj)) {
    const payload = typeof obj.payload === 'object' && obj.payload !== null ? obj.payload as Record<string, unknown> : {};
    const signerDid = [
      obj.signer_did,
      payload.agent_did,
      payload.signer_did,
      payload.did,
    ].find((c) => typeof c === 'string' && (c as string).trim().startsWith('did:')) as string | undefined;

    const issuedAt = [
      obj.issued_at,
      payload.timestamp,
      payload.issued_at,
      payload.created_at,
      payload.createdAt,
    ].find((c) => typeof c === 'string' && (c as string).trim().length > 0) as string | undefined;

    const normalized: Record<string, unknown> = { ...obj };
    if (signerDid && !normalized.signer_did) normalized.signer_did = signerDid.trim();
    if (issuedAt && !normalized.issued_at) normalized.issued_at = (issuedAt as string).trim();
    if (!normalized.hash_algorithm) normalized.hash_algorithm = 'SHA-256';
    if (!normalized.algorithm) normalized.algorithm = 'Ed25519';

    if (!normalized.payload_hash_b64u) {
      try {
        const encoded = new TextEncoder().encode(jcsCanonicalize(payload));
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
        normalized.payload_hash_b64u = base64UrlEncode(new Uint8Array(hashBuffer));
      } catch {
        // Let the normal validator produce a precise error
      }
    }

    return normalized;
  }

  return input;
}

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

  // 0. Normalize legacy formats before structural validation
  const normalizedEnvelope = await normalizeLegacyCommitProof(envelope);

  // 1. Validate envelope structure
  if (!validateEnvelopeStructure(normalizedEnvelope)) {
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

  // Use the normalized (and now type-narrowed) envelope for all remaining checks
  const envelope_ = normalizedEnvelope;

  // 2. Fail-closed: reject unknown envelope version
  if (!isAllowedVersion(envelope_.envelope_version)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown envelope version: ${envelope_.envelope_version}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_VERSION',
        message: `Envelope version "${envelope_.envelope_version}" is not in the allowlist`,
        field: 'envelope_version',
      },
    };
  }

  // 3. Fail-closed: reject unknown envelope type
  if (!isAllowedType(envelope_.envelope_type)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown envelope type: ${envelope_.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: `Envelope type "${envelope_.envelope_type}" is not in the allowlist`,
        field: 'envelope_type',
      },
    };
  }

  // 4. Verify this is a commit_proof envelope
  if (envelope_.envelope_type !== 'commit_proof') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected commit_proof envelope, got: ${envelope_.envelope_type}`,
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
  if (!isAllowedAlgorithm(envelope_.algorithm)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown signature algorithm: ${envelope_.algorithm}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ALGORITHM',
        message: `Signature algorithm "${envelope_.algorithm}" is not in the allowlist`,
        field: 'algorithm',
      },
    };
  }

  // 6. Fail-closed: reject unknown hash algorithm
  if (!isAllowedHashAlgorithm(envelope_.hash_algorithm)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown hash algorithm: ${envelope_.hash_algorithm}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_HASH_ALGORITHM',
        message: `Hash algorithm "${envelope_.hash_algorithm}" is not in the allowlist`,
        field: 'hash_algorithm',
      },
    };
  }

  // 7. Validate signer DID format
  if (!isValidDidFormat(envelope_.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Invalid DID format: ${envelope_.signer_did}`,
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
  if (!isValidIsoDate(envelope_.issued_at)) {
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
  if (!isValidBase64Url(envelope_.payload_hash_b64u)) {
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

  if (!isValidBase64Url(envelope_.signature_b64u)) {
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
  if (!validateCommitProofPayload(envelope_.payload)) {
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
      repository: envelope_.payload.repository,
      commit_sha: envelope_.payload.commit_sha,
      signer_did: envelope_.signer_did,
      repo_claim_id: envelope_.payload.repo_claim_id,
      error: {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message:
          'Repo claim allowlist is not configured. Set CLAWCLAIM_REPO_CLAIM_ALLOWLIST to enable commit proof verification.',
        field: 'env.CLAWCLAIM_REPO_CLAIM_ALLOWLIST',
      },
    };
  }

  if (!isRepoClaimAllowlisted(envelope_.payload.repo_claim_id, options.allowlistedRepoClaimIds)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Repo claim not found in clawclaim',
        verified_at: now,
      },
      repository: envelope_.payload.repository,
      commit_sha: envelope_.payload.commit_sha,
      signer_did: envelope_.signer_did,
      repo_claim_id: envelope_.payload.repo_claim_id,
      error: {
        code: 'CLAIM_NOT_FOUND',
        message: `Repo claim '${envelope_.payload.repo_claim_id}' was not found in the allowlisted clawclaim registry`,
        field: 'payload.repo_claim_id',
      },
    };
  }

  // 12. Recompute hash and verify it matches
  try {
    const computedHash = await computeHash(envelope_.payload, envelope_.hash_algorithm);

    if (computedHash !== envelope_.payload_hash_b64u) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Payload hash mismatch: envelope may have been tampered with',
          verified_at: now,
        },
        repository: envelope_.payload.repository,
        commit_sha: envelope_.payload.commit_sha,
        signer_did: envelope_.signer_did,
        repo_claim_id: envelope_.payload.repo_claim_id,
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
      repository: envelope_.payload.repository,
      commit_sha: envelope_.payload.commit_sha,
      signer_did: envelope_.signer_did,
      repo_claim_id: envelope_.payload.repo_claim_id,
      error: {
        code: 'HASH_MISMATCH',
        message: 'Failed to compute payload hash',
      },
    };
  }

  // 13. Extract public key from DID
  const publicKeyBytes = extractPublicKeyFromDidKey(envelope_.signer_did);
  if (!publicKeyBytes) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Could not extract public key from signer DID',
        verified_at: now,
      },
      repository: envelope_.payload.repository,
      commit_sha: envelope_.payload.commit_sha,
      signer_did: envelope_.signer_did,
      repo_claim_id: envelope_.payload.repo_claim_id,
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
    const signatureBytes = base64UrlDecode(envelope_.signature_b64u);
    const messageBytes = new TextEncoder().encode(envelope_.payload_hash_b64u);

    const isValid = await verifySignature(
      envelope_.algorithm,
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
        repository: envelope_.payload.repository,
        commit_sha: envelope_.payload.commit_sha,
        signer_did: envelope_.signer_did,
        repo_claim_id: envelope_.payload.repo_claim_id,
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
      repository: envelope_.payload.repository,
      commit_sha: envelope_.payload.commit_sha,
      signer_did: envelope_.signer_did,
      repo_claim_id: envelope_.payload.repo_claim_id,
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
      envelope_type: envelope_.envelope_type,
      signer_did: envelope_.signer_did,
      verified_at: now,
    },
    repository: envelope_.payload.repository,
    commit_sha: envelope_.payload.commit_sha,
    signer_did: envelope_.signer_did,
    repo_claim_id: envelope_.payload.repo_claim_id,
  };
}
