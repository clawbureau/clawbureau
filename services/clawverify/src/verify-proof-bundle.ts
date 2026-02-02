/**
 * Proof Bundle Verification
 * CVF-US-007: Verify proof bundles for trust tier computation
 *
 * Validates:
 * - URM (Universal Resource Manifest)
 * - Event chains
 * - Gateway receipts
 * - Attestations
 *
 * Computes trust tier based on which components are present and valid.
 */

import type {
  SignedEnvelope,
  ProofBundlePayload,
  ProofBundleVerificationResult,
  VerificationError,
  TrustTier,
  URMReference,
  AttestationReference,
  GatewayReceiptPayload,
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
 * Validate envelope structure for proof bundle
 */
function validateEnvelopeStructure(
  envelope: unknown
): envelope is SignedEnvelope<ProofBundlePayload> {
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
 * Validate proof bundle payload structure
 */
function validateBundlePayload(
  payload: unknown
): payload is ProofBundlePayload {
  if (typeof payload !== 'object' || payload === null) {
    return false;
  }

  const p = payload as Record<string, unknown>;

  // Required fields
  if (p.bundle_version !== '1') return false;
  if (typeof p.bundle_id !== 'string' || p.bundle_id.length === 0) return false;
  if (typeof p.agent_did !== 'string') return false;

  // At least one component must be present
  const hasUrm = p.urm !== undefined;
  const hasEventChain = Array.isArray(p.event_chain);
  const hasReceipts = Array.isArray(p.receipts);
  const hasAttestations = Array.isArray(p.attestations);

  return hasUrm || hasEventChain || hasReceipts || hasAttestations;
}

/**
 * Validate URM reference structure
 */
function validateURM(urm: unknown): urm is URMReference {
  if (typeof urm !== 'object' || urm === null) return false;

  const u = urm as Record<string, unknown>;

  return (
    u.urm_version === '1' &&
    typeof u.urm_id === 'string' &&
    typeof u.resource_type === 'string' &&
    typeof u.resource_hash_b64u === 'string' &&
    isValidBase64Url(u.resource_hash_b64u)
  );
}

/**
 * Validate event chain entries and hash chain integrity
 */
function validateEventChain(
  events: unknown[]
): { valid: boolean; error?: string } {
  if (events.length === 0) {
    return { valid: false, error: 'Empty event chain' };
  }

  let prevHash: string | null = null;
  let expectedRunId: string | null = null;

  for (let i = 0; i < events.length; i++) {
    const event = events[i] as Record<string, unknown>;

    // Validate required fields
    if (typeof event.event_id !== 'string') {
      return { valid: false, error: `Event ${i}: missing event_id` };
    }
    if (typeof event.run_id !== 'string') {
      return { valid: false, error: `Event ${i}: missing run_id` };
    }
    if (typeof event.event_type !== 'string') {
      return { valid: false, error: `Event ${i}: missing event_type` };
    }
    if (!isValidIsoDate(event.timestamp)) {
      return { valid: false, error: `Event ${i}: invalid timestamp` };
    }
    if (!isValidBase64Url(event.payload_hash_b64u)) {
      return { valid: false, error: `Event ${i}: invalid payload_hash_b64u` };
    }
    if (!isValidBase64Url(event.event_hash_b64u)) {
      return { valid: false, error: `Event ${i}: invalid event_hash_b64u` };
    }

    // Enforce run_id consistency
    if (expectedRunId === null) {
      expectedRunId = event.run_id as string;
    } else if (event.run_id !== expectedRunId) {
      return {
        valid: false,
        error: `Event ${i}: inconsistent run_id (expected ${expectedRunId})`,
      };
    }

    // Validate hash chain linkage
    const eventPrevHash = event.prev_hash_b64u;
    if (i === 0) {
      // First event should have null prev_hash
      if (eventPrevHash !== null && eventPrevHash !== '') {
        // Allow empty string for first entry
        return {
          valid: false,
          error: 'First event should have null prev_hash_b64u',
        };
      }
    } else {
      // Subsequent events should link to previous
      if (eventPrevHash !== prevHash) {
        return {
          valid: false,
          error: `Event ${i}: hash chain break detected`,
        };
      }
    }

    prevHash = event.event_hash_b64u as string;
  }

  return { valid: true };
}

/**
 * Validate attestation references
 */
function validateAttestation(
  attestation: unknown
): attestation is AttestationReference {
  if (typeof attestation !== 'object' || attestation === null) return false;

  const a = attestation as Record<string, unknown>;

  // Check required fields
  if (typeof a.attestation_id !== 'string') return false;
  if (a.attestation_type !== 'owner' && a.attestation_type !== 'third_party')
    return false;
  if (!isValidDidFormat(a.attester_did)) return false;
  if (!isValidDidFormat(a.subject_did)) return false;
  if (!isValidBase64Url(a.signature_b64u)) return false;

  // Check expiry if present
  if (a.expires_at !== undefined) {
    if (!isValidIsoDate(a.expires_at)) return false;
    const expiryDate = new Date(a.expires_at as string);
    if (expiryDate < new Date()) {
      return false; // Expired
    }
  }

  return true;
}

/**
 * Validate gateway receipt envelope structure (minimal check)
 */
function validateReceiptEnvelope(
  receipt: unknown
): receipt is SignedEnvelope<GatewayReceiptPayload> {
  if (typeof receipt !== 'object' || receipt === null) return false;

  const r = receipt as Record<string, unknown>;

  if (r.envelope_type !== 'gateway_receipt') return false;
  if (!isAllowedVersion(r.envelope_version)) return false;

  const payload = r.payload as Record<string, unknown> | undefined;
  if (!payload) return false;

  return (
    payload.receipt_version === '1' &&
    typeof payload.receipt_id === 'string' &&
    typeof payload.gateway_id === 'string' &&
    typeof payload.provider === 'string' &&
    typeof payload.model === 'string'
  );
}

/**
 * Compute trust tier based on validated components
 *
 * Trust Tier Levels:
 * - unknown: No valid components
 * - basic: Valid envelope signature only
 * - verified: Valid event chain or receipts
 * - attested: Valid owner attestation
 * - full: All components valid (URM + events + receipts + attestations)
 */
function computeTrustTier(components: {
  envelope_valid: boolean;
  urm_valid?: boolean;
  event_chain_valid?: boolean;
  receipts_valid?: boolean;
  attestations_valid?: boolean;
}): TrustTier {
  if (!components.envelope_valid) {
    return 'unknown';
  }

  // Full trust: all components present and valid
  if (
    components.urm_valid &&
    components.event_chain_valid &&
    components.receipts_valid &&
    components.attestations_valid
  ) {
    return 'full';
  }

  // Attested: has valid attestations
  if (components.attestations_valid) {
    return 'attested';
  }

  // Verified: has valid event chain or receipts
  if (components.event_chain_valid || components.receipts_valid) {
    return 'verified';
  }

  // Basic: envelope is valid but no strong proofs
  return 'basic';
}

/**
 * Verify a proof bundle envelope
 *
 * Acceptance Criteria:
 * - Validate URM + event chain + receipts + attestations
 * - Fail closed on unknown schema/version
 * - Return computed trust tier
 */
export async function verifyProofBundle(
  envelope: unknown
): Promise<{ result: ProofBundleVerificationResult; error?: VerificationError }> {
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

  // 4. Verify this is a proof_bundle envelope
  if (envelope.envelope_type !== 'proof_bundle') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected proof_bundle envelope, got: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: 'This endpoint only accepts proof_bundle envelopes',
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

  // 10. Validate proof bundle payload structure
  if (!validateBundlePayload(envelope.payload)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid proof bundle payload structure',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message:
          'Proof bundle payload is missing required fields or has no components',
        field: 'payload',
      },
    };
  }

  // 11. Validate agent_did in payload matches expected format
  if (!isValidDidFormat(envelope.payload.agent_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Invalid agent_did format: ${envelope.payload.agent_did}`,
        verified_at: now,
      },
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'agent_did does not match expected DID format',
        field: 'payload.agent_did',
      },
    };
  }

  // 12. Recompute hash and verify it matches
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

  // 13. Extract public key from DID
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

  // 14. Verify envelope signature
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

  // 15. Validate individual components
  const payload = envelope.payload;
  const componentResults: ProofBundleVerificationResult['component_results'] = {
    envelope_valid: true,
  };

  // Validate URM if present
  if (payload.urm !== undefined) {
    componentResults.urm_valid = validateURM(payload.urm);
  }

  // Validate event chain if present
  if (payload.event_chain !== undefined && payload.event_chain.length > 0) {
    const chainResult = validateEventChain(payload.event_chain);
    componentResults.event_chain_valid = chainResult.valid;
  }

  // Validate receipts if present
  if (payload.receipts !== undefined && payload.receipts.length > 0) {
    const validReceipts = payload.receipts.filter(validateReceiptEnvelope);
    componentResults.receipts_valid = validReceipts.length === payload.receipts.length;
    componentResults.receipts_count = payload.receipts.length;
  }

  // Validate attestations if present
  if (payload.attestations !== undefined && payload.attestations.length > 0) {
    const validAttestations = payload.attestations.filter(validateAttestation);
    componentResults.attestations_valid =
      validAttestations.length === payload.attestations.length;
    componentResults.attestations_count = payload.attestations.length;
  }

  // 16. Compute trust tier
  const trustTier = computeTrustTier(componentResults);

  // 17. Return success with trust tier
  return {
    result: {
      status: 'VALID',
      reason: 'Proof bundle verified successfully',
      verified_at: now,
      bundle_id: payload.bundle_id,
      agent_did: payload.agent_did,
      trust_tier: trustTier,
      component_results: componentResults,
    },
  };
}
