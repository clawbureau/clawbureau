/**
 * Proof Bundle Verification
 * CVF-US-007: Verify proof bundles for trust tier computation
 * POH-US-003: Validate proof bundles against PoH schema, verify receipts
 *             with clawproxy DID, verify event-chain hash linkage, and
 *             return trust tier based on validated components.
 *
 * Validates:
 * - Proof bundle payload against PoH schema (proof_bundle.v1)
 * - URM (Universal Resource Manifest) structure
 * - Event chain hash linkage and run_id consistency
 * - Gateway receipt envelopes (cryptographic verification)
 * - Attestations
 *
 * Computes trust tier based on which components are present and valid.
 * Fail-closed: unknown or malformed payloads always result in 'unknown' tier.
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
import { verifyReceipt } from './verify-receipt';

export interface ProofBundleVerifierOptions {
  /** Allowlisted gateway receipt signer DIDs (did:key:...). */
  allowlistedReceiptSignerDids?: readonly string[];
}

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
 * Validate proof bundle payload structure against PoH schema (proof_bundle.v1).
 *
 * Schema constraints enforced:
 * - bundle_version: const "1"
 * - bundle_id: string, minLength 1
 * - agent_did: string, pattern ^did:
 * - At least one of: urm, event_chain, receipts, attestations
 */
function validateBundlePayload(
  payload: unknown
): { valid: boolean; error?: string } {
  if (typeof payload !== 'object' || payload === null) {
    return { valid: false, error: 'Payload must be an object' };
  }

  const p = payload as Record<string, unknown>;

  // Required fields per schema
  if (p.bundle_version !== '1') {
    return { valid: false, error: 'bundle_version must be "1"' };
  }
  if (typeof p.bundle_id !== 'string' || p.bundle_id.length === 0) {
    return { valid: false, error: 'bundle_id is required and must be non-empty' };
  }
  if (typeof p.agent_did !== 'string' || !/^did:/.test(p.agent_did)) {
    return { valid: false, error: 'agent_did must be a string starting with "did:"' };
  }

  // At least one component must be present (schema anyOf)
  const hasUrm = p.urm !== undefined;
  const hasEventChain = Array.isArray(p.event_chain) && p.event_chain.length > 0;
  const hasReceipts = Array.isArray(p.receipts) && p.receipts.length > 0;
  const hasAttestations = Array.isArray(p.attestations) && p.attestations.length > 0;

  if (!hasUrm && !hasEventChain && !hasReceipts && !hasAttestations) {
    return { valid: false, error: 'At least one of urm, event_chain, receipts, or attestations is required' };
  }

  return { valid: true };
}

/**
 * Type guard helper (thin wrapper for backward compatibility)
 */
function isBundlePayload(payload: unknown): payload is ProofBundlePayload {
  return validateBundlePayload(payload).valid;
}

/**
 * Validate URM reference structure per PoH schema (proof_bundle.v1 → urm).
 *
 * Schema constraints:
 * - urm_version: const "1"
 * - urm_id: string, minLength 1
 * - resource_type: string, minLength 1
 * - resource_hash_b64u: base64url string, minLength 8
 */
function validateURM(urm: unknown): urm is URMReference {
  if (typeof urm !== 'object' || urm === null) return false;

  const u = urm as Record<string, unknown>;

  return (
    u.urm_version === '1' &&
    typeof u.urm_id === 'string' &&
    u.urm_id.length >= 1 &&
    typeof u.resource_type === 'string' &&
    u.resource_type.length >= 1 &&
    typeof u.resource_hash_b64u === 'string' &&
    u.resource_hash_b64u.length >= 8 &&
    isValidBase64Url(u.resource_hash_b64u)
  );
}

/**
 * Validate event chain entries and hash chain integrity per PoH schema.
 *
 * Schema constraints per event_chain.v1 / proof_bundle.v1:
 * - event_id, run_id, event_type: string, minLength 1
 * - timestamp: ISO 8601 date-time
 * - payload_hash_b64u, event_hash_b64u: base64url, minLength 8
 * - prev_hash_b64u: base64url (minLength 8) or null for the first event
 * - Hash chain: first event has null prev_hash, subsequent events link
 * - run_id consistency across all events
 */
function validateEventChain(
  events: unknown[]
): { valid: boolean; chain_root_hash?: string; error?: string } {
  if (events.length === 0) {
    return { valid: false, error: 'Empty event chain' };
  }

  let prevHash: string | null = null;
  let expectedRunId: string | null = null;
  let chainRootHash: string | null = null;

  for (let i = 0; i < events.length; i++) {
    const event = events[i] as Record<string, unknown>;

    // Validate required fields with minLength constraints
    if (typeof event.event_id !== 'string' || event.event_id.length < 1) {
      return { valid: false, error: `Event ${i}: missing or empty event_id` };
    }
    if (typeof event.run_id !== 'string' || event.run_id.length < 1) {
      return { valid: false, error: `Event ${i}: missing or empty run_id` };
    }
    if (typeof event.event_type !== 'string' || event.event_type.length < 1) {
      return { valid: false, error: `Event ${i}: missing or empty event_type` };
    }
    if (!isValidIsoDate(event.timestamp)) {
      return { valid: false, error: `Event ${i}: invalid timestamp` };
    }
    if (
      !isValidBase64Url(event.payload_hash_b64u) ||
      (event.payload_hash_b64u as string).length < 8
    ) {
      return { valid: false, error: `Event ${i}: invalid payload_hash_b64u (must be base64url, minLength 8)` };
    }
    if (
      !isValidBase64Url(event.event_hash_b64u) ||
      (event.event_hash_b64u as string).length < 8
    ) {
      return { valid: false, error: `Event ${i}: invalid event_hash_b64u (must be base64url, minLength 8)` };
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
        return {
          valid: false,
          error: 'First event should have null prev_hash_b64u',
        };
      }
      chainRootHash = event.event_hash_b64u as string;
    } else {
      // Non-first events: prev_hash must be base64url, minLength 8
      if (
        typeof eventPrevHash !== 'string' ||
        !isValidBase64Url(eventPrevHash) ||
        eventPrevHash.length < 8
      ) {
        return {
          valid: false,
          error: `Event ${i}: invalid prev_hash_b64u (must be base64url, minLength 8)`,
        };
      }
      // Must link to previous event's hash
      if (eventPrevHash !== prevHash) {
        return {
          valid: false,
          error: `Event ${i}: hash chain break detected`,
        };
      }
    }

    prevHash = event.event_hash_b64u as string;
  }

  return { valid: true, chain_root_hash: chainRootHash ?? undefined };
}

/**
 * Validate attestation references per PoH schema (proof_bundle.v1 → attestations).
 *
 * Schema constraints:
 * - attestation_id: string, minLength 1
 * - attestation_type: enum ["owner", "third_party"]
 * - attester_did: string, pattern ^did:
 * - subject_did: string, pattern ^did:
 * - signature_b64u: base64url, minLength 8
 * - expires_at: optional ISO 8601 date-time
 */
function validateAttestation(
  attestation: unknown
): attestation is AttestationReference {
  if (typeof attestation !== 'object' || attestation === null) return false;

  const a = attestation as Record<string, unknown>;

  // Check required fields with schema constraints
  if (typeof a.attestation_id !== 'string' || a.attestation_id.length < 1) return false;
  if (a.attestation_type !== 'owner' && a.attestation_type !== 'third_party')
    return false;
  if (!isValidDidFormat(a.attester_did)) return false;
  if (!isValidDidFormat(a.subject_did)) return false;
  if (
    !isValidBase64Url(a.signature_b64u) ||
    (a.signature_b64u as string).length < 8
  )
    return false;

  // Check expiry if present
  if (a.expires_at !== undefined) {
    if (!isValidIsoDate(a.expires_at)) return false;
    const expiryDate = new Date(a.expires_at as string);
    if (expiryDate < new Date()) {
      return false; // Expired — fail closed
    }
  }

  return true;
}

interface ReceiptBindingContext {
  expectedRunId: string;
  allowedEventHashes: ReadonlySet<string>;
}

/**
 * Verify a gateway receipt envelope cryptographically *and* ensure it is bound
 * to the proof bundle's event chain.
 *
 * Security note (POH-US-010):
 * - A receipt that is signature-valid but not bound to this bundle's run/event
 *   chain MUST NOT count toward gateway-tier trust. Otherwise, receipts can be
 *   replayed across bundles.
 *
 * Binding rules (fail-closed for counting):
 * - Proof bundle must include a valid event_chain
 * - receipt.payload.binding.run_id must equal the bundle run_id
 * - receipt.payload.binding.event_hash_b64u must reference an event_hash_b64u
 *   present in the bundle event_chain
 */
async function verifyReceiptEnvelope(
  receipt: unknown,
  allowlistedSignerDids: readonly string[] | undefined,
  bindingContext: ReceiptBindingContext | null
): Promise<{
  /** Whether the receipt counts as verified for gateway-tier (signature + binding). */
  valid: boolean;
  /** Whether the receipt signature+payload hash verified. */
  signature_valid: boolean;
  /** Whether the receipt was bound to the proof bundle's event chain. */
  binding_valid: boolean;
  provider?: string;
  model?: string;
  gateway_id?: string;
  signer_did?: string;
  error?: string;
}> {
  const verification = await verifyReceipt(receipt, { allowlistedSignerDids });

  if (verification.result.status !== 'VALID') {
    return {
      valid: false,
      signature_valid: false,
      binding_valid: false,
      error: verification.error?.message ?? verification.result.reason,
    };
  }

  if (!bindingContext) {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      provider: verification.provider,
      model: verification.model,
      gateway_id: verification.gateway_id,
      signer_did: verification.result.signer_did,
      error:
        'Receipt binding cannot be verified: proof bundle event_chain is missing or invalid',
    };
  }

  const env = receipt as SignedEnvelope<GatewayReceiptPayload>;
  const binding = env.payload.binding;

  if (!binding || typeof binding !== 'object') {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      provider: verification.provider,
      model: verification.model,
      gateway_id: verification.gateway_id,
      signer_did: verification.result.signer_did,
      error: 'Receipt is missing binding (expected run_id + event_hash_b64u)',
    };
  }

  const runId = (binding as Record<string, unknown>).run_id;
  const eventHash = (binding as Record<string, unknown>).event_hash_b64u;

  if (typeof runId !== 'string' || runId.trim().length === 0) {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      provider: verification.provider,
      model: verification.model,
      gateway_id: verification.gateway_id,
      signer_did: verification.result.signer_did,
      error: 'Receipt binding.run_id is missing or invalid',
    };
  }

  if (runId !== bindingContext.expectedRunId) {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      provider: verification.provider,
      model: verification.model,
      gateway_id: verification.gateway_id,
      signer_did: verification.result.signer_did,
      error: 'Receipt binding.run_id does not match proof bundle run_id',
    };
  }

  if (
    typeof eventHash !== 'string' ||
    eventHash.length < 8 ||
    !isValidBase64Url(eventHash)
  ) {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      provider: verification.provider,
      model: verification.model,
      gateway_id: verification.gateway_id,
      signer_did: verification.result.signer_did,
      error: 'Receipt binding.event_hash_b64u is missing or invalid',
    };
  }

  if (!bindingContext.allowedEventHashes.has(eventHash)) {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      provider: verification.provider,
      model: verification.model,
      gateway_id: verification.gateway_id,
      signer_did: verification.result.signer_did,
      error:
        'Receipt binding.event_hash_b64u does not reference an event in the proof bundle event chain',
    };
  }

  return {
    valid: true,
    signature_valid: true,
    binding_valid: true,
    provider: verification.provider,
    model: verification.model,
    gateway_id: verification.gateway_id,
    signer_did: verification.result.signer_did,
  };
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
  envelope: unknown,
  options: ProofBundleVerifierOptions = {}
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

  // 10. Validate proof bundle payload structure against PoH schema
  const payloadValidation = validateBundlePayload(envelope.payload);
  if (!payloadValidation.valid) {
    return {
      result: {
        status: 'INVALID',
        reason: `Invalid proof bundle payload: ${payloadValidation.error}`,
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: payloadValidation.error ?? 'Proof bundle payload is missing required fields or has no components',
        field: 'payload',
      },
    };
  }

  // Type assertion after schema validation
  if (!isBundlePayload(envelope.payload)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid proof bundle payload structure',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'Proof bundle payload failed type guard after schema validation',
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

  // CVF-US-022: Enforce envelope signer DID equals payload agent DID
  if (envelope.signer_did !== envelope.payload.agent_did) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Proof bundle signer_did must match payload.agent_did',
        verified_at: now,
      },
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'envelope.signer_did must equal payload.agent_did',
        field: 'signer_did',
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

  // Validate event chain if present (verify hash linkage per POH-US-003)
  if (payload.event_chain !== undefined && payload.event_chain.length > 0) {
    const chainResult = validateEventChain(payload.event_chain);

    if (!chainResult.valid) {
      return {
        result: {
          status: 'INVALID',
          reason: chainResult.error ?? 'Event chain validation failed',
          verified_at: now,
        },
        error: {
          code: 'MALFORMED_ENVELOPE',
          message: chainResult.error ?? 'Invalid event_chain',
          field: 'payload.event_chain',
        },
      };
    }

    // CVF-US-021: Recompute event_hash_b64u from canonical event headers (fail-closed)
    // Canonical header key order per ADAPTER_SPEC_v1 §4.2.
    for (let i = 0; i < payload.event_chain.length; i++) {
      const e = payload.event_chain[i];

      const canonical = {
        event_id: e.event_id,
        run_id: e.run_id,
        event_type: e.event_type,
        timestamp: e.timestamp,
        payload_hash_b64u: e.payload_hash_b64u,
        prev_hash_b64u: e.prev_hash_b64u ?? null,
      };

      let expectedHash: string;
      try {
        expectedHash = await computeHash(canonical, 'SHA-256');
      } catch (err) {
        return {
          result: {
            status: 'INVALID',
            reason: `Event ${i}: event hash recomputation failed`,
            verified_at: now,
          },
          error: {
            code: 'HASH_MISMATCH',
            message: `Failed to recompute event hash: ${err instanceof Error ? err.message : 'unknown error'}`,
            field: `payload.event_chain[${i}]`,
          },
        };
      }

      if (expectedHash !== e.event_hash_b64u) {
        return {
          result: {
            status: 'INVALID',
            reason: `Event ${i}: event_hash_b64u mismatch`,
            verified_at: now,
          },
          error: {
            code: 'HASH_MISMATCH',
            message: 'event_hash_b64u does not match SHA-256 hash of the canonical event header',
            field: `payload.event_chain[${i}].event_hash_b64u`,
          },
        };
      }
    }

    componentResults.event_chain_valid = true;
    if (chainResult.chain_root_hash) {
      componentResults.chain_root_hash = chainResult.chain_root_hash;
    }
  }

  // Verify receipt envelopes cryptographically (POH-US-003)
  // Each receipt is verified with its signer DID (clawproxy DID) using full
  // signature verification — not just structural validation.
  if (payload.receipts !== undefined && payload.receipts.length > 0) {
    // POH-US-010: Require receipts to be bound to this bundle's event chain.
    // Without binding, a signature-valid receipt could be replayed across bundles.
    const bindingContext =
      componentResults.event_chain_valid &&
      payload.event_chain !== undefined &&
      payload.event_chain.length > 0
        ? {
            expectedRunId: payload.event_chain[0].run_id,
            allowedEventHashes: new Set(
              payload.event_chain.map((e) => e.event_hash_b64u)
            ),
          }
        : null;

    const receiptResults = await Promise.all(
      payload.receipts.map((r) =>
        verifyReceiptEnvelope(
          r,
          options.allowlistedReceiptSignerDids,
          bindingContext
        )
      )
    );

    const signatureValidCount = receiptResults.filter(
      (r) => r.signature_valid
    ).length;
    const boundValidCount = receiptResults.filter((r) => r.valid).length;

    componentResults.receipts_valid = boundValidCount === payload.receipts.length;
    componentResults.receipts_count = payload.receipts.length;
    componentResults.receipts_signature_verified_count = signatureValidCount;
    componentResults.receipts_verified_count = boundValidCount;
  }

  // Validate attestations if present
  if (payload.attestations !== undefined && payload.attestations.length > 0) {
    const validAttestations = payload.attestations.filter(validateAttestation);
    componentResults.attestations_valid =
      validAttestations.length === payload.attestations.length;
    componentResults.attestations_count = payload.attestations.length;
  }

  // 16. Compute trust tier based on validated components (POH-US-003)
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
