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
  ProofTier,
  ModelIdentityTier,
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
import { computeModelIdentityTierFromReceipts } from './model-identity';
import { jcsCanonicalize } from './jcs';
import {
  validateProofBundleEnvelopeV1,
  validateUrmV1,
  validatePromptPackV1,
  validateSystemPromptReportV1,
} from './schema-validation';

export interface ProofBundleVerifierOptions {
  /** Allowlisted gateway receipt signer DIDs (did:key:...). */
  allowlistedReceiptSignerDids?: readonly string[];

  /** Allowlisted attester DIDs for proof bundle attestations (did:key:...). */
  allowlistedAttesterDids?: readonly string[];

  /**
   * Optional materialized URM document (JSON object).
   *
   * POH-US-015: If provided, clawverify will:
   * - validate the URM against the strict schema (urm.v1)
   * - hash it (SHA-256 over JSON bytes) and compare to payload.urm.resource_hash_b64u
   *
   * If the proof bundle contains a URM reference but no `urm` is provided,
   * verification fails closed (result.status=INVALID).
   */
  urm?: unknown;
}

// CVF-US-025: size/count hardening
const MAX_EVENT_CHAIN_ENTRIES = 1000;
const MAX_RECEIPTS = 1000;
const MAX_ATTESTATIONS = 100;
const MAX_METADATA_BYTES = 16 * 1024;

function jsonByteSize(value: unknown): number {
  try {
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    return bytes.byteLength;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
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

  // Fail-closed: reject unknown fields (schemas use additionalProperties:false)
  const allowedKeys = new Set([
    'attestation_id',
    'attestation_type',
    'attester_did',
    'subject_did',
    'expires_at',
    'signature_b64u',
  ]);
  for (const k of Object.keys(a)) {
    if (!allowedKeys.has(k)) return false;
  }

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

async function verifyAttestationReference(
  attestation: AttestationReference,
  expectedSubjectDid: string,
  allowlistedAttesterDids: readonly string[] | undefined
): Promise<{
  /** Whether the attestation counts for tier uplift (allowlisted + subject-bound + signature-verified). */
  valid: boolean;
  /** Whether the attestation signature verified (regardless of allowlist/subject binding). */
  signature_valid: boolean;
  /** Whether attester_did is in the allowlist. */
  allowlisted: boolean;
  /** Whether subject_did matches the bundle agent_did. */
  subject_valid: boolean;
  attester_did: string;
  error?: string;
}> {
  const allowlisted =
    Array.isArray(allowlistedAttesterDids) &&
    allowlistedAttesterDids.includes(attestation.attester_did);

  const subjectValid = attestation.subject_did === expectedSubjectDid;

  const pub = extractPublicKeyFromDidKey(attestation.attester_did);
  if (!pub) {
    return {
      valid: false,
      signature_valid: false,
      allowlisted,
      subject_valid: subjectValid,
      attester_did: attestation.attester_did,
      error: 'Unable to extract Ed25519 public key from attester_did (expected did:key with 0xed01 multicodec prefix)',
    };
  }

  let canonical: string;
  try {
    const canonicalObject: AttestationReference = {
      ...attestation,
      signature_b64u: '',
    };
    canonical = jcsCanonicalize(canonicalObject);
  } catch (err) {
    return {
      valid: false,
      signature_valid: false,
      allowlisted,
      subject_valid: subjectValid,
      attester_did: attestation.attester_did,
      error: `Attestation canonicalization failed: ${err instanceof Error ? err.message : 'unknown error'}`,
    };
  }

  let signatureValid = false;
  try {
    const sigBytes = base64UrlDecode(attestation.signature_b64u);
    if (sigBytes.length !== 64) {
      return {
        valid: false,
        signature_valid: false,
        allowlisted,
        subject_valid: subjectValid,
        attester_did: attestation.attester_did,
        error: 'Invalid attestation signature length (expected 64 bytes for Ed25519)',
      };
    }

    const msgBytes = new TextEncoder().encode(canonical);
    signatureValid = await verifySignature('Ed25519', pub, sigBytes, msgBytes);
  } catch (err) {
    return {
      valid: false,
      signature_valid: false,
      allowlisted,
      subject_valid: subjectValid,
      attester_did: attestation.attester_did,
      error: `Attestation signature verification error: ${err instanceof Error ? err.message : 'unknown error'}`,
    };
  }

  const valid = signatureValid && allowlisted && subjectValid;

  if (!signatureValid) {
    return {
      valid: false,
      signature_valid: false,
      allowlisted,
      subject_valid: subjectValid,
      attester_did: attestation.attester_did,
      error: 'Attestation signature verification failed',
    };
  }

  if (!allowlisted) {
    return {
      valid: false,
      signature_valid: true,
      allowlisted,
      subject_valid: subjectValid,
      attester_did: attestation.attester_did,
      error: 'Attester DID is not allowlisted',
    };
  }

  if (!subjectValid) {
    return {
      valid: false,
      signature_valid: true,
      allowlisted,
      subject_valid: subjectValid,
      attester_did: attestation.attester_did,
      error: 'Attestation subject_did does not match proof bundle agent_did',
    };
  }

  return {
    valid,
    signature_valid: signatureValid,
    allowlisted,
    subject_valid: subjectValid,
    attester_did: attestation.attester_did,
  };
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
 * - attested: Valid allowlisted signature-verified attestations
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
 * Compute canonical proof tier (marketplace-facing) based on verified components.
 *
 * NOTE: This is intentionally *not* the same as trust_tier. For example, an
 * event_chain-only bundle may be trust_tier=verified but proof_tier=self.
 */
function computeProofTier(components: {
  envelope_valid: boolean;
  receipts_verified_count?: number;
  attestations_verified_count?: number;
}): ProofTier {
  if (!components.envelope_valid) return 'unknown';

  // Higher tiers win. Proof tiers are based on *at least one* verified component,
  // not on the all-or-nothing `*_valid` booleans.
  if ((components.attestations_verified_count ?? 0) > 0) return 'sandbox';
  if ((components.receipts_verified_count ?? 0) > 0) return 'gateway';

  return 'self';
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

  // 9.75 Strict JSON schema validation (Ajv) for envelope + payload
  // CVF-US-024: Fail closed on schema violations (additionalProperties:false, missing fields, etc.)
  const schemaResult = validateProofBundleEnvelopeV1(envelope);
  if (!schemaResult.valid) {
    return {
      result: {
        status: 'INVALID',
        reason: schemaResult.message,
        verified_at: now,
      },
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: schemaResult.message,
        field: schemaResult.field,
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

  // CVF-US-025: enforce count/size limits and uniqueness constraints (fail-closed)
  const p = envelope.payload;

  if (p.event_chain && p.event_chain.length > MAX_EVENT_CHAIN_ENTRIES) {
    return {
      result: {
        status: 'INVALID',
        reason: `event_chain exceeds max length (${MAX_EVENT_CHAIN_ENTRIES})`,
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: `payload.event_chain length exceeds limit (${MAX_EVENT_CHAIN_ENTRIES})`,
        field: 'payload.event_chain',
      },
    };
  }

  if (p.receipts && p.receipts.length > MAX_RECEIPTS) {
    return {
      result: {
        status: 'INVALID',
        reason: `receipts exceeds max length (${MAX_RECEIPTS})`,
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: `payload.receipts length exceeds limit (${MAX_RECEIPTS})`,
        field: 'payload.receipts',
      },
    };
  }

  if (p.attestations && p.attestations.length > MAX_ATTESTATIONS) {
    return {
      result: {
        status: 'INVALID',
        reason: `attestations exceeds max length (${MAX_ATTESTATIONS})`,
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: `payload.attestations length exceeds limit (${MAX_ATTESTATIONS})`,
        field: 'payload.attestations',
      },
    };
  }

  // Metadata byte-size limits (metadata objects are intentionally flexible; bound size to prevent DoS)
  if (p.metadata && jsonByteSize(p.metadata) > MAX_METADATA_BYTES) {
    return {
      result: {
        status: 'INVALID',
        reason: `payload.metadata exceeds max size (${MAX_METADATA_BYTES} bytes)`,
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: `payload.metadata exceeds max size (${MAX_METADATA_BYTES} bytes)`,
        field: 'payload.metadata',
      },
    };
  }

  if (p.urm?.metadata && jsonByteSize(p.urm.metadata) > MAX_METADATA_BYTES) {
    return {
      result: {
        status: 'INVALID',
        reason: `payload.urm.metadata exceeds max size (${MAX_METADATA_BYTES} bytes)`,
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: `payload.urm.metadata exceeds max size (${MAX_METADATA_BYTES} bytes)`,
        field: 'payload.urm.metadata',
      },
    };
  }

  if (p.receipts) {
    for (let i = 0; i < p.receipts.length; i++) {
      const md = p.receipts[i].payload.metadata;
      if (md !== undefined && jsonByteSize(md) > MAX_METADATA_BYTES) {
        return {
          result: {
            status: 'INVALID',
            reason: `payload.receipts[${i}].payload.metadata exceeds max size (${MAX_METADATA_BYTES} bytes)`,
            verified_at: now,
          },
          error: {
            code: 'MALFORMED_ENVELOPE',
            message: `receipt metadata exceeds max size (${MAX_METADATA_BYTES} bytes)`,
            field: `payload.receipts[${i}].payload.metadata`,
          },
        };
      }
    }
  }

  // Uniqueness constraints within a bundle
  if (p.event_chain) {
    const seenEventIds = new Set<string>();
    for (let i = 0; i < p.event_chain.length; i++) {
      const id = p.event_chain[i].event_id;
      if (seenEventIds.has(id)) {
        return {
          result: {
            status: 'INVALID',
            reason: 'Duplicate event_id in payload.event_chain',
            verified_at: now,
          },
          error: {
            code: 'MALFORMED_ENVELOPE',
            message: 'event_id must be unique within payload.event_chain',
            field: `payload.event_chain[${i}].event_id`,
          },
        };
      }
      seenEventIds.add(id);
    }
  }

  if (p.receipts) {
    const seenReceiptIds = new Set<string>();
    for (let i = 0; i < p.receipts.length; i++) {
      const rid = p.receipts[i].payload.receipt_id;
      if (seenReceiptIds.has(rid)) {
        return {
          result: {
            status: 'INVALID',
            reason: 'Duplicate receipt_id in payload.receipts',
            verified_at: now,
          },
          error: {
            code: 'MALFORMED_ENVELOPE',
            message: 'receipt_id must be unique within payload.receipts',
            field: `payload.receipts[${i}].payload.receipt_id`,
          },
        };
      }
      seenReceiptIds.add(rid);
    }
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

  // CVF-US-016: model identity is an orthogonal axis to PoH tiers.
  let modelIdentityTier: ModelIdentityTier = 'unknown';
  const modelIdentityRiskFlags = new Set<string>();

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

  // POH-US-016/017: Prompt commitments (optional; fail-closed when present)
  //
  // These are *hash-only* objects carried in payload.metadata that commit to:
  // - prompt pack inputs (prompt_pack.prompt_root_hash_b64u)
  // - per-llm_call rendered system prompt hashes (system_prompt_report)
  //
  // They do not uplift proof tier; they are evidence for replay/audit safety.
  let promptPackRootHashB64u: string | null = null;

  const md = payload.metadata;
  const mdRecord = md && typeof md === 'object' && md !== null && !Array.isArray(md)
    ? (md as Record<string, unknown>)
    : null;

  const promptPackRaw = mdRecord ? mdRecord.prompt_pack : undefined;
  if (promptPackRaw !== undefined) {
    const schemaResult = validatePromptPackV1(promptPackRaw);
    if (!schemaResult.valid) {
      return {
        result: {
          status: 'INVALID',
          reason: schemaResult.message,
          verified_at: now,
        },
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: schemaResult.message,
          field: schemaResult.field
            ? `payload.metadata.prompt_pack.${schemaResult.field}`
            : 'payload.metadata.prompt_pack',
        },
      };
    }

    const pp = promptPackRaw as Record<string, unknown>;
    const claimed = typeof pp.prompt_root_hash_b64u === 'string' ? pp.prompt_root_hash_b64u.trim() : null;
    const entries = Array.isArray(pp.entries) ? (pp.entries as unknown[]) : [];

    const canonicalEntries = entries
      .filter((e) => typeof e === 'object' && e !== null && !Array.isArray(e))
      .map((e) => {
        const er = e as Record<string, unknown>;
        return {
          entry_id: typeof er.entry_id === 'string' ? er.entry_id.trim() : '',
          content_hash_b64u: typeof er.content_hash_b64u === 'string' ? er.content_hash_b64u.trim() : '',
        };
      })
      .filter((e) => e.entry_id.length > 0 && e.content_hash_b64u.length > 0)
      .sort((a, b) => a.entry_id.localeCompare(b.entry_id));

    const canonical = {
      prompt_pack_version: '1',
      entries: canonicalEntries,
    };

    let computed: string;
    try {
      computed = await computeHash(canonical, 'SHA-256');
    } catch (err) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Failed to compute prompt_pack root hash',
          verified_at: now,
        },
        error: {
          code: 'HASH_MISMATCH',
          message: `Failed to compute prompt_pack prompt_root_hash_b64u: ${err instanceof Error ? err.message : 'unknown error'}`,
          field: 'payload.metadata.prompt_pack',
        },
      };
    }

    if (!claimed || claimed !== computed) {
      return {
        result: {
          status: 'INVALID',
          reason: 'prompt_pack.prompt_root_hash_b64u mismatch',
          verified_at: now,
        },
        error: {
          code: 'HASH_MISMATCH',
          message: 'prompt_root_hash_b64u does not match canonical entry list hash',
          field: 'payload.metadata.prompt_pack.prompt_root_hash_b64u',
        },
      };
    }

    promptPackRootHashB64u = claimed;
    componentResults.prompt_pack_valid = true;
  }

  const systemPromptReportRaw = mdRecord ? mdRecord.system_prompt_report : undefined;
  if (systemPromptReportRaw !== undefined) {
    const schemaResult = validateSystemPromptReportV1(systemPromptReportRaw);
    if (!schemaResult.valid) {
      return {
        result: {
          status: 'INVALID',
          reason: schemaResult.message,
          verified_at: now,
        },
        error: {
          code: 'SCHEMA_VALIDATION_FAILED',
          message: schemaResult.message,
          field: schemaResult.field
            ? `payload.metadata.system_prompt_report.${schemaResult.field}`
            : 'payload.metadata.system_prompt_report',
        },
      };
    }

    if (!payload.event_chain || payload.event_chain.length === 0) {
      return {
        result: {
          status: 'INVALID',
          reason: 'system_prompt_report requires payload.event_chain',
          verified_at: now,
        },
        error: {
          code: 'MALFORMED_ENVELOPE',
          message: 'payload.event_chain is required when payload.metadata.system_prompt_report is present',
          field: 'payload.event_chain',
        },
      };
    }

    const spr = systemPromptReportRaw as Record<string, unknown>;
    const sprRunId = typeof spr.run_id === 'string' ? spr.run_id.trim() : null;
    const sprAgentDid = typeof spr.agent_did === 'string' ? spr.agent_did.trim() : null;
    const expectedRunId = payload.event_chain[0].run_id;

    if (!sprRunId || sprRunId !== expectedRunId) {
      return {
        result: {
          status: 'INVALID',
          reason: 'system_prompt_report.run_id mismatch',
          verified_at: now,
        },
        error: {
          code: 'PROMPT_COMMITMENT_MISMATCH',
          message: 'system_prompt_report.run_id must equal payload.event_chain[0].run_id',
          field: 'payload.metadata.system_prompt_report.run_id',
        },
      };
    }

    if (!sprAgentDid || sprAgentDid !== payload.agent_did) {
      return {
        result: {
          status: 'INVALID',
          reason: 'system_prompt_report.agent_did mismatch',
          verified_at: now,
        },
        error: {
          code: 'PROMPT_COMMITMENT_MISMATCH',
          message: 'system_prompt_report.agent_did must equal payload.agent_did',
          field: 'payload.metadata.system_prompt_report.agent_did',
        },
      };
    }

    const sprPromptRoot = typeof spr.prompt_root_hash_b64u === 'string' ? spr.prompt_root_hash_b64u.trim() : null;
    if (promptPackRootHashB64u && sprPromptRoot && sprPromptRoot !== promptPackRootHashB64u) {
      return {
        result: {
          status: 'INVALID',
          reason: 'system_prompt_report.prompt_root_hash_b64u mismatch',
          verified_at: now,
        },
        error: {
          code: 'PROMPT_COMMITMENT_MISMATCH',
          message: 'system_prompt_report.prompt_root_hash_b64u must match prompt_pack.prompt_root_hash_b64u (when both present)',
          field: 'payload.metadata.system_prompt_report.prompt_root_hash_b64u',
        },
      };
    }

    const eventsById = new Map(payload.event_chain.map((e) => [e.event_id, e]));
    const calls = Array.isArray(spr.calls) ? (spr.calls as unknown[]) : [];

    for (let i = 0; i < calls.length; i++) {
      const c = calls[i];
      if (typeof c !== 'object' || c === null || Array.isArray(c)) continue;
      const cr = c as Record<string, unknown>;

      const eventId = typeof cr.event_id === 'string' ? cr.event_id.trim() : null;
      if (!eventId) continue;

      const evt = eventsById.get(eventId);
      if (!evt) {
        return {
          result: {
            status: 'INVALID',
            reason: 'system_prompt_report references unknown event_id',
            verified_at: now,
          },
          error: {
            code: 'PROMPT_COMMITMENT_MISMATCH',
            message: 'system_prompt_report.calls[*].event_id must refer to an event in payload.event_chain',
            field: `payload.metadata.system_prompt_report.calls[${i}].event_id`,
          },
        };
      }

      if (evt.event_type !== 'llm_call') {
        return {
          result: {
            status: 'INVALID',
            reason: 'system_prompt_report references a non-llm_call event',
            verified_at: now,
          },
          error: {
            code: 'PROMPT_COMMITMENT_MISMATCH',
            message: 'system_prompt_report.calls[*] must reference llm_call events',
            field: `payload.metadata.system_prompt_report.calls[${i}].event_id`,
          },
        };
      }

      const claimedEventHash = typeof cr.event_hash_b64u === 'string' ? cr.event_hash_b64u.trim() : null;
      if (claimedEventHash && claimedEventHash !== evt.event_hash_b64u) {
        return {
          result: {
            status: 'INVALID',
            reason: 'system_prompt_report event_hash_b64u mismatch',
            verified_at: now,
          },
          error: {
            code: 'PROMPT_COMMITMENT_MISMATCH',
            message: 'system_prompt_report.calls[*].event_hash_b64u must match payload.event_chain[event_id].event_hash_b64u',
            field: `payload.metadata.system_prompt_report.calls[${i}].event_hash_b64u`,
          },
        };
      }
    }

    componentResults.system_prompt_report_valid = true;
  }

  // POH-US-015: URM materialization + hash verification.
  // Proof bundles carry only a URM *reference* (hash). To make that meaningful,
  // callers may provide the materialized URM document bytes (as a JSON object).
  //
  // Fail-closed semantics:
  // - If URM reference is present but URM bytes are not provided, the bundle is INVALID.
  // - If URM bytes are provided but fail schema validation, binding checks, or hash verification,
  //   the bundle is INVALID.
  if (payload.urm !== undefined) {
    if (!validateURM(payload.urm)) {
      componentResults.urm_valid = false;
    } else if (options.urm === undefined) {
      return {
        result: {
          status: 'INVALID',
          reason: 'URM document is required when payload.urm is present',
          verified_at: now,
        },
        error: {
          code: 'URM_MISSING',
          message: 'Missing URM document (provide request field: urm)',
          field: 'urm',
        },
      };
    } else {
      const ref = payload.urm as URMReference;

      const schemaResult = validateUrmV1(options.urm);
      if (!schemaResult.valid) {
        return {
          result: {
            status: 'INVALID',
            reason: schemaResult.message,
            verified_at: now,
          },
          error: {
            code: 'SCHEMA_VALIDATION_FAILED',
            message: schemaResult.message,
            field: schemaResult.field ? `urm.${schemaResult.field}` : 'urm',
          },
        };
      }

      const u = options.urm as Record<string, unknown>;

      // Binding checks (fail-closed): URM must describe the same run/agent.
      const urmId = typeof u.urm_id === 'string' ? u.urm_id.trim() : null;
      const agentDid = typeof u.agent_did === 'string' ? u.agent_did.trim() : null;
      const runId = typeof u.run_id === 'string' ? u.run_id.trim() : null;

      if (!urmId || urmId !== ref.urm_id) {
        return {
          result: {
            status: 'INVALID',
            reason: 'URM urm_id does not match proof bundle URM reference',
            verified_at: now,
          },
          error: {
            code: 'URM_MISMATCH',
            message: 'urm.urm_id must equal payload.urm.urm_id',
            field: 'urm.urm_id',
          },
        };
      }

      if (!agentDid || agentDid !== payload.agent_did) {
        return {
          result: {
            status: 'INVALID',
            reason: 'URM agent_did does not match proof bundle agent_did',
            verified_at: now,
          },
          error: {
            code: 'URM_MISMATCH',
            message: 'urm.agent_did must equal payload.agent_did',
            field: 'urm.agent_did',
          },
        };
      }

      if (componentResults.event_chain_valid && payload.event_chain && payload.event_chain.length > 0) {
        const expectedRunId = payload.event_chain[0].run_id;
        if (!runId || runId !== expectedRunId) {
          return {
            result: {
              status: 'INVALID',
              reason: 'URM run_id does not match proof bundle run_id',
              verified_at: now,
            },
            error: {
              code: 'URM_MISMATCH',
              message: 'urm.run_id must equal payload.event_chain[0].run_id',
              field: 'urm.run_id',
            },
          };
        }

        const chainRoot = componentResults.chain_root_hash;
        const claimedRoot = typeof u.event_chain_root_hash_b64u === 'string' ? u.event_chain_root_hash_b64u.trim() : null;
        if (chainRoot && claimedRoot && claimedRoot !== chainRoot) {
          return {
            result: {
              status: 'INVALID',
              reason: 'URM event_chain_root_hash_b64u does not match proof bundle event chain root',
              verified_at: now,
            },
            error: {
              code: 'URM_MISMATCH',
              message: 'urm.event_chain_root_hash_b64u must match the proof bundle event chain root hash',
              field: 'urm.event_chain_root_hash_b64u',
            },
          };
        }
      }

      let computedUrmHash: string;
      try {
        computedUrmHash = await computeHash(options.urm, 'SHA-256');
      } catch (err) {
        return {
          result: {
            status: 'INVALID',
            reason: 'Failed to hash URM document',
            verified_at: now,
          },
          error: {
            code: 'HASH_MISMATCH',
            message: `Failed to compute URM hash: ${err instanceof Error ? err.message : 'unknown error'}`,
            field: 'urm',
          },
        };
      }

      if (computedUrmHash !== ref.resource_hash_b64u) {
        return {
          result: {
            status: 'INVALID',
            reason: 'URM hash mismatch',
            verified_at: now,
          },
          error: {
            code: 'HASH_MISMATCH',
            message: 'Computed URM hash does not match payload.urm.resource_hash_b64u',
            field: 'payload.urm.resource_hash_b64u',
          },
        };
      }

      componentResults.urm_valid = true;
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

    // CVF-US-016: Extract + verify model identity and compute an overall tier.
    try {
      const modelIdentity = await computeModelIdentityTierFromReceipts({
        receipts: payload.receipts,
        receiptResults,
      });
      modelIdentityTier = modelIdentity.model_identity_tier;
      for (const f of modelIdentity.risk_flags) modelIdentityRiskFlags.add(f);
    } catch {
      modelIdentityTier = 'unknown';
      modelIdentityRiskFlags.add('MODEL_IDENTITY_VERIFY_FAILED');
    }
  }

  // Validate + verify attestations if present
  // CVF-US-023: Attestations MUST be signature-verified AND attester_did allowlisted
  //             before they can uplift trust tier.
  if (payload.attestations !== undefined && payload.attestations.length > 0) {
    const attestationResults = await Promise.all(
      payload.attestations.map(async (a) => {
        if (!validateAttestation(a)) {
          return {
            valid: false,
            signature_valid: false,
          };
        }

        return verifyAttestationReference(
          a,
          payload.agent_did,
          options.allowlistedAttesterDids
        );
      })
    );

    const signatureVerifiedCount = attestationResults.filter(
      (r) => r.signature_valid
    ).length;
    const verifiedCount = attestationResults.filter((r) => r.valid).length;

    componentResults.attestations_count = payload.attestations.length;
    componentResults.attestations_signature_verified_count = signatureVerifiedCount;
    componentResults.attestations_verified_count = verifiedCount;

    // Strict: all attestations must verify to count this component as valid.
    componentResults.attestations_valid = verifiedCount === payload.attestations.length;
  }

  // 16. Compute tiers based on validated components
  const trustTier = computeTrustTier(componentResults);
  const proofTier = computeProofTier(componentResults);

  // 17. Return success with computed tiers
  return {
    result: {
      status: 'VALID',
      reason: 'Proof bundle verified successfully',
      verified_at: now,
      bundle_id: payload.bundle_id,
      agent_did: payload.agent_did,
      trust_tier: trustTier,
      proof_tier: proofTier,
      model_identity_tier: modelIdentityTier,
      risk_flags:
        modelIdentityRiskFlags.size > 0
          ? [...modelIdentityRiskFlags].sort()
          : undefined,
      component_results: componentResults,
    },
  };
}
