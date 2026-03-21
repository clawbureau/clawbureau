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
  RateLimitClaim,
  SideEffectReceiptPayload,
  HumanApprovalReceiptPayload,
  TrustTier,
  ProofTier,
  ModelIdentityTier,
  URMReference,
  AttestationReference,
  GatewayReceiptPayload,
  VirReceiptPayload,
  VirReceiptEnvelope,
  VirSource,
  WebReceiptPayload,
  CoverageAttestationPayload,
  ExecutionAttestationPayload,
  X402BindingReasonCode,
  EgressPolicyReceiptPayload,
  PolicyBindingMetadata,
  RunnerMeasurementBindingMetadata,
  RunnerAttestationReceiptPayload,
  SignedPolicyBundlePayload,
  SignedPolicyLayer,
  SignedPolicyStatement,
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
import { verifyReceipt } from './verify-receipt';
import { verifyWebReceipt } from './verify-web-receipt';
import { verifyCoverageAttestation } from './verify-coverage-attestation';
import {
  verifyBinarySemanticEvidence,
  evaluateBinarySemanticEvidencePolicy,
  compareBinarySemanticPolicyResult,
  isBinarySemanticFailClosedVerdict,
  isBinarySemanticConstrainedVerdict,
  verificationFailureToPolicyResult,
  type BinarySemanticPolicyResult,
} from './verify-binary-semantic-evidence';
import {
  evaluateCompletenessPolicy,
  isCompletenessConstrainedVerdict,
  isCompletenessFailClosedVerdict,
} from './verify-completeness';
import { inspectX402Claim } from './x402-binding';
import { verifyExecutionAttestation } from './verify-execution-attestation';
import { verifyLogInclusionProof } from './verify-log-inclusion-proof';
import { computeModelIdentityTierFromReceipts } from './model-identity';
import { jcsCanonicalize } from './jcs';
import {
  CRITICAL_VIR_CODES,
  compareVirCandidate,
  classifyVirConflictSeverity,
  mergeVirConflictSeverity,
  type VirConflictSeverity,
  type VirFailureCode,
  validateVirReceiptCore,
} from './vir-core';
import {
  validateProofBundleEnvelopeV1,
  validateUrmV1,
  validatePromptPackV1,
  validateSystemPromptReportV1,
  validateVirV1,
  validateVirV2,
  validateVirEnvelopeV1,
  validateVirEnvelopeV2,
  validateCoverageAttestationEnvelopeV1,
} from './schema-validation';

export interface ProofBundleVerifierOptions {
  /** Allowlisted gateway receipt signer DIDs (did:key:...). */
  allowlistedReceiptSignerDids?: readonly string[];

  /** Allowlisted witness signer DIDs for web_receipts (did:key:...). */
  allowlistedWitnessSignerDids?: readonly string[];

  /** Witnessed-web policy mode: warn/degrade (default) or strict INVALID. */
  witnessed_web_policy_mode?: 'warn' | 'enforce';

  /** Optional witnessed-web quorum policy (m-of-n) scoped per run_id + event_hash. */
  witnessed_web_quorum_m?: number;
  witnessed_web_quorum_n?: number;

  /** Witnessed-web transparency policy mode. */
  witnessed_web_transparency_mode?: 'optional' | 'warn' | 'enforce';

  /** Require transparency anchoring only at/after this receipt timestamp (ISO-8601 UTC). */
  witnessed_web_transparency_required_after?: string;

  /** Allowlisted attester DIDs for proof bundle attestations (did:key:...). */
  allowlistedAttesterDids?: readonly string[];

  /** Allowlisted signer DIDs for coverage attestations (did:key:...). */
  allowlistedCoverageAttestationSignerDids?: readonly string[];

  /** Allowlisted signer DIDs for binary semantic evidence attestations (did:key:...). */
  allowlistedBinarySemanticEvidenceSignerDids?: readonly string[];

  /** Phase gate for deterministic coverage invariants. Defaults to 'observe'. */
  coverage_enforcement_phase?: 'observe' | 'warn' | 'enforce';

  /** Causal graph connectivity/orphan enforcement mode. Defaults to 'enforce'. */
  causal_connectivity_mode?: 'observe' | 'warn' | 'enforce';

  /**
   * Causal policy profile for anti-downgrade enforcement.
   * - compat: preserve legacy option override behavior.
   * - strict: lock causal-relevant enforcement modes to enforce.
   */
  causal_policy_profile?: 'compat' | 'strict';

  /** Optional strict VIR binding checks (non-transferability). */
  expectedVirNonce?: string;
  expectedVirSubject?: string;
  expectedVirScope?: string;

  /** VIR conflict resolver policy. `strict` fail-closes on high/critical conflict; `cap` demotes to low-trust source. */
  vir_conflict_policy_mode?: 'strict' | 'cap';

  /** Maximum tolerated timestamp skew (ms) when correlating VIR claims to allowlisted gateway receipts. */
  maxVirCorroborationSkewMs?: number;

  /** Optional execution attestations bound to this bundle. */
  execution_attestations?: SignedEnvelope<ExecutionAttestationPayload>[];

  /** Allowlisted execution attestation signer DIDs (did:key:...). */
  allowlistedExecutionAttestationSignerDids?: readonly string[];

  /** Allowlisted TEE roots/TCB versions for tee_execution attestations. */
  teeRootAllowlist?: readonly string[];
  teeTcbAllowlist?: readonly string[];

  /** Revocation denylist for TEE roots/TCB versions. */
  teeRootRevoked?: readonly string[];
  teeTcbRevoked?: readonly string[];

  /** Max tolerated coverage liveness gap in milliseconds (default 1000). */
  maxCoverageLivenessGapMs?: number;

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

  /**
   * PRV-EGR-003: require signed egress policy receipt evidence.
   * When true, missing or malformed payload.metadata.sentinels.egress_policy_receipt
   * fails closed.
   */
  requireEgressPolicyReceipt?: boolean;
}

// CVF-US-025: size/count hardening
const MAX_EVENT_CHAIN_ENTRIES = 1000;
const MAX_RECEIPTS = 1000;
const MAX_ATTESTATIONS = 100;
const MAX_METADATA_BYTES = 16 * 1024;

const DEFAULT_VIR_CORROBORATION_MAX_SKEW_MS = 5 * 60 * 1000;
const HIGH_CLAIM_VIR_SOURCES = new Set<VirSource>([
  'tls_decrypt',
  'gateway',
  'interpose',
]);

type WitnessedWebPolicyMode = 'warn' | 'enforce';
type WitnessedWebTransparencyMode = 'optional' | 'warn' | 'enforce';

function jsonByteSize(value: unknown): number {
  try {
    const bytes = new TextEncoder().encode(JSON.stringify(value));
    return bytes.byteLength;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}

function classifyCausalSchemaValidationCode(
  field: string | undefined
):
  | 'CAUSAL_PHASE_INVALID'
  | 'CAUSAL_CONFIDENCE_OUT_OF_RANGE'
  | 'CAUSAL_BINDING_NORMALIZATION_FAILED'
  | null {
  if (!field) return null;

  if (/(^|\.)binding\.phase(\.|$|\[)/.test(field)) {
    return 'CAUSAL_PHASE_INVALID';
  }

  if (/(^|\.)binding\.(attribution_confidence|attributionConfidence)(\.|$|\[)/.test(field)) {
    return 'CAUSAL_CONFIDENCE_OUT_OF_RANGE';
  }

  if (
    /(^|\.)binding\.(span_id|spanId|parent_span_id|parentSpanId|tool_span_id|toolSpanId)(\.|$|\[)/.test(
      field
    )
  ) {
    return 'CAUSAL_BINDING_NORMALIZATION_FAILED';
  }

  return null;
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
  const virReceipts = p.vir_receipts;
  const hasVirReceipts = Array.isArray(virReceipts) && virReceipts.length > 0;
  const webReceipts = p.web_receipts;
  const hasWebReceipts = Array.isArray(webReceipts) && webReceipts.length > 0;
  const binarySemanticEvidence = p.binary_semantic_evidence_attestations;
  const hasBinarySemanticEvidence =
    Array.isArray(binarySemanticEvidence) && binarySemanticEvidence.length > 0;

  if (
    !hasUrm &&
    !hasEventChain &&
    !hasReceipts &&
    !hasAttestations &&
    !hasVirReceipts &&
    !hasWebReceipts &&
    !hasBinarySemanticEvidence
  ) {
    return {
      valid: false,
      error:
        'At least one of urm, event_chain, receipts, attestations, vir_receipts, web_receipts, or binary_semantic_evidence_attestations is required',
    };
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
    const eventValue = events[i];
    if (!isObjectRecord(eventValue)) {
      return { valid: false, error: `Event ${i}: must be an object` };
    }
    const event = eventValue;

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

function hasFiniteNonNegativeNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function validateRateLimitClaims(
  claims: RateLimitClaim[],
  expectedRunId: string | null
):
  | { ok: true }
  | {
      ok: false;
      code:
        | 'RATE_LIMIT_WINDOW_INVALID'
        | 'RATE_LIMIT_CLAIM_INCONSISTENT'
        | 'RATE_LIMIT_EXCEEDED';
      message: string;
      field: string;
    } {
  for (let i = 0; i < claims.length; i++) {
    const c = claims[i];

    const windowStartMs = Date.parse(c.window_start);
    const windowEndMs = Date.parse(c.window_end);
    if (!Number.isFinite(windowStartMs) || !Number.isFinite(windowEndMs)) {
      return {
        ok: false,
        code: 'RATE_LIMIT_CLAIM_INCONSISTENT',
        message: 'rate_limit_claim window_start/window_end must be valid ISO-8601 timestamps',
        field: `rate_limit_claims[${i}]`,
      };
    }

    if (windowStartMs > windowEndMs) {
      return {
        ok: false,
        code: 'RATE_LIMIT_WINDOW_INVALID',
        message: 'rate_limit_claim window_start must be less than or equal to window_end',
        field: `rate_limit_claims[${i}].window_start`,
      };
    }

    if (
      !hasFiniteNonNegativeNumber(c.max_requests) ||
      !hasFiniteNonNegativeNumber(c.observed_requests)
    ) {
      return {
        ok: false,
        code: 'RATE_LIMIT_CLAIM_INCONSISTENT',
        message: 'rate_limit_claim max_requests and observed_requests must be finite non-negative numbers',
        field: `rate_limit_claims[${i}]`,
      };
    }

    if (c.observed_requests > c.max_requests) {
      return {
        ok: false,
        code: 'RATE_LIMIT_EXCEEDED',
        message: 'rate_limit_claim observed_requests exceeds max_requests',
        field: `rate_limit_claims[${i}].observed_requests`,
      };
    }

    const pairs: Array<
      [
        max: number | undefined,
        observed: number | undefined,
        label: 'tokens_input' | 'tokens_output'
      ]
    > = [
      [c.max_tokens_input, c.observed_tokens_input, 'tokens_input'],
      [c.max_tokens_output, c.observed_tokens_output, 'tokens_output'],
    ];

    for (const [max, observed, label] of pairs) {
      const maxSet = max !== undefined;
      const observedSet = observed !== undefined;

      if (maxSet !== observedSet) {
        return {
          ok: false,
          code: 'RATE_LIMIT_CLAIM_INCONSISTENT',
          message: `rate_limit_claim max_${label} and observed_${label} must be provided together`,
          field: `rate_limit_claims[${i}]`,
        };
      }

      if (!maxSet || !observedSet) continue;

      if (!hasFiniteNonNegativeNumber(max) || !hasFiniteNonNegativeNumber(observed)) {
        return {
          ok: false,
          code: 'RATE_LIMIT_CLAIM_INCONSISTENT',
          message: `rate_limit_claim max_${label} and observed_${label} must be finite non-negative numbers`,
          field: `rate_limit_claims[${i}]`,
        };
      }

      if (observed > max) {
        return {
          ok: false,
          code: 'RATE_LIMIT_EXCEEDED',
          message: `rate_limit_claim observed_${label} exceeds max_${label}`,
          field: `rate_limit_claims[${i}].observed_${label}`,
        };
      }
    }

    if (
      expectedRunId !== null &&
      c.run_id !== undefined &&
      c.run_id !== expectedRunId
    ) {
      return {
        ok: false,
        code: 'RATE_LIMIT_CLAIM_INCONSISTENT',
        message: 'rate_limit_claim run_id does not match proof bundle run_id',
        field: `rate_limit_claims[${i}].run_id`,
      };
    }
  }

  return { ok: true };
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
  expectedChainRootHash: string;
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
  /** Whether this receipt claims x402 payment metadata. */
  x402_claimed: boolean;
  /** Deterministic x402 reason code for this receipt path. */
  x402_reason_code?: X402BindingReasonCode;
  /** Claimed x402 payment auth hash (if present). */
  x402_payment_auth_hash_b64u?: string;
  provider?: string;
  model?: string;
  gateway_id?: string;
  signer_did?: string;
  error?: string;
}> {
  const envelopePayload =
    typeof receipt === 'object' &&
    receipt !== null &&
    'payload' in (receipt as Record<string, unknown>)
      ? (receipt as { payload: unknown }).payload
      : undefined;

  const x402Inspection = inspectX402Claim(envelopePayload);

  const verification = await verifyReceipt(receipt, { allowlistedSignerDids });

  if (verification.result.status !== 'VALID') {
    return {
      valid: false,
      signature_valid: false,
      binding_valid: false,
      x402_claimed: x402Inspection.claimed,
      x402_reason_code: verification.x402_reason_code,
      x402_payment_auth_hash_b64u: x402Inspection.payment_auth_hash_b64u,
      error: verification.error?.message ?? verification.result.reason,
    };
  }

  const x402BindingMismatchCode = x402Inspection.claimed
    ? ('X402_EXECUTION_BINDING_MISMATCH' as const)
    : verification.x402_reason_code;

  if (!bindingContext) {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      x402_claimed: x402Inspection.claimed,
      x402_reason_code: x402BindingMismatchCode,
      x402_payment_auth_hash_b64u: x402Inspection.payment_auth_hash_b64u,
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
      x402_claimed: x402Inspection.claimed,
      x402_reason_code: x402BindingMismatchCode,
      x402_payment_auth_hash_b64u: x402Inspection.payment_auth_hash_b64u,
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
      x402_claimed: x402Inspection.claimed,
      x402_reason_code: x402BindingMismatchCode,
      x402_payment_auth_hash_b64u: x402Inspection.payment_auth_hash_b64u,
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
      x402_claimed: x402Inspection.claimed,
      x402_reason_code: x402BindingMismatchCode,
      x402_payment_auth_hash_b64u: x402Inspection.payment_auth_hash_b64u,
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
      x402_claimed: x402Inspection.claimed,
      x402_reason_code: x402BindingMismatchCode,
      x402_payment_auth_hash_b64u: x402Inspection.payment_auth_hash_b64u,
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
      x402_claimed: x402Inspection.claimed,
      x402_reason_code: x402BindingMismatchCode,
      x402_payment_auth_hash_b64u: x402Inspection.payment_auth_hash_b64u,
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
    x402_claimed: x402Inspection.claimed,
    x402_reason_code: verification.x402_reason_code,
    x402_payment_auth_hash_b64u: x402Inspection.payment_auth_hash_b64u,
    provider: verification.provider,
    model: verification.model,
    gateway_id: verification.gateway_id,
    signer_did: verification.result.signer_did,
  };
}

async function verifyWebReceiptEnvelope(
  receipt: unknown,
  allowlistedSignerDids: readonly string[] | undefined,
  bindingContext: ReceiptBindingContext | null
): Promise<{
  valid: boolean;
  signature_valid: boolean;
  binding_valid: boolean;
  witness_id?: string;
  source?: WebReceiptPayload['source'];
  signer_did?: string;
  error?: string;
}> {
  const verification = await verifyWebReceipt(receipt, { allowlistedSignerDids });

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
      witness_id: verification.witness_id,
      source: verification.source,
      signer_did: verification.result.signer_did,
      error:
        'Web receipt binding cannot be verified: proof bundle event_chain is missing or invalid',
    };
  }

  const env = receipt as SignedEnvelope<WebReceiptPayload>;
  const binding = env.payload.binding;

  if (!binding || typeof binding !== 'object') {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      witness_id: verification.witness_id,
      source: verification.source,
      signer_did: verification.result.signer_did,
      error: 'Web receipt is missing binding (expected run_id + event_hash_b64u)',
    };
  }

  const runId = (binding as Record<string, unknown>).run_id;
  const eventHash = (binding as Record<string, unknown>).event_hash_b64u;

  if (typeof runId !== 'string' || runId.trim().length === 0) {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      witness_id: verification.witness_id,
      source: verification.source,
      signer_did: verification.result.signer_did,
      error: 'Web receipt binding.run_id is missing or invalid',
    };
  }

  if (runId !== bindingContext.expectedRunId) {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      witness_id: verification.witness_id,
      source: verification.source,
      signer_did: verification.result.signer_did,
      error: 'Web receipt binding.run_id does not match proof bundle run_id',
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
      witness_id: verification.witness_id,
      source: verification.source,
      signer_did: verification.result.signer_did,
      error: 'Web receipt binding.event_hash_b64u is missing or invalid',
    };
  }

  if (!bindingContext.allowedEventHashes.has(eventHash)) {
    return {
      valid: false,
      signature_valid: true,
      binding_valid: false,
      witness_id: verification.witness_id,
      source: verification.source,
      signer_did: verification.result.signer_did,
      error:
        'Web receipt binding.event_hash_b64u does not reference an event in the proof bundle event chain',
    };
  }

  return {
    valid: true,
    signature_valid: true,
    binding_valid: true,
    witness_id: verification.witness_id,
    source: verification.source,
    signer_did: verification.result.signer_did,
  };
}

async function verifyCoverageAttestationEnvelope(
  attestation: unknown,
  allowlistedSignerDids: readonly string[] | undefined,
  bindingContext: ReceiptBindingContext | null,
  expectedAgentDid: string,
  maxLivenessGapMs: number,
): Promise<{
  valid: boolean;
  signature_valid: boolean;
  binding_valid: boolean;
  invariants_valid: boolean;
  signer_did?: string;
  sentinel_did?: string;
  error?: string;
  risk_flags?: string[];
  cldd_metrics?: ClddMetrics;
}> {
  const verification = await verifyCoverageAttestation(attestation, {
    allowlistedSignerDids,
  });

  if (verification.result.status !== 'VALID') {
    return {
      valid: false,
      signature_valid: false,
      binding_valid: false,
      invariants_valid: false,
      signer_did: verification.signer_did,
      sentinel_did: verification.sentinel_did,
      error: verification.error?.message ?? verification.result.reason,
      risk_flags: ['COVERAGE_ATTESTATION_VERIFY_FAILED'],
    };
  }

  const riskFlags: string[] = [];

  let bindingValid = true;
  if (verification.agent_did !== expectedAgentDid) {
    bindingValid = false;
    riskFlags.push('COVERAGE_ATTESTATION_AGENT_MISMATCH');
  }

  if (!bindingContext) {
    bindingValid = false;
    riskFlags.push('COVERAGE_ATTESTATION_BINDING_CONTEXT_MISSING');
  } else {
    if (verification.run_id !== bindingContext.expectedRunId) {
      bindingValid = false;
      riskFlags.push('COVERAGE_ATTESTATION_RUN_ID_MISMATCH');
    }

    if (
      verification.event_chain_root_hash_b64u !==
      bindingContext.expectedChainRootHash
    ) {
      bindingValid = false;
      riskFlags.push('COVERAGE_ATTESTATION_CHAIN_ROOT_MISMATCH');
    }
  }

  const metrics = verification.metrics;
  let invariantsValid = true;

  if (!metrics) {
    invariantsValid = false;
    riskFlags.push('COVERAGE_ATTESTATION_METRICS_MISSING');
  } else {
    if (metrics.lineage.unmonitored_spawns > 0) {
      invariantsValid = false;
      riskFlags.push('COVERAGE_UNMONITORED_SPAWNS');
    }

    if (metrics.lineage.escapes_suspected) {
      invariantsValid = false;
      riskFlags.push('COVERAGE_ESCAPES_SUSPECTED');
    }

    if (metrics.egress.unmediated_connections > 0) {
      invariantsValid = false;
      riskFlags.push('COVERAGE_UNMEDIATED_EGRESS');
    }

    if (metrics.liveness.status !== 'continuous') {
      invariantsValid = false;
      riskFlags.push('COVERAGE_LIVENESS_INTERRUPTED');
    }

    if (metrics.liveness.max_gap_ms > maxLivenessGapMs) {
      invariantsValid = false;
      riskFlags.push('COVERAGE_LIVENESS_GAP_EXCEEDED');
    }
  }

  return {
    valid: bindingValid && invariantsValid,
    signature_valid: true,
    binding_valid: bindingValid,
    invariants_valid: invariantsValid,
    signer_did: verification.signer_did,
    sentinel_did: verification.sentinel_did,
    error:
      bindingValid && invariantsValid
        ? undefined
        : 'Coverage attestation failed bundle binding or coverage invariants',
    risk_flags: riskFlags.length > 0 ? riskFlags : undefined,
    cldd_metrics: metrics
      ? {
          unmediated_connections: metrics.egress.unmediated_connections,
          unmonitored_spawns: metrics.lineage.unmonitored_spawns,
          escapes_suspected: metrics.lineage.escapes_suspected,
        }
      : undefined,
  };
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isIsoDate(value: unknown): value is string {
  return isValidIsoDate(value);
}

function isBase64Url(value: unknown): value is string {
  return isValidBase64Url(value);
}

interface ClddMetrics {
  unmediated_connections: number;
  unmonitored_spawns: number;
  escapes_suspected: boolean;
}

interface ProcessorPolicyEvidenceRoute {
  provider: string;
  model: string;
  region: string;
  retention_profile: string;
  count: number;
}

interface ProcessorPolicyEvidenceAttemptRoute {
  provider: string;
  model: string;
  region: string;
  retention_profile: string;
}

interface ProcessorPolicyEvidenceBlockedAttempt {
  route: ProcessorPolicyEvidenceAttemptRoute;
  reason_code: string;
  timestamp: string;
}

interface ProcessorPolicyEvidenceConstraints {
  allowed_providers: string[];
  allowed_models: string[];
  allowed_regions: string[];
  allowed_retention_profiles: string[];
  default_region: string;
  default_retention_profile: string;
}

interface ProcessorPolicyEvidenceBinding {
  run_id: string;
  event_chain_root_hash_b64u?: string;
}

interface ProcessorPolicyEvidence {
  receipt_version: '1';
  receipt_type: 'processor_policy';
  policy_version: string;
  profile_id: string;
  policy_hash_b64u: string;
  enforce: boolean;
  binding: ProcessorPolicyEvidenceBinding;
  constraints: ProcessorPolicyEvidenceConstraints;
  counters: {
    allowed_routes: number;
    denied_routes: number;
  };
  used_processors: ProcessorPolicyEvidenceRoute[];
  blocked_attempts: ProcessorPolicyEvidenceBlockedAttempt[];
}

type DataHandlingAction = 'allow' | 'redact' | 'block' | 'require_approval';

const DLP_POLICY_VERSION = 'prv.dlp.v1' as const;
const DLP_TAXONOMY_VERSION = 'prv.dlp.taxonomy.v2' as const;
const DLP_CLASS_ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const DLP_RULE_ID_PATTERN = /^[A-Za-z0-9._:-]+$/;
const DLP_CUSTOM_RULE_ID_PATTERN =
  /^prv\.dlp\.custom\.([a-z0-9]+(?:[._-][a-z0-9]+)*)\.[A-Za-z0-9_-]{8,}\.v[0-9]+$/;

interface DataHandlingPolicyEvidence {
  taxonomy_version: typeof DLP_TAXONOMY_VERSION;
  ruleset_hash_b64u: string;
  built_in_rule_count: number;
  custom_rule_count: number;
}

interface DataHandlingClassMatch {
  class_id: string;
  rule_id: string;
  action: DataHandlingAction;
  match_count: number;
}

interface DataHandlingReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  policy_version: typeof DLP_POLICY_VERSION;
  effective_policy_hash_b64u: string;
  policy?: DataHandlingPolicyEvidence;
  run_id: string;
  provider: string;
  action: DataHandlingAction;
  reason_code: string;
  classes: DataHandlingClassMatch[];
  approval: {
    required: boolean;
    satisfied: boolean;
    mechanism: 'signed_receipt';
    scope_hash_b64u: string | null;
    receipt_hash_b64u: string | null;
    receipt_signer_did: string | null;
    receipt_envelope: SignedEnvelope<Record<string, unknown>> | null;
  };
  redaction: {
    applied: boolean;
    original_payload_hash_b64u: string;
    outbound_payload_hash_b64u: string | null;
  };
  timestamp: string;
}

interface DataHandlingApprovalScope {
  scope_version: 'prv.dlp.approval_scope.v1';
  provider: string;
  policy_version: 'prv.dlp.v1';
  effective_policy_hash_b64u: string;
  class_ids: string[];
}

function isDataHandlingAction(value: unknown): value is DataHandlingAction {
  return (
    value === 'allow' ||
    value === 'redact' ||
    value === 'block' ||
    value === 'require_approval'
  );
}

function dataHandlingPoliciesEqual(
  left: DataHandlingPolicyEvidence,
  right: DataHandlingPolicyEvidence,
): boolean {
  return (
    left.taxonomy_version === right.taxonomy_version &&
    left.ruleset_hash_b64u === right.ruleset_hash_b64u &&
    left.built_in_rule_count === right.built_in_rule_count &&
    left.custom_rule_count === right.custom_rule_count
  );
}

function validateDataHandlingPolicyEvidence(args: {
  value: unknown;
  field: string;
}):
  | { ok: true; value: DataHandlingPolicyEvidence }
  | { ok: false; code: VerificationError['code']; message: string; field: string } {
  if (!isObjectRecord(args.value)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `${args.field} must be an object`,
      field: args.field,
    };
  }

  const policy = args.value;
  if (policy.taxonomy_version !== DLP_TAXONOMY_VERSION) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `${args.field}.taxonomy_version must be "${DLP_TAXONOMY_VERSION}"`,
      field: `${args.field}.taxonomy_version`,
    };
  }
  if (
    typeof policy.ruleset_hash_b64u !== 'string' ||
    !isValidBase64Url(policy.ruleset_hash_b64u)
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `${args.field}.ruleset_hash_b64u must be base64url`,
      field: `${args.field}.ruleset_hash_b64u`,
    };
  }

  const counts: Array<{
    key: 'built_in_rule_count' | 'custom_rule_count';
    value: unknown;
  }> = [
    { key: 'built_in_rule_count', value: policy.built_in_rule_count },
    { key: 'custom_rule_count', value: policy.custom_rule_count },
  ];

  for (const entry of counts) {
    if (
      typeof entry.value !== 'number' ||
      !Number.isInteger(entry.value) ||
      entry.value < 0
    ) {
      return {
        ok: false,
        code: 'MALFORMED_ENVELOPE',
        message: `${args.field}.${entry.key} must be a non-negative integer`,
        field: `${args.field}.${entry.key}`,
      };
    }
  }

  return {
    ok: true,
    value: {
      taxonomy_version: DLP_TAXONOMY_VERSION,
      ruleset_hash_b64u: policy.ruleset_hash_b64u,
      built_in_rule_count: Number(policy.built_in_rule_count),
      custom_rule_count: Number(policy.custom_rule_count),
    },
  };
}

function validateDataHandlingClassMatch(args: {
  value: unknown;
  field: string;
}):
  | { ok: true; value: DataHandlingClassMatch }
  | { ok: false; code: VerificationError['code']; message: string; field: string } {
  if (!isObjectRecord(args.value)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `${args.field} must be an object`,
      field: args.field,
    };
  }

  const value = args.value;
  const rawClassId = typeof value.class_id === 'string' ? value.class_id.trim() : '';
  const classId = rawClassId.toLowerCase();
  if (rawClassId !== classId || !DLP_CLASS_ID_PATTERN.test(classId)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `${args.field}.class_id is invalid`,
      field: `${args.field}.class_id`,
    };
  }

  const ruleId = typeof value.rule_id === 'string' ? value.rule_id.trim() : '';
  if (!ruleId.startsWith('prv.dlp.') || !DLP_RULE_ID_PATTERN.test(ruleId)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `${args.field}.rule_id is invalid`,
      field: `${args.field}.rule_id`,
    };
  }

  const customMatch = ruleId.match(DLP_CUSTOM_RULE_ID_PATTERN);
  if (ruleId.startsWith('prv.dlp.custom.') && customMatch === null) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `${args.field}.rule_id must use deterministic custom format`,
      field: `${args.field}.rule_id`,
    };
  }
  if (customMatch && customMatch[1] !== classId) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: `${args.field}.rule_id class segment must match class_id`,
      field: `${args.field}.rule_id`,
    };
  }
  if (
    !ruleId.startsWith('prv.dlp.custom.') &&
    !ruleId.startsWith(`prv.dlp.${classId}.`)
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: `${args.field}.rule_id must align with class_id`,
      field: `${args.field}.rule_id`,
    };
  }

  if (!isDataHandlingAction(value.action)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `${args.field}.action is invalid`,
      field: `${args.field}.action`,
    };
  }

  if (
    typeof value.match_count !== 'number' ||
    !Number.isInteger(value.match_count) ||
    value.match_count < 0
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `${args.field}.match_count must be a non-negative integer`,
      field: `${args.field}.match_count`,
    };
  }

  return {
    ok: true,
    value: {
      class_id: classId,
      rule_id: ruleId,
      action: value.action,
      match_count: value.match_count,
    },
  };
}

function isValidDataHandlingReasonCode(payload: Record<string, unknown>): boolean {
  if (typeof payload.reason_code !== 'string') return false;

  if (payload.action === 'block') {
    return payload.reason_code === 'PRV_DLP_BLOCKED';
  }

  if (payload.action === 'redact') {
    return payload.reason_code === 'PRV_DLP_REDACTED';
  }

  if (payload.action === 'allow') {
    if (
      isObjectRecord(payload.approval) &&
      payload.approval.required === true &&
      payload.approval.satisfied === true
    ) {
      return payload.reason_code === 'PRV_DLP_APPROVAL_GRANTED';
    }
    return payload.reason_code === 'PRV_DLP_ALLOW';
  }

  if (payload.action === 'require_approval') {
    return (
      payload.reason_code === 'PRV_DLP_APPROVAL_REQUIRED' ||
      payload.reason_code === 'PRV_DLP_CLASSIFIER_ERROR'
    );
  }

  return false;
}

function buildDataHandlingApprovalScope(payload: DataHandlingReceiptPayload): DataHandlingApprovalScope {
  const classIds = [...new Set(
    payload.classes
      .filter((entry) => entry.action === 'require_approval')
      .map((entry) => entry.class_id),
  )].sort((a, b) => a.localeCompare(b));

  return {
    scope_version: 'prv.dlp.approval_scope.v1',
    provider: payload.provider.trim().toLowerCase(),
    policy_version: payload.policy_version,
    effective_policy_hash_b64u: payload.effective_policy_hash_b64u,
    class_ids: classIds,
  };
}

async function verifyEmbeddedApprovalReceiptEnvelope(args: {
  envelope: unknown;
  field: string;
  expectedAgentDid: string;
  expectedRunId: string;
  allowedEventHashes: ReadonlySet<string> | null;
  expectedScopeHashB64u: string;
  expectedPolicyHashB64u: string;
  evidenceTimestamp: string;
  expectedSignerDid: string;
}):
  Promise<
    | { ok: true; signature_valid: boolean }
    | { ok: false; code: VerificationError['code']; message: string; field: string; signature_valid: boolean }
  > {
  if (!isObjectRecord(args.envelope)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'approval receipt envelope must be an object',
      field: args.field,
      signature_valid: false,
    };
  }

  const env = args.envelope;
  if (env.envelope_version !== '1' || env.envelope_type !== 'human_approval_receipt') {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'approval receipt envelope must be human_approval_receipt v1',
      field: `${args.field}.envelope_type`,
      signature_valid: false,
    };
  }
  if (env.hash_algorithm !== 'SHA-256' || env.algorithm !== 'Ed25519') {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'approval receipt envelope must use SHA-256 + Ed25519',
      field: `${args.field}.algorithm`,
      signature_valid: false,
    };
  }
  if (
    typeof env.payload_hash_b64u !== 'string' ||
    !isValidBase64Url(env.payload_hash_b64u) ||
    typeof env.signature_b64u !== 'string' ||
    !isValidBase64Url(env.signature_b64u) ||
    typeof env.signer_did !== 'string' ||
    !isValidDidFormat(env.signer_did)
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'approval receipt envelope hash/signature/signer fields are invalid',
      field: `${args.field}.payload_hash_b64u`,
      signature_valid: false,
    };
  }
  if (env.signer_did !== args.expectedSignerDid) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'approval receipt signer does not match data handling signer binding',
      field: `${args.field}.signer_did`,
      signature_valid: false,
    };
  }
  if (!isObjectRecord(env.payload)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'approval receipt payload must be an object',
      field: `${args.field}.payload`,
      signature_valid: false,
    };
  }

  const payload = env.payload as Record<string, unknown>;
  if (payload.receipt_version !== '1') {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'approval receipt payload.receipt_version must be "1"',
      field: `${args.field}.payload.receipt_version`,
      signature_valid: false,
    };
  }
  if (
    typeof payload.approver_subject !== 'string' ||
    payload.approver_subject.trim().length === 0
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'approval receipt payload.approver_subject must be a non-empty string',
      field: `${args.field}.payload.approver_subject`,
      signature_valid: false,
    };
  }
  if (payload.approval_type !== 'explicit_approve' && payload.approval_type !== 'auto_approve') {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'approval receipt must be an approving decision',
      field: `${args.field}.payload.approval_type`,
      signature_valid: false,
    };
  }
  if (
    typeof payload.agent_did !== 'string' ||
    payload.agent_did !== args.expectedAgentDid
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'approval receipt payload.agent_did must match proof bundle agent_did',
      field: `${args.field}.payload.agent_did`,
      signature_valid: false,
    };
  }
  if (
    typeof payload.policy_hash_b64u !== 'string' ||
    payload.policy_hash_b64u !== args.expectedPolicyHashB64u
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'approval receipt payload.policy_hash_b64u must match effective policy hash',
      field: `${args.field}.payload.policy_hash_b64u`,
      signature_valid: false,
    };
  }
  if (
    typeof payload.scope_hash_b64u !== 'string' ||
    payload.scope_hash_b64u !== args.expectedScopeHashB64u
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'approval receipt payload.scope_hash_b64u does not match approval scope',
      field: `${args.field}.payload.scope_hash_b64u`,
      signature_valid: false,
    };
  }
  if (
    typeof payload.timestamp !== 'string' ||
    !isValidIsoDate(payload.timestamp) ||
    payload.hash_algorithm !== 'SHA-256' ||
    typeof payload.minted_capability_ttl_seconds !== 'number' ||
    !Number.isInteger(payload.minted_capability_ttl_seconds) ||
    payload.minted_capability_ttl_seconds <= 0
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'approval receipt timestamp/ttl fields are invalid',
      field: `${args.field}.payload.minted_capability_ttl_seconds`,
      signature_valid: false,
    };
  }

  const approvalTimestampMs = Date.parse(payload.timestamp);
  const evidenceTimestampMs = Date.parse(args.evidenceTimestamp);
  const approvalExpiryMs =
    approvalTimestampMs + payload.minted_capability_ttl_seconds * 1000;
  if (
    !Number.isFinite(approvalTimestampMs) ||
    !Number.isFinite(evidenceTimestampMs) ||
    evidenceTimestampMs < approvalTimestampMs ||
    evidenceTimestampMs > approvalExpiryMs
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'approval receipt is expired or not yet valid at data handling decision time',
      field: `${args.field}.payload.timestamp`,
      signature_valid: false,
    };
  }

  const binding = isObjectRecord(payload.binding)
    ? (payload.binding as Record<string, unknown>)
    : null;
  if (binding && binding.run_id !== undefined) {
    if (typeof binding.run_id !== 'string' || binding.run_id !== args.expectedRunId) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message: 'approval receipt binding.run_id does not match data handling run_id',
        field: `${args.field}.payload.binding.run_id`,
        signature_valid: false,
      };
    }
  }
  if (binding && binding.event_hash_b64u !== undefined) {
    if (
      typeof binding.event_hash_b64u !== 'string' ||
      !isValidBase64Url(binding.event_hash_b64u) ||
      !args.allowedEventHashes ||
      !args.allowedEventHashes.has(binding.event_hash_b64u)
    ) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message: 'approval receipt binding.event_hash_b64u must match an event hash in the proof bundle',
        field: `${args.field}.payload.binding.event_hash_b64u`,
        signature_valid: false,
      };
    }
  }
  if (binding && binding.policy_hash !== undefined) {
    if (
      typeof binding.policy_hash !== 'string' ||
      binding.policy_hash !== args.expectedPolicyHashB64u
    ) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message: 'approval receipt binding.policy_hash must match the effective policy hash',
        field: `${args.field}.payload.binding.policy_hash`,
        signature_valid: false,
      };
    }
  }

  let computedHash: string;
  try {
    computedHash = await computeHash(payload, 'SHA-256');
  } catch (err) {
    return {
      ok: false,
      code: 'HASH_MISMATCH',
      message: `approval receipt hash computation failed: ${err instanceof Error ? err.message : 'unknown error'}`,
      field: `${args.field}.payload_hash_b64u`,
      signature_valid: false,
    };
  }
  if (computedHash !== env.payload_hash_b64u) {
    return {
      ok: false,
      code: 'HASH_MISMATCH',
      message: 'approval receipt payload_hash_b64u mismatch',
      field: `${args.field}.payload_hash_b64u`,
      signature_valid: false,
    };
  }

  const publicKeyBytes = extractPublicKeyFromDidKey(env.signer_did);
  if (!publicKeyBytes) {
    return {
      ok: false,
      code: 'INVALID_DID_FORMAT',
      message: 'approval receipt signer_did is not a valid did:key Ed25519 identifier',
      field: `${args.field}.signer_did`,
      signature_valid: false,
    };
  }
  try {
    const signatureValid = await verifySignature(
      env.algorithm,
      publicKeyBytes,
      base64UrlDecode(env.signature_b64u),
      new TextEncoder().encode(env.payload_hash_b64u),
    );
    if (!signatureValid) {
      return {
        ok: false,
        code: 'SIGNATURE_INVALID',
        message: 'approval receipt signature verification failed',
        field: `${args.field}.signature_b64u`,
        signature_valid: false,
      };
    }
  } catch (err) {
    return {
      ok: false,
      code: 'SIGNATURE_INVALID',
      message: `approval receipt signature verification error: ${err instanceof Error ? err.message : 'unknown error'}`,
      field: `${args.field}.signature_b64u`,
      signature_valid: false,
    };
  }

  return { ok: true, signature_valid: true };
}

async function verifyDataHandlingReceiptEnvelope(args: {
  envelope: unknown;
  expectedSignerDid: string;
  expectedPolicyHashB64u: string;
  expectedRunId: string | null;
  allowedEventHashes: ReadonlySet<string> | null;
  field: string;
}):
  Promise<
    | { ok: true; signature_valid: boolean; policy: DataHandlingPolicyEvidence | null }
    | {
        ok: false;
        code: VerificationError['code'];
        message: string;
        field: string;
        signature_valid: boolean;
      }
  > {
  if (!isObjectRecord(args.envelope)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt entry must be an object',
      field: args.field,
      signature_valid: false,
    };
  }

  const env = args.envelope;
  if (env.envelope_version !== '1') {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt envelope_version must be "1"',
      field: `${args.field}.envelope_version`,
      signature_valid: false,
    };
  }
  if (env.envelope_type !== 'data_handling_receipt') {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt envelope_type must be "data_handling_receipt"',
      field: `${args.field}.envelope_type`,
      signature_valid: false,
    };
  }
  if (env.hash_algorithm !== 'SHA-256') {
    return {
      ok: false,
      code: 'UNKNOWN_HASH_ALGORITHM',
      message: 'data handling receipt hash_algorithm must be SHA-256',
      field: `${args.field}.hash_algorithm`,
      signature_valid: false,
    };
  }
  if (env.algorithm !== 'Ed25519') {
    return {
      ok: false,
      code: 'UNKNOWN_ALGORITHM',
      message: 'data handling receipt algorithm must be Ed25519',
      field: `${args.field}.algorithm`,
      signature_valid: false,
    };
  }
  if (typeof env.payload_hash_b64u !== 'string' || !isValidBase64Url(env.payload_hash_b64u)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload_hash_b64u must be base64url',
      field: `${args.field}.payload_hash_b64u`,
      signature_valid: false,
    };
  }
  if (typeof env.signature_b64u !== 'string' || !isValidBase64Url(env.signature_b64u)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt signature_b64u must be base64url',
      field: `${args.field}.signature_b64u`,
      signature_valid: false,
    };
  }
  if (typeof env.signer_did !== 'string' || !isValidDidFormat(env.signer_did)) {
    return {
      ok: false,
      code: 'INVALID_DID_FORMAT',
      message: 'data handling receipt signer_did is invalid',
      field: `${args.field}.signer_did`,
      signature_valid: false,
    };
  }
  if (env.signer_did !== args.expectedSignerDid) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'data handling receipt signer_did must match payload.agent_did',
      field: `${args.field}.signer_did`,
      signature_valid: false,
    };
  }
  if (!isObjectRecord(env.payload)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload must be an object',
      field: `${args.field}.payload`,
      signature_valid: false,
    };
  }

  const payload = env.payload as Record<string, unknown>;
  if (payload.receipt_version !== '1') {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.receipt_version must be "1"',
      field: `${args.field}.payload.receipt_version`,
      signature_valid: false,
    };
  }
  if (payload.policy_version !== DLP_POLICY_VERSION) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `data handling receipt payload.policy_version must be "${DLP_POLICY_VERSION}"`,
      field: `${args.field}.payload.policy_version`,
      signature_valid: false,
    };
  }
  let payloadPolicy: DataHandlingPolicyEvidence | null = null;
  if (payload.policy !== undefined) {
    const policyValidation = validateDataHandlingPolicyEvidence({
      value: payload.policy,
      field: `${args.field}.payload.policy`,
    });
    if (!policyValidation.ok) {
      return {
        ok: false,
        code: policyValidation.code,
        message: policyValidation.message,
        field: policyValidation.field,
        signature_valid: false,
      };
    }
    payloadPolicy = policyValidation.value;
  }
  if (
    typeof payload.effective_policy_hash_b64u !== 'string' ||
    !isValidBase64Url(payload.effective_policy_hash_b64u)
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.effective_policy_hash_b64u must be base64url',
      field: `${args.field}.payload.effective_policy_hash_b64u`,
      signature_valid: false,
    };
  }
  if (payload.effective_policy_hash_b64u !== args.expectedPolicyHashB64u) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'data handling receipt policy hash does not match effective signed policy hash',
      field: `${args.field}.payload.effective_policy_hash_b64u`,
      signature_valid: false,
    };
  }
  if (typeof payload.receipt_id !== 'string' || payload.receipt_id.trim().length === 0) {
    return {
      ok: false,
      code: 'MISSING_REQUIRED_FIELD',
      message: 'data handling receipt payload.receipt_id is required',
      field: `${args.field}.payload.receipt_id`,
      signature_valid: false,
    };
  }
  if (typeof payload.provider !== 'string' || payload.provider.trim().length === 0) {
    return {
      ok: false,
      code: 'MISSING_REQUIRED_FIELD',
      message: 'data handling receipt payload.provider is required',
      field: `${args.field}.payload.provider`,
      signature_valid: false,
    };
  }
  if (typeof payload.run_id !== 'string' || payload.run_id.trim().length === 0) {
    return {
      ok: false,
      code: 'MISSING_REQUIRED_FIELD',
      message: 'data handling receipt payload.run_id is required',
      field: `${args.field}.payload.run_id`,
      signature_valid: false,
    };
  }
  if (args.expectedRunId && payload.run_id !== args.expectedRunId) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'data handling receipt payload.run_id does not match proof bundle run_id',
      field: `${args.field}.payload.run_id`,
      signature_valid: false,
    };
  }
  if (!isDataHandlingAction(payload.action)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.action is invalid',
      field: `${args.field}.payload.action`,
      signature_valid: false,
    };
  }
  if (
    typeof payload.reason_code !== 'string' ||
    !payload.reason_code.startsWith('PRV_DLP_') ||
    !isValidDataHandlingReasonCode(payload)
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.reason_code is inconsistent with payload.action/approval state',
      field: `${args.field}.payload.reason_code`,
      signature_valid: false,
    };
  }
  if (typeof payload.timestamp !== 'string' || !isValidIsoDate(payload.timestamp)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.timestamp must be an ISO timestamp',
      field: `${args.field}.payload.timestamp`,
      signature_valid: false,
    };
  }

  if (!Array.isArray(payload.classes)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.classes must be an array of class matches',
      field: `${args.field}.payload.classes`,
      signature_valid: false,
    };
  }
  const classMatchKeys = new Set<string>();
  let previousSortKey: string | null = null;
  for (let i = 0; i < payload.classes.length; i++) {
    const classValidation = validateDataHandlingClassMatch({
      value: payload.classes[i],
      field: `${args.field}.payload.classes[${i}]`,
    });
    if (!classValidation.ok) {
      return {
        ok: false,
        code: classValidation.code,
        message: classValidation.message,
        field: classValidation.field,
        signature_valid: false,
      };
    }

    const classKey = `${classValidation.value.class_id}\u0000${classValidation.value.rule_id}`;
    if (classMatchKeys.has(classKey)) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          'data handling receipt payload.classes must not contain duplicate class_id/rule_id pairs',
        field: `${args.field}.payload.classes[${i}]`,
        signature_valid: false,
      };
    }
    classMatchKeys.add(classKey);

    if (previousSortKey !== null && classKey.localeCompare(previousSortKey) < 0) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          'data handling receipt payload.classes must be sorted by class_id then rule_id',
        field: `${args.field}.payload.classes[${i}]`,
        signature_valid: false,
      };
    }
    previousSortKey = classKey;

    const isCustomRule = classValidation.value.rule_id.startsWith('prv.dlp.custom.');
    if (isCustomRule && payloadPolicy === null) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          'data handling receipt payload.policy is required when payload.classes contains custom rule matches',
        field: `${args.field}.payload.policy`,
        signature_valid: false,
      };
    }
    if (
      isCustomRule &&
      payloadPolicy !== null &&
      payloadPolicy.custom_rule_count === 0
    ) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          'data handling receipt payload.policy.custom_rule_count must be positive when payload.classes contains custom rule matches',
        field: `${args.field}.payload.policy.custom_rule_count`,
        signature_valid: false,
      };
    }
    if (
      !isCustomRule &&
      payloadPolicy !== null &&
      payloadPolicy.built_in_rule_count === 0
    ) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          'data handling receipt payload.policy.built_in_rule_count must be positive when payload.classes contains built-in rule matches',
        field: `${args.field}.payload.policy.built_in_rule_count`,
        signature_valid: false,
      };
    }
  }

  if (!isObjectRecord(payload.approval)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.approval must be an object',
      field: `${args.field}.payload.approval`,
      signature_valid: false,
    };
  }
  if (
    typeof payload.approval.required !== 'boolean' ||
    typeof payload.approval.satisfied !== 'boolean'
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.approval flags must be booleans',
      field: `${args.field}.payload.approval`,
      signature_valid: false,
    };
  }
  if (
    typeof payload.approval.mechanism !== 'string' ||
    payload.approval.mechanism !== 'signed_receipt'
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.approval.mechanism must be "signed_receipt"',
      field: `${args.field}.payload.approval.mechanism`,
      signature_valid: false,
    };
  }
  if (
    payload.approval.scope_hash_b64u !== null &&
    (
      typeof payload.approval.scope_hash_b64u !== 'string' ||
      !isValidBase64Url(payload.approval.scope_hash_b64u)
    )
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.approval.scope_hash_b64u must be base64url or null',
      field: `${args.field}.payload.approval.scope_hash_b64u`,
      signature_valid: false,
    };
  }
  if (
    payload.approval.receipt_hash_b64u !== null &&
    (
      typeof payload.approval.receipt_hash_b64u !== 'string' ||
      !isValidBase64Url(payload.approval.receipt_hash_b64u)
    )
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.approval.receipt_hash_b64u must be base64url or null',
      field: `${args.field}.payload.approval.receipt_hash_b64u`,
      signature_valid: false,
    };
  }
  if (
    payload.approval.receipt_signer_did !== null &&
    (
      typeof payload.approval.receipt_signer_did !== 'string' ||
      !isValidDidFormat(payload.approval.receipt_signer_did)
    )
  ) {
    return {
      ok: false,
      code: 'INVALID_DID_FORMAT',
      message: 'data handling receipt payload.approval.receipt_signer_did must be did format or null',
      field: `${args.field}.payload.approval.receipt_signer_did`,
      signature_valid: false,
    };
  }

  if (!isObjectRecord(payload.redaction)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.redaction must be an object',
      field: `${args.field}.payload.redaction`,
      signature_valid: false,
    };
  }
  if (typeof payload.redaction.applied !== 'boolean') {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt payload.redaction.applied must be boolean',
      field: `${args.field}.payload.redaction.applied`,
      signature_valid: false,
    };
  }
  if (
    typeof payload.redaction.original_payload_hash_b64u !== 'string' ||
    !isValidBase64Url(payload.redaction.original_payload_hash_b64u)
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt original_payload_hash_b64u must be base64url',
      field: `${args.field}.payload.redaction.original_payload_hash_b64u`,
      signature_valid: false,
    };
  }
  if (
    payload.redaction.outbound_payload_hash_b64u !== null &&
    (
      typeof payload.redaction.outbound_payload_hash_b64u !== 'string' ||
      !isValidBase64Url(payload.redaction.outbound_payload_hash_b64u)
    )
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'data handling receipt outbound_payload_hash_b64u must be base64url or null',
      field: `${args.field}.payload.redaction.outbound_payload_hash_b64u`,
      signature_valid: false,
    };
  }

  if (payload.action === 'redact' && payload.redaction.applied !== true) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'redact action requires redaction.applied=true',
      field: `${args.field}.payload.redaction.applied`,
      signature_valid: false,
    };
  }
  if (payload.action === 'require_approval' && payload.approval.satisfied !== false) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'require_approval action must be unsatisfied in fail-closed state',
      field: `${args.field}.payload.approval.satisfied`,
      signature_valid: false,
    };
  }
  if (payload.approval.required === false && payload.approval.satisfied === true) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'approval.satisfied=true requires approval.required=true',
      field: `${args.field}.payload.approval.satisfied`,
      signature_valid: false,
    };
  }

  const approvalScopeHash = await computeHash(
    canonicalizeForHash(buildDataHandlingApprovalScope(
      payload as unknown as DataHandlingReceiptPayload,
    )),
    'SHA-256',
  );
  if (payload.approval.required === true) {
    if (payload.approval.scope_hash_b64u !== approvalScopeHash) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message: 'approval-required data handling receipts must carry the expected scope hash',
        field: `${args.field}.payload.approval.scope_hash_b64u`,
        signature_valid: false,
      };
    }
  } else if (payload.approval.scope_hash_b64u !== null) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'approval.scope_hash_b64u requires approval.required=true',
      field: `${args.field}.payload.approval.scope_hash_b64u`,
      signature_valid: false,
    };
  }

  if (
    payload.approval.satisfied === true &&
    (
      payload.approval.receipt_hash_b64u === null ||
      payload.approval.receipt_signer_did === null ||
      payload.approval.receipt_envelope === null
    )
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'approval.satisfied=true requires signed approval receipt evidence',
      field: `${args.field}.payload.approval.receipt_hash_b64u`,
      signature_valid: false,
    };
  }
  if (
    payload.approval.satisfied === false &&
    (
      payload.approval.receipt_hash_b64u !== null ||
      payload.approval.receipt_signer_did !== null ||
      payload.approval.receipt_envelope !== null
    )
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'unsatisfied approvals must not carry signed approval receipt evidence',
      field: `${args.field}.payload.approval.receipt_hash_b64u`,
      signature_valid: false,
    };
  }
  if (payload.approval.satisfied === true) {
    const approvalVerification = await verifyEmbeddedApprovalReceiptEnvelope({
      envelope: payload.approval.receipt_envelope,
      field: `${args.field}.payload.approval.receipt_envelope`,
      expectedAgentDid: args.expectedSignerDid,
      expectedRunId: payload.run_id as string,
      allowedEventHashes: args.allowedEventHashes,
      expectedScopeHashB64u: approvalScopeHash,
      expectedPolicyHashB64u: payload.effective_policy_hash_b64u as string,
      evidenceTimestamp: payload.timestamp as string,
      expectedSignerDid: payload.approval.receipt_signer_did as string,
    });
    if (!approvalVerification.ok) {
      return approvalVerification;
    }

    const embeddedReceiptEnvelope = payload.approval.receipt_envelope as
      | Record<string, unknown>
      | null;
    if (
      embeddedReceiptEnvelope &&
      payload.approval.receipt_hash_b64u !== embeddedReceiptEnvelope.payload_hash_b64u
    ) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message: 'approval.receipt_hash_b64u must match approval receipt envelope payload hash',
        field: `${args.field}.payload.approval.receipt_hash_b64u`,
        signature_valid: false,
      };
    }
  }
  if (
    (payload.action === 'block' || payload.action === 'require_approval') &&
    payload.redaction.outbound_payload_hash_b64u !== null
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'blocked or approval-required actions must not report an outbound payload hash',
      field: `${args.field}.payload.redaction.outbound_payload_hash_b64u`,
      signature_valid: false,
    };
  }
  if (
    (payload.action === 'block' || payload.action === 'require_approval') &&
    payload.redaction.applied !== false
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'blocked or approval-required actions must not report redaction.applied=true',
      field: `${args.field}.payload.redaction.applied`,
      signature_valid: false,
    };
  }
  if (
    payload.action === 'allow' &&
    payload.redaction.applied !== false
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'allow action must not report redaction.applied=true',
      field: `${args.field}.payload.redaction.applied`,
      signature_valid: false,
    };
  }
  if (
    (payload.action === 'allow' || payload.action === 'redact') &&
    payload.redaction.outbound_payload_hash_b64u === null
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'allow/redact actions must include outbound_payload_hash_b64u',
      field: `${args.field}.payload.redaction.outbound_payload_hash_b64u`,
      signature_valid: false,
    };
  }
  if (
    payload.action === 'allow' &&
    payload.redaction.outbound_payload_hash_b64u !==
      payload.redaction.original_payload_hash_b64u
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'allow action must preserve the outbound payload hash',
      field: `${args.field}.payload.redaction.outbound_payload_hash_b64u`,
      signature_valid: false,
    };
  }
  if (
    payload.action === 'redact' &&
    payload.redaction.outbound_payload_hash_b64u ===
      payload.redaction.original_payload_hash_b64u
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'redact action must change the outbound payload hash',
      field: `${args.field}.payload.redaction.outbound_payload_hash_b64u`,
      signature_valid: false,
    };
  }

  let computedHash: string;
  try {
    computedHash = await computeHash(payload, 'SHA-256');
  } catch (err) {
    return {
      ok: false,
      code: 'HASH_MISMATCH',
      message: `data handling receipt hash computation failed: ${err instanceof Error ? err.message : 'unknown error'}`,
      field: `${args.field}.payload_hash_b64u`,
      signature_valid: false,
    };
  }

  if (computedHash !== env.payload_hash_b64u) {
    return {
      ok: false,
      code: 'HASH_MISMATCH',
      message: 'data handling receipt payload_hash_b64u mismatch',
      field: `${args.field}.payload_hash_b64u`,
      signature_valid: false,
    };
  }

  const publicKeyBytes = extractPublicKeyFromDidKey(env.signer_did);
  if (!publicKeyBytes) {
    return {
      ok: false,
      code: 'INVALID_DID_FORMAT',
      message: 'data handling receipt signer_did is not a valid did:key Ed25519 identifier',
      field: `${args.field}.signer_did`,
      signature_valid: false,
    };
  }

  try {
    const signatureBytes = base64UrlDecode(env.signature_b64u);
    const messageBytes = new TextEncoder().encode(env.payload_hash_b64u);
    const signatureValid = await verifySignature(
      env.algorithm,
      publicKeyBytes,
      signatureBytes,
      messageBytes,
    );
    if (!signatureValid) {
      return {
        ok: false,
        code: 'SIGNATURE_INVALID',
        message: 'data handling receipt signature verification failed',
        field: `${args.field}.signature_b64u`,
        signature_valid: false,
      };
    }
  } catch (err) {
    return {
      ok: false,
      code: 'SIGNATURE_INVALID',
      message: `data handling receipt signature verification error: ${err instanceof Error ? err.message : 'unknown error'}`,
      field: `${args.field}.signature_b64u`,
      signature_valid: false,
    };
  }

  return { ok: true, signature_valid: true, policy: payloadPolicy };
}

async function verifyDataHandlingEvidence(args: {
  metadataRecord: Record<string, unknown> | null;
  expectedSignerDid: string;
  expectedRunId: string | null;
  expectedPolicyHashB64u: string | null;
  allowedEventHashes: ReadonlySet<string> | null;
}):
  Promise<
    | { ok: true }
    | { ok: false; code: VerificationError['code']; message: string; field: string }
  > {
  if (!args.metadataRecord) return { ok: true };

  const dataHandling = args.metadataRecord.data_handling;
  if (dataHandling === undefined) return { ok: true };
  if (!isObjectRecord(dataHandling)) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'payload.metadata.data_handling must be an object',
      field: 'payload.metadata.data_handling',
    };
  }

  if (dataHandling.policy_version !== DLP_POLICY_VERSION) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: `payload.metadata.data_handling.policy_version must be "${DLP_POLICY_VERSION}"`,
      field: 'payload.metadata.data_handling.policy_version',
    };
  }
  const metadataHasPolicyEvidenceFields =
    dataHandling.taxonomy_version !== undefined ||
    dataHandling.ruleset_hash_b64u !== undefined ||
    dataHandling.built_in_rule_count !== undefined ||
    dataHandling.custom_rule_count !== undefined;

  let metadataPolicy: DataHandlingPolicyEvidence | null = null;
  if (metadataHasPolicyEvidenceFields) {
    const metadataPolicyValidation = validateDataHandlingPolicyEvidence({
      value: {
        taxonomy_version: dataHandling.taxonomy_version,
        ruleset_hash_b64u: dataHandling.ruleset_hash_b64u,
        built_in_rule_count: dataHandling.built_in_rule_count,
        custom_rule_count: dataHandling.custom_rule_count,
      },
      field: 'payload.metadata.data_handling',
    });
    if (!metadataPolicyValidation.ok) {
      return {
        ok: false,
        code: metadataPolicyValidation.code,
        message: metadataPolicyValidation.message,
        field: metadataPolicyValidation.field,
      };
    }
    metadataPolicy = metadataPolicyValidation.value;
  }

  const policyError = dataHandling.policy_error;
  if (
    policyError !== undefined &&
    (typeof policyError !== 'string' || policyError.trim().length === 0)
  ) {
    return {
      ok: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'payload.metadata.data_handling.policy_error must be a non-empty string',
      field: 'payload.metadata.data_handling.policy_error',
    };
  }
  if (metadataPolicy && policyError !== undefined) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'payload.metadata.data_handling cannot include both policy evidence and policy_error',
      field: 'payload.metadata.data_handling.policy_error',
    };
  }
  if (!args.expectedPolicyHashB64u || !isValidBase64Url(args.expectedPolicyHashB64u)) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'payload.metadata.data_handling requires payload.metadata.policy_binding.effective_policy_hash_b64u',
      field: 'payload.metadata.policy_binding.effective_policy_hash_b64u',
    };
  }
  const expectedPolicyHashB64u = args.expectedPolicyHashB64u;
  if (
    dataHandling.effective_policy_hash_b64u !== undefined &&
    dataHandling.effective_policy_hash_b64u !== expectedPolicyHashB64u
  ) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'payload.metadata.data_handling.effective_policy_hash_b64u must match policy_binding hash',
      field: 'payload.metadata.data_handling.effective_policy_hash_b64u',
    };
  }

  if (!args.expectedRunId) {
    return {
      ok: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'payload.metadata.data_handling requires a valid event_chain-bound run_id',
      field: 'payload.metadata.data_handling',
    };
  }

  if (!Array.isArray(dataHandling.receipts) || dataHandling.receipts.length === 0) {
    return {
      ok: false,
      code: 'MISSING_REQUIRED_FIELD',
      message: 'payload.metadata.data_handling.receipts must contain at least one signed receipt',
      field: 'payload.metadata.data_handling.receipts',
    };
  }

  for (let i = 0; i < dataHandling.receipts.length; i++) {
    const result = await verifyDataHandlingReceiptEnvelope({
      envelope: dataHandling.receipts[i],
      expectedSignerDid: args.expectedSignerDid,
      expectedPolicyHashB64u,
      expectedRunId: args.expectedRunId,
      allowedEventHashes: args.allowedEventHashes,
      field: `payload.metadata.data_handling.receipts[${i}]`,
    });

    if (!result.ok) {
      return {
        ok: false,
        code: result.code,
        message: result.message,
        field: result.field,
      };
    }

    if (metadataPolicy) {
      if (!result.policy) {
        return {
          ok: false,
          code: 'EVIDENCE_MISMATCH',
          message:
            'data handling receipt payload.policy must be present when bundle metadata carries policy evidence',
          field: `payload.metadata.data_handling.receipts[${i}].payload.policy`,
        };
      }
      if (!dataHandlingPoliciesEqual(result.policy, metadataPolicy)) {
        return {
          ok: false,
          code: 'EVIDENCE_MISMATCH',
          message:
            'data handling receipt payload.policy must match payload.metadata.data_handling policy evidence',
          field: `payload.metadata.data_handling.receipts[${i}].payload.policy`,
        };
      }
    } else if (result.policy) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          'payload.metadata.data_handling policy evidence is required when receipts carry payload.policy',
        field: 'payload.metadata.data_handling',
      };
    }

    if (policyError !== undefined && result.policy) {
      return {
        ok: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          'policy_error metadata is incompatible with receipt payload.policy evidence',
        field: `payload.metadata.data_handling.receipts[${i}].payload.policy`,
      };
    }
  }

  return { ok: true };
}

interface ClddDiscrepancySummary {
  claimed: ClddMetrics | null;
  attested: ClddMetrics | null;
  mismatch_fields: Array<keyof ClddMetrics>;
  risk_flags: string[];
  discrepancy: boolean;
}

const ALLOWED_CAUSAL_PHASES = new Set([
  'setup',
  'planning',
  'reasoning',
  'execution',
  'observation',
  'reflection',
  'teardown',
]);

const CAUSAL_PHASE_TRANSITIONS: Record<string, ReadonlySet<string>> = {
  setup: new Set(['setup', 'planning']),
  planning: new Set(['planning', 'reasoning', 'execution']),
  reasoning: new Set(['reasoning', 'execution', 'observation']),
  execution: new Set(['execution', 'observation', 'reflection', 'teardown']),
  observation: new Set(['observation', 'reflection', 'teardown']),
  reflection: new Set(['reflection', 'teardown']),
  teardown: new Set(['teardown']),
};

function isAllowedCausalPhaseTransition(parentPhase: string, childPhase: string): boolean {
  const allowedTargets = CAUSAL_PHASE_TRANSITIONS[parentPhase];
  if (!allowedTargets) return false;
  return allowedTargets.has(childPhase);
}

type CausalBindingNormalizationCode =
  | 'CAUSAL_BINDING_FIELD_CONFLICT'
  | 'CAUSAL_BINDING_NORMALIZATION_FAILED';

interface CausalBindingEntry {
  path: string;
  spanId?: string;
  spanFieldPath: string;
  parentSpanId?: string;
  parentSpanFieldPath: string;
  toolSpanId?: string;
  toolSpanFieldPath: string;
  phase?: unknown;
  phaseFieldPath: string;
  attributionConfidence?: unknown;
  attributionConfidenceFieldPath: string;
  payloadTimestamp?: unknown;
  payloadTimestampFieldPath: string;
  envelopeIssuedAt?: unknown;
  envelopeIssuedAtFieldPath: string;
}

function toNonNegativeInteger(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    return null;
  }
  return value;
}

function isCanonicalHostList(value: unknown): value is string[] {
  if (!Array.isArray(value)) return false;
  let previous: string | null = null;
  const seen = new Set<string>();

  for (const entry of value) {
    if (typeof entry !== 'string') return false;
    const normalized = entry.trim().toLowerCase();
    if (normalized.length === 0 || normalized !== entry) return false;
    if (seen.has(normalized)) return false;
    if (previous !== null && normalized.localeCompare(previous) <= 0) return false;
    seen.add(normalized);
    previous = normalized;
  }

  return true;
}

function extractEgressPolicyReceiptEnvelope(
  metadataRecord: Record<string, unknown> | null
): unknown {
  if (!metadataRecord) return undefined;
  const sentinels = isObjectRecord(metadataRecord.sentinels)
    ? metadataRecord.sentinels
    : null;
  if (!sentinels) return undefined;
  return sentinels.egress_policy_receipt;
}

function extractRunnerAttestationReceiptEnvelope(
  metadataRecord: Record<string, unknown> | null
): unknown {
  if (!metadataRecord) return undefined;
  return metadataRecord.runner_attestation_receipt;
}

interface EgressPolicyReceiptVerificationOutcome {
  valid: boolean;
  signature_valid: boolean;
  code?: VerificationError['code'];
  message?: string;
  field?: string;
}

interface RunnerAttestationReceiptVerificationOutcome {
  valid: boolean;
  signature_valid: boolean;
  code?: VerificationError['code'];
  message?: string;
  field?: string;
}

interface PolicyBindingVerificationOutcome {
  ok?: false;
  valid: boolean;
  code?: VerificationError['code'];
  message?: string;
  field?: string;
}

function hasOnlyAllowedKeys(
  value: Record<string, unknown>,
  allowedKeys: readonly string[],
): boolean {
  const allowed = new Set(allowedKeys);
  return Object.keys(value).every((key) => allowed.has(key));
}

function canonicalizeForHash(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalizeForHash(entry));
  }
  if (isObjectRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort((a, b) => a.localeCompare(b))) {
      out[key] = canonicalizeForHash(value[key]);
    }
    return out;
  }
  return value;
}

function normalizePolicyStatementForHash(
  statement: SignedPolicyStatement,
  fieldPrefix: string,
):
  | { ok: true; value: SignedPolicyStatement }
  | PolicyBindingVerificationOutcome {
  if (!isNonEmptyString(statement.sid)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.sid must be a non-empty string`,
      field: `${fieldPrefix}.sid`,
    };
  }
  if (statement.effect !== 'Allow' && statement.effect !== 'Deny') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.effect must be Allow or Deny`,
      field: `${fieldPrefix}.effect`,
    };
  }
  if (!Array.isArray(statement.actions) || statement.actions.length === 0) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.actions must be a non-empty string array`,
      field: `${fieldPrefix}.actions`,
    };
  }
  if (!Array.isArray(statement.resources) || statement.resources.length === 0) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.resources must be a non-empty string array`,
      field: `${fieldPrefix}.resources`,
    };
  }

  const actions = statement.actions
    .map((action) => (typeof action === 'string' ? action.trim() : ''))
    .filter((action) => action.length > 0)
    .sort((a, b) => a.localeCompare(b));
  if (actions.length === 0) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.actions must contain non-empty strings`,
      field: `${fieldPrefix}.actions`,
    };
  }

  const resources = statement.resources
    .map((resource) => (typeof resource === 'string' ? resource.trim() : ''))
    .filter((resource) => resource.length > 0)
    .sort((a, b) => a.localeCompare(b));
  if (resources.length === 0) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.resources must contain non-empty strings`,
      field: `${fieldPrefix}.resources`,
    };
  }

  let conditions: SignedPolicyStatement['conditions'] | undefined;
  if (statement.conditions !== undefined) {
    if (!isObjectRecord(statement.conditions)) {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${fieldPrefix}.conditions must be an object when present`,
        field: `${fieldPrefix}.conditions`,
      };
    }
    const normalizedConditions: Record<string, Record<string, string[]>> = {};
    for (const op of Object.keys(statement.conditions).sort((a, b) => a.localeCompare(b))) {
      const conditionMap = statement.conditions[op];
      if (!isObjectRecord(conditionMap)) {
        return {
          valid: false,
          code: 'SCHEMA_VALIDATION_FAILED',
          message: `${fieldPrefix}.conditions.${op} must be an object`,
          field: `${fieldPrefix}.conditions.${op}`,
        };
      }
      const normalizedMap: Record<string, string[]> = {};
      for (const key of Object.keys(conditionMap).sort((a, b) => a.localeCompare(b))) {
        const rawValues = conditionMap[key];
        if (!Array.isArray(rawValues)) {
          return {
            valid: false,
            code: 'SCHEMA_VALIDATION_FAILED',
            message: `${fieldPrefix}.conditions.${op}.${key} must be a string array`,
            field: `${fieldPrefix}.conditions.${op}.${key}`,
          };
        }
        const values = rawValues
          .map((value) => (typeof value === 'string' ? value.trim() : ''))
          .filter((value) => value.length > 0)
          .sort((a, b) => a.localeCompare(b));
        normalizedMap[key] = values;
      }
      normalizedConditions[op] = normalizedMap;
    }
    conditions = normalizedConditions;
  }

  return {
    ok: true,
    value: {
      sid: statement.sid.trim(),
      effect: statement.effect,
      actions,
      resources,
      ...(conditions ? { conditions } : {}),
    },
  };
}

async function normalizePolicyForHash(
  policy: unknown,
  fieldPrefix: string,
):
  Promise<
    | { ok: true; normalized: { statements: SignedPolicyStatement[] }; hash: string }
    | PolicyBindingVerificationOutcome
  > {
  if (!isObjectRecord(policy)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix} must be an object`,
      field: fieldPrefix,
    };
  }

  const statementsRaw = policy.statements;
  if (!Array.isArray(statementsRaw) || statementsRaw.length === 0) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.statements must be a non-empty array`,
      field: `${fieldPrefix}.statements`,
    };
  }

  const bySid = new Map<string, SignedPolicyStatement>();
  for (let i = 0; i < statementsRaw.length; i++) {
    const rawStatement = statementsRaw[i];
    if (!isObjectRecord(rawStatement)) {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${fieldPrefix}.statements[${i}] must be an object`,
        field: `${fieldPrefix}.statements[${i}]`,
      };
    }
    const normalizedStatement = normalizePolicyStatementForHash(
      rawStatement as unknown as SignedPolicyStatement,
      `${fieldPrefix}.statements[${i}]`,
    );
    if (!normalizedStatement.ok) return normalizedStatement;
    bySid.set(normalizedStatement.value.sid, normalizedStatement.value);
  }

  const normalizedPolicy = {
    statements: [...bySid.values()].sort((a, b) => a.sid.localeCompare(b.sid)),
  };
  const hash = await computeHash(canonicalizeForHash(normalizedPolicy), 'SHA-256');
  return { ok: true, normalized: normalizedPolicy, hash };
}

async function validateSignedPolicyBundleEnvelopeForBinding(
  envelopeRaw: unknown,
  fieldPrefix: string,
):
  Promise<
    | {
        ok: true;
        payload: SignedPolicyBundlePayload;
      }
    | PolicyBindingVerificationOutcome
  > {
  if (!isObjectRecord(envelopeRaw)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix} must be an object`,
      field: fieldPrefix,
    };
  }

  const envelope = envelopeRaw as Record<string, unknown>;
  if (envelope.envelope_version !== '1') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.envelope_version must be "1"`,
      field: `${fieldPrefix}.envelope_version`,
    };
  }
  if (envelope.envelope_type !== 'policy_bundle') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.envelope_type must be "policy_bundle"`,
      field: `${fieldPrefix}.envelope_type`,
    };
  }
  if (envelope.hash_algorithm !== 'SHA-256') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.hash_algorithm must be SHA-256`,
      field: `${fieldPrefix}.hash_algorithm`,
    };
  }
  if (envelope.algorithm !== 'Ed25519') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.algorithm must be Ed25519`,
      field: `${fieldPrefix}.algorithm`,
    };
  }
  if (!isBase64Url(envelope.payload_hash_b64u)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.payload_hash_b64u must be base64url`,
      field: `${fieldPrefix}.payload_hash_b64u`,
    };
  }
  if (!isBase64Url(envelope.signature_b64u)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.signature_b64u must be base64url`,
      field: `${fieldPrefix}.signature_b64u`,
    };
  }
  if (!isValidDidFormat(envelope.signer_did)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.signer_did must be a valid DID`,
      field: `${fieldPrefix}.signer_did`,
    };
  }
  if (!isIsoDate(envelope.issued_at)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.issued_at must be ISO-8601`,
      field: `${fieldPrefix}.issued_at`,
    };
  }
  if (!isObjectRecord(envelope.payload)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.payload must be an object`,
      field: `${fieldPrefix}.payload`,
    };
  }

  const payloadRecord = envelope.payload;
  if (payloadRecord.policy_bundle_version !== '1') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.payload.policy_bundle_version must be "1"`,
      field: `${fieldPrefix}.payload.policy_bundle_version`,
    };
  }
  if (!isNonEmptyString(payloadRecord.bundle_id)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.payload.bundle_id must be non-empty`,
      field: `${fieldPrefix}.payload.bundle_id`,
    };
  }
  if (!isValidDidFormat(payloadRecord.issuer_did)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.payload.issuer_did must be a valid DID`,
      field: `${fieldPrefix}.payload.issuer_did`,
    };
  }
  if (!isIsoDate(payloadRecord.issued_at)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.payload.issued_at must be ISO-8601`,
      field: `${fieldPrefix}.payload.issued_at`,
    };
  }
  if (payloadRecord.hash_algorithm !== 'SHA-256') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.payload.hash_algorithm must be SHA-256`,
      field: `${fieldPrefix}.payload.hash_algorithm`,
    };
  }
  if (!Array.isArray(payloadRecord.layers) || payloadRecord.layers.length === 0) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.payload.layers must be a non-empty array`,
      field: `${fieldPrefix}.payload.layers`,
    };
  }

  const normalizedLayers: SignedPolicyLayer[] = [];
  for (let i = 0; i < payloadRecord.layers.length; i++) {
    const rawLayer = payloadRecord.layers[i];
    if (!isObjectRecord(rawLayer)) {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${fieldPrefix}.payload.layers[${i}] must be an object`,
        field: `${fieldPrefix}.payload.layers[${i}]`,
      };
    }
    if (!isNonEmptyString(rawLayer.layer_id)) {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${fieldPrefix}.payload.layers[${i}].layer_id must be non-empty`,
        field: `${fieldPrefix}.payload.layers[${i}].layer_id`,
      };
    }
    if (!isObjectRecord(rawLayer.scope)) {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${fieldPrefix}.payload.layers[${i}].scope must be an object`,
        field: `${fieldPrefix}.payload.layers[${i}].scope`,
      };
    }
    const rawScope = rawLayer.scope;
    const scopeType = rawScope.scope_type;
    if (
      scopeType !== 'org' &&
      scopeType !== 'project' &&
      scopeType !== 'task' &&
      scopeType !== 'exception'
    ) {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${fieldPrefix}.payload.layers[${i}].scope.scope_type is invalid`,
        field: `${fieldPrefix}.payload.layers[${i}].scope.scope_type`,
      };
    }
    if (!isNonEmptyString(rawScope.org_id)) {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${fieldPrefix}.payload.layers[${i}].scope.org_id must be non-empty`,
        field: `${fieldPrefix}.payload.layers[${i}].scope.org_id`,
      };
    }
    if (!isBase64Url(rawLayer.policy_hash_b64u)) {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${fieldPrefix}.payload.layers[${i}].policy_hash_b64u must be base64url`,
        field: `${fieldPrefix}.payload.layers[${i}].policy_hash_b64u`,
      };
    }

    const normalizedPolicy = await normalizePolicyForHash(
      rawLayer.policy,
      `${fieldPrefix}.payload.layers[${i}].policy`,
    );
    if (!normalizedPolicy.ok) return normalizedPolicy;

    if (normalizedPolicy.hash !== rawLayer.policy_hash_b64u) {
      return {
        valid: false,
        code: 'HASH_MISMATCH',
        message: `${fieldPrefix}.payload.layers[${i}].policy_hash_b64u mismatch`,
        field: `${fieldPrefix}.payload.layers[${i}].policy_hash_b64u`,
      };
    }

    normalizedLayers.push({
      layer_id: String(rawLayer.layer_id).trim(),
      scope: {
        scope_type: scopeType,
        org_id: String(rawScope.org_id).trim(),
        ...(isNonEmptyString(rawScope.project_id)
          ? { project_id: String(rawScope.project_id).trim() }
          : {}),
        ...(isNonEmptyString(rawScope.task_id)
          ? { task_id: String(rawScope.task_id).trim() }
          : {}),
        ...(isNonEmptyString(rawScope.exception_id)
          ? { exception_id: String(rawScope.exception_id).trim() }
          : {}),
        ...(typeof rawScope.priority === 'number'
          ? { priority: Math.trunc(rawScope.priority) }
          : {}),
        ...(isIsoDate(rawScope.expires_at)
          ? { expires_at: String(rawScope.expires_at) }
          : {}),
      },
      apply_mode:
        rawLayer.apply_mode === 'replace' || rawLayer.apply_mode === 'merge'
          ? rawLayer.apply_mode
          : 'merge',
      policy: normalizedPolicy.normalized,
      policy_hash_b64u: String(rawLayer.policy_hash_b64u),
      ...(isObjectRecord(rawLayer.metadata) ? { metadata: rawLayer.metadata } : {}),
    });
  }

  const normalizedPayload: SignedPolicyBundlePayload = {
    policy_bundle_version: '1',
    bundle_id: String(payloadRecord.bundle_id).trim(),
    issuer_did: String(payloadRecord.issuer_did).trim(),
    issued_at: String(payloadRecord.issued_at),
    hash_algorithm: 'SHA-256',
    layers: normalizedLayers,
    ...(isObjectRecord(payloadRecord.metadata) ? { metadata: payloadRecord.metadata } : {}),
  };

  const computedPayloadHash = await computeHash(
    canonicalizeForHash(normalizedPayload),
    'SHA-256',
  );
  if (computedPayloadHash !== envelope.payload_hash_b64u) {
    return {
      valid: false,
      code: 'HASH_MISMATCH',
      message: `${fieldPrefix}.payload_hash_b64u mismatch`,
      field: `${fieldPrefix}.payload_hash_b64u`,
    };
  }

  const publicKey = extractPublicKeyFromDidKey(String(envelope.signer_did));
  if (!publicKey) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `${fieldPrefix}.signer_did must resolve to an Ed25519 did:key`,
      field: `${fieldPrefix}.signer_did`,
    };
  }

  const signatureValid = await verifySignature(
    'Ed25519',
    publicKey,
    base64UrlDecode(String(envelope.signature_b64u)),
    new TextEncoder().encode(String(envelope.payload_hash_b64u)),
  );
  if (!signatureValid) {
    return {
      valid: false,
      code: 'SIGNATURE_INVALID',
      message: `${fieldPrefix}.signature_b64u failed verification`,
      field: `${fieldPrefix}.signature_b64u`,
    };
  }

  return {
    ok: true,
    payload: normalizedPayload,
  };
}

async function validatePolicyBindingMetadata(args: {
  payload: ProofBundlePayload;
  metadataRecord: Record<string, unknown> | null;
  eventChainValid: boolean;
}): Promise<PolicyBindingVerificationOutcome> {
  const bindingRaw = args.metadataRecord?.policy_binding;
  if (bindingRaw === undefined) {
    return { valid: true };
  }
  if (!isObjectRecord(bindingRaw)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.policy_binding must be an object when present',
      field: 'payload.metadata.policy_binding',
    };
  }

  const binding = bindingRaw as unknown as PolicyBindingMetadata;
  if (binding.binding_version !== '1') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.policy_binding.binding_version must be "1"',
      field: 'payload.metadata.policy_binding.binding_version',
    };
  }
  if (!isBase64Url(binding.effective_policy_hash_b64u)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.policy_binding.effective_policy_hash_b64u must be base64url',
      field: 'payload.metadata.policy_binding.effective_policy_hash_b64u',
    };
  }
  if (!isObjectRecord(binding.effective_policy_snapshot)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.policy_binding.effective_policy_snapshot must be an object',
      field: 'payload.metadata.policy_binding.effective_policy_snapshot',
    };
  }

  const snapshot = binding.effective_policy_snapshot;
  if (snapshot.snapshot_version !== '1') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.policy_binding.effective_policy_snapshot.snapshot_version must be "1"',
      field: 'payload.metadata.policy_binding.effective_policy_snapshot.snapshot_version',
    };
  }
  if (snapshot.resolver_version !== 'org_project_task_exception.v1') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.policy_binding.effective_policy_snapshot.resolver_version must be org_project_task_exception.v1',
      field: 'payload.metadata.policy_binding.effective_policy_snapshot.resolver_version',
    };
  }
  if (!isObjectRecord(snapshot.context) || !isNonEmptyString(snapshot.context.org_id)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.policy_binding.effective_policy_snapshot.context.org_id is required',
      field: 'payload.metadata.policy_binding.effective_policy_snapshot.context.org_id',
    };
  }
  if (
    !isObjectRecord(snapshot.source_bundle) ||
    !isNonEmptyString(snapshot.source_bundle.bundle_id) ||
    !isValidDidFormat(snapshot.source_bundle.issuer_did) ||
    !isIsoDate(snapshot.source_bundle.issued_at)
  ) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.policy_binding.effective_policy_snapshot.source_bundle is malformed',
      field: 'payload.metadata.policy_binding.effective_policy_snapshot.source_bundle',
    };
  }
  if (!Array.isArray(snapshot.applied_layers) || snapshot.applied_layers.length === 0) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.policy_binding.effective_policy_snapshot.applied_layers must be non-empty',
      field: 'payload.metadata.policy_binding.effective_policy_snapshot.applied_layers',
    };
  }

  const normalizedEffectivePolicy = await normalizePolicyForHash(
    snapshot.effective_policy,
    'payload.metadata.policy_binding.effective_policy_snapshot.effective_policy',
  );
  if (!normalizedEffectivePolicy.ok) return normalizedEffectivePolicy;

  const normalizedSnapshot = {
    ...snapshot,
    effective_policy: normalizedEffectivePolicy.normalized,
  };
  const computedEffectiveHash = await computeHash(
    canonicalizeForHash(normalizedSnapshot),
    'SHA-256',
  );
  if (computedEffectiveHash !== binding.effective_policy_hash_b64u) {
    return {
      valid: false,
      code: 'HASH_MISMATCH',
      message:
        'payload.metadata.policy_binding.effective_policy_hash_b64u does not match effective_policy_snapshot',
      field: 'payload.metadata.policy_binding.effective_policy_hash_b64u',
    };
  }

  if (binding.signed_policy_bundle_envelope === undefined) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.policy_binding.signed_policy_bundle_envelope is required',
      field: 'payload.metadata.policy_binding.signed_policy_bundle_envelope',
    };
  }

  const signedBundleValidation = await validateSignedPolicyBundleEnvelopeForBinding(
    binding.signed_policy_bundle_envelope,
    'payload.metadata.policy_binding.signed_policy_bundle_envelope',
  );
  if (!signedBundleValidation.ok) return signedBundleValidation;

  const signedPayload = signedBundleValidation.payload;
  if (signedPayload.bundle_id !== snapshot.source_bundle.bundle_id) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'policy binding source_bundle.bundle_id must match signed policy bundle payload.bundle_id',
      field: 'payload.metadata.policy_binding.effective_policy_snapshot.source_bundle.bundle_id',
    };
  }
  if (signedPayload.issuer_did !== snapshot.source_bundle.issuer_did) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'policy binding source_bundle.issuer_did must match signed policy bundle payload.issuer_did',
      field: 'payload.metadata.policy_binding.effective_policy_snapshot.source_bundle.issuer_did',
    };
  }

  const signedLayerById = new Map<string, SignedPolicyLayer>(
    signedPayload.layers.map((layer) => [layer.layer_id, layer]),
  );
  for (let i = 0; i < snapshot.applied_layers.length; i++) {
    const applied = snapshot.applied_layers[i];
    const signedLayer = signedLayerById.get(applied.layer_id);
    if (!signedLayer) {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'policy binding applied layer is missing from signed policy bundle layers',
        field: `payload.metadata.policy_binding.effective_policy_snapshot.applied_layers[${i}].layer_id`,
      };
    }
    if (signedLayer.policy_hash_b64u !== applied.policy_hash_b64u) {
      return {
        valid: false,
        code: 'HASH_MISMATCH',
        message:
          'policy binding applied layer policy hash does not match signed policy bundle layer hash',
        field: `payload.metadata.policy_binding.effective_policy_snapshot.applied_layers[${i}].policy_hash_b64u`,
      };
    }
  }

  const sentinels =
    args.metadataRecord && isObjectRecord(args.metadataRecord.sentinels)
      ? args.metadataRecord.sentinels
      : null;
  if (!sentinels || !isObjectRecord(sentinels.egress_policy_receipt)) {
    return {
      valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'payload.metadata.policy_binding requires payload.metadata.sentinels.egress_policy_receipt',
      field: 'payload.metadata.sentinels.egress_policy_receipt',
    };
  }

  const egress = sentinels.egress_policy_receipt as Record<string, unknown>;
  const egressPayload = isObjectRecord(egress.payload) ? egress.payload : null;
  if (!egressPayload) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.sentinels.egress_policy_receipt.payload must be an object when policy_binding is present',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload',
    };
  }

  const egressEffectiveHash =
    typeof egressPayload.effective_policy_hash_b64u === 'string'
      ? egressPayload.effective_policy_hash_b64u
      : null;
  if (!egressEffectiveHash || !isBase64Url(egressEffectiveHash)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'egress policy receipt must carry an effective policy hash when policy_binding is present',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.effective_policy_hash_b64u',
    };
  }
  if (egressEffectiveHash !== binding.effective_policy_hash_b64u) {
    return {
      valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'egress policy receipt effective policy hash does not match payload.metadata.policy_binding.effective_policy_hash_b64u',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.effective_policy_hash_b64u',
    };
  }

  if (args.eventChainValid && Array.isArray(args.payload.event_chain) && args.payload.event_chain.length > 0) {
    const expectedRunId = args.payload.event_chain[0].run_id;
    const eventHashSet = new Set(args.payload.event_chain.map((event) => event.event_hash_b64u));
    const bindingRecord = isObjectRecord(egressPayload.binding) ? egressPayload.binding : null;
    if (!bindingRecord) {
      return {
        valid: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          'egress policy receipt must include binding.run_id/event_hash_b64u when event_chain is present',
        field: 'payload.metadata.sentinels.egress_policy_receipt.payload.binding',
      };
    }
    if (bindingRecord.run_id !== expectedRunId) {
      return {
        valid: false,
        code: 'EVIDENCE_MISMATCH',
        message: 'egress policy receipt binding.run_id does not match payload.event_chain run_id',
        field: 'payload.metadata.sentinels.egress_policy_receipt.payload.binding.run_id',
      };
    }
    if (
      typeof bindingRecord.event_hash_b64u !== 'string' ||
      !eventHashSet.has(bindingRecord.event_hash_b64u)
    ) {
      return {
        valid: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          'egress policy receipt binding.event_hash_b64u must reference payload.event_chain',
        field: 'payload.metadata.sentinels.egress_policy_receipt.payload.binding.event_hash_b64u',
      };
    }
  }

  return { valid: true };
}

async function validateRunnerMeasurementMetadata(args: {
  metadataRecord: Record<string, unknown> | null;
}): Promise<PolicyBindingVerificationOutcome> {
  const bindingRaw = args.metadataRecord?.runner_measurement;
  if (bindingRaw === undefined) {
    return { valid: true };
  }
  if (!isObjectRecord(bindingRaw)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.runner_measurement must be an object when present',
      field: 'payload.metadata.runner_measurement',
    };
  }

  const binding = bindingRaw as unknown as RunnerMeasurementBindingMetadata;
  if (binding.binding_version !== '1') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.runner_measurement.binding_version must be "1"',
      field: 'payload.metadata.runner_measurement.binding_version',
    };
  }
  if (binding.hash_algorithm !== 'SHA-256') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.runner_measurement.hash_algorithm must be SHA-256',
      field: 'payload.metadata.runner_measurement.hash_algorithm',
    };
  }
  if (
    typeof binding.manifest_hash_b64u !== 'string' ||
    !isBase64Url(binding.manifest_hash_b64u)
  ) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.runner_measurement.manifest_hash_b64u must be base64url',
      field: 'payload.metadata.runner_measurement.manifest_hash_b64u',
    };
  }
  if (!isObjectRecord(binding.manifest)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.runner_measurement.manifest must be an object',
      field: 'payload.metadata.runner_measurement.manifest',
    };
  }

  const manifest = binding.manifest;
  if (manifest.manifest_version !== '1') {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.runner_measurement.manifest.manifest_version must be "1"',
      field: 'payload.metadata.runner_measurement.manifest.manifest_version',
    };
  }
  if (
    !isObjectRecord(manifest.runtime) ||
    !isNonEmptyString(manifest.runtime.platform) ||
    !isNonEmptyString(manifest.runtime.arch) ||
    !isNonEmptyString(manifest.runtime.node_version)
  ) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.runner_measurement.manifest.runtime must include non-empty platform/arch/node_version',
      field: 'payload.metadata.runner_measurement.manifest.runtime',
    };
  }
  if (!isObjectRecord(manifest.proofed)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.runner_measurement.manifest.proofed must be an object',
      field: 'payload.metadata.runner_measurement.manifest.proofed',
    };
  }
  if (manifest.proofed.proofed_mode !== true) {
    return {
      valid: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'payload.metadata.runner_measurement.manifest.proofed.proofed_mode must be true',
      field: 'payload.metadata.runner_measurement.manifest.proofed.proofed_mode',
    };
  }
  if (
    typeof manifest.proofed.clawproxy_url !== 'string' ||
    manifest.proofed.clawproxy_url.length === 0
  ) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.runner_measurement.manifest.proofed.clawproxy_url must be non-empty',
      field: 'payload.metadata.runner_measurement.manifest.proofed.clawproxy_url',
    };
  }
  try {
    const parsedUrl = new URL(manifest.proofed.clawproxy_url);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          'payload.metadata.runner_measurement.manifest.proofed.clawproxy_url must use http/https',
        field: 'payload.metadata.runner_measurement.manifest.proofed.clawproxy_url',
      };
    }
  } catch {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.runner_measurement.manifest.proofed.clawproxy_url must be an absolute URL',
      field: 'payload.metadata.runner_measurement.manifest.proofed.clawproxy_url',
    };
  }
  if (!isCanonicalHostList(manifest.proofed.allowed_proxy_destinations)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.runner_measurement.manifest.proofed.allowed_proxy_destinations must be a lowercase sorted unique host list',
      field: 'payload.metadata.runner_measurement.manifest.proofed.allowed_proxy_destinations',
    };
  }
  if (!isCanonicalHostList(manifest.proofed.allowed_child_destinations)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.runner_measurement.manifest.proofed.allowed_child_destinations must be a lowercase sorted unique host list',
      field: 'payload.metadata.runner_measurement.manifest.proofed.allowed_child_destinations',
    };
  }
  if (
    !isObjectRecord(manifest.proofed.sentinels) ||
    typeof manifest.proofed.sentinels.shell_enabled !== 'boolean' ||
    typeof manifest.proofed.sentinels.interpose_enabled !== 'boolean' ||
    typeof manifest.proofed.sentinels.preload_enabled !== 'boolean' ||
    typeof manifest.proofed.sentinels.fs_enabled !== 'boolean' ||
    typeof manifest.proofed.sentinels.net_enabled !== 'boolean'
  ) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.runner_measurement.manifest.proofed.sentinels must include boolean sentinel flags',
      field: 'payload.metadata.runner_measurement.manifest.proofed.sentinels',
    };
  }
  if (!isObjectRecord(manifest.policy)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.runner_measurement.manifest.policy must be an object',
      field: 'payload.metadata.runner_measurement.manifest.policy',
    };
  }
  if (
    manifest.policy.effective_policy_hash_b64u !== undefined &&
    !isBase64Url(manifest.policy.effective_policy_hash_b64u)
  ) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.metadata.runner_measurement.manifest.policy.effective_policy_hash_b64u must be base64url when present',
      field: 'payload.metadata.runner_measurement.manifest.policy.effective_policy_hash_b64u',
    };
  }
  if (!isObjectRecord(manifest.artifacts)) {
    return {
      valid: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.metadata.runner_measurement.manifest.artifacts must be an object',
      field: 'payload.metadata.runner_measurement.manifest.artifacts',
    };
  }

  const artifactFields = [
    'preload_hash_b64u',
    'node_preload_sentinel_hash_b64u',
    'sentinel_shell_hash_b64u',
    'sentinel_shell_policy_hash_b64u',
    'interpose_library_hash_b64u',
  ] as const;
  for (const field of artifactFields) {
    const value = manifest.artifacts[field];
    if (value !== null && !isBase64Url(value)) {
      return {
        valid: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `payload.metadata.runner_measurement.manifest.artifacts.${field} must be base64url or null`,
        field: `payload.metadata.runner_measurement.manifest.artifacts.${field}`,
      };
    }
  }
  if (
    manifest.proofed.sentinels.preload_enabled &&
    (!manifest.artifacts.preload_hash_b64u || !manifest.artifacts.node_preload_sentinel_hash_b64u)
  ) {
    return {
      valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'runner measurement preload-enabled manifests must include preload and node-preload artifact hashes',
      field: 'payload.metadata.runner_measurement.manifest.artifacts.preload_hash_b64u',
    };
  }
  if (
    manifest.proofed.sentinels.shell_enabled &&
    (!manifest.artifacts.sentinel_shell_hash_b64u ||
      !manifest.artifacts.sentinel_shell_policy_hash_b64u)
  ) {
    return {
      valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'runner measurement shell-enabled manifests must include sentinel shell artifact hashes',
      field: 'payload.metadata.runner_measurement.manifest.artifacts.sentinel_shell_hash_b64u',
    };
  }
  if (
    manifest.proofed.sentinels.interpose_enabled &&
    !manifest.artifacts.interpose_library_hash_b64u
  ) {
    return {
      valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'runner measurement interpose-enabled manifests must include interpose library hash',
      field: 'payload.metadata.runner_measurement.manifest.artifacts.interpose_library_hash_b64u',
    };
  }

  const policyBinding = args.metadataRecord?.policy_binding;
  if (isObjectRecord(policyBinding) && isNonEmptyString(policyBinding.effective_policy_hash_b64u)) {
    if (manifest.policy.effective_policy_hash_b64u !== policyBinding.effective_policy_hash_b64u) {
      return {
        valid: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          'runner measurement policy hash must match payload.metadata.policy_binding.effective_policy_hash_b64u',
        field: 'payload.metadata.runner_measurement.manifest.policy.effective_policy_hash_b64u',
      };
    }
  }

  const computedManifestHash = await computeHash(manifest, 'SHA-256');
  if (computedManifestHash !== binding.manifest_hash_b64u) {
    return {
      valid: false,
      code: 'HASH_MISMATCH',
      message:
        'payload.metadata.runner_measurement.manifest_hash_b64u does not match manifest',
      field: 'payload.metadata.runner_measurement.manifest_hash_b64u',
    };
  }

  return { valid: true };
}

async function verifyEgressPolicyReceiptEnvelope(args: {
  envelope: unknown;
  bundleAgentDid: string;
  expectedRunId: string | null;
  allowedEventHashes: Set<string> | null;
}): Promise<EgressPolicyReceiptVerificationOutcome> {
  const { envelope, bundleAgentDid, expectedRunId, allowedEventHashes } = args;

  if (!isObjectRecord(envelope)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'payload.metadata.sentinels.egress_policy_receipt must be an object',
      field: 'payload.metadata.sentinels.egress_policy_receipt',
    };
  }

  if (
    !hasOnlyAllowedKeys(envelope, [
      'envelope_version',
      'envelope_type',
      'payload',
      'payload_hash_b64u',
      'hash_algorithm',
      'signature_b64u',
      'algorithm',
      'signer_did',
      'issued_at',
    ])
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt envelope has unsupported fields',
      field: 'payload.metadata.sentinels.egress_policy_receipt',
    };
  }

  if (envelope.envelope_version !== '1') {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt envelope_version must be "1"',
      field: 'payload.metadata.sentinels.egress_policy_receipt.envelope_version',
    };
  }

  if (envelope.envelope_type !== 'egress_policy_receipt') {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt envelope_type must be "egress_policy_receipt"',
      field: 'payload.metadata.sentinels.egress_policy_receipt.envelope_type',
    };
  }

  if (envelope.hash_algorithm !== 'SHA-256') {
    return {
      valid: false,
      signature_valid: false,
      code: 'UNKNOWN_HASH_ALGORITHM',
      message: 'egress policy receipt hash_algorithm must be SHA-256',
      field: 'payload.metadata.sentinels.egress_policy_receipt.hash_algorithm',
    };
  }

  if (envelope.algorithm !== 'Ed25519') {
    return {
      valid: false,
      signature_valid: false,
      code: 'UNKNOWN_ALGORITHM',
      message: 'egress policy receipt algorithm must be Ed25519',
      field: 'payload.metadata.sentinels.egress_policy_receipt.algorithm',
    };
  }

  if (
    typeof envelope.payload_hash_b64u !== 'string' ||
    !isValidBase64Url(envelope.payload_hash_b64u)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt payload_hash_b64u must be valid base64url',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload_hash_b64u',
    };
  }

  if (
    typeof envelope.signature_b64u !== 'string' ||
    !isValidBase64Url(envelope.signature_b64u)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt signature_b64u must be valid base64url',
      field: 'payload.metadata.sentinels.egress_policy_receipt.signature_b64u',
    };
  }

  if (
    typeof envelope.signer_did !== 'string' ||
    !isValidDidFormat(envelope.signer_did)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'INVALID_DID_FORMAT',
      message: 'egress policy receipt signer_did must be a valid DID',
      field: 'payload.metadata.sentinels.egress_policy_receipt.signer_did',
    };
  }

  if (!isValidIsoDate(envelope.issued_at)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt issued_at must be ISO-8601',
      field: 'payload.metadata.sentinels.egress_policy_receipt.issued_at',
    };
  }

  if (!isObjectRecord(envelope.payload)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt payload must be an object',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload',
    };
  }

  const payload = envelope.payload as unknown as EgressPolicyReceiptPayload;

  if (
    !hasOnlyAllowedKeys(envelope.payload, [
      'receipt_version',
      'receipt_id',
      'policy_version',
      'policy_hash_b64u',
      'effective_policy_hash_b64u',
      'proofed_mode',
      'clawproxy_url',
      'allowed_proxy_destinations',
      'allowed_child_destinations',
      'direct_provider_access_blocked',
      'blocked_attempt_count',
      'blocked_attempts_observed',
      'hash_algorithm',
      'agent_did',
      'timestamp',
      'binding',
    ])
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt payload has unsupported fields',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload',
    };
  }

  if (payload.receipt_version !== '1') {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt payload.receipt_version must be "1"',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.receipt_version',
    };
  }

  if (
    typeof payload.receipt_id !== 'string' ||
    payload.receipt_id.trim().length === 0
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt payload.receipt_id must be non-empty',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.receipt_id',
    };
  }

  if (payload.policy_version !== '1') {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt payload.policy_version must be "1"',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.policy_version',
    };
  }

  if (
    typeof payload.policy_hash_b64u !== 'string' ||
    !isValidBase64Url(payload.policy_hash_b64u)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt payload.policy_hash_b64u must be base64url',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.policy_hash_b64u',
    };
  }

  if (
    payload.effective_policy_hash_b64u !== undefined &&
    (typeof payload.effective_policy_hash_b64u !== 'string' ||
      !isValidBase64Url(payload.effective_policy_hash_b64u))
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message:
        'egress policy receipt payload.effective_policy_hash_b64u must be base64url when present',
      field:
        'payload.metadata.sentinels.egress_policy_receipt.payload.effective_policy_hash_b64u',
    };
  }

  if (payload.proofed_mode !== true) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'egress policy receipt payload.proofed_mode must be true',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.proofed_mode',
    };
  }

  if (typeof payload.clawproxy_url !== 'string' || payload.clawproxy_url.length === 0) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt payload.clawproxy_url must be non-empty',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.clawproxy_url',
    };
  }

  try {
    const parsedUrl = new URL(payload.clawproxy_url);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return {
        valid: false,
        signature_valid: false,
        code: 'MALFORMED_ENVELOPE',
        message: 'egress policy receipt payload.clawproxy_url must use http/https',
        field: 'payload.metadata.sentinels.egress_policy_receipt.payload.clawproxy_url',
      };
    }
  } catch {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt payload.clawproxy_url must be an absolute URL',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.clawproxy_url',
    };
  }

  if (!isCanonicalHostList(payload.allowed_proxy_destinations)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message:
        'egress policy receipt payload.allowed_proxy_destinations must be lowercase sorted unique host list',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.allowed_proxy_destinations',
    };
  }

  if (!isCanonicalHostList(payload.allowed_child_destinations)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message:
        'egress policy receipt payload.allowed_child_destinations must be lowercase sorted unique host list',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.allowed_child_destinations',
    };
  }

  if (payload.direct_provider_access_blocked !== true) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'egress policy receipt payload.direct_provider_access_blocked must be true',
      field:
        'payload.metadata.sentinels.egress_policy_receipt.payload.direct_provider_access_blocked',
    };
  }

  if (!Number.isInteger(payload.blocked_attempt_count) || payload.blocked_attempt_count < 0) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message:
        'egress policy receipt payload.blocked_attempt_count must be a non-negative integer',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.blocked_attempt_count',
    };
  }

  if (typeof payload.blocked_attempts_observed !== 'boolean') {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message:
        'egress policy receipt payload.blocked_attempts_observed must be boolean',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.blocked_attempts_observed',
    };
  }

  if (payload.blocked_attempts_observed !== (payload.blocked_attempt_count > 0)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'egress policy receipt blocked_attempts_observed must match blocked_attempt_count > 0',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.blocked_attempts_observed',
    };
  }

  if (payload.hash_algorithm !== 'SHA-256') {
    return {
      valid: false,
      signature_valid: false,
      code: 'UNKNOWN_HASH_ALGORITHM',
      message: 'egress policy receipt payload.hash_algorithm must be SHA-256',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.hash_algorithm',
    };
  }

  if (typeof payload.agent_did !== 'string' || !isValidDidFormat(payload.agent_did)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'INVALID_DID_FORMAT',
      message: 'egress policy receipt payload.agent_did must be a valid DID',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.agent_did',
    };
  }

  if (payload.agent_did !== bundleAgentDid || envelope.signer_did !== bundleAgentDid) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'egress policy receipt signer/payload agent_did must match proof bundle agent_did',
      field: 'payload.metadata.sentinels.egress_policy_receipt.signer_did',
    };
  }

  if (!isValidIsoDate(payload.timestamp)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt payload.timestamp must be ISO-8601',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.timestamp',
    };
  }

  if (!isObjectRecord(payload.binding)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MISSING_REQUIRED_FIELD',
      message: 'egress policy receipt payload.binding.run_id is required',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.binding.run_id',
    };
  }

  const bindingRecord = payload.binding;

  if (!hasOnlyAllowedKeys(bindingRecord, ['run_id', 'event_hash_b64u'])) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'egress policy receipt binding has unsupported fields',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.binding',
    };
  }

  if (
    typeof bindingRecord.run_id !== 'string' ||
    bindingRecord.run_id.trim().length === 0
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MISSING_REQUIRED_FIELD',
      message: 'egress policy receipt payload.binding.run_id is required',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.binding.run_id',
    };
  }

  if (expectedRunId && bindingRecord.run_id !== expectedRunId) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'egress policy receipt binding.run_id does not match proof bundle run_id',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.binding.run_id',
    };
  }

  if (
    typeof bindingRecord.event_hash_b64u !== 'string' ||
    !isValidBase64Url(bindingRecord.event_hash_b64u)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MISSING_REQUIRED_FIELD',
      message: 'egress policy receipt payload.binding.event_hash_b64u is required',
      field:
        'payload.metadata.sentinels.egress_policy_receipt.payload.binding.event_hash_b64u',
    };
  }

  if (!allowedEventHashes) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'egress policy receipt requires a valid payload.event_chain for binding verification',
      field:
        'payload.metadata.sentinels.egress_policy_receipt.payload.binding.event_hash_b64u',
    };
  }

  if (!allowedEventHashes.has(bindingRecord.event_hash_b64u)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'egress policy receipt binding.event_hash_b64u must reference an event in payload.event_chain',
      field:
        'payload.metadata.sentinels.egress_policy_receipt.payload.binding.event_hash_b64u',
    };
  }

  const canonicalPolicy = {
    policy_version: payload.policy_version,
    proofed_mode: payload.proofed_mode,
    clawproxy_url: payload.clawproxy_url,
    allowed_proxy_destinations: payload.allowed_proxy_destinations,
    allowed_child_destinations: payload.allowed_child_destinations,
    direct_provider_access_blocked: payload.direct_provider_access_blocked,
  };
  const computedPolicyHash = await computeHash(canonicalPolicy, 'SHA-256');
  if (computedPolicyHash !== payload.policy_hash_b64u) {
    return {
      valid: false,
      signature_valid: false,
      code: 'HASH_MISMATCH',
      message: 'egress policy receipt policy_hash_b64u mismatch',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload.policy_hash_b64u',
    };
  }

  const computedPayloadHash = await computeHash(payload, 'SHA-256');
  if (computedPayloadHash !== envelope.payload_hash_b64u) {
    return {
      valid: false,
      signature_valid: false,
      code: 'HASH_MISMATCH',
      message: 'egress policy receipt payload_hash_b64u mismatch',
      field: 'payload.metadata.sentinels.egress_policy_receipt.payload_hash_b64u',
    };
  }

  const publicKeyBytes = extractPublicKeyFromDidKey(envelope.signer_did);
  if (!publicKeyBytes) {
    return {
      valid: false,
      signature_valid: false,
      code: 'INVALID_DID_FORMAT',
      message: 'Unable to extract Ed25519 public key from egress policy signer DID',
      field: 'payload.metadata.sentinels.egress_policy_receipt.signer_did',
    };
  }

  const signatureBytes = base64UrlDecode(envelope.signature_b64u);
  const sigMessageBytes = new TextEncoder().encode(envelope.payload_hash_b64u);
  const signatureValid = await verifySignature(
    envelope.algorithm,
    publicKeyBytes,
    signatureBytes,
    sigMessageBytes
  );

  if (!signatureValid) {
    return {
      valid: false,
      signature_valid: false,
      code: 'SIGNATURE_INVALID',
      message: 'egress policy receipt signature verification failed',
      field: 'payload.metadata.sentinels.egress_policy_receipt.signature_b64u',
    };
  }

  return { valid: true, signature_valid: true };
}

async function verifyRunnerAttestationReceiptEnvelope(args: {
  envelope: unknown;
  bundleAgentDid: string;
  expectedRunId: string | null;
  allowedEventHashes: Set<string> | null;
  runnerMeasurement: RunnerMeasurementBindingMetadata;
  expectedPolicyHashB64u: string;
}): Promise<RunnerAttestationReceiptVerificationOutcome> {
  const {
    envelope,
    bundleAgentDid,
    expectedRunId,
    allowedEventHashes,
    runnerMeasurement,
    expectedPolicyHashB64u,
  } = args;

  if (!isObjectRecord(envelope)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'payload.metadata.runner_attestation_receipt must be an object',
      field: 'payload.metadata.runner_attestation_receipt',
    };
  }

  if (
    !hasOnlyAllowedKeys(envelope, [
      'envelope_version',
      'envelope_type',
      'payload',
      'payload_hash_b64u',
      'hash_algorithm',
      'signature_b64u',
      'algorithm',
      'signer_did',
      'issued_at',
    ])
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt envelope has unsupported fields',
      field: 'payload.metadata.runner_attestation_receipt',
    };
  }

  if (envelope.envelope_version !== '1') {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt envelope_version must be "1"',
      field: 'payload.metadata.runner_attestation_receipt.envelope_version',
    };
  }
  if (envelope.envelope_type !== 'runner_attestation_receipt') {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt envelope_type must be "runner_attestation_receipt"',
      field: 'payload.metadata.runner_attestation_receipt.envelope_type',
    };
  }
  if (envelope.hash_algorithm !== 'SHA-256') {
    return {
      valid: false,
      signature_valid: false,
      code: 'UNKNOWN_HASH_ALGORITHM',
      message: 'runner attestation receipt hash_algorithm must be SHA-256',
      field: 'payload.metadata.runner_attestation_receipt.hash_algorithm',
    };
  }
  if (envelope.algorithm !== 'Ed25519') {
    return {
      valid: false,
      signature_valid: false,
      code: 'UNKNOWN_ALGORITHM',
      message: 'runner attestation receipt algorithm must be Ed25519',
      field: 'payload.metadata.runner_attestation_receipt.algorithm',
    };
  }
  if (
    typeof envelope.payload_hash_b64u !== 'string' ||
    !isValidBase64Url(envelope.payload_hash_b64u)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt payload_hash_b64u must be base64url',
      field: 'payload.metadata.runner_attestation_receipt.payload_hash_b64u',
    };
  }
  if (
    typeof envelope.signature_b64u !== 'string' ||
    !isValidBase64Url(envelope.signature_b64u)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt signature_b64u must be base64url',
      field: 'payload.metadata.runner_attestation_receipt.signature_b64u',
    };
  }
  if (
    typeof envelope.signer_did !== 'string' ||
    !isValidDidFormat(envelope.signer_did)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'INVALID_DID_FORMAT',
      message: 'runner attestation receipt signer_did must be a valid DID',
      field: 'payload.metadata.runner_attestation_receipt.signer_did',
    };
  }
  if (!isValidIsoDate(envelope.issued_at)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt issued_at must be ISO-8601',
      field: 'payload.metadata.runner_attestation_receipt.issued_at',
    };
  }
  if (!isObjectRecord(envelope.payload)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt payload must be an object',
      field: 'payload.metadata.runner_attestation_receipt.payload',
    };
  }

  const payload = envelope.payload as unknown as RunnerAttestationReceiptPayload;
  if (
    !hasOnlyAllowedKeys(envelope.payload, [
      'receipt_version',
      'receipt_id',
      'hash_algorithm',
      'agent_did',
      'timestamp',
      'binding',
      'runner_measurement',
      'policy',
    ])
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt payload has unsupported fields',
      field: 'payload.metadata.runner_attestation_receipt.payload',
    };
  }

  if (payload.receipt_version !== '1') {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt payload.receipt_version must be "1"',
      field: 'payload.metadata.runner_attestation_receipt.payload.receipt_version',
    };
  }
  if (
    typeof payload.receipt_id !== 'string' ||
    payload.receipt_id.trim().length === 0
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt payload.receipt_id must be non-empty',
      field: 'payload.metadata.runner_attestation_receipt.payload.receipt_id',
    };
  }
  if (payload.hash_algorithm !== 'SHA-256') {
    return {
      valid: false,
      signature_valid: false,
      code: 'UNKNOWN_HASH_ALGORITHM',
      message: 'runner attestation receipt payload.hash_algorithm must be SHA-256',
      field: 'payload.metadata.runner_attestation_receipt.payload.hash_algorithm',
    };
  }
  if (typeof payload.agent_did !== 'string' || !isValidDidFormat(payload.agent_did)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'INVALID_DID_FORMAT',
      message: 'runner attestation receipt payload.agent_did must be a valid DID',
      field: 'payload.metadata.runner_attestation_receipt.payload.agent_did',
    };
  }
  if (payload.agent_did !== bundleAgentDid || envelope.signer_did !== bundleAgentDid) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'runner attestation receipt signer/payload agent_did must match proof bundle agent_did',
      field: 'payload.metadata.runner_attestation_receipt.signer_did',
    };
  }
  if (!isValidIsoDate(payload.timestamp)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt payload.timestamp must be ISO-8601',
      field: 'payload.metadata.runner_attestation_receipt.payload.timestamp',
    };
  }

  if (!isObjectRecord(payload.binding)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt payload.binding must be an object',
      field: 'payload.metadata.runner_attestation_receipt.payload.binding',
    };
  }
  if (!hasOnlyAllowedKeys(payload.binding, ['run_id', 'event_hash_b64u'])) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt payload.binding has unsupported fields',
      field: 'payload.metadata.runner_attestation_receipt.payload.binding',
    };
  }
  if (
    typeof payload.binding.run_id !== 'string' ||
    payload.binding.run_id.trim().length === 0
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MISSING_REQUIRED_FIELD',
      message: 'runner attestation receipt payload.binding.run_id is required',
      field: 'payload.metadata.runner_attestation_receipt.payload.binding.run_id',
    };
  }
  if (
    typeof payload.binding.event_hash_b64u !== 'string' ||
    !isBase64Url(payload.binding.event_hash_b64u)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MISSING_REQUIRED_FIELD',
      message:
        'runner attestation receipt payload.binding.event_hash_b64u must be base64url',
      field:
        'payload.metadata.runner_attestation_receipt.payload.binding.event_hash_b64u',
    };
  }
  if (!expectedRunId || !allowedEventHashes) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'runner attestation receipt requires a valid payload.event_chain for run/event binding',
      field:
        'payload.metadata.runner_attestation_receipt.payload.binding.event_hash_b64u',
    };
  }
  if (payload.binding.run_id !== expectedRunId) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message: 'runner attestation receipt binding.run_id does not match proof bundle run_id',
      field: 'payload.metadata.runner_attestation_receipt.payload.binding.run_id',
    };
  }
  if (!allowedEventHashes.has(payload.binding.event_hash_b64u)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'runner attestation receipt binding.event_hash_b64u must reference payload.event_chain',
      field:
        'payload.metadata.runner_attestation_receipt.payload.binding.event_hash_b64u',
    };
  }

  if (!isObjectRecord(payload.policy)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt payload.policy must be an object',
      field: 'payload.metadata.runner_attestation_receipt.payload.policy',
    };
  }
  if (
    typeof payload.policy.effective_policy_hash_b64u !== 'string' ||
    !isBase64Url(payload.policy.effective_policy_hash_b64u)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message:
        'runner attestation receipt payload.policy.effective_policy_hash_b64u must be base64url',
      field:
        'payload.metadata.runner_attestation_receipt.payload.policy.effective_policy_hash_b64u',
    };
  }
  if (payload.policy.effective_policy_hash_b64u !== expectedPolicyHashB64u) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'runner attestation receipt policy hash does not match payload.metadata.policy_binding.effective_policy_hash_b64u',
      field:
        'payload.metadata.runner_attestation_receipt.payload.policy.effective_policy_hash_b64u',
    };
  }

  if (!isObjectRecord(payload.runner_measurement)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message: 'runner attestation receipt payload.runner_measurement must be an object',
      field: 'payload.metadata.runner_attestation_receipt.payload.runner_measurement',
    };
  }
  if (
    typeof payload.runner_measurement.manifest_hash_b64u !== 'string' ||
    !isBase64Url(payload.runner_measurement.manifest_hash_b64u)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message:
        'runner attestation receipt payload.runner_measurement.manifest_hash_b64u must be base64url',
      field:
        'payload.metadata.runner_attestation_receipt.payload.runner_measurement.manifest_hash_b64u',
    };
  }
  if (
    payload.runner_measurement.manifest_hash_b64u !==
    runnerMeasurement.manifest_hash_b64u
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'EVIDENCE_MISMATCH',
      message:
        'runner attestation receipt manifest hash does not match payload.metadata.runner_measurement.manifest_hash_b64u',
      field:
        'payload.metadata.runner_attestation_receipt.payload.runner_measurement.manifest_hash_b64u',
    };
  }
  if (
    typeof payload.runner_measurement.runtime_hash_b64u !== 'string' ||
    !isBase64Url(payload.runner_measurement.runtime_hash_b64u)
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message:
        'runner attestation receipt payload.runner_measurement.runtime_hash_b64u must be base64url',
      field:
        'payload.metadata.runner_attestation_receipt.payload.runner_measurement.runtime_hash_b64u',
    };
  }
  const computedRuntimeHash = await computeHash(runnerMeasurement.manifest.runtime, 'SHA-256');
  if (payload.runner_measurement.runtime_hash_b64u !== computedRuntimeHash) {
    return {
      valid: false,
      signature_valid: false,
      code: 'HASH_MISMATCH',
      message: 'runner attestation receipt runtime_hash_b64u mismatch',
      field:
        'payload.metadata.runner_attestation_receipt.payload.runner_measurement.runtime_hash_b64u',
    };
  }

  if (!isObjectRecord(payload.runner_measurement.artifacts)) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message:
        'runner attestation receipt payload.runner_measurement.artifacts must be an object',
      field: 'payload.metadata.runner_attestation_receipt.payload.runner_measurement.artifacts',
    };
  }
  if (
    !hasOnlyAllowedKeys(payload.runner_measurement.artifacts, [
      'preload_hash_b64u',
      'node_preload_sentinel_hash_b64u',
      'sentinel_shell_hash_b64u',
      'sentinel_shell_policy_hash_b64u',
      'interpose_library_hash_b64u',
    ])
  ) {
    return {
      valid: false,
      signature_valid: false,
      code: 'MALFORMED_ENVELOPE',
      message:
        'runner attestation receipt payload.runner_measurement.artifacts has unsupported fields',
      field: 'payload.metadata.runner_attestation_receipt.payload.runner_measurement.artifacts',
    };
  }
  const artifactFields = [
    'preload_hash_b64u',
    'node_preload_sentinel_hash_b64u',
    'sentinel_shell_hash_b64u',
    'sentinel_shell_policy_hash_b64u',
    'interpose_library_hash_b64u',
  ] as const;
  for (const field of artifactFields) {
    const receiptValue = payload.runner_measurement.artifacts[field];
    if (receiptValue !== null && !isBase64Url(receiptValue)) {
      return {
        valid: false,
        signature_valid: false,
        code: 'MALFORMED_ENVELOPE',
        message:
          `runner attestation receipt payload.runner_measurement.artifacts.${field} must be base64url or null`,
        field:
          `payload.metadata.runner_attestation_receipt.payload.runner_measurement.artifacts.${field}`,
      };
    }
    if (receiptValue !== runnerMeasurement.manifest.artifacts[field]) {
      return {
        valid: false,
        signature_valid: false,
        code: 'EVIDENCE_MISMATCH',
        message:
          `runner attestation receipt artifact hash ${field} does not match payload.metadata.runner_measurement.manifest.artifacts.${field}`,
        field:
          `payload.metadata.runner_attestation_receipt.payload.runner_measurement.artifacts.${field}`,
      };
    }
  }

  const computedPayloadHash = await computeHash(payload, 'SHA-256');
  if (computedPayloadHash !== envelope.payload_hash_b64u) {
    return {
      valid: false,
      signature_valid: false,
      code: 'HASH_MISMATCH',
      message: 'runner attestation receipt payload_hash_b64u mismatch',
      field: 'payload.metadata.runner_attestation_receipt.payload_hash_b64u',
    };
  }

  const publicKeyBytes = extractPublicKeyFromDidKey(envelope.signer_did);
  if (!publicKeyBytes) {
    return {
      valid: false,
      signature_valid: false,
      code: 'INVALID_DID_FORMAT',
      message: 'Unable to extract Ed25519 public key from runner attestation signer DID',
      field: 'payload.metadata.runner_attestation_receipt.signer_did',
    };
  }
  const signatureValid = await verifySignature(
    envelope.algorithm,
    publicKeyBytes,
    base64UrlDecode(envelope.signature_b64u),
    new TextEncoder().encode(envelope.payload_hash_b64u),
  );
  if (!signatureValid) {
    return {
      valid: false,
      signature_valid: false,
      code: 'SIGNATURE_INVALID',
      message: 'runner attestation receipt signature verification failed',
      field: 'payload.metadata.runner_attestation_receipt.signature_b64u',
    };
  }

  return { valid: true, signature_valid: true };
}

function parseClddMetricsClaim(
  metadataRecord: Record<string, unknown> | null
):
  | { ok: true; metrics: ClddMetrics | null }
  | {
      ok: false;
      message: string;
      field: string;
    } {
  if (!metadataRecord) {
    return { ok: true, metrics: null };
  }

  const sentinels = isObjectRecord(metadataRecord.sentinels)
    ? metadataRecord.sentinels
    : null;

  if (!sentinels) {
    return { ok: true, metrics: null };
  }

  const interposeState = isObjectRecord(sentinels.interpose_state)
    ? sentinels.interpose_state
    : null;

  if (!interposeState) {
    return { ok: true, metrics: null };
  }

  const clddRaw = interposeState.cldd;
  if (clddRaw === undefined) {
    return { ok: true, metrics: null };
  }

  if (!isObjectRecord(clddRaw)) {
    return {
      ok: false,
      message:
        'payload.metadata.sentinels.interpose_state.cldd must be an object when present',
      field: 'payload.metadata.sentinels.interpose_state.cldd',
    };
  }

  const unmediatedConnections = toNonNegativeInteger(
    clddRaw.unmediated_connections
  );
  if (unmediatedConnections === null) {
    return {
      ok: false,
      message:
        'payload.metadata.sentinels.interpose_state.cldd.unmediated_connections must be a non-negative integer',
      field:
        'payload.metadata.sentinels.interpose_state.cldd.unmediated_connections',
    };
  }

  const unmonitoredSpawns = toNonNegativeInteger(clddRaw.unmonitored_spawns);
  if (unmonitoredSpawns === null) {
    return {
      ok: false,
      message:
        'payload.metadata.sentinels.interpose_state.cldd.unmonitored_spawns must be a non-negative integer',
      field:
        'payload.metadata.sentinels.interpose_state.cldd.unmonitored_spawns',
    };
  }

  if (typeof clddRaw.escapes_suspected !== 'boolean') {
    return {
      ok: false,
      message:
        'payload.metadata.sentinels.interpose_state.cldd.escapes_suspected must be a boolean',
      field:
        'payload.metadata.sentinels.interpose_state.cldd.escapes_suspected',
    };
  }

  return {
    ok: true,
    metrics: {
      unmediated_connections: unmediatedConnections,
      unmonitored_spawns: unmonitoredSpawns,
      escapes_suspected: clddRaw.escapes_suspected,
    },
  };
}

function parseProcessorPolicyEvidence(
  metadataRecord: Record<string, unknown> | null
):
  | { ok: true; evidence: ProcessorPolicyEvidence | null }
  | {
      ok: false;
      message: string;
      field: string;
    } {
  if (!metadataRecord) return { ok: true, evidence: null };

  const raw = metadataRecord.processor_policy;
  if (raw === undefined) return { ok: true, evidence: null };
  if (!isObjectRecord(raw)) {
    return {
      ok: false,
      message: 'payload.metadata.processor_policy must be an object when present',
      field: 'payload.metadata.processor_policy',
    };
  }

  if (raw.receipt_version !== '1') {
    return {
      ok: false,
      message: 'payload.metadata.processor_policy.receipt_version must be "1"',
      field: 'payload.metadata.processor_policy.receipt_version',
    };
  }

  if (raw.receipt_type !== 'processor_policy') {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.receipt_type must be "processor_policy"',
      field: 'payload.metadata.processor_policy.receipt_type',
    };
  }

  if (typeof raw.policy_version !== 'string' || raw.policy_version.trim().length === 0) {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.policy_version must be a non-empty string',
      field: 'payload.metadata.processor_policy.policy_version',
    };
  }

  if (typeof raw.profile_id !== 'string' || raw.profile_id.trim().length === 0) {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.profile_id must be a non-empty string',
      field: 'payload.metadata.processor_policy.profile_id',
    };
  }

  if (
    typeof raw.policy_hash_b64u !== 'string' ||
    raw.policy_hash_b64u.length < 8 ||
    !isValidBase64Url(raw.policy_hash_b64u)
  ) {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.policy_hash_b64u must be a base64url string (minLength 8)',
      field: 'payload.metadata.processor_policy.policy_hash_b64u',
    };
  }

  if (typeof raw.enforce !== 'boolean') {
    return {
      ok: false,
      message: 'payload.metadata.processor_policy.enforce must be a boolean',
      field: 'payload.metadata.processor_policy.enforce',
    };
  }

  const binding = isObjectRecord(raw.binding) ? raw.binding : null;
  if (!binding) {
    return {
      ok: false,
      message: 'payload.metadata.processor_policy.binding must be an object',
      field: 'payload.metadata.processor_policy.binding',
    };
  }

  const bindingRunId =
    typeof binding.run_id === 'string' && binding.run_id.trim().length > 0
      ? binding.run_id
      : null;
  if (!bindingRunId) {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.binding.run_id must be a non-empty string',
      field: 'payload.metadata.processor_policy.binding.run_id',
    };
  }

  const bindingChainRoot =
    binding.event_chain_root_hash_b64u === undefined
      ? undefined
      : typeof binding.event_chain_root_hash_b64u === 'string' &&
          binding.event_chain_root_hash_b64u.length >= 8 &&
          isValidBase64Url(binding.event_chain_root_hash_b64u)
        ? binding.event_chain_root_hash_b64u
        : null;
  if (bindingChainRoot === null) {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.binding.event_chain_root_hash_b64u must be a base64url string (minLength 8) when present',
      field: 'payload.metadata.processor_policy.binding.event_chain_root_hash_b64u',
    };
  }

  const constraints = isObjectRecord(raw.constraints) ? raw.constraints : null;
  if (!constraints) {
    return {
      ok: false,
      message: 'payload.metadata.processor_policy.constraints must be an object',
      field: 'payload.metadata.processor_policy.constraints',
    };
  }

  const parseConstraintList = (
    value: unknown,
    field: string
  ): { ok: true; values: string[] } | { ok: false; message: string; field: string } => {
    if (!Array.isArray(value)) {
      return {
        ok: false,
        message: `${field} must be an array`,
        field,
      };
    }

    const values: string[] = [];
    for (let i = 0; i < value.length; i++) {
      const entry = value[i];
      if (typeof entry !== 'string' || entry.trim().length === 0) {
        return {
          ok: false,
          message: `${field}[${i}] must be a non-empty string`,
          field: `${field}[${i}]`,
        };
      }
      values.push(entry);
    }

    if (values.length === 0) {
      return {
        ok: false,
        message: `${field} must contain at least one entry`,
        field,
      };
    }

    return { ok: true, values };
  };

  const allowedProviders = parseConstraintList(
    constraints.allowed_providers,
    'payload.metadata.processor_policy.constraints.allowed_providers'
  );
  if (!allowedProviders.ok) {
    return allowedProviders;
  }

  const allowedModels = parseConstraintList(
    constraints.allowed_models,
    'payload.metadata.processor_policy.constraints.allowed_models'
  );
  if (!allowedModels.ok) {
    return allowedModels;
  }

  const allowedRegions = parseConstraintList(
    constraints.allowed_regions,
    'payload.metadata.processor_policy.constraints.allowed_regions'
  );
  if (!allowedRegions.ok) {
    return allowedRegions;
  }

  const allowedRetentionProfiles = parseConstraintList(
    constraints.allowed_retention_profiles,
    'payload.metadata.processor_policy.constraints.allowed_retention_profiles'
  );
  if (!allowedRetentionProfiles.ok) {
    return allowedRetentionProfiles;
  }

  const defaultRegion =
    typeof constraints.default_region === 'string' &&
    constraints.default_region.trim().length > 0
      ? constraints.default_region
      : null;
  if (!defaultRegion) {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.constraints.default_region must be a non-empty string',
      field: 'payload.metadata.processor_policy.constraints.default_region',
    };
  }

  const defaultRetentionProfile =
    typeof constraints.default_retention_profile === 'string' &&
    constraints.default_retention_profile.trim().length > 0
      ? constraints.default_retention_profile
      : null;
  if (!defaultRetentionProfile) {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.constraints.default_retention_profile must be a non-empty string',
      field:
        'payload.metadata.processor_policy.constraints.default_retention_profile',
    };
  }

  const counters = isObjectRecord(raw.counters) ? raw.counters : null;
  if (!counters) {
    return {
      ok: false,
      message: 'payload.metadata.processor_policy.counters must be an object',
      field: 'payload.metadata.processor_policy.counters',
    };
  }

  const allowedRoutes = toNonNegativeInteger(counters.allowed_routes);
  if (allowedRoutes === null) {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.counters.allowed_routes must be a non-negative integer',
      field: 'payload.metadata.processor_policy.counters.allowed_routes',
    };
  }

  const deniedRoutes = toNonNegativeInteger(counters.denied_routes);
  if (deniedRoutes === null) {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.counters.denied_routes must be a non-negative integer',
      field: 'payload.metadata.processor_policy.counters.denied_routes',
    };
  }

  const usedProcessorsRaw = raw.used_processors;
  if (!Array.isArray(usedProcessorsRaw)) {
    return {
      ok: false,
      message: 'payload.metadata.processor_policy.used_processors must be an array',
      field: 'payload.metadata.processor_policy.used_processors',
    };
  }

  const usedProcessors: ProcessorPolicyEvidenceRoute[] = [];
  for (let i = 0; i < usedProcessorsRaw.length; i++) {
    const route = usedProcessorsRaw[i];
    if (!isObjectRecord(route)) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.used_processors entries must be objects',
        field: `payload.metadata.processor_policy.used_processors[${i}]`,
      };
    }

    const provider =
      typeof route.provider === 'string' && route.provider.trim().length > 0
        ? route.provider
        : null;
    const model =
      typeof route.model === 'string' && route.model.trim().length > 0
        ? route.model
        : null;
    const region =
      typeof route.region === 'string' && route.region.trim().length > 0
        ? route.region
        : null;
    const retentionProfile =
      typeof route.retention_profile === 'string' &&
      route.retention_profile.trim().length > 0
        ? route.retention_profile
        : null;
    const count = toNonNegativeInteger(route.count);

    if (!provider) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.used_processors[*].provider must be a non-empty string',
        field: `payload.metadata.processor_policy.used_processors[${i}].provider`,
      };
    }
    if (!model) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.used_processors[*].model must be a non-empty string',
        field: `payload.metadata.processor_policy.used_processors[${i}].model`,
      };
    }
    if (!region) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.used_processors[*].region must be a non-empty string',
        field: `payload.metadata.processor_policy.used_processors[${i}].region`,
      };
    }
    if (!retentionProfile) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.used_processors[*].retention_profile must be a non-empty string',
        field: `payload.metadata.processor_policy.used_processors[${i}].retention_profile`,
      };
    }
    if (count === null) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.used_processors[*].count must be a non-negative integer',
        field: `payload.metadata.processor_policy.used_processors[${i}].count`,
      };
    }

    usedProcessors.push({
      provider,
      model,
      region,
      retention_profile: retentionProfile,
      count,
    });
  }

  const blockedAttemptsRaw =
    raw.blocked_attempts === undefined ? [] : raw.blocked_attempts;
  if (!Array.isArray(blockedAttemptsRaw)) {
    return {
      ok: false,
      message:
        'payload.metadata.processor_policy.blocked_attempts must be an array when present',
      field: 'payload.metadata.processor_policy.blocked_attempts',
    };
  }

  const blockedAttempts: ProcessorPolicyEvidenceBlockedAttempt[] = [];
  for (let i = 0; i < blockedAttemptsRaw.length; i++) {
    const attempt = blockedAttemptsRaw[i];
    if (!isObjectRecord(attempt)) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.blocked_attempts entries must be objects',
        field: `payload.metadata.processor_policy.blocked_attempts[${i}]`,
      };
    }

    const route = isObjectRecord(attempt.route) ? attempt.route : null;
    if (!route) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.blocked_attempts[*].route must be an object',
        field: `payload.metadata.processor_policy.blocked_attempts[${i}].route`,
      };
    }

    const provider =
      typeof route.provider === 'string' && route.provider.trim().length > 0
        ? route.provider
        : null;
    const model =
      typeof route.model === 'string' && route.model.trim().length > 0
        ? route.model
        : null;
    const region =
      typeof route.region === 'string' && route.region.trim().length > 0
        ? route.region
        : null;
    const retentionProfile =
      typeof route.retention_profile === 'string' &&
      route.retention_profile.trim().length > 0
        ? route.retention_profile
        : null;

    if (!provider) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.blocked_attempts[*].route.provider must be a non-empty string',
        field: `payload.metadata.processor_policy.blocked_attempts[${i}].route.provider`,
      };
    }
    if (!model) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.blocked_attempts[*].route.model must be a non-empty string',
        field: `payload.metadata.processor_policy.blocked_attempts[${i}].route.model`,
      };
    }
    if (!region) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.blocked_attempts[*].route.region must be a non-empty string',
        field: `payload.metadata.processor_policy.blocked_attempts[${i}].route.region`,
      };
    }
    if (!retentionProfile) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.blocked_attempts[*].route.retention_profile must be a non-empty string',
        field: `payload.metadata.processor_policy.blocked_attempts[${i}].route.retention_profile`,
      };
    }

    if (
      typeof attempt.reason_code !== 'string' ||
      attempt.reason_code.trim().length === 0
    ) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.blocked_attempts[*].reason_code must be a non-empty string',
        field: `payload.metadata.processor_policy.blocked_attempts[${i}].reason_code`,
      };
    }

    if (
      typeof attempt.timestamp !== 'string' ||
      !isValidIsoDate(attempt.timestamp)
    ) {
      return {
        ok: false,
        message:
          'payload.metadata.processor_policy.blocked_attempts[*].timestamp must be an ISO-8601 string',
        field: `payload.metadata.processor_policy.blocked_attempts[${i}].timestamp`,
      };
    }

    blockedAttempts.push({
      route: {
        provider,
        model,
        region,
        retention_profile: retentionProfile,
      },
      reason_code: attempt.reason_code,
      timestamp: attempt.timestamp,
    });
  }

  return {
    ok: true,
    evidence: {
      receipt_version: '1',
      receipt_type: 'processor_policy',
      policy_version: raw.policy_version,
      profile_id: raw.profile_id,
      policy_hash_b64u: raw.policy_hash_b64u,
      enforce: raw.enforce,
      binding: {
        run_id: bindingRunId,
        ...(bindingChainRoot ? { event_chain_root_hash_b64u: bindingChainRoot } : {}),
      },
      constraints: {
        allowed_providers: allowedProviders.values,
        allowed_models: allowedModels.values,
        allowed_regions: allowedRegions.values,
        allowed_retention_profiles: allowedRetentionProfiles.values,
        default_region: defaultRegion,
        default_retention_profile: defaultRetentionProfile,
      },
      counters: {
        allowed_routes: allowedRoutes,
        denied_routes: deniedRoutes,
      },
      used_processors: usedProcessors,
      blocked_attempts: blockedAttempts,
    },
  };
}

async function computeProcessorPolicyHashB64u(
  evidence: ProcessorPolicyEvidence
): Promise<string> {
  const canonical = jcsCanonicalize({
    policy_version: evidence.policy_version,
    profile_id: evidence.profile_id,
    enforce: evidence.enforce,
    allowed_providers: evidence.constraints.allowed_providers,
    allowed_models: evidence.constraints.allowed_models,
    allowed_regions: evidence.constraints.allowed_regions,
    allowed_retention_profiles: evidence.constraints.allowed_retention_profiles,
    default_region: evidence.constraints.default_region,
    default_retention_profile: evidence.constraints.default_retention_profile,
  });
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical)
  );
  return base64UrlEncode(new Uint8Array(digest));
}

function aggregateCoverageClddMetrics(
  coverageResults: Array<{ cldd_metrics?: ClddMetrics }>
): ClddMetrics | null {
  let aggregate: ClddMetrics | null = null;

  for (const result of coverageResults) {
    if (!result.cldd_metrics) continue;

    if (!aggregate) {
      aggregate = {
        unmediated_connections: result.cldd_metrics.unmediated_connections,
        unmonitored_spawns: result.cldd_metrics.unmonitored_spawns,
        escapes_suspected: result.cldd_metrics.escapes_suspected,
      };
      continue;
    }

    aggregate = {
      unmediated_connections: Math.max(
        aggregate.unmediated_connections,
        result.cldd_metrics.unmediated_connections
      ),
      unmonitored_spawns: Math.max(
        aggregate.unmonitored_spawns,
        result.cldd_metrics.unmonitored_spawns
      ),
      escapes_suspected:
        aggregate.escapes_suspected || result.cldd_metrics.escapes_suspected,
    };
  }

  return aggregate;
}

function evaluateClddDiscrepancy(
  claimed: ClddMetrics | null,
  attested: ClddMetrics | null
): ClddDiscrepancySummary {
  if (!claimed || !attested) {
    return {
      claimed,
      attested,
      mismatch_fields: [],
      risk_flags: [],
      discrepancy: false,
    };
  }

  const mismatchFields: Array<keyof ClddMetrics> = [];
  const riskFlags: string[] = [];

  if (claimed.unmediated_connections !== attested.unmediated_connections) {
    mismatchFields.push('unmediated_connections');
    riskFlags.push('COVERAGE_CLDD_UNMEDIATED_CONNECTIONS_MISMATCH');
  }

  if (claimed.unmonitored_spawns !== attested.unmonitored_spawns) {
    mismatchFields.push('unmonitored_spawns');
    riskFlags.push('COVERAGE_CLDD_UNMONITORED_SPAWNS_MISMATCH');
  }

  if (claimed.escapes_suspected !== attested.escapes_suspected) {
    mismatchFields.push('escapes_suspected');
    riskFlags.push('COVERAGE_CLDD_ESCAPES_SUSPECTED_MISMATCH');
  }

  if (mismatchFields.length > 0) {
    riskFlags.unshift('COVERAGE_CLDD_DISCREPANCY');
  }

  return {
    claimed,
    attested,
    mismatch_fields: mismatchFields,
    risk_flags: riskFlags,
    discrepancy: mismatchFields.length > 0,
  };
}

function hasOwnField(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function normalizeCausalIdentifierField(args: {
  binding: Record<string, unknown>;
  path: string;
  snakeKey: 'span_id' | 'parent_span_id' | 'tool_span_id';
  camelKey: 'spanId' | 'parentSpanId' | 'toolSpanId';
  label: 'span_id' | 'parent_span_id' | 'tool_span_id';
}):
  | { ok: true; value?: string; fieldPath: string }
  | {
      ok: false;
      code: CausalBindingNormalizationCode;
      message: string;
      field: string;
    } {
  const snakeFieldPath = `${args.path}.${args.snakeKey}`;
  const camelFieldPath = `${args.path}.${args.camelKey}`;
  const hasSnake = hasOwnField(args.binding, args.snakeKey);
  const hasCamel = hasOwnField(args.binding, args.camelKey);

  const parse = (
    raw: unknown,
    fieldPath: string,
    keyName: string
  ):
    | { ok: true; value: string }
    | {
        ok: false;
        code: CausalBindingNormalizationCode;
        message: string;
        field: string;
      } => {
    if (typeof raw !== 'string') {
      return {
        ok: false,
        code: 'CAUSAL_BINDING_NORMALIZATION_FAILED',
        message: `${keyName} must be a string when present`,
        field: fieldPath,
      };
    }

    const normalized = raw.trim();
    if (normalized.length === 0) {
      return {
        ok: false,
        code: 'CAUSAL_BINDING_NORMALIZATION_FAILED',
        message: `${keyName} must be a non-empty identifier after normalization`,
        field: fieldPath,
      };
    }

    return { ok: true, value: normalized };
  };

  let snakeValue: string | undefined;
  if (hasSnake) {
    const parsed = parse(args.binding[args.snakeKey], snakeFieldPath, args.label);
    if (!parsed.ok) return parsed;
    snakeValue = parsed.value;
  }

  let camelValue: string | undefined;
  if (hasCamel) {
    const parsed = parse(args.binding[args.camelKey], camelFieldPath, args.camelKey);
    if (!parsed.ok) return parsed;
    camelValue = parsed.value;
  }

  if (hasSnake && hasCamel && snakeValue !== camelValue) {
    return {
      ok: false,
      code: 'CAUSAL_BINDING_FIELD_CONFLICT',
      message: `${args.label} and ${args.camelKey} conflict after normalization`,
      field: snakeFieldPath,
    };
  }

  if (hasSnake) {
    return { ok: true, value: snakeValue, fieldPath: snakeFieldPath };
  }

  if (hasCamel) {
    return { ok: true, value: camelValue, fieldPath: camelFieldPath };
  }

  return { ok: true, value: undefined, fieldPath: snakeFieldPath };
}

function normalizeCausalNumericField(args: {
  binding: Record<string, unknown>;
  path: string;
  snakeKey: 'attribution_confidence';
  camelKey: 'attributionConfidence';
  label: 'attribution_confidence';
}):
  | { ok: true; value?: number; fieldPath: string }
  | {
      ok: false;
      code: CausalBindingNormalizationCode;
      message: string;
      field: string;
    } {
  const snakeFieldPath = `${args.path}.${args.snakeKey}`;
  const camelFieldPath = `${args.path}.${args.camelKey}`;
  const hasSnake = hasOwnField(args.binding, args.snakeKey);
  const hasCamel = hasOwnField(args.binding, args.camelKey);

  const parse = (
    raw: unknown,
    fieldPath: string,
    keyName: string
  ):
    | { ok: true; value: number }
    | {
        ok: false;
        code: CausalBindingNormalizationCode;
        message: string;
        field: string;
      } => {
    if (typeof raw !== 'number' || !Number.isFinite(raw)) {
      return {
        ok: false,
        code: 'CAUSAL_BINDING_NORMALIZATION_FAILED',
        message: `${keyName} must be a finite number when present`,
        field: fieldPath,
      };
    }

    return { ok: true, value: raw };
  };

  let snakeValue: number | undefined;
  if (hasSnake) {
    const parsed = parse(args.binding[args.snakeKey], snakeFieldPath, args.label);
    if (!parsed.ok) return parsed;
    snakeValue = parsed.value;
  }

  let camelValue: number | undefined;
  if (hasCamel) {
    const parsed = parse(args.binding[args.camelKey], camelFieldPath, args.camelKey);
    if (!parsed.ok) return parsed;
    camelValue = parsed.value;
  }

  if (
    hasSnake &&
    hasCamel &&
    snakeValue !== undefined &&
    camelValue !== undefined &&
    !Object.is(snakeValue, camelValue)
  ) {
    return {
      ok: false,
      code: 'CAUSAL_BINDING_FIELD_CONFLICT',
      message: `${args.label} and ${args.camelKey} conflict after normalization`,
      field: snakeFieldPath,
    };
  }

  if (hasSnake) {
    return { ok: true, value: snakeValue, fieldPath: snakeFieldPath };
  }

  if (hasCamel) {
    return { ok: true, value: camelValue, fieldPath: camelFieldPath };
  }

  return { ok: true, value: undefined, fieldPath: snakeFieldPath };
}

function toCausalBindingEntry(
  binding: Record<string, unknown>,
  path: string,
  options: {
    payloadTimestamp?: unknown;
    payloadTimestampFieldPath?: string;
    envelopeIssuedAt?: unknown;
    envelopeIssuedAtFieldPath?: string;
  } = {}
):
  | { ok: true; entry: CausalBindingEntry | null }
  | {
      ok: false;
      code: CausalBindingNormalizationCode;
      message: string;
      field: string;
    } {
  const hasCausalField =
    hasOwnField(binding, 'span_id') ||
    hasOwnField(binding, 'spanId') ||
    hasOwnField(binding, 'parent_span_id') ||
    hasOwnField(binding, 'parentSpanId') ||
    hasOwnField(binding, 'tool_span_id') ||
    hasOwnField(binding, 'toolSpanId') ||
    hasOwnField(binding, 'phase') ||
    hasOwnField(binding, 'attribution_confidence') ||
    hasOwnField(binding, 'attributionConfidence');

  if (!hasCausalField) {
    return { ok: true, entry: null };
  }

  const span = normalizeCausalIdentifierField({
    binding,
    path,
    snakeKey: 'span_id',
    camelKey: 'spanId',
    label: 'span_id',
  });
  if (!span.ok) return span;

  const parentSpan = normalizeCausalIdentifierField({
    binding,
    path,
    snakeKey: 'parent_span_id',
    camelKey: 'parentSpanId',
    label: 'parent_span_id',
  });
  if (!parentSpan.ok) return parentSpan;

  const toolSpan = normalizeCausalIdentifierField({
    binding,
    path,
    snakeKey: 'tool_span_id',
    camelKey: 'toolSpanId',
    label: 'tool_span_id',
  });
  if (!toolSpan.ok) return toolSpan;

  const confidence = normalizeCausalNumericField({
    binding,
    path,
    snakeKey: 'attribution_confidence',
    camelKey: 'attributionConfidence',
    label: 'attribution_confidence',
  });
  if (!confidence.ok) return confidence;

  return {
    ok: true,
    entry: {
      path,
      spanId: span.value,
      spanFieldPath: span.fieldPath,
      parentSpanId: parentSpan.value,
      parentSpanFieldPath: parentSpan.fieldPath,
      toolSpanId: toolSpan.value,
      toolSpanFieldPath: toolSpan.fieldPath,
      phase: binding.phase,
      phaseFieldPath: `${path}.phase`,
      attributionConfidence: confidence.value,
      attributionConfidenceFieldPath: confidence.fieldPath,
      payloadTimestamp: options.payloadTimestamp,
      payloadTimestampFieldPath:
        options.payloadTimestampFieldPath ?? `${path}.timestamp`,
      envelopeIssuedAt: options.envelopeIssuedAt,
      envelopeIssuedAtFieldPath:
        options.envelopeIssuedAtFieldPath ?? `${path}.issued_at`,
    },
  };
}

function collectCausalBindingEntries(
  payload: ProofBundlePayload
):
  | { ok: true; entries: CausalBindingEntry[] }
  | {
      ok: false;
      code: CausalBindingNormalizationCode;
      message: string;
      field: string;
    } {
  const out: CausalBindingEntry[] = [];

  if (payload.receipts !== undefined) {
    for (let i = 0; i < payload.receipts.length; i++) {
      const envelope = payload.receipts[i];
      const binding = envelope?.payload?.binding;
      if (!isObjectRecord(binding)) continue;

      const entry = toCausalBindingEntry(
        binding,
        `payload.receipts[${i}].payload.binding`,
        {
          payloadTimestamp: envelope?.payload?.timestamp,
          payloadTimestampFieldPath: `payload.receipts[${i}].payload.timestamp`,
          envelopeIssuedAt: envelope?.issued_at,
          envelopeIssuedAtFieldPath: `payload.receipts[${i}].issued_at`,
        }
      );
      if (!entry.ok) return entry;
      if (entry.entry) out.push(entry.entry);
    }
  }

  if (payload.web_receipts !== undefined) {
    for (let i = 0; i < payload.web_receipts.length; i++) {
      const envelope = payload.web_receipts[i];
      const binding = envelope?.payload?.binding;
      if (!isObjectRecord(binding)) continue;

      const entry = toCausalBindingEntry(
        binding,
        `payload.web_receipts[${i}].payload.binding`,
        {
          payloadTimestamp: envelope?.payload?.timestamp,
          payloadTimestampFieldPath: `payload.web_receipts[${i}].payload.timestamp`,
          envelopeIssuedAt: envelope?.issued_at,
          envelopeIssuedAtFieldPath: `payload.web_receipts[${i}].issued_at`,
        }
      );
      if (!entry.ok) return entry;
      if (entry.entry) out.push(entry.entry);
    }
  }

  if (payload.vir_receipts !== undefined) {
    for (let i = 0; i < payload.vir_receipts.length; i++) {
      const raw = payload.vir_receipts[i] as unknown;
      if (!isObjectRecord(raw)) continue;

      const hasEnvelopePayload = isObjectRecord(raw.payload);
      const maybePayload = (hasEnvelopePayload ? raw.payload : raw) as Record<
        string,
        unknown
      >;
      const binding = isObjectRecord(maybePayload.binding)
        ? maybePayload.binding
        : null;

      if (!binding) continue;

      const bindingPath = hasEnvelopePayload
        ? `payload.vir_receipts[${i}].payload.binding`
        : `payload.vir_receipts[${i}].binding`;

      const entry = toCausalBindingEntry(binding, bindingPath, {
        payloadTimestamp: maybePayload.timestamp,
        payloadTimestampFieldPath: hasEnvelopePayload
          ? `payload.vir_receipts[${i}].payload.timestamp`
          : `payload.vir_receipts[${i}].timestamp`,
        envelopeIssuedAt: hasEnvelopePayload ? raw.issued_at : undefined,
        envelopeIssuedAtFieldPath: `payload.vir_receipts[${i}].issued_at`,
      });
      if (!entry.ok) return entry;
      if (entry.entry) out.push(entry.entry);
    }
  }

  return { ok: true, entries: out };
}

interface CausalSupportBindingEntry {
  spanId?: string;
  spanFieldPath: string;
  parentSpanId?: string;
  parentSpanFieldPath: string;
  toolSpanId?: string;
  toolSpanFieldPath: string;
}

function normalizeCausalSupportBinding(
  binding: Record<string, unknown>,
  path: string
):
  | { ok: true; entry: CausalSupportBindingEntry }
  | {
      ok: false;
      code: CausalBindingNormalizationCode;
      message: string;
      field: string;
    } {
  const span = normalizeCausalIdentifierField({
    binding,
    path,
    snakeKey: 'span_id',
    camelKey: 'spanId',
    label: 'span_id',
  });
  if (!span.ok) return span;

  const parentSpan = normalizeCausalIdentifierField({
    binding,
    path,
    snakeKey: 'parent_span_id',
    camelKey: 'parentSpanId',
    label: 'parent_span_id',
  });
  if (!parentSpan.ok) return parentSpan;

  const toolSpan = normalizeCausalIdentifierField({
    binding,
    path,
    snakeKey: 'tool_span_id',
    camelKey: 'toolSpanId',
    label: 'tool_span_id',
  });
  if (!toolSpan.ok) return toolSpan;

  return {
    ok: true,
    entry: {
      spanId: span.value,
      spanFieldPath: span.fieldPath,
      parentSpanId: parentSpan.value,
      parentSpanFieldPath: parentSpan.fieldPath,
      toolSpanId: toolSpan.value,
      toolSpanFieldPath: toolSpan.fieldPath,
    },
  };
}

function validateCausalAnchoredSupportReceipts(args: {
  receipts: Array<SideEffectReceiptPayload | HumanApprovalReceiptPayload> | undefined;
  knownSpanIds: Set<string>;
  pathPrefix: 'payload.side_effect_receipts' | 'payload.human_approval_receipts';
  orphanCode: 'CAUSAL_SIDE_EFFECT_ORPHANED' | 'CAUSAL_HUMAN_APPROVAL_ORPHANED';
}):
  | { ok: true }
  | {
      ok: false;
      code:
        | 'CAUSAL_SIDE_EFFECT_ORPHANED'
        | 'CAUSAL_HUMAN_APPROVAL_ORPHANED'
        | CausalBindingNormalizationCode;
      message: string;
      field: string;
    } {
  if (!args.receipts || args.receipts.length === 0) {
    return { ok: true };
  }

  for (let i = 0; i < args.receipts.length; i++) {
    const record = args.receipts[i] as unknown;
    if (!isObjectRecord(record)) {
      return {
        ok: false,
        code: args.orphanCode,
        message: `${args.pathPrefix}[${i}] is malformed and cannot be causally anchored`,
        field: `${args.pathPrefix}[${i}]`,
      };
    }

    const binding = isObjectRecord(record.binding) ? record.binding : null;
    if (!binding) {
      return {
        ok: false,
        code: args.orphanCode,
        message: `${args.pathPrefix}[${i}] missing binding object for causal anchoring`,
        field: `${args.pathPrefix}[${i}].binding`,
      };
    }

    const normalized = normalizeCausalSupportBinding(
      binding,
      `${args.pathPrefix}[${i}].binding`
    );
    if (!normalized.ok) {
      return normalized;
    }

    const anchorCandidate =
      normalized.entry.toolSpanId ??
      normalized.entry.parentSpanId ??
      normalized.entry.spanId;

    if (!anchorCandidate || !args.knownSpanIds.has(anchorCandidate)) {
      return {
        ok: false,
        code: args.orphanCode,
        message:
          `${args.pathPrefix}[${i}] is not anchored to a known causal span lineage`,
        field:
          normalized.entry.toolSpanId !== undefined
            ? normalized.entry.toolSpanFieldPath
            : normalized.entry.parentSpanId !== undefined
              ? normalized.entry.parentSpanFieldPath
              : normalized.entry.spanFieldPath,
      };
    }
  }

  return { ok: true };
}

function validateCausalBindingEntries(
  entries: CausalBindingEntry[],
  connectivityMode: 'observe' | 'warn' | 'enforce'
):
  | { ok: true; knownSpanIds: Set<string> }
  | {
      ok: false;
      code:
        | 'CAUSAL_REFERENCE_DANGLING'
        | 'CAUSAL_CYCLE_DETECTED'
        | 'CAUSAL_PHASE_INVALID'
        | 'CAUSAL_PHASE_TRANSITION_INVALID'
        | 'CAUSAL_CLOCK_CONTRADICTION'
        | 'CAUSAL_CONFIDENCE_OUT_OF_RANGE'
        | 'CAUSAL_CONFIDENCE_EVIDENCE_INCONSISTENT'
        | 'CAUSAL_SPAN_REUSE_CONFLICT'
        | 'CAUSAL_GRAPH_DISCONNECTED';
      message: string;
      field: string;
    } {
  if (entries.length === 0) {
    return { ok: true, knownSpanIds: new Set<string>() };
  }

  const knownSpanIds = new Set<string>();
  for (const entry of entries) {
    if (entry.spanId) knownSpanIds.add(entry.spanId);
  }

  for (const entry of entries) {
    const payloadTimestamp = entry.payloadTimestamp;
    const envelopeIssuedAt = entry.envelopeIssuedAt;

    if (
      payloadTimestamp !== undefined &&
      (typeof payloadTimestamp !== 'string' || !isValidIsoDate(payloadTimestamp))
    ) {
      return {
        ok: false,
        code: 'CAUSAL_CLOCK_CONTRADICTION',
        message: 'binding-coupled payload.timestamp must be a valid ISO-8601 date-time string',
        field: entry.payloadTimestampFieldPath,
      };
    }

    if (
      envelopeIssuedAt !== undefined &&
      (typeof envelopeIssuedAt !== 'string' || !isValidIsoDate(envelopeIssuedAt))
    ) {
      return {
        ok: false,
        code: 'CAUSAL_CLOCK_CONTRADICTION',
        message: 'binding-coupled envelope.issued_at must be a valid ISO-8601 date-time string',
        field: entry.envelopeIssuedAtFieldPath,
      };
    }

    if (
      typeof payloadTimestamp === 'string' &&
      typeof envelopeIssuedAt === 'string' &&
      Date.parse(payloadTimestamp) > Date.parse(envelopeIssuedAt)
    ) {
      return {
        ok: false,
        code: 'CAUSAL_CLOCK_CONTRADICTION',
        message:
          'binding-coupled payload.timestamp must be less than or equal to envelope.issued_at',
        field: entry.payloadTimestampFieldPath,
      };
    }

    if (entry.phase !== undefined) {
      const phase = entry.phase;
      if (typeof phase !== 'string' || !ALLOWED_CAUSAL_PHASES.has(phase)) {
        return {
          ok: false,
          code: 'CAUSAL_PHASE_INVALID',
          message:
            'binding.phase must be one of setup|planning|reasoning|execution|observation|reflection|teardown',
          field: entry.phaseFieldPath,
        };
      }
    }

    if (entry.attributionConfidence !== undefined) {
      const confidence = entry.attributionConfidence;
      if (
        typeof confidence !== 'number' ||
        !Number.isFinite(confidence) ||
        confidence < 0 ||
        confidence > 1
      ) {
        return {
          ok: false,
          code: 'CAUSAL_CONFIDENCE_OUT_OF_RANGE',
          message:
            'binding.attribution_confidence must be a finite number in inclusive range [0.0, 1.0]',
          field: entry.attributionConfidenceFieldPath,
        };
      }
    }

    if (entry.parentSpanId && !knownSpanIds.has(entry.parentSpanId)) {
      return {
        ok: false,
        code: 'CAUSAL_REFERENCE_DANGLING',
        message: `binding.parent_span_id references unknown span_id: ${entry.parentSpanId}`,
        field: entry.parentSpanFieldPath,
      };
    }

    if (entry.toolSpanId && !knownSpanIds.has(entry.toolSpanId)) {
      return {
        ok: false,
        code: 'CAUSAL_REFERENCE_DANGLING',
        message: `binding.tool_span_id references unknown span_id: ${entry.toolSpanId}`,
        field: entry.toolSpanFieldPath,
      };
    }
  }

  const spanSemanticBySpanId = new Map<
    string,
    {
      parentSpanId?: string;
      toolSpanId?: string;
      phase?: string;
      phaseFieldPath: string;
      attributionConfidence?: number;
      spanFieldPath: string;
      timestampMs?: number;
      timestampFieldPath: string;
    }
  >();

  for (const entry of entries) {
    if (!entry.spanId) continue;

    const phase = typeof entry.phase === 'string' ? entry.phase : undefined;
    const attributionConfidence =
      typeof entry.attributionConfidence === 'number'
        ? entry.attributionConfidence
        : undefined;

    const payloadTimestampMs =
      typeof entry.payloadTimestamp === 'string'
        ? Date.parse(entry.payloadTimestamp)
        : undefined;
    const envelopeIssuedAtMs =
      typeof entry.envelopeIssuedAt === 'string'
        ? Date.parse(entry.envelopeIssuedAt)
        : undefined;

    const causalTimestampMs = payloadTimestampMs ?? envelopeIssuedAtMs;
    const causalTimestampFieldPath =
      payloadTimestampMs !== undefined
        ? entry.payloadTimestampFieldPath
        : entry.envelopeIssuedAtFieldPath;

    const prev = spanSemanticBySpanId.get(entry.spanId);
    if (!prev) {
      spanSemanticBySpanId.set(entry.spanId, {
        parentSpanId: entry.parentSpanId,
        toolSpanId: entry.toolSpanId,
        phase,
        phaseFieldPath: entry.phaseFieldPath,
        attributionConfidence,
        spanFieldPath: entry.spanFieldPath,
        timestampMs: causalTimestampMs,
        timestampFieldPath: causalTimestampFieldPath,
      });
      continue;
    }

    const conflicts: string[] = [];

    if (
      prev.parentSpanId !== undefined &&
      entry.parentSpanId !== undefined &&
      prev.parentSpanId !== entry.parentSpanId
    ) {
      conflicts.push('parent_span_id');
    }

    if (
      prev.toolSpanId !== undefined &&
      entry.toolSpanId !== undefined &&
      prev.toolSpanId !== entry.toolSpanId
    ) {
      conflicts.push('tool_span_id');
    }

    if (prev.phase !== undefined && phase !== undefined && prev.phase !== phase) {
      conflicts.push('phase');
    }

    if (
      prev.attributionConfidence !== undefined &&
      attributionConfidence !== undefined &&
      !Object.is(prev.attributionConfidence, attributionConfidence)
    ) {
      conflicts.push('attribution_confidence');
    }

    if (
      prev.timestampMs !== undefined &&
      causalTimestampMs !== undefined &&
      prev.timestampMs !== causalTimestampMs
    ) {
      return {
        ok: false,
        code: 'CAUSAL_CLOCK_CONTRADICTION',
        message:
          `span_id ${entry.spanId} has inconsistent causal timestamps across bindings`,
        field: causalTimestampFieldPath,
      };
    }

    if (conflicts.length > 0) {
      return {
        ok: false,
        code: 'CAUSAL_SPAN_REUSE_CONFLICT',
        message: `span_id ${entry.spanId} reused with incompatible semantics for: ${conflicts.join(', ')}`,
        field: entry.spanFieldPath,
      };
    }
  }

  for (const [spanId, semantic] of spanSemanticBySpanId.entries()) {
    const childPhase = semantic.phase;

    const checkTemporalAndPhase = (
      relation:
        | {
            relationName: 'parent_span_id' | 'tool_span_id';
            parentSpanId: string;
          }
        | null
    ):
      | { ok: true }
      | {
          ok: false;
          code: 'CAUSAL_CLOCK_CONTRADICTION' | 'CAUSAL_PHASE_TRANSITION_INVALID';
          message: string;
          field: string;
        } => {
      if (!relation) return { ok: true };

      const parentSemantic = spanSemanticBySpanId.get(relation.parentSpanId);
      if (!parentSemantic) return { ok: true };

      if (
        semantic.timestampMs !== undefined &&
        parentSemantic.timestampMs !== undefined &&
        semantic.timestampMs < parentSemantic.timestampMs
      ) {
        return {
          ok: false,
          code: 'CAUSAL_CLOCK_CONTRADICTION',
          message:
            `span_id ${spanId} occurs before ${relation.relationName} ${relation.parentSpanId}`,
          field: semantic.timestampFieldPath,
        };
      }

      if (
        childPhase !== undefined &&
        parentSemantic.phase !== undefined &&
        !isAllowedCausalPhaseTransition(parentSemantic.phase, childPhase)
      ) {
        return {
          ok: false,
          code: 'CAUSAL_PHASE_TRANSITION_INVALID',
          message:
            `invalid causal phase transition ${parentSemantic.phase} -> ${childPhase} for span_id ${spanId}`,
          field: semantic.phaseFieldPath,
        };
      }

      return { ok: true };
    };

    const parentCheck = checkTemporalAndPhase(
      semantic.parentSpanId
        ? {
            relationName: 'parent_span_id',
            parentSpanId: semantic.parentSpanId,
          }
        : null
    );
    if (!parentCheck.ok) {
      return parentCheck;
    }

    const toolCheck = checkTemporalAndPhase(
      semantic.toolSpanId
        ? {
            relationName: 'tool_span_id',
            parentSpanId: semantic.toolSpanId,
          }
        : null
    );
    if (!toolCheck.ok) {
      return toolCheck;
    }
  }

  const parentBySpan = new Map<string, string>();
  const parentFieldBySpan = new Map<string, string>();

  for (const entry of entries) {
    if (!entry.spanId || !entry.parentSpanId) continue;

    if (!parentBySpan.has(entry.spanId)) {
      parentBySpan.set(entry.spanId, entry.parentSpanId);
      parentFieldBySpan.set(entry.spanId, entry.parentSpanFieldPath);
    }
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();

  const detectCycle = (spanId: string): string | null => {
    if (visiting.has(spanId)) {
      return spanId;
    }

    if (visited.has(spanId)) {
      return null;
    }

    visiting.add(spanId);

    const parent = parentBySpan.get(spanId);
    if (parent) {
      const cycleAt = detectCycle(parent);
      if (cycleAt) {
        return cycleAt;
      }
    }

    visiting.delete(spanId);
    visited.add(spanId);
    return null;
  };

  for (const spanId of parentBySpan.keys()) {
    const cycleAt = detectCycle(spanId);
    if (!cycleAt) continue;

    return {
      ok: false,
      code: 'CAUSAL_CYCLE_DETECTED',
      message: `causal parent_span_id cycle detected at span_id: ${cycleAt}`,
      field: parentFieldBySpan.get(cycleAt) ?? parentFieldBySpan.get(spanId) ?? 'payload',
    };
  }

  const inboundReferenceCountBySpan = new Map<string, number>();
  for (const entry of entries) {
    if (entry.parentSpanId) {
      inboundReferenceCountBySpan.set(
        entry.parentSpanId,
        (inboundReferenceCountBySpan.get(entry.parentSpanId) ?? 0) + 1
      );
    }

    if (entry.toolSpanId) {
      inboundReferenceCountBySpan.set(
        entry.toolSpanId,
        (inboundReferenceCountBySpan.get(entry.toolSpanId) ?? 0) + 1
      );
    }
  }

  for (const entry of entries) {
    if (entry.attributionConfidence === undefined) continue;

    const confidence = entry.attributionConfidence;
    if (typeof confidence !== 'number') continue;

    const isDirectLineageProvable =
      entry.parentSpanId !== undefined ||
      entry.toolSpanId !== undefined ||
      (entry.spanId !== undefined &&
        (inboundReferenceCountBySpan.get(entry.spanId) ?? 0) > 0);

    const evidenceClass = isDirectLineageProvable
      ? 'direct'
      : entry.spanId !== undefined
        ? 'inferred'
        : 'unattributed';

    const maxAllowedConfidence =
      evidenceClass === 'direct'
        ? 1.0
        : evidenceClass === 'inferred'
          ? 0.5
          : 0.0;

    if (confidence > maxAllowedConfidence) {
      return {
        ok: false,
        code: 'CAUSAL_CONFIDENCE_EVIDENCE_INCONSISTENT',
        message:
          `binding.attribution_confidence=${confidence} exceeds max ${maxAllowedConfidence.toFixed(1)} for ${evidenceClass} causal evidence class`,
        field: entry.attributionConfidenceFieldPath,
      };
    }
  }

  if (connectivityMode === 'enforce' && knownSpanIds.size > 0) {
    const semanticBySpan = new Map<
      string,
      {
        parentSpanId?: string;
        toolSpanId?: string;
        fieldPath: string;
      }
    >();

    for (const entry of entries) {
      if (!entry.spanId) continue;
      if (!semanticBySpan.has(entry.spanId)) {
        semanticBySpan.set(entry.spanId, {
          parentSpanId: entry.parentSpanId,
          toolSpanId: entry.toolSpanId,
          fieldPath: entry.spanFieldPath,
        });
      }
    }

    const roots = new Set<string>();
    for (const [spanId, semantic] of semanticBySpan.entries()) {
      if (semantic.parentSpanId === undefined && semantic.toolSpanId === undefined) {
        roots.add(spanId);
      }
    }

    if (roots.size === 0) {
      const firstField = semanticBySpan.values().next().value?.fieldPath ?? 'payload';
      return {
        ok: false,
        code: 'CAUSAL_GRAPH_DISCONNECTED',
        message: 'causal graph has no valid root lineage in enforce mode',
        field: firstField,
      };
    }

    const reachesRootMemo = new Map<string, boolean>();
    const reachesRoot = (spanId: string, visiting = new Set<string>()): boolean => {
      if (roots.has(spanId)) return true;
      if (reachesRootMemo.has(spanId)) return reachesRootMemo.get(spanId) === true;
      if (visiting.has(spanId)) return false;

      visiting.add(spanId);
      const semantic = semanticBySpan.get(spanId);
      if (!semantic) {
        reachesRootMemo.set(spanId, false);
        return false;
      }

      const parentOk =
        semantic.parentSpanId !== undefined
          ? reachesRoot(semantic.parentSpanId, new Set(visiting))
          : false;
      const toolOk =
        semantic.toolSpanId !== undefined
          ? reachesRoot(semantic.toolSpanId, new Set(visiting))
          : false;

      const ok = parentOk || toolOk;
      reachesRootMemo.set(spanId, ok);
      return ok;
    };

    for (const [spanId, semantic] of semanticBySpan.entries()) {
      if (roots.has(spanId)) continue;
      if (!reachesRoot(spanId)) {
        return {
          ok: false,
          code: 'CAUSAL_GRAPH_DISCONNECTED',
          message: `non-root span_id ${spanId} does not connect to a valid root lineage`,
          field: semantic.fieldPath,
        };
      }
    }

    const neighbors = new Map<string, Set<string>>();
    for (const spanId of semanticBySpan.keys()) {
      neighbors.set(spanId, new Set<string>());
    }

    for (const [spanId, semantic] of semanticBySpan.entries()) {
      if (semantic.parentSpanId && semanticBySpan.has(semantic.parentSpanId)) {
        neighbors.get(spanId)?.add(semantic.parentSpanId);
        neighbors.get(semantic.parentSpanId)?.add(spanId);
      }

      if (semantic.toolSpanId && semanticBySpan.has(semantic.toolSpanId)) {
        neighbors.get(spanId)?.add(semantic.toolSpanId);
        neighbors.get(semantic.toolSpanId)?.add(spanId);
      }
    }

    const first = semanticBySpan.keys().next().value as string | undefined;
    if (first) {
      const visitedComponent = new Set<string>();
      const stack = [first];

      while (stack.length > 0) {
        const current = stack.pop();
        if (!current || visitedComponent.has(current)) continue;
        visitedComponent.add(current);

        const next = neighbors.get(current);
        if (!next) continue;
        for (const n of next) {
          if (!visitedComponent.has(n)) stack.push(n);
        }
      }

      if (visitedComponent.size !== semanticBySpan.size) {
        const disconnectedSpanId = [...semanticBySpan.keys()].find(
          (id) => !visitedComponent.has(id)
        );
        return {
          ok: false,
          code: 'CAUSAL_GRAPH_DISCONNECTED',
          message: 'causal graph contains disconnected components in enforce mode',
          field:
            (disconnectedSpanId && semanticBySpan.get(disconnectedSpanId)?.fieldPath) ||
            'payload',
        };
      }
    }
  }

  return { ok: true, knownSpanIds };
}

interface ParsedVirReceipt {
  payload: VirReceiptPayload;
  envelope?: VirReceiptEnvelope;
}

function parseVirReceiptEntry(entry: unknown):
  | { ok: true; parsed: ParsedVirReceipt }
  | { ok: false; error: string } {
  const record = isObjectRecord(entry) ? entry : null;
  if (!record) {
    return { ok: false, error: 'Malformed VIR receipt entry' };
  }

  if (record.envelope_type === 'vir_receipt') {
    const envelopeValidationV2 = validateVirEnvelopeV2(record);
    if (envelopeValidationV2.valid) {
      const envelope = record as unknown as VirReceiptEnvelope;
      return {
        ok: true,
        parsed: {
          payload: envelope.payload,
          envelope,
        },
      };
    }

    const envelopeValidationV1 = validateVirEnvelopeV1(record);
    if (!envelopeValidationV1.valid) {
      return { ok: false, error: envelopeValidationV1.message };
    }

    const envelope = record as unknown as VirReceiptEnvelope;
    const payloadValidation = validateVirV1(envelope.payload);
    if (!payloadValidation.valid) {
      return { ok: false, error: payloadValidation.message };
    }

    return {
      ok: true,
      parsed: {
        payload: envelope.payload,
        envelope,
      },
    };
  }

  const payloadValidationV2 = validateVirV2(record);
  if (payloadValidationV2.valid) {
    return {
      ok: true,
      parsed: {
        payload: record as unknown as VirReceiptPayload,
      },
    };
  }

  const payloadValidationV1 = validateVirV1(record);
  if (!payloadValidationV1.valid) {
    return { ok: false, error: payloadValidationV1.message };
  }

  return {
    ok: true,
    parsed: {
      payload: record as unknown as VirReceiptPayload,
    },
  };
}

function parseGatewayReceiptEntry(entry: unknown):
  | { ok: true; payload: GatewayReceiptPayload }
  | { ok: false } {
  const record = isObjectRecord(entry) ? entry : null;
  if (!record || record.envelope_type !== 'gateway_receipt') {
    return { ok: false };
  }

  const payload = isObjectRecord(record.payload) ? record.payload : null;
  if (!payload) {
    return { ok: false };
  }

  return {
    ok: true,
    payload: payload as unknown as GatewayReceiptPayload,
  };
}

function parseWebReceiptEntry(entry: unknown):
  | {
      ok: true;
      envelope: SignedEnvelope<WebReceiptPayload>;
      payload: WebReceiptPayload;
    }
  | { ok: false } {
  const record = isObjectRecord(entry) ? entry : null;
  if (!record || record.envelope_type !== 'web_receipt') {
    return { ok: false };
  }

  const payload = isObjectRecord(record.payload) ? record.payload : null;
  if (!payload) {
    return { ok: false };
  }

  return {
    ok: true,
    envelope: record as unknown as SignedEnvelope<WebReceiptPayload>,
    payload: payload as unknown as WebReceiptPayload,
  };
}

function normalizePositiveInteger(value: number | undefined): number | undefined {
  if (!Number.isFinite(value) || value === undefined) return undefined;
  if (!Number.isInteger(value) || value <= 0) return undefined;
  return value;
}

function normalizeWitnessedWebPolicyMode(
  mode: ProofBundleVerifierOptions['witnessed_web_policy_mode']
): WitnessedWebPolicyMode {
  return mode === 'enforce' ? 'enforce' : 'warn';
}

function normalizeWitnessedWebTransparencyMode(
  mode: ProofBundleVerifierOptions['witnessed_web_transparency_mode']
): WitnessedWebTransparencyMode {
  if (mode === 'warn' || mode === 'enforce' || mode === 'optional') {
    return mode;
  }
  return 'optional';
}

function normalizeIsoTimestampToMs(value: string | undefined): number | undefined {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return undefined;
  }

  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : undefined;
}

function normalizeCausalConnectivityMode(
  mode: ProofBundleVerifierOptions['causal_connectivity_mode']
): 'observe' | 'warn' | 'enforce' {
  if (mode === 'observe' || mode === 'warn' || mode === 'enforce') {
    return mode;
  }
  return 'enforce';
}

function normalizeCoverageEnforcementPhase(
  phase: ProofBundleVerifierOptions['coverage_enforcement_phase']
): 'observe' | 'warn' | 'enforce' {
  if (phase === 'observe' || phase === 'warn' || phase === 'enforce') {
    return phase;
  }
  return 'observe';
}

type ResolvedCausalPolicySnapshot = {
  profile: 'compat' | 'strict';
  causal_connectivity_mode: 'observe' | 'warn' | 'enforce';
  coverage_enforcement_phase: 'observe' | 'warn' | 'enforce';
};

type CausalPolicyResolution =
  | { ok: true; snapshot: ResolvedCausalPolicySnapshot }
  | {
      ok: false;
      code: 'CAUSAL_POLICY_PROFILE_INVALID' | 'CAUSAL_POLICY_PROFILE_DOWNGRADE';
      message: string;
      field: string;
      snapshot?: ResolvedCausalPolicySnapshot;
    };

function resolveCausalPolicySnapshot(
  options: ProofBundleVerifierOptions
): CausalPolicyResolution {
  const rawProfile =
    options.causal_policy_profile === undefined
      ? 'compat'
      : options.causal_policy_profile;

  if (rawProfile !== 'compat' && rawProfile !== 'strict') {
    return {
      ok: false,
      code: 'CAUSAL_POLICY_PROFILE_INVALID',
      message:
        'causal_policy_profile must be one of: compat, strict',
      field: 'options.causal_policy_profile',
    };
  }

  const requestedConnectivity = normalizeCausalConnectivityMode(
    options.causal_connectivity_mode
  );
  const requestedCoverage = normalizeCoverageEnforcementPhase(
    options.coverage_enforcement_phase
  );

  if (rawProfile === 'strict') {
    const downgradeFields: string[] = [];

    if (
      options.causal_connectivity_mode !== undefined &&
      requestedConnectivity !== 'enforce'
    ) {
      downgradeFields.push('causal_connectivity_mode');
    }

    if (
      options.coverage_enforcement_phase !== undefined &&
      requestedCoverage !== 'enforce'
    ) {
      downgradeFields.push('coverage_enforcement_phase');
    }

    const lockedSnapshot: ResolvedCausalPolicySnapshot = {
      profile: 'strict',
      causal_connectivity_mode: 'enforce',
      coverage_enforcement_phase: 'enforce',
    };

    if (downgradeFields.length > 0) {
      return {
        ok: false,
        code: 'CAUSAL_POLICY_PROFILE_DOWNGRADE',
        message:
          `strict causal policy profile rejects downgrade override(s): ${downgradeFields.join(', ')}`,
        field: `options.${downgradeFields[0]}`,
        snapshot: lockedSnapshot,
      };
    }

    return {
      ok: true,
      snapshot: lockedSnapshot,
    };
  }

  return {
    ok: true,
    snapshot: {
      profile: 'compat',
      causal_connectivity_mode: requestedConnectivity,
      coverage_enforcement_phase: requestedCoverage,
    },
  };
}

function extractWebReceiptInclusionProof(payload: WebReceiptPayload): unknown {
  if (isObjectRecord(payload.transparency) && payload.transparency.inclusion_proof !== undefined) {
    return payload.transparency.inclusion_proof;
  }

  const metadata = isObjectRecord(payload.metadata) ? payload.metadata : null;
  const metadataTransparency = metadata && isObjectRecord(metadata.transparency)
    ? metadata.transparency
    : null;

  if (metadataTransparency && metadataTransparency.inclusion_proof !== undefined) {
    return metadataTransparency.inclusion_proof;
  }

  return undefined;
}

async function computeWebReceiptTransparencyLeafHash(
  payload: WebReceiptPayload
): Promise<string> {
  const binding = payload.binding;

  return computeHash(
    {
      leaf_version: 'web_receipt_v1',
      receipt_version: payload.receipt_version,
      receipt_id: payload.receipt_id,
      witness_id: payload.witness_id,
      source: payload.source,
      request_hash_b64u: payload.request_hash_b64u,
      response_hash_b64u: payload.response_hash_b64u,
      session_hash_b64u: payload.session_hash_b64u ?? null,
      timestamp: payload.timestamp,
      binding: binding
        ? {
            run_id: binding.run_id ?? null,
            event_hash_b64u: binding.event_hash_b64u ?? null,
            nonce: binding.nonce ?? null,
            subject: binding.subject ?? binding.subject_did ?? null,
            scope: binding.scope ?? binding.scope_hash_b64u ?? null,
            job_id: binding.job_id ?? null,
            contract_id: binding.contract_id ?? null,
            jurisdiction: binding.jurisdiction ?? null,
            policy_hash: binding.policy_hash ?? null,
            token_scope_hash_b64u: binding.token_scope_hash_b64u ?? null,
          }
        : null,
    },
    'SHA-256'
  );
}

function normalizeVirConflictPolicyMode(
  mode: ProofBundleVerifierOptions['vir_conflict_policy_mode']
): 'strict' | 'cap' {
  return mode === 'cap' ? 'cap' : 'strict';
}

function normalizeVirCorroborationSkewMs(value: number | undefined): number {
  if (!Number.isFinite(value) || value === undefined || value < 0) {
    return DEFAULT_VIR_CORROBORATION_MAX_SKEW_MS;
  }
  return value;
}

async function verifyVirReceiptEntry(
  entry: unknown,
  bindingContext: ReceiptBindingContext | null,
  expectedBountyNonce: string | null,
  expectedSubject: string | null,
  expectedScope: string | null,
): Promise<{
  valid: boolean;
  signature_valid: boolean;
  binding_valid: boolean;
  source?: VirSource;
  receipt_id?: string;
  risk_flags?: string[];
  code?: VirFailureCode;
  error?: string;
}> {
  const parsed = parseVirReceiptEntry(entry);
  if (!parsed.ok) {
    return {
      valid: false,
      signature_valid: false,
      binding_valid: false,
      error: parsed.error,
    };
  }

  const { payload, envelope } = parsed.parsed;
  const source = payload.source;

  let signatureValid = false;
  if (envelope) {
    let computedHash: string;
    try {
      computedHash = await computeHash(envelope.payload, envelope.hash_algorithm);
    } catch {
      return {
        valid: false,
        signature_valid: false,
        binding_valid: false,
        source,
        receipt_id: payload.receipt_id,
        error: 'VIR hash computation failed',
      };
    }

    if (computedHash !== envelope.payload_hash_b64u) {
      return {
        valid: false,
        signature_valid: false,
        binding_valid: false,
        source,
        receipt_id: payload.receipt_id,
        error: 'VIR payload hash mismatch',
      };
    }

    const publicKeyBytes = extractPublicKeyFromDidKey(envelope.signer_did);
    if (!publicKeyBytes) {
      return {
        valid: false,
        signature_valid: false,
        binding_valid: false,
        source,
        receipt_id: payload.receipt_id,
        error: 'Invalid VIR signer DID',
      };
    }

    try {
      const signatureBytes = base64UrlDecode(envelope.signature_b64u);
      const messageBytes = new TextEncoder().encode(envelope.payload_hash_b64u);
      signatureValid = await verifySignature(
        envelope.algorithm,
        publicKeyBytes,
        signatureBytes,
        messageBytes,
      );
    } catch {
      signatureValid = false;
    }

    if (!signatureValid) {
      return {
        valid: false,
        signature_valid: false,
        binding_valid: false,
        source,
        receipt_id: payload.receipt_id,
        error: 'VIR signature verification failed',
      };
    }

    if (envelope.signer_did !== payload.agent_did) {
      return {
        valid: false,
        signature_valid: true,
        binding_valid: false,
        source,
        receipt_id: payload.receipt_id,
        error: 'VIR signer_did does not match payload.agent_did',
      };
    }
  }

  if (!bindingContext) {
    return {
      valid: false,
      signature_valid: signatureValid,
      binding_valid: false,
      source,
      receipt_id: payload.receipt_id,
      code: 'ERR_BINDING_RUN_ID_MISMATCH',
      error: 'VIR binding cannot be verified: proof bundle event_chain is missing or invalid',
    };
  }

  const vir = await validateVirReceiptCore({
    payload,
    bindingContext,
    expected: {
      nonce: expectedBountyNonce,
      subject: expectedSubject,
      scope: expectedScope,
    },
  });

  if (!vir.valid) {
    return {
      valid: false,
      signature_valid: signatureValid,
      binding_valid: false,
      source: vir.source ?? source,
      receipt_id: payload.receipt_id,
      risk_flags: vir.riskFlags.length > 0 ? vir.riskFlags : undefined,
      code: vir.code,
      error: vir.message ?? vir.code,
    };
  }

  return {
    valid: true,
    signature_valid: signatureValid,
    binding_valid: true,
    source: vir.source ?? source,
    receipt_id: payload.receipt_id,
    risk_flags: vir.riskFlags.length > 0 ? vir.riskFlags : undefined,
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
  vir_receipts_valid?: boolean;
  web_receipts_valid?: boolean;
  coverage_attestations_valid?: boolean;
  execution_attestations_valid?: boolean;
  attestations_valid?: boolean;
}): TrustTier {
  if (!components.envelope_valid) {
    return 'unknown';
  }

  // Full trust: all components present and valid
  if (
    components.urm_valid &&
    components.event_chain_valid &&
    (components.receipts_valid || components.vir_receipts_valid || components.web_receipts_valid) &&
    (components.attestations_valid || components.execution_attestations_valid)
  ) {
    return 'full';
  }

  // Attested: has valid attestations
  if (components.attestations_valid) {
    return 'attested';
  }

  // Verified: has valid event chain or receipts
  if (
    components.event_chain_valid ||
    components.receipts_valid ||
    components.vir_receipts_valid ||
    components.web_receipts_valid
  ) {
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
  vir_receipts_verified_count?: number;
  vir_best_source?: VirSource;
  web_receipts_verified_count?: number;
  attestations_verified_count?: number;
  execution_attestations_verified_count?: number;
  tee_execution_verified_count?: number;
}): ProofTier {
  if (!components.envelope_valid) return 'unknown';

  // Explicit tee path (CVF-US-064) wins when verified tee_execution evidence exists.
  if ((components.tee_execution_verified_count ?? 0) > 0) {
    return 'tee';
  }

  // Higher tiers win. Proof tiers are based on *at least one* verified component,
  // not on the all-or-nothing `*_valid` booleans.
  if (
    (components.attestations_verified_count ?? 0) > 0 ||
    (components.execution_attestations_verified_count ?? 0) > 0
  ) {
    return 'sandbox';
  }

  if ((components.receipts_verified_count ?? 0) > 0) return 'gateway';

  if ((components.vir_receipts_verified_count ?? 0) > 0) {
    if (
      components.vir_best_source === 'tls_decrypt' ||
      components.vir_best_source === 'gateway' ||
      components.vir_best_source === 'interpose'
    ) {
      return 'gateway';
    }
  }

  if ((components.web_receipts_verified_count ?? 0) > 0) {
    return 'witnessed_web';
  }

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

  const causalPolicy = resolveCausalPolicySnapshot(options);
  if (!causalPolicy.ok) {
    return {
      result: {
        status: 'INVALID',
        reason: causalPolicy.message,
        verified_at: now,
        component_results: {
          envelope_valid: false,
          causal_policy_profile: causalPolicy.snapshot?.profile ?? 'compat',
          causal_policy_snapshot: causalPolicy.snapshot,
        },
      },
      error: {
        code: causalPolicy.code,
        message: causalPolicy.message,
        field: causalPolicy.field,
      },
    };
  }

  const resolvedCausalPolicy = causalPolicy.snapshot;

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
  //
  const schemaResult = validateProofBundleEnvelopeV1(envelope);
  if (!schemaResult.valid) {
    const causalSchemaCode = classifyCausalSchemaValidationCode(schemaResult.field);
    const schemaErrorCode = causalSchemaCode ?? 'SCHEMA_VALIDATION_FAILED';

    return {
      result: {
        status: 'INVALID',
        reason: schemaResult.message,
        verified_at: now,
      },
      error: {
        code: schemaErrorCode,
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

  if (p.vir_receipts && p.vir_receipts.length > MAX_RECEIPTS) {
    return {
      result: {
        status: 'INVALID',
        reason: `vir_receipts exceeds max length (${MAX_RECEIPTS})`,
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: `payload.vir_receipts length exceeds limit (${MAX_RECEIPTS})`,
        field: 'payload.vir_receipts',
      },
    };
  }

  if (p.web_receipts && p.web_receipts.length > MAX_RECEIPTS) {
    return {
      result: {
        status: 'INVALID',
        reason: `web_receipts exceeds max length (${MAX_RECEIPTS})`,
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: `payload.web_receipts length exceeds limit (${MAX_RECEIPTS})`,
        field: 'payload.web_receipts',
      },
    };
  }

  if (
    p.binary_semantic_evidence_attestations &&
    p.binary_semantic_evidence_attestations.length > MAX_RECEIPTS
  ) {
    return {
      result: {
        status: 'INVALID',
        reason: `binary_semantic_evidence_attestations exceeds max length (${MAX_RECEIPTS})`,
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: `payload.binary_semantic_evidence_attestations length exceeds limit (${MAX_RECEIPTS})`,
        field: 'payload.binary_semantic_evidence_attestations',
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
      const parsedReceipt = parseGatewayReceiptEntry(p.receipts[i]);
      if (!parsedReceipt.ok) {
        return {
          result: {
            status: 'INVALID',
            reason: `payload.receipts[${i}] is not a valid gateway receipt envelope`,
            verified_at: now,
          },
          error: {
            code: 'MALFORMED_ENVELOPE',
            message:
              'payload.receipts must contain gateway_receipt envelopes with a payload object',
            field: `payload.receipts[${i}]`,
          },
        };
      }

      const md = parsedReceipt.payload.metadata;
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
      const entry = isObjectRecord(p.event_chain[i]) ? p.event_chain[i] : null;
      const id =
        entry && typeof entry.event_id === 'string' ? entry.event_id : null;
      if (!id || id.length === 0) {
        return {
          result: {
            status: 'INVALID',
            reason: 'event_chain entry missing event_id',
            verified_at: now,
          },
          error: {
            code: 'MALFORMED_ENVELOPE',
            message:
              'event_id must be present for each payload.event_chain entry',
            field: `payload.event_chain[${i}].event_id`,
          },
        };
      }

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

  const seenReceiptFingerprints = new Map<
    string,
    { fingerprint: string; field: string }
  >();

  const registerReceiptReplayFingerprint = (args: {
    receiptId: string;
    receiptType: 'gateway_receipt' | 'web_receipt' | 'vir_receipt';
    payload: unknown;
    field: string;
  }): { ok: true } | { ok: false; field: string } => {
    let fingerprint: string;

    try {
      fingerprint = jcsCanonicalize({
        receipt_type: args.receiptType,
        payload: args.payload,
      });
    } catch {
      fingerprint = JSON.stringify({
        receipt_type: args.receiptType,
        payload: args.payload,
      });
    }

    const existing = seenReceiptFingerprints.get(args.receiptId);
    if (!existing) {
      seenReceiptFingerprints.set(args.receiptId, {
        fingerprint,
        field: args.field,
      });
      return { ok: true };
    }

    if (existing.fingerprint === fingerprint) {
      return { ok: true };
    }

    return { ok: false, field: args.field };
  };

  if (p.receipts) {
    for (let i = 0; i < p.receipts.length; i++) {
      const parsedReceipt = parseGatewayReceiptEntry(p.receipts[i]);
      if (!parsedReceipt.ok) {
        return {
          result: {
            status: 'INVALID',
            reason: `payload.receipts[${i}] is not a valid gateway receipt envelope`,
            verified_at: now,
          },
          error: {
            code: 'MALFORMED_ENVELOPE',
            message:
              'payload.receipts must contain gateway_receipt envelopes with a payload object',
            field: `payload.receipts[${i}]`,
          },
        };
      }

      const rid = parsedReceipt.payload.receipt_id;
      const field = `payload.receipts[${i}].payload.receipt_id`;
      const replay = registerReceiptReplayFingerprint({
        receiptId: rid,
        receiptType: 'gateway_receipt',
        payload: parsedReceipt.payload,
        field,
      });

      if (!replay.ok) {
        return {
          result: {
            status: 'INVALID',
            reason: `receipt_id replay detected with divergent content: ${rid}`,
            verified_at: now,
          },
          error: {
            code: 'CAUSAL_RECEIPT_REPLAY_DETECTED',
            message:
              'same receipt_id appears multiple times with divergent canonicalized content',
            field: replay.field,
          },
        };
      }
    }
  }

  if (p.web_receipts) {
    for (let i = 0; i < p.web_receipts.length; i++) {
      const parsedReceipt = parseWebReceiptEntry(p.web_receipts[i]);
      if (!parsedReceipt.ok) {
        return {
          result: {
            status: 'INVALID',
            reason: `payload.web_receipts[${i}] is not a valid web receipt envelope`,
            verified_at: now,
          },
          error: {
            code: 'MALFORMED_ENVELOPE',
            message:
              'payload.web_receipts must contain web_receipt envelopes with a payload object',
            field: `payload.web_receipts[${i}]`,
          },
        };
      }

      const rid = parsedReceipt.payload.receipt_id;
      const field = `payload.web_receipts[${i}].payload.receipt_id`;
      const replay = registerReceiptReplayFingerprint({
        receiptId: rid,
        receiptType: 'web_receipt',
        payload: parsedReceipt.payload,
        field,
      });

      if (!replay.ok) {
        return {
          result: {
            status: 'INVALID',
            reason: `receipt_id replay detected with divergent content: ${rid}`,
            verified_at: now,
          },
          error: {
            code: 'CAUSAL_RECEIPT_REPLAY_DETECTED',
            message:
              'same receipt_id appears multiple times with divergent canonicalized content',
            field: replay.field,
          },
        };
      }
    }
  }

  if (p.vir_receipts) {
    for (let i = 0; i < p.vir_receipts.length; i++) {
      const entry = p.vir_receipts[i];
      const record = isObjectRecord(entry) ? entry : null;
      const payloadRecord =
        record && isObjectRecord(record.payload) ? record.payload : null;
      const rid =
        (record &&
        typeof record.receipt_id === 'string' &&
        record.receipt_id.length > 0
          ? record.receipt_id
          : undefined) ??
        (payloadRecord &&
        typeof payloadRecord.receipt_id === 'string' &&
        payloadRecord.receipt_id.length > 0
          ? payloadRecord.receipt_id
          : undefined);

      if (!rid) {
        return {
          result: {
            status: 'INVALID',
            reason: 'VIR receipt_id missing in payload.vir_receipts',
            verified_at: now,
          },
          error: {
            code: 'MALFORMED_ENVELOPE',
            message:
              'receipt_id must be present for each payload.vir_receipts entry',
            field: `payload.vir_receipts[${i}]`,
          },
        };
      }

      const field = `payload.vir_receipts[${i}]`;
      const replay = registerReceiptReplayFingerprint({
        receiptId: rid,
        receiptType: 'vir_receipt',
        payload: payloadRecord ?? record,
        field,
      });

      if (!replay.ok) {
        return {
          result: {
            status: 'INVALID',
            reason: `receipt_id replay detected with divergent content: ${rid}`,
            verified_at: now,
          },
          error: {
            code: 'CAUSAL_RECEIPT_REPLAY_DETECTED',
            message:
              'same receipt_id appears multiple times with divergent canonicalized content',
            field: replay.field,
          },
        };
      }
    }
  }

  if (p.binary_semantic_evidence_attestations) {
    const seenBinaryEvidenceHashes = new Set<string>();
    for (let i = 0; i < p.binary_semantic_evidence_attestations.length; i++) {
      const entry = p.binary_semantic_evidence_attestations[i];
      const hash = entry?.payload?.binary_hash_b64u;

      if (typeof hash !== 'string' || hash.length < 8 || !isValidBase64Url(hash)) {
        return {
          result: {
            status: 'INVALID',
            reason:
              'binary_semantic_evidence_attestations entry is missing payload.binary_hash_b64u',
            verified_at: now,
          },
          error: {
            code: 'MALFORMED_ENVELOPE',
            message:
              'payload.binary_semantic_evidence_attestations[*].payload.binary_hash_b64u must be present and base64url',
            field: `payload.binary_semantic_evidence_attestations[${i}].payload.binary_hash_b64u`,
          },
        };
      }

      if (seenBinaryEvidenceHashes.has(hash)) {
        return {
          result: {
            status: 'INVALID',
            reason:
              'Duplicate binary_hash_b64u in payload.binary_semantic_evidence_attestations',
            verified_at: now,
          },
          error: {
            code: 'MALFORMED_ENVELOPE',
            message:
              'binary_hash_b64u must be unique within payload.binary_semantic_evidence_attestations',
            field: `payload.binary_semantic_evidence_attestations[${i}].payload.binary_hash_b64u`,
          },
        };
      }

      seenBinaryEvidenceHashes.add(hash);
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
  const componentResults: NonNullable<ProofBundleVerificationResult['component_results']> = {
    envelope_valid: true,
    causal_policy_profile: resolvedCausalPolicy.profile,
    causal_policy_snapshot: {
      profile: resolvedCausalPolicy.profile,
      causal_connectivity_mode: resolvedCausalPolicy.causal_connectivity_mode,
      coverage_enforcement_phase: resolvedCausalPolicy.coverage_enforcement_phase,
    },
  };

  // CVF-US-016: model identity is an orthogonal axis to PoH tiers.
  let modelIdentityTier: ModelIdentityTier = 'unknown';
  const modelIdentityRiskFlags = new Set<string>();
  let binarySemanticPolicyResult: BinarySemanticPolicyResult | null = null;

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

  // CPL-V2-001: deterministic, fail-closed rate-limit claim semantics.
  if (
    payload.rate_limit_claims !== undefined &&
    payload.rate_limit_claims.length > 0
  ) {
    const expectedRunId =
      payload.event_chain && payload.event_chain.length > 0
        ? payload.event_chain[0].run_id
        : null;

    const rateCheck = validateRateLimitClaims(
      payload.rate_limit_claims,
      expectedRunId
    );

    if (!rateCheck.ok) {
      return {
        result: {
          status: 'INVALID',
          reason: rateCheck.message,
          verified_at: now,
        },
        error: {
          code: rateCheck.code,
          message: rateCheck.message,
          field: `payload.${rateCheck.field}`,
        },
      };
    }

    componentResults.rate_limit_claims_count = payload.rate_limit_claims.length;
    componentResults.rate_limit_claims_valid = true;
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

  // POH-US-010: Build binding context from event chain for replay-safe receipt checks.
  const bindingContext =
    componentResults.event_chain_valid &&
    payload.event_chain !== undefined &&
    payload.event_chain.length > 0 &&
    typeof componentResults.chain_root_hash === 'string' &&
    componentResults.chain_root_hash.length > 0
      ? {
          expectedRunId: payload.event_chain[0].run_id,
          allowedEventHashes: new Set(
            payload.event_chain.map((e) => e.event_hash_b64u)
          ),
          expectedChainRootHash: componentResults.chain_root_hash,
        }
      : null;

  const metadataRecord = isObjectRecord(payload.metadata) ? payload.metadata : null;

  const requireEgressPolicyReceipt = options.requireEgressPolicyReceipt === true;
  const egressPolicyReceiptEnvelope = extractEgressPolicyReceiptEnvelope(metadataRecord);
  const hasEgressPolicyReceipt = egressPolicyReceiptEnvelope !== undefined;
  componentResults.egress_policy_receipt_present = hasEgressPolicyReceipt;

  const policyBindingVerification = await validatePolicyBindingMetadata({
    payload,
    metadataRecord,
    eventChainValid: componentResults.event_chain_valid === true,
  });
  if (!policyBindingVerification.valid) {
    return {
      result: {
        status: 'INVALID',
        reason:
          policyBindingVerification.message ??
          'Invalid payload.metadata.policy_binding evidence',
        verified_at: now,
        bundle_id: payload.bundle_id,
        agent_did: payload.agent_did,
        component_results: componentResults,
      },
      error: {
        code: policyBindingVerification.code ?? 'SCHEMA_VALIDATION_FAILED',
        message:
          policyBindingVerification.message ??
          'Invalid payload.metadata.policy_binding evidence',
        field:
          policyBindingVerification.field ??
          'payload.metadata.policy_binding',
      },
    };
  }

  const policyBindingRecord =
    metadataRecord && isObjectRecord(metadataRecord.policy_binding)
      ? (metadataRecord.policy_binding as Record<string, unknown>)
      : null;
  const policyBindingHash =
    policyBindingRecord && typeof policyBindingRecord.effective_policy_hash_b64u === 'string'
      ? policyBindingRecord.effective_policy_hash_b64u
      : null;

  const dataHandlingEvidence = await verifyDataHandlingEvidence({
    metadataRecord,
    expectedSignerDid: payload.agent_did,
    expectedRunId: bindingContext?.expectedRunId ?? null,
    expectedPolicyHashB64u: policyBindingHash,
    allowedEventHashes: bindingContext?.allowedEventHashes ?? null,
  });
  if (!dataHandlingEvidence.ok) {
    return {
      result: {
        status: 'INVALID',
        reason: dataHandlingEvidence.message,
        verified_at: now,
        bundle_id: payload.bundle_id,
        agent_did: payload.agent_did,
      },
      error: {
        code: dataHandlingEvidence.code,
        message: dataHandlingEvidence.message,
        field: dataHandlingEvidence.field,
      },
    };
  }

  const runnerMeasurementVerification = await validateRunnerMeasurementMetadata({
    metadataRecord,
  });
  if (!runnerMeasurementVerification.valid) {
    return {
      result: {
        status: 'INVALID',
        reason:
          runnerMeasurementVerification.message ??
          'Invalid payload.metadata.runner_measurement evidence',
        verified_at: now,
        bundle_id: payload.bundle_id,
        agent_did: payload.agent_did,
        component_results: componentResults,
      },
      error: {
        code: runnerMeasurementVerification.code ?? 'SCHEMA_VALIDATION_FAILED',
        message:
          runnerMeasurementVerification.message ??
          'Invalid payload.metadata.runner_measurement evidence',
        field:
          runnerMeasurementVerification.field ??
          'payload.metadata.runner_measurement',
      },
    };
  }

  const runnerMeasurementRecord =
    metadataRecord && isObjectRecord(metadataRecord.runner_measurement)
      ? (metadataRecord.runner_measurement as RunnerMeasurementBindingMetadata)
      : null;
  const runnerAttestationReceiptEnvelope =
    extractRunnerAttestationReceiptEnvelope(metadataRecord);

  if (!runnerMeasurementRecord) {
    if (runnerAttestationReceiptEnvelope !== undefined) {
      return {
        result: {
          status: 'INVALID',
          reason:
            'payload.metadata.runner_measurement is required when payload.metadata.runner_attestation_receipt is present',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
          component_results: componentResults,
        },
        error: {
          code: 'MISSING_REQUIRED_FIELD',
          message:
            'payload.metadata.runner_measurement is required when payload.metadata.runner_attestation_receipt is present',
          field: 'payload.metadata.runner_measurement',
        },
      };
    }
  } else {
    if (runnerAttestationReceiptEnvelope === undefined) {
      return {
        result: {
          status: 'INVALID',
          reason:
            'payload.metadata.runner_measurement requires payload.metadata.runner_attestation_receipt',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
          component_results: componentResults,
        },
        error: {
          code: 'MISSING_REQUIRED_FIELD',
          message:
            'payload.metadata.runner_attestation_receipt is required when payload.metadata.runner_measurement is present',
          field: 'payload.metadata.runner_attestation_receipt',
        },
      };
    }
    if (!policyBindingHash) {
      return {
        result: {
          status: 'INVALID',
          reason:
            'runner attestation receipt requires payload.metadata.policy_binding.effective_policy_hash_b64u',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
          component_results: componentResults,
        },
        error: {
          code: 'EVIDENCE_MISMATCH',
          message:
            'runner attestation receipt requires payload.metadata.policy_binding.effective_policy_hash_b64u',
          field: 'payload.metadata.policy_binding.effective_policy_hash_b64u',
        },
      };
    }

    const runnerAttestationVerification =
      await verifyRunnerAttestationReceiptEnvelope({
        envelope: runnerAttestationReceiptEnvelope,
        bundleAgentDid: payload.agent_did,
        expectedRunId: bindingContext?.expectedRunId ?? null,
        allowedEventHashes: bindingContext?.allowedEventHashes ?? null,
        runnerMeasurement: runnerMeasurementRecord,
        expectedPolicyHashB64u: policyBindingHash,
      });
    if (!runnerAttestationVerification.valid) {
      return {
        result: {
          status: 'INVALID',
          reason:
            runnerAttestationVerification.message ??
            'Invalid runner attestation receipt evidence',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
          component_results: componentResults,
        },
        error: {
          code: runnerAttestationVerification.code ?? 'EVIDENCE_MISMATCH',
          message:
            runnerAttestationVerification.message ??
            'Invalid runner attestation receipt evidence',
          field:
            runnerAttestationVerification.field ??
            'payload.metadata.runner_attestation_receipt',
        },
      };
    }
  }

  if (!hasEgressPolicyReceipt) {
    componentResults.egress_policy_receipt_signature_verified = false;
    componentResults.egress_policy_receipt_valid = false;

    if (requireEgressPolicyReceipt) {
      return {
        result: {
          status: 'INVALID',
          reason:
            'Missing required payload.metadata.sentinels.egress_policy_receipt evidence',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
          component_results: componentResults,
        },
        error: {
          code: 'MISSING_REQUIRED_FIELD',
          message:
            'payload.metadata.sentinels.egress_policy_receipt is required by verifier policy',
          field: 'payload.metadata.sentinels.egress_policy_receipt',
        },
      };
    }
  } else {
    const egressPolicyReceiptVerification = await verifyEgressPolicyReceiptEnvelope({
      envelope: egressPolicyReceiptEnvelope,
      bundleAgentDid: payload.agent_did,
      expectedRunId:
        payload.event_chain && payload.event_chain.length > 0
          ? payload.event_chain[0].run_id
          : null,
      allowedEventHashes:
        payload.event_chain && payload.event_chain.length > 0
          ? new Set(payload.event_chain.map((event) => event.event_hash_b64u))
          : null,
    });

    componentResults.egress_policy_receipt_signature_verified =
      egressPolicyReceiptVerification.signature_valid;
    componentResults.egress_policy_receipt_valid =
      egressPolicyReceiptVerification.valid;

    if (!egressPolicyReceiptVerification.valid) {
      return {
        result: {
          status: 'INVALID',
          reason:
            egressPolicyReceiptVerification.message ??
            'Invalid egress policy receipt evidence',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
          component_results: componentResults,
        },
        error: {
          code: egressPolicyReceiptVerification.code ?? 'EVIDENCE_MISMATCH',
          message:
            egressPolicyReceiptVerification.message ??
            'Invalid egress policy receipt evidence',
          field:
            egressPolicyReceiptVerification.field ??
            'payload.metadata.sentinels.egress_policy_receipt',
        },
      };
    }
  }

  const clddMetricsClaim = parseClddMetricsClaim(metadataRecord);
  if (!clddMetricsClaim.ok) {
    return {
      result: {
        status: 'INVALID',
        reason: clddMetricsClaim.message,
        verified_at: now,
        bundle_id: payload.bundle_id,
        agent_did: payload.agent_did,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: clddMetricsClaim.message,
        field: clddMetricsClaim.field,
      },
    };
  }

  const processorPolicyEvidence = parseProcessorPolicyEvidence(metadataRecord);
  if (!processorPolicyEvidence.ok) {
    return {
      result: {
        status: 'INVALID',
        reason: processorPolicyEvidence.message,
        verified_at: now,
        bundle_id: payload.bundle_id,
        agent_did: payload.agent_did,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: processorPolicyEvidence.message,
        field: processorPolicyEvidence.field,
      },
    };
  }

  if (processorPolicyEvidence.evidence) {
    const computedProcessorPolicyHash = await computeProcessorPolicyHashB64u(
      processorPolicyEvidence.evidence
    );
    if (
      computedProcessorPolicyHash !==
      processorPolicyEvidence.evidence.policy_hash_b64u
    ) {
      return {
        result: {
          status: 'INVALID',
          reason:
            'payload.metadata.processor_policy.policy_hash_b64u does not match the canonical processor policy constraints',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
        },
        error: {
          code: 'HASH_MISMATCH',
          message:
            'payload.metadata.processor_policy.policy_hash_b64u must match the canonical SHA-256 hash of the declared processor policy constraints',
          field: 'payload.metadata.processor_policy.policy_hash_b64u',
        },
      };
    }

    const usedProcessorCount = processorPolicyEvidence.evidence.used_processors.reduce(
      (sum, route) => sum + route.count,
      0
    );
    if (
      usedProcessorCount !==
      processorPolicyEvidence.evidence.counters.allowed_routes
    ) {
      return {
        result: {
          status: 'INVALID',
          reason:
            'payload.metadata.processor_policy.counters.allowed_routes must equal the sum of used_processors[*].count',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
        },
        error: {
          code: 'MALFORMED_ENVELOPE',
          message:
            'payload.metadata.processor_policy.counters.allowed_routes must equal the sum of payload.metadata.processor_policy.used_processors[*].count',
          field: 'payload.metadata.processor_policy.counters.allowed_routes',
        },
      };
    }

    if (
      processorPolicyEvidence.evidence.blocked_attempts.length !==
      processorPolicyEvidence.evidence.counters.denied_routes
    ) {
      return {
        result: {
          status: 'INVALID',
          reason:
            'payload.metadata.processor_policy.counters.denied_routes must equal payload.metadata.processor_policy.blocked_attempts.length',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
        },
        error: {
          code: 'MALFORMED_ENVELOPE',
          message:
            'payload.metadata.processor_policy.counters.denied_routes must equal payload.metadata.processor_policy.blocked_attempts.length',
          field: 'payload.metadata.processor_policy.counters.denied_routes',
        },
      };
    }

    const expectedProcessorRunId =
      payload.event_chain && payload.event_chain.length > 0
        ? payload.event_chain[0].run_id
        : null;
    if (
      expectedProcessorRunId &&
      processorPolicyEvidence.evidence.binding.run_id !== expectedProcessorRunId
    ) {
      return {
        result: {
          status: 'INVALID',
          reason:
            'payload.metadata.processor_policy.binding.run_id does not match the proof bundle run_id',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
        },
        error: {
          code: 'EVIDENCE_MISMATCH',
          message:
            'payload.metadata.processor_policy.binding.run_id must match payload.event_chain[0].run_id',
          field: 'payload.metadata.processor_policy.binding.run_id',
        },
      };
    }

    const expectedProcessorChainRoot =
      typeof componentResults.chain_root_hash === 'string' &&
      componentResults.chain_root_hash.length > 0
        ? componentResults.chain_root_hash
        : null;
    if (
      expectedProcessorChainRoot &&
      processorPolicyEvidence.evidence.binding.event_chain_root_hash_b64u !==
        expectedProcessorChainRoot
    ) {
      return {
        result: {
          status: 'INVALID',
          reason:
            'payload.metadata.processor_policy.binding.event_chain_root_hash_b64u does not match the proof bundle event chain root hash',
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
        },
        error: {
          code: 'EVIDENCE_MISMATCH',
          message:
            'payload.metadata.processor_policy.binding.event_chain_root_hash_b64u must match the proof bundle event chain root hash',
          field:
            'payload.metadata.processor_policy.binding.event_chain_root_hash_b64u',
        },
      };
    }

    const processorComponent = componentResults as unknown as Record<string, unknown>;
    processorComponent['processor_policy_evidence_present'] = true;
    processorComponent['processor_policy_evidence_valid'] = true;
    processorComponent['processor_policy_binding_run_id'] =
      processorPolicyEvidence.evidence.binding.run_id;
    processorComponent['processor_policy_binding_chain_root_hash_b64u'] =
      processorPolicyEvidence.evidence.binding.event_chain_root_hash_b64u;
    processorComponent['processor_policy_profile_id'] =
      processorPolicyEvidence.evidence.profile_id;
    processorComponent['processor_policy_hash_b64u'] =
      computedProcessorPolicyHash;
    processorComponent['processor_policy_allowed_routes'] =
      processorPolicyEvidence.evidence.counters.allowed_routes;
    processorComponent['processor_policy_denied_routes'] =
      processorPolicyEvidence.evidence.counters.denied_routes;
    processorComponent['processor_policy_used_processors_count'] =
      processorPolicyEvidence.evidence.used_processors.length;
  }

  const metadataBountyNonce =
    metadataRecord && typeof metadataRecord.bounty_nonce === 'string'
      ? metadataRecord.bounty_nonce
      : null;

  const expectedVirNonce =
    typeof options.expectedVirNonce === 'string' && options.expectedVirNonce.length > 0
      ? options.expectedVirNonce
      : metadataBountyNonce;

  const expectedVirSubject =
    typeof options.expectedVirSubject === 'string' && options.expectedVirSubject.length > 0
      ? options.expectedVirSubject
      : metadataRecord && typeof metadataRecord.bounty_subject_did === 'string'
        ? metadataRecord.bounty_subject_did
        : null;

  const expectedVirScope =
    typeof options.expectedVirScope === 'string' && options.expectedVirScope.length > 0
      ? options.expectedVirScope
      : metadataRecord && typeof metadataRecord.bounty_scope_hash_b64u === 'string'
        ? metadataRecord.bounty_scope_hash_b64u
        : null;

  // CAV-US-002: fail-closed causal binding DAG checks (only when causal fields are present).
  const causalBindingEntries = collectCausalBindingEntries(payload);
  if (!causalBindingEntries.ok) {
    return {
      result: {
        status: 'INVALID',
        reason: causalBindingEntries.message,
        verified_at: now,
        bundle_id: payload.bundle_id,
        agent_did: payload.agent_did,
      },
      error: {
        code: causalBindingEntries.code,
        message: causalBindingEntries.message,
        field: causalBindingEntries.field,
      },
    };
  }

  const causalConnectivityMode =
    resolvedCausalPolicy.causal_connectivity_mode;

  const causalValidation = validateCausalBindingEntries(
    causalBindingEntries.entries,
    causalConnectivityMode
  );
  if (!causalValidation.ok) {
    return {
      result: {
        status: 'INVALID',
        reason: causalValidation.message,
        verified_at: now,
        bundle_id: payload.bundle_id,
        agent_did: payload.agent_did,
      },
      error: {
        code: causalValidation.code,
        message: causalValidation.message,
        field: causalValidation.field,
      },
    };
  }

  if (causalConnectivityMode === 'enforce') {
    const sideEffectAnchoring = validateCausalAnchoredSupportReceipts({
      receipts: payload.side_effect_receipts,
      knownSpanIds: causalValidation.knownSpanIds,
      pathPrefix: 'payload.side_effect_receipts',
      orphanCode: 'CAUSAL_SIDE_EFFECT_ORPHANED',
    });

    if (!sideEffectAnchoring.ok) {
      return {
        result: {
          status: 'INVALID',
          reason: sideEffectAnchoring.message,
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
        },
        error: {
          code: sideEffectAnchoring.code,
          message: sideEffectAnchoring.message,
          field: sideEffectAnchoring.field,
        },
      };
    }

    const humanApprovalAnchoring = validateCausalAnchoredSupportReceipts({
      receipts: payload.human_approval_receipts,
      knownSpanIds: causalValidation.knownSpanIds,
      pathPrefix: 'payload.human_approval_receipts',
      orphanCode: 'CAUSAL_HUMAN_APPROVAL_ORPHANED',
    });

    if (!humanApprovalAnchoring.ok) {
      return {
        result: {
          status: 'INVALID',
          reason: humanApprovalAnchoring.message,
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
        },
        error: {
          code: humanApprovalAnchoring.code,
          message: humanApprovalAnchoring.message,
          field: humanApprovalAnchoring.field,
        },
      };
    }
  }

  // Verify VIR receipts (R43 evidence-fusion path).
  if (payload.vir_receipts !== undefined && payload.vir_receipts.length > 0) {
    const virConflictPolicyMode = normalizeVirConflictPolicyMode(
      options.vir_conflict_policy_mode
    );
    const maxVirCorroborationSkewMs = normalizeVirCorroborationSkewMs(
      options.maxVirCorroborationSkewMs
    );

    const gatewayCorroborationByEvent = new Map<string, number[]>();

    // CVF-US-059: corroboration sources must be cryptographic + allowlisted.
    // Only verified gateway receipts qualify (web receipts and metadata do not).
    if (payload.receipts !== undefined && payload.receipts.length > 0) {
      const receiptCorroborationResults = await Promise.all(
        payload.receipts.map((r) =>
          verifyReceiptEnvelope(
            r,
            options.allowlistedReceiptSignerDids,
            bindingContext
          )
        )
      );

      for (let i = 0; i < receiptCorroborationResults.length; i++) {
        if (!receiptCorroborationResults[i]?.valid) continue;

        const parsedReceipt = parseGatewayReceiptEntry(payload.receipts[i]);
        if (!parsedReceipt.ok) continue;

        const eventHash = parsedReceipt.payload.binding?.event_hash_b64u;
        if (typeof eventHash !== 'string' || eventHash.trim().length === 0) continue;

        const timestampMs = Date.parse(parsedReceipt.payload.timestamp);
        if (!Number.isFinite(timestampMs)) continue;

        const timestamps = gatewayCorroborationByEvent.get(eventHash) ?? [];
        timestamps.push(timestampMs);
        gatewayCorroborationByEvent.set(eventHash, timestamps);
      }
    }

    const virResults = await Promise.all(
      payload.vir_receipts.map((r) =>
        verifyVirReceiptEntry(
          r,
          bindingContext,
          expectedVirNonce,
          expectedVirSubject,
          expectedVirScope
        )
      )
    );

    const signatureValidCount = virResults.filter((r) => r.signature_valid).length;
    const verifiedCount = virResults.filter((r) => r.valid).length;

    const criticalVirFailure = virResults.find(
      (r) => !r.valid && r.code !== undefined && CRITICAL_VIR_CODES.has(r.code)
    );

    if (criticalVirFailure) {
      return {
        result: {
          status: 'INVALID',
          reason: `Critical VIR validation failure: ${criticalVirFailure.error ?? criticalVirFailure.code}`,
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
        },
        error: {
          code: 'EVIDENCE_MISMATCH',
          message:
            criticalVirFailure.error ??
            criticalVirFailure.code ??
            'Critical VIR validation failure',
          field: 'payload.vir_receipts',
        },
      };
    }

    componentResults.vir_receipts_count = payload.vir_receipts.length;
    componentResults.vir_receipts_signature_verified_count = signatureValidCount;
    componentResults.vir_receipts_verified_count = verifiedCount;
    componentResults.vir_receipts_valid = verifiedCount === payload.vir_receipts.length;

    type VirCandidate = {
      source: VirSource;
      timestampMs: number;
      receiptId: string;
      eventHash?: string;
    };

    const validVirCandidates: VirCandidate[] = [];

    for (let i = 0; i < virResults.length; i++) {
      const result = virResults[i];
      if (result.risk_flags) {
        for (const flag of result.risk_flags) modelIdentityRiskFlags.add(flag);
      }
      if (!result.valid || !result.source) continue;

      const entry = payload.vir_receipts[i];
      const parsed = parseVirReceiptEntry(entry);
      if (!parsed.ok) continue;

      const virPayload = parsed.parsed.payload;
      const eventHash = virPayload.binding?.event_hash_b64u;
      const timestampMs = Date.parse(virPayload.timestamp);

      let effectiveSource: VirSource = result.source;
      let maxConflictSeverity: VirConflictSeverity = 'none';

      const evidenceConflicts = Array.isArray(virPayload.evidence_conflicts)
        ? virPayload.evidence_conflicts
        : [];

      for (const conflict of evidenceConflicts) {
        if (!isObjectRecord(conflict)) continue;
        const severity = classifyVirConflictSeverity(conflict.field);
        maxConflictSeverity = mergeVirConflictSeverity(maxConflictSeverity, severity);
      }

      if (maxConflictSeverity !== 'none') {
        modelIdentityRiskFlags.add(
          `VIR_CONFLICT_${maxConflictSeverity.toUpperCase()}`
        );
      }

      if (maxConflictSeverity === 'high' || maxConflictSeverity === 'critical') {
        if (virConflictPolicyMode === 'strict') {
          return {
            result: {
              status: 'INVALID',
              reason: `VIR conflict severity ${maxConflictSeverity} rejected by policy`,
              verified_at: now,
              bundle_id: payload.bundle_id,
              agent_did: payload.agent_did,
            },
            error: {
              code: 'EVIDENCE_MISMATCH',
              message: `ERR_VIR_CONFLICT_${maxConflictSeverity.toUpperCase()}_POLICY`,
              field: `payload.vir_receipts[${i}].evidence_conflicts`,
            },
          };
        }

        effectiveSource = 'sni';
        modelIdentityRiskFlags.add(
          `VIR_CONFLICT_${maxConflictSeverity.toUpperCase()}_TIER_CAPPED`
        );
      }

      if (HIGH_CLAIM_VIR_SOURCES.has(result.source)) {
        const normalizedEventHash =
          typeof eventHash === 'string' && eventHash.length > 0
            ? eventHash
            : undefined;

        const corroborationTimestamps = normalizedEventHash
          ? gatewayCorroborationByEvent.get(normalizedEventHash) ?? []
          : [];

        const hasCorroboration =
          normalizedEventHash !== undefined &&
          Number.isFinite(timestampMs) &&
          corroborationTimestamps.some(
            (receiptTimestampMs) =>
              Math.abs(receiptTimestampMs - timestampMs) <=
              maxVirCorroborationSkewMs
          );

        if (!hasCorroboration) {
          effectiveSource = 'sni';
          modelIdentityRiskFlags.add('VIR_HIGH_CLAIM_UNCORROBORATED');

          if (!normalizedEventHash) {
            modelIdentityRiskFlags.add('VIR_CORROBORATION_BINDING_MISSING');
          } else if (corroborationTimestamps.length > 0 && Number.isFinite(timestampMs)) {
            modelIdentityRiskFlags.add('VIR_CORROBORATION_SKEW_EXCEEDED');
          }
        }
      }

      validVirCandidates.push({
        source: effectiveSource,
        timestampMs: Number.isFinite(timestampMs)
          ? timestampMs
          : Number.POSITIVE_INFINITY,
        receiptId: virPayload.receipt_id,
        eventHash: typeof eventHash === 'string' && eventHash.length > 0 ? eventHash : undefined,
      });
    }

    let bestCandidate: VirCandidate | undefined;
    for (const c of validVirCandidates) {
      if (!bestCandidate || compareVirCandidate(c, bestCandidate) < 0) {
        bestCandidate = c;
      }
    }

    if (bestCandidate) {
      componentResults.vir_best_source = bestCandidate.source;
    }

    // CVF-US-060: reject intra-bundle event contradictions deterministically.
    const candidatesByEvent = new Map<string, VirCandidate[]>();
    for (const c of validVirCandidates) {
      if (!c.eventHash) continue;
      const arr = candidatesByEvent.get(c.eventHash) ?? [];
      arr.push(c);
      candidatesByEvent.set(c.eventHash, arr);
    }

    for (const [eventHash, candidates] of candidatesByEvent.entries()) {
      if (candidates.length <= 1) continue;

      return {
        result: {
          status: 'INVALID',
          reason: `VIR event contradiction detected for event_hash_b64u ${eventHash}`,
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
        },
        error: {
          code: 'EVIDENCE_MISMATCH',
          message: 'ERR_VIR_EVENT_CONTRADICTION',
          field: 'payload.vir_receipts',
        },
      };
    }

    if (virResults.some((r) => !r.valid)) {
      modelIdentityRiskFlags.add('VIR_VERIFY_PARTIAL_FAILURE');
    }
  }

  // Verify gateway receipt envelopes cryptographically (POH-US-003)
  // Each receipt is verified with its signer DID (clawproxy DID) using full
  // signature verification — not just structural validation.
  if (payload.receipts !== undefined && payload.receipts.length > 0) {
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

    const x402ClaimedResults = receiptResults.filter((r) => r.x402_claimed);
    const x402ClaimedCount = x402ClaimedResults.length;
    const x402BoundCount = x402ClaimedResults.filter((r) => r.valid).length;

    componentResults.x402_claimed_count = x402ClaimedCount;
    componentResults.x402_bound_count = x402BoundCount;
    componentResults.x402_binding_valid =
      x402ClaimedCount === 0 ? true : x402BoundCount === x402ClaimedCount;

    let x402ReasonCode: X402BindingReasonCode =
      x402ClaimedCount === 0 ? 'X402_NOT_CLAIMED' : 'X402_BOUND';

    const seenPaymentAuthHashes = new Set<string>();
    for (const result of x402ClaimedResults) {
      const hash = result.x402_payment_auth_hash_b64u;
      if (typeof hash !== 'string' || hash.length === 0) continue;

      if (seenPaymentAuthHashes.has(hash)) {
        x402ReasonCode = 'X402_PAYMENT_AUTH_REPLAY';
        break;
      }

      seenPaymentAuthHashes.add(hash);
    }

    if (x402ReasonCode === 'X402_BOUND') {
      const firstX402Failure = x402ClaimedResults.find((r) => !r.valid);
      if (firstX402Failure?.x402_reason_code) {
        x402ReasonCode = firstX402Failure.x402_reason_code;
      } else if (firstX402Failure) {
        x402ReasonCode = 'X402_EXECUTION_BINDING_MISMATCH';
      }
    }

    componentResults.x402_reason_code = x402ReasonCode;

    if (x402ClaimedCount > 0 && x402ReasonCode !== 'X402_BOUND') {
      modelIdentityRiskFlags.add(`X402_${x402ReasonCode}`);

      const reason = `x402 payment↔execution binding failed (${x402ReasonCode})`;
      return {
        result: {
          status: 'INVALID',
          reason,
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
          component_results: componentResults,
          risk_flags:
            modelIdentityRiskFlags.size > 0
              ? [...modelIdentityRiskFlags].sort()
              : undefined,
        },
        error: {
          code: 'EVIDENCE_MISMATCH',
          message: x402ReasonCode,
          field: 'payload.receipts',
        },
      };
    }

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

  // Verify witnessed-web receipts (POH-US-018, CVF-US-062, CVF-US-063)
  if (payload.web_receipts !== undefined && payload.web_receipts.length > 0) {
    const witnessedWebPolicyMode = normalizeWitnessedWebPolicyMode(
      options.witnessed_web_policy_mode
    );
    const transparencyMode = normalizeWitnessedWebTransparencyMode(
      options.witnessed_web_transparency_mode
    );
    const transparencyRequiredAfterMs = normalizeIsoTimestampToMs(
      options.witnessed_web_transparency_required_after
    );

    const quorumM = normalizePositiveInteger(options.witnessed_web_quorum_m);
    const quorumN = normalizePositiveInteger(options.witnessed_web_quorum_n);

    const quorumPolicyConfigured = quorumM !== undefined || quorumN !== undefined;
    const quorumPolicyValid =
      quorumM !== undefined &&
      quorumN !== undefined &&
      quorumM <= quorumN;

    if (quorumPolicyConfigured && !quorumPolicyValid) {
      modelIdentityRiskFlags.add('WITNESS_QUORUM_POLICY_INVALID');
    }

    const webReceiptResults = await Promise.all(
      payload.web_receipts.map((r) =>
        verifyWebReceiptEnvelope(
          r,
          options.allowlistedWitnessSignerDids,
          bindingContext
        )
      )
    );

    const signatureValidCount = webReceiptResults.filter((r) => r.signature_valid).length;

    type WebCandidate = {
      signerDid: string;
      witnessId: string;
      runId: string;
      eventHash: string;
      responseHash: string;
      timestampMs: number;
      payload: WebReceiptPayload;
      transparencyEligible: boolean;
    };

    const verifiedWebCandidates: WebCandidate[] = [];

    for (let i = 0; i < webReceiptResults.length; i++) {
      const result = webReceiptResults[i];
      if (!result?.valid || !result.signer_did) continue;

      const parsed = parseWebReceiptEntry(payload.web_receipts[i]);
      if (!parsed.ok) continue;

      const binding = parsed.payload.binding;
      const runId = typeof binding?.run_id === 'string' ? binding.run_id : null;
      const eventHash =
        typeof binding?.event_hash_b64u === 'string' ? binding.event_hash_b64u : null;

      if (!runId || !eventHash) {
        modelIdentityRiskFlags.add('WITNESS_BINDING_MISSING');
        continue;
      }

      const timestampMs = Date.parse(parsed.payload.timestamp);

      verifiedWebCandidates.push({
        signerDid: result.signer_did,
        witnessId: parsed.payload.witness_id,
        runId,
        eventHash,
        responseHash: parsed.payload.response_hash_b64u,
        timestampMs: Number.isFinite(timestampMs)
          ? timestampMs
          : Number.POSITIVE_INFINITY,
        payload: parsed.payload,
        transparencyEligible: true,
      });
    }

    let transparencyPolicyViolation = false;

    for (const candidate of verifiedWebCandidates) {
      const transparencyRequired =
        transparencyMode !== 'optional' &&
        (transparencyRequiredAfterMs === undefined ||
          (Number.isFinite(candidate.timestampMs) &&
            candidate.timestampMs >= transparencyRequiredAfterMs));

      if (!transparencyRequired) continue;

      const inclusionProof = extractWebReceiptInclusionProof(candidate.payload);
      if (inclusionProof === undefined) {
        candidate.transparencyEligible = false;
        transparencyPolicyViolation = true;
        modelIdentityRiskFlags.add('WITNESS_TRANSPARENCY_REQUIRED_MISSING');
        continue;
      }

      const proofVerification = await verifyLogInclusionProof(inclusionProof);
      if (!proofVerification.valid) {
        candidate.transparencyEligible = false;
        transparencyPolicyViolation = true;
        modelIdentityRiskFlags.add('WITNESS_TRANSPARENCY_REQUIRED_INVALID');
        continue;
      }

      const proofLeafHash =
        isObjectRecord(inclusionProof) &&
        typeof inclusionProof.leaf_hash_b64u === 'string'
          ? inclusionProof.leaf_hash_b64u
          : null;

      const expectedLeafHash = await computeWebReceiptTransparencyLeafHash(
        candidate.payload
      );

      if (!proofLeafHash || proofLeafHash !== expectedLeafHash) {
        candidate.transparencyEligible = false;
        transparencyPolicyViolation = true;
        modelIdentityRiskFlags.add('WITNESS_TRANSPARENCY_LEAF_MISMATCH');
      }
    }

    const transparencyEligibleCandidates = verifiedWebCandidates.filter(
      (candidate) => candidate.transparencyEligible
    );

    type WitnessGroup = {
      responseBySigner: Map<string, string>;
      responseCount: Map<string, number>;
    };

    const witnessGroups = new Map<string, WitnessGroup>();

    for (const candidate of transparencyEligibleCandidates) {
      const key = `${candidate.runId}::${candidate.eventHash}`;
      const group =
        witnessGroups.get(key) ??
        {
          responseBySigner: new Map<string, string>(),
          responseCount: new Map<string, number>(),
        };

      const priorResponse = group.responseBySigner.get(candidate.signerDid);
      if (priorResponse) {
        if (priorResponse !== candidate.responseHash) {
          modelIdentityRiskFlags.add('WITNESS_DUPLICATE_SIGNER_CONFLICT');
        }
        witnessGroups.set(key, group);
        continue;
      }

      group.responseBySigner.set(candidate.signerDid, candidate.responseHash);
      group.responseCount.set(
        candidate.responseHash,
        (group.responseCount.get(candidate.responseHash) ?? 0) + 1
      );
      witnessGroups.set(key, group);
    }

    let witnessSplitViewConflict = false;
    let witnessQuorumFailed = false;

    for (const group of witnessGroups.values()) {
      if (group.responseCount.size > 1) {
        witnessSplitViewConflict = true;
      }

      if (quorumPolicyValid && quorumM !== undefined && quorumN !== undefined) {
        const witnessCount = group.responseBySigner.size;
        let maxAgreementCount = 0;
        for (const count of group.responseCount.values()) {
          if (count > maxAgreementCount) maxAgreementCount = count;
        }

        const quorumSatisfied =
          witnessCount >= quorumN && maxAgreementCount >= quorumM;
        if (!quorumSatisfied) {
          witnessQuorumFailed = true;
        }
      }
    }

    if (witnessSplitViewConflict) {
      modelIdentityRiskFlags.add('WITNESS_CONFLICT_SPLIT_VIEW');
    }

    if (quorumPolicyValid && witnessQuorumFailed) {
      modelIdentityRiskFlags.add('WITNESS_QUORUM_FAILED');
    }

    const witnessPolicyViolation =
      (quorumPolicyConfigured && !quorumPolicyValid) ||
      witnessSplitViewConflict ||
      (quorumPolicyValid && witnessQuorumFailed);

    const enforceWitnessPolicyViolation =
      (witnessPolicyViolation && witnessedWebPolicyMode === 'enforce') ||
      (transparencyPolicyViolation && transparencyMode === 'enforce');

    if (enforceWitnessPolicyViolation) {
      const reason = transparencyPolicyViolation
        ? 'Witnessed-web transparency requirement failed under enforce policy'
        : witnessSplitViewConflict
          ? 'Witnessed-web split-view conflict detected under enforce policy'
          : quorumPolicyConfigured && !quorumPolicyValid
            ? 'Witnessed-web quorum policy is invalid (expected positive m<=n)'
            : 'Witnessed-web quorum policy failed under enforce mode';

      const message = transparencyPolicyViolation
        ? 'WITNESS_TRANSPARENCY_REQUIRED'
        : witnessSplitViewConflict
          ? 'WITNESS_CONFLICT_SPLIT_VIEW'
          : quorumPolicyConfigured && !quorumPolicyValid
            ? 'WITNESS_QUORUM_POLICY_INVALID'
            : 'WITNESS_QUORUM_FAILED';

      return {
        result: {
          status: 'INVALID',
          reason,
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
        },
        error: {
          code: 'EVIDENCE_MISMATCH',
          message,
          field: 'payload.web_receipts',
        },
      };
    }

    const shouldDegradeWitnessedWeb =
      witnessPolicyViolation ||
      (transparencyPolicyViolation && transparencyMode === 'warn');

    let effectiveVerifiedCount = transparencyEligibleCandidates.length;
    if (shouldDegradeWitnessedWeb) {
      effectiveVerifiedCount = 0;
      modelIdentityRiskFlags.add('WITNESS_POLICY_DEGRADED');
    }

    componentResults.web_receipts_count = payload.web_receipts.length;
    componentResults.web_receipts_signature_verified_count = signatureValidCount;
    componentResults.web_receipts_verified_count = effectiveVerifiedCount;
    componentResults.web_receipts_valid =
      effectiveVerifiedCount === payload.web_receipts.length;

    if (webReceiptResults.some((r) => !r.valid)) {
      modelIdentityRiskFlags.add('WEB_RECEIPT_VERIFY_PARTIAL_FAILURE');
    }

    // witnessed_web can only claim closed opaque identity, never gateway-equivalent model identity.
    if (modelIdentityTier === 'unknown' && effectiveVerifiedCount > 0) {
      modelIdentityTier = 'closed_opaque';
    }
  }

  const maxCoverageLivenessGapMs =
    typeof options.maxCoverageLivenessGapMs === 'number' &&
    Number.isInteger(options.maxCoverageLivenessGapMs) &&
    options.maxCoverageLivenessGapMs >= 0
      ? options.maxCoverageLivenessGapMs
      : 1_000;

  let coverageAttestedClddMetrics: ClddMetrics | null = null;

  // Verify coverage attestations (CVF-US-057)
  if (payload.coverage_attestations !== undefined && payload.coverage_attestations.length > 0) {
    const coverageResults = await Promise.all(
      payload.coverage_attestations.map((a) =>
        verifyCoverageAttestationEnvelope(
          a,
          options.allowlistedCoverageAttestationSignerDids,
          bindingContext,
          payload.agent_did,
          maxCoverageLivenessGapMs,
        )
      )
    );

    const signatureValidCount = coverageResults.filter((r) => r.signature_valid).length;
    const verifiedCount = coverageResults.filter((r) => r.valid).length;

    componentResults.coverage_attestations_count = payload.coverage_attestations.length;
    componentResults.coverage_attestations_signature_verified_count = signatureValidCount;
    componentResults.coverage_attestations_verified_count = verifiedCount;
    componentResults.coverage_attestations_valid =
      verifiedCount === payload.coverage_attestations.length;

    coverageAttestedClddMetrics = aggregateCoverageClddMetrics(coverageResults);

    for (const r of coverageResults) {
      if (r.risk_flags) {
        for (const flag of r.risk_flags) modelIdentityRiskFlags.add(flag);
      }
    }

    if (coverageResults.some((r) => !r.valid)) {
      modelIdentityRiskFlags.add('COVERAGE_ATTESTATION_VERIFY_PARTIAL_FAILURE');
    }
  }

  // Verify binary semantic evidence attestations (CEC-US-005 / CEC-US-006)
  if (
    payload.binary_semantic_evidence_attestations !== undefined &&
    payload.binary_semantic_evidence_attestations.length > 0
  ) {
    const envelopeResults = await Promise.all(
      payload.binary_semantic_evidence_attestations.map((attestation) =>
        verifyBinarySemanticEvidence(attestation, {
          allowlistedSignerDids:
            options.allowlistedBinarySemanticEvidenceSignerDids,
        }),
      ),
    );

    const dynamicContext = {
      verifiedNetworkEgressPresent:
        (componentResults.receipts_verified_count ?? 0) > 0 ||
        (componentResults.vir_receipts_verified_count ?? 0) > 0 ||
        (componentResults.web_receipts_verified_count ?? 0) > 0,
    };

    const policyResults: BinarySemanticPolicyResult[] = [];
    let signatureVerifiedCount = 0;

    for (const envelopeResult of envelopeResults) {
      if (envelopeResult.result.status === 'VALID' && envelopeResult.payload) {
        signatureVerifiedCount += 1;
        policyResults.push(
          evaluateBinarySemanticEvidencePolicy(
            envelopeResult.payload,
            dynamicContext,
          ),
        );
        continue;
      }

      policyResults.push(
        verificationFailureToPolicyResult(
          envelopeResult.error,
          envelopeResult.reason_code,
        ),
      );
    }

    let aggregatePolicyResult = policyResults[0]!;
    for (let i = 1; i < policyResults.length; i++) {
      if (compareBinarySemanticPolicyResult(policyResults[i]!, aggregatePolicyResult) < 0) {
        aggregatePolicyResult = policyResults[i]!;
      }
    }

    componentResults.binary_semantic_evidence_count =
      payload.binary_semantic_evidence_attestations.length;
    componentResults.binary_semantic_evidence_signature_verified_count =
      signatureVerifiedCount;
    componentResults.binary_semantic_evidence_verified_count = policyResults.filter(
      (r) => !isBinarySemanticFailClosedVerdict(r.verdict),
    ).length;
    componentResults.binary_semantic_evidence_policy_verdict =
      aggregatePolicyResult.verdict;
    componentResults.binary_semantic_evidence_reason_code =
      aggregatePolicyResult.reason_code;
    componentResults.binary_semantic_evidence_valid =
      aggregatePolicyResult.verdict === 'VALID';

    binarySemanticPolicyResult = aggregatePolicyResult;

    if (isBinarySemanticFailClosedVerdict(aggregatePolicyResult.verdict)) {
      const reason = `Binary semantic evidence policy verdict ${aggregatePolicyResult.verdict} (${aggregatePolicyResult.reason_code})`;
      return {
        result: {
          status: 'INVALID',
          reason,
          verified_at: now,
          bundle_id: payload.bundle_id,
          agent_did: payload.agent_did,
          component_results: componentResults,
          risk_flags:
            modelIdentityRiskFlags.size > 0
              ? [...modelIdentityRiskFlags].sort()
              : undefined,
        },
        error: {
          code: 'EVIDENCE_MISMATCH',
          message: reason,
          field: 'payload.binary_semantic_evidence_attestations',
        },
      };
    }

    if (isBinarySemanticConstrainedVerdict(aggregatePolicyResult.verdict)) {
      modelIdentityRiskFlags.add(
        `BINARY_SEMANTIC_${aggregatePolicyResult.reason_code}`,
      );
    }
  }

  // Optional in-band execution attestations (TEE/sandbox) bound to this bundle.
  if (options.execution_attestations && options.execution_attestations.length > 0) {
    const expectedBundleHash = envelope.payload_hash_b64u;
    const expectedRunId = bindingContext?.expectedRunId ?? null;

    let executionVerifiedCount = 0;
    let teeExecutionVerifiedCount = 0;

    for (let i = 0; i < options.execution_attestations.length; i++) {
      const attEnv = options.execution_attestations[i]!;
      const attPayload = attEnv.payload;
      const teeClaimed = attPayload.execution_type === 'tee_execution';

      const verification = await verifyExecutionAttestation(attEnv, {
        allowlistedSignerDids: options.allowlistedExecutionAttestationSignerDids,
        teeRootAllowlist: options.teeRootAllowlist,
        teeTcbAllowlist: options.teeTcbAllowlist,
        teeRootRevoked: options.teeRootRevoked,
        teeTcbRevoked: options.teeTcbRevoked,
      });

      if (verification.result.status !== 'VALID') {
        if (verification.error?.code === 'REVOKED') {
          return {
            result: {
              status: 'INVALID',
              reason: verification.result.reason,
              verified_at: now,
              bundle_id: payload.bundle_id,
              agent_did: payload.agent_did,
            },
            error: {
              code: 'REVOKED',
              message: verification.error.message,
              field: `execution_attestations[${i}]`,
            },
          };
        }

        if (teeClaimed) {
          return {
            result: {
              status: 'INVALID',
              reason:
                verification.result.reason ||
                'TEE execution attestation verification failed',
              verified_at: now,
              bundle_id: payload.bundle_id,
              agent_did: payload.agent_did,
            },
            error:
              verification.error ??
              {
                code: 'EVIDENCE_MISMATCH',
                message: 'TEE execution attestation verification failed',
                field: `execution_attestations[${i}]`,
              },
          };
        }

        modelIdentityRiskFlags.add('EXECUTION_ATTESTATION_VERIFY_PARTIAL_FAILURE');
        continue;
      }

      if (attPayload.agent_did !== payload.agent_did) {
        if (teeClaimed) {
          return {
            result: {
              status: 'INVALID',
              reason: 'TEE execution attestation agent_did binding mismatch',
              verified_at: now,
              bundle_id: payload.bundle_id,
              agent_did: payload.agent_did,
            },
            error: {
              code: 'EVIDENCE_MISMATCH',
              message: 'TEE execution attestation agent_did does not match proof bundle agent_did',
              field: `execution_attestations[${i}].payload.agent_did`,
            },
          };
        }

        modelIdentityRiskFlags.add('EXECUTION_ATTESTATION_BINDING_MISMATCH');
        continue;
      }

      if (!expectedRunId || attPayload.run_id !== expectedRunId) {
        if (teeClaimed) {
          return {
            result: {
              status: 'INVALID',
              reason: 'TEE execution attestation run_id binding mismatch',
              verified_at: now,
              bundle_id: payload.bundle_id,
              agent_did: payload.agent_did,
            },
            error: {
              code: 'EVIDENCE_MISMATCH',
              message: 'TEE execution attestation run_id does not match proof bundle run_id',
              field: `execution_attestations[${i}].payload.run_id`,
            },
          };
        }

        modelIdentityRiskFlags.add('EXECUTION_ATTESTATION_BINDING_MISMATCH');
        continue;
      }

      if (attPayload.proof_bundle_hash_b64u !== expectedBundleHash) {
        if (teeClaimed) {
          return {
            result: {
              status: 'INVALID',
              reason: 'TEE execution attestation proof_bundle_hash binding mismatch',
              verified_at: now,
              bundle_id: payload.bundle_id,
              agent_did: payload.agent_did,
            },
            error: {
              code: 'EVIDENCE_MISMATCH',
              message:
                'TEE execution attestation proof_bundle_hash_b64u does not match this proof bundle',
              field: `execution_attestations[${i}].payload.proof_bundle_hash_b64u`,
            },
          };
        }

        modelIdentityRiskFlags.add('EXECUTION_ATTESTATION_BINDING_MISMATCH');
        continue;
      }

      executionVerifiedCount += 1;

      if (teeClaimed) {
        teeExecutionVerifiedCount += 1;
      }
    }

    componentResults.execution_attestations_count = options.execution_attestations.length;
    componentResults.execution_attestations_verified_count = executionVerifiedCount;
    componentResults.execution_attestations_valid =
      executionVerifiedCount === options.execution_attestations.length;
    componentResults.tee_execution_verified_count = teeExecutionVerifiedCount;

    if (teeExecutionVerifiedCount > 0) {
      modelIdentityTier = 'tee_measured';
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
  let trustTier = computeTrustTier(componentResults);
  let proofTier = computeProofTier(componentResults);

  // CEC-US-005: constrained binary semantic verdicts are non-fail but must not uplift tiers.
  if (
    binarySemanticPolicyResult &&
    isBinarySemanticConstrainedVerdict(binarySemanticPolicyResult.verdict)
  ) {
    if (
      proofTier === 'gateway' ||
      proofTier === 'sandbox' ||
      proofTier === 'tee' ||
      proofTier === 'witnessed_web'
    ) {
      proofTier = 'self';
      modelIdentityRiskFlags.add('BINARY_SEMANTIC_TIER_CONSTRAINED');
    }

    if (trustTier === 'verified' || trustTier === 'attested' || trustTier === 'full') {
      trustTier = 'basic';
      modelIdentityRiskFlags.add('BINARY_SEMANTIC_TRUST_CONSTRAINED');
    }
  }

  // CVF-US-065/066: deterministic completeness semantics under partial observability.
  const completenessPolicyResult = evaluateCompletenessPolicy({
    envelope_valid: componentResults.envelope_valid,
    event_chain_declared:
      payload.event_chain !== undefined && payload.event_chain.length > 0,
    event_chain_valid: componentResults.event_chain_valid === true,
    binding_context_available: bindingContext !== null,
    receipts_declared:
      payload.receipts !== undefined && payload.receipts.length > 0,
    receipts_signature_verified_count:
      componentResults.receipts_signature_verified_count ?? 0,
    receipts_verified_count: componentResults.receipts_verified_count ?? 0,
    attestations_declared:
      payload.attestations !== undefined && payload.attestations.length > 0,
    attestations_signature_verified_count:
      componentResults.attestations_signature_verified_count ?? 0,
    attestations_verified_count:
      componentResults.attestations_verified_count ?? 0,
  });

  componentResults.completeness_verdict = completenessPolicyResult.verdict;
  componentResults.completeness_reason_code = completenessPolicyResult.reason_code;

  if (isCompletenessFailClosedVerdict(completenessPolicyResult.verdict)) {
    const reason = `Completeness policy verdict ${completenessPolicyResult.verdict} (${completenessPolicyResult.reason_code})`;

    return {
      result: {
        status: 'INVALID',
        reason,
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
      error: {
        code: 'EVIDENCE_MISMATCH',
        message: reason,
        field: 'payload',
      },
    };
  }

  if (isCompletenessConstrainedVerdict(completenessPolicyResult.verdict)) {
    if (
      proofTier === 'gateway' ||
      proofTier === 'sandbox' ||
      proofTier === 'tee' ||
      proofTier === 'witnessed_web'
    ) {
      proofTier = 'self';
      modelIdentityRiskFlags.add('COMPLETENESS_PROOF_TIER_CONSTRAINED');
    }

    if (trustTier === 'verified' || trustTier === 'attested' || trustTier === 'full') {
      trustTier = 'basic';
      modelIdentityRiskFlags.add('COMPLETENESS_TRUST_TIER_CONSTRAINED');
    }
  }

  // CVF-US-057: coverage attestation phase-gating (deterministic, fail-closed semantics)
  const enforcementPhase = resolvedCausalPolicy.coverage_enforcement_phase;

  const sentinels = metadataRecord?.sentinels;
  const claimedInterpose =
    isObjectRecord(sentinels) && sentinels.interpose_active === true;

  const coveragePolicy =
    metadataRecord && isObjectRecord(metadataRecord.coverage_enforcement)
      ? metadataRecord.coverage_enforcement
      : null;
  const coverageRequiredByMetadata = coveragePolicy?.required === true;

  const coverageCount = componentResults.coverage_attestations_count ?? 0;
  const coverageVerifiedCount = componentResults.coverage_attestations_verified_count ?? 0;
  const hasCoverageEvidence = coverageCount > 0;

  const clddDiscrepancy = evaluateClddDiscrepancy(
    clddMetricsClaim.metrics,
    coverageAttestedClddMetrics
  );

  componentResults.coverage_cldd_claimed_metrics =
    clddDiscrepancy.claimed ?? undefined;
  componentResults.coverage_cldd_attested_metrics =
    clddDiscrepancy.attested ?? undefined;
  componentResults.coverage_cldd_mismatch_fields =
    clddDiscrepancy.mismatch_fields.length > 0
      ? [...clddDiscrepancy.mismatch_fields]
      : undefined;
  componentResults.coverage_cldd_discrepancy = clddDiscrepancy.discrepancy;

  for (const flag of clddDiscrepancy.risk_flags) {
    modelIdentityRiskFlags.add(flag);
  }

  const coverageInvariantFailed =
    hasCoverageEvidence && coverageVerifiedCount < coverageCount;

  const requiredCoverage =
    enforcementPhase === 'enforce' || coverageRequiredByMetadata;
  const requiredCoverageMissing = requiredCoverage && !hasCoverageEvidence;

  if (claimedInterpose && !hasCoverageEvidence) {
    modelIdentityRiskFlags.add('COVERAGE_DEGRADED_NO_INTERPOSE');
    modelIdentityRiskFlags.add('COVERAGE_INTERPOSE_CLAIM_WITHOUT_ATTESTATION');
  }

  if (coverageInvariantFailed) {
    modelIdentityRiskFlags.add('COVERAGE_INVARIANT_FAILED');
  }

  if (requiredCoverageMissing) {
    modelIdentityRiskFlags.add('COVERAGE_REQUIRED_MISSING');
  }

  if (enforcementPhase === 'enforce' && clddDiscrepancy.discrepancy) {
    const reason =
      'Coverage enforcement is set to enforce and CLDD discrepancy was detected between runtime telemetry and coverage attestations';

    return {
      result: {
        status: 'INVALID',
        reason,
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
      error: {
        code: 'COVERAGE_CLDD_DISCREPANCY_ENFORCED',
        message: reason,
        field: 'payload.coverage_attestations',
      },
    };
  }

  if (enforcementPhase === 'enforce' && (requiredCoverageMissing || coverageInvariantFailed)) {
    const reason = requiredCoverageMissing
      ? 'Coverage enforcement is set to enforce but coverage_attestations are missing'
      : 'Coverage enforcement is set to enforce but coverage evidence failed verification invariants';

    return {
      result: {
        status: 'INVALID',
        reason,
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
      error: {
        code: 'EVIDENCE_MISMATCH',
        message: reason,
        field: 'payload.coverage_attestations',
      },
    };
  }

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
