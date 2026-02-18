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

interface ClddMetrics {
  unmediated_connections: number;
  unmonitored_spawns: number;
  escapes_suspected: boolean;
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
      const rid = p.receipts[i].payload.receipt_id;
      const field = `payload.receipts[${i}].payload.receipt_id`;
      const replay = registerReceiptReplayFingerprint({
        receiptId: rid,
        receiptType: 'gateway_receipt',
        payload: p.receipts[i].payload,
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
      const rid = p.web_receipts[i].payload.receipt_id;
      const field = `payload.web_receipts[${i}].payload.receipt_id`;
      const replay = registerReceiptReplayFingerprint({
        receiptId: rid,
        receiptType: 'web_receipt',
        payload: p.web_receipts[i].payload,
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

  const causalConnectivityMode = normalizeCausalConnectivityMode(
    options.causal_connectivity_mode
  );

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
  const enforcementPhase = options.coverage_enforcement_phase ?? 'observe';

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
