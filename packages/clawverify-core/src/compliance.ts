/**
 * Compliance report compiler (Wave 1 foundations)
 *
 * CEC-RT-001: verified-evidence ingest contract
 * CEC-RT-002: deterministic control-pack runtime
 * CEC-RT-003: fail-closed compiler state machine
 */

import {
  base64UrlDecode,
  base64UrlEncode,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto.js';
import { jcsCanonicalize } from './jcs.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ComplianceFramework =
  | 'SOC2_Type2'
  | 'ISO27001'
  | 'EU_AI_Act'
  | 'NIST_AI_RMF'
  | 'CLAW_AI_EXECUTION_ASSURANCE_V1';

export type ControlStatus =
  | 'PASS'
  | 'FAIL'
  | 'NOT_APPLICABLE'
  | 'INSUFFICIENT_EVIDENCE';

export type EvidenceType =
  | 'gateway_receipt'
  | 'tool_receipt'
  | 'side_effect_receipt'
  | 'human_approval_receipt'
  | 'wpc'
  | 'event_chain'
  | 'delegation_receipt'
  | 'log_inclusion_proof'
  | 'egress_policy_receipt'
  | 'data_handling_receipt'
  | 'coverage_attestation'
  | 'binary_semantic_evidence_attestation'
  | 'reviewer_signoff_receipt';

export interface ControlResult {
  control_id: string;
  control_name: string;
  status: ControlStatus;
  evidence_type?: EvidenceType;
  evidence_ref?: string;
  narrative?: string;
  /** Deterministic outcome code for this control branch. */
  reason_code?: string;
}

export interface ComplianceGap {
  control_id: string;
  description: string;
  recommendation: string;
}

export interface ComplianceReport {
  report_version: '1';
  framework: ComplianceFramework;
  generated_at: string;
  proof_bundle_hash_b64u: string;
  agent_did: string;
  policy_hash_b64u?: string;
  controls: ControlResult[];
  gaps: ComplianceGap[];
}

export type CompiledEvidenceControlStatus =
  | 'PASS'
  | 'FAIL'
  | 'PARTIAL'
  | 'INAPPLICABLE'
  | 'FAIL_CLOSED_INVALID_EVIDENCE';

export type CompiledEvidenceOverallStatus =
  | 'PASS'
  | 'FAIL'
  | 'PARTIAL'
  | 'FAIL_CLOSED_INVALID_EVIDENCE';

export interface CompiledEvidenceReportEvidenceRefs {
  proof_bundle_hash_b64u: string;
  ontology_hash_b64u: string;
  mapping_rules_hash_b64u: string;
  verify_result_hash_b64u: string;
}

export interface CompiledEvidenceControlResult {
  control_id: string;
  status: CompiledEvidenceControlStatus;
  reason_codes: string[];
  evidence_hashes_b64u: string[];
  waiver_applied: boolean;
}

export interface CompiledEvidenceNarrative {
  narrative_version: '1';
  report_id: string;
  generated_at: string;
  authoritative: false;
  disclaimer: string;
  authoritative_matrix_hash_b64u: string;
  authoritative_report_hash_b64u: string;
  text: string;
  generator_provider?: string;
  generator_model?: string;
}

export interface CompiledEvidenceReport {
  report_version: '1';
  report_id: string;
  compiled_at: string;
  compiler_version: string;
  evidence_refs: CompiledEvidenceReportEvidenceRefs;
  overall_status: CompiledEvidenceOverallStatus;
  matrix_hash_b64u: string;
  control_results: CompiledEvidenceControlResult[];
  narrative?: CompiledEvidenceNarrative;
}

export interface CompiledEvidenceReportEnvelope {
  envelope_version: '1';
  envelope_type: 'compiled_evidence_report';
  payload: CompiledEvidenceReport;
  payload_hash_b64u: string;
  hash_algorithm: 'SHA-256';
  signature_b64u: string;
  algorithm: 'Ed25519';
  signer_did: string;
  issued_at: string;
}

export interface AuthoritativeCompiledReportSignerInput {
  signer_did: string;
  private_key_pkcs8_b64u: string;
  issued_at?: string;
}

export interface CompiledEvidenceNarrativeRuntimeInput {
  enabled?: boolean;
  generator_provider?: string;
  generator_model?: string;
}

export interface VerifyCompiledEvidenceReportEnvelopeResult {
  status: 'VALID' | 'INVALID';
  reason: string;
  envelope_type: 'compiled_evidence_report';
  signer_did?: string;
  verified_at: string;
}

export interface VerifyCompiledEvidenceReportEnvelopeError {
  code:
    | 'SIGNATURE_INVALID'
    | 'HASH_MISMATCH'
    | 'MISSING_REQUIRED_FIELD'
    | 'SCHEMA_VALIDATION_FAILED'
    | 'UNKNOWN_ALGORITHM'
    | 'UNKNOWN_HASH_ALGORITHM'
    | 'INVALID_DID_FORMAT'
    | 'MALFORMED_ENVELOPE';
  message: string;
  field?: string;
}

export interface VerifyCompiledEvidenceReportEnvelopeResponse {
  result: VerifyCompiledEvidenceReportEnvelopeResult;
  report_id?: string;
  matrix_hash_b64u?: string;
  payload_hash_b64u?: string;
  error?: VerifyCompiledEvidenceReportEnvelopeError;
}

// ---------------------------------------------------------------------------
// Lightweight bundle shape
// ---------------------------------------------------------------------------

export interface ComplianceBundleInput {
  bundle_version?: string;
  bundle_id?: string;
  agent_did: string;
  event_chain?: unknown[];
  receipts?: Array<{
    payload?: {
      receipt_id?: string;
      model?: string;
      [key: string]: unknown;
    };
    [key: string]: unknown;
  }>;
  tool_receipts?: Array<{
    receipt_id?: string;
    tool_name?: string;
    [key: string]: unknown;
  }>;
  side_effect_receipts?: Array<{
    receipt_id?: string;
    effect_class?: string;
    [key: string]: unknown;
  }>;
  human_approval_receipts?: Array<{
    receipt_id?: string;
    approval_type?: string;
    [key: string]: unknown;
  }>;
  delegation_receipts?: Array<{
    receipt_id?: string;
    delegate_did?: string;
    delegate_bundle_hash_b64u?: string;
    [key: string]: unknown;
  }>;
  attestations?: unknown[];
  coverage_attestations?: unknown[];
  binary_semantic_evidence_attestations?: unknown[];
  metadata?: Record<string, unknown>;
}

export interface CompliancePolicyInput {
  /** Raw WPC hash (base64url). Used for CC6.1 evidence. */
  policy_hash_b64u?: string;
  /** If the WPC contains allowed_models, list them here. */
  allowed_models?: string[];
  /** Minimum model identity tier required by the WPC. */
  minimum_model_identity_tier?: string;
  /** Strict-policy gate: disables narrative generation even when runtime config requests it. */
  disable_narrative_generation?: boolean;
}

export type WaiverKind = 'COMPENSATING_CONTROL' | 'HUMAN_EXCEPTION';

export interface SignedControlWaiverInput {
  waiver_version: '1';
  waiver_id: string;
  framework: ComplianceFramework;
  control_id: string;
  bundle_hash_b64u: string;
  agent_did: string;
  waiver_kind: WaiverKind;
  issued_at: string;
  expires_at: string;
  payload_hash_b64u: string;
  hash_algorithm: 'SHA-256';
  signature_b64u: string;
  algorithm: 'Ed25519';
  signer_did: string;
}

// ---------------------------------------------------------------------------
// Authoritative Wave-1 compiler contract
// ---------------------------------------------------------------------------

export interface AuthoritativeVerificationFact {
  fact_version: '1';
  status: 'VALID' | 'INVALID';
  reason_code: string;
  reason: string;
  verified_at: string;
  verifier?: string;
  proof_tier?: string;
  agent_did?: string;
}

export interface AuthoritativeCompilerInput {
  compiler_input_version: '1';
  framework: ComplianceFramework;
  bundle_hash_b64u: string;
  bundle: ComplianceBundleInput;
  policy?: CompliancePolicyInput;
  verification_fact: AuthoritativeVerificationFact;
  waivers?: SignedControlWaiverInput[];
  compiled_report_refs?: Partial<CompiledEvidenceReportEvidenceRefs>;
  compiled_report_signer?: AuthoritativeCompiledReportSignerInput;
  narrative_runtime?: CompiledEvidenceNarrativeRuntimeInput;
}

export type AuthoritativeCompilerState =
  | 'INPUT_REJECTED'
  | 'HALTED_UPSTREAM_INVALID'
  | 'COMPILED_PASS'
  | 'COMPILED_FAIL';

export interface AuthoritativeCompilerRuntime {
  runtime_version: '1';
  engine:
    | 'clawcompiler-runtime-v1-wave1'
    | 'clawcompiler-runtime-v1-wave2'
    | 'clawcompiler-runtime-v1-wave3';
  deterministic: true;
  state: AuthoritativeCompilerState;
  framework?: ComplianceFramework;
  bundle_hash_b64u?: string;
  generated_at: string;
  global_status: 'PASS' | 'FAIL';
  global_reason_code: string;
}

export interface AuthoritativeCompilerFailure {
  reason_code: string;
  reason: string;
  upstream_reason_code?: string;
}

export interface AuthoritativeCompilerResult {
  runtime: AuthoritativeCompilerRuntime;
  report?: ComplianceReport;
  compiled_report?: CompiledEvidenceReport;
  compiled_report_envelope?: CompiledEvidenceReportEnvelope;
  failure?: AuthoritativeCompilerFailure;
}

// ---------------------------------------------------------------------------
// Constants + helpers
// ---------------------------------------------------------------------------

const DETERMINISTIC_EPOCH_ISO = '1970-01-01T00:00:00.000Z';
const REASON_CODE_RE = /^[A-Z0-9_]{1,64}$/;
const STRICT_ISO_UTC_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const BASE64_URL_RE = /^[A-Za-z0-9_-]+$/;
const COMPILED_REPORT_ID_RE = /^cer_[A-Za-z0-9._:-]+$/;
const COMPILER_VERSION_WAVE2 = 'clawcompiler-runtime-v1-wave2';
const COMPILER_VERSION_WAVE3 = 'clawcompiler-runtime-v1-wave3';
const COMPILER_MAPPING_VERSION = 'control-pack-v1';
const AI_EXECUTION_ASSURANCE_PACK_ID = 'claw.ai_execution_assurance.v1';
export const COMPILED_EVIDENCE_NARRATIVE_DISCLAIMER =
  'NON_NORMATIVE: This narrative is explanatory only and is not authoritative compliance evidence. Authoritative determinations are in compiled_evidence_report.control_results.';
const WAIVER_APPLIED_REASON_CODE = 'WAIVER_APPLIED_SIGNED';
const WAIVER_RESIDUAL_REASON_CODES = new Set([
  'RESIDUAL_COMPENSATING_CONTROL_RELIANCE',
  'RESIDUAL_HUMAN_EXCEPTION_APPLIED',
]);

interface ParseFailure {
  ok: false;
  reason_code: string;
  reason: string;
}

const FRAMEWORKS: ReadonlySet<ComplianceFramework> = new Set([
  'SOC2_Type2',
  'ISO27001',
  'EU_AI_Act',
  'NIST_AI_RMF',
  'CLAW_AI_EXECUTION_ASSURANCE_V1',
]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function isFramework(v: unknown): v is ComplianceFramework {
  return typeof v === 'string' && FRAMEWORKS.has(v as ComplianceFramework);
}

function normalizeReasonCode(raw: unknown, fallback: string): string {
  if (typeof raw !== 'string') return fallback;

  const normalized = raw
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');

  if (!normalized) return fallback;
  if (!REASON_CODE_RE.test(normalized)) return fallback;
  return normalized;
}

function resolveGeneratedAt(raw: unknown): string {
  if (typeof raw !== 'string') return DETERMINISTIC_EPOCH_ISO;
  return STRICT_ISO_UTC_RE.test(raw) ? raw : DETERMINISTIC_EPOCH_ISO;
}

function reportGeneratedAt(raw: unknown): string {
  return resolveGeneratedAt(raw);
}

function isBase64UrlString(value: unknown, minLength: number = 1): value is string {
  return (
    typeof value === 'string' &&
    value.length >= minLength &&
    BASE64_URL_RE.test(value)
  );
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const source = bytes.buffer;
  if (source instanceof ArrayBuffer) {
    return source.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }

  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function sha256B64uFromCanonical(value: unknown): Promise<string> {
  const canonical = jcsCanonicalize(value);
  const bytes = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes));
  return base64UrlEncode(new Uint8Array(digest));
}

async function sha256B64uFromString(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', toArrayBuffer(bytes));
  return base64UrlEncode(new Uint8Array(digest));
}

function ensureOptionalArrayField(
  raw: Record<string, unknown>,
  field: string,
  reason_code: string,
  reason: string,
): ParseFailure | undefined {
  const value = raw[field];
  if (value !== undefined && !Array.isArray(value)) {
    return {
      ok: false,
      reason_code,
      reason,
    };
  }
  return undefined;
}

function parseBundleInput(
  rawBundle: Record<string, unknown>,
): { ok: true; value: ComplianceBundleInput } | ParseFailure {
  if (typeof rawBundle.agent_did !== 'string' || rawBundle.agent_did.trim().length === 0) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_BUNDLE_AGENT_DID',
      reason: 'bundle.agent_did must be a non-empty string.',
    };
  }

  const collectionChecks: Array<ParseFailure | undefined> = [
    ensureOptionalArrayField(
      rawBundle,
      'event_chain',
      'COMPILER_INPUT_MALFORMED_EVENT_CHAIN',
      'bundle.event_chain, when present, must be an array.',
    ),
    ensureOptionalArrayField(
      rawBundle,
      'receipts',
      'COMPILER_INPUT_MALFORMED_RECEIPTS',
      'bundle.receipts, when present, must be an array.',
    ),
    ensureOptionalArrayField(
      rawBundle,
      'tool_receipts',
      'COMPILER_INPUT_MALFORMED_TOOL_RECEIPTS',
      'bundle.tool_receipts, when present, must be an array.',
    ),
    ensureOptionalArrayField(
      rawBundle,
      'side_effect_receipts',
      'COMPILER_INPUT_MALFORMED_SIDE_EFFECT_RECEIPTS',
      'bundle.side_effect_receipts, when present, must be an array.',
    ),
    ensureOptionalArrayField(
      rawBundle,
      'human_approval_receipts',
      'COMPILER_INPUT_MALFORMED_HUMAN_APPROVAL_RECEIPTS',
      'bundle.human_approval_receipts, when present, must be an array.',
    ),
    ensureOptionalArrayField(
      rawBundle,
      'delegation_receipts',
      'COMPILER_INPUT_MALFORMED_DELEGATION_RECEIPTS',
      'bundle.delegation_receipts, when present, must be an array.',
    ),
    ensureOptionalArrayField(
      rawBundle,
      'attestations',
      'COMPILER_INPUT_MALFORMED_ATTESTATIONS',
      'bundle.attestations, when present, must be an array.',
    ),
    ensureOptionalArrayField(
      rawBundle,
      'coverage_attestations',
      'COMPILER_INPUT_MALFORMED_COVERAGE_ATTESTATIONS',
      'bundle.coverage_attestations, when present, must be an array.',
    ),
    ensureOptionalArrayField(
      rawBundle,
      'binary_semantic_evidence_attestations',
      'COMPILER_INPUT_MALFORMED_BINARY_SEMANTIC_EVIDENCE_ATTESTATIONS',
      'bundle.binary_semantic_evidence_attestations, when present, must be an array.',
    ),
  ];

  const collectionFailure = collectionChecks.find(
    (failure): failure is ParseFailure => failure !== undefined,
  );
  if (collectionFailure) {
    return collectionFailure;
  }

  if (rawBundle.metadata !== undefined && !isRecord(rawBundle.metadata)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_BUNDLE_METADATA',
      reason: 'bundle.metadata, when present, must be a JSON object.',
    };
  }

  if (
    rawBundle.bundle_version !== undefined &&
    typeof rawBundle.bundle_version !== 'string'
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_BUNDLE_VERSION',
      reason: 'bundle.bundle_version, when present, must be a string.',
    };
  }

  if (rawBundle.bundle_id !== undefined && typeof rawBundle.bundle_id !== 'string') {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_BUNDLE_ID',
      reason: 'bundle.bundle_id, when present, must be a string.',
    };
  }

  return {
    ok: true,
    value: rawBundle as unknown as ComplianceBundleInput,
  };
}

function parsePolicyInput(
  rawPolicy: Record<string, unknown>,
): { ok: true; value: CompliancePolicyInput } | ParseFailure {
  if (rawPolicy.policy_hash_b64u !== undefined) {
    if (!isBase64UrlString(rawPolicy.policy_hash_b64u, 8)) {
      return {
        ok: false,
        reason_code: 'COMPILER_INPUT_MALFORMED_POLICY_HASH',
        reason:
          'policy.policy_hash_b64u, when present, must be base64url (min length 8).',
      };
    }
  }

  if (
    rawPolicy.minimum_model_identity_tier !== undefined &&
    typeof rawPolicy.minimum_model_identity_tier !== 'string'
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_MINIMUM_MODEL_IDENTITY_TIER',
      reason:
        'policy.minimum_model_identity_tier, when present, must be a string.',
    };
  }

  if (
    rawPolicy.disable_narrative_generation !== undefined &&
    typeof rawPolicy.disable_narrative_generation !== 'boolean'
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_DISABLE_NARRATIVE_GENERATION',
      reason:
        'policy.disable_narrative_generation, when present, must be a boolean.',
    };
  }

  if (rawPolicy.allowed_models !== undefined) {
    if (!Array.isArray(rawPolicy.allowed_models)) {
      return {
        ok: false,
        reason_code: 'COMPILER_INPUT_MALFORMED_ALLOWED_MODELS',
        reason: 'policy.allowed_models, when present, must be an array of strings.',
      };
    }

    const hasInvalidModel = rawPolicy.allowed_models.some(
      (model) => typeof model !== 'string' || model.trim().length === 0,
    );

    if (hasInvalidModel) {
      return {
        ok: false,
        reason_code: 'COMPILER_INPUT_MALFORMED_ALLOWED_MODELS',
        reason: 'policy.allowed_models, when present, must be an array of strings.',
      };
    }
  }

  return {
    ok: true,
    value: rawPolicy as CompliancePolicyInput,
  };
}

function parseCompiledReportRefsInput(
  rawRefs: Record<string, unknown>,
): { ok: true; value: Partial<CompiledEvidenceReportEvidenceRefs> } | ParseFailure {
  const refFields: Array<keyof CompiledEvidenceReportEvidenceRefs> = [
    'proof_bundle_hash_b64u',
    'ontology_hash_b64u',
    'mapping_rules_hash_b64u',
    'verify_result_hash_b64u',
  ];

  for (const field of refFields) {
    if (rawRefs[field] === undefined) continue;

    if (!isBase64UrlString(rawRefs[field], 8)) {
      return {
        ok: false,
        reason_code: 'COMPILER_INPUT_MALFORMED_COMPILED_REPORT_REFS',
        reason:
          `compiled_report_refs.${field}, when present, must be base64url (min length 8).`,
      };
    }
  }

  return {
    ok: true,
    value: rawRefs as Partial<CompiledEvidenceReportEvidenceRefs>,
  };
}

function parseCompiledReportSignerInput(
  rawSigner: Record<string, unknown>,
): { ok: true; value: AuthoritativeCompiledReportSignerInput } | ParseFailure {
  if (!isNonEmptyString(rawSigner.signer_did)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_COMPILED_REPORT_SIGNER_DID',
      reason: 'compiled_report_signer.signer_did must be a non-empty string.',
    };
  }

  if (!isNonEmptyString(rawSigner.private_key_pkcs8_b64u)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_COMPILED_REPORT_SIGNER_KEY',
      reason:
        'compiled_report_signer.private_key_pkcs8_b64u must be a non-empty string.',
    };
  }

  if (
    rawSigner.issued_at !== undefined &&
    (!isNonEmptyString(rawSigner.issued_at) || !STRICT_ISO_UTC_RE.test(rawSigner.issued_at))
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_COMPILED_REPORT_SIGNER_ISSUED_AT',
      reason:
        'compiled_report_signer.issued_at, when present, must be a strict UTC ISO-8601 timestamp.',
    };
  }

  return {
    ok: true,
    value: {
      signer_did: rawSigner.signer_did,
      private_key_pkcs8_b64u: rawSigner.private_key_pkcs8_b64u,
      issued_at: rawSigner.issued_at,
    },
  };
}

function parseNarrativeRuntimeInput(
  rawNarrativeRuntime: Record<string, unknown>,
): { ok: true; value: CompiledEvidenceNarrativeRuntimeInput } | ParseFailure {
  if (
    rawNarrativeRuntime.enabled !== undefined &&
    typeof rawNarrativeRuntime.enabled !== 'boolean'
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_NARRATIVE_RUNTIME_ENABLED',
      reason: 'narrative_runtime.enabled, when present, must be a boolean.',
    };
  }

  if (
    rawNarrativeRuntime.generator_provider !== undefined &&
    !isNonEmptyString(rawNarrativeRuntime.generator_provider)
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_NARRATIVE_GENERATOR_PROVIDER',
      reason:
        'narrative_runtime.generator_provider, when present, must be a non-empty string.',
    };
  }

  if (
    rawNarrativeRuntime.generator_model !== undefined &&
    !isNonEmptyString(rawNarrativeRuntime.generator_model)
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_NARRATIVE_GENERATOR_MODEL',
      reason:
        'narrative_runtime.generator_model, when present, must be a non-empty string.',
    };
  }

  return {
    ok: true,
    value: {
      enabled:
        typeof rawNarrativeRuntime.enabled === 'boolean'
          ? rawNarrativeRuntime.enabled
          : undefined,
      generator_provider: asString(rawNarrativeRuntime.generator_provider),
      generator_model: asString(rawNarrativeRuntime.generator_model),
    },
  };
}

function parseSignedControlWaiverInput(
  rawWaiver: Record<string, unknown>,
): { ok: true; value: SignedControlWaiverInput } | ParseFailure {
  if (rawWaiver.waiver_version !== '1') {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_VERSION',
      reason: 'waivers[].waiver_version must equal "1".',
    };
  }

  if (!isNonEmptyString(rawWaiver.waiver_id)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_ID',
      reason: 'waivers[].waiver_id must be a non-empty string.',
    };
  }

  if (!isFramework(rawWaiver.framework)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_FRAMEWORK',
      reason: 'waivers[].framework must be a supported compliance framework identifier.',
    };
  }

  if (!isNonEmptyString(rawWaiver.control_id)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_CONTROL_ID',
      reason: 'waivers[].control_id must be a non-empty string.',
    };
  }

  if (!isBase64UrlString(rawWaiver.bundle_hash_b64u, 8)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_BUNDLE_HASH',
      reason: 'waivers[].bundle_hash_b64u must be base64url (min length 8).',
    };
  }

  if (!isNonEmptyString(rawWaiver.agent_did)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_AGENT_DID',
      reason: 'waivers[].agent_did must be a non-empty string.',
    };
  }

  if (
    rawWaiver.waiver_kind !== 'COMPENSATING_CONTROL' &&
    rawWaiver.waiver_kind !== 'HUMAN_EXCEPTION'
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_KIND',
      reason:
        'waivers[].waiver_kind must be COMPENSATING_CONTROL or HUMAN_EXCEPTION.',
    };
  }

  if (!isNonEmptyString(rawWaiver.issued_at) || !STRICT_ISO_UTC_RE.test(rawWaiver.issued_at)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_ISSUED_AT',
      reason: 'waivers[].issued_at must be a strict UTC ISO-8601 timestamp.',
    };
  }

  if (
    !isNonEmptyString(rawWaiver.expires_at) ||
    !STRICT_ISO_UTC_RE.test(rawWaiver.expires_at)
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_EXPIRES_AT',
      reason: 'waivers[].expires_at must be a strict UTC ISO-8601 timestamp.',
    };
  }

  if (!isBase64UrlString(rawWaiver.payload_hash_b64u, 8)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_PAYLOAD_HASH',
      reason: 'waivers[].payload_hash_b64u must be base64url (min length 8).',
    };
  }

  if (rawWaiver.hash_algorithm !== 'SHA-256') {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_HASH_ALGORITHM',
      reason: 'waivers[].hash_algorithm must equal "SHA-256".',
    };
  }

  if (rawWaiver.algorithm !== 'Ed25519') {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_ALGORITHM',
      reason: 'waivers[].algorithm must equal "Ed25519".',
    };
  }

  if (!isBase64UrlString(rawWaiver.signature_b64u, 8)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_SIGNATURE',
      reason: 'waivers[].signature_b64u must be base64url (min length 8).',
    };
  }

  if (!isNonEmptyString(rawWaiver.signer_did) || !rawWaiver.signer_did.startsWith('did:key:')) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER_SIGNER_DID',
      reason: 'waivers[].signer_did must be a did:key DID.',
    };
  }

  return {
    ok: true,
    value: {
      waiver_version: '1',
      waiver_id: rawWaiver.waiver_id as string,
      framework: rawWaiver.framework as ComplianceFramework,
      control_id: rawWaiver.control_id as string,
      bundle_hash_b64u: rawWaiver.bundle_hash_b64u as string,
      agent_did: rawWaiver.agent_did as string,
      waiver_kind: rawWaiver.waiver_kind as WaiverKind,
      issued_at: rawWaiver.issued_at as string,
      expires_at: rawWaiver.expires_at as string,
      payload_hash_b64u: rawWaiver.payload_hash_b64u as string,
      hash_algorithm: 'SHA-256',
      signature_b64u: rawWaiver.signature_b64u as string,
      algorithm: 'Ed25519',
      signer_did: rawWaiver.signer_did as string,
    },
  };
}

function parseSignedControlWaiversInput(
  rawWaivers: unknown,
): { ok: true; value: SignedControlWaiverInput[] } | ParseFailure {
  if (!Array.isArray(rawWaivers)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVERS',
      reason: 'waivers, when present, must be an array.',
    };
  }

  const waivers: SignedControlWaiverInput[] = [];
  const seenWaiverIds = new Set<string>();

  for (const entry of rawWaivers) {
    if (!isRecord(entry)) {
      return {
        ok: false,
        reason_code: 'COMPILER_INPUT_MALFORMED_WAIVER',
        reason: 'Each waivers[] entry must be a JSON object.',
      };
    }

    const parsedWaiver = parseSignedControlWaiverInput(entry);
    if (!parsedWaiver.ok) {
      return parsedWaiver;
    }

    if (seenWaiverIds.has(parsedWaiver.value.waiver_id)) {
      return {
        ok: false,
        reason_code: 'COMPILER_INPUT_DUPLICATE_WAIVER_ID',
        reason: `Duplicate waiver_id detected: ${parsedWaiver.value.waiver_id}`,
      };
    }

    seenWaiverIds.add(parsedWaiver.value.waiver_id);
    waivers.push(parsedWaiver.value);
  }

  waivers.sort((a, b) => a.waiver_id.localeCompare(b.waiver_id));

  return {
    ok: true,
    value: waivers,
  };
}

function hashBundle(_bundle: ComplianceBundleInput): string {
  // Deterministic fallback only. Authoritative compiler requires caller-provided
  // bundle_hash_b64u and never relies on this value.
  return 'UNSPECIFIED_BUNDLE_HASH';
}

function hasFileWriteReceipts(bundle: ComplianceBundleInput): boolean {
  return (bundle.tool_receipts ?? []).length > 0;
}

function hasHumanApprovals(bundle: ComplianceBundleInput): boolean {
  return (bundle.human_approval_receipts ?? []).some(
    (r) => r.approval_type === 'explicit_approve',
  );
}

function hasGatewayReceipts(bundle: ComplianceBundleInput): boolean {
  return (bundle.receipts ?? []).length > 0;
}

function hasEventChain(bundle: ComplianceBundleInput): boolean {
  return (bundle.event_chain ?? []).length > 0;
}

// ---------------------------------------------------------------------------
// SOC2 Type II Mapper (deterministic branch reason codes)
// ---------------------------------------------------------------------------

function mapCC6_1(
  bundle: ComplianceBundleInput,
  policy: CompliancePolicyInput | undefined,
): ControlResult {
  const control: ControlResult = {
    control_id: 'CC6.1',
    control_name: 'Logical Access Controls',
    status: 'INSUFFICIENT_EVIDENCE',
    reason_code: 'CC6_1_UNEVALUATED',
  };

  if (policy?.allowed_models && policy.allowed_models.length > 0) {
    const gatewayModels = (bundle.receipts ?? [])
      .map((r) => r.payload?.model)
      .filter((m): m is string => typeof m === 'string' && m.length > 0);

    if (gatewayModels.length > 0) {
      const allWithinPolicy = gatewayModels.every((m) =>
        policy.allowed_models!.includes(m),
      );

      control.status = allWithinPolicy ? 'PASS' : 'FAIL';
      control.evidence_type = 'wpc';
      control.evidence_ref = policy.policy_hash_b64u;
      control.reason_code = allWithinPolicy
        ? 'CC6_1_PASS_WPC_ALLOWLIST_ENFORCED'
        : 'CC6_1_FAIL_MODEL_OUTSIDE_WPC_ALLOWLIST';
      control.narrative = allWithinPolicy
        ? `All ${gatewayModels.length} gateway receipt(s) reference models within the WPC allowlist (${policy.allowed_models.join(', ')}).`
        : `One or more gateway receipts reference a model outside the WPC allowlist. Models used: ${gatewayModels.join(', ')}.`;
      return control;
    }

    control.status = 'INSUFFICIENT_EVIDENCE';
    control.reason_code = 'CC6_1_MISSING_GATEWAY_RECEIPTS_FOR_WPC';
    control.narrative =
      'WPC defines allowed_models but no gateway receipts are present to prove model usage.';
    return control;
  }

  if (hasGatewayReceipts(bundle)) {
    const firstGatewayReceiptId = bundle.receipts?.[0]?.payload?.receipt_id;

    control.status = 'PASS';
    control.evidence_type = 'gateway_receipt';
    control.evidence_ref = firstGatewayReceiptId;
    control.reason_code = 'CC6_1_PASS_GATEWAY_RECEIPTS_PRESENT';
    control.narrative =
      'Gateway receipts are present. No WPC model allowlist was supplied; add allowed_models for stronger CC6.1 evidence.';
    return control;
  }

  control.status = 'INSUFFICIENT_EVIDENCE';
  control.reason_code = 'CC6_1_MISSING_WPC_AND_GATEWAY_RECEIPTS';
  control.narrative =
    'No gateway receipts and no WPC allowlist are present. Logical access evidence is incomplete.';
  return control;
}

function mapCC6_2(bundle: ComplianceBundleInput): ControlResult {
  const control: ControlResult = {
    control_id: 'CC6.2',
    control_name: 'System Boundary Controls',
    status: 'INSUFFICIENT_EVIDENCE',
    reason_code: 'CC6_2_UNEVALUATED',
  };

  const sideEffects = bundle.side_effect_receipts ?? [];
  const networkReceipts = sideEffects.filter(
    (r) => r.effect_class === 'network_egress',
  );

  if (networkReceipts.length > 0) {
    control.status = 'PASS';
    control.evidence_type = 'side_effect_receipt';
    control.evidence_ref = networkReceipts[0]?.receipt_id;
    control.reason_code = 'CC6_2_PASS_NETWORK_EGRESS_RECEIPTS_PRESENT';
    control.narrative = `${networkReceipts.length} network egress side-effect receipt(s) are present.`;
    return control;
  }

  if (sideEffects.length > 0) {
    control.status = 'PASS';
    control.evidence_type = 'side_effect_receipt';
    control.evidence_ref = sideEffects[0]?.receipt_id;
    control.reason_code = 'CC6_2_PASS_SIDE_EFFECT_RECEIPTS_NON_NETWORK';
    control.narrative =
      'Side-effect receipts are present and no network egress side effects were recorded.';
    return control;
  }

  control.status = 'INSUFFICIENT_EVIDENCE';
  control.reason_code = 'CC6_2_MISSING_SIDE_EFFECT_RECEIPTS';
  control.narrative =
    'No side-effect receipts are present. Boundary controls cannot be evidenced.';
  return control;
}

function mapCC7_1(bundle: ComplianceBundleInput): ControlResult {
  const control: ControlResult = {
    control_id: 'CC7.1',
    control_name: 'Detection of Changes',
    status: 'INSUFFICIENT_EVIDENCE',
    reason_code: 'CC7_1_UNEVALUATED',
  };

  if (hasFileWriteReceipts(bundle)) {
    control.status = 'PASS';
    control.evidence_type = 'tool_receipt';
    control.evidence_ref = bundle.tool_receipts?.[0]?.receipt_id;
    control.reason_code = 'CC7_1_PASS_TOOL_RECEIPTS_PRESENT';
    control.narrative = `${bundle.tool_receipts?.length ?? 0} tool receipt(s) are present.`;
    return control;
  }

  if (hasEventChain(bundle)) {
    control.status = 'INSUFFICIENT_EVIDENCE';
    control.evidence_type = 'event_chain';
    control.reason_code = 'CC7_1_MISSING_TOOL_RECEIPTS';
    control.narrative =
      'Event chain exists, but required tool receipts are missing for file/tool change detection.';
    return control;
  }

  control.status = 'INSUFFICIENT_EVIDENCE';
  control.reason_code = 'CC7_1_MISSING_EVENT_CHAIN_AND_TOOL_RECEIPTS';
  control.narrative =
    'No event chain and no tool receipts are present. Change detection evidence is missing.';
  return control;
}

function mapCC7_2(bundle: ComplianceBundleInput): ControlResult {
  const control: ControlResult = {
    control_id: 'CC7.2',
    control_name: 'System Monitoring',
    status: 'INSUFFICIENT_EVIDENCE',
    reason_code: 'CC7_2_UNEVALUATED',
  };

  if (hasEventChain(bundle)) {
    control.status = 'PASS';
    control.evidence_type = 'event_chain';
    control.reason_code = 'CC7_2_PASS_EVENT_CHAIN_PRESENT';
    control.narrative = `Hash-linked event chain present with ${bundle.event_chain?.length ?? 0} event(s).`;
    return control;
  }

  control.status = 'INSUFFICIENT_EVIDENCE';
  control.reason_code = 'CC7_2_MISSING_EVENT_CHAIN';
  control.narrative =
    'No event chain is present. Monitoring evidence is incomplete.';
  return control;
}

function mapCC8_1(bundle: ComplianceBundleInput): ControlResult {
  const control: ControlResult = {
    control_id: 'CC8.1',
    control_name: 'Change Management',
    status: 'INSUFFICIENT_EVIDENCE',
    reason_code: 'CC8_1_UNEVALUATED',
  };

  if (hasHumanApprovals(bundle)) {
    const approvals = (bundle.human_approval_receipts ?? []).filter(
      (r) => r.approval_type === 'explicit_approve',
    );

    control.status = 'PASS';
    control.evidence_type = 'human_approval_receipt';
    control.evidence_ref = approvals[0]?.receipt_id;
    control.reason_code = 'CC8_1_PASS_HUMAN_APPROVAL_PRESENT';
    control.narrative = `${approvals.length} explicit human approval receipt(s) are present.`;
    return control;
  }

  if (hasGatewayReceipts(bundle)) {
    control.status = 'PASS';
    control.evidence_type = 'gateway_receipt';
    control.evidence_ref = bundle.receipts?.[0]?.payload?.receipt_id;
    control.reason_code = 'CC8_1_PASS_GATEWAY_RECEIPT_EVIDENCE';
    control.narrative =
      'Gateway receipts are present. No explicit human approval receipts were provided.';
    return control;
  }

  control.status = 'INSUFFICIENT_EVIDENCE';
  control.reason_code = 'CC8_1_MISSING_HUMAN_APPROVAL_AND_GATEWAY_RECEIPTS';
  control.narrative =
    'No human approval receipts and no gateway receipts are present.';
  return control;
}

/**
 * Maps a proof bundle to SOC2 Type II controls.
 */
export function mapToSOC2(
  bundle: ComplianceBundleInput,
  policy?: CompliancePolicyInput,
  opts?: { bundleHash?: string; generatedAt?: string },
): ComplianceReport {
  const controls: ControlResult[] = [
    mapCC6_1(bundle, policy),
    mapCC6_2(bundle),
    mapCC7_1(bundle),
    mapCC7_2(bundle),
    mapCC8_1(bundle),
  ];

  const gaps: ComplianceGap[] = [];

  for (const c of controls) {
    if (c.status === 'FAIL' || c.status === 'INSUFFICIENT_EVIDENCE') {
      gaps.push({
        control_id: c.control_id,
        description:
          c.narrative ??
          (c.status === 'FAIL'
            ? `Control ${c.control_id} failed evaluation.`
            : `Insufficient evidence for ${c.control_id}.`),
        recommendation: getRemediation(c.control_id),
      });
    }
  }

  return {
    report_version: '1',
    framework: 'SOC2_Type2',
    generated_at: reportGeneratedAt(opts?.generatedAt),
    proof_bundle_hash_b64u: opts?.bundleHash ?? hashBundle(bundle),
    agent_did: bundle.agent_did,
    policy_hash_b64u: policy?.policy_hash_b64u,
    controls,
    gaps,
  };
}

function getRemediation(controlId: string): string {
  switch (controlId) {
    case 'CC6.1':
      return 'Configure a Work Policy Contract (WPC) with allowed_models and route LLM calls through clawproxy to generate gateway receipts.';
    case 'CC6.2':
      return 'Instrument the agent harness to emit side_effect_receipts for all network egress calls.';
    case 'CC7.1':
      return 'Instrument the agent harness to emit tool_receipts for all file system operations and tool invocations.';
    case 'CC7.2':
      return 'Configure the agent harness to emit a hash-linked event chain. Enable Receipt Transparency Log integration for Merkle tree inclusion proofs.';
    case 'CC8.1':
      return 'Add human-in-the-loop approval gates for high-risk actions, or route through clawproxy for gateway-tier evidence.';
    default:
      return 'Review the Clawsig Protocol documentation for instrumentation guidance.';
  }
}

// ---------------------------------------------------------------------------
// ISO 27001 Mapper (stub)
// ---------------------------------------------------------------------------

export function mapToISO27001(
  bundle: ComplianceBundleInput,
  policy?: CompliancePolicyInput,
  opts?: { bundleHash?: string; generatedAt?: string },
): ComplianceReport {
  return {
    report_version: '1',
    framework: 'ISO27001',
    generated_at: reportGeneratedAt(opts?.generatedAt),
    proof_bundle_hash_b64u: opts?.bundleHash ?? hashBundle(bundle),
    agent_did: bundle.agent_did,
    policy_hash_b64u: policy?.policy_hash_b64u,
    controls: [
      {
        control_id: 'A.9.1',
        control_name: 'Access Control Policy',
        status: 'NOT_APPLICABLE',
        reason_code: 'ISO27001_MAPPER_NOT_IMPLEMENTED',
        narrative:
          'ISO 27001 mapper not yet implemented. SOC2 mapping is currently available.',
      },
    ],
    gaps: [
      {
        control_id: 'A.9.1',
        description: 'ISO 27001 compliance mapping is not yet implemented.',
        recommendation:
          'Use SOC2 framework for current compliance reporting. ISO 27001 support is planned.',
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// EU AI Act Mapper (stub)
// ---------------------------------------------------------------------------

export function mapToEUAIAct(
  bundle: ComplianceBundleInput,
  policy?: CompliancePolicyInput,
  opts?: { bundleHash?: string; generatedAt?: string },
): ComplianceReport {
  const hasApprovals = hasHumanApprovals(bundle);
  const firstApproval = bundle.human_approval_receipts?.find(
    (r) => r.approval_type === 'explicit_approve',
  );

  return {
    report_version: '1',
    framework: 'EU_AI_Act',
    generated_at: reportGeneratedAt(opts?.generatedAt),
    proof_bundle_hash_b64u: opts?.bundleHash ?? hashBundle(bundle),
    agent_did: bundle.agent_did,
    policy_hash_b64u: policy?.policy_hash_b64u,
    controls: [
      {
        control_id: 'Art14',
        control_name: 'Human Oversight',
        status: hasApprovals ? 'PASS' : 'INSUFFICIENT_EVIDENCE',
        evidence_type: hasApprovals ? 'human_approval_receipt' : undefined,
        evidence_ref: hasApprovals ? firstApproval?.receipt_id : undefined,
        reason_code: hasApprovals
          ? 'ART14_PASS_HUMAN_APPROVAL_PRESENT'
          : 'ART14_MISSING_HUMAN_APPROVAL',
        narrative: hasApprovals
          ? 'Cryptographic proof of Article 14 human oversight is present.'
          : 'No human approval receipts present. Article 14 evidence is incomplete.',
      },
    ],
    gaps: hasApprovals
      ? []
      : [
          {
            control_id: 'Art14',
            description:
              'No human approval receipts. EU AI Act Article 14 requires verifiable human oversight.',
            recommendation:
              'Add human-in-the-loop approval gates and emit human_approval_receipts for high-risk operations.',
          },
        ],
  };
}

function getBundleMetadata(
  bundle: ComplianceBundleInput,
): Record<string, unknown> | undefined {
  return isRecord(bundle.metadata) ? bundle.metadata : undefined;
}

function getPolicyBindingHash(bundle: ComplianceBundleInput): string | undefined {
  const metadata = getBundleMetadata(bundle);
  if (!metadata) return undefined;
  if (!isRecord(metadata.policy_binding)) return undefined;

  const hash = metadata.policy_binding.effective_policy_hash_b64u;
  return isBase64UrlString(hash, 8) ? hash : undefined;
}

function getEgressPolicyReceiptPayload(
  bundle: ComplianceBundleInput,
): Record<string, unknown> | undefined {
  const metadata = getBundleMetadata(bundle);
  if (!metadata) return undefined;

  const sentinels = metadata.sentinels;
  if (!isRecord(sentinels)) return undefined;

  const receiptEnvelope = sentinels.egress_policy_receipt;
  if (!isRecord(receiptEnvelope)) return undefined;

  const payload = receiptEnvelope.payload;
  if (!isRecord(payload)) return undefined;

  return payload;
}

function getDataHandlingReceipts(bundle: ComplianceBundleInput): Record<string, unknown>[] {
  const metadata = getBundleMetadata(bundle);
  if (!metadata) return [];

  const dataHandling = metadata.data_handling;
  if (!isRecord(dataHandling)) return [];

  const receipts = dataHandling.receipts;
  if (!Array.isArray(receipts)) return [];

  return receipts.filter(isRecord);
}

function getReviewerSignoffReceipts(
  bundle: ComplianceBundleInput,
): Record<string, unknown>[] {
  const metadata = getBundleMetadata(bundle);
  if (!metadata) return [];

  const reviewerReceipts = metadata.reviewer_signoff_receipts;
  if (!Array.isArray(reviewerReceipts)) return [];

  return reviewerReceipts.filter(isRecord);
}

function getAxaRemediation(controlId: string): string {
  switch (controlId) {
    case 'AXA.POLICY.1':
      return 'Provide policy hash evidence via policy.policy_hash_b64u or metadata.policy_binding.effective_policy_hash_b64u.';
    case 'AXA.APPROVAL.1':
      return 'Emit explicit_approve human approval receipts for governed high-impact actions.';
    case 'AXA.EGRESS.1':
      return 'Include signed metadata.sentinels.egress_policy_receipt with proofed_mode=true and direct_provider_access_blocked=true.';
    case 'AXA.DLP.1':
      return 'Include signed metadata.data_handling.receipts with enforcement.mode="enforced" for all observed decisions.';
    case 'AXA.ATTESTATION.1':
      return 'Include verified coverage_attestations and/or binary_semantic_evidence_attestations in the proof bundle.';
    case 'AXA.REVIEW.1':
      return 'Include signed metadata.reviewer_signoff_receipts bound to the run/event chain.';
    default:
      return 'Provide signed and verifier-backed execution assurance evidence for this control.';
  }
}

export function mapToAIExecutionAssurancePackV1(
  bundle: ComplianceBundleInput,
  policy?: CompliancePolicyInput,
  opts?: { bundleHash?: string; generatedAt?: string },
): ComplianceReport {
  const controls: ControlResult[] = [];

  const boundPolicyHash = getPolicyBindingHash(bundle);
  const inputPolicyHash = policy?.policy_hash_b64u;

  let policyStatus: ControlStatus = 'FAIL';
  let policyEvidenceRef = boundPolicyHash ?? inputPolicyHash;
  let policyReasonCode = 'AXA_POLICY_FAIL_MISSING_POLICY_BINDING_EVIDENCE';
  let policyNarrative =
    'No verified bundle policy binding hash is present in metadata.policy_binding.effective_policy_hash_b64u.';

  if (boundPolicyHash && inputPolicyHash && boundPolicyHash !== inputPolicyHash) {
    policyReasonCode = 'AXA_POLICY_FAIL_POLICY_HASH_MISMATCH';
    policyNarrative =
      'Compiler input policy.policy_hash_b64u does not match the verified bundle policy binding hash.';
  } else if (boundPolicyHash) {
    policyStatus = 'PASS';
    policyReasonCode = inputPolicyHash
      ? 'AXA_POLICY_PASS_BOUND_POLICY_HASH_MATCHED'
      : 'AXA_POLICY_PASS_BOUND_POLICY_HASH_PRESENT';
    policyNarrative = inputPolicyHash
      ? 'Verified bundle policy binding hash matches compiler input policy.policy_hash_b64u.'
      : 'Verified bundle policy binding hash is present in proof-bundle metadata.';
  } else if (inputPolicyHash) {
    policyReasonCode = 'AXA_POLICY_FAIL_UNBOUND_POLICY_HASH_INPUT';
    policyNarrative =
      'Compiler input policy.policy_hash_b64u was supplied, but no verified bundle policy binding hash is present.';
  }

  controls.push({
    control_id: 'AXA.POLICY.1',
    control_name: 'Execution policy hash binding',
    status: policyStatus,
    evidence_type: policyEvidenceRef ? 'wpc' : undefined,
    evidence_ref: policyEvidenceRef,
    reason_code: policyReasonCode,
    narrative: policyNarrative,
  });

  const explicitApprovals = (bundle.human_approval_receipts ?? []).filter(
    (receipt) => receipt.approval_type === 'explicit_approve',
  );

  controls.push({
    control_id: 'AXA.APPROVAL.1',
    control_name: 'Explicit approval evidence',
    status: explicitApprovals.length > 0 ? 'PASS' : 'FAIL',
    evidence_type: explicitApprovals.length > 0 ? 'human_approval_receipt' : undefined,
    evidence_ref: explicitApprovals[0]?.receipt_id,
    reason_code:
      explicitApprovals.length > 0
        ? 'AXA_APPROVAL_PASS_EXPLICIT_APPROVAL_PRESENT'
        : 'AXA_APPROVAL_FAIL_MISSING_EXPLICIT_APPROVAL',
    narrative:
      explicitApprovals.length > 0
        ? `${explicitApprovals.length} explicit approval receipt(s) are present.`
        : 'No explicit approval receipt is present.',
  });

  const egressPayload = getEgressPolicyReceiptPayload(bundle);
  const networkEgressSideEffects = (bundle.side_effect_receipts ?? []).filter(
    (receipt) => receipt.effect_class === 'network_egress',
  );
  const egressProofedMode = egressPayload?.proofed_mode === true;
  const egressDirectBlocked = egressPayload?.direct_provider_access_blocked === true;
  const egressEvidenceRef = isNonEmptyString(egressPayload?.receipt_id)
    ? egressPayload.receipt_id
    : undefined;

  let egressReason = 'AXA_EGRESS_FAIL_MISSING_SIGNED_EGRESS_POLICY_RECEIPT';
  let egressNarrative =
    'No signed egress policy receipt is present in metadata.sentinels.egress_policy_receipt.';
  let egressStatus: ControlStatus = 'FAIL';

  if (egressPayload && egressProofedMode && egressDirectBlocked) {
    egressStatus = 'PASS';
    egressReason = 'AXA_EGRESS_PASS_SIGNED_POLICY_RECEIPT_PRESENT';
    egressNarrative =
      'Signed egress policy receipt shows proofed_mode=true and direct_provider_access_blocked=true.';
  } else if (egressPayload) {
    egressReason = 'AXA_EGRESS_FAIL_POLICY_RECEIPT_FLAGS_UNSAFE';
    egressNarrative =
      'Signed egress policy receipt is present but proofed_mode/direct_provider_access_blocked flags are not both true.';
  } else if (networkEgressSideEffects.length > 0) {
    egressReason =
      'AXA_EGRESS_FAIL_NETWORK_ACTIVITY_WITHOUT_SIGNED_EGRESS_POLICY_RECEIPT';
    egressNarrative =
      'Network egress side-effect evidence exists but no signed egress policy receipt was provided.';
  }

  controls.push({
    control_id: 'AXA.EGRESS.1',
    control_name: 'Proxy and egress hygiene evidence',
    status: egressStatus,
    evidence_type: egressPayload ? 'egress_policy_receipt' : undefined,
    evidence_ref: egressEvidenceRef,
    reason_code: egressReason,
    narrative: egressNarrative,
  });

  const dataHandlingReceipts = getDataHandlingReceipts(bundle);
  const dataHandlingEvidenceRef = dataHandlingReceipts.find((receipt) => {
    const payload = receipt.payload;
    return isRecord(payload) && isNonEmptyString(payload.receipt_id);
  });

  const enforcementModes = dataHandlingReceipts.map((receipt) => {
    const payload = receipt.payload;
    if (!isRecord(payload) || !isRecord(payload.enforcement)) {
      return undefined;
    }
    return asString(payload.enforcement.mode);
  });

  const allReceiptsEnforced =
    dataHandlingReceipts.length > 0 &&
    enforcementModes.length === dataHandlingReceipts.length &&
    enforcementModes.every((mode) => mode === 'enforced');

  const dataHandlingEvidenceRefId = (() => {
    if (!dataHandlingEvidenceRef) return undefined;
    const payload = dataHandlingEvidenceRef.payload;
    if (!isRecord(payload)) return undefined;
    return asString(payload.receipt_id);
  })();

  controls.push({
    control_id: 'AXA.DLP.1',
    control_name: 'DLP/privacy handling evidence',
    status: allReceiptsEnforced ? 'PASS' : 'FAIL',
    evidence_type: dataHandlingReceipts.length > 0 ? 'data_handling_receipt' : undefined,
    evidence_ref: dataHandlingEvidenceRefId,
    reason_code:
      allReceiptsEnforced
        ? 'AXA_DLP_PASS_ENFORCED_DATA_HANDLING_RECEIPTS_PRESENT'
        : dataHandlingReceipts.length > 0
          ? 'AXA_DLP_FAIL_NON_ENFORCED_DATA_HANDLING_RECEIPT_MODE'
          : 'AXA_DLP_FAIL_MISSING_DATA_HANDLING_RECEIPTS',
    narrative: allReceiptsEnforced
      ? `Signed data handling receipts are present with enforced mode (${dataHandlingReceipts.length} receipt(s)).`
      : dataHandlingReceipts.length > 0
        ? 'Signed data handling receipts exist, but at least one receipt is not in enforced mode.'
        : 'No signed data handling receipt evidence is present.',
  });

  const coverageAttestationCount = bundle.coverage_attestations?.length ?? 0;
  const binarySemanticAttestationCount =
    bundle.binary_semantic_evidence_attestations?.length ?? 0;

  const firstCoverageAttestation = bundle.coverage_attestations?.[0];
  let firstCoverageAttestationId: string | undefined;
  if (isRecord(firstCoverageAttestation) && isRecord(firstCoverageAttestation.payload)) {
    firstCoverageAttestationId = asString(firstCoverageAttestation.payload.attestation_id);
  }

  const firstBinarySemanticEvidence =
    bundle.binary_semantic_evidence_attestations?.[0];
  let firstBinarySemanticEvidenceHash: string | undefined;
  if (
    isRecord(firstBinarySemanticEvidence) &&
    isRecord(firstBinarySemanticEvidence.payload)
  ) {
    firstBinarySemanticEvidenceHash = asString(
      firstBinarySemanticEvidence.payload.binary_hash_b64u,
    );
  }

  const hasAttestationEvidence =
    coverageAttestationCount > 0 || binarySemanticAttestationCount > 0;

  controls.push({
    control_id: 'AXA.ATTESTATION.1',
    control_name: 'Attestation posture evidence',
    status: hasAttestationEvidence ? 'PASS' : 'FAIL',
    evidence_type:
      coverageAttestationCount > 0
        ? 'coverage_attestation'
        : binarySemanticAttestationCount > 0
          ? 'binary_semantic_evidence_attestation'
          : undefined,
    evidence_ref: firstCoverageAttestationId ?? firstBinarySemanticEvidenceHash,
    reason_code: hasAttestationEvidence
      ? 'AXA_ATTESTATION_PASS_RUNTIME_ATTESTATION_PRESENT'
      : 'AXA_ATTESTATION_FAIL_MISSING_RUNTIME_ATTESTATION_EVIDENCE',
    narrative: hasAttestationEvidence
      ? `Runtime attestation evidence present (coverage=${coverageAttestationCount}, binary_semantic=${binarySemanticAttestationCount}).`
      : 'No runtime attestation evidence is present (coverage/binary semantic attestations missing).',
  });

  const reviewerSignoffReceipts = getReviewerSignoffReceipts(bundle);
  const reviewerDecisionEvidence = reviewerSignoffReceipts.find((receipt) => {
    const payload = receipt.payload;
    if (!isRecord(payload)) return false;
    const decision = asString(payload.decision);
    return decision === 'approve' || decision === 'reject' || decision === 'needs_changes';
  });

  const reviewerEvidenceRefId = (() => {
    if (!reviewerDecisionEvidence) return undefined;
    const payload = reviewerDecisionEvidence.payload;
    if (!isRecord(payload)) return undefined;
    return asString(payload.receipt_id);
  })();

  controls.push({
    control_id: 'AXA.REVIEW.1',
    control_name: 'Reviewer signoff evidence',
    status: reviewerDecisionEvidence ? 'PASS' : 'FAIL',
    evidence_type: reviewerDecisionEvidence ? 'reviewer_signoff_receipt' : undefined,
    evidence_ref: reviewerEvidenceRefId,
    reason_code: reviewerDecisionEvidence
      ? 'AXA_REVIEW_PASS_SIGNOFF_RECEIPT_PRESENT'
      : reviewerSignoffReceipts.length > 0
        ? 'AXA_REVIEW_FAIL_SIGNOFF_DECISION_UNRECOGNIZED'
        : 'AXA_REVIEW_FAIL_MISSING_SIGNOFF_RECEIPTS',
    narrative: reviewerDecisionEvidence
      ? `Reviewer signoff evidence is present (${reviewerSignoffReceipts.length} receipt(s)).`
      : reviewerSignoffReceipts.length > 0
        ? 'Reviewer signoff receipts are present but decision fields are malformed or unsupported.'
        : 'No reviewer signoff receipt evidence is present.',
  });

  const gaps: ComplianceGap[] = [];
  for (const control of controls) {
    if (control.status === 'FAIL' || control.status === 'INSUFFICIENT_EVIDENCE') {
      gaps.push({
        control_id: control.control_id,
        description: control.narrative ?? `Control ${control.control_id} failed.`,
        recommendation: getAxaRemediation(control.control_id),
      });
    }
  }

  return {
    report_version: '1',
    framework: 'CLAW_AI_EXECUTION_ASSURANCE_V1',
    generated_at: reportGeneratedAt(opts?.generatedAt),
    proof_bundle_hash_b64u: opts?.bundleHash ?? hashBundle(bundle),
    agent_did: bundle.agent_did,
    policy_hash_b64u: policyEvidenceRef,
    controls,
    gaps,
  };
}

// ---------------------------------------------------------------------------
// Framework dispatcher
// ---------------------------------------------------------------------------

export function generateComplianceReport(
  framework: ComplianceFramework,
  bundle: ComplianceBundleInput,
  policy?: CompliancePolicyInput,
  opts?: { bundleHash?: string; generatedAt?: string },
): ComplianceReport {
  switch (framework) {
    case 'SOC2_Type2':
      return mapToSOC2(bundle, policy, opts);
    case 'ISO27001':
      return mapToISO27001(bundle, policy, opts);
    case 'EU_AI_Act':
      return mapToEUAIAct(bundle, policy, opts);
    case 'CLAW_AI_EXECUTION_ASSURANCE_V1':
      return mapToAIExecutionAssurancePackV1(bundle, policy, opts);
    case 'NIST_AI_RMF':
      return {
        report_version: '1',
        framework: 'NIST_AI_RMF',
        generated_at: reportGeneratedAt(opts?.generatedAt),
        proof_bundle_hash_b64u: opts?.bundleHash ?? hashBundle(bundle),
        agent_did: bundle.agent_did,
        policy_hash_b64u: policy?.policy_hash_b64u,
        controls: [],
        gaps: [
          {
            control_id: 'GOVERN',
            description: 'NIST AI RMF compliance mapping is not yet implemented.',
            recommendation:
              'Use SOC2 framework for current compliance reporting. NIST AI RMF support is planned.',
          },
        ],
      };
    default: {
      const _exhaustive: never = framework;
      throw new Error(`Unknown compliance framework: ${_exhaustive}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Authoritative Wave-1 compiler (fail-closed state machine)
// ---------------------------------------------------------------------------

type ParseCompilerResult =
  | { ok: true; value: AuthoritativeCompilerInput }
  | ParseFailure;

function parseCompilerInput(rawInput: unknown): ParseCompilerResult {
  if (!isRecord(rawInput)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED',
      reason: 'Authoritative compiler input must be a JSON object.',
    };
  }

  if (rawInput.compiler_input_version !== '1') {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_UNSUPPORTED_VERSION',
      reason: 'compiler_input_version must be "1".',
    };
  }

  if (!isFramework(rawInput.framework)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_UNKNOWN_FRAMEWORK',
      reason: 'framework is missing or unsupported.',
    };
  }

  if (typeof rawInput.bundle_hash_b64u !== 'string' || rawInput.bundle_hash_b64u.trim().length === 0) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MISSING_BUNDLE_HASH',
      reason: 'bundle_hash_b64u is required for authoritative compilation.',
    };
  }

  if (!isBase64UrlString(rawInput.bundle_hash_b64u, 8)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_BUNDLE_HASH',
      reason: 'bundle_hash_b64u must be base64url (min length 8).',
    };
  }

  if (!isRecord(rawInput.bundle)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MISSING_BUNDLE',
      reason: 'bundle is required for authoritative compilation.',
    };
  }

  const parsedBundle = parseBundleInput(rawInput.bundle);
  if (!parsedBundle.ok) {
    return parsedBundle;
  }

  if (rawInput.policy !== undefined && !isRecord(rawInput.policy)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_POLICY',
      reason: 'policy, when present, must be a JSON object.',
    };
  }

  const parsedPolicy =
    rawInput.policy !== undefined ? parsePolicyInput(rawInput.policy) : undefined;
  if (parsedPolicy && !parsedPolicy.ok) {
    return parsedPolicy;
  }
  const normalizedPolicy = parsedPolicy?.ok ? parsedPolicy.value : undefined;

  if (!isRecord(rawInput.verification_fact)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MISSING_VERIFICATION_FACT',
      reason:
        'verification_fact is required. Authoritative compilation only accepts verifier-backed evidence.',
    };
  }

  const vf = rawInput.verification_fact;

  if (vf.fact_version !== '1') {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_UNSUPPORTED_VERIFICATION_FACT_VERSION',
      reason: 'verification_fact.fact_version must be "1".',
    };
  }

  if (vf.status !== 'VALID' && vf.status !== 'INVALID') {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_VERIFICATION_STATUS',
      reason: 'verification_fact.status must be VALID or INVALID.',
    };
  }

  if (typeof vf.reason_code !== 'string' || vf.reason_code.trim().length === 0) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MISSING_VERIFICATION_REASON_CODE',
      reason: 'verification_fact.reason_code must be a non-empty string.',
    };
  }

  if (typeof vf.reason !== 'string' || vf.reason.trim().length === 0) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MISSING_VERIFICATION_REASON',
      reason: 'verification_fact.reason must be a non-empty string.',
    };
  }

  if (typeof vf.verified_at !== 'string' || vf.verified_at.trim().length === 0) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MISSING_VERIFICATION_TIMESTAMP',
      reason: 'verification_fact.verified_at must be a non-empty string.',
    };
  }

  if (!STRICT_ISO_UTC_RE.test(vf.verified_at)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_VERIFICATION_TIMESTAMP',
      reason:
        'verification_fact.verified_at must be a strict UTC ISO-8601 timestamp.',
    };
  }

  const bundleAgentDid = parsedBundle.value.agent_did;
  const vfAgentDid = asString(vf.agent_did);

  if (vfAgentDid !== undefined && vfAgentDid !== bundleAgentDid) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_VERIFICATION_AGENT_DID_MISMATCH',
      reason: 'verification_fact.agent_did must match bundle.agent_did when provided.',
    };
  }

  if (rawInput.waivers !== undefined && !Array.isArray(rawInput.waivers)) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_WAIVERS',
      reason: 'waivers, when present, must be an array.',
    };
  }

  const parsedWaivers =
    rawInput.waivers !== undefined
      ? parseSignedControlWaiversInput(rawInput.waivers)
      : undefined;

  if (parsedWaivers && !parsedWaivers.ok) {
    return parsedWaivers;
  }

  if (
    rawInput.compiled_report_refs !== undefined &&
    !isRecord(rawInput.compiled_report_refs)
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_COMPILED_REPORT_REFS',
      reason: 'compiled_report_refs, when present, must be a JSON object.',
    };
  }

  const parsedCompiledReportRefs =
    rawInput.compiled_report_refs !== undefined
      ? parseCompiledReportRefsInput(rawInput.compiled_report_refs)
      : undefined;

  if (parsedCompiledReportRefs && !parsedCompiledReportRefs.ok) {
    return parsedCompiledReportRefs;
  }

  if (
    rawInput.compiled_report_signer !== undefined &&
    !isRecord(rawInput.compiled_report_signer)
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_COMPILED_REPORT_SIGNER',
      reason: 'compiled_report_signer, when present, must be a JSON object.',
    };
  }

  const parsedCompiledReportSigner =
    rawInput.compiled_report_signer !== undefined
      ? parseCompiledReportSignerInput(rawInput.compiled_report_signer)
      : undefined;

  if (parsedCompiledReportSigner && !parsedCompiledReportSigner.ok) {
    return parsedCompiledReportSigner;
  }

  if (
    rawInput.narrative_runtime !== undefined &&
    !isRecord(rawInput.narrative_runtime)
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_NARRATIVE_RUNTIME',
      reason: 'narrative_runtime, when present, must be a JSON object.',
    };
  }

  const parsedNarrativeRuntime =
    rawInput.narrative_runtime !== undefined
      ? parseNarrativeRuntimeInput(rawInput.narrative_runtime)
      : undefined;

  if (parsedNarrativeRuntime && !parsedNarrativeRuntime.ok) {
    return parsedNarrativeRuntime;
  }

  return {
    ok: true,
    value: {
      compiler_input_version: '1',
      framework: rawInput.framework,
      bundle_hash_b64u: rawInput.bundle_hash_b64u,
      bundle: parsedBundle.value,
      policy: normalizedPolicy,
      verification_fact: {
        fact_version: '1',
        status: vf.status,
        reason_code: vf.reason_code,
        reason: vf.reason,
        verified_at: vf.verified_at,
        verifier: asString(vf.verifier),
        proof_tier: asString(vf.proof_tier),
        agent_did: vfAgentDid,
      },
      waivers: parsedWaivers?.ok ? parsedWaivers.value : undefined,
      compiled_report_refs: parsedCompiledReportRefs?.ok
        ? parsedCompiledReportRefs.value
        : undefined,
      compiled_report_signer: parsedCompiledReportSigner?.ok
        ? parsedCompiledReportSigner.value
        : undefined,
      narrative_runtime: parsedNarrativeRuntime?.ok
        ? parsedNarrativeRuntime.value
        : undefined,
    },
  };
}

function firstBlockingControl(
  report: ComplianceReport,
): ControlResult | undefined {
  return report.controls.find((control) => control.status !== 'PASS');
}

/**
 * Authoritative Wave-1 compiler entrypoint.
 *
 * Fail-closed behavior:
 * - malformed input => INPUT_REJECTED
 * - upstream INVALID verification => HALTED_UPSTREAM_INVALID
 * - missing/failed control evidence => COMPILED_FAIL
 */
export function compileAuthoritativeComplianceWave1(
  rawInput: unknown,
): AuthoritativeCompilerResult {
  const parsed = parseCompilerInput(rawInput);

  if (!parsed.ok) {
    return {
      runtime: {
        runtime_version: '1',
        engine: 'clawcompiler-runtime-v1-wave1',
        deterministic: true,
        state: 'INPUT_REJECTED',
        generated_at: DETERMINISTIC_EPOCH_ISO,
        global_status: 'FAIL',
        global_reason_code: parsed.reason_code,
      },
      failure: {
        reason_code: parsed.reason_code,
        reason: parsed.reason,
      },
    };
  }

  const input = parsed.value;
  const generatedAt = resolveGeneratedAt(input.verification_fact.verified_at);

  if (input.verification_fact.status !== 'VALID') {
    const mappedUpstreamReasonCode = normalizeReasonCode(
      input.verification_fact.reason_code,
      'UPSTREAM_VERIFICATION_FAILED',
    );

    return {
      runtime: {
        runtime_version: '1',
        engine: 'clawcompiler-runtime-v1-wave1',
        deterministic: true,
        state: 'HALTED_UPSTREAM_INVALID',
        framework: input.framework,
        bundle_hash_b64u: input.bundle_hash_b64u,
        generated_at: generatedAt,
        global_status: 'FAIL',
        global_reason_code: mappedUpstreamReasonCode,
      },
      failure: {
        reason_code: mappedUpstreamReasonCode,
        reason:
          'Authoritative compilation halted because upstream verification status is INVALID.',
        upstream_reason_code: input.verification_fact.reason_code,
      },
    };
  }

  const report = generateComplianceReport(input.framework, input.bundle, input.policy, {
    bundleHash: input.bundle_hash_b64u,
    generatedAt,
  });

  const blocking = firstBlockingControl(report);

  if (!blocking) {
    return {
      runtime: {
        runtime_version: '1',
        engine: 'clawcompiler-runtime-v1-wave1',
        deterministic: true,
        state: 'COMPILED_PASS',
        framework: input.framework,
        bundle_hash_b64u: input.bundle_hash_b64u,
        generated_at: generatedAt,
        global_status: 'PASS',
        global_reason_code: 'OK',
      },
      report,
    };
  }

  const blockingReasonCode = normalizeReasonCode(
    blocking.reason_code,
    blocking.status === 'FAIL' ? 'CONTROL_FAILURE' : 'INSUFFICIENT_EVIDENCE',
  );

  return {
    runtime: {
      runtime_version: '1',
      engine: 'clawcompiler-runtime-v1-wave1',
      deterministic: true,
      state: 'COMPILED_FAIL',
      framework: input.framework,
      bundle_hash_b64u: input.bundle_hash_b64u,
      generated_at: generatedAt,
      global_status: 'FAIL',
      global_reason_code: blockingReasonCode,
    },
    report,
    failure: {
      reason_code: blockingReasonCode,
      reason:
        blocking.narrative ??
        `Control ${blocking.control_id} did not pass authoritative compilation.`,
    },
  };
}

function compiledReasonFallback(status: CompiledEvidenceControlStatus): string {
  switch (status) {
    case 'PASS':
      return 'CONTROL_PREDICATE_SATISFIED';
    case 'FAIL':
      return 'CONTROL_PREDICATE_FAILED';
    case 'PARTIAL':
      return 'CONTROL_PARTIAL';
    case 'INAPPLICABLE':
      return 'CONTROL_INAPPLICABLE';
    case 'FAIL_CLOSED_INVALID_EVIDENCE':
      return 'CONTROL_FAIL_CLOSED_INVALID_EVIDENCE';
    default: {
      const _never: never = status;
      return _never;
    }
  }
}

function toCompiledControlStatus(status: ControlStatus): CompiledEvidenceControlStatus {
  switch (status) {
    case 'PASS':
      return 'PASS';
    case 'FAIL':
      return 'FAIL';
    case 'NOT_APPLICABLE':
      return 'INAPPLICABLE';
    case 'INSUFFICIENT_EVIDENCE':
      return 'FAIL_CLOSED_INVALID_EVIDENCE';
    default: {
      const _never: never = status;
      return _never;
    }
  }
}

function summarizeCompiledOverallStatus(
  controls: CompiledEvidenceControlResult[],
): CompiledEvidenceOverallStatus {
  if (controls.some((control) => control.status === 'FAIL_CLOSED_INVALID_EVIDENCE')) {
    return 'FAIL_CLOSED_INVALID_EVIDENCE';
  }

  if (controls.some((control) => control.status === 'FAIL')) {
    return 'FAIL';
  }

  if (controls.some((control) => control.status === 'PARTIAL')) {
    return 'PARTIAL';
  }

  return 'PASS';
}

function countWaiverResidualReasonCodes(reasonCodes: string[]): number {
  return reasonCodes.filter((reasonCode) =>
    WAIVER_RESIDUAL_REASON_CODES.has(reasonCode),
  ).length;
}

function hasWaiverReasonMarkers(reasonCodes: string[]): boolean {
  return (
    reasonCodes.includes(WAIVER_APPLIED_REASON_CODE) ||
    countWaiverResidualReasonCodes(reasonCodes) > 0
  );
}

function normalizeCompiledMatrixControlResults(
  controlResults: CompiledEvidenceControlResult[],
): CompiledEvidenceControlResult[] {
  return [...controlResults]
    .map((control) => ({
      control_id: control.control_id,
      status: control.status,
      reason_codes: [...control.reason_codes],
      evidence_hashes_b64u: [...control.evidence_hashes_b64u],
      waiver_applied: control.waiver_applied,
    }))
    .sort((a, b) => a.control_id.localeCompare(b.control_id));
}

async function computeCompiledMatrixHashB64u(
  controlResults: CompiledEvidenceControlResult[],
): Promise<string> {
  const matrixView = {
    matrix_version: '1',
    control_results: normalizeCompiledMatrixControlResults(controlResults),
  };

  return sha256B64uFromCanonical(matrixView);
}

function resolveCompilerVersion(input: AuthoritativeCompilerInput): string {
  if (
    input.framework === 'CLAW_AI_EXECUTION_ASSURANCE_V1' ||
    (input.waivers?.length ?? 0) > 0
  ) {
    return COMPILER_VERSION_WAVE3;
  }

  return COMPILER_VERSION_WAVE2;
}

async function resolveCompiledEvidenceRefs(
  input: AuthoritativeCompilerInput,
  complianceReport: ComplianceReport,
  compilerVersion: string,
): Promise<CompiledEvidenceReportEvidenceRefs> {
  const provided = input.compiled_report_refs;

  const ontologyHash =
    provided?.ontology_hash_b64u ??
    (await sha256B64uFromCanonical({
      ontology_version: '1',
      framework: input.framework,
      compiler_version: compilerVersion,
      assurance_pack_id:
        input.framework === 'CLAW_AI_EXECUTION_ASSURANCE_V1'
          ? AI_EXECUTION_ASSURANCE_PACK_ID
          : null,
    }));

  const mappingRulesHash =
    provided?.mapping_rules_hash_b64u ??
    (await sha256B64uFromCanonical({
      mapping_version: COMPILER_MAPPING_VERSION,
      framework: input.framework,
      controls: [...complianceReport.controls.map((control) => control.control_id)].sort(),
    }));

  const verifyResultHash =
    provided?.verify_result_hash_b64u ??
    (await sha256B64uFromCanonical({
      verification_fact_version: input.verification_fact.fact_version,
      status: input.verification_fact.status,
      reason_code: input.verification_fact.reason_code,
      reason: input.verification_fact.reason,
      verified_at: input.verification_fact.verified_at,
      verifier: input.verification_fact.verifier ?? null,
      proof_tier: input.verification_fact.proof_tier ?? null,
      agent_did: input.verification_fact.agent_did ?? null,
    }));

  return {
    proof_bundle_hash_b64u:
      provided?.proof_bundle_hash_b64u ?? input.bundle_hash_b64u,
    ontology_hash_b64u: ontologyHash,
    mapping_rules_hash_b64u: mappingRulesHash,
    verify_result_hash_b64u: verifyResultHash,
  };
}

async function compileDeterministicControlResults(
  report: ComplianceReport,
): Promise<CompiledEvidenceControlResult[]> {
  const controls = await Promise.all(
    report.controls.map(async (control) => {
      const compiledStatus = toCompiledControlStatus(control.status);
      const reasonCode = normalizeReasonCode(
        control.reason_code,
        compiledReasonFallback(compiledStatus),
      );

      const evidenceHash = await sha256B64uFromCanonical({
        control_id: control.control_id,
        evidence_type: control.evidence_type ?? null,
        evidence_ref: control.evidence_ref ?? null,
        proof_bundle_hash_b64u: report.proof_bundle_hash_b64u,
      });

      return {
        control_id: control.control_id,
        status: compiledStatus,
        reason_codes: [reasonCode],
        evidence_hashes_b64u: [evidenceHash],
        waiver_applied: false,
      } satisfies CompiledEvidenceControlResult;
    }),
  );

  return controls.sort((a, b) => a.control_id.localeCompare(b.control_id));
}

function waiverResidualReasonCodes(waiverKind: WaiverKind): string[] {
  if (waiverKind === 'COMPENSATING_CONTROL') {
    return [
      WAIVER_APPLIED_REASON_CODE,
      'RESIDUAL_COMPENSATING_CONTROL_RELIANCE',
    ];
  }

  return [WAIVER_APPLIED_REASON_CODE, 'RESIDUAL_HUMAN_EXCEPTION_APPLIED'];
}

async function computeSignedWaiverPayloadHash(
  waiver: SignedControlWaiverInput,
): Promise<string> {
  return sha256B64uFromCanonical({
    waiver_version: waiver.waiver_version,
    waiver_id: waiver.waiver_id,
    framework: waiver.framework,
    control_id: waiver.control_id,
    bundle_hash_b64u: waiver.bundle_hash_b64u,
    agent_did: waiver.agent_did,
    waiver_kind: waiver.waiver_kind,
    issued_at: waiver.issued_at,
    expires_at: waiver.expires_at,
  });
}

async function applySignedControlWaivers(
  input: AuthoritativeCompilerInput,
  controlResults: CompiledEvidenceControlResult[],
  compiledAt: string,
): Promise<
  | { ok: true; value: CompiledEvidenceControlResult[] }
  | { ok: false; reason_code: string; reason: string }
> {
  const waivers = input.waivers ?? [];
  if (waivers.length === 0) {
    return { ok: true, value: controlResults };
  }

  const evaluatedAtMs = Date.parse(compiledAt);
  if (!Number.isFinite(evaluatedAtMs)) {
    return {
      ok: false,
      reason_code: 'WAIVER_EVALUATION_TIMESTAMP_INVALID',
      reason: 'Compiled-at timestamp is not a valid ISO instant for waiver evaluation.',
    };
  }

  const controlsById = new Map<string, CompiledEvidenceControlResult>();
  for (const control of controlResults) {
    controlsById.set(control.control_id, {
      ...control,
      reason_codes: [...control.reason_codes],
      evidence_hashes_b64u: [...control.evidence_hashes_b64u],
    });
  }

  const seenControlTargets = new Set<string>();

  for (const waiver of waivers) {
    if (waiver.framework !== input.framework) {
      return {
        ok: false,
        reason_code: 'WAIVER_FRAMEWORK_MISMATCH',
        reason: `Waiver ${waiver.waiver_id} framework does not match compiler framework.`,
      };
    }

    if (waiver.bundle_hash_b64u !== input.bundle_hash_b64u) {
      return {
        ok: false,
        reason_code: 'WAIVER_BUNDLE_HASH_MISMATCH',
        reason: `Waiver ${waiver.waiver_id} bundle hash does not match compiler input bundle hash.`,
      };
    }

    if (waiver.agent_did !== input.bundle.agent_did) {
      return {
        ok: false,
        reason_code: 'WAIVER_AGENT_DID_MISMATCH',
        reason: `Waiver ${waiver.waiver_id} agent DID does not match bundle.agent_did.`,
      };
    }

    const issuedAtMs = Date.parse(waiver.issued_at);
    const expiresAtMs = Date.parse(waiver.expires_at);

    if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)) {
      return {
        ok: false,
        reason_code: 'WAIVER_TIMESTAMP_INVALID',
        reason: `Waiver ${waiver.waiver_id} includes invalid issued_at/expires_at timestamps.`,
      };
    }

    if (expiresAtMs <= issuedAtMs) {
      return {
        ok: false,
        reason_code: 'WAIVER_EXPIRY_INVALID',
        reason: `Waiver ${waiver.waiver_id} expires_at must be later than issued_at.`,
      };
    }

    if (evaluatedAtMs < issuedAtMs) {
      return {
        ok: false,
        reason_code: 'WAIVER_NOT_YET_ACTIVE',
        reason: `Waiver ${waiver.waiver_id} is not active at compile evaluation time.`,
      };
    }

    if (evaluatedAtMs > expiresAtMs) {
      return {
        ok: false,
        reason_code: 'WAIVER_EXPIRED',
        reason: `Waiver ${waiver.waiver_id} is expired at compile evaluation time.`,
      };
    }

    const expectedWaiverPayloadHash = await computeSignedWaiverPayloadHash(waiver);
    if (expectedWaiverPayloadHash !== waiver.payload_hash_b64u) {
      return {
        ok: false,
        reason_code: 'WAIVER_PAYLOAD_HASH_MISMATCH',
        reason: `Waiver ${waiver.waiver_id} payload hash does not match canonical waiver fields.`,
      };
    }

    const waiverSignerPublicKey = extractPublicKeyFromDidKey(waiver.signer_did);
    if (!waiverSignerPublicKey) {
      return {
        ok: false,
        reason_code: 'WAIVER_SIGNER_DID_INVALID',
        reason: `Waiver ${waiver.waiver_id} signer_did is not a valid Ed25519 did:key DID.`,
      };
    }

    let waiverSignatureBytes: Uint8Array;
    try {
      waiverSignatureBytes = base64UrlDecode(waiver.signature_b64u);
    } catch {
      return {
        ok: false,
        reason_code: 'WAIVER_SIGNATURE_MALFORMED',
        reason: `Waiver ${waiver.waiver_id} signature_b64u is not valid base64url.`,
      };
    }

    const waiverSignatureValid = await verifySignature(
      'Ed25519',
      waiverSignerPublicKey,
      waiverSignatureBytes,
      new TextEncoder().encode(waiver.payload_hash_b64u),
    );

    if (!waiverSignatureValid) {
      return {
        ok: false,
        reason_code: 'WAIVER_SIGNATURE_INVALID',
        reason: `Waiver ${waiver.waiver_id} signature does not verify payload_hash_b64u.`,
      };
    }

    if (seenControlTargets.has(waiver.control_id)) {
      return {
        ok: false,
        reason_code: 'WAIVER_CONTROL_SCOPE_DUPLICATE',
        reason: `Multiple waivers target control ${waiver.control_id}; deterministic one-waiver-per-control semantics enforced.`,
      };
    }

    const targetControl = controlsById.get(waiver.control_id);
    if (!targetControl) {
      return {
        ok: false,
        reason_code: 'WAIVER_CONTROL_SCOPE_INVALID',
        reason: `Waiver ${waiver.waiver_id} targets unknown control_id ${waiver.control_id}.`,
      };
    }

    if (targetControl.status !== 'FAIL') {
      return {
        ok: false,
        reason_code: 'WAIVER_TARGET_NOT_FAIL',
        reason: `Waiver ${waiver.waiver_id} can only apply to FAIL controls; ${waiver.control_id} is ${targetControl.status}.`,
      };
    }

    seenControlTargets.add(waiver.control_id);

    const mergedReasonCodes = [
      ...targetControl.reason_codes,
      ...waiverResidualReasonCodes(waiver.waiver_kind),
    ]
      .map((reasonCode) => normalizeReasonCode(reasonCode, 'WAIVER_REASON_INVALID'))
      .filter((reasonCode, idx, arr) => arr.indexOf(reasonCode) === idx)
      .sort();

    const mergedEvidenceHashes = [
      ...targetControl.evidence_hashes_b64u,
      waiver.payload_hash_b64u,
    ].filter((hash, idx, arr) => arr.indexOf(hash) === idx);
    mergedEvidenceHashes.sort();

    targetControl.status = 'PARTIAL';
    targetControl.waiver_applied = true;
    targetControl.reason_codes = mergedReasonCodes;
    targetControl.evidence_hashes_b64u = mergedEvidenceHashes;
  }

  return {
    ok: true,
    value: [...controlsById.values()].sort((a, b) =>
      a.control_id.localeCompare(b.control_id),
    ),
  };
}

type AuthoritativeCompiledEvidenceReportView = Omit<
  CompiledEvidenceReport,
  'narrative'
>;

function authoritativeCompiledReportView(
  report: CompiledEvidenceReport,
): AuthoritativeCompiledEvidenceReportView {
  const { narrative: _ignoredNarrative, ...authoritative } = report;
  return authoritative;
}

async function computeAuthoritativeReportHashB64u(
  report: CompiledEvidenceReport,
): Promise<string> {
  return sha256B64uFromCanonical(authoritativeCompiledReportView(report));
}

function buildDeterministicNarrativeText(report: CompiledEvidenceReport): string {
  const statuses: CompiledEvidenceControlStatus[] = [
    'PASS',
    'FAIL',
    'PARTIAL',
    'INAPPLICABLE',
    'FAIL_CLOSED_INVALID_EVIDENCE',
  ];

  const statusSummary = statuses
    .map((status) => {
      const count = report.control_results.filter(
        (control) => control.status === status,
      ).length;
      return `${status}=${count}`;
    })
    .join(', ');

  const nonPassControls = report.control_results
    .filter((control) => control.status !== 'PASS')
    .map((control) => `${control.control_id}:${control.status}`)
    .sort();

  const nonPassSummary =
    nonPassControls.length > 0 ? nonPassControls.join(', ') : 'none';

  return [
    `Authoritative compiled matrix ${report.report_id} evaluated with overall status ${report.overall_status}.`,
    `Control status counts: ${statusSummary}.`,
    `Non-pass controls: ${nonPassSummary}.`,
  ].join(' ');
}

async function attachNarrativePlaneIfEnabled(
  input: AuthoritativeCompilerInput,
  compiledReport: CompiledEvidenceReport,
): Promise<CompiledEvidenceReport> {
  const policyDisablesNarrative =
    input.policy?.disable_narrative_generation === true;
  const runtimeRequestsNarrative = input.narrative_runtime?.enabled === true;

  if (!runtimeRequestsNarrative || policyDisablesNarrative) {
    return compiledReport;
  }

  const authoritativeReportHashB64u =
    await computeAuthoritativeReportHashB64u(compiledReport);

  const narrative: CompiledEvidenceNarrative = {
    narrative_version: '1',
    report_id: compiledReport.report_id,
    generated_at: compiledReport.compiled_at,
    authoritative: false,
    disclaimer: COMPILED_EVIDENCE_NARRATIVE_DISCLAIMER,
    authoritative_matrix_hash_b64u: compiledReport.matrix_hash_b64u,
    authoritative_report_hash_b64u: authoritativeReportHashB64u,
    text: buildDeterministicNarrativeText(compiledReport),
  };

  if (input.narrative_runtime?.generator_provider) {
    narrative.generator_provider = input.narrative_runtime.generator_provider;
  }

  if (input.narrative_runtime?.generator_model) {
    narrative.generator_model = input.narrative_runtime.generator_model;
  }

  return {
    ...compiledReport,
    narrative,
  };
}

function deterministicCompiledReportId(input: AuthoritativeCompilerInput): string {
  const frameworkPart = input.framework.replace(/[^A-Za-z0-9._:-]/g, '_');
  const bundlePart = input.bundle_hash_b64u.slice(0, 24);
  return `cer_${frameworkPart}_${bundlePart}`;
}

export async function buildCompiledEvidenceReport(
  input: AuthoritativeCompilerInput,
  complianceReport: ComplianceReport,
): Promise<CompiledEvidenceReport> {
  const compilerVersion = resolveCompilerVersion(input);
  const compiledAt = resolveGeneratedAt(complianceReport.generated_at);

  const baseControlResults = await compileDeterministicControlResults(complianceReport);
  const waiverApplied = await applySignedControlWaivers(
    input,
    baseControlResults,
    compiledAt,
  );

  if (!waiverApplied.ok) {
    throw new Error(`${waiverApplied.reason_code}: ${waiverApplied.reason}`);
  }

  const controlResults = waiverApplied.value;
  const matrixHash = await computeCompiledMatrixHashB64u(controlResults);
  const evidenceRefs = await resolveCompiledEvidenceRefs(
    input,
    complianceReport,
    compilerVersion,
  );

  const reportId = deterministicCompiledReportId(input);
  if (!COMPILED_REPORT_ID_RE.test(reportId)) {
    throw new Error('Deterministic compiled report ID generation failed schema constraints.');
  }

  const authoritativeReport: CompiledEvidenceReport = {
    report_version: '1',
    report_id: reportId,
    compiled_at: compiledAt,
    compiler_version: compilerVersion,
    evidence_refs: evidenceRefs,
    overall_status: summarizeCompiledOverallStatus(controlResults),
    matrix_hash_b64u: matrixHash,
    control_results: controlResults,
  };

  return attachNarrativePlaneIfEnabled(input, authoritativeReport);
}

async function signCompiledReportEnvelope(
  compiledReport: CompiledEvidenceReport,
  signer: AuthoritativeCompiledReportSignerInput,
  fallbackIssuedAt: string,
): Promise<
  { ok: true; envelope: CompiledEvidenceReportEnvelope }
  | { ok: false; reason_code: string; reason: string }
> {
  if (!isNonEmptyString(signer.signer_did) || !signer.signer_did.startsWith('did:key:')) {
    return {
      ok: false,
      reason_code: 'COMPILER_SIGNER_DID_INVALID',
      reason: 'compiled_report_signer.signer_did must be a did:key DID.',
    };
  }

  const signerPublicKey = extractPublicKeyFromDidKey(signer.signer_did);
  if (!signerPublicKey) {
    return {
      ok: false,
      reason_code: 'COMPILER_SIGNER_DID_INVALID',
      reason:
        'compiled_report_signer.signer_did must be did:key with an Ed25519 multicodec key.',
    };
  }

  let pkcs8Bytes: Uint8Array;
  try {
    pkcs8Bytes = base64UrlDecode(signer.private_key_pkcs8_b64u);
  } catch {
    return {
      ok: false,
      reason_code: 'COMPILER_SIGNER_KEY_INVALID',
      reason: 'compiled_report_signer.private_key_pkcs8_b64u must be valid base64url.',
    };
  }

  let privateKey: CryptoKey;
  try {
    privateKey = await crypto.subtle.importKey(
      'pkcs8',
      toArrayBuffer(pkcs8Bytes),
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
  } catch {
    return {
      ok: false,
      reason_code: 'COMPILER_SIGNER_KEY_IMPORT_FAILED',
      reason: 'Could not import compiled report signer private key.',
    };
  }

  const payloadHash = await sha256B64uFromCanonical(compiledReport);
  const payloadHashBytes = new TextEncoder().encode(payloadHash);

  let signatureBytes: Uint8Array;
  try {
    const signed = await crypto.subtle.sign(
      'Ed25519',
      privateKey,
      toArrayBuffer(payloadHashBytes),
    );
    signatureBytes = new Uint8Array(signed);
  } catch {
    return {
      ok: false,
      reason_code: 'COMPILER_SIGNER_SIGNATURE_FAILED',
      reason: 'Failed to sign compiled report payload hash.',
    };
  }

  const signerMatchesDid = await verifySignature(
    'Ed25519',
    signerPublicKey,
    signatureBytes,
    payloadHashBytes,
  );

  if (!signerMatchesDid) {
    return {
      ok: false,
      reason_code: 'COMPILER_SIGNER_DID_MISMATCH',
      reason:
        'compiled_report_signer.private_key_pkcs8_b64u does not match compiled_report_signer.signer_did.',
    };
  }

  return {
    ok: true,
    envelope: {
      envelope_version: '1',
      envelope_type: 'compiled_evidence_report',
      payload: compiledReport,
      payload_hash_b64u: payloadHash,
      hash_algorithm: 'SHA-256',
      signature_b64u: base64UrlEncode(signatureBytes),
      algorithm: 'Ed25519',
      signer_did: signer.signer_did,
      issued_at: resolveGeneratedAt(signer.issued_at ?? fallbackIssuedAt),
    },
  };
}

export async function compileAuthoritativeComplianceWave2(
  rawInput: unknown,
): Promise<AuthoritativeCompilerResult> {
  const wave1 = compileAuthoritativeComplianceWave1(rawInput);

  if (!wave1.report) {
    return wave1;
  }

  const parsed = parseCompilerInput(rawInput);
  if (!parsed.ok) {
    return {
      runtime: {
        ...wave1.runtime,
        engine: 'clawcompiler-runtime-v1-wave2',
        state: 'INPUT_REJECTED',
        global_status: 'FAIL',
        global_reason_code: parsed.reason_code,
      },
      failure: {
        reason_code: parsed.reason_code,
        reason: parsed.reason,
      },
    };
  }

  const input = parsed.value;

  let compiledReport: CompiledEvidenceReport;
  try {
    compiledReport = await buildCompiledEvidenceReport(input, wave1.report);
  } catch (err) {
    const reason =
      err instanceof Error
        ? err.message
        : 'Failed to deterministically compile authoritative evidence report.';

    const maybePrefixedReasonCode =
      err instanceof Error ? err.message.match(/^([A-Z0-9_]{3,}):\s+/)?.[1] : undefined;

    const reasonCode = maybePrefixedReasonCode ?? 'COMPILER_COMPILED_REPORT_FAILED';

    return {
      runtime: {
        ...wave1.runtime,
        engine: 'clawcompiler-runtime-v1-wave2',
        state: 'COMPILED_FAIL',
        global_status: 'FAIL',
        global_reason_code: reasonCode,
      },
      report: wave1.report,
      failure: {
        reason_code: reasonCode,
        reason,
      },
    };
  }

  const runtime: AuthoritativeCompilerRuntime = {
    ...wave1.runtime,
    engine:
      compiledReport.compiler_version === COMPILER_VERSION_WAVE3
        ? 'clawcompiler-runtime-v1-wave3'
        : 'clawcompiler-runtime-v1-wave2',
  };

  if (!input.compiled_report_signer) {
    return {
      ...wave1,
      runtime,
      compiled_report: compiledReport,
    };
  }

  const signed = await signCompiledReportEnvelope(
    compiledReport,
    input.compiled_report_signer,
    runtime.generated_at,
  );

  if (!signed.ok) {
    return {
      runtime: {
        ...runtime,
        state: 'COMPILED_FAIL',
        global_status: 'FAIL',
        global_reason_code: signed.reason_code,
      },
      report: wave1.report,
      compiled_report: compiledReport,
      failure: {
        reason_code: signed.reason_code,
        reason: signed.reason,
      },
    };
  }

  return {
    ...wave1,
    runtime,
    compiled_report: compiledReport,
    compiled_report_envelope: signed.envelope,
  };
}

function validateCompiledReportPayloadShape(
  rawPayload: unknown,
):
  | {
      ok: true;
      value: CompiledEvidenceReport;
    }
  | {
      ok: false;
      code: VerifyCompiledEvidenceReportEnvelopeError['code'];
      message: string;
      field?: string;
    } {
  if (!isRecord(rawPayload)) {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload must be a JSON object.',
      field: 'payload',
    };
  }

  if (rawPayload.report_version !== '1') {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.report_version must equal "1".',
      field: 'payload.report_version',
    };
  }

  if (!isNonEmptyString(rawPayload.report_id) || !COMPILED_REPORT_ID_RE.test(rawPayload.report_id)) {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.report_id must match /^cer_[A-Za-z0-9._:-]+$/.',
      field: 'payload.report_id',
    };
  }

  if (!isNonEmptyString(rawPayload.compiled_at) || !STRICT_ISO_UTC_RE.test(rawPayload.compiled_at)) {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.compiled_at must be a strict UTC ISO-8601 timestamp.',
      field: 'payload.compiled_at',
    };
  }

  if (
    rawPayload.compiler_version !== COMPILER_VERSION_WAVE2 &&
    rawPayload.compiler_version !== COMPILER_VERSION_WAVE3
  ) {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        `payload.compiler_version must equal "${COMPILER_VERSION_WAVE2}" or "${COMPILER_VERSION_WAVE3}".`,
      field: 'payload.compiler_version',
    };
  }

  const isWave3CompiledPayload =
    rawPayload.compiler_version === COMPILER_VERSION_WAVE3;

  if (!isRecord(rawPayload.evidence_refs)) {
    return {
      ok: false,
      code: 'MISSING_REQUIRED_FIELD',
      message: 'payload.evidence_refs is required.',
      field: 'payload.evidence_refs',
    };
  }

  const evidenceRefFields: Array<keyof CompiledEvidenceReportEvidenceRefs> = [
    'proof_bundle_hash_b64u',
    'ontology_hash_b64u',
    'mapping_rules_hash_b64u',
    'verify_result_hash_b64u',
  ];

  for (const field of evidenceRefFields) {
    const value = rawPayload.evidence_refs[field];
    if (!isNonEmptyString(value)) {
      return {
        ok: false,
        code: 'MISSING_REQUIRED_FIELD',
        message: `payload.evidence_refs.${field} is required.`,
        field: `payload.evidence_refs.${field}`,
      };
    }

    if (!isBase64UrlString(value, 8)) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `payload.evidence_refs.${field} must be base64url (min length 8).`,
        field: `payload.evidence_refs.${field}`,
      };
    }
  }

  if (
    rawPayload.overall_status !== 'PASS' &&
    rawPayload.overall_status !== 'FAIL' &&
    rawPayload.overall_status !== 'FAIL_CLOSED_INVALID_EVIDENCE' &&
    rawPayload.overall_status !== 'PARTIAL'
  ) {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.overall_status must be PASS, FAIL, PARTIAL, or FAIL_CLOSED_INVALID_EVIDENCE.',
      field: 'payload.overall_status',
    };
  }

  if (!isWave3CompiledPayload && rawPayload.overall_status === 'PARTIAL') {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.overall_status=PARTIAL is only allowed for wave3 compiled reports.',
      field: 'payload.overall_status',
    };
  }

  if (!isBase64UrlString(rawPayload.matrix_hash_b64u, 8)) {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.matrix_hash_b64u must be base64url (min length 8).',
      field: 'payload.matrix_hash_b64u',
    };
  }

  if (!Array.isArray(rawPayload.control_results) || rawPayload.control_results.length === 0) {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: 'payload.control_results must be a non-empty array.',
      field: 'payload.control_results',
    };
  }

  for (let i = 0; i < rawPayload.control_results.length; i++) {
    const control = rawPayload.control_results[i];
    const prefix = `payload.control_results[${i}]`;

    if (!isRecord(control)) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix} must be an object.`,
        field: prefix,
      };
    }

    if (!isNonEmptyString(control.control_id)) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.control_id must be a non-empty string.`,
        field: `${prefix}.control_id`,
      };
    }

    if (
      control.status !== 'PASS' &&
      control.status !== 'FAIL' &&
      control.status !== 'PARTIAL' &&
      control.status !== 'INAPPLICABLE' &&
      control.status !== 'FAIL_CLOSED_INVALID_EVIDENCE'
    ) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          `${prefix}.status must be PASS, FAIL, PARTIAL, INAPPLICABLE, or FAIL_CLOSED_INVALID_EVIDENCE.`,
        field: `${prefix}.status`,
      };
    }

    if (!isWave3CompiledPayload && control.status === 'PARTIAL') {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.status=PARTIAL is only allowed for wave3 compiled reports.`,
        field: `${prefix}.status`,
      };
    }

    if (!Array.isArray(control.reason_codes) || control.reason_codes.length === 0) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.reason_codes must be a non-empty array.`,
        field: `${prefix}.reason_codes`,
      };
    }

    const invalidReasonCode = control.reason_codes.some(
      (reason) => !isNonEmptyString(reason) || !/^[A-Z0-9_]{3,}$/.test(reason),
    );
    if (invalidReasonCode) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.reason_codes values must match /^[A-Z0-9_]{3,}$/.`,
        field: `${prefix}.reason_codes`,
      };
    }

    if (
      !Array.isArray(control.evidence_hashes_b64u) ||
      control.evidence_hashes_b64u.length === 0
    ) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.evidence_hashes_b64u must be a non-empty array.`,
        field: `${prefix}.evidence_hashes_b64u`,
      };
    }

    const invalidEvidenceHash = control.evidence_hashes_b64u.some(
      (hash) => !isBase64UrlString(hash, 8),
    );
    if (invalidEvidenceHash) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.evidence_hashes_b64u values must be base64url (min length 8).`,
        field: `${prefix}.evidence_hashes_b64u`,
      };
    }

    if (typeof control.waiver_applied !== 'boolean') {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.waiver_applied must be a boolean.`,
        field: `${prefix}.waiver_applied`,
      };
    }

    if (!isWave3CompiledPayload && control.waiver_applied !== false) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.waiver_applied must be false for wave2 compiled reports.`,
        field: `${prefix}.waiver_applied`,
      };
    }

    if (isWave3CompiledPayload && control.waiver_applied && control.status !== 'PARTIAL') {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.waiver_applied=true requires status=PARTIAL.`,
        field: `${prefix}.status`,
      };
    }

    if (isWave3CompiledPayload && control.status === 'PARTIAL' && control.waiver_applied !== true) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.status=PARTIAL requires waiver_applied=true.`,
        field: `${prefix}.waiver_applied`,
      };
    }

    const residualReasonCount = countWaiverResidualReasonCodes(control.reason_codes);
    const hasWaiverAppliedReason = control.reason_codes.includes(
      WAIVER_APPLIED_REASON_CODE,
    );
    const hasBaseReasonCode = control.reason_codes.some(
      (reasonCode) =>
        reasonCode !== WAIVER_APPLIED_REASON_CODE &&
        !WAIVER_RESIDUAL_REASON_CODES.has(reasonCode),
    );

    if (control.waiver_applied) {
      if (!hasWaiverAppliedReason) {
        return {
          ok: false,
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            `${prefix}.waiver_applied=true requires reason_codes to include ${WAIVER_APPLIED_REASON_CODE}.`,
          field: `${prefix}.reason_codes`,
        };
      }

      if (residualReasonCount !== 1) {
        return {
          ok: false,
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            `${prefix}.waiver_applied=true requires exactly one deterministic residual reason code.`,
          field: `${prefix}.reason_codes`,
        };
      }

      if (!hasBaseReasonCode) {
        return {
          ok: false,
          code: 'SCHEMA_VALIDATION_FAILED',
          message:
            `${prefix}.waiver_applied=true requires the underlying control failure reason code to remain present.`,
          field: `${prefix}.reason_codes`,
        };
      }
    } else if (hasWaiverReasonMarkers(control.reason_codes)) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          `${prefix}.reason_codes may not contain waiver markers when waiver_applied=false.`,
        field: `${prefix}.reason_codes`,
      };
    }
  }

  if (rawPayload.narrative !== undefined) {
    const narrative = rawPayload.narrative;

    if (!isRecord(narrative)) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.narrative must be a JSON object when present.',
        field: 'payload.narrative',
      };
    }

    if (narrative.narrative_version !== '1') {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.narrative.narrative_version must equal "1".',
        field: 'payload.narrative.narrative_version',
      };
    }

    if (!isNonEmptyString(narrative.report_id)) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.narrative.report_id must be a non-empty string.',
        field: 'payload.narrative.report_id',
      };
    }

    if (narrative.report_id !== rawPayload.report_id) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.narrative.report_id must match payload.report_id.',
        field: 'payload.narrative.report_id',
      };
    }

    if (!isNonEmptyString(narrative.generated_at) || !STRICT_ISO_UTC_RE.test(narrative.generated_at)) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          'payload.narrative.generated_at must be a strict UTC ISO-8601 timestamp.',
        field: 'payload.narrative.generated_at',
      };
    }

    if (narrative.authoritative !== false) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.narrative.authoritative must equal false.',
        field: 'payload.narrative.authoritative',
      };
    }

    if (narrative.disclaimer !== COMPILED_EVIDENCE_NARRATIVE_DISCLAIMER) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          'payload.narrative.disclaimer must match the fixed non-authoritative disclaimer contract.',
        field: 'payload.narrative.disclaimer',
      };
    }

    if (!isBase64UrlString(narrative.authoritative_matrix_hash_b64u, 8)) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          'payload.narrative.authoritative_matrix_hash_b64u must be base64url (min length 8).',
        field: 'payload.narrative.authoritative_matrix_hash_b64u',
      };
    }

    if (narrative.authoritative_matrix_hash_b64u !== rawPayload.matrix_hash_b64u) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          'payload.narrative.authoritative_matrix_hash_b64u must match payload.matrix_hash_b64u.',
        field: 'payload.narrative.authoritative_matrix_hash_b64u',
      };
    }

    if (!isBase64UrlString(narrative.authoritative_report_hash_b64u, 8)) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          'payload.narrative.authoritative_report_hash_b64u must be base64url (min length 8).',
        field: 'payload.narrative.authoritative_report_hash_b64u',
      };
    }

    if (
      !isNonEmptyString(narrative.text) ||
      narrative.text.length > 20000
    ) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: 'payload.narrative.text must be 1..20000 characters.',
        field: 'payload.narrative.text',
      };
    }

    if (
      narrative.generator_provider !== undefined &&
      !isNonEmptyString(narrative.generator_provider)
    ) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          'payload.narrative.generator_provider, when present, must be a non-empty string.',
        field: 'payload.narrative.generator_provider',
      };
    }

    if (
      narrative.generator_model !== undefined &&
      !isNonEmptyString(narrative.generator_model)
    ) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          'payload.narrative.generator_model, when present, must be a non-empty string.',
        field: 'payload.narrative.generator_model',
      };
    }
  }

  const computedOverallStatus = summarizeCompiledOverallStatus(
    rawPayload.control_results as unknown as CompiledEvidenceControlResult[],
  );
  if (computedOverallStatus !== rawPayload.overall_status) {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        `payload.overall_status must equal ${computedOverallStatus} for the provided control_results.`,
      field: 'payload.overall_status',
    };
  }

  return {
    ok: true,
    value: rawPayload as unknown as CompiledEvidenceReport,
  };
}

export async function verifyCompiledEvidenceReportEnvelope(
  rawEnvelope: unknown,
): Promise<VerifyCompiledEvidenceReportEnvelopeResponse> {
  const verifiedAt = new Date().toISOString();

  const invalid = (
    code: VerifyCompiledEvidenceReportEnvelopeError['code'],
    reason: string,
    message: string,
    field?: string,
    payload?: { report_id?: string; matrix_hash_b64u?: string; payload_hash_b64u?: string },
  ): VerifyCompiledEvidenceReportEnvelopeResponse => ({
    result: {
      status: 'INVALID',
      reason,
      envelope_type: 'compiled_evidence_report',
      verified_at: verifiedAt,
    },
    report_id: payload?.report_id,
    matrix_hash_b64u: payload?.matrix_hash_b64u,
    payload_hash_b64u: payload?.payload_hash_b64u,
    error: {
      code,
      message,
      field,
    },
  });

  if (!isRecord(rawEnvelope)) {
    return invalid(
      'SCHEMA_VALIDATION_FAILED',
      'Compiled evidence report envelope is malformed.',
      'Envelope must be a JSON object.',
      'envelope',
    );
  }

  if (rawEnvelope.envelope_version !== '1') {
    return invalid(
      'SCHEMA_VALIDATION_FAILED',
      'Compiled evidence report envelope version is unsupported.',
      'envelope_version must equal "1".',
      'envelope_version',
    );
  }

  if (rawEnvelope.envelope_type !== 'compiled_evidence_report') {
    return invalid(
      'SCHEMA_VALIDATION_FAILED',
      'Compiled evidence report envelope type is invalid.',
      'envelope_type must equal "compiled_evidence_report".',
      'envelope_type',
    );
  }

  if (rawEnvelope.hash_algorithm !== 'SHA-256') {
    return invalid(
      rawEnvelope.hash_algorithm === 'BLAKE3'
        ? 'UNKNOWN_HASH_ALGORITHM'
        : 'SCHEMA_VALIDATION_FAILED',
      'Compiled evidence report hash algorithm is unsupported.',
      'hash_algorithm must equal "SHA-256".',
      'hash_algorithm',
    );
  }

  if (rawEnvelope.algorithm !== 'Ed25519') {
    return invalid(
      'UNKNOWN_ALGORITHM',
      'Compiled evidence report signature algorithm is unsupported.',
      'algorithm must equal "Ed25519".',
      'algorithm',
    );
  }

  if (!isBase64UrlString(rawEnvelope.payload_hash_b64u, 8)) {
    return invalid(
      'SCHEMA_VALIDATION_FAILED',
      'Compiled evidence report payload hash format is invalid.',
      'payload_hash_b64u must be base64url (min length 8).',
      'payload_hash_b64u',
    );
  }

  if (!isBase64UrlString(rawEnvelope.signature_b64u, 8)) {
    return invalid(
      'SCHEMA_VALIDATION_FAILED',
      'Compiled evidence report signature format is invalid.',
      'signature_b64u must be base64url (min length 8).',
      'signature_b64u',
    );
  }

  if (!isNonEmptyString(rawEnvelope.signer_did)) {
    return invalid(
      'SCHEMA_VALIDATION_FAILED',
      'Compiled evidence report signer DID is missing.',
      'signer_did must be a non-empty string.',
      'signer_did',
    );
  }

  if (!rawEnvelope.signer_did.startsWith('did:')) {
    return invalid(
      'INVALID_DID_FORMAT',
      'Compiled evidence report signer DID format is invalid.',
      'signer_did must start with "did:".',
      'signer_did',
    );
  }

  if (!isNonEmptyString(rawEnvelope.issued_at) || !STRICT_ISO_UTC_RE.test(rawEnvelope.issued_at)) {
    return invalid(
      'SCHEMA_VALIDATION_FAILED',
      'Compiled evidence report issued_at is invalid.',
      'issued_at must be a strict UTC ISO-8601 timestamp.',
      'issued_at',
    );
  }

  const payloadValidation = validateCompiledReportPayloadShape(rawEnvelope.payload);
  if (!payloadValidation.ok) {
    return invalid(
      payloadValidation.code,
      'Compiled evidence report payload failed schema validation.',
      payloadValidation.message,
      payloadValidation.field,
    );
  }

  const payload = payloadValidation.value;

  if (payload.narrative) {
    const expectedAuthoritativeReportHash =
      await computeAuthoritativeReportHashB64u(payload);

    if (
      expectedAuthoritativeReportHash !==
      payload.narrative.authoritative_report_hash_b64u
    ) {
      return invalid(
        'HASH_MISMATCH',
        'Compiled evidence narrative binding hash mismatch.',
        'payload.narrative.authoritative_report_hash_b64u does not match the canonical authoritative compiled report hash.',
        'payload.narrative.authoritative_report_hash_b64u',
        {
          report_id: payload.report_id,
          matrix_hash_b64u: payload.matrix_hash_b64u,
          payload_hash_b64u: rawEnvelope.payload_hash_b64u,
        },
      );
    }
  }

  const expectedMatrixHash = await computeCompiledMatrixHashB64u(payload.control_results);
  if (expectedMatrixHash !== payload.matrix_hash_b64u) {
    return invalid(
      'HASH_MISMATCH',
      'Compiled evidence report matrix hash mismatch.',
      'matrix_hash_b64u does not match the canonical hash of control_results.',
      'payload.matrix_hash_b64u',
      {
        report_id: payload.report_id,
        matrix_hash_b64u: payload.matrix_hash_b64u,
        payload_hash_b64u: rawEnvelope.payload_hash_b64u,
      },
    );
  }

  const expectedPayloadHash = await sha256B64uFromCanonical(payload);
  if (expectedPayloadHash !== rawEnvelope.payload_hash_b64u) {
    return invalid(
      'HASH_MISMATCH',
      'Compiled evidence report payload hash mismatch.',
      'payload_hash_b64u does not match the canonical hash of payload.',
      'payload_hash_b64u',
      {
        report_id: payload.report_id,
        matrix_hash_b64u: payload.matrix_hash_b64u,
        payload_hash_b64u: rawEnvelope.payload_hash_b64u,
      },
    );
  }

  const publicKey = extractPublicKeyFromDidKey(rawEnvelope.signer_did);
  if (!publicKey) {
    return invalid(
      'INVALID_DID_FORMAT',
      'Compiled evidence report signer DID could not be resolved to an Ed25519 key.',
      'signer_did must be did:key with an Ed25519 multicodec key.',
      'signer_did',
      {
        report_id: payload.report_id,
        matrix_hash_b64u: payload.matrix_hash_b64u,
        payload_hash_b64u: rawEnvelope.payload_hash_b64u,
      },
    );
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecode(rawEnvelope.signature_b64u);
  } catch {
    return invalid(
      'MALFORMED_ENVELOPE',
      'Compiled evidence report signature encoding is invalid.',
      'signature_b64u must be valid base64url encoding.',
      'signature_b64u',
      {
        report_id: payload.report_id,
        matrix_hash_b64u: payload.matrix_hash_b64u,
        payload_hash_b64u: rawEnvelope.payload_hash_b64u,
      },
    );
  }

  const signatureValid = await verifySignature(
    'Ed25519',
    publicKey,
    signatureBytes,
    new TextEncoder().encode(rawEnvelope.payload_hash_b64u),
  );

  if (!signatureValid) {
    return invalid(
      'SIGNATURE_INVALID',
      'Compiled evidence report signature verification failed.',
      'signature_b64u does not verify payload_hash_b64u with signer_did key.',
      'signature_b64u',
      {
        report_id: payload.report_id,
        matrix_hash_b64u: payload.matrix_hash_b64u,
        payload_hash_b64u: rawEnvelope.payload_hash_b64u,
      },
    );
  }

  return {
    result: {
      status: 'VALID',
      reason: 'Compiled evidence report envelope verified successfully.',
      envelope_type: 'compiled_evidence_report',
      signer_did: rawEnvelope.signer_did,
      verified_at: verifiedAt,
    },
    report_id: payload.report_id,
    matrix_hash_b64u: payload.matrix_hash_b64u,
    payload_hash_b64u: rawEnvelope.payload_hash_b64u,
  };
}
