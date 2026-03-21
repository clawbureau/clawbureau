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
  | 'NIST_AI_RMF';

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
  | 'log_inclusion_proof';

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

export interface CompiledEvidenceReport {
  report_version: '1';
  report_id: string;
  compiled_at: string;
  compiler_version: string;
  evidence_refs: CompiledEvidenceReportEvidenceRefs;
  overall_status: CompiledEvidenceOverallStatus;
  matrix_hash_b64u: string;
  control_results: CompiledEvidenceControlResult[];
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
  metadata?: Record<string, unknown>;
}

export interface CompliancePolicyInput {
  /** Raw WPC hash (base64url). Used for CC6.1 evidence. */
  policy_hash_b64u?: string;
  /** If the WPC contains allowed_models, list them here. */
  allowed_models?: string[];
  /** Minimum model identity tier required by the WPC. */
  minimum_model_identity_tier?: string;
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
  compiled_report_refs?: Partial<CompiledEvidenceReportEvidenceRefs>;
  compiled_report_signer?: AuthoritativeCompiledReportSignerInput;
}

export type AuthoritativeCompilerState =
  | 'INPUT_REJECTED'
  | 'HALTED_UPSTREAM_INVALID'
  | 'COMPILED_PASS'
  | 'COMPILED_FAIL';

export interface AuthoritativeCompilerRuntime {
  runtime_version: '1';
  engine: 'clawcompiler-runtime-v1-wave1' | 'clawcompiler-runtime-v1-wave2';
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
const COMPILER_MAPPING_VERSION = 'control-pack-v1';

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
  if (
    rawPolicy.policy_hash_b64u !== undefined &&
    typeof rawPolicy.policy_hash_b64u !== 'string'
  ) {
    return {
      ok: false,
      reason_code: 'COMPILER_INPUT_MALFORMED_POLICY_HASH',
      reason: 'policy.policy_hash_b64u, when present, must be a string.',
    };
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
      compiled_report_refs: parsedCompiledReportRefs?.ok
        ? parsedCompiledReportRefs.value
        : undefined,
      compiled_report_signer: parsedCompiledReportSigner?.ok
        ? parsedCompiledReportSigner.value
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

async function resolveCompiledEvidenceRefs(
  input: AuthoritativeCompilerInput,
  complianceReport: ComplianceReport,
): Promise<CompiledEvidenceReportEvidenceRefs> {
  const provided = input.compiled_report_refs;

  const ontologyHash =
    provided?.ontology_hash_b64u ??
    (await sha256B64uFromCanonical({
      ontology_version: '1',
      framework: input.framework,
      compiler_version: COMPILER_VERSION_WAVE2,
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

function deterministicCompiledReportId(input: AuthoritativeCompilerInput): string {
  const frameworkPart = input.framework.replace(/[^A-Za-z0-9._:-]/g, '_');
  const bundlePart = input.bundle_hash_b64u.slice(0, 24);
  return `cer_${frameworkPart}_${bundlePart}`;
}

export async function buildCompiledEvidenceReport(
  input: AuthoritativeCompilerInput,
  complianceReport: ComplianceReport,
): Promise<CompiledEvidenceReport> {
  const controlResults = await compileDeterministicControlResults(complianceReport);
  const matrixHash = await computeCompiledMatrixHashB64u(controlResults);
  const evidenceRefs = await resolveCompiledEvidenceRefs(input, complianceReport);

  const reportId = deterministicCompiledReportId(input);
  if (!COMPILED_REPORT_ID_RE.test(reportId)) {
    throw new Error('Deterministic compiled report ID generation failed schema constraints.');
  }

  return {
    report_version: '1',
    report_id: reportId,
    compiled_at: resolveGeneratedAt(complianceReport.generated_at),
    compiler_version: COMPILER_VERSION_WAVE2,
    evidence_refs: evidenceRefs,
    overall_status: summarizeCompiledOverallStatus(controlResults),
    matrix_hash_b64u: matrixHash,
    control_results: controlResults,
  };
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

    return {
      runtime: {
        ...wave1.runtime,
        engine: 'clawcompiler-runtime-v1-wave2',
        state: 'COMPILED_FAIL',
        global_status: 'FAIL',
        global_reason_code: 'COMPILER_COMPILED_REPORT_FAILED',
      },
      report: wave1.report,
      failure: {
        reason_code: 'COMPILER_COMPILED_REPORT_FAILED',
        reason,
      },
    };
  }

  const runtime: AuthoritativeCompilerRuntime = {
    ...wave1.runtime,
    engine: 'clawcompiler-runtime-v1-wave2',
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

  if (rawPayload.compiler_version !== COMPILER_VERSION_WAVE2) {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message: `payload.compiler_version must equal "${COMPILER_VERSION_WAVE2}".`,
      field: 'payload.compiler_version',
    };
  }

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
    rawPayload.overall_status !== 'FAIL_CLOSED_INVALID_EVIDENCE'
  ) {
    return {
      ok: false,
      code: 'SCHEMA_VALIDATION_FAILED',
      message:
        'payload.overall_status must be PASS, FAIL, or FAIL_CLOSED_INVALID_EVIDENCE for wave2 compiled reports.',
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
      control.status !== 'INAPPLICABLE' &&
      control.status !== 'FAIL_CLOSED_INVALID_EVIDENCE'
    ) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message:
          `${prefix}.status must be PASS, FAIL, INAPPLICABLE, or FAIL_CLOSED_INVALID_EVIDENCE for wave2 compiled reports.`,
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

    if (control.waiver_applied !== false) {
      return {
        ok: false,
        code: 'SCHEMA_VALIDATION_FAILED',
        message: `${prefix}.waiver_applied must be false for wave2 compiled reports.`,
        field: `${prefix}.waiver_applied`,
      };
    }
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
