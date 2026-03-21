/**
 * Compliance report compiler (Wave 1 foundations)
 *
 * CEC-RT-001: verified-evidence ingest contract
 * CEC-RT-002: deterministic control-pack runtime
 * CEC-RT-003: fail-closed compiler state machine
 */

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
}

export type AuthoritativeCompilerState =
  | 'INPUT_REJECTED'
  | 'HALTED_UPSTREAM_INVALID'
  | 'COMPILED_PASS'
  | 'COMPILED_FAIL';

export interface AuthoritativeCompilerRuntime {
  runtime_version: '1';
  engine: 'clawcompiler-runtime-v1-wave1';
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
  failure?: AuthoritativeCompilerFailure;
}

// ---------------------------------------------------------------------------
// Constants + helpers
// ---------------------------------------------------------------------------

const DETERMINISTIC_EPOCH_ISO = '1970-01-01T00:00:00.000Z';
const REASON_CODE_RE = /^[A-Z0-9_]{1,64}$/;
const STRICT_ISO_UTC_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

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
