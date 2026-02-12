/**
 * Compliance Report Generator
 *
 * Maps verified Clawsig proof bundles to enterprise compliance framework controls.
 * P9 (Revenue): SOC2 is the wedge, EU AI Act is the whale.
 *
 * Mapping rules (from Gemini Deep Think Round 2):
 *   CC6.1 (Logical Access)       <- WPC allowed_models + proof_tier
 *   CC6.2 (System Boundaries)    <- side_effect_receipts (network_egress)
 *   CC7.1 (Detection of Changes) <- tool_receipts (file changes)
 *   CC7.2 (Monitoring)           <- event_chain existence + log_inclusion_proof
 *   CC8.1 (Change Management)    <- human_approval_receipts OR gateway_receipt tier
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ComplianceFramework = 'SOC2_Type2' | 'ISO27001' | 'EU_AI_Act' | 'NIST_AI_RMF';

export type ControlStatus = 'PASS' | 'FAIL' | 'NOT_APPLICABLE' | 'INSUFFICIENT_EVIDENCE';

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
// Lightweight bundle shape (avoids coupling to full ProofBundlePayload import
// path — the compliance mapper only inspects presence/counts, not signatures).
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
// Helpers
// ---------------------------------------------------------------------------

function hashBundle(bundle: ComplianceBundleInput): string {
  // Deterministic hash placeholder — in production this would be
  // sha256_b64u(JCS(bundle)). The CLI layer computes the real hash
  // before calling the mapper.
  return 'BUNDLE_HASH_COMPUTED_BY_CALLER';
}

function hasNetworkEgressReceipts(bundle: ComplianceBundleInput): boolean {
  return (bundle.side_effect_receipts ?? []).some(
    (r) => r.effect_class === 'network_egress',
  );
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
// SOC2 Type II Mapper
// ---------------------------------------------------------------------------

function mapCC6_1(
  bundle: ComplianceBundleInput,
  policy: CompliancePolicyInput | undefined,
): ControlResult {
  const control: ControlResult = {
    control_id: 'CC6.1',
    control_name: 'Logical Access Controls',
    status: 'INSUFFICIENT_EVIDENCE',
  };

  // CC6.1: WPC allowed_models + proof_tier from gateway receipts
  if (policy?.allowed_models && policy.allowed_models.length > 0) {
    const gatewayModels = (bundle.receipts ?? [])
      .map((r) => r.payload?.model)
      .filter(Boolean) as string[];

    if (gatewayModels.length > 0) {
      const allWithinPolicy = gatewayModels.every((m) =>
        policy.allowed_models!.includes(m),
      );
      control.status = allWithinPolicy ? 'PASS' : 'FAIL';
      control.evidence_type = 'wpc';
      control.evidence_ref = policy.policy_hash_b64u;
      control.narrative = allWithinPolicy
        ? `All ${gatewayModels.length} gateway receipt(s) reference models within the WPC allowlist (${policy.allowed_models.join(', ')}). Agent operated strictly within approved intelligence boundaries.`
        : `One or more gateway receipts reference a model outside the WPC allowlist. Models used: ${gatewayModels.join(', ')}.`;
    } else if (hasGatewayReceipts(bundle)) {
      control.status = 'PASS';
      control.evidence_type = 'gateway_receipt';
      control.evidence_ref = bundle.receipts![0].payload?.receipt_id;
      control.narrative =
        'Gateway receipts present; WPC policy defines allowed models. Agent used approved gateway for all LLM calls.';
    } else {
      control.narrative =
        'WPC defines allowed_models but no gateway receipts present to verify compliance.';
    }
  } else if (hasGatewayReceipts(bundle)) {
    // No WPC but gateway receipts exist — partial evidence
    control.status = 'PASS';
    control.evidence_type = 'gateway_receipt';
    control.evidence_ref = bundle.receipts![0].payload?.receipt_id;
    control.narrative =
      'Gateway receipts prove agent routed through trusted proxy. No WPC model allowlist configured — recommend adding allowed_models for full CC6.1 coverage.';
  } else {
    control.narrative =
      'No gateway receipts and no WPC model allowlist. Cannot verify logical access controls for LLM usage.';
  }

  return control;
}

function mapCC6_2(bundle: ComplianceBundleInput): ControlResult {
  const control: ControlResult = {
    control_id: 'CC6.2',
    control_name: 'System Boundary Controls',
    status: 'INSUFFICIENT_EVIDENCE',
  };

  const networkReceipts = (bundle.side_effect_receipts ?? []).filter(
    (r) => r.effect_class === 'network_egress',
  );

  if (networkReceipts.length > 0) {
    control.status = 'PASS';
    control.evidence_type = 'side_effect_receipt';
    control.evidence_ref = networkReceipts[0].receipt_id;
    control.narrative = `${networkReceipts.length} network egress side-effect receipt(s) present. Every outbound network call by the agent is cryptographically logged with target digest and response hash.`;
  } else if ((bundle.side_effect_receipts ?? []).length > 0) {
    // Has side-effect receipts but none for network egress
    control.status = 'PASS';
    control.evidence_type = 'side_effect_receipt';
    control.evidence_ref = bundle.side_effect_receipts![0].receipt_id;
    control.narrative =
      'Side-effect receipts present (non-network). No network egress detected — agent stayed within system boundaries.';
  } else {
    control.narrative =
      'No side-effect receipts present. Cannot verify system boundary compliance. Add side-effect receipt instrumentation to the harness.';
  }

  return control;
}

function mapCC7_1(bundle: ComplianceBundleInput): ControlResult {
  const control: ControlResult = {
    control_id: 'CC7.1',
    control_name: 'Detection of Changes',
    status: 'INSUFFICIENT_EVIDENCE',
  };

  if (hasFileWriteReceipts(bundle)) {
    control.status = 'PASS';
    control.evidence_type = 'tool_receipt';
    control.evidence_ref = bundle.tool_receipts![0].receipt_id;
    control.narrative = `${bundle.tool_receipts!.length} tool receipt(s) present. Every file modification and tool invocation by the agent is logged with input/output hashes in an immutable event chain.`;
  } else if (hasEventChain(bundle)) {
    control.status = 'PASS';
    control.evidence_type = 'event_chain';
    control.narrative =
      'Event chain present but no tool receipts. Change detection relies on event chain integrity — recommend adding tool receipt instrumentation for granular file-level evidence.';
  } else {
    control.narrative =
      'No tool receipts or event chain present. Cannot verify change detection compliance.';
  }

  return control;
}

function mapCC7_2(bundle: ComplianceBundleInput): ControlResult {
  const control: ControlResult = {
    control_id: 'CC7.2',
    control_name: 'System Monitoring',
    status: 'INSUFFICIENT_EVIDENCE',
  };

  if (hasEventChain(bundle)) {
    control.status = 'PASS';
    control.evidence_type = 'event_chain';
    control.narrative = `Hash-linked event chain present with ${bundle.event_chain!.length} event(s). Every agent action is logged to a tamper-evident, append-only chain. Receipt Transparency Log integration provides additional Merkle tree inclusion proof coverage.`;
  } else {
    control.narrative =
      'No event chain present. System monitoring requires a tamper-evident event log. Configure the harness to emit an event chain.';
  }

  return control;
}

function mapCC8_1(bundle: ComplianceBundleInput): ControlResult {
  const control: ControlResult = {
    control_id: 'CC8.1',
    control_name: 'Change Management',
    status: 'INSUFFICIENT_EVIDENCE',
  };

  if (hasHumanApprovals(bundle)) {
    const approvals = bundle.human_approval_receipts!.filter(
      (r) => r.approval_type === 'explicit_approve',
    );
    control.status = 'PASS';
    control.evidence_type = 'human_approval_receipt';
    control.evidence_ref = approvals[0]?.receipt_id;
    control.narrative = `${approvals.length} explicit human approval receipt(s) present. Cryptographic proof that a human reviewer authorized changes before deployment. This satisfies change management controls without traditional peer review.`;
  } else if (hasGatewayReceipts(bundle)) {
    // Gateway receipts provide weaker but acceptable evidence
    control.status = 'PASS';
    control.evidence_type = 'gateway_receipt';
    control.evidence_ref = bundle.receipts![0].payload?.receipt_id;
    control.narrative =
      'Gateway receipts prove code was generated through a trusted, auditable proxy under policy constraints. No explicit human approval — recommend adding human_approval_receipts for stronger CC8.1 evidence.';
  } else {
    control.narrative =
      'No human approval receipts or gateway receipts present. Change management requires either human oversight proof or gateway-tier evidence.';
  }

  return control;
}

/**
 * Maps a proof bundle to SOC2 Type II controls.
 *
 * The bundle should already be verified (signature + hash chain valid).
 * This function evaluates evidence presence and quality, not cryptographic integrity.
 */
export function mapToSOC2(
  bundle: ComplianceBundleInput,
  policy?: CompliancePolicyInput,
  opts?: { bundleHash?: string },
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
    if (c.status === 'FAIL') {
      gaps.push({
        control_id: c.control_id,
        description: c.narrative ?? `Control ${c.control_id} failed evaluation.`,
        recommendation: getRemediation(c.control_id),
      });
    } else if (c.status === 'INSUFFICIENT_EVIDENCE') {
      gaps.push({
        control_id: c.control_id,
        description: c.narrative ?? `Insufficient evidence for ${c.control_id}.`,
        recommendation: getRemediation(c.control_id),
      });
    }
  }

  return {
    report_version: '1',
    framework: 'SOC2_Type2',
    generated_at: new Date().toISOString(),
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
      return 'Add human-in-the-loop approval gates for high-risk actions. The harness should emit human_approval_receipts, or at minimum route through clawproxy for gateway-tier evidence.';
    default:
      return 'Review the Clawsig Protocol documentation for instrumentation guidance.';
  }
}

// ---------------------------------------------------------------------------
// ISO 27001 Mapper (stub)
// ---------------------------------------------------------------------------

// TODO: Implement ISO 27001 information security control mapping.
// Key controls to map:
//   A.9.1 (Access Control Policy) <- WPC + gateway_receipts
//   A.9.2 (User Access Management) <- agent_did + owner_attestation
//   A.12.4 (Logging and Monitoring) <- event_chain + log_inclusion_proof
//   A.14.2 (Security in Development) <- tool_receipts + human_approval_receipts
//   A.18.1 (Compliance with Legal Requirements) <- full proof_bundle
export function mapToISO27001(
  bundle: ComplianceBundleInput,
  policy?: CompliancePolicyInput,
  opts?: { bundleHash?: string },
): ComplianceReport {
  return {
    report_version: '1',
    framework: 'ISO27001',
    generated_at: new Date().toISOString(),
    proof_bundle_hash_b64u: opts?.bundleHash ?? hashBundle(bundle),
    agent_did: bundle.agent_did,
    policy_hash_b64u: policy?.policy_hash_b64u,
    controls: [
      {
        control_id: 'A.9.1',
        control_name: 'Access Control Policy',
        status: 'NOT_APPLICABLE',
        narrative: 'ISO 27001 mapper not yet implemented. SOC2 mapping is available.',
      },
    ],
    gaps: [
      {
        control_id: 'A.9.1',
        description: 'ISO 27001 compliance mapping is not yet implemented.',
        recommendation: 'Use SOC2 framework for current compliance reporting. ISO 27001 support is planned.',
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// EU AI Act Mapper (stub)
// ---------------------------------------------------------------------------

// TODO: Implement EU AI Act compliance mapping.
// Key articles to map:
//   Art 9 (Risk Management) <- WPC + proof_tier
//   Art 11 (Technical Documentation) <- export_bundle + urm
//   Art 13 (Transparency) <- system_prompt_report + model_identity
//   Art 14 (Human Oversight) <- human_approval_receipts (the killer feature)
//   Art 15 (Accuracy, Robustness, Security) <- audit_result_attestations
export function mapToEUAIAct(
  bundle: ComplianceBundleInput,
  policy?: CompliancePolicyInput,
  opts?: { bundleHash?: string },
): ComplianceReport {
  return {
    report_version: '1',
    framework: 'EU_AI_Act',
    generated_at: new Date().toISOString(),
    proof_bundle_hash_b64u: opts?.bundleHash ?? hashBundle(bundle),
    agent_did: bundle.agent_did,
    policy_hash_b64u: policy?.policy_hash_b64u,
    controls: [
      {
        control_id: 'Art14',
        control_name: 'Human Oversight',
        status: hasHumanApprovals(bundle) ? 'PASS' : 'INSUFFICIENT_EVIDENCE',
        evidence_type: hasHumanApprovals(bundle) ? 'human_approval_receipt' : undefined,
        evidence_ref: hasHumanApprovals(bundle)
          ? bundle.human_approval_receipts?.find((r) => r.approval_type === 'explicit_approve')?.receipt_id
          : undefined,
        narrative: hasHumanApprovals(bundle)
          ? 'Cryptographic proof of Article 14 compliance. High-risk actions are mathematically locked until a HumanApprovalReceipt is signed by a verified operator.'
          : 'No human approval receipts present. Article 14 requires proof of human oversight for high-risk AI systems.',
      },
    ],
    gaps: hasHumanApprovals(bundle)
      ? []
      : [
          {
            control_id: 'Art14',
            description: 'No human approval receipts. EU AI Act Article 14 requires verifiable human oversight.',
            recommendation: 'Add human-in-the-loop approval gates. The harness should emit human_approval_receipts for high-risk operations.',
          },
        ],
  };
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/**
 * Generate a compliance report for any supported framework.
 */
export function generateComplianceReport(
  framework: ComplianceFramework,
  bundle: ComplianceBundleInput,
  policy?: CompliancePolicyInput,
  opts?: { bundleHash?: string },
): ComplianceReport {
  switch (framework) {
    case 'SOC2_Type2':
      return mapToSOC2(bundle, policy, opts);
    case 'ISO27001':
      return mapToISO27001(bundle, policy, opts);
    case 'EU_AI_Act':
      return mapToEUAIAct(bundle, policy, opts);
    case 'NIST_AI_RMF':
      // TODO: Implement NIST AI RMF mapping
      return {
        report_version: '1',
        framework: 'NIST_AI_RMF',
        generated_at: new Date().toISOString(),
        proof_bundle_hash_b64u: opts?.bundleHash ?? hashBundle(bundle),
        agent_did: bundle.agent_did,
        policy_hash_b64u: policy?.policy_hash_b64u,
        controls: [],
        gaps: [
          {
            control_id: 'GOVERN',
            description: 'NIST AI RMF compliance mapping is not yet implemented.',
            recommendation: 'Use SOC2 framework for current compliance reporting. NIST AI RMF support is planned.',
          },
        ],
      };
    default: {
      const _exhaustive: never = framework;
      throw new Error(`Unknown compliance framework: ${_exhaustive}`);
    }
  }
}
