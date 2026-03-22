import { access, mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import crypto from 'node:crypto';

import { decryptBundle, extractPublicLayer, InspectError } from './inspect-cmd.js';

import type { ClawsigIdentity } from './identity.js';

export interface ProveOptions {
  inputPath: string;
  htmlPath?: string;
  exportPackPath?: string;
  compareWithPath?: string;
  decrypt: boolean;
  json: boolean;
  runSummaryPath?: string;
}

export interface ProofGatewaySummary {
  signed_count: number;
  signer_dids: string[];
  provider: string | null;
  model: string | null;
  gateway_id: string | null;
  latency_ms: number | null;
  timestamp: string | null;
}

export type ProofReviewBucketTone = 'good' | 'caution' | 'info' | 'action';

export interface ProofReviewBucket {
  key: 'gateway_proof' | 'execution_hygiene' | 'background_noise' | 'reviewer_action_needed';
  label: string;
  tone: ProofReviewBucketTone;
  summary: string;
  items: string[];
}

export interface ProofRuntimeProfile {
  profile_id: string | null;
  profile_version: string | null;
  mode: string | null;
  status: string | null;
  fallback_reasons: string[];
  baseline_process_count: number | null;
  baseline_process_hash_b64u: string | null;
}

export interface ProofRuntimeHygiene {
  verdict: 'good' | 'caution' | 'action' | null;
  reviewer_action_required: boolean;
  background_signals: string[];
  caution_signals: string[];
  action_required_signals: string[];
}

type ProofPrivacyVerdict = 'good' | 'caution' | 'action';

type DataHandlingAction = 'allow' | 'redact' | 'block' | 'require_approval';

type ProofRunnerAttestationPosture = 'attested' | 'non_attested';

type ProofRunnerAttestationReasonCode =
  | 'ATTESTED_TIER_GRANTED'
  | 'ATTESTED_TIER_NOT_GRANTED_NO_RUNNER_ATTESTATION'
  | 'ATTESTED_TIER_NOT_GRANTED_TRUST_CONSTRAINED'
  | 'ATTESTED_TIER_NOT_GRANTED_REVOKED_POLICY_ISSUER'
  | 'ATTESTED_TIER_NOT_GRANTED_REVOKED_RUNNER'
  | 'ATTESTED_TIER_NOT_GRANTED_INVALID_RUNNER_ATTESTATION';

type ProofReviewerSignoffDecision = 'approve' | 'reject' | 'needs_changes';
type ProofReviewerSignoffTargetKind = 'run' | 'export_pack';

export interface ProofReviewerSignoffState {
  present: boolean;
  receipt_count: number;
  structured_receipt_count: number;
  revoked_receipt_count: number;
  revoked_reviewer_dids: string[];
  reviewer_dids: string[];
  decision_counts: {
    approve: number;
    reject: number;
    needs_changes: number;
  };
  target_counts: {
    run: number;
    export_pack: number;
  };
  latest_timestamp: string | null;
  dispute_present: boolean;
  dispute_note_count: number;
  dispute_evidence_refs_count: number;
}

export interface ProofPrivacyProcessorRoute {
  provider: string;
  model: string;
  region: string;
  retention_profile: string;
  count: number;
}

export interface ProofPrivacyProcessorBlockedAttempt {
  route: Omit<ProofPrivacyProcessorRoute, 'count'>;
  reason_code: string;
  timestamp: string | null;
}

export interface ProofPrivacySensitiveClass {
  class_id: string;
  match_count: number;
  actions: DataHandlingAction[];
}

export interface ProofPrivacyActionCount {
  action: DataHandlingAction;
  count: number;
}

export interface ProofPrivacyPosture {
  overall_verdict: ProofPrivacyVerdict;
  reviewer_action_required: boolean;
  evidence: {
    egress_policy_receipt_present: boolean;
    runtime_profile_present: boolean;
    runtime_hygiene_present: boolean;
    data_handling_receipts_present: boolean;
    processor_policy_evidence_present: boolean;
    runner_measurement_present: boolean;
    runner_attestation_receipt_present: boolean;
  };
  egress: {
    proofed_mode: boolean | null;
    direct_provider_access_blocked: boolean | null;
    blocked_attempt_count: number | null;
    blocked_attempts_observed: boolean | null;
    allowed_proxy_destinations: string[];
    allowed_child_destinations: string[];
  };
  processor_policy: {
    profile_id: string | null;
    policy_version: string | null;
    enforce: boolean | null;
    allowed_routes: number | null;
    denied_routes: number | null;
    used_processors: ProofPrivacyProcessorRoute[];
    blocked_attempts: ProofPrivacyProcessorBlockedAttempt[];
  };
  data_handling: {
    policy_version: string | null;
    receipt_count: number;
    actions: ProofPrivacyActionCount[];
    sensitive_classes: ProofPrivacySensitiveClass[];
    approval_required_count: number;
    approval_satisfied_count: number;
    approval_unsatisfied_count: number;
    redaction_applied_count: number;
    reason_codes: string[];
  };
  runtime: {
    profile_id: string | null;
    profile_status: string | null;
    hygiene_verdict: ProofRuntimeHygiene['verdict'];
  };
  runner_attestation: {
    posture: ProofRunnerAttestationPosture;
    reason_code: ProofRunnerAttestationReasonCode;
    claimed_tier: string | null;
    claimed_trust_tier: string | null;
    attested_tier_claimed: boolean;
    evidence: {
      runner_measurement_present: boolean;
      runner_measurement_structured: boolean;
      runner_attestation_receipt_present: boolean;
      runner_attestation_receipt_structured: boolean;
      binding_consistent: boolean;
    };
  };
  signal_buckets: {
    background_noise: string[];
    caution: string[];
    reviewer_action_required: string[];
  };
  proven_claims: string[];
  not_proven_claims: string[];
}

export type ProofCompiledEvidenceControlStatus =
  | 'PASS'
  | 'FAIL'
  | 'PARTIAL'
  | 'INAPPLICABLE'
  | 'FAIL_CLOSED_INVALID_EVIDENCE';

export type ProofCompiledEvidenceOverallStatus =
  | 'PASS'
  | 'FAIL'
  | 'PARTIAL'
  | 'FAIL_CLOSED_INVALID_EVIDENCE';

export interface ProofCompiledEvidenceOutcomeCounts {
  total: number;
  pass: number;
  fail: number;
  partial: number;
  inapplicable: number;
  fail_closed_invalid_evidence: number;
}

export interface ProofCompiledEvidenceRefSummary {
  proof_bundle_hash_b64u: string | null;
  ontology_hash_b64u: string | null;
  mapping_rules_hash_b64u: string | null;
  verify_result_hash_b64u: string | null;
}

export interface ProofCompiledEvidenceNarrativeSummary {
  present: boolean;
  authoritative_flag: boolean | null;
  disclaimer: string | null;
}

export interface ProofCompiledEvidenceArtifactPaths {
  envelope: string;
  report?: string;
  summary?: string;
  narrative?: string;
}

export interface ProofCompiledEvidenceSummary {
  envelope_present: boolean;
  authoritative_report_present: boolean;
  metadata_path: string | null;
  report_id: string | null;
  compiler_version: string | null;
  overall_status: ProofCompiledEvidenceOverallStatus | null;
  matrix_hash_b64u: string | null;
  payload_hash_b64u: string | null;
  signer_did: string | null;
  issued_at: string | null;
  control_outcome_counts: ProofCompiledEvidenceOutcomeCounts;
  non_pass_controls: string[];
  evidence_refs: ProofCompiledEvidenceRefSummary;
  narrative: ProofCompiledEvidenceNarrativeSummary;
  invalid_reasons: string[];
  artifact_paths?: ProofCompiledEvidenceArtifactPaths;
}

export interface ProofReport {
  input_path: string;
  run_summary_path: string | null;
  generated_at: string;
  public_layer: ReturnType<typeof extractPublicLayer>;
  harness: {
    status: string | null;
    tier: string | null;
    trust_tier: string | null;
    duration_seconds: number | null;
    timestamp: string | null;
    did: string | null;
  };
  evidence: {
    event_chain_count: number;
    receipt_count: number;
    execution_receipt_count: number;
    network_receipt_count: number;
    tool_receipt_count: number;
    files_modified_count: number | null;
    tools_used_count: number | null;
  };
  gateway: ProofGatewaySummary;
  sentinels: {
    shell_events: number;
    fs_events: number;
    net_events: number;
    net_suspicious: number;
    preload_llm_events: number;
    interpose_active: boolean;
    unmediated_connections: number;
    unmonitored_spawns: number;
    escapes_suspected: boolean;
    runtime_profile: ProofRuntimeProfile;
    runtime_hygiene: ProofRuntimeHygiene;
  };
  network: {
    classification_counts: Record<string, number>;
    top_processes: Array<{ process_name: string; count: number }>;
  };
  reviewer_signoff: ProofReviewerSignoffState;
  privacy_posture: ProofPrivacyPosture;
  compiled_evidence: ProofCompiledEvidenceSummary;
  review_buckets: ProofReviewBucket[];
  warnings: string[];
  next_steps: string[];
  verify_command: string;
  html_path?: string;
  export_pack_path?: string;
  decrypted_payload_keys?: string[];
  run_comparison?: ProofRunComparison;
}

type ProofRunComparisonValue = string | number | boolean | null;

export interface ProofRunComparisonDeltaRow {
  label: string;
  baseline: ProofRunComparisonValue;
  candidate: ProofRunComparisonValue;
  changed: boolean;
}

export interface ProofRunComparisonStringSetDelta {
  added: string[];
  removed: string[];
}

export interface ProofRunComparisonCountDelta {
  key: string;
  baseline_count: number;
  candidate_count: number;
}

export interface ProofRunComparisonSnapshot {
  bundle_id: string | null;
  harness_status: string | null;
  tier: string | null;
  trust_tier: string | null;
  privacy_verdict: ProofPrivacyVerdict;
  reviewer_action_required: boolean;
  runner_attestation_posture: ProofRunnerAttestationPosture;
  runner_attestation_reason_code: ProofRunnerAttestationReasonCode;
}

export interface ProofRunComparison {
  comparison_version: '1';
  generated_at: string;
  baseline_source: {
    type: 'proof_bundle' | 'export_pack' | 'proof_report';
  };
  baseline: ProofRunComparisonSnapshot;
  candidate: ProofRunComparisonSnapshot;
  deltas: {
    assurance: {
      rows: ProofRunComparisonDeltaRow[];
      changed: boolean;
    };
    evidence: {
      rows: ProofRunComparisonDeltaRow[];
      changed: boolean;
    };
    policy: {
      rows: ProofRunComparisonDeltaRow[];
      changed: boolean;
    };
    processor: {
      used_processor_routes: ProofRunComparisonStringSetDelta;
      used_processor_count_deltas: ProofRunComparisonCountDelta[];
      blocked_attempts: ProofRunComparisonStringSetDelta;
      changed: boolean;
    };
    privacy: {
      rows: ProofRunComparisonDeltaRow[];
      data_handling_action_rows: ProofRunComparisonDeltaRow[];
      sensitive_class_deltas: ProofRunComparisonStringSetDelta;
      signal_deltas: {
        background_noise: ProofRunComparisonStringSetDelta;
        caution: ProofRunComparisonStringSetDelta;
        reviewer_action_required: ProofRunComparisonStringSetDelta;
      };
      claim_deltas: {
        proven_claims: ProofRunComparisonStringSetDelta;
        not_proven_claims: ProofRunComparisonStringSetDelta;
      };
      changed: boolean;
    };
  };
  reviewer_highlights: string[];
}

type ProofReportBase = Omit<
  ProofReport,
  'input_path' | 'run_summary_path' | 'generated_at' | 'review_buckets' | 'warnings' | 'next_steps' | 'verify_command' | 'html_path'
>;

const DEFAULT_REVIEWER_SIGNOFF_STATE: ProofReviewerSignoffState = {
  present: false,
  receipt_count: 0,
  structured_receipt_count: 0,
  revoked_receipt_count: 0,
  revoked_reviewer_dids: [],
  reviewer_dids: [],
  decision_counts: {
    approve: 0,
    reject: 0,
    needs_changes: 0,
  },
  target_counts: {
    run: 0,
    export_pack: 0,
  },
  latest_timestamp: null,
  dispute_present: false,
  dispute_note_count: 0,
  dispute_evidence_refs_count: 0,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function asNonNegativeInteger(value: unknown): number | null {
  const parsed = asNumber(value);
  if (parsed === null || !Number.isInteger(parsed) || parsed < 0) {
    return null;
  }
  return parsed;
}

function asBoolean(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => asString(entry))
    .filter((entry): entry is string => entry !== null);
}

function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return count === 1 ? singular : plural;
}

function dedupeStrings(values: string[]): string[] {
  const normalized = values
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  return [...new Set(normalized)];
}

function hasOnlyAllowedKeys(record: Record<string, unknown>, allowedKeys: readonly string[]): boolean {
  return Object.keys(record).every((key) => allowedKeys.includes(key));
}

function isDataHandlingAction(value: unknown): value is DataHandlingAction {
  return value === 'allow' || value === 'redact' || value === 'block' || value === 'require_approval';
}

function isBase64UrlLike(value: string | null, minLength = 8): boolean {
  return value !== null && value.length >= minLength && /^[A-Za-z0-9_-]+$/.test(value);
}

function isCanonicalHostList(value: unknown): value is string[] {
  if (!Array.isArray(value)) {
    return false;
  }

  let previous: string | null = null;
  const seen = new Set<string>();
  for (const entry of value) {
    const normalized = asString(entry);
    if (
      normalized === null ||
      normalized !== normalized.toLowerCase() ||
      seen.has(normalized) ||
      (previous !== null && normalized.localeCompare(previous) < 0)
    ) {
      return false;
    }
    seen.add(normalized);
    previous = normalized;
  }

  return true;
}

function isIsoTimestamp(value: string | null): boolean {
  if (value === null) {
    return false;
  }

  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && value === new Date(parsed).toISOString();
}

function computeJsonSha256B64u(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('base64url');
}

const COMPILED_REPORT_ENVELOPE_METADATA_PATHS: ReadonlyArray<readonly string[]> = [
  ['compiled_report_envelope'],
  ['compiled_evidence_report_envelope'],
  ['compliance', 'compiled_report_envelope'],
  ['compliance', 'compiled_evidence_report_envelope'],
  ['clawcompiler', 'compiled_report_envelope'],
  ['clawcompiler', 'compiled_evidence_report_envelope'],
];

const COMPILED_REPORT_NARRATIVE_DISCLAIMER =
  'NON_NORMATIVE: This narrative is explanatory only and is not authoritative compliance evidence. Authoritative determinations are in compiled_evidence_report.control_results.';

const COMPILED_EVIDENCE_CONTROL_STATUS_VALUES = new Set<ProofCompiledEvidenceControlStatus>([
  'PASS',
  'FAIL',
  'PARTIAL',
  'INAPPLICABLE',
  'FAIL_CLOSED_INVALID_EVIDENCE',
]);

const COMPILED_EVIDENCE_OVERALL_STATUS_VALUES = new Set<ProofCompiledEvidenceOverallStatus>([
  'PASS',
  'FAIL',
  'PARTIAL',
  'FAIL_CLOSED_INVALID_EVIDENCE',
]);

interface CompiledEvidenceEnvelopeCandidate {
  metadata_path: string;
  envelope: Record<string, unknown>;
}

interface CompiledEvidenceExtraction {
  summary: ProofCompiledEvidenceSummary;
  envelope: Record<string, unknown> | null;
  report_payload: Record<string, unknown> | null;
  narrative_payload: Record<string, unknown> | null;
}

function buildDefaultCompiledEvidenceSummary(): ProofCompiledEvidenceSummary {
  return {
    envelope_present: false,
    authoritative_report_present: false,
    metadata_path: null,
    report_id: null,
    compiler_version: null,
    overall_status: null,
    matrix_hash_b64u: null,
    payload_hash_b64u: null,
    signer_did: null,
    issued_at: null,
    control_outcome_counts: {
      total: 0,
      pass: 0,
      fail: 0,
      partial: 0,
      inapplicable: 0,
      fail_closed_invalid_evidence: 0,
    },
    non_pass_controls: [],
    evidence_refs: {
      proof_bundle_hash_b64u: null,
      ontology_hash_b64u: null,
      mapping_rules_hash_b64u: null,
      verify_result_hash_b64u: null,
    },
    narrative: {
      present: false,
      authoritative_flag: null,
      disclaimer: null,
    },
    invalid_reasons: [],
  };
}

function isCompiledEvidenceControlStatus(
  value: string | null,
): value is ProofCompiledEvidenceControlStatus {
  return value !== null && COMPILED_EVIDENCE_CONTROL_STATUS_VALUES.has(value as ProofCompiledEvidenceControlStatus);
}

function isCompiledEvidenceOverallStatus(
  value: string | null,
): value is ProofCompiledEvidenceOverallStatus {
  return value !== null && COMPILED_EVIDENCE_OVERALL_STATUS_VALUES.has(value as ProofCompiledEvidenceOverallStatus);
}

function readMetadataRecordAtPath(
  metadata: Record<string, unknown> | null,
  pathParts: readonly string[],
): Record<string, unknown> | null {
  if (!metadata) {
    return null;
  }

  let cursor: unknown = metadata;
  for (const part of pathParts) {
    if (!isRecord(cursor) || !isRecord(cursor[part])) {
      return null;
    }
    cursor = cursor[part];
  }

  return isRecord(cursor) ? cursor : null;
}

function discoverCompiledReportEnvelopeCandidates(
  payload: Record<string, unknown>,
): CompiledEvidenceEnvelopeCandidate[] {
  const metadata = isRecord(payload.metadata) ? payload.metadata : null;
  if (!metadata) {
    return [];
  }

  const candidates: CompiledEvidenceEnvelopeCandidate[] = [];
  for (const pathParts of COMPILED_REPORT_ENVELOPE_METADATA_PATHS) {
    const envelope = readMetadataRecordAtPath(metadata, pathParts);
    if (!envelope) {
      continue;
    }
    candidates.push({
      metadata_path: `metadata.${pathParts.join('.')}`,
      envelope,
    });
  }

  return candidates;
}

function extractCompiledEvidence(payload: Record<string, unknown>): CompiledEvidenceExtraction {
  const summary = buildDefaultCompiledEvidenceSummary();
  const candidates = discoverCompiledReportEnvelopeCandidates(payload);
  const authoritativeInvalidReasons: string[] = [];
  const narrativeInvalidReasons: string[] = [];

  if (candidates.length === 0) {
    return {
      summary,
      envelope: null,
      report_payload: null,
      narrative_payload: null,
    };
  }

  const primary = candidates[0]!;
  summary.envelope_present = true;
  summary.metadata_path = primary.metadata_path;

  if (candidates.length > 1) {
    authoritativeInvalidReasons.push(
      `Multiple compiled report envelope metadata paths were found: ${candidates.map((candidate) => candidate.metadata_path).join(', ')}.`,
    );
  }

  const envelope = primary.envelope;
  summary.signer_did = asString(envelope.signer_did);
  summary.issued_at = asString(envelope.issued_at);
  summary.payload_hash_b64u = asString(envelope.payload_hash_b64u);

  if (asString(envelope.envelope_version) !== '1') {
    authoritativeInvalidReasons.push('Compiled report envelope_version must equal "1".');
  }
  if (asString(envelope.envelope_type) !== 'compiled_evidence_report') {
    authoritativeInvalidReasons.push('Compiled report envelope_type must equal "compiled_evidence_report".');
  }
  if (asString(envelope.hash_algorithm) !== 'SHA-256') {
    authoritativeInvalidReasons.push('Compiled report hash_algorithm must equal "SHA-256".');
  }
  if (asString(envelope.algorithm) !== 'Ed25519') {
    authoritativeInvalidReasons.push('Compiled report algorithm must equal "Ed25519".');
  }
  if (!isBase64UrlLike(summary.payload_hash_b64u)) {
    authoritativeInvalidReasons.push('Compiled report payload_hash_b64u must be base64url (min length 8).');
  }
  if (!isBase64UrlLike(asString(envelope.signature_b64u))) {
    authoritativeInvalidReasons.push('Compiled report signature_b64u must be base64url (min length 8).');
  }

  const reportPayload = isRecord(envelope.payload) ? envelope.payload : null;
  if (!reportPayload) {
    authoritativeInvalidReasons.push('Compiled report envelope payload is missing or not an object.');
    summary.invalid_reasons = dedupeStrings(authoritativeInvalidReasons);
    summary.authoritative_report_present = false;
    return {
      summary,
      envelope,
      report_payload: null,
      narrative_payload: null,
    };
  }

  summary.report_id = asString(reportPayload.report_id);
  summary.compiler_version = asString(reportPayload.compiler_version);
  summary.matrix_hash_b64u = asString(reportPayload.matrix_hash_b64u);

  if (asString(reportPayload.report_version) !== '1') {
    authoritativeInvalidReasons.push('Compiled report payload.report_version must equal "1".');
  }
  if (summary.report_id === null) {
    authoritativeInvalidReasons.push('Compiled report payload.report_id is missing.');
  }
  if (summary.compiler_version === null) {
    authoritativeInvalidReasons.push('Compiled report payload.compiler_version is missing.');
  }
  if (!isBase64UrlLike(summary.matrix_hash_b64u)) {
    authoritativeInvalidReasons.push('Compiled report payload.matrix_hash_b64u must be base64url (min length 8).');
  }

  const overallStatus = asString(reportPayload.overall_status);
  if (isCompiledEvidenceOverallStatus(overallStatus)) {
    summary.overall_status = overallStatus;
  } else {
    authoritativeInvalidReasons.push('Compiled report payload.overall_status is missing or unsupported.');
  }

  const evidenceRefs = isRecord(reportPayload.evidence_refs) ? reportPayload.evidence_refs : null;
  if (!evidenceRefs) {
    authoritativeInvalidReasons.push('Compiled report payload.evidence_refs is missing or malformed.');
  } else {
    summary.evidence_refs = {
      proof_bundle_hash_b64u: asString(evidenceRefs.proof_bundle_hash_b64u),
      ontology_hash_b64u: asString(evidenceRefs.ontology_hash_b64u),
      mapping_rules_hash_b64u: asString(evidenceRefs.mapping_rules_hash_b64u),
      verify_result_hash_b64u: asString(evidenceRefs.verify_result_hash_b64u),
    };

    const missingEvidenceRef =
      summary.evidence_refs.proof_bundle_hash_b64u === null ||
      summary.evidence_refs.ontology_hash_b64u === null ||
      summary.evidence_refs.mapping_rules_hash_b64u === null ||
      summary.evidence_refs.verify_result_hash_b64u === null;

    if (missingEvidenceRef) {
      authoritativeInvalidReasons.push('Compiled report payload.evidence_refs is missing required hash fields.');
    }
  }

  const controlResultsRaw = reportPayload.control_results;
  if (!Array.isArray(controlResultsRaw) || controlResultsRaw.length === 0) {
    authoritativeInvalidReasons.push('Compiled report payload.control_results must be a non-empty array.');
  } else {
    for (const control of controlResultsRaw) {
      if (!isRecord(control)) {
        authoritativeInvalidReasons.push('Compiled report payload.control_results contains a non-object entry.');
        continue;
      }

      const controlId = asString(control.control_id);
      const status = asString(control.status);
      if (!controlId || !isCompiledEvidenceControlStatus(status)) {
        authoritativeInvalidReasons.push('Compiled report payload.control_results contains an invalid control_id/status pair.');
        continue;
      }

      summary.control_outcome_counts.total += 1;
      switch (status) {
        case 'PASS':
          summary.control_outcome_counts.pass += 1;
          break;
        case 'FAIL':
          summary.control_outcome_counts.fail += 1;
          break;
        case 'PARTIAL':
          summary.control_outcome_counts.partial += 1;
          break;
        case 'INAPPLICABLE':
          summary.control_outcome_counts.inapplicable += 1;
          break;
        case 'FAIL_CLOSED_INVALID_EVIDENCE':
          summary.control_outcome_counts.fail_closed_invalid_evidence += 1;
          break;
      }

      if (status !== 'PASS') {
        summary.non_pass_controls.push(`${controlId} (${status})`);
      }
    }
  }

  let narrativePayload: Record<string, unknown> | null = null;
  let narrativeValid = false;
  if (reportPayload.narrative !== undefined) {
    if (!isRecord(reportPayload.narrative)) {
      narrativeInvalidReasons.push('Compiled report payload.narrative must be an object when present.');
    } else {
      narrativePayload = reportPayload.narrative;
      summary.narrative = {
        present: true,
        authoritative_flag: asBoolean(reportPayload.narrative.authoritative),
        disclaimer: asString(reportPayload.narrative.disclaimer),
      };

      if (
        !hasOnlyAllowedKeys(reportPayload.narrative, [
          'narrative_version',
          'report_id',
          'generated_at',
          'authoritative',
          'disclaimer',
          'text',
          'generator_provider',
          'generator_model',
        ])
      ) {
        narrativeInvalidReasons.push(
          'Compiled report narrative contains unexpected fields outside the non-authoritative membrane schema.',
        );
      }
      if (asString(reportPayload.narrative.narrative_version) !== '1') {
        narrativeInvalidReasons.push('Compiled report narrative.narrative_version must equal "1".');
      }

      const narrativeReportId = asString(reportPayload.narrative.report_id);
      if (narrativeReportId === null) {
        narrativeInvalidReasons.push('Compiled report narrative.report_id is missing.');
      } else if (summary.report_id !== null && narrativeReportId !== summary.report_id) {
        narrativeInvalidReasons.push(
          'Compiled report narrative.report_id must match the authoritative compiled report_id.',
        );
      }

      if (!isIsoTimestamp(asString(reportPayload.narrative.generated_at))) {
        narrativeInvalidReasons.push(
          'Compiled report narrative.generated_at must be a strict UTC ISO-8601 timestamp.',
        );
      }
      if (asString(reportPayload.narrative.text) === null) {
        narrativeInvalidReasons.push('Compiled report narrative.text must be a non-empty string.');
      }
      if (summary.narrative.authoritative_flag !== false) {
        narrativeInvalidReasons.push(
          'Compiled report narrative must keep authoritative=false to preserve the narrative membrane.',
        );
      }
      if (summary.narrative.disclaimer !== COMPILED_REPORT_NARRATIVE_DISCLAIMER) {
        narrativeInvalidReasons.push(
          'Compiled report narrative disclaimer is missing or does not match the required non-authoritative membrane text.',
        );
      }

      narrativeValid = dedupeStrings(narrativeInvalidReasons).length === 0;
    }
  }

  summary.non_pass_controls = dedupeStrings(summary.non_pass_controls);
  summary.invalid_reasons = dedupeStrings([
    ...authoritativeInvalidReasons,
    ...narrativeInvalidReasons,
  ]);
  summary.authoritative_report_present = dedupeStrings(authoritativeInvalidReasons).length === 0;

  return {
    summary,
    envelope,
    report_payload: summary.authoritative_report_present ? reportPayload : null,
    narrative_payload:
      summary.authoritative_report_present && narrativeValid && narrativePayload
        ? narrativePayload
        : null,
  };
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_DID_KEY_PREFIX = 'did:key:z';
const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);
const ED25519_SPKI_DER_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function base58Decode(value: string): Uint8Array {
  const bytes: number[] = [0];

  for (const char of value) {
    const digit = BASE58_ALPHABET.indexOf(char);
    if (digit === -1) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

    for (let index = 0; index < bytes.length; index++) {
      bytes[index] *= 58;
    }
    bytes[0] += digit;

    let carry = 0;
    for (let index = 0; index < bytes.length; index++) {
      bytes[index] += carry;
      carry = bytes[index] >> 8;
      bytes[index] &= 0xff;
    }

    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  for (const char of value) {
    if (char !== '1') {
      break;
    }
    bytes.push(0);
  }

  return new Uint8Array(bytes.reverse());
}

function extractEd25519PublicKeyFromDidKey(did: string): Buffer | null {
  if (!did.startsWith(ED25519_DID_KEY_PREFIX)) {
    return null;
  }

  try {
    const decoded = base58Decode(did.slice(ED25519_DID_KEY_PREFIX.length));
    if (
      decoded.length < ED25519_MULTICODEC_PREFIX.length + 32 ||
      !decoded.subarray(0, ED25519_MULTICODEC_PREFIX.length).every((byte, index) => byte === ED25519_MULTICODEC_PREFIX[index])
    ) {
      return null;
    }

    return Buffer.from(decoded.subarray(ED25519_MULTICODEC_PREFIX.length));
  } catch {
    return null;
  }
}

function verifyEd25519DidKeySignature(args: {
  signerDid: string;
  signatureB64u: string;
  message: string;
}): boolean {
  const publicKey = extractEd25519PublicKeyFromDidKey(args.signerDid);
  if (!publicKey) {
    return false;
  }

  try {
    const key = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_DER_PREFIX, publicKey]),
      format: 'der',
      type: 'spki',
    });

    return crypto.verify(
      null,
      Buffer.from(args.message),
      key,
      Buffer.from(args.signatureB64u, 'base64url'),
    );
  } catch {
    return false;
  }
}

function describeAttestationEvidenceState(present: boolean, structured: boolean): string {
  if (!present) {
    return 'missing';
  }

  return structured ? 'present' : 'present but invalid';
}

function isSignedEnvelopeLike(envelope: Record<string, unknown>, expectedType: string): boolean {
  return (
    asString(envelope.envelope_version) === '1' &&
    asString(envelope.envelope_type) === expectedType &&
    isRecord(envelope.payload) &&
    asString(envelope.hash_algorithm) === 'SHA-256' &&
    asString(envelope.algorithm) === 'Ed25519' &&
    asString(envelope.signer_did) !== null &&
    asString(envelope.issued_at) !== null &&
    isBase64UrlLike(asString(envelope.payload_hash_b64u)) &&
    isBase64UrlLike(asString(envelope.signature_b64u))
  );
}

function hasStructuredEgressPolicyReceipt(envelope: Record<string, unknown> | null): envelope is Record<string, unknown> {
  if (!envelope || !isSignedEnvelopeLike(envelope, 'egress_policy_receipt')) {
    return false;
  }

  const payload = isRecord(envelope.payload) ? envelope.payload : null;
  const binding = payload && isRecord(payload.binding) ? payload.binding : null;

  return (
    asString(payload?.receipt_version) === '1' &&
    asString(payload?.receipt_id) !== null &&
    asString(payload?.policy_version) === '1' &&
    isBase64UrlLike(asString(payload?.policy_hash_b64u)) &&
    asBoolean(payload?.proofed_mode) !== null &&
    asString(payload?.clawproxy_url) !== null &&
    Array.isArray(payload?.allowed_proxy_destinations) &&
    Array.isArray(payload?.allowed_child_destinations) &&
    asBoolean(payload?.direct_provider_access_blocked) !== null &&
    asNumber(payload?.blocked_attempt_count) !== null &&
    asBoolean(payload?.blocked_attempts_observed) !== null &&
    asString(payload?.hash_algorithm) === 'SHA-256' &&
    asString(payload?.agent_did) !== null &&
    asString(payload?.timestamp) !== null &&
    binding !== null &&
    asString(binding.run_id) !== null &&
    isBase64UrlLike(asString(binding.event_hash_b64u))
  );
}

function hasStructuredProcessorPolicyEvidence(evidence: Record<string, unknown> | null): evidence is Record<string, unknown> {
  if (!evidence) {
    return false;
  }

  const binding = isRecord(evidence.binding) ? evidence.binding : null;
  const counters = isRecord(evidence.counters) ? evidence.counters : null;

  return (
    asString(evidence.receipt_version) === '1' &&
    asString(evidence.receipt_type) === 'processor_policy' &&
    asString(evidence.policy_version) !== null &&
    asString(evidence.profile_id) !== null &&
    isBase64UrlLike(asString(evidence.policy_hash_b64u)) &&
    asBoolean(evidence.enforce) !== null &&
    binding !== null &&
    asString(binding.run_id) !== null &&
    counters !== null &&
    asNumber(counters.allowed_routes) !== null &&
    asNumber(counters.denied_routes) !== null &&
    Array.isArray(evidence.used_processors)
  );
}

function getStructuredDataHandlingPayload(envelope: Record<string, unknown>): Record<string, unknown> | null {
  if (!isSignedEnvelopeLike(envelope, 'data_handling_receipt')) {
    return null;
  }

  const payload = isRecord(envelope.payload) ? envelope.payload : null;
  const approval = payload && isRecord(payload.approval) ? payload.approval : null;
  const redaction = payload && isRecord(payload.redaction) ? payload.redaction : null;

  if (
    !payload ||
    asString(payload.receipt_version) !== '1' ||
    asString(payload.receipt_id) === null ||
    asString(payload.policy_version) === null ||
    asString(payload.run_id) === null ||
    asString(payload.provider) === null ||
    !isDataHandlingAction(payload.action) ||
    asString(payload.reason_code) === null ||
    !Array.isArray(payload.classes) ||
    !approval ||
    asBoolean(approval.required) === null ||
    asBoolean(approval.satisfied) === null ||
    asString(approval.mechanism) === null ||
    !redaction ||
    asBoolean(redaction.applied) === null ||
    asString(redaction.original_payload_hash_b64u) === null ||
    asString(payload.timestamp) === null
  ) {
    return null;
  }

  return payload;
}

const RUNNER_MEASUREMENT_ARTIFACT_FIELDS = [
  'preload_hash_b64u',
  'node_preload_sentinel_hash_b64u',
  'sentinel_shell_hash_b64u',
  'sentinel_shell_policy_hash_b64u',
  'interpose_library_hash_b64u',
] as const;

type RunnerMeasurementArtifactField = typeof RUNNER_MEASUREMENT_ARTIFACT_FIELDS[number];
type RunnerMeasurementArtifacts = Record<RunnerMeasurementArtifactField, string | null>;

interface StructuredRunnerMeasurementEvidence {
  manifest_hash_b64u: string;
  policy_effective_policy_hash_b64u: string;
  runtime: Record<string, unknown>;
  artifacts: RunnerMeasurementArtifacts;
}

interface StructuredRunnerAttestationReceiptEvidence {
  payload_hash_b64u: string;
  signer_did: string;
  binding_run_id: string;
  binding_event_hash_b64u: string;
  policy_effective_policy_hash_b64u: string;
  runner_measurement_manifest_hash_b64u: string;
  runner_measurement_runtime_hash_b64u: string;
  artifacts: RunnerMeasurementArtifacts;
}

interface ParsedTrustRootRevocationEvidence {
  revoked_signer_did: string;
  effective_at: string;
  reason: string | null;
}

function parseTrustRootRevocationEvidence(
  value: unknown,
): ParsedTrustRootRevocationEvidence[] | null {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    return null;
  }

  const parsed: ParsedTrustRootRevocationEvidence[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) {
      return null;
    }
    if (
      !hasOnlyAllowedKeys(entry, [
        'revocation_version',
        'revoked_signer_did',
        'effective_at',
        'reason',
      ])
    ) {
      return null;
    }

    const version = asString(entry.revocation_version);
    const revokedDid = asString(entry.revoked_signer_did);
    const effectiveAt = asString(entry.effective_at);
    const reason = asString(entry.reason);
    if (
      version !== '1' ||
      revokedDid === null ||
      !revokedDid.startsWith('did:') ||
      effectiveAt === null ||
      !isIsoTimestamp(effectiveAt)
    ) {
      return null;
    }

    parsed.push({
      revoked_signer_did: revokedDid,
      effective_at: effectiveAt,
      reason,
    });
  }

  return parsed;
}

function findMatchingTrustRootRevocation(
  revocations: readonly ParsedTrustRootRevocationEvidence[],
  signerDid: string | null,
): ParsedTrustRootRevocationEvidence | null {
  if (signerDid === null) {
    return null;
  }
  for (const revocation of revocations) {
    if (revocation.revoked_signer_did === signerDid) {
      return revocation;
    }
  }
  return null;
}

function describeTrustRootRevocation(
  label: string,
  revocation: ParsedTrustRootRevocationEvidence,
): string {
  return `${label} signer DID ${revocation.revoked_signer_did} is listed as revoked (effective_at=${revocation.effective_at}${revocation.reason ? `, reason=${revocation.reason}` : ''}).`;
}

function parseRunnerMeasurementArtifacts(
  value: Record<string, unknown> | null,
): RunnerMeasurementArtifacts | null {
  if (!value) {
    return null;
  }

  const result = {} as RunnerMeasurementArtifacts;
  for (const field of RUNNER_MEASUREMENT_ARTIFACT_FIELDS) {
    const raw = value[field];
    if (raw === null) {
      result[field] = null;
      continue;
    }
    const normalized = asString(raw);
    if (!isBase64UrlLike(normalized)) {
      return null;
    }
    result[field] = normalized;
  }

  return result;
}

function parseStructuredRunnerMeasurementEvidence(
  value: Record<string, unknown> | null,
): StructuredRunnerMeasurementEvidence | null {
  if (!value) {
    return null;
  }

  const manifestHash = asString(value.manifest_hash_b64u);
  if (
    asString(value.binding_version) !== '1' ||
    asString(value.hash_algorithm) !== 'SHA-256' ||
    !isBase64UrlLike(manifestHash)
  ) {
    return null;
  }

  const manifest = isRecord(value.manifest) ? value.manifest : null;
  const runtime = manifest && isRecord(manifest.runtime) ? manifest.runtime : null;
  const proofed = manifest && isRecord(manifest.proofed) ? manifest.proofed : null;
  const policy = manifest && isRecord(manifest.policy) ? manifest.policy : null;
  const artifacts = manifest && isRecord(manifest.artifacts) ? manifest.artifacts : null;
  const sentinels = proofed && isRecord(proofed.sentinels) ? proofed.sentinels : null;
  const policyHash = asString(policy?.effective_policy_hash_b64u);
  const parsedArtifacts = parseRunnerMeasurementArtifacts(artifacts);

  if (
    !manifest ||
    asString(manifest.manifest_version) !== '1' ||
    !runtime ||
    asString(runtime.platform) === null ||
    asString(runtime.arch) === null ||
    asString(runtime.node_version) === null ||
    !proofed ||
    proofed.proofed_mode !== true ||
    asString(proofed.clawproxy_url) === null ||
    !isCanonicalHostList(proofed.allowed_proxy_destinations) ||
    !isCanonicalHostList(proofed.allowed_child_destinations) ||
    !sentinels ||
    typeof sentinels.shell_enabled !== 'boolean' ||
    typeof sentinels.interpose_enabled !== 'boolean' ||
    typeof sentinels.preload_enabled !== 'boolean' ||
    typeof sentinels.fs_enabled !== 'boolean' ||
    typeof sentinels.net_enabled !== 'boolean' ||
    !isBase64UrlLike(policyHash) ||
    !parsedArtifacts
  ) {
    return null;
  }

  try {
    const clawproxyUrl = new URL(asString(proofed.clawproxy_url)!);
    if (clawproxyUrl.protocol !== 'http:' && clawproxyUrl.protocol !== 'https:') {
      return null;
    }
  } catch {
    return null;
  }

  if (
    sentinels.preload_enabled &&
    (!parsedArtifacts.preload_hash_b64u || !parsedArtifacts.node_preload_sentinel_hash_b64u)
  ) {
    return null;
  }
  if (
    sentinels.shell_enabled &&
    (!parsedArtifacts.sentinel_shell_hash_b64u || !parsedArtifacts.sentinel_shell_policy_hash_b64u)
  ) {
    return null;
  }
  if (sentinels.interpose_enabled && !parsedArtifacts.interpose_library_hash_b64u) {
    return null;
  }
  if (computeJsonSha256B64u(manifest) !== manifestHash) {
    return null;
  }

  return {
    manifest_hash_b64u: manifestHash!,
    policy_effective_policy_hash_b64u: policyHash!,
    runtime,
    artifacts: parsedArtifacts,
  };
}

function parseStructuredRunnerAttestationReceiptEvidence(
  envelope: Record<string, unknown> | null,
  expectedAgentDid: string | null,
): StructuredRunnerAttestationReceiptEvidence | null {
  if (!envelope || !isSignedEnvelopeLike(envelope, 'runner_attestation_receipt')) {
    return null;
  }

  const payload = isRecord(envelope.payload) ? envelope.payload : null;
  const binding = payload && isRecord(payload.binding) ? payload.binding : null;
  const policy = payload && isRecord(payload.policy) ? payload.policy : null;
  const runnerMeasurement = payload && isRecord(payload.runner_measurement)
    ? payload.runner_measurement
    : null;
  const artifacts = runnerMeasurement && isRecord(runnerMeasurement.artifacts)
    ? runnerMeasurement.artifacts
    : null;

  const runId = asString(binding?.run_id);
  const eventHash = asString(binding?.event_hash_b64u);
  const policyHash = asString(policy?.effective_policy_hash_b64u);
  const manifestHash = asString(runnerMeasurement?.manifest_hash_b64u);
  const runtimeHash = asString(runnerMeasurement?.runtime_hash_b64u);
  const agentDid = asString(payload?.agent_did);
  const signerDid = asString(envelope.signer_did);
  const parsedArtifacts = parseRunnerMeasurementArtifacts(artifacts);

  if (
    !payload ||
    asString(payload.receipt_version) !== '1' ||
    asString(payload.receipt_id) === null ||
    asString(payload.hash_algorithm) !== 'SHA-256' ||
    !isIsoTimestamp(asString(payload.timestamp)) ||
    !runId ||
    !isBase64UrlLike(eventHash) ||
    !isBase64UrlLike(policyHash) ||
    !isBase64UrlLike(manifestHash) ||
    !isBase64UrlLike(runtimeHash) ||
    !agentDid ||
    !signerDid ||
    agentDid !== signerDid ||
    (expectedAgentDid !== null && agentDid !== expectedAgentDid) ||
    computeJsonSha256B64u(payload) !== asString(envelope.payload_hash_b64u) ||
    !parsedArtifacts
  ) {
    return null;
  }

  return {
    payload_hash_b64u: asString(envelope.payload_hash_b64u)!,
    signer_did: signerDid,
    binding_run_id: runId,
    binding_event_hash_b64u: eventHash!,
    policy_effective_policy_hash_b64u: policyHash!,
    runner_measurement_manifest_hash_b64u: manifestHash!,
    runner_measurement_runtime_hash_b64u: runtimeHash!,
    artifacts: parsedArtifacts,
  };
}

function runnerMeasurementArtifactsMatch(
  left: RunnerMeasurementArtifacts,
  right: RunnerMeasurementArtifacts,
): boolean {
  for (const field of RUNNER_MEASUREMENT_ARTIFACT_FIELDS) {
    if (left[field] !== right[field]) {
      return false;
    }
  }
  return true;
}

function normalizeTierValue(value: string | null): string | null {
  return value ? value.trim().toLowerCase() : null;
}

const BACKGROUND_NETWORK_CLASSIFICATIONS = new Set([
  'infrastructure',
  'expected',
  'system_noise',
  'local',
  'fd_inheritance',
]);

function formatTopProcesses(processes: Array<{ process_name: string; count: number }>): string {
  if (processes.length === 0) return 'no dominant processes recorded';
  if (processes.length === 1) return `${processes[0]!.process_name} (${processes[0]!.count})`;
  if (processes.length === 2) {
    return `${processes[0]!.process_name} (${processes[0]!.count}) and ${processes[1]!.process_name} (${processes[1]!.count})`;
  }
  return `${processes[0]!.process_name} (${processes[0]!.count}), ${processes[1]!.process_name} (${processes[1]!.count}), and ${processes.length - 2} more`;
}

interface PrivacyExportPackManifestEntry {
  path: string;
  content_type: string;
  size_bytes: number;
  sha256_b64u: string;
}

interface PrivacyExportPackManifest {
  manifest_version: '1';
  pack_type: 'privacy_compliance_export_pack';
  generated_at: string;
  source: {
    bundle_path: string;
    verify_command: string;
    privacy_verdict: ProofPrivacyVerdict;
  };
  entries: PrivacyExportPackManifestEntry[];
}

const EXPORT_PACK_BUNDLE_PATH = 'proof-bundle/proof_bundle.json';
const EXPORT_PACK_REPORT_JSON_PATH = 'reports/proof-report.json';
const EXPORT_PACK_REPORT_TEXT_PATH = 'reports/proof-report.txt';
const EXPORT_PACK_REPORT_HTML_PATH = 'reports/proof-report.html';
const EXPORT_PACK_CLAIMS_BOUNDARY_PATH = 'reports/claims-boundary.md';
const EXPORT_PACK_COMPILED_REPORT_SUMMARY_PATH = 'reports/compiled-evidence-summary.md';
const EXPORT_PACK_RUN_COMPARISON_JSON_PATH = 'reports/run-comparison.json';
const EXPORT_PACK_RUN_COMPARISON_MARKDOWN_PATH = 'reports/run-comparison.md';
const EXPORT_PACK_COMPILED_REPORT_ENVELOPE_PATH = 'compiled-evidence/compiled-report-envelope.json';
const EXPORT_PACK_COMPILED_REPORT_JSON_PATH = 'compiled-evidence/compiled-report.json';
const EXPORT_PACK_COMPILED_REPORT_NARRATIVE_PATH = 'compiled-evidence/compiled-report-narrative.json';
const EXPORT_PACK_README_PATH = 'README.md';
const EXPORT_PACK_VIEWER_PATH = 'viewer/index.html';

function sha256B64u(bytes: Buffer): string {
  return crypto.createHash('sha256').update(bytes).digest('base64url');
}

function deriveStableExportPackTimestamp(report: ProofReport): string {
  return report.public_layer.issued_at ?? report.harness.timestamp ?? report.gateway.timestamp ?? 'unknown';
}

function buildExportPackReport(report: ProofReport): ProofReport {
  const generatedAt = deriveStableExportPackTimestamp(report);
  const verifyCommand = `clawverify verify proof-bundle --input ${EXPORT_PACK_BUNDLE_PATH}`;
  const packReport: ProofReport = {
    ...report,
    input_path: EXPORT_PACK_BUNDLE_PATH,
    run_summary_path: null,
    generated_at: generatedAt,
    verify_command: verifyCommand,
  };

  delete packReport.html_path;
  delete packReport.export_pack_path;
  packReport.next_steps = deriveNextSteps({
    gateway: packReport.gateway,
    warnings: packReport.warnings,
    verify_command: verifyCommand,
    privacy_posture: packReport.privacy_posture,
    reviewer_signoff: packReport.reviewer_signoff,
    compiled_evidence: packReport.compiled_evidence,
  });

  return packReport;
}

function renderPrivacyClaimsBoundaryMarkdown(report: ProofReport): string {
  const lines: string[] = [];
  lines.push('# Privacy/Compliance Claim Boundaries');
  lines.push('');
  lines.push(`Generated at: ${report.generated_at}`);
  lines.push(`Bundle ID: ${report.public_layer.bundle_id ?? 'unknown'}`);
  lines.push(`Agent DID: ${report.public_layer.agent_did ?? 'unknown'}`);
  lines.push(`Privacy verdict: ${report.privacy_posture.overall_verdict.toUpperCase()}`);
  lines.push(`Runner attestation posture: ${report.privacy_posture.runner_attestation.posture.toUpperCase()} (${report.privacy_posture.runner_attestation.reason_code})`);
  lines.push(`Reviewer signoff receipts: ${report.reviewer_signoff.receipt_count}`);
  lines.push(`Structured reviewer signoff receipts: ${report.reviewer_signoff.structured_receipt_count}`);
  lines.push(`Revoked reviewer signoff receipts: ${report.reviewer_signoff.revoked_receipt_count}`);
  lines.push(`Reviewer dispute state: ${report.reviewer_signoff.dispute_present ? 'present' : 'none'}`);
  lines.push(`Compiled report envelope present: ${report.compiled_evidence.envelope_present ? 'yes' : 'no'}`);
  if (report.compiled_evidence.envelope_present) {
    lines.push(`Compiled report authoritative: ${report.compiled_evidence.authoritative_report_present ? 'yes' : 'no'}`);
    lines.push(`Compiled report id: ${report.compiled_evidence.report_id ?? 'unknown'}`);
    lines.push(`Compiled matrix status: ${report.compiled_evidence.overall_status ?? 'unknown'}`);
    lines.push(`Compiled matrix hash: ${report.compiled_evidence.matrix_hash_b64u ?? 'unknown'}`);
    lines.push(`Compiled report envelope signer DID: ${report.compiled_evidence.signer_did ?? 'unknown'}`);
  }
  lines.push('');
  lines.push('## What This Pack Proves');
  if (report.privacy_posture.proven_claims.length === 0) {
    lines.push('- No privacy proof claims could be established from the available signed evidence.');
  } else {
    for (const claim of report.privacy_posture.proven_claims) {
      lines.push(`- ${claim}`);
    }
  }
  lines.push('');
  lines.push('## What This Pack Does Not Prove');
  for (const claim of report.privacy_posture.not_proven_claims) {
    lines.push(`- ${claim}`);
  }
  lines.push('');
  lines.push('## Reviewer Notes');
  lines.push(`- Run canonical verification first: \`${report.verify_command}\`.`);
  lines.push('- Treat `reports/proof-report.txt` and `reports/proof-report.json` as reviewer summaries derived from bundle evidence.');
  lines.push('- Use this claim-boundary section to avoid overstating privacy/compliance guarantees.');
  lines.push('');
  return lines.join('\n');
}

function renderCompiledEvidenceSummaryMarkdown(report: ProofReport): string {
  const compiled = report.compiled_evidence;
  const lines: string[] = [];
  lines.push('# Compiled Evidence Summary');
  lines.push('');
  lines.push('This summary surfaces authoritative compiled evidence artifacts (when present) without overriding proof-bundle verification semantics.');
  lines.push('');
  lines.push(`Generated at: ${report.generated_at}`);
  lines.push(`Bundle ID: ${report.public_layer.bundle_id ?? 'unknown'}`);
  lines.push(`Envelope source: ${compiled.metadata_path ?? 'not present in bundle metadata'}`);
  lines.push('');

  if (!compiled.envelope_present) {
    lines.push('No compiled evidence report envelope was found in the proof bundle metadata.');
    lines.push('');
    return lines.join('\n');
  }

  lines.push('## Authoritative compiled matrix');
  lines.push(`Report ID: ${compiled.report_id ?? 'unknown'}`);
  lines.push(`Compiler version: ${compiled.compiler_version ?? 'unknown'}`);
  lines.push(`Overall status: ${compiled.overall_status ?? 'unknown'}`);
  lines.push(`Matrix hash: ${compiled.matrix_hash_b64u ?? 'unknown'}`);
  lines.push(`Envelope payload hash: ${compiled.payload_hash_b64u ?? 'unknown'}`);
  lines.push(`Signer DID: ${compiled.signer_did ?? 'unknown'}`);
  lines.push(`Issued at: ${compiled.issued_at ?? 'unknown'}`);
  lines.push(`Structurally valid authoritative report: ${compiled.authoritative_report_present ? 'yes' : 'no'}`);
  lines.push('');

  lines.push('### Control outcome counts');
  lines.push(`- Total controls: ${compiled.control_outcome_counts.total}`);
  lines.push(`- PASS: ${compiled.control_outcome_counts.pass}`);
  lines.push(`- FAIL: ${compiled.control_outcome_counts.fail}`);
  lines.push(`- PARTIAL: ${compiled.control_outcome_counts.partial}`);
  lines.push(`- INAPPLICABLE: ${compiled.control_outcome_counts.inapplicable}`);
  lines.push(`- FAIL_CLOSED_INVALID_EVIDENCE: ${compiled.control_outcome_counts.fail_closed_invalid_evidence}`);
  lines.push('');

  lines.push('### Evidence refs');
  lines.push(`- proof_bundle_hash_b64u: ${compiled.evidence_refs.proof_bundle_hash_b64u ?? 'unknown'}`);
  lines.push(`- ontology_hash_b64u: ${compiled.evidence_refs.ontology_hash_b64u ?? 'unknown'}`);
  lines.push(`- mapping_rules_hash_b64u: ${compiled.evidence_refs.mapping_rules_hash_b64u ?? 'unknown'}`);
  lines.push(`- verify_result_hash_b64u: ${compiled.evidence_refs.verify_result_hash_b64u ?? 'unknown'}`);
  lines.push('');

  lines.push('### Non-pass controls');
  if (compiled.non_pass_controls.length === 0) {
    lines.push('- none');
  } else {
    for (const control of compiled.non_pass_controls) {
      lines.push(`- ${control}`);
    }
  }
  lines.push('');

  lines.push('### Narrative membrane');
  if (!compiled.narrative.present) {
    lines.push('- No narrative plane was embedded in the compiled report payload.');
  } else {
    lines.push(`- Narrative present: yes (authoritative=${compiled.narrative.authoritative_flag === null ? 'unknown' : compiled.narrative.authoritative_flag ? 'true' : 'false'})`);
    lines.push(`- Disclaimer: ${compiled.narrative.disclaimer ?? 'missing'}`);
    lines.push('- Narrative is non-authoritative explanatory text only; control outcomes remain authoritative in compiled control_results.');
  }
  lines.push('');

  lines.push('### Artifact linkage');
  lines.push(`- Envelope artifact: ${compiled.artifact_paths?.envelope ?? EXPORT_PACK_COMPILED_REPORT_ENVELOPE_PATH}`);
  if (compiled.artifact_paths?.report) {
    lines.push(`- Report payload artifact: ${compiled.artifact_paths.report}`);
  }
  if (compiled.artifact_paths?.narrative) {
    lines.push(`- Narrative artifact: ${compiled.artifact_paths.narrative}`);
  }
  lines.push(`- Canonical envelope verifier command: \`clawverify verify compiled-report --input ${compiled.artifact_paths?.envelope ?? EXPORT_PACK_COMPILED_REPORT_ENVELOPE_PATH}\`.`);
  lines.push('');

  if (compiled.invalid_reasons.length > 0) {
    lines.push('### Invalid/unsafe markers');
    for (const reason of compiled.invalid_reasons) {
      lines.push(`- ${reason}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function renderPrivacyExportPackReadme(report: ProofReport, hasComparison: boolean): string {
  const lines: string[] = [];
  const hasCompiledEnvelope = report.compiled_evidence.envelope_present;
  const compiledArtifacts = report.compiled_evidence.artifact_paths;

  lines.push('# Clawsig Privacy/Compliance Export Pack');
  lines.push('');
  lines.push('This pack is a reviewer-facing snapshot of proof artifacts and privacy evidence.');
  lines.push('It is meant for audit/security/compliance review workflows.');
  lines.push('');
  lines.push('## Contents');
  lines.push('- `proof-bundle/proof_bundle.json`: proof bundle included in this export pack.');
  lines.push('- `privacy-evidence/*.json`: privacy policy receipts/evidence extracted from bundle metadata when present.');
  lines.push('- Runner measurement / runner attestation evidence is copied into `privacy-evidence/` when present so reviewers can inspect the exact posture inputs.');
  lines.push('- Reviewer signoff/dispute receipt evidence is copied into `privacy-evidence/` when present.');
  if (hasCompiledEnvelope) {
    lines.push(`- \`${compiledArtifacts?.envelope ?? EXPORT_PACK_COMPILED_REPORT_ENVELOPE_PATH}\`: authoritative compiled report envelope copied from bundle metadata.`);
    if (compiledArtifacts?.report) {
      lines.push(`- \`${compiledArtifacts.report}\`: extracted authoritative compiled control-matrix payload.`);
    }
    if (compiledArtifacts?.narrative) {
      lines.push(`- \`${compiledArtifacts.narrative}\`: non-authoritative narrative plane from the compiled payload (if present, never authoritative).`);
    }
    lines.push(`- \`${compiledArtifacts?.summary ?? EXPORT_PACK_COMPILED_REPORT_SUMMARY_PATH}\`: reviewer summary linking compiled outcomes back to envelope/evidence refs.`);
  }
  lines.push('- `reports/proof-report.json`: machine-readable prove report (includes privacy + runner-attestation posture).');
  lines.push('- `reports/proof-report.txt`: human-readable prove report.');
  lines.push('- `reports/proof-report.html`: pre-rendered proof report HTML using the same prove/export posture language.');
  lines.push('- `reports/claims-boundary.md`: explicit what-is-proven / not-proven boundaries.');
  if (hasComparison) {
    lines.push('- `reports/run-comparison.json`: machine-readable side-by-side delta report against the baseline run.');
    lines.push('- `reports/run-comparison.md`: reviewer-oriented side-by-side delta summary.');
  }
  lines.push('- `viewer/index.html`: portable hosted/local reviewer surface with pack-local artifact navigation.');
  lines.push('- `manifest.json`: deterministic file manifest with SHA-256 digests.');
  lines.push('');
  lines.push('## How To Interpret');
  lines.push(`- Verify canonical proof-bundle cryptographic validity with \`${report.verify_command}\`.`);
  if (hasCompiledEnvelope) {
    lines.push(`- Verify compiled-report envelope validity with \`clawverify verify compiled-report --input ${compiledArtifacts?.envelope ?? EXPORT_PACK_COMPILED_REPORT_ENVELOPE_PATH}\`.`);
    lines.push('- Treat compiled control outcomes as authoritative; treat any narrative plane as non-authoritative explanatory text only.');
  }
  lines.push('- Open `viewer/index.html` for reviewer-facing navigation, then drill into raw files as needed.');
  lines.push('- Review claim limits in `reports/claims-boundary.md` before making privacy/compliance statements.');
  lines.push('- Use `manifest.json` to detect tampering when sharing this pack externally.');
  lines.push('');
  return lines.join('\n');
}

function normalizePackRelativePath(path: string): string | null {
  const normalized = path.replaceAll('\\', '/').trim();
  if (
    normalized.length === 0 ||
    normalized === '.' ||
    normalized === '..' ||
    normalized.startsWith('/') ||
    normalized.startsWith('../') ||
    normalized.includes('/../') ||
    /^[A-Za-z]:\//.test(normalized)
  ) {
    return null;
  }

  return normalized;
}

function requirePackRelativePath(path: string): string {
  const normalized = normalizePackRelativePath(path);
  if (!normalized) {
    throw new Error(`Export pack paths must stay pack-local and relative: ${path}`);
  }
  return normalized;
}

function toViewerHref(path: string): string | null {
  const normalized = normalizePackRelativePath(path);
  return normalized ? `../${normalized}` : null;
}

function renderExportPackViewerHtml(args: {
  report: ProofReport;
  artifactPaths: string[];
  comparison?: ProofRunComparison;
}): string {
  const { report } = args;
  const artifactLinks = dedupeStrings(args.artifactPaths)
    .map((path) => requirePackRelativePath(path))
    .sort((a, b) => a.localeCompare(b))
    .map((path) => {
      const href = toViewerHref(path);
      return `<li><a href="${escapeHtml(href!)}">${escapeHtml(path)}</a></li>`;
    })
    .join('');
  const runnerMeasurementEvidence = describeAttestationEvidenceState(
    report.privacy_posture.runner_attestation.evidence.runner_measurement_present,
    report.privacy_posture.runner_attestation.evidence.runner_measurement_structured,
  );
  const runnerAttestationReceiptEvidence = describeAttestationEvidenceState(
    report.privacy_posture.runner_attestation.evidence.runner_attestation_receipt_present,
    report.privacy_posture.runner_attestation.evidence.runner_attestation_receipt_structured,
  );
  const reviewerDecisionSummary = `approve=${report.reviewer_signoff.decision_counts.approve}, reject=${report.reviewer_signoff.decision_counts.reject}, needs_changes=${report.reviewer_signoff.decision_counts.needs_changes}`;
  const reviewerTargetSummary = `run=${report.reviewer_signoff.target_counts.run}, export_pack=${report.reviewer_signoff.target_counts.export_pack}`;
  const compiled = report.compiled_evidence;
  const compiledSummaryPath = compiled.artifact_paths?.summary ?? (compiled.envelope_present ? EXPORT_PACK_COMPILED_REPORT_SUMMARY_PATH : null);
  const compiledEnvelopePath = compiled.artifact_paths?.envelope ?? (compiled.envelope_present ? EXPORT_PACK_COMPILED_REPORT_ENVELOPE_PATH : null);
  const compiledReportPath = compiled.artifact_paths?.report ?? null;
  const compiledNarrativePath = compiled.artifact_paths?.narrative ?? null;
  const compiledSummaryHref = compiledSummaryPath ? toViewerHref(compiledSummaryPath) : null;
  const compiledEnvelopeHref = compiledEnvelopePath ? toViewerHref(compiledEnvelopePath) : null;
  const compiledReportHref = compiledReportPath ? toViewerHref(compiledReportPath) : null;
  const compiledNarrativeHref = compiledNarrativePath ? toViewerHref(compiledNarrativePath) : null;
  const compiledStatus = !compiled.envelope_present
    ? 'MISSING'
    : compiled.authoritative_report_present
      ? 'AUTHORITATIVE'
      : 'INVALID';
  const compiledNarrativeItems = !compiled.narrative.present
    ? ['No narrative plane embedded in compiled payload.']
    : [
      `Narrative present with authoritative=${compiled.narrative.authoritative_flag === null ? 'unknown' : compiled.narrative.authoritative_flag ? 'true' : 'false'}.`,
      `Disclaimer: ${compiled.narrative.disclaimer ?? 'missing'}`,
      'Narrative remains non-authoritative explanatory text only.',
    ];
  const compiledControlOutcomeItems = [
    `PASS: ${compiled.control_outcome_counts.pass}`,
    `FAIL: ${compiled.control_outcome_counts.fail}`,
    `PARTIAL: ${compiled.control_outcome_counts.partial}`,
    `INAPPLICABLE: ${compiled.control_outcome_counts.inapplicable}`,
    `FAIL_CLOSED_INVALID_EVIDENCE: ${compiled.control_outcome_counts.fail_closed_invalid_evidence}`,
  ];
  const compiledEvidenceRefItems = [
    `proof_bundle_hash_b64u: ${compiled.evidence_refs.proof_bundle_hash_b64u ?? 'unknown'}`,
    `ontology_hash_b64u: ${compiled.evidence_refs.ontology_hash_b64u ?? 'unknown'}`,
    `mapping_rules_hash_b64u: ${compiled.evidence_refs.mapping_rules_hash_b64u ?? 'unknown'}`,
    `verify_result_hash_b64u: ${compiled.evidence_refs.verify_result_hash_b64u ?? 'unknown'}`,
  ];
  const compiledPrimaryLinks = compiled.envelope_present
    ? `
          ${compiledSummaryPath && compiledSummaryHref ? `<li><a href="${escapeHtml(compiledSummaryHref)}">${escapeHtml(compiledSummaryPath)}</a></li>` : ''}
          ${compiledEnvelopePath && compiledEnvelopeHref ? `<li><a href="${escapeHtml(compiledEnvelopeHref)}">${escapeHtml(compiledEnvelopePath)}</a></li>` : ''}
          ${compiledReportPath && compiledReportHref ? `<li><a href="${escapeHtml(compiledReportHref)}">${escapeHtml(compiledReportPath)}</a></li>` : ''}
          ${compiledNarrativePath && compiledNarrativeHref ? `<li><a href="${escapeHtml(compiledNarrativeHref)}">${escapeHtml(compiledNarrativePath)}</a></li>` : ''}`
    : '';
  const compiledSection = compiled.envelope_present
    ? `
      <article class="card">
        <h2>Compiled evidence (authoritative matrix)</h2>
        <div class="rows">
          <div class="row"><span class="label">Compiled status</span><strong>${escapeHtml(compiledStatus)}</strong></div>
          <div class="row"><span class="label">Report ID</span><strong>${escapeHtml(compiled.report_id ?? 'unknown')}</strong></div>
          <div class="row"><span class="label">Compiler version</span><strong>${escapeHtml(compiled.compiler_version ?? 'unknown')}</strong></div>
          <div class="row"><span class="label">Overall status</span><strong>${escapeHtml(compiled.overall_status ?? 'unknown')}</strong></div>
          <div class="row"><span class="label">Matrix hash</span><strong>${escapeHtml(compiled.matrix_hash_b64u ?? 'unknown')}</strong></div>
          <div class="row"><span class="label">Signer DID</span><strong>${escapeHtml(compiled.signer_did ?? 'unknown')}</strong></div>
          <div class="row"><span class="label">Issued at</span><strong>${escapeHtml(compiled.issued_at ?? 'unknown')}</strong></div>
          <div class="row"><span class="label">Total controls</span><strong>${compiled.control_outcome_counts.total}</strong></div>
        </div>
        <div class="section">
          <h3>Control outcomes</h3>
          <ul>${renderList(compiledControlOutcomeItems)}</ul>
        </div>
        <div class="section">
          <h3>Evidence refs</h3>
          <ul>${renderList(compiledEvidenceRefItems)}</ul>
        </div>
        <div class="section">
          <h3>Non-pass controls</h3>
          <ul>${renderList(compiled.non_pass_controls)}</ul>
        </div>
        <div class="section">
          <h3>Narrative membrane</h3>
          <ul>${renderList(compiledNarrativeItems)}</ul>
        </div>
        ${compiled.invalid_reasons.length > 0 ? `<div class="section"><h3>Invalid/unsafe markers</h3><ul>${renderList(compiled.invalid_reasons)}</ul></div>` : ''}
      </article>`
    : `
      <article class="card">
        <h2>Compiled evidence (authoritative matrix)</h2>
        <p class="subtitle">No compiled report envelope was found in bundle metadata for this pack.</p>
      </article>`;
  const hasComparison = args.comparison !== undefined;
  const comparisonHighlights = args.comparison?.reviewer_highlights ?? [];
  const comparisonPrimaryLinks = hasComparison
    ? `
          <li><a href="../${EXPORT_PACK_RUN_COMPARISON_MARKDOWN_PATH}">${EXPORT_PACK_RUN_COMPARISON_MARKDOWN_PATH}</a></li>
          <li><a href="../${EXPORT_PACK_RUN_COMPARISON_JSON_PATH}">${EXPORT_PACK_RUN_COMPARISON_JSON_PATH}</a></li>`
    : '';
  const comparisonSection = hasComparison
    ? `
      <article class="card">
        <h2>Side-by-side run comparison</h2>
        <div class="rows">
          <div class="row"><span class="label">Baseline source type</span><strong>${escapeHtml(args.comparison!.baseline_source.type)}</strong></div>
          <div class="row"><span class="label">Baseline bundle ID</span><strong>${escapeHtml(args.comparison!.baseline.bundle_id ?? 'unknown')}</strong></div>
          <div class="row"><span class="label">Candidate bundle ID</span><strong>${escapeHtml(args.comparison!.candidate.bundle_id ?? 'unknown')}</strong></div>
        </div>
        <div class="section">
          <h3>Reviewer highlights</h3>
          <ul>${renderList(comparisonHighlights)}</ul>
        </div>
      </article>`
    : '';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clawsig export-pack viewer</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f7fb;
      --card: #ffffff;
      --line: #d9e2ef;
      --text: #12253f;
      --muted: #526780;
      --accent: #0b62d6;
      --good: #0c7a43;
      --caution: #9a6400;
      --action: #a81f36;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
    }
    main { max-width: 1040px; margin: 0 auto; padding: 28px 18px 64px; }
    h1, h2, h3, p { margin: 0; }
    .hero, .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 14px;
      box-shadow: 0 10px 30px rgba(17, 37, 62, 0.06);
    }
    .hero { padding: 24px; margin-bottom: 14px; }
    .subtitle { color: var(--muted); margin-top: 8px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }
    .card { padding: 18px; }
    .rows { margin-top: 10px; }
    .row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 6px 0;
      border-bottom: 1px solid #eef3f9;
    }
    .row:last-child { border-bottom: 0; }
    .label { color: var(--muted); }
    .pill {
      display: inline-block;
      margin-top: 10px;
      border-radius: 999px;
      padding: 5px 11px;
      border: 1px solid var(--line);
      font-size: 12px;
      font-weight: 600;
    }
    .pill.good { color: var(--good); border-color: #bce3cf; background: #eefaf3; }
    .pill.caution { color: var(--caution); border-color: #f0d8a6; background: #fff8eb; }
    .pill.action { color: var(--action); border-color: #f4bcc7; background: #fff0f3; }
    ul { margin: 10px 0 0 18px; padding: 0; }
    li + li { margin-top: 7px; }
    a { color: var(--accent); word-break: break-all; }
    .section { margin-top: 14px; }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Export-pack viewer</h1>
      <p class="subtitle">Portable reviewer surface for hosted or local inspection. This viewer reuses the same prove/export privacy posture and runner attestation posture outputs in this pack.</p>
      <p class="subtitle">Canonical verification command: <code>${escapeHtml(report.verify_command)}</code></p>
      <span class="pill ${escapeHtml(report.privacy_posture.overall_verdict)}">Privacy verdict: ${escapeHtml(report.privacy_posture.overall_verdict.toUpperCase())}</span>
      <span class="pill ${compiledStatus === 'AUTHORITATIVE' ? 'good' : compiledStatus === 'INVALID' ? 'action' : 'caution'}">Compiled matrix: ${escapeHtml(compiledStatus)}</span>
    </section>

    <section class="grid">
      <article class="card">
        <h2>Privacy posture</h2>
        <div class="rows">
          <div class="row"><span class="label">Overall verdict</span><strong>${escapeHtml(report.privacy_posture.overall_verdict.toUpperCase())}</strong></div>
          <div class="row"><span class="label">Reviewer action required</span><strong>${report.privacy_posture.reviewer_action_required ? 'yes' : 'no'}</strong></div>
          <div class="row"><span class="label">Runner attestation posture</span><strong>${escapeHtml(report.privacy_posture.runner_attestation.posture.toUpperCase())}</strong></div>
          <div class="row"><span class="label">Attested-tier reason code</span><strong>${escapeHtml(report.privacy_posture.runner_attestation.reason_code)}</strong></div>
          <div class="row"><span class="label">Runner measurement evidence</span><strong>${escapeHtml(runnerMeasurementEvidence)}</strong></div>
          <div class="row"><span class="label">Runner attestation receipt</span><strong>${escapeHtml(runnerAttestationReceiptEvidence)}</strong></div>
          <div class="row"><span class="label">Runner attestation bindings</span><strong>${report.privacy_posture.runner_attestation.evidence.binding_consistent ? 'consistent' : 'not established'}</strong></div>
          <div class="row"><span class="label">Reviewer signoff receipts</span><strong>${report.reviewer_signoff.receipt_count}</strong></div>
          <div class="row"><span class="label">Structured reviewer signoff</span><strong>${report.reviewer_signoff.structured_receipt_count}</strong></div>
          <div class="row"><span class="label">Revoked reviewer signoff</span><strong>${report.reviewer_signoff.revoked_receipt_count}</strong></div>
          <div class="row"><span class="label">Reviewer decisions</span><strong>${escapeHtml(reviewerDecisionSummary)}</strong></div>
          <div class="row"><span class="label">Bound targets</span><strong>${escapeHtml(reviewerTargetSummary)}</strong></div>
          <div class="row"><span class="label">Latest reviewer timestamp</span><strong>${escapeHtml(report.reviewer_signoff.latest_timestamp ?? 'unknown')}</strong></div>
          <div class="row"><span class="label">Dispute state</span><strong>${report.reviewer_signoff.dispute_present ? 'present' : 'none'}</strong></div>
        </div>
      </article>

      <article class="card">
        <h2>Primary reports</h2>
        <ul>
          <li><a href="../${EXPORT_PACK_REPORT_HTML_PATH}">${EXPORT_PACK_REPORT_HTML_PATH}</a></li>
          <li><a href="../${EXPORT_PACK_REPORT_TEXT_PATH}">${EXPORT_PACK_REPORT_TEXT_PATH}</a></li>
          <li><a href="../${EXPORT_PACK_REPORT_JSON_PATH}">${EXPORT_PACK_REPORT_JSON_PATH}</a></li>
          <li><a href="../${EXPORT_PACK_CLAIMS_BOUNDARY_PATH}">${EXPORT_PACK_CLAIMS_BOUNDARY_PATH}</a></li>
          ${compiledPrimaryLinks}
          ${comparisonPrimaryLinks}
          <li><a href="../manifest.json">manifest.json</a></li>
        </ul>
      </article>

      <article class="card">
        <h2>What is proven</h2>
        <ul>${renderList(report.privacy_posture.proven_claims)}</ul>
        <div class="section">
          <h3>What is not proven</h3>
          <ul>${renderList(report.privacy_posture.not_proven_claims)}</ul>
        </div>
      </article>

      ${compiledSection}
      ${comparisonSection}
    </section>

    <section class="card section">
      <h2>Pack-local artifacts</h2>
      <p class="subtitle">All links are relative to this pack so the viewer remains portable across local and hosted static environments.</p>
      <ul>${artifactLinks || '<li>No artifacts listed.</li>'}</ul>
    </section>
  </main>
</body>
</html>`;
}

function collectPrivacyEvidenceFiles(bundle: Record<string, unknown>): Array<{
  relative_path: string;
  payload: unknown;
}> {
  const payload = isRecord(bundle.payload) ? bundle.payload : null;
  const metadata = payload && isRecord(payload.metadata) ? payload.metadata : null;
  const sentinels = metadata && isRecord(metadata.sentinels) ? metadata.sentinels : null;
  const files: Array<{ relative_path: string; payload: unknown }> = [];

  if (sentinels && sentinels.egress_policy_receipt !== undefined) {
    files.push({
      relative_path: 'privacy-evidence/egress_policy_receipt.json',
      payload: sentinels.egress_policy_receipt,
    });
  }
  if (sentinels && sentinels.runtime_profile !== undefined) {
    files.push({
      relative_path: 'privacy-evidence/runtime_profile.json',
      payload: sentinels.runtime_profile,
    });
  }
  if (sentinels && sentinels.runtime_hygiene !== undefined) {
    files.push({
      relative_path: 'privacy-evidence/runtime_hygiene.json',
      payload: sentinels.runtime_hygiene,
    });
  }
  if (metadata && metadata.data_handling !== undefined) {
    files.push({
      relative_path: 'privacy-evidence/data_handling.json',
      payload: metadata.data_handling,
    });
  }
  if (metadata && metadata.processor_policy !== undefined) {
    files.push({
      relative_path: 'privacy-evidence/processor_policy.json',
      payload: metadata.processor_policy,
    });
  }
  if (metadata && metadata.runner_measurement !== undefined) {
    files.push({
      relative_path: 'privacy-evidence/runner_measurement.json',
      payload: metadata.runner_measurement,
    });
  }
  if (metadata && metadata.runner_attestation_receipt !== undefined) {
    files.push({
      relative_path: 'privacy-evidence/runner_attestation_receipt.json',
      payload: metadata.runner_attestation_receipt,
    });
  }
  if (metadata && metadata.reviewer_signoff_receipts !== undefined) {
    files.push({
      relative_path: 'privacy-evidence/reviewer_signoff_receipts.json',
      payload: metadata.reviewer_signoff_receipts,
    });
  }

  return files;
}

function collectCompiledEvidenceFiles(bundle: Record<string, unknown>): {
  summary: ProofCompiledEvidenceSummary;
  files: Array<{ relative_path: string; payload: unknown }>;
  artifact_paths?: ProofCompiledEvidenceArtifactPaths;
} {
  const payload = isRecord(bundle.payload) ? bundle.payload : {};
  const extraction = extractCompiledEvidence(payload);
  const files: Array<{ relative_path: string; payload: unknown }> = [];
  let artifactPaths: ProofCompiledEvidenceArtifactPaths | undefined;

  if (extraction.summary.envelope_present && extraction.envelope) {
    files.push({
      relative_path: EXPORT_PACK_COMPILED_REPORT_ENVELOPE_PATH,
      payload: extraction.envelope,
    });

    artifactPaths = {
      envelope: EXPORT_PACK_COMPILED_REPORT_ENVELOPE_PATH,
      summary: EXPORT_PACK_COMPILED_REPORT_SUMMARY_PATH,
    };

    if (extraction.summary.authoritative_report_present && extraction.report_payload) {
      files.push({
        relative_path: EXPORT_PACK_COMPILED_REPORT_JSON_PATH,
        payload: extraction.report_payload,
      });
      artifactPaths.report = EXPORT_PACK_COMPILED_REPORT_JSON_PATH;
    }

    if (extraction.summary.authoritative_report_present && extraction.narrative_payload) {
      files.push({
        relative_path: EXPORT_PACK_COMPILED_REPORT_NARRATIVE_PATH,
        payload: extraction.narrative_payload,
      });
      artifactPaths.narrative = EXPORT_PACK_COMPILED_REPORT_NARRATIVE_PATH;
    }
  }

  return {
    summary: extraction.summary,
    files,
    artifact_paths: artifactPaths,
  };
}

async function writeExportPackFile(
  packRoot: string,
  relativePath: string,
  bytes: Buffer,
  contentType: string,
  entries: PrivacyExportPackManifestEntry[],
): Promise<void> {
  const normalizedPath = requirePackRelativePath(relativePath);
  const fullPath = resolve(packRoot, normalizedPath);
  await mkdir(dirname(fullPath), { recursive: true });
  await writeFile(fullPath, bytes);
  entries.push({
    path: normalizedPath,
    content_type: contentType,
    size_bytes: bytes.length,
    sha256_b64u: sha256B64u(bytes),
  });
}

async function writePrivacyComplianceExportPack(args: {
  packPath: string;
  bundle: Record<string, unknown>;
  report: ProofReport;
  comparison?: ProofRunComparison;
}): Promise<string> {
  const packRoot = resolve(args.packPath);
  await mkdir(packRoot, { recursive: true });
  const existingEntries = await readdir(packRoot);
  if (existingEntries.length > 0) {
    throw new Error(
      `Export pack directory must be empty to avoid stale artifacts: ${packRoot}`,
    );
  }

  const packReport = buildExportPackReport(args.report);
  const entries: PrivacyExportPackManifestEntry[] = [];

  const bundleBytes = Buffer.from(JSON.stringify(args.bundle, null, 2) + '\n', 'utf-8');
  await writeExportPackFile(
    packRoot,
    EXPORT_PACK_BUNDLE_PATH,
    bundleBytes,
    'application/json',
    entries,
  );

  const privacyEvidenceFiles = collectPrivacyEvidenceFiles(args.bundle);
  for (const file of privacyEvidenceFiles) {
    const bytes = Buffer.from(JSON.stringify(file.payload, null, 2) + '\n', 'utf-8');
    await writeExportPackFile(
      packRoot,
      file.relative_path,
      bytes,
      'application/json',
      entries,
    );
  }

  const compiledEvidenceFiles = collectCompiledEvidenceFiles(args.bundle);
  packReport.compiled_evidence = {
    ...compiledEvidenceFiles.summary,
    artifact_paths: compiledEvidenceFiles.artifact_paths,
  };
  if (!compiledEvidenceFiles.artifact_paths) {
    delete packReport.compiled_evidence.artifact_paths;
  }

  for (const file of compiledEvidenceFiles.files) {
    const bytes = Buffer.from(JSON.stringify(file.payload, null, 2) + '\n', 'utf-8');
    await writeExportPackFile(
      packRoot,
      file.relative_path,
      bytes,
      'application/json',
      entries,
    );
  }

  if (packReport.compiled_evidence.artifact_paths?.summary) {
    const compiledSummaryBytes = Buffer.from(
      renderCompiledEvidenceSummaryMarkdown(packReport),
      'utf-8',
    );
    await writeExportPackFile(
      packRoot,
      packReport.compiled_evidence.artifact_paths.summary,
      compiledSummaryBytes,
      'text/markdown; charset=utf-8',
      entries,
    );
  }

  packReport.next_steps = deriveNextSteps({
    gateway: packReport.gateway,
    warnings: packReport.warnings,
    verify_command: packReport.verify_command,
    privacy_posture: packReport.privacy_posture,
    reviewer_signoff: packReport.reviewer_signoff,
    compiled_evidence: packReport.compiled_evidence,
  });

  const reportJsonBytes = Buffer.from(JSON.stringify(packReport, null, 2) + '\n', 'utf-8');
  const reportTextBytes = Buffer.from(renderProofReportText(packReport), 'utf-8');
  const reportHtmlBytes = Buffer.from(renderProofReportHtml(packReport), 'utf-8');
  const claimsBoundaryBytes = Buffer.from(renderPrivacyClaimsBoundaryMarkdown(packReport), 'utf-8');
  const readmeBytes = Buffer.from(renderPrivacyExportPackReadme(packReport, args.comparison !== undefined), 'utf-8');

  await writeExportPackFile(
    packRoot,
    EXPORT_PACK_REPORT_JSON_PATH,
    reportJsonBytes,
    'application/json',
    entries,
  );
  await writeExportPackFile(
    packRoot,
    EXPORT_PACK_REPORT_TEXT_PATH,
    reportTextBytes,
    'text/plain; charset=utf-8',
    entries,
  );
  await writeExportPackFile(
    packRoot,
    EXPORT_PACK_REPORT_HTML_PATH,
    reportHtmlBytes,
    'text/html; charset=utf-8',
    entries,
  );
  await writeExportPackFile(
    packRoot,
    EXPORT_PACK_CLAIMS_BOUNDARY_PATH,
    claimsBoundaryBytes,
    'text/markdown; charset=utf-8',
    entries,
  );
  await writeExportPackFile(
    packRoot,
    EXPORT_PACK_README_PATH,
    readmeBytes,
    'text/markdown; charset=utf-8',
    entries,
  );

  if (args.comparison) {
    const comparisonJsonBytes = Buffer.from(JSON.stringify(args.comparison, null, 2) + '\n', 'utf-8');
    const comparisonMarkdownBytes = Buffer.from(
      renderProofRunComparisonMarkdown(args.comparison),
      'utf-8',
    );
    await writeExportPackFile(
      packRoot,
      EXPORT_PACK_RUN_COMPARISON_JSON_PATH,
      comparisonJsonBytes,
      'application/json',
      entries,
    );
    await writeExportPackFile(
      packRoot,
      EXPORT_PACK_RUN_COMPARISON_MARKDOWN_PATH,
      comparisonMarkdownBytes,
      'text/markdown; charset=utf-8',
      entries,
    );
  }

  const viewerBytes = Buffer.from(
    renderExportPackViewerHtml({
      report: packReport,
      artifactPaths: [...entries.map((entry) => entry.path), EXPORT_PACK_VIEWER_PATH, 'manifest.json'],
      comparison: args.comparison,
    }),
    'utf-8',
  );
  await writeExportPackFile(
    packRoot,
    EXPORT_PACK_VIEWER_PATH,
    viewerBytes,
    'text/html; charset=utf-8',
    entries,
  );

  const sortedEntries = [...entries].sort((a, b) => a.path.localeCompare(b.path));
  const manifest: PrivacyExportPackManifest = {
    manifest_version: '1',
    pack_type: 'privacy_compliance_export_pack',
    generated_at: packReport.generated_at,
    source: {
      bundle_path: packReport.input_path,
      verify_command: packReport.verify_command,
      privacy_verdict: packReport.privacy_posture.overall_verdict,
    },
    entries: sortedEntries,
  };

  const manifestPath = resolve(packRoot, 'manifest.json');
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf-8');
  return packRoot;
}

async function readJsonObject(path: string): Promise<Record<string, unknown>> {
  const raw = await readFile(path, 'utf-8');
  const parsed = JSON.parse(raw);
  if (!isRecord(parsed)) {
    throw new Error(`Expected JSON object in ${path}`);
  }
  return parsed;
}

async function maybeReadJsonObject(path: string): Promise<Record<string, unknown> | null> {
  try {
    await access(path);
  } catch {
    return null;
  }

  return readJsonObject(path);
}

function inferRunSummaryPath(inputPath: string): string {
  return resolve(dirname(inputPath), 'run_summary.json');
}

function summarizeGateway(payload: Record<string, unknown>): ProofGatewaySummary {
  const receipts = asArray(payload.receipts);
  const signed = receipts.filter((entry) => {
    if (!isRecord(entry)) return false;
    const inner = isRecord(entry.payload) ? entry.payload : null;
    return (
      entry.envelope_type === 'gateway_receipt' &&
      typeof entry.envelope_version === 'string' &&
      typeof entry.signer_did === 'string' &&
      !!inner &&
      typeof inner.provider === 'string'
    );
  }) as Array<Record<string, unknown>>;

  const first = signed[0];
  const firstPayload = first && isRecord(first.payload) ? first.payload : null;

  return {
    signed_count: signed.length,
    signer_dids: [...new Set(signed.map((entry) => asString(entry.signer_did)).filter(Boolean) as string[])],
    provider: asString(firstPayload?.provider),
    model: asString(firstPayload?.model),
    gateway_id: asString(firstPayload?.gateway_id),
    latency_ms: asNumber(firstPayload?.latency_ms),
    timestamp: asString(firstPayload?.timestamp),
  };
}

function summarizeNetwork(payload: Record<string, unknown>): ProofReport['network'] {
  const receipts = asArray(payload.network_receipts);
  const classificationCounts: Record<string, number> = {};
  const processCounts = new Map<string, number>();

  for (const entry of receipts) {
    if (!isRecord(entry)) continue;
    const classification = asString(entry.classification) ?? 'unknown';
    classificationCounts[classification] = (classificationCounts[classification] ?? 0) + 1;

    const processName = asString(entry.process_name) ?? 'unknown';
    processCounts.set(processName, (processCounts.get(processName) ?? 0) + 1);
  }

  const topProcesses = [...processCounts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([process_name, count]) => ({ process_name, count }));

  return {
    classification_counts: classificationCounts,
    top_processes: topProcesses,
  };
}

function summarizeSentinels(payload: Record<string, unknown>): ProofReport['sentinels'] {
  const metadata = isRecord(payload.metadata) ? payload.metadata : null;
  const sentinels = metadata && isRecord(metadata.sentinels) ? metadata.sentinels : null;
  const interposeState = sentinels && isRecord(sentinels.interpose_state) ? sentinels.interpose_state : null;
  const cldd = interposeState && isRecord(interposeState.cldd) ? interposeState.cldd : null;
  const runtimeProfile = sentinels && isRecord(sentinels.runtime_profile) ? sentinels.runtime_profile : null;
  const runtimeHygiene = sentinels && isRecord(sentinels.runtime_hygiene) ? sentinels.runtime_hygiene : null;
  const profileActivation = runtimeProfile && isRecord(runtimeProfile.activation) ? runtimeProfile.activation : null;
  const profileBaseline = runtimeProfile && isRecord(runtimeProfile.baseline) ? runtimeProfile.baseline : null;
  const hygieneBuckets = runtimeHygiene && isRecord(runtimeHygiene.buckets) ? runtimeHygiene.buckets : null;
  const hygieneVerdict = asString(runtimeHygiene?.verdict);
  const resolvedVerdict = hygieneVerdict === 'good' || hygieneVerdict === 'caution' || hygieneVerdict === 'action'
    ? hygieneVerdict
    : null;

  return {
    shell_events: asNumber(sentinels?.shell_events) ?? 0,
    fs_events: asNumber(sentinels?.fs_events) ?? 0,
    net_events: asNumber(sentinels?.net_events) ?? 0,
    net_suspicious: asNumber(sentinels?.net_suspicious) ?? 0,
    preload_llm_events: asNumber(sentinels?.preload_llm_events) ?? 0,
    interpose_active: Boolean(sentinels?.interpose_active),
    unmediated_connections: asNumber(cldd?.unmediated_connections) ?? 0,
    unmonitored_spawns: asNumber(cldd?.unmonitored_spawns) ?? 0,
    escapes_suspected: Boolean(cldd?.escapes_suspected),
    runtime_profile: {
      profile_id: asString(runtimeProfile?.profile_id),
      profile_version: asString(runtimeProfile?.profile_version),
      mode: asString(runtimeProfile?.mode),
      status: asString(profileActivation?.status),
      fallback_reasons: asStringArray(profileActivation?.reasons),
      baseline_process_count: asNumber(profileBaseline?.process_count),
      baseline_process_hash_b64u: asString(profileBaseline?.process_hash_b64u),
    },
    runtime_hygiene: {
      verdict: resolvedVerdict,
      reviewer_action_required: Boolean(runtimeHygiene?.reviewer_action_required),
      background_signals: asStringArray(hygieneBuckets?.background_noise),
      caution_signals: asStringArray(hygieneBuckets?.caution),
      action_required_signals: asStringArray(hygieneBuckets?.action_required),
    },
  };
}

function isReviewerSignoffDecision(value: unknown): value is ProofReviewerSignoffDecision {
  return value === 'approve' || value === 'reject' || value === 'needs_changes';
}

function isReviewerSignoffTargetKind(value: unknown): value is ProofReviewerSignoffTargetKind {
  return value === 'run' || value === 'export_pack';
}

function summarizeReviewerSignoff(payload: Record<string, unknown>): ProofReviewerSignoffState {
  const metadata = isRecord(payload.metadata) ? payload.metadata : null;
  const receiptsRaw = metadata?.reviewer_signoff_receipts;
  const receipts = Array.isArray(receiptsRaw)
    ? receiptsRaw.filter((entry): entry is Record<string, unknown> => isRecord(entry))
    : [];
  const decisionCounts: ProofReviewerSignoffState['decision_counts'] = {
    approve: 0,
    reject: 0,
    needs_changes: 0,
  };
  const targetCounts: ProofReviewerSignoffState['target_counts'] = {
    run: 0,
    export_pack: 0,
  };
  const reviewerDids = new Set<string>();
  const bundleId = asString(payload.bundle_id);
  const eventChain = asArray(payload.event_chain).filter((entry): entry is Record<string, unknown> => isRecord(entry));
  const expectedRunId = asString(eventChain[0]?.run_id);
  const allowedEventHashes = new Set(
    eventChain
      .map((entry) => asString(entry.event_hash_b64u))
      .filter((entry): entry is string => entry !== null),
  );

  let structuredCount = 0;
  let revokedReceiptCount = 0;
  const revokedReviewerDids = new Set<string>();
  let latestTimestamp: string | null = null;
  let latestTimestampMs = Number.NEGATIVE_INFINITY;
  let disputePresent = false;
  let disputeNoteCount = 0;
  let disputeEvidenceRefCount = 0;

  receiptLoop:
  for (const envelope of receipts) {
    const signerDid = asString(envelope.signer_did);
    const payloadHashB64u = asString(envelope.payload_hash_b64u);
    const signatureB64u = asString(envelope.signature_b64u);
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
      ]) ||
      asString(envelope.envelope_version) !== '1' ||
      asString(envelope.envelope_type) !== 'reviewer_signoff_receipt' ||
      asString(envelope.hash_algorithm) !== 'SHA-256' ||
      asString(envelope.algorithm) !== 'Ed25519' ||
      signerDid === null ||
      payloadHashB64u === null ||
      signatureB64u === null ||
      !signerDid.startsWith('did:') ||
      !isBase64UrlLike(payloadHashB64u) ||
      !isBase64UrlLike(signatureB64u) ||
      !isIsoTimestamp(asString(envelope.issued_at)) ||
      !isRecord(envelope.payload)
    ) {
      continue;
    }

    const receiptPayload = envelope.payload;
    const binding = isRecord(receiptPayload.binding) ? receiptPayload.binding : null;
    const reviewerDid = asString(receiptPayload.reviewer_did);
    const timestamp = asString(receiptPayload.timestamp);
    const eventHash = asString(binding?.event_hash_b64u);
    if (
      !hasOnlyAllowedKeys(receiptPayload, [
        'receipt_version',
        'receipt_id',
        'reviewer_did',
        'decision',
        'timestamp',
        'binding',
        'dispute',
        'revoked_reviewer_keys',
      ]) ||
      bundleId === null ||
      expectedRunId === null ||
      allowedEventHashes.size === 0 ||
      computeJsonSha256B64u(receiptPayload) !== asString(envelope.payload_hash_b64u) ||
      asString(receiptPayload.receipt_version) !== '1' ||
      asString(receiptPayload.receipt_id) === null ||
      reviewerDid === null ||
      reviewerDid !== signerDid ||
      !isReviewerSignoffDecision(receiptPayload.decision) ||
      !isIsoTimestamp(timestamp) ||
      !binding ||
      !hasOnlyAllowedKeys(binding, [
        'run_id',
        'bundle_id',
        'proof_bundle_hash_b64u',
        'event_hash_b64u',
        'target_kind',
        'export_pack_root_hash_b64u',
      ]) ||
      asString(binding.run_id) !== expectedRunId ||
      asString(binding.bundle_id) !== bundleId ||
      (binding.proof_bundle_hash_b64u !== undefined &&
        !isBase64UrlLike(asString(binding.proof_bundle_hash_b64u))) ||
      !isBase64UrlLike(eventHash) ||
      !allowedEventHashes.has(eventHash!) ||
      !isReviewerSignoffTargetKind(binding.target_kind)
    ) {
      continue;
    }
    if (binding.target_kind === 'export_pack') {
      if (!isBase64UrlLike(asString(binding.export_pack_root_hash_b64u))) {
        continue;
      }
    } else if (binding.export_pack_root_hash_b64u !== undefined) {
      continue;
    }
    if (
      !verifyEd25519DidKeySignature({
        signerDid,
        signatureB64u,
        message: payloadHashB64u,
      })
    ) {
      continue;
    }

    const reviewerRevocations = parseTrustRootRevocationEvidence(
      receiptPayload.revoked_reviewer_keys,
    );
    if (reviewerRevocations === null) {
      continue;
    }
    if (findMatchingTrustRootRevocation(reviewerRevocations, signerDid)) {
      revokedReceiptCount += 1;
      revokedReviewerDids.add(signerDid);
      continue;
    }

    let receiptDisputePresent = false;
    let receiptDisputeNoteCount = 0;
    let receiptDisputeEvidenceRefCount = 0;

    if (receiptPayload.dispute !== undefined) {
      const dispute = isRecord(receiptPayload.dispute) ? receiptPayload.dispute : null;
      if (!dispute || !hasOnlyAllowedKeys(dispute, ['status', 'notes'])) {
        continue;
      }
      const status = asString(dispute.status);
      if (status !== 'none' && status !== 'raised' && status !== 'resolved') {
        continue;
      }
      const notesRaw = dispute.notes;
      if (notesRaw !== undefined && !Array.isArray(notesRaw)) {
        continue;
      }
      const notes = Array.isArray(notesRaw) ? notesRaw : [];
      if (status !== 'none' && notes.length === 0) {
        continue;
      }
      if (status === 'none' && notes.length > 0) {
        continue;
      }
      for (const note of notes) {
        if (
          !isRecord(note) ||
          !hasOnlyAllowedKeys(note, ['note_id', 'note', 'evidence_refs']) ||
          asString(note.note_id) === null ||
          asString(note.note) === null
        ) {
          continue receiptLoop;
        }
        const evidenceRefsRaw = note.evidence_refs;
        if (evidenceRefsRaw !== undefined && !Array.isArray(evidenceRefsRaw)) {
          continue receiptLoop;
        }
        receiptDisputeNoteCount += 1;
        for (const ref of evidenceRefsRaw ?? []) {
          const uri = isRecord(ref) ? asString(ref.uri) : null;
          const sha256 = isRecord(ref) ? asString(ref.sha256_b64u) : null;
          if (
            !isRecord(ref) ||
            !hasOnlyAllowedKeys(ref, ['ref_id', 'uri', 'sha256_b64u']) ||
            (ref.ref_id !== undefined && asString(ref.ref_id) === null) ||
            (ref.uri !== undefined && uri === null) ||
            (ref.sha256_b64u !== undefined && !isBase64UrlLike(sha256)) ||
            (uri === null && !isBase64UrlLike(sha256))
          ) {
            continue receiptLoop;
          }
          receiptDisputeEvidenceRefCount += 1;
        }
      }
      if (status === 'raised' || status === 'resolved') {
        receiptDisputePresent = true;
      }
    }

    structuredCount += 1;
    decisionCounts[receiptPayload.decision] += 1;
    targetCounts[binding.target_kind] += 1;
    reviewerDids.add(reviewerDid);

    if (timestamp) {
      const timestampMs = Date.parse(timestamp);
      if (Number.isFinite(timestampMs) && timestampMs >= latestTimestampMs) {
        latestTimestampMs = timestampMs;
        latestTimestamp = timestamp;
      }
    }
    disputePresent ||= receiptDisputePresent;
    disputeNoteCount += receiptDisputeNoteCount;
    disputeEvidenceRefCount += receiptDisputeEvidenceRefCount;
  }

  return {
    present: receiptsRaw !== undefined,
    receipt_count: Array.isArray(receiptsRaw) ? receiptsRaw.length : 0,
    structured_receipt_count: structuredCount,
    revoked_receipt_count: revokedReceiptCount,
    revoked_reviewer_dids: [...revokedReviewerDids].sort((a, b) => a.localeCompare(b)),
    reviewer_dids: [...reviewerDids].sort((a, b) => a.localeCompare(b)),
    decision_counts: decisionCounts,
    target_counts: targetCounts,
    latest_timestamp: latestTimestamp,
    dispute_present: disputePresent,
    dispute_note_count: disputeNoteCount,
    dispute_evidence_refs_count: disputeEvidenceRefCount,
  };
}

const DATA_HANDLING_ACTION_ORDER: DataHandlingAction[] = ['allow', 'redact', 'block', 'require_approval'];

function buildComparisonDeltaRow(
  label: string,
  baseline: ProofRunComparisonValue,
  candidate: ProofRunComparisonValue,
): ProofRunComparisonDeltaRow {
  return {
    label,
    baseline,
    candidate,
    changed: baseline !== candidate,
  };
}

function hasChangedDeltaRows(rows: ProofRunComparisonDeltaRow[]): boolean {
  return rows.some((row) => row.changed);
}

function countChangedDeltaRows(rows: ProofRunComparisonDeltaRow[]): number {
  return rows.filter((row) => row.changed).length;
}

function normalizeComparisonSet(values: string[]): string[] {
  return dedupeStrings(values).sort((a, b) => a.localeCompare(b));
}

function diffComparisonStringSets(baseline: string[], candidate: string[]): ProofRunComparisonStringSetDelta {
  const baselineSet = new Set(normalizeComparisonSet(baseline));
  const candidateSet = new Set(normalizeComparisonSet(candidate));
  const added = [...candidateSet].filter((entry) => !baselineSet.has(entry)).sort((a, b) => a.localeCompare(b));
  const removed = [...baselineSet].filter((entry) => !candidateSet.has(entry)).sort((a, b) => a.localeCompare(b));
  return { added, removed };
}

function hasStringSetDelta(delta: ProofRunComparisonStringSetDelta): boolean {
  return delta.added.length > 0 || delta.removed.length > 0;
}

function countStringSetDeltaEntries(delta: ProofRunComparisonStringSetDelta): number {
  return delta.added.length + delta.removed.length;
}

function formatProcessorRouteKey(route: Omit<ProofPrivacyProcessorRoute, 'count'>): string {
  return `${route.provider} / ${route.model} (${route.region}, ${route.retention_profile})`;
}

function formatProcessorBlockedAttemptKey(attempt: ProofPrivacyProcessorBlockedAttempt): string {
  const route = formatProcessorRouteKey(attempt.route);
  return `${route} — ${attempt.reason_code}${attempt.timestamp ? ` @ ${attempt.timestamp}` : ''}`;
}

function mapProcessorRouteCounts(routes: ProofPrivacyProcessorRoute[]): Map<string, number> {
  const routeCounts = new Map<string, number>();
  for (const route of routes) {
    const key = formatProcessorRouteKey(route);
    routeCounts.set(key, (routeCounts.get(key) ?? 0) + route.count);
  }
  return routeCounts;
}

function actionCountForPosture(
  posture: ProofPrivacyPosture,
  action: DataHandlingAction,
): number {
  return posture.data_handling.actions.find((entry) => entry.action === action)?.count ?? 0;
}

function buildRunComparisonSnapshot(report: ProofReport): ProofRunComparisonSnapshot {
  return {
    bundle_id: report.public_layer.bundle_id,
    harness_status: report.harness.status,
    tier: report.harness.tier,
    trust_tier: report.harness.trust_tier,
    privacy_verdict: report.privacy_posture.overall_verdict,
    reviewer_action_required: report.privacy_posture.reviewer_action_required,
    runner_attestation_posture: report.privacy_posture.runner_attestation.posture,
    runner_attestation_reason_code: report.privacy_posture.runner_attestation.reason_code,
  };
}

function buildRunComparisonReviewerHighlights(args: {
  baseline: ProofReport;
  candidate: ProofReport;
  deltas: ProofRunComparison['deltas'];
}): string[] {
  const { baseline, candidate, deltas } = args;
  const highlights: string[] = [];
  let assuranceHighlights = 0;
  let evidenceHighlights = 0;
  let processorHighlights = 0;
  let privacyHighlights = 0;

  if (baseline.harness.tier !== candidate.harness.tier || baseline.harness.trust_tier !== candidate.harness.trust_tier) {
    highlights.push(
      `Assurance tier changed: tier ${baseline.harness.tier ?? 'unknown'} -> ${candidate.harness.tier ?? 'unknown'}, trust ${baseline.harness.trust_tier ?? 'unknown'} -> ${candidate.harness.trust_tier ?? 'unknown'}.`,
    );
    assuranceHighlights += 1;
  }

  if (baseline.privacy_posture.overall_verdict !== candidate.privacy_posture.overall_verdict) {
    highlights.push(
      `Privacy verdict changed: ${baseline.privacy_posture.overall_verdict.toUpperCase()} -> ${candidate.privacy_posture.overall_verdict.toUpperCase()}.`,
    );
    privacyHighlights += 1;
  }

  if (baseline.reviewer_signoff.receipt_count !== candidate.reviewer_signoff.receipt_count) {
    highlights.push(
      `Reviewer signoff receipt count changed: ${baseline.reviewer_signoff.receipt_count} -> ${candidate.reviewer_signoff.receipt_count}.`,
    );
    privacyHighlights += 1;
  }

  if (baseline.reviewer_signoff.dispute_present !== candidate.reviewer_signoff.dispute_present) {
    highlights.push(
      `Reviewer dispute state changed: ${baseline.reviewer_signoff.dispute_present ? 'present' : 'none'} -> ${candidate.reviewer_signoff.dispute_present ? 'present' : 'none'}.`,
    );
    privacyHighlights += 1;
  }

  const blockedAttemptDelta =
    (candidate.privacy_posture.egress.blocked_attempt_count ?? 0) -
    (baseline.privacy_posture.egress.blocked_attempt_count ?? 0);
  if (blockedAttemptDelta !== 0) {
    highlights.push(
      `Blocked egress attempts changed by ${blockedAttemptDelta > 0 ? '+' : ''}${blockedAttemptDelta} (baseline=${baseline.privacy_posture.egress.blocked_attempt_count ?? 0}, candidate=${candidate.privacy_posture.egress.blocked_attempt_count ?? 0}).`,
    );
    evidenceHighlights += 1;
  }

  const approvalUnsatisfiedDelta =
    candidate.privacy_posture.data_handling.approval_unsatisfied_count -
    baseline.privacy_posture.data_handling.approval_unsatisfied_count;
  if (approvalUnsatisfiedDelta !== 0) {
    highlights.push(
      `Unsatisfied approvals changed by ${approvalUnsatisfiedDelta > 0 ? '+' : ''}${approvalUnsatisfiedDelta} (baseline=${baseline.privacy_posture.data_handling.approval_unsatisfied_count}, candidate=${candidate.privacy_posture.data_handling.approval_unsatisfied_count}).`,
    );
    privacyHighlights += 1;
  }

  const redactionDelta =
    candidate.privacy_posture.data_handling.redaction_applied_count -
    baseline.privacy_posture.data_handling.redaction_applied_count;
  if (redactionDelta !== 0) {
    highlights.push(
      `Redaction-applied receipts changed by ${redactionDelta > 0 ? '+' : ''}${redactionDelta} (baseline=${baseline.privacy_posture.data_handling.redaction_applied_count}, candidate=${candidate.privacy_posture.data_handling.redaction_applied_count}).`,
    );
    privacyHighlights += 1;
  }

  if (deltas.processor.used_processor_routes.added.length > 0 || deltas.processor.used_processor_routes.removed.length > 0) {
    highlights.push(
      `Processor route set changed: +${deltas.processor.used_processor_routes.added.length} / -${deltas.processor.used_processor_routes.removed.length}.`,
    );
    processorHighlights += 1;
  }

  if (deltas.processor.blocked_attempts.added.length > 0 || deltas.processor.blocked_attempts.removed.length > 0) {
    highlights.push(
      `Blocked processor attempt set changed: +${deltas.processor.blocked_attempts.added.length} / -${deltas.processor.blocked_attempts.removed.length}.`,
    );
    processorHighlights += 1;
  }

  const changedAssuranceRowCount = countChangedDeltaRows(deltas.assurance.rows);
  if (changedAssuranceRowCount > 0 && assuranceHighlights === 0) {
    highlights.push(
      `Assurance delta summary: ${changedAssuranceRowCount} assurance ${pluralize(changedAssuranceRowCount, 'field')} changed.`,
    );
  }

  const changedEvidenceRowCount = countChangedDeltaRows(deltas.evidence.rows);
  if (changedEvidenceRowCount > 0 && evidenceHighlights === 0) {
    highlights.push(
      `Evidence delta summary: ${changedEvidenceRowCount} evidence ${pluralize(changedEvidenceRowCount, 'field')} changed.`,
    );
  }

  const changedPolicyRowCount = countChangedDeltaRows(deltas.policy.rows);
  if (changedPolicyRowCount > 0) {
    highlights.push(
      `Policy delta summary: ${changedPolicyRowCount} policy ${pluralize(changedPolicyRowCount, 'field')} changed.`,
    );
  }

  if (deltas.processor.used_processor_count_deltas.length > 0 && processorHighlights === 0) {
    const changedRouteCount = deltas.processor.used_processor_count_deltas.length;
    highlights.push(
      `Processor invocation counts changed across ${changedRouteCount} ${pluralize(changedRouteCount, 'route')}.`,
    );
  }

  const changedPrivacyDeltaCount =
    countChangedDeltaRows(deltas.privacy.rows) +
    countChangedDeltaRows(deltas.privacy.data_handling_action_rows) +
    countStringSetDeltaEntries(deltas.privacy.sensitive_class_deltas) +
    countStringSetDeltaEntries(deltas.privacy.signal_deltas.background_noise) +
    countStringSetDeltaEntries(deltas.privacy.signal_deltas.caution) +
    countStringSetDeltaEntries(deltas.privacy.signal_deltas.reviewer_action_required) +
    countStringSetDeltaEntries(deltas.privacy.claim_deltas.proven_claims) +
    countStringSetDeltaEntries(deltas.privacy.claim_deltas.not_proven_claims);
  if (changedPrivacyDeltaCount > 0 && privacyHighlights === 0) {
    highlights.push(
      `Privacy delta summary: ${changedPrivacyDeltaCount} privacy detail ${pluralize(changedPrivacyDeltaCount, 'entry')} changed.`,
    );
  }

  const hasAnyDelta =
    deltas.assurance.changed ||
    deltas.evidence.changed ||
    deltas.policy.changed ||
    deltas.processor.changed ||
    deltas.privacy.changed;
  if (!hasAnyDelta) {
    return ['No assurance, evidence, policy, processor, or privacy deltas were detected between the compared runs.'];
  }

  return highlights;
}

function buildProofRunComparison(args: {
  baseline: ProofReport;
  candidate: ProofReport;
  baselineSourceType: ProofRunComparison['baseline_source']['type'];
}): ProofRunComparison {
  const { baseline, candidate, baselineSourceType } = args;

  const assuranceRows: ProofRunComparisonDeltaRow[] = [
    buildComparisonDeltaRow('Harness status', baseline.harness.status, candidate.harness.status),
    buildComparisonDeltaRow('Harness tier', baseline.harness.tier, candidate.harness.tier),
    buildComparisonDeltaRow('Harness trust tier', baseline.harness.trust_tier, candidate.harness.trust_tier),
    buildComparisonDeltaRow(
      'Runner attestation posture',
      baseline.privacy_posture.runner_attestation.posture,
      candidate.privacy_posture.runner_attestation.posture,
    ),
    buildComparisonDeltaRow(
      'Runner attestation reason code',
      baseline.privacy_posture.runner_attestation.reason_code,
      candidate.privacy_posture.runner_attestation.reason_code,
    ),
  ];

  const evidenceRows: ProofRunComparisonDeltaRow[] = [
    buildComparisonDeltaRow('Signed gateway receipts', baseline.gateway.signed_count, candidate.gateway.signed_count),
    buildComparisonDeltaRow('Event-chain entries', baseline.evidence.event_chain_count, candidate.evidence.event_chain_count),
    buildComparisonDeltaRow('Execution receipts', baseline.evidence.execution_receipt_count, candidate.evidence.execution_receipt_count),
    buildComparisonDeltaRow('Network receipts', baseline.evidence.network_receipt_count, candidate.evidence.network_receipt_count),
    buildComparisonDeltaRow('Tool receipts', baseline.evidence.tool_receipt_count, candidate.evidence.tool_receipt_count),
    buildComparisonDeltaRow(
      'Egress policy evidence present',
      baseline.privacy_posture.evidence.egress_policy_receipt_present,
      candidate.privacy_posture.evidence.egress_policy_receipt_present,
    ),
    buildComparisonDeltaRow(
      'Processor policy evidence present',
      baseline.privacy_posture.evidence.processor_policy_evidence_present,
      candidate.privacy_posture.evidence.processor_policy_evidence_present,
    ),
    buildComparisonDeltaRow(
      'Data-handling evidence present',
      baseline.privacy_posture.evidence.data_handling_receipts_present,
      candidate.privacy_posture.evidence.data_handling_receipts_present,
    ),
    buildComparisonDeltaRow(
      'Runtime hygiene evidence present',
      baseline.privacy_posture.evidence.runtime_hygiene_present,
      candidate.privacy_posture.evidence.runtime_hygiene_present,
    ),
    buildComparisonDeltaRow(
      'Runner measurement evidence present',
      baseline.privacy_posture.evidence.runner_measurement_present,
      candidate.privacy_posture.evidence.runner_measurement_present,
    ),
    buildComparisonDeltaRow(
      'Runner attestation receipt present',
      baseline.privacy_posture.evidence.runner_attestation_receipt_present,
      candidate.privacy_posture.evidence.runner_attestation_receipt_present,
    ),
    buildComparisonDeltaRow(
      'Reviewer signoff receipts',
      baseline.reviewer_signoff.receipt_count,
      candidate.reviewer_signoff.receipt_count,
    ),
    buildComparisonDeltaRow(
      'Reviewer dispute notes',
      baseline.reviewer_signoff.dispute_note_count,
      candidate.reviewer_signoff.dispute_note_count,
    ),
    buildComparisonDeltaRow(
      'Blocked egress attempts',
      baseline.privacy_posture.egress.blocked_attempt_count,
      candidate.privacy_posture.egress.blocked_attempt_count,
    ),
    buildComparisonDeltaRow(
      'Data-handling receipts',
      baseline.privacy_posture.data_handling.receipt_count,
      candidate.privacy_posture.data_handling.receipt_count,
    ),
    buildComparisonDeltaRow(
      'Approval required receipts',
      baseline.privacy_posture.data_handling.approval_required_count,
      candidate.privacy_posture.data_handling.approval_required_count,
    ),
    buildComparisonDeltaRow(
      'Approval unsatisfied receipts',
      baseline.privacy_posture.data_handling.approval_unsatisfied_count,
      candidate.privacy_posture.data_handling.approval_unsatisfied_count,
    ),
    buildComparisonDeltaRow(
      'Redaction applied receipts',
      baseline.privacy_posture.data_handling.redaction_applied_count,
      candidate.privacy_posture.data_handling.redaction_applied_count,
    ),
  ];

  const policyRows: ProofRunComparisonDeltaRow[] = [
    buildComparisonDeltaRow(
      'Egress proofed mode',
      baseline.privacy_posture.egress.proofed_mode,
      candidate.privacy_posture.egress.proofed_mode,
    ),
    buildComparisonDeltaRow(
      'Direct provider access blocked',
      baseline.privacy_posture.egress.direct_provider_access_blocked,
      candidate.privacy_posture.egress.direct_provider_access_blocked,
    ),
    buildComparisonDeltaRow(
      'Processor profile',
      baseline.privacy_posture.processor_policy.profile_id,
      candidate.privacy_posture.processor_policy.profile_id,
    ),
    buildComparisonDeltaRow(
      'Processor policy version',
      baseline.privacy_posture.processor_policy.policy_version,
      candidate.privacy_posture.processor_policy.policy_version,
    ),
    buildComparisonDeltaRow(
      'Processor enforce flag',
      baseline.privacy_posture.processor_policy.enforce,
      candidate.privacy_posture.processor_policy.enforce,
    ),
    buildComparisonDeltaRow(
      'Processor allowed routes',
      baseline.privacy_posture.processor_policy.allowed_routes,
      candidate.privacy_posture.processor_policy.allowed_routes,
    ),
    buildComparisonDeltaRow(
      'Processor denied routes',
      baseline.privacy_posture.processor_policy.denied_routes,
      candidate.privacy_posture.processor_policy.denied_routes,
    ),
    buildComparisonDeltaRow(
      'Data-handling policy version',
      baseline.privacy_posture.data_handling.policy_version,
      candidate.privacy_posture.data_handling.policy_version,
    ),
    buildComparisonDeltaRow(
      'Runtime profile',
      baseline.privacy_posture.runtime.profile_id,
      candidate.privacy_posture.runtime.profile_id,
    ),
    buildComparisonDeltaRow(
      'Runtime profile status',
      baseline.privacy_posture.runtime.profile_status,
      candidate.privacy_posture.runtime.profile_status,
    ),
    buildComparisonDeltaRow(
      'Runtime hygiene verdict',
      baseline.privacy_posture.runtime.hygiene_verdict,
      candidate.privacy_posture.runtime.hygiene_verdict,
    ),
  ];

  const baselineProcessorCounts = mapProcessorRouteCounts(baseline.privacy_posture.processor_policy.used_processors);
  const candidateProcessorCounts = mapProcessorRouteCounts(candidate.privacy_posture.processor_policy.used_processors);
  const baselineProcessorRoutes = [...baselineProcessorCounts.keys()];
  const candidateProcessorRoutes = [...candidateProcessorCounts.keys()];
  const usedProcessorRouteDelta = diffComparisonStringSets(baselineProcessorRoutes, candidateProcessorRoutes);
  const usedProcessorCountDeltas: ProofRunComparisonCountDelta[] = [...new Set([
    ...baselineProcessorRoutes,
    ...candidateProcessorRoutes,
  ])]
    .sort((a, b) => a.localeCompare(b))
    .map((key) => ({
      key,
      baseline_count: baselineProcessorCounts.get(key) ?? 0,
      candidate_count: candidateProcessorCounts.get(key) ?? 0,
    }))
    .filter((entry) => entry.baseline_count !== entry.candidate_count);

  const blockedAttemptDelta = diffComparisonStringSets(
    baseline.privacy_posture.processor_policy.blocked_attempts.map(formatProcessorBlockedAttemptKey),
    candidate.privacy_posture.processor_policy.blocked_attempts.map(formatProcessorBlockedAttemptKey),
  );

  const privacyRows: ProofRunComparisonDeltaRow[] = [
    buildComparisonDeltaRow(
      'Privacy verdict',
      baseline.privacy_posture.overall_verdict,
      candidate.privacy_posture.overall_verdict,
    ),
    buildComparisonDeltaRow(
      'Privacy reviewer action required',
      baseline.privacy_posture.reviewer_action_required,
      candidate.privacy_posture.reviewer_action_required,
    ),
    buildComparisonDeltaRow(
      'Runner attestation bindings consistent',
      baseline.privacy_posture.runner_attestation.evidence.binding_consistent,
      candidate.privacy_posture.runner_attestation.evidence.binding_consistent,
    ),
    buildComparisonDeltaRow(
      'Reviewer dispute present',
      baseline.reviewer_signoff.dispute_present,
      candidate.reviewer_signoff.dispute_present,
    ),
  ];

  const dataHandlingActionRows = DATA_HANDLING_ACTION_ORDER.map((action) =>
    buildComparisonDeltaRow(
      `Data-handling action: ${action}`,
      actionCountForPosture(baseline.privacy_posture, action),
      actionCountForPosture(candidate.privacy_posture, action),
    ));

  const baselineSensitiveClasses = baseline.privacy_posture.data_handling.sensitive_classes.map(formatSensitiveClass);
  const candidateSensitiveClasses = candidate.privacy_posture.data_handling.sensitive_classes.map(formatSensitiveClass);
  const sensitiveClassDelta = diffComparisonStringSets(baselineSensitiveClasses, candidateSensitiveClasses);

  const signalDeltas = {
    background_noise: diffComparisonStringSets(
      baseline.privacy_posture.signal_buckets.background_noise,
      candidate.privacy_posture.signal_buckets.background_noise,
    ),
    caution: diffComparisonStringSets(
      baseline.privacy_posture.signal_buckets.caution,
      candidate.privacy_posture.signal_buckets.caution,
    ),
    reviewer_action_required: diffComparisonStringSets(
      baseline.privacy_posture.signal_buckets.reviewer_action_required,
      candidate.privacy_posture.signal_buckets.reviewer_action_required,
    ),
  };

  const claimDeltas = {
    proven_claims: diffComparisonStringSets(
      baseline.privacy_posture.proven_claims,
      candidate.privacy_posture.proven_claims,
    ),
    not_proven_claims: diffComparisonStringSets(
      baseline.privacy_posture.not_proven_claims,
      candidate.privacy_posture.not_proven_claims,
    ),
  };

  const deltas: ProofRunComparison['deltas'] = {
    assurance: {
      rows: assuranceRows,
      changed: hasChangedDeltaRows(assuranceRows),
    },
    evidence: {
      rows: evidenceRows,
      changed: hasChangedDeltaRows(evidenceRows),
    },
    policy: {
      rows: policyRows,
      changed: hasChangedDeltaRows(policyRows),
    },
    processor: {
      used_processor_routes: usedProcessorRouteDelta,
      used_processor_count_deltas: usedProcessorCountDeltas,
      blocked_attempts: blockedAttemptDelta,
      changed:
        hasStringSetDelta(usedProcessorRouteDelta) ||
        usedProcessorCountDeltas.length > 0 ||
        hasStringSetDelta(blockedAttemptDelta),
    },
    privacy: {
      rows: privacyRows,
      data_handling_action_rows: dataHandlingActionRows,
      sensitive_class_deltas: sensitiveClassDelta,
      signal_deltas: signalDeltas,
      claim_deltas: claimDeltas,
      changed:
        hasChangedDeltaRows(privacyRows) ||
        hasChangedDeltaRows(dataHandlingActionRows) ||
        hasStringSetDelta(sensitiveClassDelta) ||
        hasStringSetDelta(signalDeltas.background_noise) ||
        hasStringSetDelta(signalDeltas.caution) ||
        hasStringSetDelta(signalDeltas.reviewer_action_required) ||
        hasStringSetDelta(claimDeltas.proven_claims) ||
        hasStringSetDelta(claimDeltas.not_proven_claims),
    },
  };

  return {
    comparison_version: '1',
    generated_at: deriveStableExportPackTimestamp(candidate),
    baseline_source: {
      type: baselineSourceType,
    },
    baseline: buildRunComparisonSnapshot(baseline),
    candidate: buildRunComparisonSnapshot(candidate),
    deltas,
    reviewer_highlights: buildRunComparisonReviewerHighlights({ baseline, candidate, deltas }),
  };
}

function comparisonValueToText(value: ProofRunComparisonValue): string {
  if (value === null) return 'unknown';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  return String(value);
}

function renderComparisonDeltaRows(lines: string[], rows: ProofRunComparisonDeltaRow[]): void {
  const changedRows = rows.filter((row) => row.changed);
  if (changedRows.length === 0) {
    lines.push('- No deltas.');
    return;
  }
  for (const row of changedRows) {
    lines.push(
      `- ${row.label}: baseline=\`${comparisonValueToText(row.baseline)}\` -> candidate=\`${comparisonValueToText(row.candidate)}\``,
    );
  }
}

function renderComparisonStringSetDelta(
  lines: string[],
  label: string,
  delta: ProofRunComparisonStringSetDelta,
): void {
  if (!hasStringSetDelta(delta)) {
    lines.push(`- ${label}: no deltas.`);
    return;
  }
  if (delta.added.length > 0) {
    lines.push(`- ${label} added:`);
    for (const entry of delta.added) {
      lines.push(`  - ${entry}`);
    }
  }
  if (delta.removed.length > 0) {
    lines.push(`- ${label} removed:`);
    for (const entry of delta.removed) {
      lines.push(`  - ${entry}`);
    }
  }
}

function renderProofRunComparisonMarkdown(comparison: ProofRunComparison): string {
  const lines: string[] = [];
  lines.push('# Side-by-side Run Comparison');
  lines.push('');
  lines.push(`Generated at: ${comparison.generated_at}`);
  lines.push(`Baseline source type: ${comparison.baseline_source.type}`);
  lines.push(`Baseline bundle ID: ${comparison.baseline.bundle_id ?? 'unknown'}`);
  lines.push(`Candidate bundle ID: ${comparison.candidate.bundle_id ?? 'unknown'}`);
  lines.push('');
  lines.push('## Reviewer Highlights');
  for (const highlight of comparison.reviewer_highlights) {
    lines.push(`- ${highlight}`);
  }
  lines.push('');
  lines.push('## Assurance/Tier Deltas');
  renderComparisonDeltaRows(lines, comparison.deltas.assurance.rows);
  lines.push('');
  lines.push('## Evidence Deltas');
  renderComparisonDeltaRows(lines, comparison.deltas.evidence.rows);
  lines.push('');
  lines.push('## Policy Deltas');
  renderComparisonDeltaRows(lines, comparison.deltas.policy.rows);
  lines.push('');
  lines.push('## Processor Deltas');
  renderComparisonStringSetDelta(lines, 'Used processor routes', comparison.deltas.processor.used_processor_routes);
  if (comparison.deltas.processor.used_processor_count_deltas.length === 0) {
    lines.push('- Used processor count deltas: no deltas.');
  } else {
    lines.push('- Used processor count deltas:');
    for (const delta of comparison.deltas.processor.used_processor_count_deltas) {
      lines.push(
        `  - ${delta.key}: baseline=${delta.baseline_count} -> candidate=${delta.candidate_count}`,
      );
    }
  }
  renderComparisonStringSetDelta(lines, 'Blocked processor attempts', comparison.deltas.processor.blocked_attempts);
  lines.push('');
  lines.push('## Privacy Deltas');
  renderComparisonDeltaRows(lines, comparison.deltas.privacy.rows);
  lines.push('');
  lines.push('### Data-handling Action Deltas');
  renderComparisonDeltaRows(lines, comparison.deltas.privacy.data_handling_action_rows);
  lines.push('');
  lines.push('### Sensitive-class Deltas');
  renderComparisonStringSetDelta(lines, 'Sensitive classes', comparison.deltas.privacy.sensitive_class_deltas);
  lines.push('');
  lines.push('### Signal Deltas');
  renderComparisonStringSetDelta(lines, 'Background signals', comparison.deltas.privacy.signal_deltas.background_noise);
  renderComparisonStringSetDelta(lines, 'Caution signals', comparison.deltas.privacy.signal_deltas.caution);
  renderComparisonStringSetDelta(
    lines,
    'Reviewer-action signals',
    comparison.deltas.privacy.signal_deltas.reviewer_action_required,
  );
  lines.push('');
  lines.push('### Claim Deltas');
  renderComparisonStringSetDelta(lines, 'Proven claims', comparison.deltas.privacy.claim_deltas.proven_claims);
  renderComparisonStringSetDelta(lines, 'Not-proven claims', comparison.deltas.privacy.claim_deltas.not_proven_claims);
  lines.push('');
  return lines.join('\n');
}

function isProofReportLike(value: unknown): value is ProofReport {
  if (!isRecord(value)) return false;
  return (
    isRecord(value.public_layer) &&
    isRecord(value.harness) &&
    isRecord(value.evidence) &&
    isRecord(value.gateway) &&
    isRecord(value.sentinels) &&
    isRecord(value.network) &&
    isRecord(value.privacy_posture) &&
    Array.isArray(value.review_buckets) &&
    Array.isArray(value.warnings) &&
    Array.isArray(value.next_steps) &&
    typeof value.verify_command === 'string'
  );
}

function normalizeReviewerSignoffState(value: unknown): ProofReviewerSignoffState {
  if (!isRecord(value)) {
    return DEFAULT_REVIEWER_SIGNOFF_STATE;
  }

  const decisionCounts = isRecord(value.decision_counts) ? value.decision_counts : null;
  const targetCounts = isRecord(value.target_counts) ? value.target_counts : null;
  const receiptCount = asNonNegativeInteger(value.receipt_count) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.receipt_count;
  const structuredCount = asNonNegativeInteger(value.structured_receipt_count) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.structured_receipt_count;
  const revokedCount = asNonNegativeInteger(value.revoked_receipt_count) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.revoked_receipt_count;

  return {
    present: asBoolean(value.present) ?? true,
    receipt_count: receiptCount,
    structured_receipt_count: Math.min(structuredCount, receiptCount),
    revoked_receipt_count: Math.min(revokedCount, receiptCount),
    revoked_reviewer_dids: dedupeStrings(asStringArray(value.revoked_reviewer_dids)).sort((a, b) => a.localeCompare(b)),
    reviewer_dids: dedupeStrings(asStringArray(value.reviewer_dids)).sort((a, b) => a.localeCompare(b)),
    decision_counts: {
      approve: asNonNegativeInteger(decisionCounts?.approve) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.decision_counts.approve,
      reject: asNonNegativeInteger(decisionCounts?.reject) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.decision_counts.reject,
      needs_changes: asNonNegativeInteger(decisionCounts?.needs_changes) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.decision_counts.needs_changes,
    },
    target_counts: {
      run: asNonNegativeInteger(targetCounts?.run) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.target_counts.run,
      export_pack: asNonNegativeInteger(targetCounts?.export_pack) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.target_counts.export_pack,
    },
    latest_timestamp: asString(value.latest_timestamp),
    dispute_present: asBoolean(value.dispute_present) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.dispute_present,
    dispute_note_count: asNonNegativeInteger(value.dispute_note_count) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.dispute_note_count,
    dispute_evidence_refs_count: asNonNegativeInteger(value.dispute_evidence_refs_count) ?? DEFAULT_REVIEWER_SIGNOFF_STATE.dispute_evidence_refs_count,
  };
}

function normalizeCompiledEvidenceSummary(value: unknown): ProofCompiledEvidenceSummary {
  const fallback = buildDefaultCompiledEvidenceSummary();
  if (!isRecord(value)) {
    return fallback;
  }

  const controlCounts = isRecord(value.control_outcome_counts)
    ? value.control_outcome_counts
    : null;
  const evidenceRefs = isRecord(value.evidence_refs) ? value.evidence_refs : null;
  const narrative = isRecord(value.narrative) ? value.narrative : null;
  const artifactPaths = isRecord(value.artifact_paths) ? value.artifact_paths : null;
  const overallStatus = asString(value.overall_status);

  const normalized: ProofCompiledEvidenceSummary = {
    envelope_present: asBoolean(value.envelope_present) ?? false,
    authoritative_report_present: asBoolean(value.authoritative_report_present) ?? false,
    metadata_path: asString(value.metadata_path),
    report_id: asString(value.report_id),
    compiler_version: asString(value.compiler_version),
    overall_status: isCompiledEvidenceOverallStatus(overallStatus) ? overallStatus : null,
    matrix_hash_b64u: asString(value.matrix_hash_b64u),
    payload_hash_b64u: asString(value.payload_hash_b64u),
    signer_did: asString(value.signer_did),
    issued_at: asString(value.issued_at),
    control_outcome_counts: {
      total: asNonNegativeInteger(controlCounts?.total) ?? 0,
      pass: asNonNegativeInteger(controlCounts?.pass) ?? 0,
      fail: asNonNegativeInteger(controlCounts?.fail) ?? 0,
      partial: asNonNegativeInteger(controlCounts?.partial) ?? 0,
      inapplicable: asNonNegativeInteger(controlCounts?.inapplicable) ?? 0,
      fail_closed_invalid_evidence:
        asNonNegativeInteger(controlCounts?.fail_closed_invalid_evidence) ?? 0,
    },
    non_pass_controls: dedupeStrings(asStringArray(value.non_pass_controls)),
    evidence_refs: {
      proof_bundle_hash_b64u: asString(evidenceRefs?.proof_bundle_hash_b64u),
      ontology_hash_b64u: asString(evidenceRefs?.ontology_hash_b64u),
      mapping_rules_hash_b64u: asString(evidenceRefs?.mapping_rules_hash_b64u),
      verify_result_hash_b64u: asString(evidenceRefs?.verify_result_hash_b64u),
    },
    narrative: {
      present: asBoolean(narrative?.present) ?? false,
      authoritative_flag: asBoolean(narrative?.authoritative_flag),
      disclaimer: asString(narrative?.disclaimer),
    },
    invalid_reasons: dedupeStrings(asStringArray(value.invalid_reasons)),
    artifact_paths: undefined,
  };

  const envelopePath = asString(artifactPaths?.envelope);
  const reportPath = asString(artifactPaths?.report);
  const summaryPath = asString(artifactPaths?.summary);
  const narrativePath = asString(artifactPaths?.narrative);
  if (envelopePath) {
    normalized.artifact_paths = {
      envelope: envelopePath,
      report: reportPath ?? undefined,
      summary: summaryPath ?? undefined,
      narrative: narrativePath ?? undefined,
    };
  }

  return normalized;
}

function normalizeProofReportForComparison(report: ProofReport): ProofReport {
  const reportRecord = report as unknown as Record<string, unknown>;
  return {
    ...report,
    reviewer_signoff: normalizeReviewerSignoffState(reportRecord.reviewer_signoff),
    compiled_evidence: normalizeCompiledEvidenceSummary(reportRecord.compiled_evidence),
  };
}

async function loadRunComparisonBaseline(compareWithPath: string): Promise<{
  report: ProofReport;
  sourceType: ProofRunComparison['baseline_source']['type'];
}> {
  const resolvedComparePath = resolve(compareWithPath);
  const comparePathStat = await stat(resolvedComparePath);

  if (comparePathStat.isDirectory()) {
    const reportPath = resolve(resolvedComparePath, EXPORT_PACK_REPORT_JSON_PATH);
    const parsed = await readJsonObject(reportPath);
    if (!isProofReportLike(parsed)) {
      throw new Error(`Comparison export-pack report is not a valid proof report: ${reportPath}`);
    }
    return {
      report: normalizeProofReportForComparison(parsed),
      sourceType: 'export_pack',
    };
  }

  const parsed = await readJsonObject(resolvedComparePath);
  if (isProofReportLike(parsed)) {
    return {
      report: normalizeProofReportForComparison(parsed),
      sourceType: 'proof_report',
    };
  }

  if (asString(parsed.envelope_type) !== 'proof_bundle' || !isRecord(parsed.payload)) {
    throw new Error(
      `Comparison input must be a proof bundle, export pack directory, or proof report JSON: ${resolvedComparePath}`,
    );
  }

  const baselineRunSummary = await maybeReadJsonObject(inferRunSummaryPath(resolvedComparePath));
  return {
    report: buildProofReport({
      inputPath: resolvedComparePath,
      bundle: parsed,
      runSummary: baselineRunSummary,
    }),
    sourceType: 'proof_bundle',
  };
}

function summarizePrivacyPosture(args: {
  payload: Record<string, unknown>;
  sentinels: ProofReport['sentinels'];
  claimedTier: string | null;
  claimedTrustTier: string | null;
}): ProofPrivacyPosture {
  const { payload, sentinels, claimedTier, claimedTrustTier } = args;
  const metadata = isRecord(payload.metadata) ? payload.metadata : null;
  const expectedAgentDid = asString(payload.agent_did);
  const sentinelMetadata = metadata && isRecord(metadata.sentinels) ? metadata.sentinels : null;
  const rawEgressEnvelope = sentinelMetadata && isRecord(sentinelMetadata.egress_policy_receipt)
    ? sentinelMetadata.egress_policy_receipt
    : null;
  const egressEnvelope = hasStructuredEgressPolicyReceipt(rawEgressEnvelope) ? rawEgressEnvelope : null;
  const egressPayload = egressEnvelope && isRecord(egressEnvelope.payload) ? egressEnvelope.payload : null;

  const rawProcessorPolicy = metadata && isRecord(metadata.processor_policy) ? metadata.processor_policy : null;
  const processorPolicy = hasStructuredProcessorPolicyEvidence(rawProcessorPolicy) ? rawProcessorPolicy : null;
  const usedProcessors: ProofPrivacyProcessorRoute[] = asArray(processorPolicy?.used_processors)
    .filter((entry): entry is Record<string, unknown> => isRecord(entry))
    .map((route) => {
      const provider = asString(route.provider);
      const model = asString(route.model);
      const region = asString(route.region);
      const retentionProfile = asString(route.retention_profile);
      const count = asNumber(route.count);
      if (!provider || !model || !region || !retentionProfile || count === null) {
        return null;
      }
      return {
        provider,
        model,
        region,
        retention_profile: retentionProfile,
        count,
      };
    })
    .filter((entry): entry is ProofPrivacyProcessorRoute => entry !== null);
  const processorBlockedAttempts: ProofPrivacyProcessorBlockedAttempt[] = asArray(processorPolicy?.blocked_attempts)
    .filter((entry): entry is Record<string, unknown> => isRecord(entry))
    .map((attempt) => {
      const route = isRecord(attempt.route) ? attempt.route : null;
      const provider = asString(route?.provider);
      const model = asString(route?.model);
      const region = asString(route?.region);
      const retentionProfile = asString(route?.retention_profile);
      const reasonCode = asString(attempt.reason_code);
      if (!provider || !model || !region || !retentionProfile || !reasonCode) {
        return null;
      }
      return {
        route: {
          provider,
          model,
          region,
          retention_profile: retentionProfile,
        },
        reason_code: reasonCode,
        timestamp: asString(attempt.timestamp),
      };
    })
    .filter((entry): entry is ProofPrivacyProcessorBlockedAttempt => entry !== null);

  const dataHandling = metadata && isRecord(metadata.data_handling) ? metadata.data_handling : null;
  const rawDataHandlingReceiptCount = asArray(dataHandling?.receipts).filter((entry): entry is Record<string, unknown> => isRecord(entry)).length;
  const dataHandlingPayloads = asArray(dataHandling?.receipts)
    .filter((entry): entry is Record<string, unknown> => isRecord(entry))
    .map((entry) => getStructuredDataHandlingPayload(entry))
    .filter((entry): entry is Record<string, unknown> => entry !== null);
  const actionCounts = new Map<DataHandlingAction, number>();
  for (const action of DATA_HANDLING_ACTION_ORDER) {
    actionCounts.set(action, 0);
  }
  const classMap = new Map<string, { class_id: string; match_count: number; actions: Set<DataHandlingAction> }>();
  const reasonCodes = new Set<string>();
  let approvalRequiredCount = 0;
  let approvalSatisfiedCount = 0;
  let approvalUnsatisfiedCount = 0;
  let redactionAppliedCount = 0;

  for (const receiptPayload of dataHandlingPayloads) {
    const action = isDataHandlingAction(receiptPayload.action) ? receiptPayload.action : null;
    if (action) {
      actionCounts.set(action, (actionCounts.get(action) ?? 0) + 1);
    }

    const reasonCode = asString(receiptPayload.reason_code);
    if (reasonCode) {
      reasonCodes.add(reasonCode);
    }

    const approval = isRecord(receiptPayload.approval) ? receiptPayload.approval : null;
    if (approval?.required === true) approvalRequiredCount += 1;
    if (approval?.satisfied === true) approvalSatisfiedCount += 1;
    if (approval?.required === true && approval?.satisfied !== true) approvalUnsatisfiedCount += 1;

    const redaction = isRecord(receiptPayload.redaction) ? receiptPayload.redaction : null;
    if (redaction?.applied === true) redactionAppliedCount += 1;

    const classEntries = asArray(receiptPayload.classes).filter((entry): entry is Record<string, unknown> => isRecord(entry));
    for (const classEntry of classEntries) {
      const classId = asString(classEntry.class_id);
      const classAction = isDataHandlingAction(classEntry.action)
        ? classEntry.action
        : action;
      const matchCount = asNumber(classEntry.match_count) ?? 0;
      if (!classId || !classAction) continue;

      const existing = classMap.get(classId);
      if (existing) {
        existing.match_count += matchCount;
        existing.actions.add(classAction);
      } else {
        classMap.set(classId, {
          class_id: classId,
          match_count: matchCount,
          actions: new Set([classAction]),
        });
      }
    }
  }

  const sensitiveClasses = [...classMap.values()]
    .map((entry) => ({
      class_id: entry.class_id,
      match_count: entry.match_count,
      actions: DATA_HANDLING_ACTION_ORDER.filter((action) => entry.actions.has(action)),
    }))
    .sort((a, b) => b.match_count - a.match_count || a.class_id.localeCompare(b.class_id));
  const dataHandlingActions = DATA_HANDLING_ACTION_ORDER
    .map((action) => ({ action, count: actionCounts.get(action) ?? 0 }))
    .filter((entry) => entry.count > 0);

  const runtimeProfilePresent =
    sentinels.runtime_profile.profile_id !== null ||
    sentinels.runtime_profile.status !== null ||
    sentinels.runtime_profile.mode !== null ||
    sentinels.runtime_profile.baseline_process_count !== null ||
    sentinels.runtime_profile.baseline_process_hash_b64u !== null;
  const runtimeHygienePresent =
    sentinels.runtime_hygiene.verdict !== null ||
    sentinels.runtime_hygiene.background_signals.length > 0 ||
    sentinels.runtime_hygiene.caution_signals.length > 0 ||
    sentinels.runtime_hygiene.action_required_signals.length > 0;
  const runnerMeasurementPresent = metadata ? metadata.runner_measurement !== undefined : false;
  const runnerAttestationReceiptPresent = metadata ? metadata.runner_attestation_receipt !== undefined : false;
  const rawRunnerMeasurement = metadata && isRecord(metadata.runner_measurement)
    ? metadata.runner_measurement
    : null;
  const rawRunnerAttestationReceipt = metadata && isRecord(metadata.runner_attestation_receipt)
    ? metadata.runner_attestation_receipt
    : null;
  const runnerMeasurement = parseStructuredRunnerMeasurementEvidence(rawRunnerMeasurement);
  const runnerAttestationReceipt = parseStructuredRunnerAttestationReceiptEvidence(
    rawRunnerAttestationReceipt,
    expectedAgentDid,
  );
  const policyBinding = metadata && isRecord(metadata.policy_binding) ? metadata.policy_binding : null;
  const policyBindingHash = asString(policyBinding?.effective_policy_hash_b64u);
  const signedPolicyBundleEnvelope = policyBinding && isRecord(policyBinding.signed_policy_bundle_envelope)
    ? policyBinding.signed_policy_bundle_envelope
    : null;
  const signedPolicyBundlePayload = signedPolicyBundleEnvelope && isRecord(signedPolicyBundleEnvelope.payload)
    ? signedPolicyBundleEnvelope.payload
    : null;
  const signedPolicyBundleMetadata = signedPolicyBundlePayload && isRecord(signedPolicyBundlePayload.metadata)
    ? signedPolicyBundlePayload.metadata
    : null;
  const policyIssuerRevocations = parseTrustRootRevocationEvidence(
    signedPolicyBundleMetadata?.revoked_policy_issuer_keys,
  );
  const policyIssuerRevocationArtifactsMalformed =
    signedPolicyBundleMetadata?.revoked_policy_issuer_keys !== undefined &&
    policyIssuerRevocations === null;
  const policySignerDid = asString(signedPolicyBundleEnvelope?.signer_did);
  const policyIssuerRevocation = policyIssuerRevocations
    ? findMatchingTrustRootRevocation(policyIssuerRevocations, policySignerDid)
    : null;
  const runnerRevocations = parseTrustRootRevocationEvidence(
    isRecord(rawRunnerAttestationReceipt?.payload)
      ? rawRunnerAttestationReceipt.payload.revoked_runner_keys
      : undefined,
  );
  const runnerRevocationArtifactsMalformed =
    isRecord(rawRunnerAttestationReceipt?.payload) &&
    rawRunnerAttestationReceipt.payload.revoked_runner_keys !== undefined &&
    runnerRevocations === null;
  const runnerRevocation = runnerRevocations
    ? findMatchingTrustRootRevocation(runnerRevocations, runnerAttestationReceipt?.signer_did ?? null)
    : null;
  const eventChainEntries = asArray(payload.event_chain).filter((entry): entry is Record<string, unknown> => isRecord(entry));
  const expectedRunId = asString(eventChainEntries[0]?.run_id);
  const allowedEventHashes = new Set(
    eventChainEntries
      .map((entry) => asString(entry.event_hash_b64u))
      .filter((entry): entry is string => entry !== null),
  );
  const runnerAttestationBindingConsistent =
    runnerMeasurement !== null &&
    runnerAttestationReceipt !== null &&
    runnerAttestationReceipt.signer_did === expectedAgentDid &&
    runnerAttestationReceipt.runner_measurement_manifest_hash_b64u === runnerMeasurement.manifest_hash_b64u &&
    runnerAttestationReceipt.runner_measurement_runtime_hash_b64u === computeJsonSha256B64u(runnerMeasurement.runtime) &&
    runnerAttestationReceipt.policy_effective_policy_hash_b64u === runnerMeasurement.policy_effective_policy_hash_b64u &&
    policyBindingHash !== null &&
    runnerAttestationReceipt.policy_effective_policy_hash_b64u === policyBindingHash &&
    expectedRunId !== null &&
    runnerAttestationReceipt.binding_run_id === expectedRunId &&
    allowedEventHashes.has(runnerAttestationReceipt.binding_event_hash_b64u) &&
    runnerMeasurementArtifactsMatch(runnerMeasurement.artifacts, runnerAttestationReceipt.artifacts);
  const normalizedClaimedTier = normalizeTierValue(claimedTier);
  const normalizedClaimedTrustTier = normalizeTierValue(claimedTrustTier);
  const attestedTierClaimed =
    normalizedClaimedTier === 'attested' ||
    normalizedClaimedTier === 'full' ||
    normalizedClaimedTrustTier === 'attested' ||
    normalizedClaimedTrustTier === 'full';
  const runnerAttestationEvidencePresent = runnerMeasurementPresent || runnerAttestationReceiptPresent;
  const runnerAttestationReasonCode: ProofRunnerAttestationReasonCode = !runnerAttestationEvidencePresent
    ? 'ATTESTED_TIER_NOT_GRANTED_NO_RUNNER_ATTESTATION'
    : policyIssuerRevocation !== null
      ? 'ATTESTED_TIER_NOT_GRANTED_REVOKED_POLICY_ISSUER'
      : runnerRevocation !== null
        ? 'ATTESTED_TIER_NOT_GRANTED_REVOKED_RUNNER'
        : runnerMeasurement === null || runnerAttestationReceipt === null || !runnerAttestationBindingConsistent
      ? 'ATTESTED_TIER_NOT_GRANTED_INVALID_RUNNER_ATTESTATION'
      : attestedTierClaimed
        ? 'ATTESTED_TIER_GRANTED'
        : 'ATTESTED_TIER_NOT_GRANTED_TRUST_CONSTRAINED';
  const runnerAttestationPosture: ProofRunnerAttestationPosture = runnerAttestationReasonCode === 'ATTESTED_TIER_GRANTED'
    ? 'attested'
    : 'non_attested';
  const evidence = {
    egress_policy_receipt_present: egressPayload !== null,
    runtime_profile_present: runtimeProfilePresent,
    runtime_hygiene_present: runtimeHygienePresent,
    data_handling_receipts_present: dataHandlingPayloads.length > 0,
    processor_policy_evidence_present: processorPolicy !== null,
    runner_measurement_present: runnerMeasurementPresent,
    runner_attestation_receipt_present: runnerAttestationReceiptPresent,
  };

  const cautionSignals: string[] = [];
  const reviewerActionSignals: string[] = [];
  const backgroundSignals = dedupeStrings(sentinels.runtime_hygiene.background_signals);
  cautionSignals.push(...sentinels.runtime_hygiene.caution_signals);
  reviewerActionSignals.push(...sentinels.runtime_hygiene.action_required_signals);

  if (!evidence.egress_policy_receipt_present) {
    cautionSignals.push('No signed egress policy receipt is present in this bundle.');
    if (rawEgressEnvelope !== null) {
      cautionSignals.push('An egress policy object is present, but it is not a structurally complete signed receipt envelope.');
    }
  } else {
    if (egressPayload?.proofed_mode === false) {
      reviewerActionSignals.push('Egress policy evidence reports proofed_mode=false.');
    }
    if (egressPayload?.direct_provider_access_blocked === false) {
      reviewerActionSignals.push('Egress policy evidence reports direct provider access is not blocked.');
    }
    const egressBlockedAttemptCount = asNumber(egressPayload?.blocked_attempt_count) ?? 0;
    if (egressBlockedAttemptCount > 0) {
      cautionSignals.push(
        `${egressBlockedAttemptCount} blocked egress ${pluralize(egressBlockedAttemptCount, 'attempt')} were observed.`,
      );
    }
  }

  if (!evidence.processor_policy_evidence_present) {
    cautionSignals.push('No processor policy evidence is present in this bundle.');
    if (rawProcessorPolicy !== null) {
      cautionSignals.push('A processor policy object is present, but it is missing required evidence fields.');
    }
  } else {
    if (processorPolicy?.enforce === false) {
      reviewerActionSignals.push('Processor policy evidence reports enforce=false.');
    }
    const deniedRoutes = asNumber(processorPolicy?.counters && isRecord(processorPolicy.counters) ? processorPolicy.counters.denied_routes : null) ?? 0;
    if (deniedRoutes > 0) {
      cautionSignals.push(
        `${deniedRoutes} processor route ${pluralize(deniedRoutes, 'attempt')} were blocked by policy.`,
      );
    }
  }

  if (!evidence.data_handling_receipts_present) {
    cautionSignals.push('No signed data-handling receipts are present in this bundle.');
    if (rawDataHandlingReceiptCount > 0) {
      cautionSignals.push('Data-handling metadata is present, but it does not contain structurally complete signed receipt envelopes.');
    }
  } else {
    if (rawDataHandlingReceiptCount > dataHandlingPayloads.length) {
      cautionSignals.push('Some data-handling entries are present, but not all of them are structurally complete signed receipt envelopes.');
    }
    if (approvalUnsatisfiedCount > 0) {
      reviewerActionSignals.push(
        `${approvalUnsatisfiedCount} data-handling ${pluralize(approvalUnsatisfiedCount, 'receipt')} required approval and did not satisfy it.`,
      );
    }
    const redactCount = actionCounts.get('redact') ?? 0;
    if (redactCount > 0) {
      cautionSignals.push(
        `${redactCount} data-handling ${pluralize(redactCount, 'receipt')} applied redaction before egress.`,
      );
    }
    const blockCount = actionCounts.get('block') ?? 0;
    if (blockCount > 0) {
      cautionSignals.push(
        `${blockCount} data-handling ${pluralize(blockCount, 'receipt')} blocked outbound payloads.`,
      );
    }
  }

  if (!evidence.runtime_profile_present) {
    cautionSignals.push('Runtime profile evidence is missing.');
  }
  if (!evidence.runtime_hygiene_present) {
    cautionSignals.push('Runtime hygiene evidence is missing.');
  }
  if (policyIssuerRevocationArtifactsMalformed) {
    cautionSignals.push(
      'Policy revocation metadata is present but malformed; canonical verifier is required to determine issuer revocation state.',
    );
  }
  if (runnerRevocationArtifactsMalformed) {
    cautionSignals.push(
      'Runner revocation metadata is present but malformed; canonical verifier is required to determine runner trust-root revocation state.',
    );
  }
  if (sentinels.runtime_hygiene.reviewer_action_required) {
    reviewerActionSignals.push('Runtime hygiene marked reviewer_action_required=true.');
  }
  if (!sentinels.interpose_active) {
    cautionSignals.push('Interpose monitoring was not active for this run.');
  }
  if (sentinels.escapes_suspected) {
    reviewerActionSignals.push('CLDD marked the run as escape-suspected.');
  }
  if (sentinels.unmonitored_spawns > 0) {
    reviewerActionSignals.push(
      `${sentinels.unmonitored_spawns} unmonitored ${pluralize(sentinels.unmonitored_spawns, 'spawn')} were observed.`,
    );
  }
  if (policyIssuerRevocation) {
    reviewerActionSignals.push(
      describeTrustRootRevocation('Policy issuer', policyIssuerRevocation),
    );
  }
  if (runnerRevocation) {
    reviewerActionSignals.push(
      describeTrustRootRevocation('Runner attestation', runnerRevocation),
    );
  }
  if (runnerAttestationReasonCode === 'ATTESTED_TIER_NOT_GRANTED_INVALID_RUNNER_ATTESTATION' && attestedTierClaimed) {
    reviewerActionSignals.push(
      'Run summary claims attested posture, but runner attestation evidence is missing required structure/binding consistency.',
    );
  } else if (runnerAttestationReasonCode === 'ATTESTED_TIER_NOT_GRANTED_INVALID_RUNNER_ATTESTATION') {
    cautionSignals.push(
      'Runner attestation evidence is present, but it is missing required structure or binding consistency and cannot support attested posture.',
    );
  }

  const dedupedCautionSignals = dedupeStrings(cautionSignals);
  const dedupedReviewerActionSignals = dedupeStrings(reviewerActionSignals);
  const overallVerdict: ProofPrivacyVerdict = dedupedReviewerActionSignals.length > 0
    ? 'action'
    : dedupedCautionSignals.length > 0
      ? 'caution'
      : 'good';

  const provenClaims: string[] = [];
  if (evidence.egress_policy_receipt_present) {
    const blockedCount = asNumber(egressPayload?.blocked_attempt_count) ?? 0;
    provenClaims.push(
      `Bundle carries a signed egress policy receipt recording proofed mode=${egressPayload?.proofed_mode === true ? 'true' : 'false'}, direct provider blocked=${egressPayload?.direct_provider_access_blocked === true ? 'true' : 'false'}, and ${blockedCount} blocked egress ${pluralize(blockedCount, 'attempt')}.`,
    );
  }
  if (evidence.processor_policy_evidence_present) {
    const usedCount = usedProcessors.reduce((sum, route) => sum + route.count, 0);
    provenClaims.push(
      `Bundle metadata includes processor policy evidence for profile ${(asString(processorPolicy?.profile_id) ?? 'unknown')} declaring ${usedCount} allowed processor ${pluralize(usedCount, 'route invocation')} and ${processorBlockedAttempts.length} blocked processor route ${pluralize(processorBlockedAttempts.length, 'attempt')}.`,
    );
  }
  if (evidence.data_handling_receipts_present) {
    provenClaims.push(
      `Bundle carries ${dataHandlingPayloads.length} data-handling receipt ${pluralize(dataHandlingPayloads.length, 'envelope')} covering outbound payload decision ${pluralize(dataHandlingPayloads.length, 'event')} with actions ${dataHandlingActions.length > 0 ? dataHandlingActions.map((entry) => `${entry.action}:${entry.count}`).join(', ') : 'none recorded'}.`,
    );
  }
  if (evidence.runtime_profile_present || evidence.runtime_hygiene_present) {
    provenClaims.push(
      `Runtime evidence reports profile ${(sentinels.runtime_profile.profile_id ?? 'unknown')} (${sentinels.runtime_profile.status ?? 'unknown'}) with hygiene verdict ${(sentinels.runtime_hygiene.verdict ?? 'unknown')}.`,
    );
  }
  if (runnerAttestationReasonCode === 'ATTESTED_TIER_GRANTED') {
    provenClaims.push(
      'Run summary claims attested tier and bundle metadata carries runner measurement + runner attestation receipt evidence with matching run/event/policy/manifest bindings.',
    );
  } else if (runnerAttestationReasonCode === 'ATTESTED_TIER_NOT_GRANTED_TRUST_CONSTRAINED') {
    provenClaims.push(
      'Bundle metadata carries structurally consistent runner measurement + runner attestation receipt evidence, but run summary does not claim attested tier.',
    );
  }

  const notProvenClaims: string[] = [];
  if (!evidence.egress_policy_receipt_present) {
    notProvenClaims.push('Cannot prove fail-closed egress policy posture because no signed egress policy receipt is present.');
  }
  if (!evidence.processor_policy_evidence_present) {
    notProvenClaims.push('Cannot prove processor/model/region/retention enforcement because processor policy evidence is missing.');
  }
  if (!evidence.data_handling_receipts_present) {
    notProvenClaims.push('Cannot prove sensitive-data class actions before egress because no signed data-handling receipts are present.');
  }
  if (!evidence.runtime_hygiene_present) {
    notProvenClaims.push('Cannot prove runtime hygiene posture because runtime hygiene evidence is missing.');
  }
  if (runnerAttestationReasonCode === 'ATTESTED_TIER_NOT_GRANTED_NO_RUNNER_ATTESTATION') {
    notProvenClaims.push(
      'Cannot prove attested runner posture because runner measurement/attestation evidence is absent; treat this run as non-attested.',
    );
  } else if (runnerAttestationReasonCode === 'ATTESTED_TIER_NOT_GRANTED_REVOKED_POLICY_ISSUER') {
    notProvenClaims.push(
      'Cannot prove attested runner posture because the signed policy issuer trust-root key is revoked.',
    );
  } else if (runnerAttestationReasonCode === 'ATTESTED_TIER_NOT_GRANTED_REVOKED_RUNNER') {
    notProvenClaims.push(
      'Cannot prove attested runner posture because the runner attestation trust-root key is revoked.',
    );
  } else if (runnerAttestationReasonCode === 'ATTESTED_TIER_NOT_GRANTED_INVALID_RUNNER_ATTESTATION') {
    notProvenClaims.push(
      'Cannot prove attested runner posture because runner attestation evidence is missing required structure or binding consistency; treat this run as non-attested.',
    );
  } else if (runnerAttestationReasonCode === 'ATTESTED_TIER_NOT_GRANTED_TRUST_CONSTRAINED') {
    notProvenClaims.push(
      'Cannot claim attested runner posture because run summary does not claim attested trust tier, even though runner attestation evidence is present.',
    );
  }
  notProvenClaims.push(
    'This report does not independently verify runner attestation signatures or recompute runner-measurement hashes; use clawverify verify proof-bundle for canonical attested-tier validation.',
  );
  notProvenClaims.push('This report does not independently verify every privacy receipt signature or processor-policy hash; use clawverify verify proof-bundle for canonical validation.');
  notProvenClaims.push('This report does not by itself prove legal or regulatory compliance.');
  notProvenClaims.push('This report does not prove what third-party processors retained or deleted after receipt.');
  notProvenClaims.push('This report does not replace legal, contractual, or policy review.');
  notProvenClaims.push('This report does not include hardware-rooted remote attestation or measured boot guarantees.');

  return {
    overall_verdict: overallVerdict,
    reviewer_action_required: dedupedReviewerActionSignals.length > 0,
    evidence,
    egress: {
      proofed_mode: asBoolean(egressPayload?.proofed_mode),
      direct_provider_access_blocked: asBoolean(egressPayload?.direct_provider_access_blocked),
      blocked_attempt_count: asNumber(egressPayload?.blocked_attempt_count),
      blocked_attempts_observed: asBoolean(egressPayload?.blocked_attempts_observed),
      allowed_proxy_destinations: asStringArray(egressPayload?.allowed_proxy_destinations),
      allowed_child_destinations: asStringArray(egressPayload?.allowed_child_destinations),
    },
    processor_policy: {
      profile_id: asString(processorPolicy?.profile_id),
      policy_version: asString(processorPolicy?.policy_version),
      enforce: asBoolean(processorPolicy?.enforce),
      allowed_routes: asNumber(processorPolicy?.counters && isRecord(processorPolicy.counters) ? processorPolicy.counters.allowed_routes : null),
      denied_routes: asNumber(processorPolicy?.counters && isRecord(processorPolicy.counters) ? processorPolicy.counters.denied_routes : null),
      used_processors: usedProcessors,
      blocked_attempts: processorBlockedAttempts,
    },
    data_handling: {
      policy_version: asString(dataHandling?.policy_version),
      receipt_count: dataHandlingPayloads.length,
      actions: dataHandlingActions,
      sensitive_classes: sensitiveClasses,
      approval_required_count: approvalRequiredCount,
      approval_satisfied_count: approvalSatisfiedCount,
      approval_unsatisfied_count: approvalUnsatisfiedCount,
      redaction_applied_count: redactionAppliedCount,
      reason_codes: [...reasonCodes].sort((a, b) => a.localeCompare(b)),
    },
    runtime: {
      profile_id: sentinels.runtime_profile.profile_id,
      profile_status: sentinels.runtime_profile.status,
      hygiene_verdict: sentinels.runtime_hygiene.verdict,
    },
    runner_attestation: {
      posture: runnerAttestationPosture,
      reason_code: runnerAttestationReasonCode,
      claimed_tier: claimedTier,
      claimed_trust_tier: claimedTrustTier,
      attested_tier_claimed: attestedTierClaimed,
      evidence: {
        runner_measurement_present: runnerMeasurementPresent,
        runner_measurement_structured: runnerMeasurement !== null,
        runner_attestation_receipt_present: runnerAttestationReceiptPresent,
        runner_attestation_receipt_structured: runnerAttestationReceipt !== null,
        binding_consistent: runnerAttestationBindingConsistent,
      },
    },
    signal_buckets: {
      background_noise: backgroundSignals,
      caution: dedupedCautionSignals,
      reviewer_action_required: dedupedReviewerActionSignals,
    },
    proven_claims: dedupeStrings(provenClaims),
    not_proven_claims: dedupeStrings(notProvenClaims),
  };
}

function deriveReviewBuckets(report: ProofReportBase): ProofReviewBucket[] {
  const backgroundSignals = report.sentinels.runtime_hygiene.background_signals.filter(
    (signal) => signal !== 'No baseline/background network noise receipts were classified.',
  );
  const gatewayItems = report.gateway.signed_count > 0
    ? [
        `Signed gateway receipt count: ${report.gateway.signed_count}.`,
        report.gateway.signer_dids[0] ? `Gateway signer DID: ${report.gateway.signer_dids[0]}.` : null,
        report.gateway.gateway_id ? `Gateway identity: ${report.gateway.gateway_id}.` : null,
        report.gateway.provider && report.gateway.model
          ? `Provider/model: ${report.gateway.provider} / ${report.gateway.model}.`
          : null,
      ].filter(Boolean) as string[]
    : ['No signed gateway receipt is present in the bundle yet.'];

  const gatewayBucket: ProofReviewBucket = {
    key: 'gateway_proof',
    label: 'Gateway proof',
    tone: report.gateway.signed_count > 0 ? 'good' : 'action',
    summary:
      report.gateway.signed_count > 0
        ? `${report.gateway.signed_count} signed gateway ${pluralize(report.gateway.signed_count, 'receipt')} ${report.gateway.provider && report.gateway.model ? `${report.gateway.signed_count === 1 ? 'covers' : 'cover'} ${report.gateway.provider} / ${report.gateway.model}` : 'present'}${report.gateway.gateway_id ? ` via ${report.gateway.gateway_id}` : ''}.`
        : 'Gateway-tier proof is not complete yet because no signed gateway receipt was found.',
    items: gatewayItems,
  };

  const executionItems: string[] = [];
  const runtimeProfileLabel = report.sentinels.runtime_profile.profile_id
    ? `${report.sentinels.runtime_profile.profile_id}${report.sentinels.runtime_profile.status ? ` (${report.sentinels.runtime_profile.status})` : ''}`
    : null;
  if (runtimeProfileLabel) {
    executionItems.push(`Runtime profile: ${runtimeProfileLabel}.`);
  }
  if (report.sentinels.runtime_hygiene.verdict) {
    executionItems.push(`Runtime hygiene verdict: ${report.sentinels.runtime_hygiene.verdict.toUpperCase()}.`);
  }
  if (report.sentinels.interpose_active) {
    executionItems.push('Interpose monitoring was active during the run.');
  } else {
    executionItems.push('Interpose monitoring was not active for this run.');
  }
  executionItems.push(...report.sentinels.runtime_hygiene.caution_signals);
  executionItems.push(...report.sentinels.runtime_hygiene.action_required_signals);
  if (
    report.sentinels.interpose_active &&
    report.sentinels.runtime_hygiene.caution_signals.length === 0 &&
    report.sentinels.runtime_hygiene.action_required_signals.length === 0
  ) {
    executionItems.push('No unmonitored spawns or escape flags were recorded.');
  }

  const executionTone: ProofReviewBucketTone = (() => {
    if (report.sentinels.runtime_hygiene.verdict === 'action') return 'action';
    if (report.sentinels.runtime_hygiene.verdict === 'caution') return 'caution';
    if (report.sentinels.runtime_hygiene.verdict === 'good') return 'good';
    if (report.sentinels.escapes_suspected || report.sentinels.unmonitored_spawns > 0) return 'action';
    if (report.sentinels.unmediated_connections > 0 || !report.sentinels.interpose_active) return 'caution';
    return 'good';
  })();

  const executionBucket: ProofReviewBucket = {
    key: 'execution_hygiene',
    label: 'Execution hygiene',
    tone: executionTone,
    summary:
      executionTone === 'good'
        ? 'Execution telemetry looks clean for reviewer-facing proof presentation.'
        : executionTone === 'caution'
          ? 'Execution telemetry captured the run, but there are environment-level signals worth noting.'
          : 'Execution telemetry recorded signals that should be explained before treating the run as clean external evidence.',
    items: executionItems,
  };

  const infraCount = report.network.classification_counts.infrastructure ?? 0;
  const expectedCount = report.network.classification_counts.expected ?? 0;
  const systemNoiseCount = report.network.classification_counts.system_noise ?? 0;
  const localCount = report.network.classification_counts.local ?? 0;
  const fdInheritanceCount = report.network.classification_counts.fd_inheritance ?? 0;
  const backgroundCount = Object.entries(report.network.classification_counts)
    .filter(([key]) => BACKGROUND_NETWORK_CLASSIFICATIONS.has(key))
    .reduce((sum, [, count]) => sum + count, 0);
  const backgroundBucket: ProofReviewBucket = {
    key: 'background_noise',
    label: 'Background noise / ignorable infra',
    tone: backgroundSignals.length > 0 || backgroundCount > 0 ? 'info' : 'good',
    summary:
      backgroundSignals.length > 0
        ? backgroundSignals[0]!
        : backgroundCount > 0
        ? `${backgroundCount} network ${pluralize(backgroundCount, 'receipt')} look like environment/background traffic, led by ${formatTopProcesses(report.network.top_processes)}.`
        : 'No notable background or infrastructure traffic was recorded.',
    items: [
      ...backgroundSignals,
      infraCount > 0 ? `${infraCount} ${pluralize(infraCount, 'receipt')} were classified as infrastructure traffic.` : null,
      expectedCount > 0 ? `${expectedCount} ${pluralize(expectedCount, 'receipt')} were classified as expected traffic.` : null,
      systemNoiseCount > 0 ? `${systemNoiseCount} ${pluralize(systemNoiseCount, 'receipt')} were classified as system noise.` : null,
      localCount > 0 ? `${localCount} ${pluralize(localCount, 'receipt')} were classified as local traffic.` : null,
      fdInheritanceCount > 0 ? `${fdInheritanceCount} ${pluralize(fdInheritanceCount, 'receipt')} were classified as FD inheritance noise.` : null,
      backgroundCount > 0 && report.network.top_processes.length > 0
        ? `Top observed processes: ${formatTopProcesses(report.network.top_processes)}.`
        : null,
    ].filter(Boolean) as string[],
  };

  const reviewerActionItems: string[] = [];
  if (report.gateway.signed_count === 0) {
    reviewerActionItems.push('Do not present this run as gateway-tier proof until a signed gateway receipt is present.');
  }
  if (report.sentinels.net_suspicious > 0) {
    reviewerActionItems.push(`Review ${report.sentinels.net_suspicious} suspicious network ${pluralize(report.sentinels.net_suspicious, 'receipt')} in the raw bundle before external sharing.`);
  }
  if (report.sentinels.unmediated_connections > 0) {
    reviewerActionItems.push('Decide whether the CLDD unmediated-connection signal is expected for this runtime or should be suppressed/tuned for cleaner reports.');
  }
  if (report.sentinels.unmonitored_spawns > 0) {
    reviewerActionItems.push(`Confirm ${report.sentinels.unmonitored_spawns} unmonitored ${pluralize(report.sentinels.unmonitored_spawns, 'spawn')} are expected for this environment.`);
  }
  if (report.sentinels.escapes_suspected) {
    reviewerActionItems.push('Resolve or explain the CLDD escape-suspected signal before using this as buyer-facing proof.');
  }
  if (
    report.privacy_posture.runner_attestation.reason_code ===
    'ATTESTED_TIER_NOT_GRANTED_REVOKED_POLICY_ISSUER'
  ) {
    reviewerActionItems.push(
      'Do not treat this run as attested because policy issuer trust-root metadata marks the signer key as revoked.',
    );
  }
  if (
    report.privacy_posture.runner_attestation.reason_code ===
    'ATTESTED_TIER_NOT_GRANTED_REVOKED_RUNNER'
  ) {
    reviewerActionItems.push(
      'Do not treat this run as attested because runner attestation metadata marks the signer key as revoked.',
    );
  }
  if (report.reviewer_signoff.revoked_receipt_count > 0) {
    const revokedVerb = report.reviewer_signoff.revoked_receipt_count === 1 ? 'was' : 'were';
    reviewerActionItems.push(
      `${report.reviewer_signoff.revoked_receipt_count} reviewer signoff ${pluralize(report.reviewer_signoff.revoked_receipt_count, 'receipt')} ${revokedVerb} marked revoked by reviewer trust-root metadata.`,
    );
  }

  const reviewerActionBucket: ProofReviewBucket = {
    key: 'reviewer_action_needed',
    label: 'Reviewer action needed',
    tone: reviewerActionItems.length > 0 ? 'action' : 'good',
    summary:
      reviewerActionItems.length > 0
        ? `${reviewerActionItems.length} reviewer ${pluralize(reviewerActionItems.length, 'follow-up')} remain before this report reads as clean external evidence.`
        : 'No extra reviewer follow-up is needed beyond standard verifier checks.',
    items: reviewerActionItems.length > 0 ? reviewerActionItems : ['No extra reviewer action is required.'],
  };

  return [gatewayBucket, executionBucket, backgroundBucket, reviewerActionBucket];
}

function deriveWarnings(report: ProofReportBase): string[] {
  const warnings: string[] = [];

  if (report.gateway.signed_count === 0) {
    warnings.push('No signed gateway receipt found in the bundle.');
  }
  if (report.sentinels.net_suspicious > 0) {
    warnings.push(`${report.sentinels.net_suspicious} suspicious network events were recorded.`);
  }
  if (report.sentinels.unmediated_connections > 0) {
    warnings.push(`${report.sentinels.unmediated_connections} unmediated connections were observed by CLDD.`);
  }
  if (report.sentinels.unmonitored_spawns > 0) {
    warnings.push(`${report.sentinels.unmonitored_spawns} unmonitored spawns were detected.`);
  }
  if (report.sentinels.escapes_suspected) {
    warnings.push('CLDD marked the run as escape-suspected.');
  }
  if (report.sentinels.runtime_profile.status === 'fallback') {
    warnings.push(
      `Runtime profile fallback is active (${report.sentinels.runtime_profile.fallback_reasons.join(', ') || 'unspecified reason'}).`,
    );
  }
  if (report.sentinels.runtime_hygiene.verdict === 'action') {
    warnings.push('Runtime hygiene verdict is ACTION; reviewer follow-up is required.');
  } else if (report.sentinels.runtime_hygiene.verdict === 'caution') {
    warnings.push('Runtime hygiene verdict is CAUTION; confirm the noted runtime signals are expected.');
  }
  if (report.privacy_posture.overall_verdict === 'action') {
    warnings.push('Privacy posture verdict is ACTION; reviewer follow-up is required.');
  } else if (report.privacy_posture.overall_verdict === 'caution') {
    warnings.push('Privacy posture verdict is CAUTION; verify missing/flagged privacy evidence before external sharing.');
  }
  if (
    report.privacy_posture.runner_attestation.reason_code ===
    'ATTESTED_TIER_NOT_GRANTED_REVOKED_POLICY_ISSUER'
  ) {
    warnings.push('Policy issuer trust-root key is revoked in signed policy metadata.');
  }
  if (
    report.privacy_posture.runner_attestation.reason_code ===
    'ATTESTED_TIER_NOT_GRANTED_REVOKED_RUNNER'
  ) {
    warnings.push('Runner attestation trust-root key is revoked in runner metadata.');
  }
  if (report.reviewer_signoff.structured_receipt_count < report.reviewer_signoff.receipt_count) {
    const invalidReceiptCount =
      report.reviewer_signoff.receipt_count - report.reviewer_signoff.structured_receipt_count;
    warnings.push(
      `${invalidReceiptCount} reviewer signoff ${pluralize(invalidReceiptCount, 'receipt')} failed local integrity or binding checks in the report summary.`,
    );
  }
  if (report.reviewer_signoff.revoked_receipt_count > 0) {
    const revokedVerb = report.reviewer_signoff.revoked_receipt_count === 1 ? 'was' : 'were';
    warnings.push(
      `${report.reviewer_signoff.revoked_receipt_count} reviewer signoff ${pluralize(report.reviewer_signoff.revoked_receipt_count, 'receipt')} ${revokedVerb} marked revoked by reviewer trust-root metadata.`,
    );
  }
  if (report.reviewer_signoff.decision_counts.reject > 0) {
    warnings.push(
      `${report.reviewer_signoff.decision_counts.reject} reviewer signoff ${pluralize(report.reviewer_signoff.decision_counts.reject, 'receipt')} recorded decision=reject.`,
    );
  }
  if (report.reviewer_signoff.dispute_present) {
    warnings.push(
      `Reviewer dispute notes are present (${report.reviewer_signoff.dispute_note_count} notes, ${report.reviewer_signoff.dispute_evidence_refs_count} evidence refs).`,
    );
  }
  for (const signal of report.privacy_posture.signal_buckets.reviewer_action_required.slice(0, 3)) {
    warnings.push(`Privacy signal: ${signal}`);
  }

  if (report.compiled_evidence.envelope_present && !report.compiled_evidence.authoritative_report_present) {
    warnings.push(
      'Compiled evidence envelope is present but failed strict structural checks in the prove summary; treat compiled outcomes as untrusted until canonical compiled-report verification succeeds.',
    );
    for (const reason of report.compiled_evidence.invalid_reasons.slice(0, 3)) {
      warnings.push(`Compiled evidence signal: ${reason}`);
    }
  }

  if (
    report.compiled_evidence.authoritative_report_present &&
    report.compiled_evidence.overall_status &&
    report.compiled_evidence.overall_status !== 'PASS'
  ) {
    warnings.push(
      `Compiled evidence overall status is ${report.compiled_evidence.overall_status}; review non-pass controls before presenting compliance outcomes as clean.`,
    );
  }

  return warnings;
}

function deriveNextSteps(
  report: Pick<ProofReport, 'gateway' | 'warnings' | 'verify_command' | 'privacy_posture' | 'reviewer_signoff' | 'compiled_evidence'>,
): string[] {
  const steps: string[] = [];
  if (report.gateway.signed_count > 0) {
    steps.push('Signed gateway evidence is present; attach this report to PRs, submissions, or reviews.');
  } else {
    steps.push('Re-run under clawproxy mode until a signed gateway receipt is present.');
  }
  if (report.privacy_posture.reviewer_action_required) {
    steps.push('Resolve reviewer-action-required privacy signals before making external privacy-assurance claims.');
  } else if (report.privacy_posture.overall_verdict === 'caution') {
    steps.push('Confirm caution-level privacy signals are expected before sharing this report externally.');
  } else {
    steps.push('Privacy posture evidence is clean enough for reviewer-facing discussion, subject to claim limits.');
  }
  if (report.privacy_posture.runner_attestation.posture === 'attested') {
    steps.push('Runner attestation posture is ATTESTED in this report; still run canonical verification before relying on attested-tier claims.');
  } else if (
    report.privacy_posture.runner_attestation.reason_code ===
    'ATTESTED_TIER_NOT_GRANTED_REVOKED_POLICY_ISSUER'
  ) {
    steps.push('Policy issuer trust-root key is revoked; rotate/reissue policy bundle signing keys before claiming attested posture.');
  } else if (
    report.privacy_posture.runner_attestation.reason_code ===
    'ATTESTED_TIER_NOT_GRANTED_REVOKED_RUNNER'
  ) {
    steps.push('Runner attestation trust-root key is revoked; rotate runner attestation signer keys before claiming attested posture.');
  } else {
    steps.push('Runner attestation posture is NON-ATTESTED; avoid making attested-tier runtime integrity claims for this run.');
  }
  if (report.reviewer_signoff.dispute_present) {
    steps.push('Resolve reviewer dispute notes/evidence references before final signoff or payout decisions.');
  } else if (report.reviewer_signoff.revoked_receipt_count > 0) {
    steps.push('Reviewer signoff metadata marks one or more reviewer keys as revoked; replace those signoff receipts before relying on reviewer approvals.');
  } else if (report.reviewer_signoff.structured_receipt_count > 0) {
    steps.push('Reviewer signoff receipts are present; verify decisions and binding targets before external reliance.');
  } else if (report.reviewer_signoff.receipt_count > 0) {
    steps.push('Reviewer signoff receipt objects are present, but some failed local integrity or binding validation; inspect them before external reliance.');
  }

  if (report.compiled_evidence.envelope_present) {
    const compiledEnvelopePath =
      report.compiled_evidence.artifact_paths?.envelope ??
      EXPORT_PACK_COMPILED_REPORT_ENVELOPE_PATH;
    if (report.compiled_evidence.authoritative_report_present) {
      steps.push(
        `Compiled evidence envelope is present; run canonical compiled-report verification: clawverify verify compiled-report --input ${compiledEnvelopePath}`,
      );
      if (
        report.compiled_evidence.overall_status &&
        report.compiled_evidence.overall_status !== 'PASS'
      ) {
        steps.push(
          `Compiled matrix status is ${report.compiled_evidence.overall_status}; review non-pass controls before external compliance assertions.`,
        );
      }
    } else {
      steps.push(
        'Compiled evidence envelope is present but failed strict summary checks; inspect compiled invalid markers before treating any compiled outcomes as authoritative.',
      );
    }
  }

  steps.push(`Canonical offline verifier command: ${report.verify_command}`);
  if (report.warnings.length > 0) {
    steps.push('Review the bucketed warning/action cards before treating the run as clean reviewer-facing evidence.');
  }
  return steps;
}

export function buildProofReport(args: {
  inputPath: string;
  bundle: Record<string, unknown>;
  runSummary: Record<string, unknown> | null;
  decryptedPayload?: Record<string, unknown>;
}): ProofReport {
  const { inputPath, bundle, runSummary, decryptedPayload } = args;
  const publicLayer = extractPublicLayer(bundle);
  const payload = isRecord(bundle.payload) ? bundle.payload : {};
  const gateway = summarizeGateway(payload);
  const sentinels = summarizeSentinels(payload);
  const network = summarizeNetwork(payload);
  const reviewerSignoff = summarizeReviewerSignoff(payload);
  const harnessStatus = asString(runSummary?.status);
  const harnessTier = asString(runSummary?.tier);
  const harnessTrustTier = asString(runSummary?.trust_tier);
  const privacyPosture = summarizePrivacyPosture({
    payload,
    sentinels,
    claimedTier: harnessTier,
    claimedTrustTier: harnessTrustTier,
  });
  const compiledEvidence = extractCompiledEvidence(payload).summary;

  const base: ProofReportBase = {
    public_layer: publicLayer,
    harness: {
      status: harnessStatus,
      tier: harnessTier,
      trust_tier: harnessTrustTier,
      duration_seconds: asNumber(runSummary?.duration_seconds),
      timestamp: asString(runSummary?.timestamp),
      did: asString(runSummary?.did),
    },
    evidence: {
      event_chain_count: asArray(payload.event_chain).length,
      receipt_count: asArray(payload.receipts).length,
      execution_receipt_count: asArray(payload.execution_receipts).length,
      network_receipt_count: asArray(payload.network_receipts).length,
      tool_receipt_count: asArray(payload.tool_receipts).length,
      files_modified_count: Array.isArray(runSummary?.files_modified) ? runSummary.files_modified.length : null,
      tools_used_count: Array.isArray(runSummary?.tools_used) ? runSummary.tools_used.length : null,
    },
    gateway,
    sentinels,
    network,
    reviewer_signoff: reviewerSignoff,
    privacy_posture: privacyPosture,
    compiled_evidence: compiledEvidence,
    decrypted_payload_keys: decryptedPayload ? Object.keys(decryptedPayload) : undefined,
  };

  const reviewBuckets = deriveReviewBuckets(base);
  const warnings = deriveWarnings(base);
  const verifyCommand = `clawverify verify proof-bundle --input ${inputPath}`;

  return {
    input_path: inputPath,
    run_summary_path: runSummary ? inferRunSummaryPath(inputPath) : null,
    generated_at: new Date().toISOString(),
    ...base,
    review_buckets: reviewBuckets,
    warnings,
    next_steps: deriveNextSteps({
      gateway,
      warnings,
      verify_command: verifyCommand,
      privacy_posture: privacyPosture,
      reviewer_signoff: reviewerSignoff,
      compiled_evidence: compiledEvidence,
    }),
    verify_command: verifyCommand,
  };
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function renderList(items: string[]): string {
  if (items.length === 0) return '<li>None</li>';
  return items.map((item) => `<li>${escapeHtml(item)}</li>`).join('');
}

function renderKeyValueRows(rows: Array<[string, string | number | null | undefined]>): string {
  return rows
    .map(([label, value]) => `<div class="row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value == null ? '—' : String(value))}</strong></div>`)
    .join('');
}

function formatProcessorRoute(route: ProofPrivacyProcessorRoute): string {
  return `${route.provider} / ${route.model} (${route.region}, ${route.retention_profile}) x${route.count}`;
}

function formatProcessorBlockedAttempt(attempt: ProofPrivacyProcessorBlockedAttempt): string {
  const route = `${attempt.route.provider} / ${attempt.route.model} (${attempt.route.region}, ${attempt.route.retention_profile})`;
  return `${route} — ${attempt.reason_code}${attempt.timestamp ? ` @ ${attempt.timestamp}` : ''}`;
}

function formatActionCount(actionCount: ProofPrivacyActionCount): string {
  return `${actionCount.action}: ${actionCount.count}`;
}

function formatSensitiveClass(entry: ProofPrivacySensitiveClass): string {
  return `${entry.class_id} — matches=${entry.match_count}, actions=${entry.actions.join(', ')}`;
}

function formatAllowedEgressDestination(kind: 'proxy' | 'child', host: string): string {
  return `${kind}: ${host}`;
}

function toneToPillClass(tone: ProofReviewBucketTone): string {
  switch (tone) {
    case 'good':
      return 'ok';
    case 'caution':
      return 'warn';
    case 'action':
      return 'danger';
    default:
      return 'info';
  }
}

function renderReviewBucket(bucket: ProofReviewBucket): string {
  return `<article class="card">
    <div class="bucket-header">
      <h2>${escapeHtml(bucket.label)}</h2>
      <span class="pill ${toneToPillClass(bucket.tone)}">${escapeHtml(bucket.tone.toUpperCase())}</span>
    </div>
    <p class="bucket-summary">${escapeHtml(bucket.summary)}</p>
    <ul>${renderList(bucket.items)}</ul>
  </article>`;
}

export function renderProofReportHtml(report: ProofReport): string {
  const reviewerActionBucket = report.review_buckets.find((bucket) => bucket.key === 'reviewer_action_needed');
  const warningsClass = (reviewerActionBucket?.tone === 'action' || report.warnings.length > 0) ? 'warn' : 'ok';
  const reviewerActionCount = reviewerActionBucket?.items.length ?? 0;
  const privacyPillClass = toneToPillClass(report.privacy_posture.overall_verdict);
  const usedProcessorItems = report.privacy_posture.processor_policy.used_processors.map(formatProcessorRoute);
  const blockedProcessorItems = report.privacy_posture.processor_policy.blocked_attempts.map(formatProcessorBlockedAttempt);
  const dataHandlingActionItems = report.privacy_posture.data_handling.actions.map(formatActionCount);
  const sensitiveClassItems = report.privacy_posture.data_handling.sensitive_classes.map(formatSensitiveClass);
  const allowedEgressItems = [
    ...report.privacy_posture.egress.allowed_proxy_destinations.map((host) => formatAllowedEgressDestination('proxy', host)),
    ...report.privacy_posture.egress.allowed_child_destinations.map((host) => formatAllowedEgressDestination('child', host)),
  ];
  const reviewerDecisionSummary = `approve=${report.reviewer_signoff.decision_counts.approve}, reject=${report.reviewer_signoff.decision_counts.reject}, needs_changes=${report.reviewer_signoff.decision_counts.needs_changes}`;
  const reviewerTargetSummary = `run=${report.reviewer_signoff.target_counts.run}, export_pack=${report.reviewer_signoff.target_counts.export_pack}`;
  const compiledStatusLabel = !report.compiled_evidence.envelope_present
    ? 'MISSING'
    : report.compiled_evidence.authoritative_report_present
      ? 'AUTHORITATIVE'
      : 'INVALID';
  const compiledPillClass = !report.compiled_evidence.envelope_present
    ? 'info'
    : report.compiled_evidence.authoritative_report_present
      ? 'ok'
      : 'warn';
  const compiledEvidenceRefItems = [
    `proof_bundle_hash_b64u: ${report.compiled_evidence.evidence_refs.proof_bundle_hash_b64u ?? 'unknown'}`,
    `ontology_hash_b64u: ${report.compiled_evidence.evidence_refs.ontology_hash_b64u ?? 'unknown'}`,
    `mapping_rules_hash_b64u: ${report.compiled_evidence.evidence_refs.mapping_rules_hash_b64u ?? 'unknown'}`,
    `verify_result_hash_b64u: ${report.compiled_evidence.evidence_refs.verify_result_hash_b64u ?? 'unknown'}`,
  ];
  const compiledNarrativeItems = !report.compiled_evidence.narrative.present
    ? ['No narrative plane embedded in compiled payload.']
    : [
      `Narrative present with authoritative=${report.compiled_evidence.narrative.authoritative_flag === null ? 'unknown' : report.compiled_evidence.narrative.authoritative_flag ? 'true' : 'false'}.`,
      `Disclaimer: ${report.compiled_evidence.narrative.disclaimer ?? 'missing'}`,
      'Narrative remains non-authoritative explanatory text only.',
    ];
  const compiledArtifactItems = report.compiled_evidence.artifact_paths
    ? [
      `Envelope: ${report.compiled_evidence.artifact_paths.envelope}`,
      report.compiled_evidence.artifact_paths.report
        ? `Report payload: ${report.compiled_evidence.artifact_paths.report}`
        : null,
      report.compiled_evidence.artifact_paths.summary
        ? `Summary: ${report.compiled_evidence.artifact_paths.summary}`
        : null,
      report.compiled_evidence.artifact_paths.narrative
        ? `Narrative: ${report.compiled_evidence.artifact_paths.narrative}`
        : null,
    ].filter((item): item is string => item !== null)
    : ['No export-pack artifact paths available in this report context.'];
  const compiledCard = report.compiled_evidence.envelope_present
    ? `<article class="card">
        <h2>Compiled evidence (authoritative matrix)</h2>
        ${renderKeyValueRows([
          ['Compiled status', compiledStatusLabel],
          ['Report ID', report.compiled_evidence.report_id],
          ['Compiler version', report.compiled_evidence.compiler_version],
          ['Overall status', report.compiled_evidence.overall_status],
          ['Matrix hash', report.compiled_evidence.matrix_hash_b64u],
          ['Envelope payload hash', report.compiled_evidence.payload_hash_b64u],
          ['Signer DID', report.compiled_evidence.signer_did],
          ['Issued at', report.compiled_evidence.issued_at],
          ['Total controls', report.compiled_evidence.control_outcome_counts.total],
          ['PASS controls', report.compiled_evidence.control_outcome_counts.pass],
          ['FAIL controls', report.compiled_evidence.control_outcome_counts.fail],
          ['PARTIAL controls', report.compiled_evidence.control_outcome_counts.partial],
          ['INAPPLICABLE controls', report.compiled_evidence.control_outcome_counts.inapplicable],
          ['FAIL_CLOSED controls', report.compiled_evidence.control_outcome_counts.fail_closed_invalid_evidence],
        ])}
        <div class="subheading">Non-pass controls</div>
        <ul>${renderList(report.compiled_evidence.non_pass_controls)}</ul>
        <div class="subheading">Evidence refs</div>
        <ul>${renderList(compiledEvidenceRefItems)}</ul>
        <div class="subheading">Narrative membrane</div>
        <ul>${renderList(compiledNarrativeItems)}</ul>
        <div class="subheading">Artifact linkage</div>
        <ul>${renderList(compiledArtifactItems)}</ul>
        ${report.compiled_evidence.invalid_reasons.length > 0 ? `<div class="subheading">Invalid/unsafe markers</div><ul>${renderList(report.compiled_evidence.invalid_reasons)}</ul>` : ''}
      </article>`
    : `<article class="card">
        <h2>Compiled evidence (authoritative matrix)</h2>
        <p class="subtitle">No compiled report envelope was detected in bundle metadata for this report.</p>
      </article>`;
  const runComparisonCard = report.run_comparison
    ? `<article class="card">
        <h2>Side-by-side run comparison</h2>
        ${renderKeyValueRows([
          ['Baseline source type', report.run_comparison.baseline_source.type],
          ['Baseline bundle ID', report.run_comparison.baseline.bundle_id],
          ['Candidate bundle ID', report.run_comparison.candidate.bundle_id],
        ])}
        <div class="subheading">Reviewer highlights</div>
        <ul>${renderList(report.run_comparison.reviewer_highlights)}</ul>
      </article>`
    : '';
  const rawJson = escapeHtml(JSON.stringify(report, null, 2));

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clawsig proof report</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #07111f;
      --panel: rgba(12, 23, 40, 0.88);
      --line: rgba(148, 163, 184, 0.18);
      --text: #e6eef8;
      --muted: #95a7bf;
      --accent: #76e4c3;
      --warn: #f6c177;
      --danger: #f38ba8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at top, #0d2340 0%, var(--bg) 58%);
      color: var(--text);
      line-height: 1.5;
    }
    main { max-width: 1100px; margin: 0 auto; padding: 32px 20px 72px; }
    .hero, .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 20px;
      box-shadow: 0 20px 80px rgba(0,0,0,0.28);
    }
    .hero { padding: 28px; margin-bottom: 20px; }
    h1, h2, h3, p { margin: 0; }
    .eyebrow { color: var(--accent); text-transform: uppercase; letter-spacing: .12em; font-size: 12px; margin-bottom: 10px; }
    .subtitle { color: var(--muted); margin-top: 10px; max-width: 760px; }
    .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }
    .card { padding: 20px; }
    .card h2 { font-size: 16px; margin-bottom: 14px; }
    .row { display: flex; justify-content: space-between; gap: 16px; padding: 8px 0; border-bottom: 1px solid rgba(148, 163, 184, 0.08); }
    .row:last-child { border-bottom: 0; }
    .row span { color: var(--muted); }
    .pill {
      display: inline-flex; align-items: center; gap: 8px;
      border-radius: 999px; padding: 8px 12px; font-size: 13px; margin: 6px 8px 0 0;
      border: 1px solid var(--line);
      color: var(--text);
    }
    .pill.ok { background: rgba(118, 228, 195, 0.12); border-color: rgba(118, 228, 195, 0.35); }
    .pill.warn { background: rgba(246, 193, 119, 0.14); border-color: rgba(246, 193, 119, 0.35); }
    .pill.danger { background: rgba(243, 139, 168, 0.14); border-color: rgba(243, 139, 168, 0.35); }
    .pill.info { background: rgba(147, 197, 253, 0.12); border-color: rgba(147, 197, 253, 0.35); }
    .bucket-header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .bucket-summary { margin-top: 10px; color: var(--text); }
    ul { margin: 10px 0 0 18px; color: var(--muted); }
    li + li { margin-top: 8px; }
    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    pre {
      margin: 0; white-space: pre-wrap; word-break: break-word;
      padding: 16px; border-radius: 16px; background: rgba(2, 6, 23, 0.58); border: 1px solid rgba(148,163,184,0.12);
      color: #d7e3f4; font-size: 12px;
    }
    details { margin-top: 16px; }
    summary { cursor: pointer; color: var(--accent); }
    .footer-note { color: var(--muted); font-size: 13px; margin-top: 18px; }
    .subheading { margin-top: 14px; font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="eyebrow">Clawsig proof report</div>
      <h1>Human-readable proof bundle view</h1>
      <p class="subtitle">This report renders the proof bundle into reviewer-facing evidence. Canonical verification still comes from the bundle itself and the offline verifier/service verifier.</p>
      <div>
        <span class="pill ok">Harness status: ${escapeHtml(report.harness.status ?? 'unknown')}</span>
        <span class="pill ok">Claimed tier: ${escapeHtml(report.harness.tier ?? 'unknown')}</span>
        <span class="pill info">Claimed trust tier: ${escapeHtml(report.harness.trust_tier ?? 'unknown')}</span>
        <span class="pill ${warningsClass}">Reviewer actions: ${reviewerActionCount}</span>
        <span class="pill ${privacyPillClass}">Privacy verdict: ${escapeHtml(report.privacy_posture.overall_verdict.toUpperCase())}</span>
        <span class="pill ${compiledPillClass}">Compiled matrix: ${escapeHtml(compiledStatusLabel)}</span>
        <span class="pill ok">Signed gateway receipts: ${report.gateway.signed_count}</span>
      </div>
    </section>

    <section class="grid" style="margin-bottom:16px;">
      ${report.review_buckets.map(renderReviewBucket).join('')}
    </section>

    <section class="grid" style="margin-bottom:16px;">
      <article class="card">
        <h2>Privacy posture</h2>
        ${renderKeyValueRows([
          ['Overall verdict', report.privacy_posture.overall_verdict],
          ['Reviewer action required', report.privacy_posture.reviewer_action_required ? 'yes' : 'no'],
          ['Runner attestation posture', report.privacy_posture.runner_attestation.posture],
          ['Attested-tier reason code', report.privacy_posture.runner_attestation.reason_code],
          ['Attested tier claimed', report.privacy_posture.runner_attestation.attested_tier_claimed ? 'yes' : 'no'],
          ['Egress policy evidence', report.privacy_posture.evidence.egress_policy_receipt_present ? 'present' : 'missing'],
          ['Processor policy evidence', report.privacy_posture.evidence.processor_policy_evidence_present ? 'present' : 'missing'],
          ['Data-handling evidence', report.privacy_posture.evidence.data_handling_receipts_present ? 'present' : 'missing'],
          ['Runtime hygiene evidence', report.privacy_posture.evidence.runtime_hygiene_present ? 'present' : 'missing'],
          ['Runner measurement evidence', describeAttestationEvidenceState(
            report.privacy_posture.runner_attestation.evidence.runner_measurement_present,
            report.privacy_posture.runner_attestation.evidence.runner_measurement_structured,
          )],
          ['Runner attestation receipt', describeAttestationEvidenceState(
            report.privacy_posture.runner_attestation.evidence.runner_attestation_receipt_present,
            report.privacy_posture.runner_attestation.evidence.runner_attestation_receipt_structured,
          )],
          ['Runner attestation bindings', report.privacy_posture.runner_attestation.evidence.binding_consistent ? 'consistent' : 'not established'],
        ])}
        <div class="subheading">What Is Proven</div>
        <ul>${renderList(report.privacy_posture.proven_claims)}</ul>
        <div class="subheading">What Is Not Proven</div>
        <ul>${renderList(report.privacy_posture.not_proven_claims)}</ul>
      </article>

      ${compiledCard}

      <article class="card">
        <h2>Allowed processors and blocked routes</h2>
        ${renderKeyValueRows([
          ['Processor profile', report.privacy_posture.processor_policy.profile_id],
          ['Policy version', report.privacy_posture.processor_policy.policy_version],
          ['Policy enforce', report.privacy_posture.processor_policy.enforce === null ? null : report.privacy_posture.processor_policy.enforce ? 'true' : 'false'],
          ['Allowed routes', report.privacy_posture.processor_policy.allowed_routes],
          ['Denied routes', report.privacy_posture.processor_policy.denied_routes],
          ['Blocked egress attempts', report.privacy_posture.egress.blocked_attempt_count],
          ['Direct providers blocked', report.privacy_posture.egress.direct_provider_access_blocked === null ? null : report.privacy_posture.egress.direct_provider_access_blocked ? 'true' : 'false'],
        ])}
        <div class="subheading">Used Processors</div>
        <ul>${renderList(usedProcessorItems)}</ul>
        <div class="subheading">Blocked Processor Attempts</div>
        <ul>${renderList(blockedProcessorItems)}</ul>
      </article>

      <article class="card">
        <h2>Sensitive classes and actions</h2>
        ${renderKeyValueRows([
          ['Data-handling policy', report.privacy_posture.data_handling.policy_version],
          ['Data-handling receipts', report.privacy_posture.data_handling.receipt_count],
          ['Approval required', report.privacy_posture.data_handling.approval_required_count],
          ['Approval satisfied', report.privacy_posture.data_handling.approval_satisfied_count],
          ['Approval unsatisfied', report.privacy_posture.data_handling.approval_unsatisfied_count],
          ['Redaction applied', report.privacy_posture.data_handling.redaction_applied_count],
          ['Runtime hygiene verdict', report.privacy_posture.runtime.hygiene_verdict],
          ['Runtime profile', report.privacy_posture.runtime.profile_id],
          ['Runtime profile status', report.privacy_posture.runtime.profile_status],
        ])}
        <div class="subheading">Data-handling actions</div>
        <ul>${renderList(dataHandlingActionItems)}</ul>
        <div class="subheading">Sensitive classes</div>
        <ul>${renderList(sensitiveClassItems)}</ul>
        <div class="subheading">Reason codes</div>
        <ul>${renderList(report.privacy_posture.data_handling.reason_codes)}</ul>
      </article>

      <article class="card">
        <h2>Privacy signal buckets</h2>
        <div class="subheading">Background noise</div>
        <ul>${renderList(report.privacy_posture.signal_buckets.background_noise)}</ul>
        <div class="subheading">Caution</div>
        <ul>${renderList(report.privacy_posture.signal_buckets.caution)}</ul>
        <div class="subheading">Reviewer action required</div>
        <ul>${renderList(report.privacy_posture.signal_buckets.reviewer_action_required)}</ul>
        <div class="subheading">Allowed egress destinations</div>
        <ul>${renderList(allowedEgressItems)}</ul>
      </article>

      <article class="card">
        <h2>Reviewer signoff/dispute</h2>
        ${renderKeyValueRows([
          ['Signoff receipts present', report.reviewer_signoff.present ? 'yes' : 'no'],
          ['Signoff receipt count', report.reviewer_signoff.receipt_count],
          ['Structured signoff count', report.reviewer_signoff.structured_receipt_count],
          ['Revoked signoff count', report.reviewer_signoff.revoked_receipt_count],
          ['Decision counts', reviewerDecisionSummary],
          ['Target counts', reviewerTargetSummary],
          ['Latest signoff timestamp', report.reviewer_signoff.latest_timestamp],
          ['Dispute present', report.reviewer_signoff.dispute_present ? 'yes' : 'no'],
          ['Dispute note count', report.reviewer_signoff.dispute_note_count],
          ['Dispute evidence refs', report.reviewer_signoff.dispute_evidence_refs_count],
        ])}
        <div class="subheading">Reviewer DIDs</div>
        <ul>${renderList(report.reviewer_signoff.reviewer_dids)}</ul>
        <div class="subheading">Revoked Reviewer DIDs</div>
        <ul>${renderList(report.reviewer_signoff.revoked_reviewer_dids)}</ul>
      </article>
    </section>

    <section class="grid">
      <article class="card">
        <h2>Identity & bundle</h2>
        ${renderKeyValueRows([
          ['Bundle ID', report.public_layer.bundle_id],
          ['Agent DID', report.public_layer.agent_did],
          ['Signer DID', report.public_layer.signer_did],
          ['Visibility', report.public_layer.visibility ?? 'public'],
          ['Encrypted payload', report.public_layer.has_encrypted_payload ? 'yes' : 'no'],
          ['Generated at', report.generated_at],
        ])}
      </article>

      <article class="card">
        <h2>Gateway proof</h2>
        ${renderKeyValueRows([
          ['Provider', report.gateway.provider],
          ['Model', report.gateway.model],
          ['Gateway', report.gateway.gateway_id],
          ['Signer DID', report.gateway.signer_dids[0] ?? null],
          ['Latency (ms)', report.gateway.latency_ms],
          ['Receipt timestamp', report.gateway.timestamp],
        ])}
      </article>

      <article class="card">
        <h2>Evidence counts</h2>
        ${renderKeyValueRows([
          ['Event chain entries', report.evidence.event_chain_count],
          ['Gateway receipts', report.evidence.receipt_count],
          ['Execution receipts', report.evidence.execution_receipt_count],
          ['Network receipts', report.evidence.network_receipt_count],
          ['Tool receipts', report.evidence.tool_receipt_count],
          ['Files modified', report.evidence.files_modified_count],
          ['Tools used', report.evidence.tools_used_count],
        ])}
      </article>

      <article class="card">
        <h2>Sentinel telemetry</h2>
        ${renderKeyValueRows([
          ['Shell events', report.sentinels.shell_events],
          ['FS events', report.sentinels.fs_events],
          ['Net events', report.sentinels.net_events],
          ['Suspicious net events', report.sentinels.net_suspicious],
          ['Preload LLM events', report.sentinels.preload_llm_events],
          ['Interpose active', report.sentinels.interpose_active ? 'yes' : 'no'],
          ['Unmediated connections', report.sentinels.unmediated_connections],
          ['Unmonitored spawns', report.sentinels.unmonitored_spawns],
          ['Escapes suspected', report.sentinels.escapes_suspected ? 'yes' : 'no'],
          ['Runtime profile', report.sentinels.runtime_profile.profile_id],
          ['Profile status', report.sentinels.runtime_profile.status],
          ['Baseline process count', report.sentinels.runtime_profile.baseline_process_count],
          ['Baseline hash', report.sentinels.runtime_profile.baseline_process_hash_b64u],
          ['Hygiene verdict', report.sentinels.runtime_hygiene.verdict],
          ['Action required', report.sentinels.runtime_hygiene.reviewer_action_required ? 'yes' : 'no'],
        ])}
      </article>

      <article class="card">
        <h2>Raw warning strings (debug)</h2>
        <ul>${renderList(report.warnings)}</ul>
      </article>

      <article class="card">
        <h2>Next steps</h2>
        <ul>${renderList(report.next_steps)}</ul>
        <p class="footer-note">Verifier command: <code>${escapeHtml(report.verify_command)}</code></p>
      </article>

      ${runComparisonCard}
    </section>

    <section class="grid" style="margin-top:16px;">
      <article class="card">
        <h2>Top network processes</h2>
        <ul>${renderList(report.network.top_processes.map((entry) => `${entry.process_name} — ${entry.count}`))}</ul>
      </article>
      <article class="card">
        <h2>Network classifications</h2>
        <ul>${renderList(Object.entries(report.network.classification_counts).map(([k, v]) => `${k} — ${v}`))}</ul>
      </article>
    </section>

    <section class="card" style="margin-top:16px;">
      <h2>Raw report JSON</h2>
      <details>
        <summary>Expand canonical human-readable report payload</summary>
        <pre>${rawJson}</pre>
      </details>
    </section>
  </main>
</body>
</html>`;
}

export function renderProofReportText(report: ProofReport): string {
  const lines: string[] = [];
  const allowedEgressItems = [
    ...report.privacy_posture.egress.allowed_proxy_destinations.map((host) => formatAllowedEgressDestination('proxy', host)),
    ...report.privacy_posture.egress.allowed_child_destinations.map((host) => formatAllowedEgressDestination('child', host)),
  ];
  lines.push('');
  lines.push('=== Clawsig proof report ===');
  lines.push('');
  lines.push(`Bundle ID        : ${report.public_layer.bundle_id ?? '—'}`);
  lines.push(`Agent DID        : ${report.public_layer.agent_did ?? '—'}`);
  lines.push(`Harness status   : ${report.harness.status ?? 'unknown'}`);
  lines.push(`Claimed tier     : ${report.harness.tier ?? 'unknown'}`);
  lines.push(`Claimed trust    : ${report.harness.trust_tier ?? 'unknown'}`);
  lines.push(`Gateway proof    : ${report.gateway.signed_count > 0 ? 'SIGNED' : 'MISSING'}`);
  lines.push(`Gateway signer   : ${report.gateway.signer_dids[0] ?? '—'}`);
  lines.push(`Provider/model   : ${(report.gateway.provider ?? '—')} / ${(report.gateway.model ?? '—')}`);
  lines.push(`Runtime profile  : ${report.sentinels.runtime_profile.profile_id ?? '—'} (${report.sentinels.runtime_profile.status ?? 'unknown'})`);
  lines.push(`Hygiene verdict  : ${report.sentinels.runtime_hygiene.verdict ?? 'unknown'}`);
  lines.push(`Evidence counts  : event_chain=${report.evidence.event_chain_count}, receipts=${report.evidence.receipt_count}, network=${report.evidence.network_receipt_count}, execution=${report.evidence.execution_receipt_count}`);
  lines.push('');
  lines.push('Review buckets:');
  for (const bucket of report.review_buckets) {
    lines.push(`  ${bucket.label.padEnd(31)} [${bucket.tone.toUpperCase()}] ${bucket.summary}`);
    for (const item of bucket.items) {
      lines.push(`    - ${item}`);
    }
  }
  lines.push('');
  lines.push('Privacy posture:');
  lines.push(`  Overall verdict             : ${report.privacy_posture.overall_verdict.toUpperCase()}`);
  lines.push(`  Reviewer action required    : ${report.privacy_posture.reviewer_action_required ? 'yes' : 'no'}`);
  lines.push(`  Runner attestation posture  : ${report.privacy_posture.runner_attestation.posture.toUpperCase()}`);
  lines.push(`  Attested-tier reason code   : ${report.privacy_posture.runner_attestation.reason_code}`);
  lines.push(`  Attested tier claimed       : ${report.privacy_posture.runner_attestation.attested_tier_claimed ? 'yes' : 'no'}`);
  lines.push(`  Egress policy evidence      : ${report.privacy_posture.evidence.egress_policy_receipt_present ? 'present' : 'missing'}`);
  lines.push(`  Processor policy evidence   : ${report.privacy_posture.evidence.processor_policy_evidence_present ? 'present' : 'missing'}`);
  lines.push(`  Data-handling evidence      : ${report.privacy_posture.evidence.data_handling_receipts_present ? 'present' : 'missing'}`);
  lines.push(`  Runtime hygiene evidence    : ${report.privacy_posture.evidence.runtime_hygiene_present ? 'present' : 'missing'}`);
  lines.push(`  Runner measurement evidence : ${describeAttestationEvidenceState(
    report.privacy_posture.runner_attestation.evidence.runner_measurement_present,
    report.privacy_posture.runner_attestation.evidence.runner_measurement_structured,
  )}`);
  lines.push(`  Runner attestation receipt  : ${describeAttestationEvidenceState(
    report.privacy_posture.runner_attestation.evidence.runner_attestation_receipt_present,
    report.privacy_posture.runner_attestation.evidence.runner_attestation_receipt_structured,
  )}`);
  lines.push(`  Runner attestation bindings : ${report.privacy_posture.runner_attestation.evidence.binding_consistent ? 'consistent' : 'not established'}`);
  lines.push(`  Reviewer signoff receipts   : ${report.reviewer_signoff.receipt_count}`);
  lines.push(`  Structured signoff receipts : ${report.reviewer_signoff.structured_receipt_count}`);
  lines.push(`  Revoked signoff receipts    : ${report.reviewer_signoff.revoked_receipt_count}`);
  lines.push(`  Reviewer decisions          : approve=${report.reviewer_signoff.decision_counts.approve}, reject=${report.reviewer_signoff.decision_counts.reject}, needs_changes=${report.reviewer_signoff.decision_counts.needs_changes}`);
  lines.push(`  Reviewer target bindings    : run=${report.reviewer_signoff.target_counts.run}, export_pack=${report.reviewer_signoff.target_counts.export_pack}`);
  lines.push(`  Reviewer dispute present    : ${report.reviewer_signoff.dispute_present ? 'yes' : 'no'}`);
  lines.push(`  Reviewer dispute notes      : ${report.reviewer_signoff.dispute_note_count}`);
  lines.push(`  Reviewer dispute evidence   : ${report.reviewer_signoff.dispute_evidence_refs_count}`);
  lines.push(`  Latest reviewer timestamp   : ${report.reviewer_signoff.latest_timestamp ?? 'unknown'}`);
  lines.push('  Reviewer DIDs:');
  if (report.reviewer_signoff.reviewer_dids.length === 0) {
    lines.push('    - none recorded');
  } else {
    for (const reviewerDid of report.reviewer_signoff.reviewer_dids) {
      lines.push(`    - ${reviewerDid}`);
    }
  }
  lines.push('  Revoked reviewer DIDs:');
  if (report.reviewer_signoff.revoked_reviewer_dids.length === 0) {
    lines.push('    - none recorded');
  } else {
    for (const reviewerDid of report.reviewer_signoff.revoked_reviewer_dids) {
      lines.push(`    - ${reviewerDid}`);
    }
  }
  lines.push(`  Blocked egress attempts     : ${report.privacy_posture.egress.blocked_attempt_count ?? 0}`);
  lines.push(`  Direct providers blocked    : ${report.privacy_posture.egress.direct_provider_access_blocked === null ? 'unknown' : report.privacy_posture.egress.direct_provider_access_blocked ? 'true' : 'false'}`);
  lines.push(`  Proofed mode                : ${report.privacy_posture.egress.proofed_mode === null ? 'unknown' : report.privacy_posture.egress.proofed_mode ? 'true' : 'false'}`);
  lines.push(`  Runtime hygiene posture     : ${(report.privacy_posture.runtime.hygiene_verdict ?? 'unknown').toUpperCase()}`);
  lines.push('  Allowed egress destinations:');
  if (allowedEgressItems.length === 0) {
    lines.push('    - none recorded');
  } else {
    for (const item of allowedEgressItems) {
      lines.push(`    - ${item}`);
    }
  }
  lines.push('  Allowed processors used:');
  if (report.privacy_posture.processor_policy.used_processors.length === 0) {
    lines.push('    - none recorded');
  } else {
    for (const route of report.privacy_posture.processor_policy.used_processors) {
      lines.push(`    - ${formatProcessorRoute(route)}`);
    }
  }
  lines.push('  Blocked processor attempts:');
  if (report.privacy_posture.processor_policy.blocked_attempts.length === 0) {
    lines.push('    - none recorded');
  } else {
    for (const attempt of report.privacy_posture.processor_policy.blocked_attempts) {
      lines.push(`    - ${formatProcessorBlockedAttempt(attempt)}`);
    }
  }
  lines.push('  Sensitive classes/actions:');
  if (report.privacy_posture.data_handling.sensitive_classes.length === 0) {
    lines.push('    - none recorded');
  } else {
    for (const entry of report.privacy_posture.data_handling.sensitive_classes) {
      lines.push(`    - ${formatSensitiveClass(entry)}`);
    }
  }
  if (report.privacy_posture.data_handling.actions.length > 0) {
    lines.push(`  Data-handling action counts : ${report.privacy_posture.data_handling.actions.map(formatActionCount).join(', ')}`);
  }
  lines.push('  Background privacy signals:');
  for (const signal of report.privacy_posture.signal_buckets.background_noise) {
    lines.push(`    - ${signal}`);
  }
  if (report.privacy_posture.signal_buckets.background_noise.length === 0) {
    lines.push('    - none');
  }
  lines.push('  Caution privacy signals:');
  for (const signal of report.privacy_posture.signal_buckets.caution) {
    lines.push(`    - ${signal}`);
  }
  if (report.privacy_posture.signal_buckets.caution.length === 0) {
    lines.push('    - none');
  }
  lines.push('  Reviewer-action privacy signals:');
  for (const signal of report.privacy_posture.signal_buckets.reviewer_action_required) {
    lines.push(`    - ${signal}`);
  }
  if (report.privacy_posture.signal_buckets.reviewer_action_required.length === 0) {
    lines.push('    - none');
  }
  lines.push('  What is proven:');
  for (const claim of report.privacy_posture.proven_claims) {
    lines.push(`    - ${claim}`);
  }
  if (report.privacy_posture.proven_claims.length === 0) {
    lines.push('    - no privacy evidence claims could be established from this bundle');
  }
  lines.push('  Not proven / claim limits:');
  for (const claim of report.privacy_posture.not_proven_claims) {
    lines.push(`    - ${claim}`);
  }

  lines.push('');
  lines.push('Compiled evidence (authoritative matrix):');
  lines.push(`  Envelope present            : ${report.compiled_evidence.envelope_present ? 'yes' : 'no'}`);
  lines.push(`  Authoritative report        : ${report.compiled_evidence.authoritative_report_present ? 'yes' : 'no'}`);
  lines.push(`  Source metadata path        : ${report.compiled_evidence.metadata_path ?? 'none'}`);
  lines.push(`  Report ID                   : ${report.compiled_evidence.report_id ?? 'unknown'}`);
  lines.push(`  Compiler version            : ${report.compiled_evidence.compiler_version ?? 'unknown'}`);
  lines.push(`  Overall status              : ${report.compiled_evidence.overall_status ?? 'unknown'}`);
  lines.push(`  Matrix hash                 : ${report.compiled_evidence.matrix_hash_b64u ?? 'unknown'}`);
  lines.push(`  Envelope payload hash       : ${report.compiled_evidence.payload_hash_b64u ?? 'unknown'}`);
  lines.push(`  Signer DID                  : ${report.compiled_evidence.signer_did ?? 'unknown'}`);
  lines.push(`  Issued at                   : ${report.compiled_evidence.issued_at ?? 'unknown'}`);
  lines.push(`  Control counts              : total=${report.compiled_evidence.control_outcome_counts.total}, pass=${report.compiled_evidence.control_outcome_counts.pass}, fail=${report.compiled_evidence.control_outcome_counts.fail}, partial=${report.compiled_evidence.control_outcome_counts.partial}, inapplicable=${report.compiled_evidence.control_outcome_counts.inapplicable}, fail_closed=${report.compiled_evidence.control_outcome_counts.fail_closed_invalid_evidence}`);
  lines.push('  Evidence refs:');
  lines.push(`    - proof_bundle_hash_b64u: ${report.compiled_evidence.evidence_refs.proof_bundle_hash_b64u ?? 'unknown'}`);
  lines.push(`    - ontology_hash_b64u: ${report.compiled_evidence.evidence_refs.ontology_hash_b64u ?? 'unknown'}`);
  lines.push(`    - mapping_rules_hash_b64u: ${report.compiled_evidence.evidence_refs.mapping_rules_hash_b64u ?? 'unknown'}`);
  lines.push(`    - verify_result_hash_b64u: ${report.compiled_evidence.evidence_refs.verify_result_hash_b64u ?? 'unknown'}`);
  lines.push('  Non-pass controls:');
  if (report.compiled_evidence.non_pass_controls.length === 0) {
    lines.push('    - none');
  } else {
    for (const control of report.compiled_evidence.non_pass_controls) {
      lines.push(`    - ${control}`);
    }
  }
  lines.push(`  Narrative plane             : ${report.compiled_evidence.narrative.present ? `present (authoritative=${report.compiled_evidence.narrative.authoritative_flag === null ? 'unknown' : report.compiled_evidence.narrative.authoritative_flag ? 'true' : 'false'})` : 'not present'}`);
  if (report.compiled_evidence.narrative.present) {
    lines.push(`  Narrative disclaimer        : ${report.compiled_evidence.narrative.disclaimer ?? 'missing'}`);
  }
  if (report.compiled_evidence.artifact_paths) {
    lines.push('  Artifact paths:');
    lines.push(`    - envelope: ${report.compiled_evidence.artifact_paths.envelope}`);
    if (report.compiled_evidence.artifact_paths.report) {
      lines.push(`    - report: ${report.compiled_evidence.artifact_paths.report}`);
    }
    if (report.compiled_evidence.artifact_paths.summary) {
      lines.push(`    - summary: ${report.compiled_evidence.artifact_paths.summary}`);
    }
    if (report.compiled_evidence.artifact_paths.narrative) {
      lines.push(`    - narrative: ${report.compiled_evidence.artifact_paths.narrative}`);
    }
  }
  if (report.compiled_evidence.invalid_reasons.length > 0) {
    lines.push('  Invalid/unsafe markers:');
    for (const reason of report.compiled_evidence.invalid_reasons) {
      lines.push(`    - ${reason}`);
    }
  }

  if (report.run_comparison) {
    lines.push('');
    lines.push('Run comparison highlights:');
    lines.push(`  Baseline source type       : ${report.run_comparison.baseline_source.type}`);
    lines.push(`  Baseline bundle            : ${report.run_comparison.baseline.bundle_id ?? 'unknown'}`);
    lines.push(`  Candidate bundle           : ${report.run_comparison.candidate.bundle_id ?? 'unknown'}`);
    for (const highlight of report.run_comparison.reviewer_highlights) {
      lines.push(`  - ${highlight}`);
    }
  }
  lines.push('');
  lines.push('Next steps:');
  for (const step of report.next_steps) {
    lines.push(`  - ${step}`);
  }
  if (report.html_path) {
    lines.push('');
    lines.push(`HTML report      : ${report.html_path}`);
  }
  if (report.export_pack_path) {
    lines.push(`Export pack      : ${report.export_pack_path}`);
  }
  lines.push('');
  return lines.join('\n');
}

function printHumanReadable(report: ProofReport): void {
  process.stdout.write(renderProofReportText(report));
}

export async function runProveReport(options: ProveOptions): Promise<ProofReport> {
  const bundle = await readJsonObject(options.inputPath);
  let decryptedPayload: Record<string, unknown> | undefined;

  if (options.decrypt) {
    const { loadIdentity } = await import('./identity.js');
    const identity = await loadIdentity();
    if (!identity) {
      throw new InspectError(
        'INSPECT_NO_IDENTITY',
        'No persistent identity found. Run `clawsig init` before using --decrypt.',
      );
    }
    decryptedPayload = decryptBundle(bundle, identity as ClawsigIdentity);
  }

  const runSummaryPath = options.runSummaryPath
    ? resolve(options.runSummaryPath)
    : inferRunSummaryPath(options.inputPath);
  const runSummary = await maybeReadJsonObject(runSummaryPath);

  const report = buildProofReport({
    inputPath: resolve(options.inputPath),
    bundle,
    runSummary,
    decryptedPayload,
  });

  let runComparison: ProofRunComparison | undefined;
  if (options.compareWithPath) {
    const comparisonBaseline = await loadRunComparisonBaseline(options.compareWithPath);
    runComparison = buildProofRunComparison({
      baseline: comparisonBaseline.report,
      candidate: report,
      baselineSourceType: comparisonBaseline.sourceType,
    });
    report.run_comparison = runComparison;
  }

  if (options.htmlPath) {
    const htmlPath = resolve(options.htmlPath);
    await writeFile(htmlPath, renderProofReportHtml(report), 'utf-8');
    report.html_path = htmlPath;
  }

  if (options.exportPackPath) {
    report.export_pack_path = await writePrivacyComplianceExportPack({
      packPath: options.exportPackPath,
      bundle,
      report,
      comparison: runComparison,
    });
  }

  if (options.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printHumanReadable(report);
  }

  return report;
}
