import { access, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

import { decryptBundle, extractPublicLayer, InspectError } from './inspect-cmd.js';

import type { ClawsigIdentity } from './identity.js';

export interface ProveOptions {
  inputPath: string;
  htmlPath?: string;
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
  signal_buckets: {
    background_noise: string[];
    caution: string[];
    reviewer_action_required: string[];
  };
  proven_claims: string[];
  not_proven_claims: string[];
}

export interface ProofReport {
  input_path: string;
  run_summary_path: string | null;
  generated_at: string;
  public_layer: ReturnType<typeof extractPublicLayer>;
  harness: {
    status: string | null;
    tier: string | null;
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
  privacy_posture: ProofPrivacyPosture;
  review_buckets: ProofReviewBucket[];
  warnings: string[];
  next_steps: string[];
  verify_command: string;
  html_path?: string;
  decrypted_payload_keys?: string[];
}

type ProofReportBase = Omit<
  ProofReport,
  'input_path' | 'run_summary_path' | 'generated_at' | 'review_buckets' | 'warnings' | 'next_steps' | 'verify_command' | 'html_path'
>;

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

function isDataHandlingAction(value: unknown): value is DataHandlingAction {
  return value === 'allow' || value === 'redact' || value === 'block' || value === 'require_approval';
}

function isBase64UrlLike(value: string | null, minLength = 8): boolean {
  return value !== null && value.length >= minLength && /^[A-Za-z0-9_-]+$/.test(value);
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

const DATA_HANDLING_ACTION_ORDER: DataHandlingAction[] = ['allow', 'redact', 'block', 'require_approval'];

function summarizePrivacyPosture(args: {
  payload: Record<string, unknown>;
  sentinels: ProofReport['sentinels'];
}): ProofPrivacyPosture {
  const { payload, sentinels } = args;
  const metadata = isRecord(payload.metadata) ? payload.metadata : null;
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
  const evidence = {
    egress_policy_receipt_present: egressPayload !== null,
    runtime_profile_present: runtimeProfilePresent,
    runtime_hygiene_present: runtimeHygienePresent,
    data_handling_receipts_present: dataHandlingPayloads.length > 0,
    processor_policy_evidence_present: processorPolicy !== null,
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
  notProvenClaims.push('This report does not independently verify every privacy receipt signature or processor-policy hash; use clawverify verify proof-bundle for canonical validation.');
  notProvenClaims.push('This report does not by itself prove legal or regulatory compliance.');
  notProvenClaims.push('This report does not prove what third-party processors retained or deleted after receipt.');
  notProvenClaims.push('This report does not replace legal, contractual, or policy review.');
  notProvenClaims.push('This report does not include remote attestation or measured boot guarantees.');

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
  for (const signal of report.privacy_posture.signal_buckets.reviewer_action_required.slice(0, 3)) {
    warnings.push(`Privacy signal: ${signal}`);
  }

  return warnings;
}

function deriveNextSteps(
  report: Pick<ProofReport, 'gateway' | 'warnings' | 'verify_command' | 'privacy_posture'>,
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
  const privacyPosture = summarizePrivacyPosture({ payload, sentinels });

  const base: ProofReportBase = {
    public_layer: publicLayer,
    harness: {
      status: asString(runSummary?.status),
      tier: asString(runSummary?.tier),
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
    privacy_posture: privacyPosture,
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
        <span class="pill ${warningsClass}">Reviewer actions: ${reviewerActionCount}</span>
        <span class="pill ${privacyPillClass}">Privacy verdict: ${escapeHtml(report.privacy_posture.overall_verdict.toUpperCase())}</span>
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
          ['Egress policy evidence', report.privacy_posture.evidence.egress_policy_receipt_present ? 'present' : 'missing'],
          ['Processor policy evidence', report.privacy_posture.evidence.processor_policy_evidence_present ? 'present' : 'missing'],
          ['Data-handling evidence', report.privacy_posture.evidence.data_handling_receipts_present ? 'present' : 'missing'],
          ['Runtime hygiene evidence', report.privacy_posture.evidence.runtime_hygiene_present ? 'present' : 'missing'],
        ])}
        <div class="subheading">What Is Proven</div>
        <ul>${renderList(report.privacy_posture.proven_claims)}</ul>
        <div class="subheading">What Is Not Proven</div>
        <ul>${renderList(report.privacy_posture.not_proven_claims)}</ul>
      </article>

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
  lines.push(`  Egress policy evidence      : ${report.privacy_posture.evidence.egress_policy_receipt_present ? 'present' : 'missing'}`);
  lines.push(`  Processor policy evidence   : ${report.privacy_posture.evidence.processor_policy_evidence_present ? 'present' : 'missing'}`);
  lines.push(`  Data-handling evidence      : ${report.privacy_posture.evidence.data_handling_receipts_present ? 'present' : 'missing'}`);
  lines.push(`  Runtime hygiene evidence    : ${report.privacy_posture.evidence.runtime_hygiene_present ? 'present' : 'missing'}`);
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
  lines.push('Next steps:');
  for (const step of report.next_steps) {
    lines.push(`  - ${step}`);
  }
  if (report.html_path) {
    lines.push('');
    lines.push(`HTML report      : ${report.html_path}`);
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

  if (options.htmlPath) {
    const htmlPath = resolve(options.htmlPath);
    await writeFile(htmlPath, renderProofReportHtml(report), 'utf-8');
    report.html_path = htmlPath;
  }

  if (options.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printHumanReadable(report);
  }

  return report;
}
