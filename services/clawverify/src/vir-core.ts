import type { VirReceiptPayload, VirSource } from './types';
import { base64UrlEncode } from './crypto';
import { isValidBase64Url } from './schema-registry';

export type VirFailureCode =
  | 'ERR_MERKLE_ROOT_MISMATCH'
  | 'ERR_CONFLICT_UNREPORTED'
  | 'ERR_PRECEDENCE_VIOLATION'
  | 'ERR_BINDING_NONCE_MISMATCH'
  | 'ERR_BINDING_SUBJECT_MISMATCH'
  | 'ERR_BINDING_SCOPE_MISMATCH'
  | 'ERR_BINDING_EVENT_HASH_INVALID'
  | 'ERR_BINDING_RUN_ID_MISMATCH'
  | 'ERR_LEGAL_BINDING_REQUIRED';

export interface VirValidationResult {
  valid: boolean;
  code?: VirFailureCode;
  message?: string;
  riskFlags: string[];
  source?: VirSource;
}

export interface VirBindingContext {
  expectedRunId: string;
  allowedEventHashes: ReadonlySet<string>;
}

export interface VirExpectedBindings {
  requireNonce?: boolean;
  nonce?: string | null;
  subject?: string | null;
  scope?: string | null;
}

export interface ValidateVirReceiptCoreInput {
  payload: VirReceiptPayload;
  bindingContext?: VirBindingContext | null;
  expected?: VirExpectedBindings;
}

export const SOURCE_SCORE: Record<VirSource, number> = {
  tls_decrypt: 5,
  gateway: 4,
  interpose: 3,
  preload: 2,
  sni: 1,
};

export type VirConflictSeverity =
  | 'none'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical';

export const VIR_CONFLICT_SEVERITY_SCORE: Record<VirConflictSeverity, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function classifyVirConflictSeverity(field: unknown): VirConflictSeverity {
  if (typeof field !== 'string' || field.trim().length === 0) return 'low';

  const normalized = field.trim().toLowerCase();

  if (
    normalized === 'request_hash_b64u' ||
    normalized === 'request_hash' ||
    normalized === 'response_hash_b64u' ||
    normalized === 'response_hash' ||
    normalized === 'binding.run_id' ||
    normalized === 'binding.event_hash_b64u' ||
    normalized === 'legal_binding.nonce' ||
    normalized === 'legal_binding.subject_did' ||
    normalized === 'legal_binding.scope_hash_b64u'
  ) {
    return 'critical';
  }

  if (
    normalized === 'model' ||
    normalized === 'model_claimed' ||
    normalized === 'model_observed' ||
    normalized === 'provider' ||
    normalized === 'source'
  ) {
    return 'high';
  }

  if (
    normalized === 'tokens_input' ||
    normalized === 'tokens_output' ||
    normalized === 'latency' ||
    normalized === 'latency_ms'
  ) {
    return 'medium';
  }

  return 'low';
}

export function mergeVirConflictSeverity(
  current: VirConflictSeverity,
  next: VirConflictSeverity
): VirConflictSeverity {
  return VIR_CONFLICT_SEVERITY_SCORE[next] > VIR_CONFLICT_SEVERITY_SCORE[current]
    ? next
    : current;
}

export const CRITICAL_VIR_CODES = new Set<VirFailureCode>([
  'ERR_MERKLE_ROOT_MISMATCH',
  'ERR_CONFLICT_UNREPORTED',
  'ERR_PRECEDENCE_VIOLATION',
]);

export interface VirCandidateForComparison {
  source: VirSource;
  timestampMs: number;
  receiptId: string;
}

export function compareVirCandidate(
  a: VirCandidateForComparison,
  b: VirCandidateForComparison
): number {
  return (
    SOURCE_SCORE[b.source] - SOURCE_SCORE[a.source] ||
    a.timestampMs - b.timestampMs ||
    a.receiptId.localeCompare(b.receiptId)
  );
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asVirSource(value: unknown): VirSource | undefined {
  if (
    value === 'tls_decrypt' ||
    value === 'gateway' ||
    value === 'interpose' ||
    value === 'preload' ||
    value === 'sni'
  ) {
    return value;
  }
  return undefined;
}

function stringifyVirV2LeafValue(type: string, value: unknown): string | null {
  if (type === 'string') {
    return typeof value === 'string' ? value : null;
  }

  if (type === 'number') {
    return typeof value === 'number' && Number.isFinite(value) ? `${value}` : null;
  }

  if (type === 'boolean') {
    return typeof value === 'boolean' ? (value ? 'true' : 'false') : null;
  }

  if (type === 'null') {
    return value === null ? 'null' : null;
  }

  return null;
}

async function sha256Utf8B64u(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return base64UrlEncode(new Uint8Array(digest));
}

async function computeVirV2LeafHash(args: {
  key: string;
  type: 'string' | 'number' | 'boolean' | 'null';
  value: unknown;
  saltB64u: string;
}): Promise<string | null> {
  const valueString = stringifyVirV2LeafValue(args.type, args.value);
  if (valueString === null) {
    return null;
  }

  return sha256Utf8B64u(
    `vir_v2_leaf|${args.key}|${args.type}|${args.saltB64u}|${valueString}`
  );
}

function resolveBindingValues(payload: VirReceiptPayload): {
  nonce: string | null;
  subject: string | null;
  scope: string | null;
  runId: string | null;
  eventHash: string | null;
} {
  const binding = isObjectRecord(payload.binding) ? payload.binding : null;
  const legalBinding = isObjectRecord(payload.legal_binding)
    ? payload.legal_binding
    : null;

  const nonce =
    typeof binding?.nonce === 'string'
      ? binding.nonce
      : typeof legalBinding?.nonce === 'string'
        ? legalBinding.nonce
        : null;

  const subject =
    typeof binding?.subject === 'string'
      ? binding.subject
      : typeof binding?.subject_did === 'string'
        ? binding.subject_did
        : typeof legalBinding?.subject_did === 'string'
          ? legalBinding.subject_did
          : null;

  const scope =
    typeof binding?.scope === 'string'
      ? binding.scope
      : typeof binding?.scope_hash_b64u === 'string'
        ? binding.scope_hash_b64u
        : typeof legalBinding?.scope_hash_b64u === 'string'
          ? legalBinding.scope_hash_b64u
          : null;

  const runId =
    typeof binding?.run_id === 'string' && binding.run_id.trim().length > 0
      ? binding.run_id
      : null;

  const eventHash =
    typeof binding?.event_hash_b64u === 'string' &&
    binding.event_hash_b64u.trim().length > 0
      ? binding.event_hash_b64u
      : null;

  return { nonce, subject, scope, runId, eventHash };
}

function expectedPayloadValueForLeaf(
  payload: VirReceiptPayload,
  key: string
): unknown {
  switch (key) {
    case 'model_claimed':
      return payload.model_claimed;
    case 'model_observed':
      return payload.model_observed;
    case 'request_hash_b64u':
    case 'request_hash':
      return payload.request_hash_b64u;
    case 'response_hash_b64u':
    case 'response_hash':
      return payload.response_hash_b64u;
    case 'tokens_input':
      return payload.tokens_input;
    case 'tokens_output':
      return payload.tokens_output;
    case 'latency_ms':
    case 'latency':
      return payload.latency_ms;
    case 'run_id':
      return payload.binding?.run_id;
    case 'event_hash_b64u':
    case 'event_hash':
      return payload.binding?.event_hash_b64u;
    case 'nonce':
      return payload.binding?.nonce ?? payload.legal_binding?.nonce;
    case 'subject':
    case 'subject_did':
      return (
        payload.binding?.subject ??
        payload.binding?.subject_did ??
        payload.legal_binding?.subject_did
      );
    case 'scope':
    case 'scope_hash_b64u':
      return (
        payload.binding?.scope ??
        payload.binding?.scope_hash_b64u ??
        payload.legal_binding?.scope_hash_b64u
      );
    default:
      return undefined;
  }
}

export async function validateVirReceiptCore(
  input: ValidateVirReceiptCoreInput
): Promise<VirValidationResult> {
  const { payload } = input;
  const bindingContext = input.bindingContext ?? null;
  const expected = input.expected ?? {};
  const source = asVirSource(payload.source);
  const riskFlags = new Set<string>();

  const invalid = (
    code: VirFailureCode | undefined,
    message: string
  ): VirValidationResult => ({
    valid: false,
    code,
    message,
    source,
    riskFlags: [...riskFlags].sort(),
  });

  const bindingValues = resolveBindingValues(payload);

  if (payload.receipt_version === '2') {
    if (!isObjectRecord(payload.legal_binding)) {
      return invalid(
        'ERR_LEGAL_BINDING_REQUIRED',
        'VIR v2 legal_binding is required'
      );
    }

    if (!bindingValues.nonce || !bindingValues.subject || !bindingValues.scope) {
      return invalid(
        'ERR_LEGAL_BINDING_REQUIRED',
        'VIR v2 legal_binding must include nonce, subject_did, and scope_hash_b64u'
      );
    }
  }

  if (source === 'tls_decrypt') {
    const decryptedMatch = payload.transport_attestation?.decrypted_match;
    if (
      decryptedMatch !== undefined &&
      decryptedMatch !== null &&
      decryptedMatch !== true
    ) {
      return invalid(
        undefined,
        'VIR transport_attestation.decrypted_match must be true for tls_decrypt source'
      );
    }
  }

  if (
    payload.transport_attestation?.source !== undefined &&
    payload.transport_attestation.source !== payload.source
  ) {
    return invalid(
      undefined,
      'VIR transport_attestation.source does not match payload.source'
    );
  }

  const evidenceConflicts = Array.isArray(payload.evidence_conflicts)
    ? payload.evidence_conflicts
    : [];

  for (const conflict of evidenceConflicts) {
    if (!isObjectRecord(conflict)) continue;

    const authoritativeSource = asVirSource(conflict.authoritative_source);
    const divergentSource = asVirSource(conflict.divergent_source);

    if (
      authoritativeSource &&
      divergentSource &&
      SOURCE_SCORE[divergentSource] > SOURCE_SCORE[authoritativeSource]
    ) {
      return invalid(
        'ERR_PRECEDENCE_VIOLATION',
        'VIR evidence_conflicts precedence violation'
      );
    }

    const severity = classifyVirConflictSeverity(conflict.field);
    riskFlags.add(`VIR_CONFLICT_${severity.toUpperCase()}`);

    if (conflict.field === 'tokens_input' || conflict.field === 'tokens_output') {
      riskFlags.add('EVIDENCE_METRIC_DISCREPANCY');
    }
  }

  const hasModelDivergence =
    typeof payload.model_claimed === 'string' &&
    payload.model_claimed.length > 0 &&
    typeof payload.model_observed === 'string' &&
    payload.model_observed.length > 0 &&
    payload.model_claimed !== payload.model_observed;

  if (hasModelDivergence) {
    const hasModelConflict = evidenceConflicts.some(
      (conflict) => isObjectRecord(conflict) && conflict.field === 'model'
    );

    if (!hasModelConflict) {
      return invalid(
        'ERR_CONFLICT_UNREPORTED',
        'VIR model divergence is unreported in evidence_conflicts'
      );
    }

    riskFlags.add('MODEL_SUBSTITUTION_DETECTED');
  }

  const disclosed = payload.selective_disclosure;
  if (disclosed?.merkle_root_b64u) {
    if (
      payload.receipt_version === '2' &&
      disclosed.disclosure_algorithm === 'vir_v2_typed_lexicographical'
    ) {
      const disclosedLeavesRecord = isObjectRecord(disclosed.disclosed_leaves)
        ? disclosed.disclosed_leaves
        : null;

      if (!disclosedLeavesRecord) {
        return invalid(
          undefined,
          'VIR v2 selective_disclosure.disclosed_leaves is required'
        );
      }

      const disclosedLeafHashes: string[] = [];

      for (const key of Object.keys(disclosedLeavesRecord).sort((a, b) => a.localeCompare(b))) {
        const leaf = disclosedLeavesRecord[key];
        if (!isObjectRecord(leaf)) {
          return invalid(undefined, `VIR v2 disclosed leaf '${key}' is malformed`);
        }

        const type = leaf.type;
        const saltB64u = leaf.salt_b64u;
        const value = leaf.value;

        if (
          (type !== 'string' &&
            type !== 'number' &&
            type !== 'boolean' &&
            type !== 'null') ||
          typeof saltB64u !== 'string' ||
          !isValidBase64Url(saltB64u) ||
          saltB64u.length < 8
        ) {
          return invalid(
            undefined,
            `VIR v2 disclosed leaf '${key}' has invalid type/salt`
          );
        }

        const expectedPayloadValue = expectedPayloadValueForLeaf(payload, key);
        if (expectedPayloadValue !== undefined && expectedPayloadValue !== value) {
          return invalid(
            undefined,
            `VIR plaintext payload mismatch for leaf: ${key}`
          );
        }

        const computedLeafHash = await computeVirV2LeafHash({
          key,
          type,
          value,
          saltB64u,
        });

        if (!computedLeafHash) {
          return invalid(
            undefined,
            `VIR v2 disclosed leaf '${key}' value/type mismatch`
          );
        }

        disclosedLeafHashes.push(computedLeafHash);
      }

      const redactedLeafHashes = Array.isArray(disclosed.redacted_leaf_hashes_b64u)
        ? disclosed.redacted_leaf_hashes_b64u.filter(
            (value): value is string =>
              typeof value === 'string' &&
              isValidBase64Url(value) &&
              value.length >= 8
          )
        : [];

      const allLeafHashes = [...disclosedLeafHashes, ...redactedLeafHashes];
      if (allLeafHashes.length === 0) {
        return invalid(undefined, 'VIR v2 selective_disclosure has no leaves');
      }

      const expectedRoot = await sha256Utf8B64u(
        `vir_v2_root|${[...allLeafHashes].sort((a, b) => a.localeCompare(b)).join('|')}`
      );

      if (expectedRoot !== disclosed.merkle_root_b64u) {
        return invalid(
          'ERR_MERKLE_ROOT_MISMATCH',
          'VIR selective_disclosure merkle_root mismatch'
        );
      }
    } else {
      let leafHashes: string[] = [];

      if (Array.isArray(disclosed.leaf_hashes_b64u) && disclosed.leaf_hashes_b64u.length > 0) {
        leafHashes = disclosed.leaf_hashes_b64u.filter(
          (value): value is string => typeof value === 'string' && value.length > 0
        );
      } else if (isObjectRecord(disclosed.disclosed_leaves)) {
        leafHashes = Object.keys(disclosed.disclosed_leaves)
          .sort((a, b) => a.localeCompare(b))
          .map((k) => disclosed.disclosed_leaves?.[k])
          .filter((value): value is string => typeof value === 'string' && value.length > 0);
      }

      if (leafHashes.length > 0) {
        const expectedRoot = await sha256Utf8B64u(leafHashes.join('|'));
        if (expectedRoot !== disclosed.merkle_root_b64u) {
          return invalid(
            'ERR_MERKLE_ROOT_MISMATCH',
            'VIR selective_disclosure merkle_root mismatch'
          );
        }
      }
    }
  }

  if (expected.requireNonce) {
    if (!bindingValues.nonce || bindingValues.nonce.trim().length === 0) {
      return invalid(
        'ERR_BINDING_NONCE_MISMATCH',
        'VIR binding nonce is required by policy'
      );
    }
  }

  if (typeof expected.nonce === 'string' && expected.nonce.trim().length > 0) {
    if (bindingValues.nonce !== expected.nonce) {
      return invalid(
        'ERR_BINDING_NONCE_MISMATCH',
        `VIR binding nonce does not match expected nonce (${expected.nonce})`
      );
    }
  }

  if (typeof expected.subject === 'string' && expected.subject.trim().length > 0) {
    if (!bindingValues.subject || bindingValues.subject.trim().length === 0) {
      return invalid(
        'ERR_BINDING_SUBJECT_MISMATCH',
        'VIR binding subject is required by policy'
      );
    }

    if (bindingValues.subject !== expected.subject) {
      return invalid(
        'ERR_BINDING_SUBJECT_MISMATCH',
        `VIR binding subject does not match expected subject (${expected.subject})`
      );
    }
  }

  if (typeof expected.scope === 'string' && expected.scope.trim().length > 0) {
    if (!bindingValues.scope || bindingValues.scope.trim().length === 0) {
      return invalid(
        'ERR_BINDING_SCOPE_MISMATCH',
        'VIR binding scope is required by policy'
      );
    }

    if (bindingValues.scope !== expected.scope) {
      return invalid(
        'ERR_BINDING_SCOPE_MISMATCH',
        `VIR binding scope does not match expected scope (${expected.scope})`
      );
    }
  }

  if (bindingContext) {
    if (!bindingValues.runId || bindingValues.runId !== bindingContext.expectedRunId) {
      return invalid(
        'ERR_BINDING_RUN_ID_MISMATCH',
        'VIR binding.run_id does not match proof bundle run_id'
      );
    }

    if (bindingValues.eventHash) {
      if (!isValidBase64Url(bindingValues.eventHash) || bindingValues.eventHash.length < 8) {
        return invalid(
          'ERR_BINDING_EVENT_HASH_INVALID',
          'VIR binding.event_hash_b64u is invalid'
        );
      }

      if (!bindingContext.allowedEventHashes.has(bindingValues.eventHash)) {
        return invalid(
          'ERR_BINDING_EVENT_HASH_INVALID',
          'VIR binding.event_hash_b64u does not reference an event in the proof bundle event chain'
        );
      }
    }
  }

  return {
    valid: true,
    source,
    riskFlags: [...riskFlags].sort(),
  };
}
