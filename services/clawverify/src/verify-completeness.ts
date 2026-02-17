import type {
  CompletenessReasonCode,
  CompletenessVerdict,
} from './types';

export interface CompletenessEvidenceSnapshot {
  envelope_valid: boolean;
  event_chain_declared: boolean;
  event_chain_valid: boolean;
  binding_context_available: boolean;
  receipts_declared: boolean;
  receipts_signature_verified_count: number;
  receipts_verified_count: number;
  attestations_declared: boolean;
  attestations_signature_verified_count: number;
  attestations_verified_count: number;
}

export interface CompletenessPolicyResult {
  verdict: CompletenessVerdict;
  reason_code: CompletenessReasonCode;
}

export function evaluateCompletenessPolicy(
  snapshot: CompletenessEvidenceSnapshot,
): CompletenessPolicyResult {
  // 1) hard inconsistency: execution evidence cannot be binding-checked
  if (snapshot.receipts_declared && !snapshot.binding_context_available) {
    return {
      verdict: 'INCONSISTENT',
      reason_code: 'BINDING_CONTEXT_MISSING',
    };
  }

  // 2) hard inconsistency: signed receipts present but zero bind to this bundle
  if (
    snapshot.receipts_declared &&
    snapshot.receipts_signature_verified_count > 0 &&
    snapshot.receipts_verified_count === 0
  ) {
    return {
      verdict: 'INCONSISTENT',
      reason_code: 'RECEIPT_BINDING_MISMATCH',
    };
  }

  // 3) incomplete receipt evidence class (declared but unverified)
  if (snapshot.receipts_declared && snapshot.receipts_verified_count === 0) {
    return {
      verdict: 'INCOMPLETE',
      reason_code: 'RECEIPT_CLASS_UNVERIFIED',
    };
  }

  // 4) partial attestation evidence class (declared but unverified)
  if (
    snapshot.attestations_declared &&
    snapshot.attestations_signature_verified_count > 0 &&
    snapshot.attestations_verified_count === 0
  ) {
    return {
      verdict: 'PARTIAL',
      reason_code: 'ATTESTATION_CLASS_UNVERIFIED',
    };
  }

  // 5) complete: deterministic chain + at least one verified execution/attestation class
  if (
    snapshot.event_chain_valid &&
    (snapshot.receipts_verified_count > 0 ||
      snapshot.attestations_verified_count > 0)
  ) {
    return {
      verdict: 'COMPLETE',
      reason_code: 'COMPLETE_EVIDENCE_BOUND',
    };
  }

  // 6) partial: event chain only
  if (snapshot.event_chain_declared && snapshot.event_chain_valid) {
    return {
      verdict: 'PARTIAL',
      reason_code: 'EVENT_CHAIN_ONLY',
    };
  }

  // 7) partial baseline: envelope-level only / non-execution references
  return {
    verdict: 'PARTIAL',
    reason_code: 'ENVELOPE_ONLY',
  };
}

export function isCompletenessFailClosedVerdict(
  verdict: CompletenessVerdict,
): boolean {
  return verdict === 'INCONSISTENT';
}

export function isCompletenessConstrainedVerdict(
  verdict: CompletenessVerdict,
): boolean {
  return verdict === 'INCOMPLETE';
}

function policyRank(result: CompletenessPolicyResult): number {
  if (result.verdict === 'INCONSISTENT') {
    if (result.reason_code === 'RECEIPT_BINDING_MISMATCH') return 1;
    return 0;
  }

  if (result.verdict === 'INCOMPLETE') return 2;
  if (result.verdict === 'PARTIAL') {
    if (result.reason_code === 'ATTESTATION_CLASS_UNVERIFIED') return 3;
    if (result.reason_code === 'EVENT_CHAIN_ONLY') return 4;
    return 5;
  }

  return 6;
}

export function compareCompletenessPolicyResult(
  a: CompletenessPolicyResult,
  b: CompletenessPolicyResult,
): number {
  const rankDiff = policyRank(a) - policyRank(b);
  if (rankDiff !== 0) return rankDiff;

  if (a.reason_code < b.reason_code) return -1;
  if (a.reason_code > b.reason_code) return 1;
  return 0;
}
