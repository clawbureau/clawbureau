/**
 * Binary Semantic Evidence verification + deterministic policy evaluation.
 * CEC-US-005 / CEC-US-006
 */

import type {
  BinarySemanticEvidencePayload,
  BinarySemanticEvidenceReasonCode,
  BinarySemanticEvidenceVerdict,
  SignedEnvelope,
  VerificationError,
  VerificationErrorCode,
  VerificationResult,
} from './types';
import {
  isAllowedAlgorithm,
  isAllowedHashAlgorithm,
  isAllowedType,
  isAllowedVersion,
  isValidBase64Url,
  isValidDidFormat,
  isValidIsoDate,
} from './schema-registry';
import {
  base64UrlDecode,
  computeHash,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto';
import { validateBinarySemanticEvidenceEnvelopeV1 } from './schema-validation';

export interface BinarySemanticEvidenceVerifierOptions {
  allowlistedSignerDids?: readonly string[];
}

export interface BinarySemanticDynamicContext {
  verifiedNetworkEgressPresent: boolean;
}

export interface BinarySemanticPolicyResult {
  verdict: BinarySemanticEvidenceVerdict;
  reason_code: BinarySemanticEvidenceReasonCode;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasStaticHookSpoofingSignal(payload: BinarySemanticEvidencePayload): boolean {
  const md = payload.metadata;
  if (!isRecord(md)) return false;
  return md.static_hook_spoofing_detected === true;
}

export function evaluateBinarySemanticEvidencePolicy(
  payload: BinarySemanticEvidencePayload,
  dynamicContext: BinarySemanticDynamicContext,
): BinarySemanticPolicyResult {
  // 1) crypto/causal failure
  if (!payload.causality_metrics.merkle_chain_intact) {
    return { verdict: 'INVALID', reason_code: 'MERKLE_CHAIN_BROKEN' };
  }

  if (payload.causality_metrics.unattested_children_spawned) {
    return { verdict: 'INVALID', reason_code: 'UNATTESTED_CHILD_PROCESS' };
  }

  if (hasStaticHookSpoofingSignal(payload)) {
    return { verdict: 'INVALID', reason_code: 'STATIC_HOOK_SPOOFING' };
  }

  // 2) contradiction (static ABSENT vs verified dynamic PRESENT)
  if (
    payload.extracted_claims.network_egress === 'ABSENT' &&
    dynamicContext.verifiedNetworkEgressPresent
  ) {
    return { verdict: 'INVALID', reason_code: 'CAPABILITY_EXCEEDS_STATIC_PROOF' };
  }

  // 3) analysis exhaustion
  if (
    payload.forensic_metrics.static_analysis_budget_exhausted ||
    payload.forensic_metrics.parser_timeout
  ) {
    return { verdict: 'UNKNOWN', reason_code: 'STATIC_ANALYSIS_TIMEOUT' };
  }

  // 4) inapplicable bounds
  if (payload.binary_profile.target_architecture === 'unknown') {
    return { verdict: 'INAPPLICABLE', reason_code: 'UNSUPPORTED_ARCH' };
  }

  if (payload.binary_profile.is_sip_protected) {
    return {
      verdict: 'INAPPLICABLE',
      reason_code: 'SIP_RESTRICTION_INAPPLICABLE',
    };
  }

  // 5) partial
  if (payload.binary_profile.symbols === 'STRIPPED') {
    return { verdict: 'PARTIAL', reason_code: 'STRIPPED_SYMBOLS' };
  }

  // 6) valid
  return { verdict: 'VALID', reason_code: 'SEMANTICS_VERIFIED' };
}

export function isBinarySemanticFailClosedVerdict(
  verdict: BinarySemanticEvidenceVerdict,
): boolean {
  return verdict === 'INVALID' || verdict === 'UNKNOWN';
}

export function isBinarySemanticConstrainedVerdict(
  verdict: BinarySemanticEvidenceVerdict,
): boolean {
  return verdict === 'INAPPLICABLE' || verdict === 'PARTIAL';
}

function policyRank(result: BinarySemanticPolicyResult): number {
  if (result.verdict === 'INVALID') {
    // Precedence split inside INVALID:
    // 0 => crypto/causal failure
    // 1 => contradiction
    if (result.reason_code === 'CAPABILITY_EXCEEDS_STATIC_PROOF') return 1;
    return 0;
  }

  if (result.verdict === 'UNKNOWN') return 2;
  if (result.verdict === 'INAPPLICABLE') return 3;
  if (result.verdict === 'PARTIAL') return 4;
  return 5;
}

export function compareBinarySemanticPolicyResult(
  a: BinarySemanticPolicyResult,
  b: BinarySemanticPolicyResult,
): number {
  const rankDiff = policyRank(a) - policyRank(b);
  if (rankDiff !== 0) return rankDiff;

  if (a.reason_code < b.reason_code) return -1;
  if (a.reason_code > b.reason_code) return 1;
  return 0;
}

function mapErrorCodeToReasonCode(
  code: VerificationErrorCode | undefined,
): BinarySemanticEvidenceReasonCode {
  if (code === 'HASH_MISMATCH') return 'HASH_MISMATCH';
  if (code === 'SIGNATURE_INVALID') return 'SIGNATURE_MISMATCH';
  if (code === 'DEPENDENCY_NOT_CONFIGURED') return 'MISSING_DEPENDENCY';
  return 'SIGNATURE_MISMATCH';
}

function malformedEnvelope(message: string, field?: string): {
  result: VerificationResult;
  error: VerificationError;
} {
  return {
    result: {
      status: 'INVALID',
      reason: message,
      verified_at: new Date().toISOString(),
    },
    error: {
      code: 'MALFORMED_ENVELOPE',
      message,
      field,
    },
  };
}

export async function verifyBinarySemanticEvidence(
  envelope: unknown,
  options: BinarySemanticEvidenceVerifierOptions = {},
): Promise<{
  result: VerificationResult;
  reason_code?: BinarySemanticEvidenceReasonCode;
  payload?: BinarySemanticEvidencePayload;
  signer_did?: string;
  error?: VerificationError;
}> {
  const now = new Date().toISOString();

  if (!isRecord(envelope)) {
    return malformedEnvelope('Malformed envelope: expected object');
  }

  const requiredFields = [
    'envelope_version',
    'envelope_type',
    'payload',
    'payload_hash_b64u',
    'hash_algorithm',
    'signature_b64u',
    'algorithm',
    'signer_did',
    'issued_at',
  ];

  for (const field of requiredFields) {
    if (!(field in envelope)) {
      return malformedEnvelope('Malformed envelope: missing required fields');
    }
  }

  const typedEnvelope =
    envelope as unknown as SignedEnvelope<BinarySemanticEvidencePayload>;

  if (!isAllowedVersion(typedEnvelope.envelope_version)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown envelope version: ${typedEnvelope.envelope_version}`,
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'UNKNOWN_ENVELOPE_VERSION',
        message: `Envelope version "${typedEnvelope.envelope_version}" is not in the allowlist`,
        field: 'envelope_version',
      },
      reason_code: 'MISSING_DEPENDENCY',
    };
  }

  if (!isAllowedType(typedEnvelope.envelope_type)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown envelope type: ${typedEnvelope.envelope_type}`,
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: `Envelope type "${typedEnvelope.envelope_type}" is not in the allowlist`,
        field: 'envelope_type',
      },
      reason_code: 'MISSING_DEPENDENCY',
    };
  }

  if (typedEnvelope.envelope_type !== 'binary_semantic_evidence') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected binary_semantic_evidence envelope, got: ${typedEnvelope.envelope_type}`,
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: 'This verifier only accepts binary_semantic_evidence envelopes',
        field: 'envelope_type',
      },
      reason_code: 'MISSING_DEPENDENCY',
    };
  }

  if (!isAllowedAlgorithm(typedEnvelope.algorithm)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown signature algorithm: ${typedEnvelope.algorithm}`,
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'UNKNOWN_ALGORITHM',
        message: `Signature algorithm "${typedEnvelope.algorithm}" is not in the allowlist`,
        field: 'algorithm',
      },
      reason_code: 'MISSING_DEPENDENCY',
    };
  }

  if (!isAllowedHashAlgorithm(typedEnvelope.hash_algorithm)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown hash algorithm: ${typedEnvelope.hash_algorithm}`,
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'UNKNOWN_HASH_ALGORITHM',
        message: `Hash algorithm "${typedEnvelope.hash_algorithm}" is not in the allowlist`,
        field: 'hash_algorithm',
      },
      reason_code: 'MISSING_DEPENDENCY',
    };
  }

  const schemaResult = validateBinarySemanticEvidenceEnvelopeV1(typedEnvelope);
  if (!schemaResult.valid) {
    return {
      result: {
        status: 'INVALID',
        reason: schemaResult.message,
        envelope_type: typedEnvelope.envelope_type,
        signer_did: typedEnvelope.signer_did,
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: schemaResult.message,
        field: schemaResult.field,
      },
      reason_code: 'SIGNATURE_MISMATCH',
    };
  }

  if (!isValidDidFormat(typedEnvelope.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Invalid DID format: ${typedEnvelope.signer_did}`,
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'INVALID_DID_FORMAT',
        message:
          'Signer DID does not match expected format (did:key:... or did:web:...)',
        field: 'signer_did',
      },
      reason_code: 'SIGNATURE_MISMATCH',
    };
  }

  if (!isValidIsoDate(typedEnvelope.issued_at)) {
    return malformedEnvelope('issued_at must be a valid ISO 8601 date string', 'issued_at');
  }

  if (
    !isValidBase64Url(typedEnvelope.payload_hash_b64u) ||
    typedEnvelope.payload_hash_b64u.length < 8
  ) {
    return malformedEnvelope(
      'payload_hash_b64u must be base64url and at least 8 chars',
      'payload_hash_b64u',
    );
  }

  if (
    !isValidBase64Url(typedEnvelope.signature_b64u) ||
    typedEnvelope.signature_b64u.length < 8
  ) {
    return malformedEnvelope(
      'signature_b64u must be base64url and at least 8 chars',
      'signature_b64u',
    );
  }

  if (!options.allowlistedSignerDids || options.allowlistedSignerDids.length === 0) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Binary semantic evidence signer allowlist not configured',
        envelope_type: typedEnvelope.envelope_type,
        signer_did: typedEnvelope.signer_did,
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message:
          'Binary semantic evidence signer allowlist is not configured. Set BINARY_SEMANTIC_EVIDENCE_SIGNER_DIDS to enable verification.',
        field: 'env.BINARY_SEMANTIC_EVIDENCE_SIGNER_DIDS',
      },
      reason_code: 'MISSING_DEPENDENCY',
    };
  }

  if (!options.allowlistedSignerDids.includes(typedEnvelope.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Binary semantic evidence signer DID is not allowlisted',
        envelope_type: typedEnvelope.envelope_type,
        signer_did: typedEnvelope.signer_did,
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'CLAIM_NOT_FOUND',
        message: `Signer DID '${typedEnvelope.signer_did}' is not in the allowlisted binary semantic evidence signer list`,
        field: 'signer_did',
      },
      reason_code: 'SIGNATURE_MISMATCH',
    };
  }

  let computedHash: string;
  try {
    computedHash = await computeHash(typedEnvelope.payload, typedEnvelope.hash_algorithm);
  } catch {
    return {
      result: {
        status: 'INVALID',
        reason: 'Hash computation failed',
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'HASH_MISMATCH',
        message: 'Failed to compute payload hash',
      },
      reason_code: 'HASH_MISMATCH',
    };
  }

  if (computedHash !== typedEnvelope.payload_hash_b64u) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Payload hash mismatch: envelope may have been tampered with',
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'HASH_MISMATCH',
        message: 'Computed payload hash does not match envelope hash',
      },
      reason_code: 'HASH_MISMATCH',
    };
  }

  const publicKeyBytes = extractPublicKeyFromDidKey(typedEnvelope.signer_did);
  if (!publicKeyBytes) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Could not extract public key from signer DID',
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'Unable to extract Ed25519 public key from did:key DID',
        field: 'signer_did',
      },
      reason_code: 'SIGNATURE_MISMATCH',
    };
  }

  let signatureValid = false;
  try {
    const sigBytes = base64UrlDecode(typedEnvelope.signature_b64u);
    const msgBytes = new TextEncoder().encode(typedEnvelope.payload_hash_b64u);
    signatureValid = await verifySignature('Ed25519', publicKeyBytes, sigBytes, msgBytes);
  } catch {
    signatureValid = false;
  }

  if (!signatureValid) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Signature verification failed',
        verified_at: now,
      },
      signer_did: typedEnvelope.signer_did,
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'The Ed25519 signature does not match the payload hash',
      },
      reason_code: 'SIGNATURE_MISMATCH',
    };
  }

  return {
    result: {
      status: 'VALID',
      reason: 'Binary semantic evidence envelope verified successfully',
      envelope_type: typedEnvelope.envelope_type,
      signer_did: typedEnvelope.signer_did,
      verified_at: now,
    },
    signer_did: typedEnvelope.signer_did,
    payload: typedEnvelope.payload,
    reason_code: 'SEMANTICS_VERIFIED',
  };
}

export function verificationFailureToPolicyResult(
  error: VerificationError | undefined,
  reasonCodeHint?: BinarySemanticEvidenceReasonCode,
): BinarySemanticPolicyResult {
  const reasonCode = reasonCodeHint ?? mapErrorCodeToReasonCode(error?.code);
  return {
    verdict: reasonCode === 'MISSING_DEPENDENCY' ? 'UNKNOWN' : 'INVALID',
    reason_code: reasonCode,
  };
}
