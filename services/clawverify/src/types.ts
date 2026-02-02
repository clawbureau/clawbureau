/**
 * Clawverify Types
 * Core types for the verification API
 */

// Allowlisted envelope versions
export const ENVELOPE_VERSIONS = ['1'] as const;
export type EnvelopeVersion = (typeof ENVELOPE_VERSIONS)[number];

// Allowlisted envelope types
export const ENVELOPE_TYPES = [
  'artifact_signature',
  'message_signature',
  'gateway_receipt',
  'proof_bundle',
  'event_chain',
  'owner_attestation',
  'commit_proof',
  'scoped_token',
] as const;
export type EnvelopeType = (typeof ENVELOPE_TYPES)[number];

// Allowlisted algorithms
export const ALGORITHMS = ['Ed25519'] as const;
export type Algorithm = (typeof ALGORITHMS)[number];

// Allowlisted hash algorithms
export const HASH_ALGORITHMS = ['SHA-256', 'BLAKE3'] as const;
export type HashAlgorithm = (typeof HASH_ALGORITHMS)[number];

/**
 * Signed envelope wrapper - common structure for all signed payloads
 */
export interface SignedEnvelope<T = unknown> {
  envelope_version: EnvelopeVersion;
  envelope_type: EnvelopeType;
  payload: T;
  payload_hash_b64u: string;
  hash_algorithm: HashAlgorithm;
  signature_b64u: string;
  algorithm: Algorithm;
  signer_did: string;
  issued_at: string;
}

/**
 * Artifact payload - represents a signed work artifact
 */
export interface ArtifactPayload {
  artifact_version: '1';
  artifact_id: string;
  artifact_type: string;
  content_hash_b64u: string;
  content_type: string;
  content_size_bytes: number;
  metadata?: Record<string, unknown>;
}

/**
 * Message payload - represents a signed message for DID binding
 * Used to cryptographically bind a DID to an account or prove ownership
 */
export interface MessagePayload {
  message_version: '1';
  message_type: 'account_binding' | 'ownership_proof' | 'challenge_response';
  message: string;
  nonce: string;
  audience?: string;
  expires_at?: string;
}

/**
 * Verification result
 */
export type VerificationStatus = 'VALID' | 'INVALID';

export interface VerificationResult {
  status: VerificationStatus;
  reason: string;
  envelope_type?: EnvelopeType;
  signer_did?: string;
  verified_at: string;
}

/**
 * Verification error codes for fail-closed behavior
 */
export type VerificationErrorCode =
  | 'UNKNOWN_ENVELOPE_VERSION'
  | 'UNKNOWN_ENVELOPE_TYPE'
  | 'UNKNOWN_ALGORITHM'
  | 'UNKNOWN_HASH_ALGORITHM'
  | 'HASH_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'MALFORMED_ENVELOPE'
  | 'MISSING_REQUIRED_FIELD'
  | 'INVALID_DID_FORMAT'
  | 'EXPIRED'
  | 'PARSE_ERROR';

/**
 * Structured error for verification failures
 */
export interface VerificationError {
  code: VerificationErrorCode;
  message: string;
  field?: string;
}

/**
 * API request/response types
 */
export interface VerifyArtifactRequest {
  envelope: SignedEnvelope<ArtifactPayload>;
}

export interface VerifyArtifactResponse {
  result: VerificationResult;
  error?: VerificationError;
}

export interface VerifyMessageRequest {
  envelope: SignedEnvelope<MessagePayload>;
}

export interface VerifyMessageResponse {
  result: VerificationResult;
  signer_did?: string;
  error?: VerificationError;
}
