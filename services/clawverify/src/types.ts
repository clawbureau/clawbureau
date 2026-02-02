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
 * Gateway receipt payload - represents a proxy receipt for proof-of-harness
 * Used by marketplaces to validate that requests were routed through a trusted gateway
 */
export interface GatewayReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  gateway_id: string;
  provider: string;
  model: string;
  request_hash_b64u: string;
  response_hash_b64u: string;
  tokens_input: number;
  tokens_output: number;
  latency_ms: number;
  timestamp: string;
  metadata?: Record<string, unknown>;
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

export interface VerifyReceiptRequest {
  envelope: SignedEnvelope<GatewayReceiptPayload>;
}

export interface VerifyReceiptResponse {
  result: VerificationResult;
  provider?: string;
  model?: string;
  gateway_id?: string;
  error?: VerificationError;
}

/**
 * Batch verification types
 * CVF-US-004: Batch verification for scale verification
 */

/** Maximum number of envelopes allowed in a single batch request */
export const BATCH_SIZE_LIMIT = 100;

/** Individual batch item - envelope type is detected automatically */
export interface BatchItem {
  envelope: SignedEnvelope;
  /** Optional client-provided ID for correlation */
  id?: string;
}

/** Result for a single batch item */
export interface BatchItemResult {
  /** Client-provided ID (if any) or index in the batch */
  id: string;
  /** Detected envelope type */
  envelope_type?: EnvelopeType;
  /** Verification result */
  result: VerificationResult;
  /** Error details (if verification failed) */
  error?: VerificationError;
  /** Additional fields returned based on envelope type */
  signer_did?: string;
  provider?: string;
  model?: string;
  gateway_id?: string;
}

/** Batch verification request */
export interface VerifyBatchRequest {
  items: BatchItem[];
}

/** Batch verification response */
export interface VerifyBatchResponse {
  /** Total number of items in the batch */
  total: number;
  /** Number of valid items */
  valid_count: number;
  /** Number of invalid items */
  invalid_count: number;
  /** Per-item results in same order as input */
  results: BatchItemResult[];
  /** Timestamp when verification completed */
  verified_at: string;
}

/**
 * Audit log types for verification provenance
 * CVF-US-005: Verification provenance for compliance traceability
 */

/** Audit log entry stored in D1 */
export interface AuditLogEntry {
  /** Unique identifier for this audit entry (receipt_id) */
  receipt_id: string;
  /** Hash of the verification request */
  request_hash_b64u: string;
  /** Type of envelope that was verified */
  envelope_type: EnvelopeType;
  /** Verification result status */
  status: VerificationStatus;
  /** Signer DID from the envelope */
  signer_did: string;
  /** Timestamp of verification */
  verified_at: string;
  /** Hash of the previous entry in the chain (null for first entry) */
  prev_hash_b64u: string | null;
  /** Hash of this entry (computed from all fields + prev_hash) */
  entry_hash_b64u: string;
}

/** Response when creating an audit log entry */
export interface AuditLogReceipt {
  receipt_id: string;
  entry_hash_b64u: string;
  prev_hash_b64u: string | null;
  verified_at: string;
}

/** Response when retrieving provenance by receipt ID */
export interface ProvenanceResponse {
  found: boolean;
  entry?: AuditLogEntry;
  chain_valid?: boolean;
}

/**
 * Proof Bundle types
 * CVF-US-007: Verify proof bundles for trust tier computation
 */

/** Universal Resource Manifest (URM) - minimal structure for proof bundles */
export interface URMReference {
  urm_version: '1';
  urm_id: string;
  resource_type: string;
  resource_hash_b64u: string;
  metadata?: Record<string, unknown>;
}

/** Event chain entry for hash-linked event logs */
export interface EventChainEntry {
  event_id: string;
  run_id: string;
  event_type: string;
  timestamp: string;
  payload_hash_b64u: string;
  prev_hash_b64u: string | null;
  event_hash_b64u: string;
}

/** Attestation reference in proof bundles */
export interface AttestationReference {
  attestation_id: string;
  attestation_type: 'owner' | 'third_party';
  attester_did: string;
  subject_did: string;
  expires_at?: string;
  signature_b64u: string;
}

/** Proof bundle payload structure */
export interface ProofBundlePayload {
  bundle_version: '1';
  bundle_id: string;
  agent_did: string;
  urm?: URMReference;
  event_chain?: EventChainEntry[];
  receipts?: SignedEnvelope<GatewayReceiptPayload>[];
  attestations?: AttestationReference[];
  metadata?: Record<string, unknown>;
}

/** Trust tiers computed from proof bundle contents */
export type TrustTier = 'unknown' | 'basic' | 'verified' | 'attested' | 'full';

/** Proof bundle verification result */
export interface ProofBundleVerificationResult {
  status: VerificationStatus;
  reason: string;
  verified_at: string;
  bundle_id?: string;
  agent_did?: string;
  trust_tier?: TrustTier;
  component_results?: {
    envelope_valid: boolean;
    urm_valid?: boolean;
    event_chain_valid?: boolean;
    receipts_valid?: boolean;
    attestations_valid?: boolean;
    receipts_count?: number;
    attestations_count?: number;
  };
}

/** Verify bundle request */
export interface VerifyBundleRequest {
  envelope: SignedEnvelope<ProofBundlePayload>;
}

/** Verify bundle response */
export interface VerifyBundleResponse {
  result: ProofBundleVerificationResult;
  trust_tier?: TrustTier;
  error?: VerificationError;
}
