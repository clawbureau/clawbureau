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
  'execution_attestation',
  'scoped_token',
] as const;
export type EnvelopeType = (typeof ENVELOPE_TYPES)[number];

/**
 * CVF-US-012: One-call agent verification
 */
export interface VerifyAgentRequest {
  agent_did: string;
  owner_attestation_envelope?: SignedEnvelope<OwnerAttestationPayload>;
  proof_bundle_envelope?: SignedEnvelope<ProofBundlePayload>;

  /**
   * Optional DID rotation certificates.
   *
   * When present, clawverify may accept proof components (owner attestations / bundles)
   * whose subject DID is an *older* DID that rotates forward to agent_did.
   *
   * Fail-closed rule: if any certificate is provided, it MUST verify.
   */
  did_rotation_certificates?: DidRotationCertificate[];

  /** Optional Work Policy Contract hash. If provided, receipts must match this policy hash. */
  policy_hash?: string;
}

export interface PolicyComplianceResult {
  policy_hash: string;
  compliant: boolean;
  reason: string;
}

export interface VerifyAgentResponse {
  result: VerificationResult;
  agent_did: string;
  did_valid: boolean;
  owner_status: OwnerAttestationStatus;
  trust_tier: TrustTier;
  poh_tier: number;
  policy_compliance?: PolicyComplianceResult;
  risk_flags?: string[];
  components?: {
    owner_attestation?: {
      result: VerificationResult;
      owner_status?: OwnerAttestationStatus;
      error?: VerificationError;
    };
    proof_bundle?: {
      status: VerificationStatus;
      reason: string;
      trust_tier?: TrustTier;
      error?: VerificationError;
    };
  };
  error?: VerificationError;
}

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
 * Receipt binding fields — tie a gateway receipt to a specific run, event, and idempotency scope.
 * Mirrors the receipt_binding.v1.json schema.
 * Harnesses attach these via HTTP headers when routing LLM calls through clawproxy:
 *   X-Run-Id, X-Event-Hash, X-Idempotency-Key
 */
export interface ReceiptBinding {
  /** Run ID correlating this receipt to an agent run (from X-Run-Id header) */
  run_id?: string;
  /** Event hash linking this receipt to an event chain entry (from X-Event-Hash header) */
  event_hash_b64u?: string;
  /** Idempotency nonce preventing duplicate receipt issuance (from X-Idempotency-Key header) */
  nonce?: string;
  /** Work Policy Contract hash injected by the proxy */
  policy_hash?: string;
  /** CST token scope hash injected by the proxy */
  token_scope_hash_b64u?: string;
}

/**
 * Harness metadata identifying the runtime that produced a proof bundle or receipt.
 * Matches the harness object in urm.v1.json and proof_bundle.v1.json metadata.
 */
export interface HarnessMetadata {
  /** Harness identifier (e.g. openclaw, pi, claude-code, codex, opencode, factory-droid, script) */
  id: string;
  /** Harness version string */
  version: string;
  /** Execution environment (host, docker, clawea, tee) */
  runtime?: string;
  /** SHA-256 hash of the harness config inputs (base64url, no padding) */
  config_hash_b64u?: string;
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
  /** Binding fields tying this receipt to a run/event (set by clawproxy from headers) */
  binding?: ReceiptBinding;
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
  | 'SCHEMA_VALIDATION_FAILED'
  | 'MISSING_REQUIRED_FIELD'
  | 'INVALID_DID_FORMAT'
  | 'EXPIRED'
  | 'CLAIM_NOT_FOUND'
  | 'DEPENDENCY_NOT_CONFIGURED'
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
 * Owner Attestation types
 * CVF-US-010: Verify owner attestations
 */
export interface OwnerAttestationPayload {
  attestation_version: '1';
  attestation_id: string;
  subject_did: string;
  provider_ref?: string;
  expires_at?: string;
}

export type OwnerAttestationStatus = 'verified' | 'expired' | 'unknown';

export interface VerifyOwnerAttestationRequest {
  envelope: SignedEnvelope<OwnerAttestationPayload>;
}

export interface VerifyOwnerAttestationResponse {
  result: VerificationResult;
  owner_status?: OwnerAttestationStatus;
  attestation_id?: string;
  subject_did?: string;
  provider_ref?: string;
  expires_at?: string;
  error?: VerificationError;
}

/**
 * DID Rotation Certificate types
 * CVF-US-016: Verify DID rotation certificates
 */
export interface DidRotationCertificate {
  rotation_version: '1';
  rotation_id: string;
  old_did: string;
  new_did: string;
  issued_at: string;
  reason: string;
  signature_old_b64u: string;
  signature_new_b64u: string;
  metadata?: Record<string, unknown>;
}

export interface VerifyDidRotationRequest {
  certificate: DidRotationCertificate;
}

export interface VerifyDidRotationResponse {
  result: VerificationResult;
  rotation_id?: string;
  old_did?: string;
  new_did?: string;
  issued_at?: string;
  reason?: string;
  error?: VerificationError;
}

/**
 * Commit Proof types
 * CVF-US-011: Verify commit proofs
 */
export interface CommitProofPayload {
  proof_version: '1';
  repo_claim_id: string;
  commit_sha: string;
  repository: string;
  branch?: string;
}

export interface VerifyCommitProofRequest {
  envelope: SignedEnvelope<CommitProofPayload>;
}

export interface VerifyCommitProofResponse {
  result: VerificationResult;
  repository?: string;
  commit_sha?: string;
  signer_did?: string;
  repo_claim_id?: string;
  error?: VerificationError;
}

/**
 * Scoped Token types
 * CVF-US-013: Scoped token introspection
 */
export interface ScopedTokenPayload {
  token_version: '1';
  token_id: string;
  scope: string[];
  audience: string;
  owner_ref?: string;
  expires_at: string;
}

export interface IntrospectScopedTokenRequest {
  envelope: SignedEnvelope<ScopedTokenPayload>;
}

export interface IntrospectScopedTokenResponse {
  result: VerificationResult;
  token_id?: string;
  token_hash_b64u?: string;
  scope?: string[];
  audience?: string;
  owner_ref?: string;
  expires_at?: string;
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

/** Proof bundle metadata with optional harness information */
export interface ProofBundleMetadata {
  /** Harness metadata identifying the runtime that produced this bundle */
  harness?: HarnessMetadata;
  /** Additional metadata (non-normative) */
  [key: string]: unknown;
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
  metadata?: ProofBundleMetadata;
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
    /** Root hash of the event chain (first event's hash) */
    chain_root_hash?: string;
    receipts_valid?: boolean;
    attestations_valid?: boolean;
    receipts_count?: number;
    /** Number of receipts that passed cryptographic verification AND binding checks (when enforced). */
    receipts_verified_count?: number;
    /** Number of receipts that passed cryptographic signature+hash verification (regardless of binding). */
    receipts_signature_verified_count?: number;
    attestations_count?: number;
    /** Number of attestations that passed cryptographic signature verification (regardless of allowlist/subject binding). */
    attestations_signature_verified_count?: number;
    /** Number of attestations that counted for tier uplift (signature + allowlist + subject binding). */
    attestations_verified_count?: number;
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

/**
 * Event Chain Verification types
 * CVF-US-008: Verify event chains for tamper-evident logs
 */

/** Event chain payload for standalone event chain verification */
export interface EventChainPayload {
  chain_version: '1';
  chain_id: string;
  run_id: string;
  events: EventChainEntry[];
  metadata?: Record<string, unknown>;
}

/** Event chain verification result */
export interface EventChainVerificationResult {
  status: VerificationStatus;
  reason: string;
  verified_at: string;
  chain_id?: string;
  run_id?: string;
  chain_root_hash?: string;
  events_count?: number;
  signer_did?: string;
}

/** Verify event chain request */
export interface VerifyEventChainRequest {
  envelope: SignedEnvelope<EventChainPayload>;
}

/** Verify event chain response */
export interface VerifyEventChainResponse {
  result: EventChainVerificationResult;
  chain_root_hash?: string;
  run_id?: string;
  error?: VerificationError;
}
