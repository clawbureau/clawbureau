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
  'web_receipt',
  'proof_bundle',
  'event_chain',
  'owner_attestation',
  'commit_proof',
  'execution_attestation',
  'derivation_attestation',
  'audit_result_attestation',
  'export_bundle',
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
  /** Optional materialized URM document for the provided proof_bundle_envelope (POH-US-015). */
  urm?: URMDocument;

  /** Optional execution attestations (CEA-US-010). */
  execution_attestations?: SignedEnvelope<ExecutionAttestationPayload>[];

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
  proof_tier: ProofTier;
  poh_tier: number;
  model_identity_tier?: ModelIdentityTier;
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
      proof_tier?: ProofTier;
      model_identity_tier?: ModelIdentityTier;
      error?: VerificationError;
    };

    execution_attestation?: {
      status: VerificationStatus;
      reason: string;
      verified_count?: number;
      proof_tier?: ProofTier;
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
  | 'URM_MISSING'
  | 'URM_MISMATCH'
  | 'PROMPT_COMMITMENT_MISMATCH'
  | 'SIGNATURE_INVALID'
  | 'MALFORMED_ENVELOPE'
  | 'SCHEMA_VALIDATION_FAILED'
  | 'MISSING_REQUIRED_FIELD'
  | 'INVALID_DID_FORMAT'
  | 'EXPIRED'
  | 'CLAIM_NOT_FOUND'
  | 'DEPENDENCY_NOT_CONFIGURED'
  | 'PARSE_ERROR'
  | 'INCLUSION_PROOF_INVALID'
  | 'REVOKED'
  | 'CONTROL_CHAIN_NOT_FOUND'
  | 'CONTROL_CHAIN_CONTEXT_MISMATCH'
  | 'TOKEN_CONTROL_SCOPE_HASH_MISMATCH'
  | 'TOKEN_CONTROL_AUDIENCE_MISMATCH'
  | 'TOKEN_CONTROL_SCOPE_MISSING'
  | 'TOKEN_CONTROL_TRANSITION_FORBIDDEN'
  | 'TOKEN_CONTROL_CHAIN_MISSING'
  | 'TOKEN_CONTROL_SUBJECT_MISMATCH';

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
  model_identity_tier?: ModelIdentityTier;
  risk_flags?: string[];
  error?: VerificationError;
}

/**
 * Witnessed web receipt types
 * POH-US-018: Verify witnessed-web receipts (distinct from gateway API receipts)
 */
export interface WebReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  witness_id: string;
  source: 'chatgpt_web' | 'claude_web' | 'gemini_web' | 'other';
  request_hash_b64u: string;
  response_hash_b64u: string;
  session_hash_b64u?: string;
  timestamp: string;
  binding?: ReceiptBinding;
  metadata?: Record<string, unknown>;
}

export interface VerifyWebReceiptRequest {
  envelope: SignedEnvelope<WebReceiptPayload>;
}

export interface VerifyWebReceiptResponse {
  result: VerificationResult;
  witness_id?: string;
  source?: WebReceiptPayload['source'];
  proof_tier?: ProofTier;
  equivalent_to_gateway?: boolean;
  error?: VerificationError;
}

/**
 * Derivation Attestation types
 * CVF-US-017: Verify derivation attestations
 */
export interface DerivationAttestationPayload {
  derivation_version: '1';
  derivation_id: string;
  issued_at: string;
  input_model: unknown;
  output_model: unknown;
  transform: {
    kind: string;
    code_hash_b64u?: string;
    params_hash_b64u?: string;
    build_steps?: string[];
  };
  artifacts?: unknown[];
  execution?: Record<string, unknown>;
  clawlogs?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface VerifyDerivationAttestationRequest {
  envelope: SignedEnvelope<DerivationAttestationPayload>;
}

export interface VerifyDerivationAttestationResponse {
  result: VerificationResult;
  derivation_id?: string;
  transform_kind?: string;
  input_model?: {
    provider?: string;
    name?: string;
    tier?: ModelIdentityTier;
  };
  output_model?: {
    provider?: string;
    name?: string;
    tier?: ModelIdentityTier;
  };
  clawlogs_inclusion_proof_validated?: boolean;
  error?: VerificationError;
}

/**
 * Audit Result Attestation types
 * CVF-US-018: Verify audit result attestations
 */
export interface AuditResultAttestationPayload {
  audit_version: '1';
  audit_id: string;
  issued_at: string;
  expires_at?: string;
  audit_pack?: {
    pack_id?: string;
    pack_version?: string;
    pack_hash_b64u: string;
  };
  model: unknown;
  derivation_attestation_hash_b64u?: string;
  audit_code: {
    repo_uri?: string;
    commit_sha?: string;
    code_hash_b64u: string;
    uri?: string;
  };
  dataset: {
    dataset_id: string;
    dataset_hash_b64u: string;
    access: 'public' | 'confidential';
    uri?: string;
  };
  protocol: {
    name: string;
    config_hash_b64u: string;
    seed?: number;
  };
  result: {
    status: 'pass' | 'fail' | 'warn';
    results_hash_b64u: string;
    summary?: Record<string, unknown>;
  };
  execution?: Record<string, unknown>;
  clawlogs?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface VerifyAuditResultAttestationRequest {
  envelope: SignedEnvelope<AuditResultAttestationPayload>;
}

export interface VerifyAuditResultAttestationResponse {
  result: VerificationResult;
  audit_id?: string;
  audit_pack_hash_b64u?: string;
  model?: {
    provider?: string;
    name?: string;
    tier?: ModelIdentityTier;
  };
  audit_code_hash_b64u?: string;
  dataset_id?: string;
  dataset_hash_b64u?: string;
  protocol_name?: string;
  protocol_config_hash_b64u?: string;
  result_status?: string;
  results_hash_b64u?: string;
  clawlogs_inclusion_proof_validated?: boolean;
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
 * Execution Attestation types
 * CEA-US-010: Sandbox execution attestation verification
 */
export interface ExecutionAttestationPayload {
  attestation_version: '1';
  attestation_id: string;
  execution_type: 'sandbox_execution' | 'tee_execution';
  agent_did: string;
  attester_did: string;
  run_id?: string;
  proof_bundle_hash_b64u?: string;
  harness?: {
    id?: string;
    version?: string;
    runtime?: string;
    config_hash_b64u?: string;
  };
  runtime_metadata?: {
    tee?: {
      attestation_type:
        | 'sgx_quote'
        | 'tdx_quote'
        | 'sev_snp_report'
        | 'nitro_attestation_doc'
        | 'generic_tee';
      root_id: string;
      tcb_version: string;
      evidence_ref: {
        resource_type: string;
        resource_hash_b64u: string;
        uri?: string;
      };
      measurements: {
        measurement_hash_b64u: string;
        runtime_digest_b64u?: string;
        kernel_digest_b64u?: string;
      };
      tcb?: {
        status?: 'up_to_date' | 'out_of_date' | 'configuration_needed' | 'revoked' | 'unknown';
        advisory_ids?: string[];
      };
      metadata?: Record<string, unknown>;
    };
    [key: string]: unknown;
  };
  issued_at: string;
  expires_at?: string;
  metadata?: Record<string, unknown>;
}

export interface VerifyExecutionAttestationRequest {
  envelope: SignedEnvelope<ExecutionAttestationPayload>;
}

export interface VerifyExecutionAttestationResponse {
  result: VerificationResult;
  attestation_id?: string;
  execution_type?: ExecutionAttestationPayload['execution_type'];
  agent_did?: string;
  attester_did?: string;
  run_id?: string;
  proof_bundle_hash_b64u?: string;
  signer_did?: string;
  allowlisted?: boolean;
  tee_root_id?: string;
  tee_tcb_version?: string;
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
 * Identity control-plane verification hints
 * CVF-US-018: deterministic remediation guidance
 */
export type RemediationHintCode =
  | 'REGISTER_OWNER_BINDING'
  | 'REGISTER_CONTROLLER'
  | 'REGISTER_AGENT_UNDER_CONTROLLER'
  | 'UPDATE_SENSITIVE_POLICY'
  | 'USE_CANONICAL_CST_LANE'
  | 'REQUEST_REQUIRED_SCOPE'
  | 'REQUEST_REQUIRED_AUDIENCE'
  | 'REISSUE_TOKEN'
  | 'ROTATE_KEYS_WITH_OVERLAP'
  | 'SYNC_REVOCATION_STREAM'
  | 'CHECK_CONTROL_CHAIN_CONFIG';

export interface RemediationHint {
  code: RemediationHintCode;
  message: string;
  action: string;
}

export interface VerifyControlChainRequest {
  owner_did: string;
  controller_did: string;
  agent_did: string;
}

export interface VerifyControlChainResponse {
  result: VerificationResult;
  owner_did: string;
  controller_did: string;
  agent_did: string;
  chain_active: boolean;
  policy_hash_b64u?: string;
  remediation_hints?: RemediationHint[];
  error?: VerificationError;
}

export interface VerifyTokenControlRequest {
  token: string;
  expected_owner_did?: string;
  expected_controller_did?: string;
  expected_agent_did?: string;
  required_audience?: string | string[];
  required_scope?: string[];
  required_transitions?: string[];
}

export interface VerifyTokenControlResponse {
  result: VerificationResult;
  token_hash?: string;
  active?: boolean;
  revoked?: boolean;
  token_lane?: 'legacy' | 'canonical';
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  aud?: string | string[];
  scope?: string[];
  token_scope_hash_b64u?: string;
  transition_matrix?: Record<
    string,
    {
      allowed: boolean;
      reason_code: string;
      reason: string;
    }
  >;
  remediation_hints?: RemediationHint[];
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
  model_identity_tier?: ModelIdentityTier;
  risk_flags?: string[];
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

/** Universal Resource Manifest (URM) reference embedded in a proof bundle. */
export interface URMReference {
  urm_version: '1';
  urm_id: string;
  resource_type: string;
  resource_hash_b64u: string;
  metadata?: Record<string, unknown>;
}

/** Resource item in a URM (inputs/outputs). */
export interface URMResourceItem {
  type: string;
  hash_b64u: string;
  content_type?: string;
  uri?: string;
  path?: string;
  size_bytes?: number;
  metadata?: Record<string, unknown>;
}

/** Harness descriptor embedded in a URM. */
export interface URMHarness {
  id: string;
  version: string;
  runtime?: string;
  config_hash_b64u?: string;
  metadata?: Record<string, unknown>;
}

/** Universal Run Manifest (URM) document (materialized bytes). */
export interface URMDocument {
  urm_version: '1';
  urm_id: string;
  run_id: string;
  agent_did: string;
  issued_at: string;
  harness: URMHarness;
  inputs: URMResourceItem[];
  outputs: URMResourceItem[];
  event_chain_root_hash_b64u?: string;
  receipts_root_hash_b64u?: string;
  proof_bundle_hash_b64u?: string;
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

/** Trust tiers computed from proof bundle contents (verifier-internal). */
export type TrustTier = 'unknown' | 'basic' | 'verified' | 'attested' | 'full';

/**
 * Canonical proof tiers (marketplace-facing) derived from verified components.
 *
 * Ordering (low → high):
 * - unknown: no verified evidence
 * - self: agent-signed evidence only
 * - gateway: includes at least one valid gateway receipt bound to the bundle event chain
 * - sandbox: includes at least one valid sandbox/execution attestation (allowlisted + signature verified)
 * - tee: reserved (future)
 * - witnessed_web: reserved (future; subscription/web auth only counts when witnessed)
 */
export type ProofTier =
  | 'unknown'
  | 'self'
  | 'gateway'
  | 'sandbox'
  | 'tee'
  | 'witnessed_web';

/**
 * PoH vNext: model identity tier (orthogonal to PoH proof tiers).
 *
 * Semantics:
 * - `proof_tier` answers: "how was it executed?" (self/gateway/sandbox)
 * - `model_identity_tier` answers: "what can we honestly claim about the underlying model identity?"
 */
export type ModelIdentityTier =
  | 'unknown'
  | 'closed_opaque'
  | 'closed_provider_manifest'
  | 'openweights_hashable'
  | 'tee_measured';

/** Proof bundle verification result */
export interface ProofBundleVerificationResult {
  status: VerificationStatus;
  reason: string;
  verified_at: string;
  bundle_id?: string;
  agent_did?: string;
  trust_tier?: TrustTier;
  proof_tier?: ProofTier;
  model_identity_tier?: ModelIdentityTier;
  /** Optional deterministic risk flags (non-normative). */
  risk_flags?: string[];
  component_results?: {
    envelope_valid: boolean;
    urm_valid?: boolean;
    event_chain_valid?: boolean;
    /** Root hash of the event chain (first event's hash) */
    chain_root_hash?: string;

    // POH-US-016/017 (optional prompt commitments; do not uplift tier)
    prompt_pack_valid?: boolean;
    system_prompt_report_valid?: boolean;

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

    /** CEA-US-010: optional execution attestation evidence (outside the proof bundle). */
    execution_attestations_valid?: boolean;
    execution_attestations_count?: number;
    execution_attestations_verified_count?: number;
  };
}

/** Verify bundle request */
export interface VerifyBundleRequest {
  envelope: SignedEnvelope<ProofBundlePayload>;
  /** Optional materialized URM document bytes (JSON object). */
  urm?: URMDocument;

  /** Optional execution attestations (CEA-US-010). */
  execution_attestations?: SignedEnvelope<ExecutionAttestationPayload>[];
}

/** Verify bundle response */
export interface VerifyBundleResponse {
  result: ProofBundleVerificationResult;
  trust_tier?: TrustTier;
  proof_tier?: ProofTier;
  model_identity_tier?: ModelIdentityTier;
  risk_flags?: string[];
  error?: VerificationError;
}

/**
 * Export Bundle verification (POHVN-US-007)
 */

export interface ExportBundleManifestEntry {
  path: string;
  sha256_b64u: string;
  content_type: string;
  size_bytes: number;
}

export interface ExportBundleManifest {
  manifest_version: '1';
  generated_at: string;
  entries: ExportBundleManifestEntry[];
}

export interface ExportBundleArtifacts {
  proof_bundle_envelope: SignedEnvelope<ProofBundlePayload>;
  execution_attestation_envelopes?: SignedEnvelope<ExecutionAttestationPayload>[];
  derivation_attestation_envelopes?: SignedEnvelope<DerivationAttestationPayload>[];
  audit_result_attestation_envelopes?: SignedEnvelope<AuditResultAttestationPayload>[];
}

export interface ExportBundlePayload {
  export_version: '1';
  export_id: string;
  created_at: string;
  issuer_did: string;
  manifest: ExportBundleManifest;
  artifacts: ExportBundleArtifacts;
  bundle_hash_b64u: string;
  hash_algorithm: 'SHA-256';
  signature_b64u: string;
  algorithm: 'Ed25519';
  issued_at: string;
  metadata?: Record<string, unknown>;
}

export interface VerifyExportBundleRequest {
  bundle: ExportBundlePayload;
}

export interface VerifyExportBundleResponse {
  result: VerificationResult;
  export_id?: string;
  bundle_hash_b64u?: string;
  manifest_entries_verified?: number;
  verified_components?: {
    proof_bundle_valid: boolean;
    execution_attestations_verified: number;
    derivation_attestations_verified: number;
    audit_result_attestations_verified: number;
  };
  proof_tier?: ProofTier;
  model_identity_tier?: ModelIdentityTier;
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
