/**
 * Types for the clawsig SDK.
 *
 * Standalone type definitions so this package typechecks independently
 * from the rest of the monorepo. Mirrors the proof-of-harness schemas
 * (snake_case for schema-facing types, camelCase for internal API).
 */

// ---------------------------------------------------------------------------
// Key pair
// ---------------------------------------------------------------------------

/** Ed25519 key pair (Web Crypto). */
export interface Ed25519KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

// ---------------------------------------------------------------------------
// SDK configuration
// ---------------------------------------------------------------------------

/** Configuration for a clawsig SDK run. */
export interface ClawproofConfig {
  /** Clawproxy base URL for routing LLM calls. */
  proxyBaseUrl: string;
  /** Bearer token for proxy auth (optional). */
  proxyToken?: string;
  /** Agent's Ed25519 key pair for signing proof bundles. */
  keyPair: Ed25519KeyPair;
  /** Agent DID (derived from keyPair if omitted). */
  agentDid?: string;
  /** Harness/script metadata embedded in URM and proof bundle. */
  harness: HarnessConfig;
}

/** Harness/script identification metadata. */
export interface HarnessConfig {
  id: string;
  version: string;
  runtime?: string;
  configHash?: string;
}

// ---------------------------------------------------------------------------
// Binding context
// ---------------------------------------------------------------------------

/** Per-call binding context injected into proxy requests. */
export interface BindingContext {
  runId: string;
  eventHash?: string;
  nonce?: string;
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/** Standard event types the SDK emits. */
export type SDKEventType =
  | 'run_start'
  | 'llm_call'
  | 'tool_call'
  | 'artifact_written'
  | 'run_end'
  | string;

/** Input to record an event. */
export interface RecordEventInput {
  eventType: SDKEventType;
  payload: unknown;
}

/** Internal event representation (camelCase). */
export interface RecorderEvent {
  eventId: string;
  runId: string;
  eventType: string;
  timestamp: string;
  payloadHashB64u: string;
  prevHashB64u: string | null;
  eventHashB64u: string;
}

// ---------------------------------------------------------------------------
// Receipt types (mirrors clawproxy response)
// ---------------------------------------------------------------------------

export interface ReceiptBinding {
  runId?: string;
  eventHash?: string;
  nonce?: string;
  policyHash?: string;
  tokenScopeHashB64u?: string;
}

/** Receipt from clawproxy _receipt response field. */
export interface ClawproxyReceipt {
  version: '1.0';
  proxyDid?: string;
  provider: string;
  model?: string;
  requestHash: string;
  responseHash: string;
  timestamp: string;
  latencyMs: number;
  signature?: string;
  kid?: string;
  binding?: ReceiptBinding;
}

/** Receipt artifact collected during a run. */
export interface ReceiptArtifact {
  type: 'clawproxy_receipt';
  collectedAt: string;
  model: string;
  /** Legacy clawproxy receipt (`_receipt`, version 1.0). */
  receipt: ClawproxyReceipt;
  /** Canonical clawproxy receipt envelope (`_receipt_envelope`, version 1). */
  receiptEnvelope?: SignedEnvelope<GatewayReceiptPayload>;
}

// ---------------------------------------------------------------------------
// Proof bundle types (snake_case, schema-facing)
// ---------------------------------------------------------------------------

/** Event chain entry (matches proof_bundle.v1.json). */
export interface EventChainEntry {
  event_id: string;
  run_id: string;
  event_type: string;
  timestamp: string;
  payload_hash_b64u: string;
  prev_hash_b64u: string | null;
  event_hash_b64u: string;
}

/** Gateway receipt payload (matches clawverify types). */
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
  binding?: {
    run_id?: string;
    event_hash_b64u?: string;
    nonce?: string;
    policy_hash?: string;
    token_scope_hash_b64u?: string;
  };
}

/** Signed envelope (matches clawverify). */
export interface SignedEnvelope<T = unknown> {
  envelope_version: '1';
  envelope_type: string;
  payload: T;
  payload_hash_b64u: string;
  hash_algorithm: 'SHA-256';
  signature_b64u: string;
  algorithm: 'Ed25519';
  signer_did: string;
  issued_at: string;
}

/** URM reference in proof bundle. */
export interface URMReference {
  urm_version: '1';
  urm_id: string;
  resource_type: string;
  resource_hash_b64u: string;
}

/** Resource item in URM (snake_case). */
export interface ResourceItem {
  type: string;
  hash_b64u: string;
  content_type?: string;
  uri?: string;
  path?: string;
  size_bytes?: number;
  metadata?: Record<string, unknown>;
}

/** URM document. */
export interface URMDocument {
  urm_version: '1';
  urm_id: string;
  run_id: string;
  agent_did: string;
  issued_at: string;
  harness: {
    id: string;
    version: string;
    runtime?: string;
    config_hash_b64u?: string;
  };
  inputs: ResourceItem[];
  outputs: ResourceItem[];
  event_chain_root_hash_b64u?: string;
  receipts_root_hash_b64u?: string;
  metadata?: Record<string, unknown>;
}

/** Proof bundle payload (matches proof_bundle.v1.json). */
export interface ProofBundlePayload {
  bundle_version: '1';
  bundle_id: string;
  agent_did: string;
  urm?: URMReference;
  event_chain?: EventChainEntry[];
  receipts?: SignedEnvelope<GatewayReceiptPayload>[];
  tool_receipts?: ToolReceiptPayload[];
  side_effect_receipts?: SideEffectReceiptPayload[];
  /** Execution receipts from the Sentinel Shell (bash commands). */
  execution_receipts?: ExecutionReceiptPayload[];
  /** Network receipts from the Network Sentinel (TCP connections). */
  network_receipts?: NetworkReceiptPayload[];
  human_approval_receipts?: HumanApprovalReceiptPayload[];
  metadata?: {
    harness?: {
      id: string;
      version: string;
      runtime?: string;
      config_hash_b64u?: string;
    };
    sentinels?: {
      shell_events?: number;
      fs_events?: number;
      net_events?: number;
      net_suspicious?: number;
      interpose_events?: number;
      interpose_active?: boolean;
    };
    [key: string]: unknown;
  };
}

// ---------------------------------------------------------------------------
// Execution receipt types (Sentinel Shell observations)
// ---------------------------------------------------------------------------

/** Execution receipt: a shell command observed by the Sentinel Shell. */
export interface ExecutionReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  /** The command string that was executed. */
  command_hash_b64u: string;
  /** Classification: command, network_egress, secret_access, env_manipulation. */
  command_type: string;
  /** Extracted target (URL, file path, env var). */
  target_hash_b64u?: string;
  /** PID that executed the command. */
  pid: number;
  /** Parent PID. */
  ppid: number;
  /** Working directory at execution time. */
  cwd_hash_b64u: string;
  /** Exit code of the previous command. */
  exit_code: number;
  /** Semantic command analysis metadata. */
  metadata?: {
    risk?: 'safe' | 'caution' | 'dangerous' | 'critical';
    data_flow?: 'inbound' | 'outbound' | 'bidirectional' | 'local' | 'unknown';
    patterns?: string[];
  };
  hash_algorithm: 'SHA-256';
  agent_did: string;
  timestamp: string;
  binding?: {
    run_id?: string;
  };
}

// ---------------------------------------------------------------------------
// Network receipt types (Network Sentinel observations)
// ---------------------------------------------------------------------------

/** Network receipt: a TCP connection observed by the Network Sentinel. */
export interface NetworkReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  /** Protocol (tcp, tcp6). */
  protocol: string;
  /** Remote address hash (IP:port). */
  remote_address_hash_b64u: string;
  /** Connection state. */
  state: string;
  /** Classification: llm_provider, authorized, suspicious, local. */
  classification: string;
  /** PID that owns the connection (if resolved). */
  pid: number | null;
  /** Process name (if resolved). */
  process_name: string | null;
  hash_algorithm: 'SHA-256';
  agent_did: string;
  timestamp: string;
  binding?: {
    run_id?: string;
  };
}

// ---------------------------------------------------------------------------
// Tool receipt types (matches poh/tool_receipt.v1.json)
// ---------------------------------------------------------------------------

/** Tool receipt payload. Hash-only by default. */
export interface ToolReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  tool_name: string;
  tool_version?: string;
  args_hash_b64u: string;
  result_hash_b64u: string;
  result_status?: 'success' | 'error' | 'timeout';
  hash_algorithm: 'SHA-256';
  agent_did: string;
  timestamp: string;
  latency_ms: number;
  binding?: {
    run_id?: string;
    event_hash_b64u?: string;
    nonce?: string;
    policy_hash?: string;
    token_scope_hash_b64u?: string;
  };
}

/** Tool receipt artifact collected during a run. */
export interface ToolReceiptArtifact {
  type: 'tool_receipt';
  collectedAt: string;
  toolName: string;
  receipt: ToolReceiptPayload;
  receiptEnvelope?: SignedEnvelope<ToolReceiptPayload>;
}

/** Parameters for recording a tool call. */
export interface ToolCallParams {
  /** Canonical tool name (e.g. 'bash', 'read_file'). */
  toolName: string;
  /** Tool version (optional). */
  toolVersion?: string;
  /** Raw tool arguments (will be hashed). */
  args: unknown;
  /** Raw tool result (will be hashed). */
  result: unknown;
  /** High-level outcome. */
  resultStatus?: 'success' | 'error' | 'timeout';
  /** Latency in ms. */
  latencyMs: number;
}

// ---------------------------------------------------------------------------
// Side-effect receipt types (matches poh/side_effect_receipt.v1.json)
// ---------------------------------------------------------------------------

/** Side-effect receipt payload. Hash-only by default. */
export interface SideEffectReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  effect_class: 'network_egress' | 'filesystem_write' | 'external_api_write';
  target_hash_b64u: string;
  vendor_id?: string;
  request_hash_b64u: string;
  response_hash_b64u: string;
  response_status?: 'success' | 'error' | 'timeout' | 'denied';
  hash_algorithm: 'SHA-256';
  agent_did: string;
  timestamp: string;
  latency_ms: number;
  bytes_written?: number;
  binding?: {
    run_id?: string;
    event_hash_b64u?: string;
    nonce?: string;
    policy_hash?: string;
    token_scope_hash_b64u?: string;
    capability_id?: string;
  };
}

/** Side-effect receipt artifact collected during a run. */
export interface SideEffectReceiptArtifact {
  type: 'side_effect_receipt';
  collectedAt: string;
  effectClass: string;
  receipt: SideEffectReceiptPayload;
  receiptEnvelope?: SignedEnvelope<SideEffectReceiptPayload>;
}

/** Parameters for recording a side effect. */
export interface SideEffectParams {
  effectClass: 'network_egress' | 'filesystem_write' | 'external_api_write';
  /** Raw target (URL, path, endpoint). Will be hashed. */
  target: unknown;
  vendorId?: string;
  /** Raw request payload. Will be hashed. */
  request: unknown;
  /** Raw response payload. Will be hashed. */
  response: unknown;
  responseStatus?: 'success' | 'error' | 'timeout' | 'denied';
  latencyMs: number;
  bytesWritten?: number;
}

// ---------------------------------------------------------------------------
// Human approval receipt types (matches poh/human_approval_receipt.v1.json)
// ---------------------------------------------------------------------------

/** Human approval receipt payload. */
export interface HumanApprovalReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  approval_type: 'explicit_approve' | 'explicit_deny' | 'auto_approve' | 'timeout_deny';
  approver_subject: string;
  approver_method?: 'ui_click' | 'cli_confirm' | 'api_call' | 'policy_auto' | 'timeout';
  agent_did: string;
  scope_hash_b64u: string;
  scope_summary?: string;
  policy_hash_b64u?: string;
  minted_capability_id?: string;
  minted_capability_ttl_seconds?: number;
  plan_hash_b64u?: string;
  evidence_required?: string[];
  hash_algorithm: 'SHA-256';
  timestamp: string;
  binding?: {
    run_id?: string;
    event_hash_b64u?: string;
    nonce?: string;
    policy_hash?: string;
    token_scope_hash_b64u?: string;
  };
}

/** Human approval receipt artifact. */
export interface HumanApprovalReceiptArtifact {
  type: 'human_approval_receipt';
  collectedAt: string;
  approvalType: string;
  receipt: HumanApprovalReceiptPayload;
  receiptEnvelope?: SignedEnvelope<HumanApprovalReceiptPayload>;
}

/** Parameters for recording a human approval event. */
export interface HumanApprovalParams {
  approvalType: 'explicit_approve' | 'explicit_deny' | 'auto_approve' | 'timeout_deny';
  approverSubject: string;
  approverMethod?: 'ui_click' | 'cli_confirm' | 'api_call' | 'policy_auto' | 'timeout';
  /** Raw scope claims. Will be hashed. */
  scopeClaims: unknown;
  scopeSummary?: string;
  policyHashB64u?: string;
  mintedCapabilityId?: string;
  mintedCapabilityTtlSeconds?: number;
  /** Raw plan/diff. Will be hashed if provided. */
  plan?: unknown;
  evidenceRequired?: string[];
}

// ---------------------------------------------------------------------------
// Capability negotiation types (matches poh/capability_request/response.v1.json)
// ---------------------------------------------------------------------------

/** Capability request (agent → authority). */
export interface CapabilityRequestPayload {
  request_version: '1';
  request_id: string;
  agent_did: string;
  requested_scope: {
    actions: string[];
    tools?: string[];
    ttl_seconds?: number;
    policy_hash_b64u?: string;
  };
  reason: string;
  plan_hash_b64u?: string;
  preflight?: boolean;
  timestamp: string;
  binding?: {
    run_id?: string;
    event_hash_b64u?: string;
  };
}

/** Capability response (authority → agent). */
export interface CapabilityResponsePayload {
  response_version: '1';
  response_id: string;
  request_id: string;
  decision: 'granted' | 'denied' | 'requires_approval' | 'preflight_pass' | 'preflight_fail';
  reason_code?: string;
  reason?: string;
  granted_capability?: {
    capability_id: string;
    scope_hash_b64u: string;
    policy_hash_b64u?: string;
    ttl_seconds?: number;
    expires_at?: string;
    evidence_required?: string[];
  };
  denied_actions?: Array<{
    action: string;
    reason_code: string;
    rule?: string;
    suggestion?: string;
  }>;
  approval_channel?: string;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// Camel-case resource descriptor (API-facing)
// ---------------------------------------------------------------------------

/** Resource descriptor (camelCase, for SDK API use). */
export interface ResourceDescriptor {
  type: string;
  hashB64u: string;
  contentType?: string;
  uri?: string;
  path?: string;
  sizeBytes?: number;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Finalization
// ---------------------------------------------------------------------------

/** Options for finalizing a run. */
export interface FinalizeOptions {
  inputs: ResourceDescriptor[];
  outputs: ResourceDescriptor[];
  urmMetadata?: Record<string, unknown>;
}

/** Result of finalization. */
export interface FinalizeResult {
  envelope: SignedEnvelope<ProofBundlePayload>;
  urm: URMDocument;
}

// ---------------------------------------------------------------------------
// LLM call proxying
// ---------------------------------------------------------------------------

/** Parameters for a proxied LLM call. */
export interface LLMCallParams {
  /** Upstream provider (anthropic, openai, google). */
  provider: string;
  /** Model ID (e.g. claude-sonnet-4-5-20250929). */
  model: string;
  /** Request body (provider-specific format). */
  body: unknown;
  /** Extra headers to pass through. */
  headers?: Record<string, string>;
}

/** Result of a proxied LLM call. */
export interface LLMCallResult {
  /** The raw response body from the upstream provider. */
  response: unknown;
  /** Receipt extracted from _receipt field (if present). */
  receipt?: ReceiptArtifact;
  /** HTTP status code. */
  status: number;
}

// ---------------------------------------------------------------------------
// Run interface
// ---------------------------------------------------------------------------

/** A clawsig run — the main SDK handle for recording events and producing proof bundles. */
export interface ClawproofRun {
  /** Unique run ID for this session. */
  readonly runId: string;
  /** Agent DID derived from the key pair. */
  readonly agentDid: string;

  /** Record an event in the hash-linked chain. Returns binding context for LLM calls. */
  recordEvent(input: RecordEventInput): Promise<{ event: RecorderEvent; binding: BindingContext }>;

  /** Add a receipt collected from a proxied LLM call. */
  addReceipt(artifact: ReceiptArtifact): void;

  /** Record a tool call, producing a hash-only tool receipt and event chain entry. */
  recordToolCall(params: ToolCallParams): Promise<ToolReceiptArtifact>;

  /** Record a side effect (network egress, filesystem write, external API write). */
  recordSideEffect(params: SideEffectParams): Promise<SideEffectReceiptArtifact>;

  /** Record a human approval decision. */
  recordHumanApproval(params: HumanApprovalParams): Promise<HumanApprovalReceiptArtifact>;

  /** Proxy an LLM call through clawproxy, automatically recording event + collecting receipt. */
  callLLM(params: LLMCallParams): Promise<LLMCallResult>;

  /** Finalize the run: generate URM, assemble + sign proof bundle. */
  finalize(options: FinalizeOptions): Promise<FinalizeResult>;
}
