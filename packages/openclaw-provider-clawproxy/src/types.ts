/**
 * Types for the OpenClaw clawproxy provider plugin.
 *
 * These types define the plugin's configuration surface and the
 * receipt structures returned by clawproxy. They intentionally
 * mirror the clawproxy Receipt type (camelCase, hex hashes) rather
 * than the clawverify SignedEnvelope format — bridging happens
 * downstream in the harness recorder (POH-US-006).
 */

// ---------------------------------------------------------------------------
// Plugin configuration
// ---------------------------------------------------------------------------

/** Configuration for the clawproxy provider plugin. */
export interface ClawproxyProviderConfig {
  /** Base URL of the clawproxy gateway (e.g. "https://proxy.clawbureau.com"). */
  baseUrl: string;
  /** Bearer token for authenticating with clawproxy (optional — user API keys forwarded if absent). */
  token?: string;

  /** Optional pinned Work Policy Contract (WPC) hash (policy_hash_b64u). */
  policyHashB64u?: string;

  /** If true, send X-Confidential-Mode: true on all proxied calls. */
  confidentialMode?: boolean;

  /** Optional receipt privacy mode override (sent as X-Receipt-Privacy-Mode). */
  receiptPrivacyMode?: 'hash_only' | 'encrypted';

  /** Upstream provider to route through (default: inferred from model ID). */
  defaultProvider?: 'anthropic' | 'openai' | 'google';
}

// ---------------------------------------------------------------------------
// Binding context (injected per-call by the harness)
// ---------------------------------------------------------------------------

/**
 * Binding context provided per model call.
 * The harness recorder (POH-US-006) populates this so that each
 * LLM call is cryptographically bound to a run and event chain entry.
 */
export interface BindingContext {
  /** Run ID for correlating receipts to agent runs. */
  runId: string;
  /** Base64url hash of the event-chain entry that triggered this LLM call. */
  eventHash?: string;
  /** Unique nonce for idempotency enforcement (5-min TTL on proxy). */
  nonce?: string;
}

// ---------------------------------------------------------------------------
// Receipt types (mirror of clawproxy Receipt)
// ---------------------------------------------------------------------------

export interface ReceiptBinding {
  runId?: string;
  eventHash?: string;
  nonce?: string;
  policyHash?: string;
  tokenScopeHashB64u?: string;
}

export interface ReceiptPayment {
  mode: 'user' | 'platform';
  paid: boolean;
  ledgerRef?: string;
}

/** Receipt issued by clawproxy, attached as `_receipt` on the response body. */
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
  payment?: ReceiptPayment;
  privacyMode?: 'hash_only' | 'encrypted';
}

// ---------------------------------------------------------------------------
// Run log artifact
// ---------------------------------------------------------------------------

/** A receipt artifact stored in the run log/artifacts. */
export interface ReceiptArtifact {
  /** Type discriminator for artifact storage. */
  type: 'clawproxy_receipt';
  /** ISO timestamp when the receipt was collected. */
  collectedAt: string;
  /** Model that was called. */
  model: string;
  /** The raw legacy receipt from clawproxy (`_receipt`, version 1.0). */
  receipt: ClawproxyReceipt;
  /** Canonical receipt envelope from clawproxy (`_receipt_envelope`, version 1). */
  receiptEnvelope?: SignedEnvelope<GatewayReceiptPayload>;
}

// ---------------------------------------------------------------------------
// OpenClaw plugin SDK types (minimal stubs)
// ---------------------------------------------------------------------------

/**
 * Minimal type stubs for the OpenClaw plugin SDK.
 *
 * In a real OpenClaw workspace these come from `openclaw/plugin-sdk`.
 * We declare them here so the package typechecks standalone in the
 * clawbureau monorepo (which doesn't depend on the OpenClaw runtime).
 */

export interface PluginDeps {
  logger: {
    info(msg: string, ...args: unknown[]): void;
    warn(msg: string, ...args: unknown[]): void;
    error(msg: string, ...args: unknown[]): void;
    debug(msg: string, ...args: unknown[]): void;
  };
  configDir: string;
  workspaceDir: string;
  rpc: {
    send(msg: { method: string; params?: unknown }): Promise<unknown>;
  };
}

export interface StreamEvent {
  type: 'text' | 'done' | 'error';
  text?: string;
  reason?: string;
  error?: string;
}

export interface ModelDescriptor {
  id: string;
  provider: string;
  capabilities: string[];
}

export interface ProviderImplementation {
  models: ModelDescriptor[];
  stream(
    model: string,
    messages: unknown[],
    options?: StreamOptions,
  ): AsyncIterable<StreamEvent>;
}

export interface StreamOptions {
  /** Authentication context (API keys, tokens). */
  auth?: Record<string, string>;
  /** Binding context for proof-of-harness receipt chaining. */
  binding?: BindingContext;
  /** Signal for request cancellation. */
  signal?: AbortSignal;
}

// ---------------------------------------------------------------------------
// Harness recorder types (POH-US-006)
// ---------------------------------------------------------------------------

/**
 * Ed25519 key pair for signing proof bundles.
 * The agent's DID is derived from the public key: did:key:z<base58btc(0xed01 + pubkey)>
 */
export interface Ed25519KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/** Configuration for the harness recorder. */
export interface RecorderConfig {
  /** Agent's Ed25519 key pair for signing the proof bundle. */
  keyPair: Ed25519KeyPair;
  /** Agent DID (did:key:z...). Derived from keyPair if omitted. */
  agentDid?: string;
  /** Harness metadata embedded in the URM and proof bundle. */
  harness: HarnessConfig;
}

/** Harness identification (matches urm.v1.json and proof_bundle.v1.json metadata.harness). */
export interface HarnessConfig {
  id: string;
  version: string;
  runtime?: string;
  configHash?: string;
}

/** Event types that the recorder supports. */
export type RecorderEventType =
  | 'run_start'
  | 'llm_call'
  | 'tool_call'
  | 'artifact_written'
  | 'run_end';

/** Input to record a new event. */
export interface RecordEventInput {
  eventType: RecorderEventType;
  /** Arbitrary payload for the event — hashed but not stored in the chain. */
  payload: unknown;
}

/** An event chain entry in the recorder's internal format (camelCase). */
export interface RecorderEvent {
  eventId: string;
  runId: string;
  eventType: string;
  timestamp: string;
  payloadHashB64u: string;
  prevHashB64u: string | null;
  eventHashB64u: string;
}

/** Resource descriptor for URM inputs/outputs (matches urm.v1.json items). */
export interface ResourceDescriptor {
  type: string;
  hashB64u: string;
  contentType?: string;
  uri?: string;
  path?: string;
  sizeBytes?: number;
  metadata?: Record<string, unknown>;
}

/** URM document (matches urm.v1.json). */
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
    metadata?: Record<string, unknown>;
  };
  inputs: Array<{
    type: string;
    hash_b64u: string;
    content_type?: string;
    uri?: string;
    path?: string;
    size_bytes?: number;
    metadata?: Record<string, unknown>;
  }>;
  outputs: Array<{
    type: string;
    hash_b64u: string;
    content_type?: string;
    uri?: string;
    path?: string;
    size_bytes?: number;
    metadata?: Record<string, unknown>;
  }>;
  event_chain_root_hash_b64u?: string;
  receipts_root_hash_b64u?: string;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Trust Pulse (self-reported UX artifact; non-tier)
// ---------------------------------------------------------------------------

export interface TrustPulseTool {
  name: string;
  calls: number;
}

export interface TrustPulseFile {
  path: string;
  touches: number;
}

export interface TrustPulseDocument {
  trust_pulse_version: '1';
  trust_pulse_id: string;
  run_id: string;
  agent_did: string;
  issued_at: string;
  evidence_class: 'self_reported';
  tier_uplift: false;
  started_at?: string;
  ended_at?: string;
  duration_ms?: number;
  tools: TrustPulseTool[];
  files: TrustPulseFile[];
}

// ---------------------------------------------------------------------------
// Prompt commitments (POH-US-016/017)
// ---------------------------------------------------------------------------

export interface PromptPackEntry {
  entry_id: string;
  content_hash_b64u: string;
  content_type?: string;
  size_bytes?: number;
}

export interface PromptPackDocument {
  prompt_pack_version: '1';
  prompt_pack_id: string;
  hash_algorithm: 'SHA-256';
  prompt_root_hash_b64u: string;
  entries: PromptPackEntry[];
}

export interface SystemPromptReportCall {
  event_id: string;
  event_hash_b64u?: string;
  provider?: string;
  model?: string;
  rendered_system_prompt_hash_b64u: string;
}

export interface SystemPromptReportDocument {
  system_prompt_report_version: '1';
  report_id: string;
  run_id: string;
  agent_did: string;
  issued_at: string;
  hash_algorithm: 'SHA-256';
  prompt_root_hash_b64u?: string;
  calls: SystemPromptReportCall[];
}

/** Event chain entry in snake_case (matches proof_bundle.v1.json / clawverify types). */
export interface EventChainEntry {
  event_id: string;
  run_id: string;
  event_type: string;
  timestamp: string;
  payload_hash_b64u: string;
  prev_hash_b64u: string | null;
  event_hash_b64u: string;
}

/** URM reference embedded in the proof bundle payload. */
export interface URMReference {
  urm_version: '1';
  urm_id: string;
  resource_type: string;
  resource_hash_b64u: string;
  metadata?: Record<string, unknown>;
}

/** Gateway receipt payload in snake_case (matches clawverify SignedEnvelope<GatewayReceiptPayload>). */
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
  metadata?: Record<string, unknown>;
}

/** Signed envelope structure (matches clawverify SignedEnvelope). */
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

/** Proof bundle payload (matches proof_bundle.v1.json). */
export interface ProofBundlePayload {
  bundle_version: '1';
  bundle_id: string;
  agent_did: string;
  urm?: URMReference;
  event_chain?: EventChainEntry[];
  receipts?: SignedEnvelope<GatewayReceiptPayload>[];
  metadata?: {
    harness?: {
      id: string;
      version: string;
      runtime?: string;
      config_hash_b64u?: string;
    };
    /** Optional prompt pack commitment (POH-US-016/017). */
    prompt_pack?: PromptPackDocument;
    /** Optional per-run system prompt report (POH-US-016/017). */
    system_prompt_report?: SystemPromptReportDocument;
    [key: string]: unknown;
  };
}

/** Options for finalizing a run and producing the proof bundle. */
export interface FinalizeOptions {
  /** Input resources for the URM. */
  inputs: ResourceDescriptor[];
  /** Output resources/artifacts for the URM. */
  outputs: ResourceDescriptor[];
  /** Additional URM metadata. */
  urmMetadata?: Record<string, unknown>;

  /** Optional prompt pack entries (hash-only) used to compute prompt_root_hash_b64u. */
  promptPackEntries?: PromptPackEntry[];
}

/** Result of finalizing a run — contains the signed proof bundle envelope and URM. */
export interface FinalizeResult {
  /** The signed proof bundle envelope. */
  envelope: SignedEnvelope<ProofBundlePayload>;
  /** The URM document (for separate storage/retrieval). */
  urm: URMDocument;
  /** Self-reported UX artifact (non-tier). */
  trustPulse: TrustPulseDocument;
}
