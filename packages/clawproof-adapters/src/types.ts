/**
 * Types for clawproof external harness adapters.
 *
 * These mirror the types from @openclaw/provider-clawproxy but are
 * standalone so the adapter package typechecks independently.
 */

// ---------------------------------------------------------------------------
// Harness identification
// ---------------------------------------------------------------------------

/** Supported external harness IDs. */
export type HarnessId =
  | 'claude-code'
  | 'codex'
  | 'pi'
  | 'opencode'
  | 'factory-droid';

/** Harness configuration embedded in URM and proof bundle metadata. */
export interface HarnessConfig {
  id: HarnessId | string;
  version: string;
  runtime?: string;
  configHash?: string;
}

// ---------------------------------------------------------------------------
// Adapter configuration
// ---------------------------------------------------------------------------

/** Configuration for an external harness adapter. */
export interface AdapterConfig {
  /** Clawproxy base URL for routing LLM calls. */
  proxyBaseUrl: string;
  /** Bearer token for proxy auth (optional). */
  proxyToken?: string;
  /** Agent's Ed25519 key pair for signing proof bundles. */
  keyPair: Ed25519KeyPair;
  /** Agent DID (derived from keyPair if omitted). */
  agentDid?: string;
  /** Harness metadata. */
  harness: HarnessConfig;
  /** Directory to write proof artifacts (bundle, URM). Defaults to cwd. */
  outputDir?: string;
}

/** Ed25519 key pair (Web Crypto). */
export interface Ed25519KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
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
// Event chain types (internal camelCase)
// ---------------------------------------------------------------------------

/** Event types the adapters emit. */
export type AdapterEventType =
  | 'run_start'
  | 'llm_call'
  | 'tool_call'
  | 'artifact_written'
  | 'run_end';

/** Input to record an event. */
export interface RecordEventInput {
  eventType: AdapterEventType;
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

export interface ResourceItem {
  type: string;
  hash_b64u: string;
  content_type?: string;
  uri?: string;
  path?: string;
  size_bytes?: number;
  metadata?: Record<string, unknown>;
}

/** Proof bundle payload. */
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
    [key: string]: unknown;
  };
}

/** Resource descriptor (camelCase, for API use). */
export interface ResourceDescriptor {
  type: string;
  hashB64u: string;
  contentType?: string;
  uri?: string;
  path?: string;
  sizeBytes?: number;
  metadata?: Record<string, unknown>;
}

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
// Adapter session interface
// ---------------------------------------------------------------------------

/** A running adapter session for an external harness. */
export interface AdapterSession {
  readonly runId: string;
  readonly agentDid: string;

  /** Configured clawproxy base URL (used by the shim for streaming requests). */
  readonly proxyBaseUrl: string;
  /** Optional bearer token for proxy auth (CST/JWT). */
  readonly proxyToken?: string;

  /** Record an event in the hash-linked chain. */
  recordEvent(input: RecordEventInput): Promise<{ event: RecorderEvent; binding: BindingContext }>;

  /** Add a receipt collected from a proxied LLM call. */
  addReceipt(artifact: ReceiptArtifact): void;

  /** Proxy an LLM call through clawproxy, record event + collect receipt. */
  proxyLLMCall(params: ProxyLLMCallParams): Promise<ProxyLLMCallResult>;

  /** Finalize the run and produce signed proof bundle + URM. */
  finalize(options: FinalizeOptions): Promise<FinalizeResult>;
}

/** Parameters for a proxied LLM call. */
export interface ProxyLLMCallParams {
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
export interface ProxyLLMCallResult {
  /** The raw response body from the upstream provider. */
  response: unknown;
  /** Receipt extracted from _receipt field (if present). */
  receipt?: ReceiptArtifact;
  /** HTTP status code. */
  status: number;
}

// ---------------------------------------------------------------------------
// Environment variable configuration
// ---------------------------------------------------------------------------

/** Env var names used by adapters (documented for wrapper scripts). */
export const ENV = {
  CLAWPROXY_BASE_URL: 'CLAWPROOF_PROXY_URL',
  CLAWPROXY_TOKEN: 'CLAWPROOF_PROXY_TOKEN',
  AGENT_KEY_FILE: 'CLAWPROOF_KEY_FILE',
  OUTPUT_DIR: 'CLAWPROOF_OUTPUT_DIR',
  HARNESS_ID: 'CLAWPROOF_HARNESS_ID',
  HARNESS_VERSION: 'CLAWPROOF_HARNESS_VERSION',
} as const;
