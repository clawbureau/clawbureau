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
  /** The raw receipt from clawproxy. */
  receipt: ClawproxyReceipt;
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
