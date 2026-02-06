/**
 * Clawproxy type definitions
 */

/**
 * Cloudflare Workers Rate Limit binding
 */
export interface RateLimit {
  limit(options: { key: string }): Promise<RateLimitOutcome>;
}

/**
 * Result from rate limit check
 */
export interface RateLimitOutcome {
  success: boolean;
}

export interface Env {
  PROXY_VERSION: string;
  /** Ed25519 private key in base64url format for signing receipts */
  PROXY_SIGNING_KEY?: string;
  /** Rate limiter binding for request throttling */
  PROXY_RATE_LIMITER: RateLimit;
  /** Optional AES key for encrypting receipt payloads (base64url-encoded 32-byte key) */
  PROXY_ENCRYPTION_KEY?: string;

  /**
   * CST (Scoped Token) issuer public key for validating JWT (EdDSA/Ed25519)
   * Base64url-encoded raw 32-byte Ed25519 public key.
   */
  CST_ISSUER_PUBLIC_KEY?: string;

  /** Optional audience override for CST validation (defaults to request host/origin) */
  CST_AUDIENCE?: string;

  /**
   * CPX-US-013: Platform-paid inference mode (reserve-backed)
   * When enabled, requests without an Authorization header may be routed using platform reserve credits.
   */
  PLATFORM_PAID_ENABLED?: string;

  /** Platform-paid provider API keys (used when PLATFORM_PAID_ENABLED is true) */
  PLATFORM_ANTHROPIC_API_KEY?: string;
  PLATFORM_OPENAI_API_KEY?: string;
  PLATFORM_GOOGLE_API_KEY?: string;
}

/**
 * Verification method for DID document
 * Follows W3C DID Core specification
 */
export interface VerificationMethod {
  /** Full key ID (DID#kid format) */
  id: string;
  /** Key type (Ed25519VerificationKey2020 for Ed25519) */
  type: 'Ed25519VerificationKey2020';
  /** Controller DID */
  controller: string;
  /** Public key in multibase format (base64url) */
  publicKeyMultibase: string;
}

/**
 * Deployment metadata for proxy instance
 */
export interface DeploymentMetadata {
  /** Proxy software version */
  version: string;
  /** Whether receipt signing is enabled */
  signingEnabled: boolean;
  /** Whether payload encryption is available */
  encryptionEnabled: boolean;
  /** Runtime environment identifier */
  runtime: 'cloudflare-workers';
  /** Optional deployment region (when available) */
  region?: string;
  /** Service name */
  service: string;

  /**
   * did:key signer DID used for canonical gateway receipt envelopes.
   * This is derived from PROXY_SIGNING_KEY public key and is safe to expose.
   */
  receiptSignerDidKey?: string;
}

/**
 * DID document response for /v1/did endpoint
 * Follows W3C DID Core specification with extensions for proxy metadata
 */
export interface DidResponse {
  /** DID document context */
  '@context': string[];
  /** DID identifier (did:web:clawproxy.com) */
  id: string;
  /** Verification methods (public keys) */
  verificationMethod: VerificationMethod[];
  /** Authentication key references */
  authentication: string[];
  /** Assertion method key references (for signing) */
  assertionMethod: string[];
  /** Deployment metadata (custom extension) */
  deployment: DeploymentMetadata;
}

/**
 * Supported LLM providers
 */
export type Provider = 'anthropic' | 'openai' | 'google';

/**
 * Provider configuration for routing
 */
export interface ProviderConfig {
  baseUrl: string;
  authHeader: string;
  contentType: string;
}

/**
 * Binding fields for chaining receipts to runs/events
 */
export interface ReceiptBinding {
  /** Run ID for correlating receipts to agent runs */
  runId?: string;
  /** Hash of the previous event in the chain */
  eventHash?: string;
  /** Unique nonce for idempotency enforcement */
  nonce?: string;
  /** Work Policy Contract hash for policy binding */
  policyHash?: string;
  /** Base64url token scope hash from CST claims (token_scope_hash_b64u) */
  tokenScopeHashB64u?: string;
}

/**
 * Receipt payment modes
 * - user: user provided provider API key; proxy did not spend reserve credits
 * - platform: proxy spent platform reserve credits (platform-paid inference)
 */
export type ReceiptPaymentMode = 'user' | 'platform';

export interface ReceiptPayment {
  mode: ReceiptPaymentMode;
  /** True when platform reserve credits were spent */
  paid: boolean;
  /** Reference to the ledger entry that recorded the spend (when paid=true) */
  ledgerRef?: string;
}

/**
 * Receipt privacy modes
 * - hash_only: Only include hashes (default, most private)
 * - encrypted: Include encrypted payloads for authorized decryption
 */
export type ReceiptPrivacyMode = 'hash_only' | 'encrypted';

/**
 * Encrypted payload for receipts (when privacy mode = 'encrypted')
 * Uses AES-256-GCM with per-receipt keys
 */
export interface EncryptedPayload {
  /** Encryption algorithm used */
  algorithm: 'AES-256-GCM';
  /** Base64url-encoded IV (12 bytes for GCM) */
  iv: string;
  /** Base64url-encoded ciphertext */
  ciphertext: string;
  /** Base64url-encoded authentication tag (16 bytes for GCM) */
  tag: string;
  /** Key ID used to wrap the content encryption key */
  keyWrappingKid?: string;
  /** Base64url-encoded wrapped content encryption key (when keyWrappingKid is set) */
  wrappedKey?: string;
}

/**
 * Receipt issued for each proxied request
 * Contains hashes of request/response for verification without exposing content
 * Default mode is hash-only; encrypted payloads are opt-in for authorized access
 */
export interface Receipt {
  /** Receipt schema version */
  version: '1.0';
  /** Proxy instance DID (set when signing is enabled) */
  proxyDid?: string;
  /** Provider that handled the request */
  provider: Provider;
  /** Model used (extracted from request) */
  model?: string;
  /** SHA-256 hash of the request body */
  requestHash: string;
  /** SHA-256 hash of the response body */
  responseHash: string;
  /** ISO timestamp of proxy processing */
  timestamp: string;
  /** Request latency in milliseconds */
  latencyMs: number;
  /** Ed25519 signature (when signing key is configured) */
  signature?: string;
  /** Key ID used for signing */
  kid?: string;
  /** Binding fields for chaining proofs (optional) */
  binding?: ReceiptBinding;
  /** Payment attribution (platform-paid vs user-provided key) */
  payment?: ReceiptPayment;
  /** Privacy mode: hash_only (default) or encrypted */
  privacyMode?: ReceiptPrivacyMode;
  /** Encrypted request payload (only when privacyMode = 'encrypted') */
  encryptedRequest?: EncryptedPayload;
  /** Encrypted response payload (only when privacyMode = 'encrypted') */
  encryptedResponse?: EncryptedPayload;
}

/**
 * Canonical gateway receipt binding fields (snake_case).
 * Mirrors packages/schema/poh/receipt_binding.v1.json.
 */
export interface GatewayReceiptBinding {
  run_id?: string;
  event_hash_b64u?: string;
  nonce?: string;
  policy_hash?: string;
  token_scope_hash_b64u?: string;
}

/**
 * Canonical gateway receipt payload (snake_case).
 * This shape is verified by clawverify (SignedEnvelope<GatewayReceiptPayload>).
 */
export interface GatewayReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  gateway_id: string;
  provider: Provider;
  model: string;
  request_hash_b64u: string;
  response_hash_b64u: string;
  tokens_input: number;
  tokens_output: number;
  latency_ms: number;
  timestamp: string;
  binding?: GatewayReceiptBinding;
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

/**
 * Proxy response wrapper
 */
export interface ProxyResponse {
  /** Original provider response */
  [key: string]: unknown;
  /** Attached legacy receipt (v1.0). */
  _receipt: Receipt;
  /** Attached canonical receipt envelope (v1). */
  _receipt_envelope?: SignedEnvelope<GatewayReceiptPayload>;
}

/**
 * Error response format
 */
export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

/**
 * Request body for /v1/verify-receipt endpoint
 */
export interface VerifyReceiptRequest {
  /** Receipt to verify */
  receipt: Receipt;
}

/**
 * Response from /v1/verify-receipt endpoint
 */
export interface VerifyReceiptResponse {
  /** Whether the receipt signature is valid */
  valid: boolean;
  /** Verification error code if invalid */
  error?: string;
  /** Verified claims from the receipt (only present if valid) */
  claims?: {
    /** Provider that handled the request */
    provider: string;
    /** Model used */
    model?: string;
    /** Proxy DID that signed the receipt */
    proxyDid: string;
    /** Timestamp of the proxied request */
    timestamp: string;
    /** Key ID used for signing */
    kid: string;
    /** Binding fields for chaining proofs (if present in receipt) */
    binding?: ReceiptBinding;
    /** Payment attribution (if present in receipt) */
    payment?: ReceiptPayment;
  };
}
