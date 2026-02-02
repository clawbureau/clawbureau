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
  /** Privacy mode: hash_only (default) or encrypted */
  privacyMode?: ReceiptPrivacyMode;
  /** Encrypted request payload (only when privacyMode = 'encrypted') */
  encryptedRequest?: EncryptedPayload;
  /** Encrypted response payload (only when privacyMode = 'encrypted') */
  encryptedResponse?: EncryptedPayload;
}

/**
 * Proxy response wrapper
 */
export interface ProxyResponse {
  /** Original provider response */
  [key: string]: unknown;
  /** Attached receipt */
  _receipt: Receipt;
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
  };
}
