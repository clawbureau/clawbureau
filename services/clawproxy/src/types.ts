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
}

/**
 * DID document response for /v1/did endpoint
 */
export interface DidResponse {
  /** DID identifier (did:web:clawproxy.com) */
  did: string;
  /** Public key in base64url format */
  publicKey: string;
  /** Key ID for signature verification */
  kid: string;
  /** Key algorithm */
  algorithm: 'Ed25519';
  /** Deployment metadata */
  deployment: {
    version: string;
    signingEnabled: boolean;
  };
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
 * Receipt issued for each proxied request
 * Contains hashes of request/response for verification without exposing content
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
