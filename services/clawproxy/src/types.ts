/**
 * Clawproxy type definitions
 */

export interface Env {
  PROXY_VERSION: string;
  PROXY_SIGNING_KEY?: string;
}

/**
 * Supported LLM providers
 */
export type Provider = 'anthropic' | 'openai';

/**
 * Provider configuration for routing
 */
export interface ProviderConfig {
  baseUrl: string;
  authHeader: string;
  contentType: string;
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
