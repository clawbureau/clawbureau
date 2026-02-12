/**
 * Clawsig Conformance Test Types
 */

/** Valid proof tiers in ascending order of trust. */
export const PROOF_TIERS = ['self', 'gateway', 'sandbox', 'tee'] as const;
export type ProofTier = (typeof PROOF_TIERS)[number];

/** Result of a single conformance test run. */
export interface ConformanceResult {
  passed: boolean;
  bundle_found: boolean;
  bundle_valid: boolean;
  tier: string | null;
  tier_meets_expected: boolean;
  event_chain_length: number;
  receipt_count: number;
  errors: string[];
}

/** Configuration for running a conformance test. */
export interface ConformanceConfig {
  agentCommand: string;
  expectedTier?: ProofTier;
  timeout?: number;
  outputPath?: string;
  mockProxyPort?: number;
  cwd?: string;
}

/** A recorded HTTP request to the mock proxy. */
export interface RecordedRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
  timestamp: string;
}

/** A mock gateway receipt emitted by the mock proxy. */
export interface MockReceipt {
  envelope_version: '1';
  envelope_type: 'gateway_receipt';
  payload: {
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
    };
  };
  payload_hash_b64u: string;
  hash_algorithm: 'SHA-256';
  signature_b64u: string;
  algorithm: 'Ed25519';
  signer_did: string;
  issued_at: string;
}

/** State of the mock proxy after shutdown. */
export interface MockProxyState {
  requests: RecordedRequest[];
  receipts: MockReceipt[];
  port: number;
}
