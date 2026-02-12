/**
 * Clawsig Conformance Test Types
 *
 * Shared type definitions for the conformance runner, mock proxy,
 * and GitHub Action.
 */

/** Valid proof tiers in ascending order of trust. */
export const PROOF_TIERS = ['self', 'gateway', 'sandbox', 'tee'] as const;
export type ProofTier = (typeof PROOF_TIERS)[number];

/** Result of a single conformance test run. */
export interface ConformanceResult {
  /** Whether the overall conformance test passed. */
  passed: boolean;
  /** Whether a proof bundle was found at the expected output path. */
  bundle_found: boolean;
  /** Whether the found bundle passed cryptographic verification via clawverify-core. */
  bundle_valid: boolean;
  /** The proof tier detected in the bundle (null if bundle not found/invalid). */
  tier: string | null;
  /** Whether the detected tier meets or exceeds the expected tier. */
  tier_meets_expected: boolean;
  /** Number of events in the proof bundle event chain. */
  event_chain_length: number;
  /** Total number of receipts (gateway + tool + side-effect + human approval). */
  receipt_count: number;
  /** Human-readable error messages. */
  errors: string[];
}

/** Configuration for running a conformance test. */
export interface ConformanceConfig {
  /** Shell command to invoke the agent under test. */
  agentCommand: string;
  /** Minimum proof tier the agent must achieve (default: "self"). */
  expectedTier?: ProofTier;
  /** Timeout in seconds before killing the agent process (default: 60). */
  timeout?: number;
  /** Path where the agent is expected to write its proof bundle (default: ".clawsig/proof_bundle.json"). */
  outputPath?: string;
  /** Port for the mock LLM proxy (default: 0 = auto-assign). */
  mockProxyPort?: number;
  /** Working directory for the agent process (default: cwd). */
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
