/**
 * @clawbureau/clawproof-adapters
 *
 * External harness adapters for Proof-of-Harness.
 *
 * Provides wrapper scripts and a shared runtime for routing LLM calls
 * through clawproxy and producing verifiable proof bundles from
 * external harnesses: Claude Code, Codex, Pi, Opencode, Factory Droid.
 *
 * Each adapter knows how to:
 *   1. Set provider base URL env vars to route through clawproxy
 *   2. Parse harness output to extract tool call events
 *   3. Produce a signed proof bundle with event chain + receipts + URM
 */

// Core session
export { createSession } from './session';

// Adapter registry
export {
  getAdapter,
  listAdapters,
  claudeCode,
  codex,
  pi,
  opencode,
  factoryDroid,
} from './adapters/index';
export type { AdapterModule } from './adapters/index';

// Crypto utilities
export {
  generateKeyPair,
  didFromPublicKey,
  hashJsonB64u,
  exportKeyPairJWK,
  importKeyPairJWK,
} from './crypto';

// Types
export type {
  AdapterConfig,
  AdapterSession,
  HarnessConfig,
  HarnessId,
  BindingContext,
  FinalizeOptions,
  FinalizeResult,
  ProxyLLMCallParams,
  ProxyLLMCallResult,
  ReceiptArtifact,
  ResourceDescriptor,
  Ed25519KeyPair,
} from './types';

export { ENV } from './types';
