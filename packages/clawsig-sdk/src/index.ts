/**
 * @clawbureau/clawsig-sdk
 *
 * Lightweight SDK for emitting verifiable proof bundles from
 * API scripts and automation workloads.
 *
 * Provides:
 *   - Hash-linked event chain recording
 *   - Proxied LLM calls through clawproxy with receipt collection
 *   - URM (Universal Run Manifest) generation
 *   - Ed25519-signed proof bundle output
 *   - Ephemeral DID generation for single-use agent identities
 *   - Local interceptor proxy for transparent `clawsig wrap` integration
 *
 * Usage:
 *   import { createRun, generateKeyPair, didFromPublicKey, hashJsonB64u } from '@clawbureau/clawsig-sdk';
 *
 *   const keyPair = await generateKeyPair();
 *   const run = await createRun({ proxyBaseUrl: '...', keyPair, harness: { id: 'my-script', version: '1.0' } });
 *   await run.recordEvent({ eventType: 'run_start', payload: { task: '...' } });
 *   const { response } = await run.callLLM({ provider: 'anthropic', model: 'claude-sonnet-4-5-20250929', body: { ... } });
 *   const result = await run.finalize({ inputs: [...], outputs: [...] });
 *
 * Wrap (one-line integration):
 *   import { generateEphemeralDid, startLocalProxy } from '@clawbureau/clawsig-sdk';
 *
 *   const did = await generateEphemeralDid();
 *   const proxy = await startLocalProxy({ agentDid: did, runId: 'run_123' });
 *   // ... spawn agent process with OPENAI_BASE_URL=http://127.0.0.1:${proxy.port}/v1/proxy/openai
 *   const bundle = await proxy.compileProofBundle();
 *   await proxy.stop();
 */

// Core SDK
// NOTE: Use explicit `.js` extensions so the built SDK works under plain Node ESM.
export { createRun } from './run.js';

// Ephemeral DID
export { generateEphemeralDid } from './ephemeral-did.js';

// Local interceptor proxy
export { startLocalProxy } from './local-proxy.js';

// Crypto utilities
export {
  generateKeyPair,
  didFromPublicKey,
  hashJsonB64u,
  sha256B64u,
  exportKeyPairJWK,
  importKeyPairJWK,
} from './crypto.js';

// Causal Sieve — tool observability without agent cooperation
export { CausalSieve } from './causal-sieve.js';

// Deep Execution Sentinels
export { FsSentinel } from './fs-sentinel.js';
export { NetSentinel } from './net-sentinel.js';

// Types
export type {
  ClawproofConfig,
  ClawproofRun,
  Ed25519KeyPair,
  HarnessConfig,
  BindingContext,
  SDKEventType,
  RecordEventInput,
  RecorderEvent,
  ReceiptArtifact,
  ClawproxyReceipt,
  FinalizeOptions,
  FinalizeResult,
  ResourceDescriptor,
  LLMCallParams,
  LLMCallResult,
  // Schema-facing types (for advanced use)
  SignedEnvelope,
  ProofBundlePayload,
  URMDocument,
  EventChainEntry,
  GatewayReceiptPayload,
  ToolReceiptPayload,
  SideEffectReceiptPayload,
  ExecutionReceiptPayload,
  NetworkReceiptPayload,
} from './types.js';

// Wrap types
export type { EphemeralDid } from './ephemeral-did.js';
export type { LocalProxy, ProxyOptions } from './local-proxy.js';

// Sentinel types
export type { FsEvent, FsSentinelOptions } from './fs-sentinel.js';
export type { NetEvent, NetSentinelOptions } from './net-sentinel.js';

// Causal Sieve types
export type {
  ExtractedToolCall,
  ExtractedToolResult,
  DetectedMutation,
  CausalToolInvocation,
  PolicyViolation,
  LocalPolicy,
  LocalPolicyStatement,
  CausalSieveOptions,
} from './causal-sieve.js';
