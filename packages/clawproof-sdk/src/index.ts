/**
 * @clawbureau/clawproof-sdk
 *
 * Lightweight SDK for emitting verifiable proof bundles from
 * API scripts and automation workloads.
 *
 * Provides:
 *   - Hash-linked event chain recording
 *   - Proxied LLM calls through clawproxy with receipt collection
 *   - URM (Universal Run Manifest) generation
 *   - Ed25519-signed proof bundle output
 *
 * Usage:
 *   import { createRun, generateKeyPair, didFromPublicKey, hashJsonB64u } from '@clawbureau/clawproof-sdk';
 *
 *   const keyPair = await generateKeyPair();
 *   const run = await createRun({ proxyBaseUrl: '...', keyPair, harness: { id: 'my-script', version: '1.0' } });
 *   await run.recordEvent({ eventType: 'run_start', payload: { task: '...' } });
 *   const { response } = await run.callLLM({ provider: 'anthropic', model: 'claude-sonnet-4-5-20250929', body: { ... } });
 *   const result = await run.finalize({ inputs: [...], outputs: [...] });
 */

// Core SDK
export { createRun } from './run';

// Crypto utilities
export {
  generateKeyPair,
  didFromPublicKey,
  hashJsonB64u,
  sha256B64u,
  exportKeyPairJWK,
  importKeyPairJWK,
} from './crypto';

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
} from './types';
