/**
 * @clawbureau/clawsig-conformance
 *
 * Conformance test runner for the Clawsig Inside program.
 */

export { runConformanceTest } from './runner.js';
export { startMockProxy } from './mock-proxy.js';
export type { MockProxyHandle } from './mock-proxy.js';
export type {
  ConformanceResult,
  ConformanceConfig,
  ProofTier,
  RecordedRequest,
  MockReceipt,
  MockProxyState,
} from './types.js';
export { PROOF_TIERS } from './types.js';
