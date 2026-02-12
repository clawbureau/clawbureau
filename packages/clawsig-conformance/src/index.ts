/**
 * @clawbureau/clawsig-conformance
 *
 * Conformance test runner for the Clawsig Inside program.
 *
 * Validates that AI agent frameworks emit correct Clawsig proof bundles
 * by spawning the agent against a mock LLM proxy and verifying the output
 * with @clawbureau/clawverify-core.
 *
 * Usage:
 *   import { runConformanceTest } from '@clawbureau/clawsig-conformance';
 *
 *   const result = await runConformanceTest({
 *     agentCommand: 'npm run test:agent',
 *     expectedTier: 'self',
 *     timeout: 60,
 *   });
 *
 *   if (result.passed) {
 *     console.log('Conformance test passed!');
 *   }
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
