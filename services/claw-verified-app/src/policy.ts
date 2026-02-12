/**
 * WPC Policy Loader + Default Policy.
 *
 * Per Gemini Deep Think Problem 2 (Round 1):
 * - v1: WPC is UNSIGNED — trust anchored to GitHub branch protection (Web2 trust)
 * - If no WPC found: uses minimal default policy (require valid signatures only)
 */

import type { PolicyConfig } from './types';
import { getFileContent } from './github';

const POLICY_PATH = '.clawsig/policy.json';

/**
 * Minimal default policy: accept any valid bundle.
 * Applied when repo has no .clawsig/policy.json.
 */
export const DEFAULT_POLICY: PolicyConfig = {
  version: '1',
  // No agent DID restriction (accept any)
  allowed_agent_dids: ['*'],
  // Accept any tier including self-reported
  minimum_proof_tier: 'self',
  // Only require gateway receipts
  required_receipt_types: ['gateway_receipt'],
};

/**
 * Load the WPC policy from the repo's default branch.
 * Returns default policy if not found or invalid.
 */
export async function loadPolicy(
  token: string,
  repo: string,
  defaultBranch: string,
): Promise<{ policy: PolicyConfig; source: 'repo' | 'default' }> {
  try {
    const content = await getFileContent(token, repo, POLICY_PATH, defaultBranch);
    if (!content) {
      return { policy: DEFAULT_POLICY, source: 'default' };
    }

    const parsed = JSON.parse(content) as PolicyConfig;
    if (!parsed.version) {
      return { policy: DEFAULT_POLICY, source: 'default' };
    }

    return { policy: parsed, source: 'repo' };
  } catch {
    return { policy: DEFAULT_POLICY, source: 'default' };
  }
}

/**
 * Check if an agent DID is allowed by the policy.
 */
export function isAgentAllowed(policy: PolicyConfig, agentDid: string): boolean {
  if (!policy.allowed_agent_dids || policy.allowed_agent_dids.length === 0) return true;
  if (policy.allowed_agent_dids.includes('*')) return true;
  return policy.allowed_agent_dids.includes(agentDid);
}

/**
 * Check if all required receipt types are present.
 */
export function hasRequiredReceipts(
  policy: PolicyConfig,
  presentTypes: Set<string>,
): { met: boolean; missing: string[] } {
  if (!policy.required_receipt_types || policy.required_receipt_types.length === 0) {
    return { met: true, missing: [] };
  }
  const missing = policy.required_receipt_types.filter(t => !presentTypes.has(t));
  return { met: missing.length === 0, missing };
}
