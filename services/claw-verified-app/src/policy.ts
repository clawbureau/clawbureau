/**
 * Policy Loader — Repo-Anchored TOFU
 *
 * Per Gemini Deep Think Decision (Problem 2):
 * - The policy file in the repo's default branch (main) is the source of truth.
 * - Trust chain: GitHub's native branch protection rules (Web2 trust).
 * - v1: WPC is UNSIGNED — trust anchored to branch protection.
 * - If no WPC found: uses a minimal default policy (require valid signatures only).
 *
 * Policy is loaded from `.clawsig/policy.json` in the repo's default branch.
 */

import type { GitHubClient } from './github.js';
import type { RepoPolicy, PolicyComplianceResult, BundleVerificationSummary } from './types.js';

const POLICY_PATH = '.clawsig/policy.json';

/**
 * Default policy when no `.clawsig/policy.json` exists in the repo.
 * Minimal: require valid signatures only, any agent DID accepted.
 */
export const DEFAULT_POLICY: RepoPolicy = {
  policy_version: '1',
  policy_id: 'default-minimal',
  issuer_did: 'did:web:clawprotocol.org',
  // No allowed_agents restriction (any agent DID)
  // No allowed_providers restriction
  // No allowed_models restriction
  // No minimum_proof_tier (accept any tier)
  // No required_receipt_types
};

/**
 * Load the Work Policy Contract from the repo's default branch.
 * Returns the default policy if the file is not found.
 */
export async function loadRepoPolicy(
  client: GitHubClient,
  owner: string,
  repo: string,
  defaultBranch: string,
): Promise<{ policy: RepoPolicy; isDefault: boolean }> {
  const content = await client.getFileContent(owner, repo, POLICY_PATH, defaultBranch);

  if (content === null) {
    return { policy: DEFAULT_POLICY, isDefault: true };
  }

  try {
    const parsed = JSON.parse(content) as RepoPolicy;

    // Basic structural validation (fail-closed)
    if (parsed.policy_version !== '1') {
      throw new Error(`Unsupported policy_version: ${parsed.policy_version}`);
    }

    if (typeof parsed.policy_id !== 'string' || parsed.policy_id.length === 0) {
      throw new Error('policy_id is required and must be non-empty');
    }

    if (typeof parsed.issuer_did !== 'string' || !parsed.issuer_did.startsWith('did:')) {
      throw new Error('issuer_did must be a valid DID string');
    }

    return { policy: parsed, isDefault: false };
  } catch (err) {
    // Fail-closed: invalid policy file = use default + report warning
    // We do not silently accept a malformed policy.
    throw new Error(
      `Invalid .clawsig/policy.json: ${err instanceof Error ? err.message : 'parse error'}`,
    );
  }
}

/**
 * Check a verified bundle against the repo's WPC.
 *
 * Returns compliance result with any violations found.
 */
export function checkPolicyCompliance(
  policy: RepoPolicy,
  bundleResult: BundleVerificationSummary,
): PolicyComplianceResult {
  const violations: string[] = [];

  // Check allowed agents
  if (policy.allowed_agents && policy.allowed_agents.length > 0) {
    if (bundleResult.agent_did) {
      const agentAllowed = policy.allowed_agents.some((pattern) => {
        if (pattern === 'did:key:*' || pattern === '*') return true;
        return pattern === bundleResult.agent_did;
      });

      if (!agentAllowed) {
        violations.push(
          `POLICY_AGENT_NOT_ALLOWED: Agent DID ${bundleResult.agent_did} is not in the allowed_agents list`,
        );
      }
    }
  }

  // Check allowed providers (from receipts — requires parsing, deferred to bundle metadata)
  // This is informational in v1 since we cannot extract provider from proof_tier alone.

  // Check minimum proof tier
  if (policy.minimum_proof_tier && bundleResult.proof_tier) {
    const tierOrder: Record<string, number> = {
      unknown: 0,
      self: 1,
      gateway: 2,
      sandbox: 3,
      tee: 4,
    };

    const required = tierOrder[policy.minimum_proof_tier] ?? 0;
    const actual = tierOrder[bundleResult.proof_tier] ?? 0;

    if (actual < required) {
      violations.push(
        `POLICY_PROOF_TIER_INSUFFICIENT: Required ${policy.minimum_proof_tier}, got ${bundleResult.proof_tier}`,
      );
    }
  }

  // Check required receipt types
  if (policy.required_receipt_types) {
    for (const required of policy.required_receipt_types) {
      switch (required) {
        case 'gateway':
          if ((bundleResult.receipt_count ?? 0) === 0) {
            violations.push('POLICY_MISSING_RECEIPT: Required gateway receipts not found');
          }
          break;
        case 'tool':
          if ((bundleResult.tool_receipt_count ?? 0) === 0) {
            violations.push('POLICY_MISSING_RECEIPT: Required tool receipts not found');
          }
          break;
        case 'side_effect':
          if ((bundleResult.side_effect_receipt_count ?? 0) === 0) {
            violations.push('POLICY_MISSING_RECEIPT: Required side_effect receipts not found');
          }
          break;
        case 'human_approval':
          if ((bundleResult.human_approval_receipt_count ?? 0) === 0) {
            violations.push('POLICY_MISSING_RECEIPT: Required human_approval receipts not found');
          }
          break;
      }
    }
  }

  return {
    compliant: violations.length === 0,
    violations,
  };
}
