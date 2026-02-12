/**
 * Claw Verified GitHub App — Type Definitions
 *
 * Types for the GitHub App Worker: webhook payloads, check run outputs,
 * verification orchestration, and policy structures.
 */

// ---------------------------------------------------------------------------
// Worker environment bindings
// ---------------------------------------------------------------------------

export interface Env {
  ENVIRONMENT: string;
  GITHUB_APP_ID: string;
  GITHUB_PRIVATE_KEY: string;
  GITHUB_WEBHOOK_SECRET: string;
}

// ---------------------------------------------------------------------------
// GitHub webhook payloads (subset we handle)
// ---------------------------------------------------------------------------

export interface GitHubRepository {
  id: number;
  full_name: string;
  default_branch: string;
  owner: {
    login: string;
  };
  name: string;
}

export interface GitHubInstallation {
  id: number;
}

export interface GitHubPullRequest {
  number: number;
  head: {
    sha: string;
    ref: string;
  };
  base: {
    sha: string;
    ref: string;
  };
  title: string;
}

export interface PullRequestEvent {
  action: string;
  pull_request: GitHubPullRequest;
  repository: GitHubRepository;
  installation: GitHubInstallation;
}

export interface CheckSuiteEvent {
  action: string;
  check_suite: {
    head_sha: string;
    pull_requests: GitHubPullRequest[];
  };
  repository: GitHubRepository;
  installation: GitHubInstallation;
}

// ---------------------------------------------------------------------------
// GitHub API types (Check Runs, file contents, PR files)
// ---------------------------------------------------------------------------

export interface CheckRunOutput {
  title: string;
  summary: string;
  text?: string;
}

export interface CreateCheckRunParams {
  owner: string;
  repo: string;
  name: string;
  head_sha: string;
  status: 'queued' | 'in_progress' | 'completed';
  conclusion?: 'success' | 'failure' | 'neutral' | 'cancelled' | 'action_required';
  output?: CheckRunOutput;
  started_at?: string;
  completed_at?: string;
}

export interface PRFile {
  filename: string;
  status: string;
  sha: string;
  patch?: string;
  contents_url: string;
}

// ---------------------------------------------------------------------------
// Policy / WPC types for repo-anchored trust
// ---------------------------------------------------------------------------

/**
 * Minimal Work Policy Contract for the GitHub App.
 * Loaded from `.clawsig/policy.json` in the repo's default branch.
 * v1: UNSIGNED — trust anchored to GitHub branch protection (Web2 trust).
 */
export interface RepoPolicy {
  policy_version: '1';
  policy_id: string;
  issuer_did: string;

  /** Optional: restrict which agent DIDs are allowed */
  allowed_agents?: string[];

  /** Optional: restrict which providers are allowed */
  allowed_providers?: string[];

  /** Optional: restrict which models are allowed */
  allowed_models?: string[];

  /** Minimum required proof tier */
  minimum_proof_tier?: 'self' | 'gateway' | 'sandbox';

  /** Required receipt types in the bundle */
  required_receipt_types?: ('gateway' | 'tool' | 'side_effect' | 'human_approval')[];

  /** Optional: egress allowlist */
  egress_allowlist?: string[];
}

// ---------------------------------------------------------------------------
// Verification result types
// ---------------------------------------------------------------------------

export type VerificationConclusion = 'success' | 'failure' | 'neutral';

export interface BundleVerificationSummary {
  bundle_path: string;
  valid: boolean;
  reason: string;
  reason_code?: string;
  agent_did?: string;
  proof_tier?: string;
  model_identity_tier?: string;
  receipt_count?: number;
  tool_receipt_count?: number;
  side_effect_receipt_count?: number;
  human_approval_receipt_count?: number;
}

export interface PolicyComplianceResult {
  compliant: boolean;
  violations: string[];
}

export interface VerificationOutput {
  conclusion: VerificationConclusion;
  title: string;
  summary: string;
  text: string;
  bundles_found: number;
  bundles_passed: number;
  bundles_failed: number;
  bundle_results: BundleVerificationSummary[];
  policy_loaded: boolean;
  policy_compliance?: PolicyComplianceResult;
}
