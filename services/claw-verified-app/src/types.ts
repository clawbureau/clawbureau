/**
 * Types for the Claw Verified GitHub App.
 */

export interface Env {
  GITHUB_APP_ID: string;
  GITHUB_PRIVATE_KEY: string;
  GITHUB_WEBHOOK_SECRET: string;
}

export interface WebhookEvent {
  action: string;
  installation?: { id: number };
  repository?: { full_name: string; default_branch: string };
  pull_request?: PullRequestPayload;
  check_suite?: { head_sha: string; pull_requests: Array<{ number: number }> };
}

export interface PullRequestPayload {
  number: number;
  head: { sha: string; ref: string };
  base: { sha: string; ref: string };
}

export interface CheckRunOutput {
  title: string;
  summary: string;
  text?: string;
}

export interface VerificationSummary {
  conclusion: 'success' | 'failure' | 'neutral';
  output: CheckRunOutput;
  bundleCount: number;
  receiptCount: number;
  reasonCodes: string[];
}

export interface PolicyConfig {
  version: string;
  allowed_agent_dids?: string[];
  minimum_proof_tier?: 'self' | 'gateway' | 'sandbox';
  required_receipt_types?: string[];
  allowed_providers?: string[];
}
