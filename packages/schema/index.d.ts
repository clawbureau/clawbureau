export type RunSummaryStatus = 'PASS' | 'FAIL';

export type RunSummaryTier = 'self' | 'gateway' | 'sandbox' | 'tee' | 'witnessed_web';

export interface RunSummary {
  status: RunSummaryStatus;
  tier: RunSummaryTier;
  cost_usd: number;
  tools_used: string[];
  files_modified: string[];
  policy_violations: number;
  network_connections: number;
  bundle_path: string;
  did: string;
  timestamp: string;
  duration_seconds: number;
}
