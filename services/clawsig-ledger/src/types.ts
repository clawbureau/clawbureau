export interface Env {
  LEDGER_DB: D1Database;
  BUNDLES: R2Bucket;
  LEDGER_QUEUE: Queue<LedgerIngestMessage>;
  SERVICE_VERSION: string;
  CLAWLOGS_RT_URL: string;
  CLAWLOGS_ADMIN_TOKEN?: string;
  ORACLE_SIGNING_KEY?: string;
  VAAS_API_KEY_HASH?: string;
  VAAS_POW_DIFFICULTY?: string;
  CLAWVERIFY_API_URL?: string;
  CLAWVERIFY_API_TOKEN?: string;
  GATEWAY_RECEIPT_SIGNER_DIDS?: string;
  ATTESTATION_SIGNER_DIDS?: string;
}

export interface VerifyRequest {
  proof_bundle: unknown;
  publish_to_ledger?: boolean;
  wpc_policy_override?: unknown;
  options?: { emit_compliance_report?: string[] };
}

export interface VerifyResponse {
  status: 'PASS' | 'FAIL';
  tier: string;
  reason_code: string;
  failure_class: string;
  verification_source: string;
  auth_mode: string;
  run_id: string;
  urls: { badge: string; ledger: string };
  rt_log_inclusion: { status: string };
  compliance_reports: Record<string, unknown>;
}

export type BadgeColor = 'green' | 'blue' | 'red' | 'grey';
export interface BadgeData { color: BadgeColor; label: string; message: string; }

export interface AgentRow {
  did: string; first_seen_at: string; verified_runs: number;
  gateway_tier_runs: number; policy_violations: number;
}

export interface RunRow {
  run_id: string; bundle_hash_b64u: string; agent_did: string;
  proof_tier: string; status: string; reason_code: string | null;
  failure_class: string | null; verification_source: string | null;
  auth_mode: string | null; wpc_hash_b64u: string | null;
  rt_leaf_index: number | null; models_json: string | null; created_at: string;
}

export interface LedgerIngestMessage {
  run_id: string; bundle_hash_b64u: string; agent_did: string;
  proof_tier: string; status: string; reason_code: string;
  failure_class: string; verification_source: string;
  auth_mode: string; wpc_hash_b64u?: string;
  models_json?: string; bundle_json: string;
}

export interface AgentPassportVC {
  '@context': string[]; type: string[]; issuer: string; issuanceDate: string;
  credentialSubject: {
    id: string;
    reputation_metrics: { total_verified_runs: number; gateway_tier_runs: number; policy_violations: number };
    top_models_used: string[]; first_seen_at: string;
  };
  proof: { type: string; verificationMethod: string; created: string; signatureValue: string };
}

export interface FailReasonCodeStat {
  reason_code: string;
  count: number;
}

export interface RecentRunStat {
  run_id: string;
  agent_did: string;
  proof_tier: string;
  status: string;
  created_at: string;
}

export interface GlobalStatsResponse {
  total_agents: number;
  total_runs: number;
  total_gateway_runs: number;
  total_violations: number;
  runs_24h: number;
  fail_runs_24h: number;
  fail_rate_24h: number;
  top_fail_reason_codes: FailReasonCodeStat[];
  recent_runs: RecentRunStat[];
}

export interface RunsFeedFilters {
  status?: string;
  tier?: string;
  reason_code?: string;
  agent_did?: string;
}

export interface RunsFeedResponse {
  runs: RunRow[];
  limit: number;
  has_next: boolean;
  next_cursor: string | null;
  filters: RunsFeedFilters;
}
