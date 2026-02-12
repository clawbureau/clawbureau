export interface Env {
  LEDGER_DB: D1Database;
  BUNDLES: R2Bucket;
  LEDGER_QUEUE: Queue<LedgerIngestMessage>;
  SERVICE_VERSION: string;
  CLAWLOGS_RT_URL: string;
  CLAWLOGS_ADMIN_TOKEN?: string;
  ORACLE_SIGNING_KEY?: string;
  VAAS_API_KEY_HASH?: string;
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
  proof_tier: string; status: string; wpc_hash_b64u: string | null;
  rt_leaf_index: number | null; models_json: string | null; created_at: string;
}

export interface LedgerIngestMessage {
  run_id: string; bundle_hash_b64u: string; agent_did: string;
  proof_tier: string; status: string; wpc_hash_b64u?: string;
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

export interface GlobalStatsResponse {
  total_agents: number; total_runs: number;
  total_gateway_runs: number; total_violations: number;
}
