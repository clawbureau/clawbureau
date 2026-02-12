export interface Env {
  AI: Ai;
  SENTINEL_DB: Vectorize;
  SENTINEL_INGEST: Queue<IngestMessage>;
  SENTINEL_ENABLED: string;
}

export interface SentinelResult {
  safe: boolean;
  threat_score: number;
  anomaly_type:
    | 'benign'
    | 'data_exfiltration_topology'
    | 'prompt_injection_suspected'
    | 'alien_trajectory';
  nearest_run_ids: string[];
  confidence: number;
}

export interface IngestMessage {
  proof_bundle: Record<string, unknown>;
  run_id: string;
  agent_did: string;
  status: string;
  proof_tier?: string;
  created_at?: string;
}

export interface TrajectoryMetadata {
  run_id: string;
  agent_did: string;
  status: string;
  proof_tier: string;
  created_at: string;
}
