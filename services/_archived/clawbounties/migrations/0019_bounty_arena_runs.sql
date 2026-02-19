-- AGP-US-034: Bounty Arena integration tables for run lifecycle + contender artifacts.

CREATE TABLE IF NOT EXISTS bounty_arena_runs (
  run_id TEXT PRIMARY KEY,
  arena_id TEXT NOT NULL UNIQUE,
  bounty_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('started', 'completed')),
  contract_id TEXT NOT NULL,
  contract_hash_b64u TEXT NOT NULL,
  task_fingerprint TEXT NOT NULL,
  objective_profile_json TEXT NOT NULL,
  arena_report_json TEXT,
  winner_contender_id TEXT,
  winner_reason TEXT,
  reason_codes_json TEXT,
  tradeoffs_json TEXT,
  start_idempotency_key TEXT NOT NULL UNIQUE,
  result_idempotency_key TEXT UNIQUE,
  report_hash_b64u TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS bounty_arena_runs_bounty_updated_idx
  ON bounty_arena_runs (bounty_id, updated_at DESC, run_id DESC);

CREATE INDEX IF NOT EXISTS bounty_arena_runs_status_updated_idx
  ON bounty_arena_runs (status, updated_at DESC, run_id DESC);

CREATE TABLE IF NOT EXISTS bounty_arena_contenders (
  run_id TEXT NOT NULL,
  contender_id TEXT NOT NULL,
  label TEXT NOT NULL,
  model TEXT NOT NULL,
  harness TEXT NOT NULL,
  tools_json TEXT NOT NULL,
  skills_json TEXT NOT NULL,
  plugins_json TEXT NOT NULL,
  score REAL NOT NULL,
  hard_gate_pass INTEGER NOT NULL,
  mandatory_failed INTEGER NOT NULL,
  metrics_json TEXT NOT NULL,
  check_results_json TEXT NOT NULL,
  proof_pack_json TEXT,
  manager_review_json TEXT,
  review_paste TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (run_id, contender_id),
  FOREIGN KEY (run_id) REFERENCES bounty_arena_runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS bounty_arena_contenders_run_score_idx
  ON bounty_arena_contenders (run_id, score DESC, contender_id ASC);
