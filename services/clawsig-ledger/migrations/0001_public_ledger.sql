CREATE TABLE IF NOT EXISTS agents (
  did TEXT PRIMARY KEY, first_seen_at TEXT DEFAULT (datetime('now')),
  verified_runs INTEGER DEFAULT 0, gateway_tier_runs INTEGER DEFAULT 0, policy_violations INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, bundle_hash_b64u TEXT UNIQUE NOT NULL, agent_did TEXT NOT NULL,
  proof_tier TEXT NOT NULL, status TEXT NOT NULL, wpc_hash_b64u TEXT, rt_leaf_index INTEGER,
  models_json TEXT, created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_runs_agent ON runs(agent_did);
CREATE INDEX idx_runs_status ON runs(status);
CREATE INDEX idx_runs_created ON runs(created_at);
