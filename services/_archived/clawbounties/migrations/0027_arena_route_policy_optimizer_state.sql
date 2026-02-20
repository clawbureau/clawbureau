-- AGP-US-055: Persist route policy optimizer shadow/active state for deterministic promotion.

CREATE TABLE IF NOT EXISTS bounty_arena_route_policy_optimizer_state (
  state_id TEXT PRIMARY KEY,
  task_fingerprint TEXT NOT NULL,
  environment TEXT NOT NULL,
  objective_profile_name TEXT NOT NULL,
  experiment_id TEXT NOT NULL,
  experiment_arm TEXT NOT NULL,
  active_policy_json TEXT,
  shadow_policy_json TEXT NOT NULL,
  last_promotion_event_json TEXT,
  reason_codes_json TEXT NOT NULL,
  sample_count INTEGER NOT NULL DEFAULT 0,
  confidence_score REAL NOT NULL DEFAULT 0,
  min_samples INTEGER NOT NULL DEFAULT 0,
  min_confidence REAL NOT NULL DEFAULT 0,
  promotion_status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(task_fingerprint, environment, objective_profile_name, experiment_id, experiment_arm)
);

CREATE INDEX IF NOT EXISTS idx_ba_policy_optimizer_lookup
  ON bounty_arena_route_policy_optimizer_state(task_fingerprint, environment, objective_profile_name, experiment_id, experiment_arm);

CREATE INDEX IF NOT EXISTS idx_ba_policy_optimizer_updated
  ON bounty_arena_route_policy_optimizer_state(updated_at DESC);
