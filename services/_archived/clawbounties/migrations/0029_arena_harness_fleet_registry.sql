-- AGP-US-058
-- Arena harness fleet registry + heartbeat state

CREATE TABLE IF NOT EXISTS bounty_arena_harness_fleet_workers (
  worker_did TEXT PRIMARY KEY,
  harness TEXT NOT NULL,
  model TEXT NOT NULL,
  skills_json TEXT NOT NULL,
  tools_json TEXT NOT NULL,
  objective_profiles_json TEXT NOT NULL,
  cost_tier TEXT NOT NULL CHECK(cost_tier IN ('low', 'medium', 'high')),
  risk_tier TEXT NOT NULL CHECK(risk_tier IN ('low', 'medium', 'high')),
  availability_status TEXT NOT NULL CHECK(availability_status IN ('online', 'offline', 'paused')),
  heartbeat_at TEXT,
  heartbeat_seq INTEGER NOT NULL DEFAULT 0,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_arena_fleet_workers_harness
  ON bounty_arena_harness_fleet_workers(harness);

CREATE INDEX IF NOT EXISTS idx_arena_fleet_workers_availability
  ON bounty_arena_harness_fleet_workers(availability_status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_arena_fleet_workers_cost_risk
  ON bounty_arena_harness_fleet_workers(cost_tier, risk_tier);
