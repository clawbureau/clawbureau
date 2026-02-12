-- ECON-OPS-002 Task 1: Historical health snapshots
CREATE TABLE IF NOT EXISTS ops_health_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  overall_status TEXT NOT NULL CHECK (overall_status IN ('healthy', 'degraded', 'unhealthy')),
  services_json TEXT NOT NULL,
  services_up INTEGER NOT NULL DEFAULT 0,
  services_total INTEGER NOT NULL DEFAULT 0,
  disputes_open INTEGER NOT NULL DEFAULT 0,
  recon_mismatches INTEGER NOT NULL DEFAULT 0,
  outbox_depth_apply INTEGER NOT NULL DEFAULT 0,
  outbox_depth_resolve INTEGER NOT NULL DEFAULT 0,
  avg_latency_ms REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ops_health_snapshots_timestamp
  ON ops_health_snapshots (timestamp DESC);
