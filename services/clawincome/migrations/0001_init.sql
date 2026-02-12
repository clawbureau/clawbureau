-- clawincome D1 schema (CIN-OPS-001)

CREATE TABLE IF NOT EXISTS report_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  report_type TEXT NOT NULL,
  did TEXT NOT NULL,
  period_key TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  csv_body TEXT,
  payload_hash_b64u TEXT NOT NULL,
  source_refs_json TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (report_type, did, period_key)
);

CREATE INDEX IF NOT EXISTS report_snapshots_did_type_period_idx
  ON report_snapshots(did, report_type, period_key, created_at DESC);

CREATE TABLE IF NOT EXISTS access_audit_events (
  audit_id TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL,
  requested_did TEXT NOT NULL,
  actor_did TEXT,
  is_admin INTEGER NOT NULL CHECK (is_admin IN (0, 1)),
  outcome TEXT NOT NULL,
  created_at TEXT NOT NULL,
  details_json TEXT
);

CREATE INDEX IF NOT EXISTS access_audit_events_requested_did_idx
  ON access_audit_events(requested_did, created_at DESC);
