-- TRUST-REP-002 closed-loop reputation hardening

ALTER TABLE rep_events ADD COLUMN source_service TEXT;

CREATE TABLE IF NOT EXISTS rep_drift_reports (
  report_id INTEGER PRIMARY KEY AUTOINCREMENT,
  scope TEXT NOT NULL,
  total_profiles_checked INTEGER NOT NULL,
  mismatch_count INTEGER NOT NULL,
  repaired_count INTEGER NOT NULL,
  report_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rep_events_ingested_at ON rep_events (ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_rep_events_status_ingested ON rep_events (status, ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_rep_audit_kind_created ON rep_audit_events (event_kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rep_audit_source_event ON rep_audit_events (source_event_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rep_drift_reports_created ON rep_drift_reports (created_at DESC);
