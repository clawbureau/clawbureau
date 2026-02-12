-- CRP-OPS-001 foundation schema

CREATE TABLE IF NOT EXISTS rep_profiles (
  did TEXT PRIMARY KEY,
  reputation_score REAL NOT NULL DEFAULT 0,
  events_count INTEGER NOT NULL DEFAULT 0,
  penalties_count INTEGER NOT NULL DEFAULT 0,
  dispute_penalties_count INTEGER NOT NULL DEFAULT 0,
  is_owner_verified INTEGER NOT NULL DEFAULT 0,
  owner_attestation_ref TEXT,
  last_event_at TEXT,
  last_decay_at TEXT,
  updated_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rep_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_event_id TEXT NOT NULL UNIQUE,
  did TEXT NOT NULL,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  score_delta REAL NOT NULL,
  closure_type TEXT,
  proof_tier TEXT,
  owner_verified INTEGER,
  owner_attestation_ref TEXT,
  value_usd REAL,
  concave_value REAL,
  weight_closure REAL,
  weight_proof REAL,
  weight_owner REAL,
  penalty_type TEXT,
  severity INTEGER,
  occurred_at TEXT NOT NULL,
  ingested_at TEXT NOT NULL,
  processed_at TEXT,
  error_code TEXT,
  error_message TEXT,
  metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS rep_audit_events (
  audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_kind TEXT NOT NULL,
  did TEXT,
  source_event_id TEXT,
  details_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decay_runs (
  run_day TEXT PRIMARY KEY,
  triggered_by TEXT NOT NULL,
  affected_profiles INTEGER NOT NULL DEFAULT 0,
  total_delta REAL NOT NULL DEFAULT 0,
  executed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rep_events_did ON rep_events (did);
CREATE INDEX IF NOT EXISTS idx_rep_events_status ON rep_events (status);
CREATE INDEX IF NOT EXISTS idx_rep_events_occurred_at ON rep_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_rep_audit_created ON rep_audit_events (created_at DESC);
