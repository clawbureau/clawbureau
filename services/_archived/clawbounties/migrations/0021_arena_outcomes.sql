-- AGP-US-041: outcome feedback + calibration loop for arena decisions.

CREATE TABLE IF NOT EXISTS bounty_arena_outcomes (
  outcome_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  bounty_id TEXT NOT NULL,
  arena_id TEXT NOT NULL,
  contender_id TEXT NOT NULL,
  outcome_status TEXT NOT NULL CHECK (outcome_status IN ('ACCEPTED', 'OVERRIDDEN', 'REWORK', 'REJECTED', 'DISPUTED')),
  accepted INTEGER NOT NULL CHECK (accepted IN (0, 1)),
  overridden INTEGER NOT NULL CHECK (overridden IN (0, 1)),
  rework_required INTEGER NOT NULL CHECK (rework_required IN (0, 1)),
  disputed INTEGER NOT NULL CHECK (disputed IN (0, 1)),
  review_time_minutes REAL NOT NULL,
  time_to_accept_minutes REAL,
  predicted_confidence REAL NOT NULL,
  recommendation TEXT NOT NULL CHECK (recommendation IN ('APPROVE', 'REQUEST_CHANGES', 'REJECT')),
  notes TEXT,
  source TEXT NOT NULL,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS bounty_arena_outcomes_bounty_created_idx
  ON bounty_arena_outcomes (bounty_id, created_at DESC, outcome_id DESC);

CREATE INDEX IF NOT EXISTS bounty_arena_outcomes_arena_created_idx
  ON bounty_arena_outcomes (arena_id, created_at DESC, outcome_id DESC);

CREATE INDEX IF NOT EXISTS bounty_arena_outcomes_contender_created_idx
  ON bounty_arena_outcomes (contender_id, created_at DESC, outcome_id DESC);
