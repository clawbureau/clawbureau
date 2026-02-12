-- clawtrials arbitration MVP schema (CTR-OPS-001)

CREATE TABLE IF NOT EXISTS trial_cases (
  case_id TEXT PRIMARY KEY,
  create_idempotency_key TEXT NOT NULL UNIQUE,

  source_system TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  submission_id TEXT NOT NULL,

  escrow_id TEXT NOT NULL,
  requester_did TEXT NOT NULL,
  worker_did TEXT NOT NULL,
  opened_by TEXT NOT NULL,
  reason TEXT,

  status TEXT NOT NULL,
  decision_round INTEGER NOT NULL DEFAULT 0,

  judge_did TEXT NOT NULL,
  judge_assignment_hash_b64u TEXT NOT NULL,

  evidence_json TEXT NOT NULL,
  decision_json TEXT,
  appeal_json TEXT,
  resolution_json TEXT,

  resolved_outcome TEXT,
  decision_idempotency_key TEXT,
  appeal_idempotency_key TEXT,

  opened_at TEXT NOT NULL,
  decided_at TEXT,
  appealed_at TEXT,
  resolved_at TEXT,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS trial_cases_status_idx
  ON trial_cases (status, opened_at DESC);

CREATE INDEX IF NOT EXISTS trial_cases_opened_idx
  ON trial_cases (opened_at, case_id);

CREATE INDEX IF NOT EXISTS trial_cases_escrow_idx
  ON trial_cases (escrow_id);

CREATE INDEX IF NOT EXISTS trial_cases_requester_idx
  ON trial_cases (requester_did, opened_at DESC);

CREATE INDEX IF NOT EXISTS trial_cases_worker_idx
  ON trial_cases (worker_did, opened_at DESC);

CREATE INDEX IF NOT EXISTS trial_cases_judge_idx
  ON trial_cases (judge_did, opened_at DESC);

CREATE INDEX IF NOT EXISTS trial_cases_source_idx
  ON trial_cases (source_system, source_ref, opened_at DESC);
