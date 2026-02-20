-- AGP-US-056
-- Persist contract copilot suggestions derived from real failed arena outcomes.

CREATE TABLE IF NOT EXISTS bounty_arena_contract_copilot_suggestions (
  suggestion_id TEXT PRIMARY KEY,
  task_fingerprint TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('global', 'contender')),
  contender_id TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  before_text TEXT NOT NULL,
  after_text TEXT NOT NULL,
  rationale TEXT NOT NULL,
  confidence REAL NOT NULL,
  expected_override_reduction REAL NOT NULL,
  expected_rework_reduction REAL NOT NULL,
  evidence_count INTEGER NOT NULL,
  arena_count INTEGER NOT NULL,
  outcome_count INTEGER NOT NULL,
  source_evidence_json TEXT NOT NULL,
  computed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS bounty_arena_contract_copilot_suggestions_unique_idx
  ON bounty_arena_contract_copilot_suggestions(task_fingerprint, scope, contender_id, reason_code);

CREATE INDEX IF NOT EXISTS bounty_arena_contract_copilot_suggestions_task_idx
  ON bounty_arena_contract_copilot_suggestions(task_fingerprint, confidence DESC, updated_at DESC);
