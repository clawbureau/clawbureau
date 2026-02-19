-- AGP-US-052
-- Persist contract language optimizer suggestions derived from failed/overridden arena outcomes.

CREATE TABLE IF NOT EXISTS bounty_arena_contract_language_suggestions (
  suggestion_id TEXT PRIMARY KEY,
  task_fingerprint TEXT NOT NULL,
  scope TEXT NOT NULL CHECK (scope IN ('global', 'contender')),
  contender_id TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  failures INTEGER NOT NULL,
  overrides INTEGER NOT NULL,
  share REAL NOT NULL,
  priority_score REAL NOT NULL,
  contract_rewrite TEXT NOT NULL,
  prompt_rewrite TEXT NOT NULL,
  contract_language_patch TEXT NOT NULL,
  prompt_language_patch TEXT NOT NULL,
  sample_notes_json TEXT NOT NULL,
  tags_json TEXT NOT NULL,
  computed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS bounty_arena_contract_language_suggestions_unique_idx
  ON bounty_arena_contract_language_suggestions(task_fingerprint, scope, contender_id, reason_code);

CREATE INDEX IF NOT EXISTS bounty_arena_contract_language_suggestions_task_idx
  ON bounty_arena_contract_language_suggestions(task_fingerprint, priority_score DESC, updated_at DESC);
