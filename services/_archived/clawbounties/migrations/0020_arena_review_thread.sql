-- AGP-US-040: arena decision paste thread entries for PR/bounty review workflows.

CREATE TABLE IF NOT EXISTS bounty_arena_review_thread (
  thread_entry_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  bounty_id TEXT NOT NULL,
  arena_id TEXT NOT NULL,
  contender_id TEXT NOT NULL,
  recommendation TEXT NOT NULL CHECK (recommendation IN ('APPROVE', 'REQUEST_CHANGES', 'REJECT')),
  confidence REAL NOT NULL,
  body_markdown TEXT NOT NULL,
  links_json TEXT NOT NULL,
  source TEXT NOT NULL,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS bounty_arena_review_thread_bounty_created_idx
  ON bounty_arena_review_thread (bounty_id, created_at DESC, thread_entry_id DESC);

CREATE INDEX IF NOT EXISTS bounty_arena_review_thread_arena_created_idx
  ON bounty_arena_review_thread (arena_id, created_at DESC, thread_entry_id DESC);
