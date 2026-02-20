-- AGP-US-059: auto bounty claim loop idempotency lock ledger

CREATE TABLE IF NOT EXISTS bounty_arena_auto_claim_locks (
  bounty_id TEXT PRIMARY KEY,
  lock_id TEXT NOT NULL,
  loop_id TEXT NOT NULL,
  claim_status TEXT NOT NULL CHECK (claim_status IN ('processing','claimed','skipped','failed')),
  worker_did TEXT,
  contender_id TEXT,
  reason_code TEXT NOT NULL,
  claim_idempotency_key TEXT NOT NULL,
  budget_minor_before TEXT NOT NULL,
  budget_minor_after TEXT NOT NULL,
  route_reason_codes_json TEXT NOT NULL,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auto_claim_locks_loop ON bounty_arena_auto_claim_locks(loop_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_auto_claim_locks_status ON bounty_arena_auto_claim_locks(claim_status, updated_at DESC);
