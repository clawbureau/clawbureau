-- Upgrade clawbounties D1 schema to bounty v2 (breaking)
--
-- NOTE: This migration drops the previous `bounties` table used by the v1-ish API.
-- The service is still under active development; we intentionally keep the schema clean
-- rather than carrying legacy columns.

DROP TABLE IF EXISTS bounties;

CREATE TABLE IF NOT EXISTS bounties (
  bounty_id TEXT PRIMARY KEY,
  create_idempotency_key TEXT NOT NULL UNIQUE,

  requester_did TEXT NOT NULL,

  title TEXT NOT NULL,
  description TEXT NOT NULL,

  reward_amount_minor TEXT NOT NULL,
  reward_currency TEXT NOT NULL,

  closure_type TEXT NOT NULL,
  difficulty_scalar REAL NOT NULL,

  is_code_bounty INTEGER NOT NULL,
  tags_json TEXT NOT NULL,
  min_proof_tier TEXT NOT NULL,
  require_owner_verified_votes INTEGER NOT NULL,
  test_harness_id TEXT,

  metadata_json TEXT NOT NULL,

  fee_quote_json TEXT NOT NULL,
  fee_policy_version TEXT NOT NULL,
  all_in_cost_json TEXT NOT NULL,

  escrow_id TEXT NOT NULL,
  status TEXT NOT NULL,

  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS bounties_status_idx ON bounties(status);
CREATE INDEX IF NOT EXISTS bounties_is_code_status_idx ON bounties(is_code_bounty, status);
CREATE INDEX IF NOT EXISTS bounties_requester_idx ON bounties(requester_did);
CREATE INDEX IF NOT EXISTS bounties_created_at_idx ON bounties(created_at);
