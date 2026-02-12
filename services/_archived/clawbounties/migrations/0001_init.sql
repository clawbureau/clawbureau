-- clawbounties D1 schema (v1)

CREATE TABLE IF NOT EXISTS bounties (
  bounty_id TEXT PRIMARY KEY,
  create_idempotency_key TEXT NOT NULL UNIQUE,

  buyer_did TEXT NOT NULL,
  requested_worker_did TEXT,
  worker_did TEXT,

  job_type TEXT NOT NULL,
  closure_type TEXT NOT NULL,

  title TEXT NOT NULL,
  description TEXT NOT NULL,

  reward_minor TEXT NOT NULL,
  currency TEXT NOT NULL,

  fee_quote_json TEXT NOT NULL,
  escrow_id TEXT NOT NULL,

  status TEXT NOT NULL,

  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,

  test_spec_json TEXT,
  deliverable_spec_json TEXT
);

CREATE INDEX IF NOT EXISTS bounties_status_idx ON bounties(status);
CREATE INDEX IF NOT EXISTS bounties_job_status_idx ON bounties(job_type, status);
CREATE INDEX IF NOT EXISTS bounties_buyer_idx ON bounties(buyer_did);
