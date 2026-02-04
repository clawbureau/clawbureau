-- Add bounty acceptance fields for worker assignment (CBT-US-019)

ALTER TABLE bounties ADD COLUMN worker_did TEXT;
ALTER TABLE bounties ADD COLUMN accept_idempotency_key TEXT;
ALTER TABLE bounties ADD COLUMN accepted_at TEXT;

CREATE INDEX IF NOT EXISTS bounties_worker_idx ON bounties(worker_did);
CREATE INDEX IF NOT EXISTS bounties_accept_idempotency_idx ON bounties(accept_idempotency_key);
