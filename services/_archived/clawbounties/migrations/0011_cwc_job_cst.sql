-- Add CWC job-scoped CST binding (POH-US-021)

ALTER TABLE bounties ADD COLUMN cwc_token_scope_hash_b64u TEXT;

CREATE INDEX IF NOT EXISTS bounties_cwc_token_scope_hash_idx ON bounties(cwc_token_scope_hash_b64u);
