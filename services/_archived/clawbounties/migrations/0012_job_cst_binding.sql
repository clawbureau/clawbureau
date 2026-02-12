-- Add job-scoped CST binding for non-CWC bounties (POH-US-022)

ALTER TABLE bounties ADD COLUMN job_token_scope_hash_b64u TEXT;

CREATE INDEX IF NOT EXISTS bounties_job_token_scope_hash_idx ON bounties(job_token_scope_hash_b64u);
