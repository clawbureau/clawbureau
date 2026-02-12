-- CTR-OPS-001: store clawtrials case linkage for disputed bounties.

ALTER TABLE bounties ADD COLUMN trial_case_id TEXT;
ALTER TABLE bounties ADD COLUMN trial_opened_at TEXT;

CREATE INDEX IF NOT EXISTS bounties_trial_case_idx ON bounties (trial_case_id);
