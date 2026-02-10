-- Add Confidential Work Contract (CWC) fields (CWC-US-001)

ALTER TABLE bounties ADD COLUMN cwc_hash_b64u TEXT;
ALTER TABLE bounties ADD COLUMN cwc_wpc_policy_hash_b64u TEXT;
ALTER TABLE bounties ADD COLUMN cwc_required_proof_tier TEXT;
ALTER TABLE bounties ADD COLUMN cwc_buyer_envelope_json TEXT;
ALTER TABLE bounties ADD COLUMN cwc_worker_envelope_json TEXT;

CREATE INDEX IF NOT EXISTS bounties_cwc_hash_idx ON bounties(cwc_hash_b64u);
