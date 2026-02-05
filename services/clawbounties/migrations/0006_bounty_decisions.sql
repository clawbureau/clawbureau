-- Track requester approve/reject decisions (AEM-US-008)

ALTER TABLE bounties ADD COLUMN approved_submission_id TEXT;
ALTER TABLE bounties ADD COLUMN approve_idempotency_key TEXT;
ALTER TABLE bounties ADD COLUMN approved_at TEXT;

ALTER TABLE bounties ADD COLUMN rejected_submission_id TEXT;
ALTER TABLE bounties ADD COLUMN reject_idempotency_key TEXT;
ALTER TABLE bounties ADD COLUMN rejected_at TEXT;
