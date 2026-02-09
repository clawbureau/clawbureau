-- POH-US-014: Marketplace replay database
-- Reject duplicate submissions that reuse (agent_did, run_id) or (receipt_signer_did, receipt_id).

CREATE TABLE IF NOT EXISTS replay_runs (
  agent_did TEXT NOT NULL,
  run_id TEXT NOT NULL,
  bounty_id TEXT NOT NULL,
  submission_id TEXT NOT NULL,
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (agent_did, run_id)
);

CREATE TABLE IF NOT EXISTS replay_receipts (
  receipt_signer_did TEXT NOT NULL,
  receipt_id TEXT NOT NULL,
  bounty_id TEXT NOT NULL,
  submission_id TEXT NOT NULL,
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (receipt_signer_did, receipt_id)
);
