-- Migration: Create reconciliation reports table
-- Stores results of nightly balance reconciliation jobs

CREATE TABLE IF NOT EXISTS reconciliation_reports (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('success', 'mismatch', 'error')),
  started_at TEXT NOT NULL,
  completed_at TEXT NOT NULL,
  events_replayed INTEGER NOT NULL DEFAULT 0,
  accounts_checked INTEGER NOT NULL DEFAULT 0,
  mismatch_count INTEGER NOT NULL DEFAULT 0,
  mismatches TEXT NOT NULL DEFAULT '[]',  -- JSON array of BalanceMismatch
  hash_chain_valid INTEGER NOT NULL DEFAULT 1,
  hash_chain_errors TEXT NOT NULL DEFAULT '[]',  -- JSON array of error strings
  error_message TEXT
);

-- Index for querying recent reports
CREATE INDEX IF NOT EXISTS idx_reconciliation_reports_completed_at ON reconciliation_reports(completed_at DESC);

-- Index for filtering by status
CREATE INDEX IF NOT EXISTS idx_reconciliation_reports_status ON reconciliation_reports(status);
