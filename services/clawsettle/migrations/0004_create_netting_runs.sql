CREATE TABLE IF NOT EXISTS netting_runs (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  request_hash TEXT NOT NULL,
  currency TEXT NOT NULL,
  selection_before TEXT NOT NULL,
  source_clearing_domain TEXT NOT NULL,
  target_clearing_domain TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('created', 'running', 'applied', 'failed')),
  candidate_count INTEGER NOT NULL DEFAULT 0,
  applied_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  total_amount_minor TEXT NOT NULL DEFAULT '0',
  last_error_code TEXT,
  last_error_message TEXT,
  report_hash TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS netting_entries (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  entry_key TEXT NOT NULL,
  connect_account_id TEXT NOT NULL,
  currency TEXT NOT NULL,
  amount_minor TEXT NOT NULL,
  payout_count INTEGER NOT NULL,
  payout_ids_json TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('pending', 'applying', 'applied', 'failed')),
  ledger_event_id TEXT,
  last_error_code TEXT,
  last_error_message TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  applied_at TEXT,
  UNIQUE (run_id, entry_key),
  FOREIGN KEY (run_id) REFERENCES netting_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS netting_entry_payouts (
  run_id TEXT NOT NULL,
  entry_id TEXT NOT NULL,
  payout_id TEXT NOT NULL UNIQUE,
  amount_minor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (entry_id, payout_id),
  FOREIGN KEY (run_id) REFERENCES netting_runs(id) ON DELETE CASCADE,
  FOREIGN KEY (entry_id) REFERENCES netting_entries(id) ON DELETE CASCADE,
  FOREIGN KEY (payout_id) REFERENCES payouts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_netting_runs_status_created
  ON netting_runs(status, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_netting_entries_run_status
  ON netting_entries(run_id, status, created_at ASC, id ASC);

CREATE INDEX IF NOT EXISTS idx_netting_entries_connect
  ON netting_entries(connect_account_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_netting_entry_payouts_run
  ON netting_entry_payouts(run_id, entry_id, payout_id);
