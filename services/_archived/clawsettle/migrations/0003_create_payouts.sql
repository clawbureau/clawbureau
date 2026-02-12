CREATE TABLE IF NOT EXISTS payout_connect_accounts (
  account_id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  connect_account_id TEXT NOT NULL UNIQUE,
  onboarding_status TEXT NOT NULL CHECK (onboarding_status IN ('pending', 'active')),
  onboarding_url TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS payouts (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  request_hash TEXT NOT NULL,
  provider TEXT NOT NULL,
  account_id TEXT NOT NULL,
  account_did TEXT NOT NULL,
  connect_account_id TEXT NOT NULL,
  external_payout_id TEXT UNIQUE,
  amount_minor TEXT NOT NULL,
  currency TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('initiated', 'submitted', 'finalizing_paid', 'finalizing_failed', 'paid', 'failed')),
  lock_idempotency_key TEXT NOT NULL UNIQUE,
  lock_event_id TEXT,
  finalize_idempotency_key TEXT NOT NULL UNIQUE,
  finalize_event_id TEXT,
  rollback_idempotency_key TEXT NOT NULL UNIQUE,
  rollback_event_id TEXT,
  last_error_code TEXT,
  last_error_message TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  submitted_at TEXT,
  finalized_at TEXT,
  failed_at TEXT
);

CREATE TABLE IF NOT EXISTS payout_audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  payout_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  event_idempotency_key TEXT,
  details_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (payout_id, event_type, event_idempotency_key),
  FOREIGN KEY (payout_id) REFERENCES payouts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_payouts_status_updated
  ON payouts(status, updated_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_payouts_created
  ON payouts(created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_payouts_account_created
  ON payouts(account_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_payout_audit_events_payout
  ON payout_audit_events(payout_id, id ASC);
