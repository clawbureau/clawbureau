-- ECON-RISK-MAX-001: deterministic risk-hold lifecycle for adverse settlement exposure.

CREATE TABLE IF NOT EXISTS risk_holds (
  hold_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  source_loss_event_id TEXT NOT NULL UNIQUE,
  account_ref TEXT NOT NULL,
  account_id TEXT,
  amount_minor TEXT NOT NULL,
  currency TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'released')),
  hold_transfer_event_id TEXT NOT NULL,
  release_idempotency_key TEXT,
  release_transfer_event_id TEXT,
  metadata TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  released_at TEXT
);

CREATE INDEX IF NOT EXISTS risk_holds_status_created_idx
  ON risk_holds(status, created_at DESC);

CREATE INDEX IF NOT EXISTS risk_holds_account_idx
  ON risk_holds(account_ref, created_at DESC);
