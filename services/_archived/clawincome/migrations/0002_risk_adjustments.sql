-- ECON-RISK-MAX-001: deterministic risk adjustment intake from clawsettle loss-event loop.

CREATE TABLE IF NOT EXISTS risk_adjustments (
  adjustment_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  source_loss_event_id TEXT NOT NULL,
  source_service TEXT NOT NULL,
  source_event_id TEXT,
  account_id TEXT NOT NULL,
  account_did TEXT,
  direction TEXT NOT NULL CHECK (direction IN ('debit', 'credit')),
  amount_minor TEXT NOT NULL,
  currency TEXT NOT NULL CHECK (currency = 'USD'),
  reason_code TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  occurred_at TEXT NOT NULL,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (source_loss_event_id, account_id, direction)
);

CREATE INDEX IF NOT EXISTS risk_adjustments_account_occurred_idx
  ON risk_adjustments(account_id, occurred_at DESC, adjustment_id DESC);

CREATE INDEX IF NOT EXISTS risk_adjustments_did_occurred_idx
  ON risk_adjustments(account_did, occurred_at DESC, adjustment_id DESC);
