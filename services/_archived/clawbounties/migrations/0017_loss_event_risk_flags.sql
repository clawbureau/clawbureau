-- ECON-RISK-MAX-001: loss-event risk coupling for bounty lifecycle.

CREATE TABLE IF NOT EXISTS bounty_risk_events (
  risk_event_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  source_loss_event_id TEXT NOT NULL,
  source_service TEXT NOT NULL,
  source_event_id TEXT,
  bounty_id TEXT NOT NULL,
  account_did TEXT,
  amount_minor TEXT NOT NULL,
  currency TEXT NOT NULL CHECK (currency = 'USD'),
  reason_code TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (source_loss_event_id, bounty_id)
);

CREATE INDEX IF NOT EXISTS bounty_risk_events_bounty_created_idx
  ON bounty_risk_events (bounty_id, created_at DESC, risk_event_id DESC);

CREATE INDEX IF NOT EXISTS bounty_risk_events_source_created_idx
  ON bounty_risk_events (source_loss_event_id, created_at DESC, risk_event_id DESC);
