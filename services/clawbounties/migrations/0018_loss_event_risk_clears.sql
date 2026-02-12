-- ECON-RISK-MAX-002: deterministic risk-clear records for loss-event coupling.

CREATE TABLE IF NOT EXISTS bounty_risk_event_clears (
  clear_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  source_loss_event_id TEXT NOT NULL,
  bounty_id TEXT NOT NULL,
  reason TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (source_loss_event_id, bounty_id)
);

CREATE INDEX IF NOT EXISTS bounty_risk_event_clears_bounty_created_idx
  ON bounty_risk_event_clears (bounty_id, created_at DESC, clear_id DESC);

CREATE INDEX IF NOT EXISTS bounty_risk_event_clears_source_created_idx
  ON bounty_risk_event_clears (source_loss_event_id, created_at DESC, clear_id DESC);
