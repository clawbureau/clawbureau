CREATE TABLE IF NOT EXISTS stripe_webhook_outbox (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  livemode INTEGER NOT NULL CHECK (livemode IN (0, 1)),
  settlement_payload_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'failed', 'forwarded')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_retry_at TEXT,
  last_attempted_at TEXT,
  last_error_code TEXT,
  last_error_message TEXT,
  ledger_status INTEGER,
  settlement_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  forwarded_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_outbox_retry
  ON stripe_webhook_outbox(status, next_retry_at, created_at);
