-- clawsettle: Stripe webhook dedupe/event provenance
-- Migration 0001

CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    settlement_id TEXT,
    response_json TEXT NOT NULL,
    processed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_type_processed
  ON stripe_webhook_events(event_type, processed_at DESC);
