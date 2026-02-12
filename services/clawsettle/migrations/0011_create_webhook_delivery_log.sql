-- ECON-OPS-002 Task 2: Webhook delivery SLA tracking
CREATE TABLE IF NOT EXISTS webhook_delivery_log (
  delivery_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('stripe', 'internal', 'loss_apply', 'loss_resolve')),
  received_at TEXT NOT NULL,
  processed_at TEXT,
  processing_ms INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK (status IN ('success', 'failed', 'timeout')) DEFAULT 'success',
  error_code TEXT,
  idempotency_key TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_received
  ON webhook_delivery_log (received_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_status
  ON webhook_delivery_log (status, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_log_source
  ON webhook_delivery_log (source, received_at DESC);

-- ECON-OPS-002 Task 3: Extend ops_alerts with threshold config
ALTER TABLE ops_alerts ADD COLUMN rule_id TEXT;
ALTER TABLE ops_alerts ADD COLUMN threshold_config_json TEXT;
ALTER TABLE ops_alerts ADD COLUMN resolved_at TEXT;
ALTER TABLE ops_alerts ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1;
