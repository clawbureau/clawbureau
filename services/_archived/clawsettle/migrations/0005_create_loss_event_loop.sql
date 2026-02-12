CREATE TABLE IF NOT EXISTS loss_events (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  request_hash TEXT NOT NULL,
  source_service TEXT NOT NULL,
  source_event_id TEXT NOT NULL,
  account_did TEXT NOT NULL,
  account_id TEXT,
  currency TEXT NOT NULL CHECK (currency = 'USD'),
  amount_minor TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  occurred_at TEXT NOT NULL,
  metadata_json TEXT,
  status TEXT NOT NULL CHECK (status IN ('recorded', 'processing', 'partially_forwarded', 'forwarded', 'failed')),
  target_count INTEGER NOT NULL DEFAULT 0,
  forwarded_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_forwarded_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_loss_events_source_event
  ON loss_events(source_service, source_event_id);

CREATE INDEX IF NOT EXISTS idx_loss_events_status_created
  ON loss_events(status, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_loss_events_account_did_occurred
  ON loss_events(account_did, occurred_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_loss_events_account_id_occurred
  ON loss_events(account_id, occurred_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS loss_event_outbox (
  id TEXT PRIMARY KEY,
  loss_event_id TEXT NOT NULL,
  target_service TEXT NOT NULL,
  target_url TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'forwarded', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_http_status INTEGER,
  last_error_code TEXT,
  last_error_message TEXT,
  next_retry_at TEXT,
  forwarded_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(loss_event_id, target_service),
  FOREIGN KEY (loss_event_id) REFERENCES loss_events(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_loss_event_outbox_retry
  ON loss_event_outbox(status, next_retry_at, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_loss_event_outbox_event
  ON loss_event_outbox(loss_event_id, status, created_at ASC, id ASC);
