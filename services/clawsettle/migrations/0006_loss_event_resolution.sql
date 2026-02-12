-- ECON-RISK-MAX-002: deterministic loss-event resolution + release outbox.

CREATE TABLE IF NOT EXISTS loss_event_resolutions (
  id TEXT PRIMARY KEY,
  loss_event_id TEXT NOT NULL UNIQUE,
  idempotency_key TEXT NOT NULL UNIQUE,
  request_hash TEXT NOT NULL,
  reason TEXT,
  status TEXT NOT NULL CHECK (status IN ('recorded', 'processing', 'partially_forwarded', 'forwarded', 'failed')),
  target_count INTEGER NOT NULL DEFAULT 0,
  forwarded_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_forwarded_at TEXT,
  resolved_at TEXT,
  FOREIGN KEY (loss_event_id) REFERENCES loss_events(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_loss_event_resolutions_status_created
  ON loss_event_resolutions(status, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS loss_event_resolution_outbox (
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
  FOREIGN KEY (loss_event_id) REFERENCES loss_event_resolutions(loss_event_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_loss_event_resolution_outbox_retry
  ON loss_event_resolution_outbox(status, next_retry_at, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_loss_event_resolution_outbox_event
  ON loss_event_resolution_outbox(loss_event_id, status, created_at ASC, id ASC);
