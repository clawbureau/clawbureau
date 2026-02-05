-- D1 schema for clawescrow-lite

CREATE TABLE IF NOT EXISTS escrows (
  escrow_id TEXT PRIMARY KEY,
  buyer_did TEXT NOT NULL,
  worker_did TEXT,
  amount_minor TEXT NOT NULL,
  fee_minor TEXT NOT NULL,
  currency TEXT NOT NULL,
  status TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  assigned_at TEXT,
  released_at TEXT
);
