-- clawescrow D1 schema (v1)

CREATE TABLE IF NOT EXISTS escrows (
  escrow_id TEXT PRIMARY KEY,
  create_idempotency_key TEXT NOT NULL UNIQUE,

  buyer_did TEXT NOT NULL,
  worker_did TEXT,

  currency TEXT NOT NULL,
  amount_minor TEXT NOT NULL,
  buyer_total_minor TEXT NOT NULL,
  worker_net_minor TEXT NOT NULL,

  fee_quote_json TEXT NOT NULL,
  metadata_json TEXT,

  status TEXT NOT NULL,

  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  held_at TEXT,
  released_at TEXT,

  dispute_window_seconds INTEGER NOT NULL,
  dispute_window_ends_at TEXT NOT NULL,

  ledger_hold_event_id TEXT,
  ledger_worker_event_id TEXT,
  ledger_fee_event_ids_json TEXT,

  assign_idempotency_key TEXT,
  release_idempotency_key TEXT,
  dispute_idempotency_key TEXT,

  verification_json TEXT,
  dispute_json TEXT
);

CREATE INDEX IF NOT EXISTS escrows_buyer_did_idx ON escrows(buyer_did);
CREATE INDEX IF NOT EXISTS escrows_worker_did_idx ON escrows(worker_did);
CREATE INDEX IF NOT EXISTS escrows_status_idx ON escrows(status);
