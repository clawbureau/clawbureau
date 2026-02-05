-- D1 schema for clawledger-lite

CREATE TABLE IF NOT EXISTS accounts (
  did TEXT PRIMARY KEY,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS balances (
  did TEXT NOT NULL,
  bucket TEXT NOT NULL,
  amount_minor TEXT NOT NULL,
  PRIMARY KEY (did, bucket)
);

CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  from_did TEXT,
  to_did TEXT,
  amount_minor TEXT NOT NULL,
  currency TEXT NOT NULL,
  from_bucket TEXT,
  to_bucket TEXT,
  metadata_json TEXT,
  event_hash TEXT,
  event_sig TEXT,
  event_sig_alg TEXT,
  event_sig_did TEXT,
  event_sig_pubkey TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anchors (
  anchor_id TEXT PRIMARY KEY,
  root_hash TEXT NOT NULL,
  from_created_at TEXT NOT NULL,
  to_created_at TEXT NOT NULL,
  event_count INTEGER NOT NULL,
  tx_hash TEXT,
  created_at TEXT NOT NULL
);
