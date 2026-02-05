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
  created_at TEXT NOT NULL
);
