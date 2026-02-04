-- Add worker registry (MVP)

CREATE TABLE IF NOT EXISTS workers (
  worker_id TEXT PRIMARY KEY,
  worker_did TEXT NOT NULL UNIQUE,

  status TEXT NOT NULL,
  worker_version TEXT NOT NULL,

  listing_json TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,
  offers_json TEXT NOT NULL,
  price_floor_minor TEXT NOT NULL,
  availability_json TEXT NOT NULL,

  auth_mode TEXT NOT NULL,
  auth_token_hash_hex TEXT NOT NULL,
  auth_token_prefix TEXT NOT NULL,
  auth_token_created_at TEXT NOT NULL,
  auth_token_expires_at TEXT NOT NULL,

  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS workers_status_idx ON workers(status);
CREATE INDEX IF NOT EXISTS workers_did_idx ON workers(worker_did);
CREATE INDEX IF NOT EXISTS workers_token_hash_idx ON workers(auth_token_hash_hex);
CREATE INDEX IF NOT EXISTS workers_updated_at_idx ON workers(updated_at);
