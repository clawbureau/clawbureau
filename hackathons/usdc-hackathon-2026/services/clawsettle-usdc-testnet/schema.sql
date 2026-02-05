-- D1 schema for clawsettle-usdc-testnet

CREATE TABLE IF NOT EXISTS deposit_intents (
  intent_id TEXT PRIMARY KEY,
  buyer_did TEXT NOT NULL,
  amount_minor TEXT NOT NULL,
  amount_usdc_base TEXT NOT NULL,
  deposit_address TEXT NOT NULL,
  claim_secret_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  tx_hash TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS deposit_intents_tx_hash_idx ON deposit_intents(tx_hash);

CREATE TABLE IF NOT EXISTS payouts (
  payout_id TEXT PRIMARY KEY,
  worker_did TEXT NOT NULL,
  amount_minor TEXT NOT NULL,
  destination_address TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  tx_hash TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);
