-- ClawLedger: Create machine-payment settlement tables
-- Migration 0007: Provider-agnostic settlement ingestion + idempotency replay log

CREATE TABLE IF NOT EXISTS payment_settlements (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    external_payment_id TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('payin', 'refund', 'payout')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'failed', 'reversed')),
    account_id TEXT NOT NULL,
    amount_minor TEXT NOT NULL,
    currency TEXT NOT NULL,
    network TEXT,
    rail TEXT,
    metadata TEXT,
    provider_created_at TEXT,
    provider_updated_at TEXT,
    settled_at TEXT,
    latest_event_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (latest_event_id) REFERENCES events(id),
    UNIQUE (provider, external_payment_id, direction)
);

CREATE INDEX IF NOT EXISTS idx_payment_settlements_provider_external
  ON payment_settlements(provider, external_payment_id);

CREATE INDEX IF NOT EXISTS idx_payment_settlements_account_status
  ON payment_settlements(account_id, status, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_payment_settlements_provider_status
  ON payment_settlements(provider, status, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS payment_settlement_ingestions (
    idempotency_key TEXT PRIMARY KEY,
    request_hash TEXT NOT NULL,
    settlement_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (settlement_id) REFERENCES payment_settlements(id)
);

CREATE INDEX IF NOT EXISTS idx_payment_settlement_ingestions_settlement
  ON payment_settlement_ingestions(settlement_id, created_at DESC);
