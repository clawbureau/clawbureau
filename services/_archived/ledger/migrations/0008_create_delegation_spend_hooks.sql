-- ClawLedger: Create delegation spend hook idempotency table
-- Migration 0008: deterministic reserve/consume/release hook replay store for clawdelegate

CREATE TABLE IF NOT EXISTS delegation_spend_hooks (
    event_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    delegation_id TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('reserve', 'consume', 'release')),
    delegator_did TEXT NOT NULL,
    actor_did TEXT NOT NULL,
    amount_minor TEXT NOT NULL,
    token_hash TEXT,
    request_fingerprint TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_delegation_spend_hooks_delegation_created
  ON delegation_spend_hooks(delegation_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_delegation_spend_hooks_operation_created
  ON delegation_spend_hooks(operation, created_at DESC);
