-- ClawLedger: Create events table
-- Migration 0002: Append-only event log for audit trail

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    account_id TEXT NOT NULL,
    to_account_id TEXT,
    amount TEXT NOT NULL,
    bucket TEXT NOT NULL DEFAULT 'available',
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
);

-- Index on idempotency_key for fast deduplication
CREATE INDEX IF NOT EXISTS idx_events_idempotency_key ON events(idempotency_key);

-- Index on account_id for account history queries
CREATE INDEX IF NOT EXISTS idx_events_account_id ON events(account_id);

-- Index on event_type for filtering
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

-- Index on created_at for time-based queries and hash chain ordering
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

-- Index on event_hash for hash chain verification
CREATE INDEX IF NOT EXISTS idx_events_hash ON events(event_hash);
