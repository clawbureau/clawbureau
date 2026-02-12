-- ClawLedger: Create holds table
-- Migration 0003: Track active holds for escrow operations

CREATE TABLE IF NOT EXISTS holds (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    account_id TEXT NOT NULL,
    amount TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    hold_event_id TEXT NOT NULL,
    release_event_id TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL,
    released_at TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(id),
    FOREIGN KEY (hold_event_id) REFERENCES events(id),
    FOREIGN KEY (release_event_id) REFERENCES events(id)
);

-- Index on account_id for account holds queries
CREATE INDEX IF NOT EXISTS idx_holds_account_id ON holds(account_id);

-- Index on status for filtering active holds
CREATE INDEX IF NOT EXISTS idx_holds_status ON holds(status);

-- Index on idempotency_key for fast deduplication
CREATE INDEX IF NOT EXISTS idx_holds_idempotency_key ON holds(idempotency_key);
