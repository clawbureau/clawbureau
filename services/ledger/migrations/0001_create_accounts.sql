-- ClawLedger: Create accounts table
-- Migration 0001: Initial schema for account management

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    did TEXT NOT NULL UNIQUE,
    balance_available TEXT NOT NULL DEFAULT '0',
    balance_held TEXT NOT NULL DEFAULT '0',
    balance_bonded TEXT NOT NULL DEFAULT '0',
    balance_fee_pool TEXT NOT NULL DEFAULT '0',
    balance_promo TEXT NOT NULL DEFAULT '0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

-- Index on DID for fast lookups
CREATE INDEX IF NOT EXISTS idx_accounts_did ON accounts(did);

-- Index on created_at for time-based queries
CREATE INDEX IF NOT EXISTS idx_accounts_created_at ON accounts(created_at);
