-- Migration: Create clearing_accounts table for cross-service settlement
-- Clearing accounts are system accounts for each domain (escrow, marketplace, treasury, etc.)

CREATE TABLE IF NOT EXISTS clearing_accounts (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    balance_available TEXT NOT NULL DEFAULT '0',
    balance_held TEXT NOT NULL DEFAULT '0',
    balance_bonded TEXT NOT NULL DEFAULT '0',
    balance_fee_pool TEXT NOT NULL DEFAULT '0',
    balance_promo TEXT NOT NULL DEFAULT '0',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

-- Index for domain lookups
CREATE INDEX IF NOT EXISTS idx_clearing_accounts_domain ON clearing_accounts(domain);

-- Index for active clearing accounts
CREATE INDEX IF NOT EXISTS idx_clearing_accounts_active ON clearing_accounts(is_active);
