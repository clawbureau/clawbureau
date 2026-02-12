-- Reserve asset registry
-- CLD-US-010: Reserve asset registry
-- Stores external reserve assets (e.g., provider credit balances) with haircut factors and eligibility flags

CREATE TABLE IF NOT EXISTS reserve_assets (
  asset_id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  currency TEXT NOT NULL,
  amount TEXT NOT NULL,
  haircut_bps INTEGER NOT NULL DEFAULT 10000,
  eligible INTEGER NOT NULL DEFAULT 1,
  as_of TEXT NOT NULL,
  metadata_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reserve_assets_provider ON reserve_assets(provider);
CREATE INDEX IF NOT EXISTS idx_reserve_assets_as_of ON reserve_assets(as_of);
