-- ECON-RISK-MAX-001: risk-hold state for payout-sensitive escrow transitions.

ALTER TABLE escrows ADD COLUMN risk_hold_status TEXT DEFAULT 'clear';
ALTER TABLE escrows ADD COLUMN risk_hold_json TEXT;
ALTER TABLE escrows ADD COLUMN risk_hold_updated_at TEXT;
