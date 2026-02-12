-- CTR-OPS-001: escrow decision resolution fields for clawtrials integration.

ALTER TABLE escrows ADD COLUMN ledger_refund_event_id TEXT;
ALTER TABLE escrows ADD COLUMN resolve_idempotency_key TEXT;
ALTER TABLE escrows ADD COLUMN resolution_json TEXT;
ALTER TABLE escrows ADD COLUMN resolved_at TEXT;
