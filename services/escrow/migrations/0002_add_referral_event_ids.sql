-- Add separate referral transfer event references for release tracking.

ALTER TABLE escrows ADD COLUMN ledger_referral_event_ids_json TEXT;
