-- MPY-US-015: Settlement reconciliation hardening for dispute lifecycle.
--
-- 1. Add disputed_amount_minor to dispute bridge (partial disputes).
-- 2. Create dispute_fees table for Stripe dispute fee tracking.
-- 3. Add indexes for aging/reconciliation queries.

-- Stripe disputes can be for less than the full charge amount.
-- disputed_amount_minor captures the actual dispute amount vs. the
-- charge amount_minor already stored.
ALTER TABLE dispute_loss_event_bridge
  ADD COLUMN disputed_amount_minor TEXT;

-- Stripe charges $15/dispute opened, plus chargeback amount on losses.
-- Model as separate ledger-reconcilable entries.
CREATE TABLE IF NOT EXISTS dispute_fees (
  id              TEXT    PRIMARY KEY,
  dispute_id      TEXT    NOT NULL,
  bridge_id       TEXT    NOT NULL,
  fee_type        TEXT    NOT NULL CHECK (fee_type IN ('dispute_fee', 'chargeback_fee')),
  amount_minor    TEXT    NOT NULL,
  currency        TEXT    NOT NULL DEFAULT 'USD',
  ledger_event_id TEXT,
  status          TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'recorded', 'failed')),
  created_at      TEXT    NOT NULL,
  updated_at      TEXT    NOT NULL,
  FOREIGN KEY (bridge_id) REFERENCES dispute_loss_event_bridge(id)
);

CREATE INDEX IF NOT EXISTS idx_dispute_fees_dispute_id
  ON dispute_fees (dispute_id);

CREATE INDEX IF NOT EXISTS idx_dispute_fees_status
  ON dispute_fees (status);

-- Aging query support: index on dispute_status + created_at for bucket grouping.
CREATE INDEX IF NOT EXISTS idx_dispute_bridge_aging
  ON dispute_loss_event_bridge (dispute_status, created_at);

-- Reconciliation: index on account_id for per-account mismatch detection.
CREATE INDEX IF NOT EXISTS idx_dispute_bridge_account
  ON dispute_loss_event_bridge (account_id, created_at);
