-- Dispute-to-loss-event bridge table.
-- Maps Stripe dispute IDs to loss event IDs for deterministic resolution lookups.
-- One dispute can only map to one loss event (UNIQUE on dispute_id).

CREATE TABLE IF NOT EXISTS dispute_loss_event_bridge (
  id                TEXT    PRIMARY KEY,
  dispute_id        TEXT    NOT NULL,
  stripe_event_id   TEXT    NOT NULL,
  loss_event_id     TEXT    NOT NULL,
  account_id        TEXT,
  account_did       TEXT,
  amount_minor      TEXT    NOT NULL,
  currency          TEXT    NOT NULL DEFAULT 'USD',
  dispute_status    TEXT    NOT NULL DEFAULT 'open',
  dispute_reason    TEXT,
  resolved_at       TEXT,
  resolution_type   TEXT,
  created_at        TEXT    NOT NULL,
  updated_at        TEXT    NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_dispute_bridge_dispute_id
  ON dispute_loss_event_bridge (dispute_id);

CREATE INDEX IF NOT EXISTS idx_dispute_bridge_loss_event_id
  ON dispute_loss_event_bridge (loss_event_id);

CREATE INDEX IF NOT EXISTS idx_dispute_bridge_status
  ON dispute_loss_event_bridge (dispute_status);
