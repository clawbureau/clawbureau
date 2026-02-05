-- add signed receipt columns + anchors table
ALTER TABLE events ADD COLUMN event_hash TEXT;
ALTER TABLE events ADD COLUMN event_sig TEXT;
ALTER TABLE events ADD COLUMN event_sig_alg TEXT;
ALTER TABLE events ADD COLUMN event_sig_did TEXT;
ALTER TABLE events ADD COLUMN event_sig_pubkey TEXT;

CREATE TABLE IF NOT EXISTS anchors (
  anchor_id TEXT PRIMARY KEY,
  root_hash TEXT NOT NULL,
  from_created_at TEXT NOT NULL,
  to_created_at TEXT NOT NULL,
  event_count INTEGER NOT NULL,
  tx_hash TEXT,
  created_at TEXT NOT NULL
);
