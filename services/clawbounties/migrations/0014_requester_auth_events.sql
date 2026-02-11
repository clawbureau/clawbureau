-- Requester scoped-auth usage context for bounty actions (CEA-US-049H)

CREATE TABLE IF NOT EXISTS requester_auth_events (
  auth_event_id TEXT PRIMARY KEY,
  action TEXT NOT NULL,
  bounty_id TEXT,
  submission_id TEXT,
  requester_did TEXT NOT NULL,
  auth_mode TEXT NOT NULL,
  token_hash TEXT,
  scope_json TEXT NOT NULL,
  aud_json TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_requester_auth_events_bounty_created
  ON requester_auth_events (bounty_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_requester_auth_events_requester_created
  ON requester_auth_events (requester_did, created_at DESC);
