-- CBT-US-029: persist canonical control-plane evidence for requester auth events.

ALTER TABLE requester_auth_events ADD COLUMN token_scope_hash_b64u TEXT;
ALTER TABLE requester_auth_events ADD COLUMN token_lane TEXT;
ALTER TABLE requester_auth_events ADD COLUMN payment_account_did TEXT;
ALTER TABLE requester_auth_events ADD COLUMN token_iat INTEGER;
ALTER TABLE requester_auth_events ADD COLUMN token_exp INTEGER;
ALTER TABLE requester_auth_events ADD COLUMN sensitive_transition INTEGER NOT NULL DEFAULT 0;
ALTER TABLE requester_auth_events ADD COLUMN control_plane_check_json TEXT;

CREATE INDEX IF NOT EXISTS idx_requester_auth_events_sensitive_created
  ON requester_auth_events (sensitive_transition, created_at DESC);
