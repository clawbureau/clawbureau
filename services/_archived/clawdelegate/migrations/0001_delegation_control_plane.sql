-- 0001_delegation_control_plane.sql
-- CDL-MAX-001: delegation control plane + delegated CST + spend governance + audit

CREATE TABLE IF NOT EXISTS delegations (
  delegation_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  delegator_did TEXT NOT NULL,
  delegate_did TEXT NOT NULL,
  aud_json TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  ttl_seconds INTEGER NOT NULL,
  spend_cap_minor TEXT NOT NULL,
  policy_hash_b64u TEXT,
  policy_pin_verified INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL CHECK (state IN ('pending_approval', 'approved', 'revoked', 'expired')),
  reserved_minor TEXT NOT NULL DEFAULT '0',
  consumed_minor TEXT NOT NULL DEFAULT '0',
  created_by TEXT,
  approved_by TEXT,
  revoked_by TEXT,
  created_at TEXT NOT NULL,
  approved_at TEXT,
  revoked_at TEXT,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_delegations_state_created
  ON delegations(state, created_at DESC, delegation_id DESC);

CREATE INDEX IF NOT EXISTS idx_delegations_delegator_state
  ON delegations(delegator_did, state, created_at DESC);

CREATE TABLE IF NOT EXISTS delegation_tokens (
  token_hash TEXT PRIMARY KEY,
  delegation_id TEXT NOT NULL,
  token_scope_hash_b64u TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  revocation_reason TEXT,
  FOREIGN KEY (delegation_id) REFERENCES delegations(delegation_id)
);

CREATE INDEX IF NOT EXISTS idx_delegation_tokens_by_delegation
  ON delegation_tokens(delegation_id, issued_at DESC);

CREATE TABLE IF NOT EXISTS delegation_spend_events (
  spend_event_id TEXT PRIMARY KEY,
  delegation_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('reserve', 'consume', 'release', 'authorize')),
  amount_minor TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('applied', 'already_applied', 'denied')),
  actor_did TEXT,
  token_hash TEXT,
  token_scope_hash_b64u TEXT,
  ledger_event_id TEXT,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (delegation_id) REFERENCES delegations(delegation_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_delegation_spend_idempotency
  ON delegation_spend_events(delegation_id, idempotency_key);

CREATE INDEX IF NOT EXISTS idx_delegation_spend_created
  ON delegation_spend_events(delegation_id, created_at DESC);

CREATE TABLE IF NOT EXISTS delegation_audit_events (
  audit_id TEXT PRIMARY KEY,
  delegation_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor_did TEXT,
  decision TEXT NOT NULL,
  token_hash TEXT,
  token_scope_hash_b64u TEXT,
  details_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (delegation_id) REFERENCES delegations(delegation_id)
);

CREATE INDEX IF NOT EXISTS idx_delegation_audit_created
  ON delegation_audit_events(delegation_id, created_at DESC, audit_id DESC);
