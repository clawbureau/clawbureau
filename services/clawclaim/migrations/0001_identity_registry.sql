-- CCL-US-004/005/006/007/009 identity productization registry

CREATE TABLE IF NOT EXISTS platform_claims (
  claim_id TEXT PRIMARY KEY,
  owner_did TEXT NOT NULL,
  platform TEXT NOT NULL,
  handle TEXT NOT NULL,
  proof_url TEXT NOT NULL,
  verification_ref TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_claim_owner_platform_handle
  ON platform_claims(owner_did, platform, handle);

CREATE INDEX IF NOT EXISTS idx_platform_claim_owner
  ON platform_claims(owner_did, updated_at DESC);

CREATE TABLE IF NOT EXISTS account_primary_dids (
  account_id TEXT PRIMARY KEY,
  primary_did TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS owner_attestations (
  attestation_id TEXT PRIMARY KEY,
  owner_did TEXT NOT NULL,
  owner_provider TEXT NOT NULL,
  provider_ref TEXT,
  verification_level TEXT NOT NULL,
  proof_url TEXT,
  expires_at INTEGER,
  envelope_json TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_owner_attestations_owner
  ON owner_attestations(owner_did, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_owner_attestations_provider_ref
  ON owner_attestations(owner_provider, provider_ref);

CREATE TABLE IF NOT EXISTS org_roster_manifests (
  manifest_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  owner_did TEXT NOT NULL,
  manifest_hash_b64u TEXT NOT NULL,
  manifest_version TEXT NOT NULL,
  member_count INTEGER NOT NULL,
  issued_at INTEGER NOT NULL,
  signature_b64u TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_org_roster_manifests_org
  ON org_roster_manifests(org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS org_roster_members (
  manifest_id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  member_did TEXT NOT NULL,
  team_role TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (manifest_id, member_did)
);

CREATE INDEX IF NOT EXISTS idx_org_roster_members_org
  ON org_roster_members(org_id, member_did);

CREATE TABLE IF NOT EXISTS binding_audit_events (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  event_type TEXT NOT NULL,
  actor_did TEXT NOT NULL,
  subject_did TEXT,
  occurred_at INTEGER NOT NULL,
  details_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_binding_audit_events_occurred
  ON binding_audit_events(occurred_at DESC);
