-- ICP-M6.3 / ICP-M6.4
-- Key transparency snapshots + revocation propagation SLO state

CREATE TABLE IF NOT EXISTS scope_key_transparency_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  generated_at INTEGER NOT NULL,
  generated_at_iso TEXT NOT NULL,
  active_kid TEXT NOT NULL,
  accepted_kids_json TEXT NOT NULL,
  signing_kids_json TEXT NOT NULL,
  verify_only_kids_json TEXT NOT NULL,
  expiring_kids_json TEXT NOT NULL,
  overlap_seconds INTEGER NOT NULL,
  snapshot_hash_b64u TEXT NOT NULL,
  signer_kid TEXT NOT NULL,
  signature_b64u TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  r2_object_key TEXT,
  persisted_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scope_key_transparency_generated
  ON scope_key_transparency_snapshots(generated_at DESC);

CREATE TABLE IF NOT EXISTS scope_revocation_slo_tokens (
  token_hash TEXT PRIMARY KEY,
  revoked_at INTEGER NOT NULL,
  revoked_at_iso TEXT NOT NULL,
  first_observed_revoked_at INTEGER,
  last_observed_revoked_at INTEGER,
  observed_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_scope_revocation_slo_revoked_at
  ON scope_revocation_slo_tokens(revoked_at DESC);
