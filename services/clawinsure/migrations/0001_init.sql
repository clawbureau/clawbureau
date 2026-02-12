-- clawinsure MVP schema (CINR-OPS-001)

CREATE TABLE IF NOT EXISTS quotes (
  quote_id TEXT PRIMARY KEY,
  claimant_did TEXT NOT NULL,
  coverage_type TEXT NOT NULL,
  coverage_amount_minor TEXT NOT NULL,
  term_days INTEGER NOT NULL,
  risk_score INTEGER NOT NULL,
  risk_tier INTEGER NOT NULL,
  dispute_rate_bps INTEGER NOT NULL,
  premium_bps INTEGER NOT NULL,
  premium_minor TEXT NOT NULL,
  quote_hash_b64u TEXT NOT NULL,
  source_refs_json TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS quotes_claimant_created_idx ON quotes (claimant_did, created_at DESC);

CREATE TABLE IF NOT EXISTS policies (
  policy_id TEXT PRIMARY KEY,
  create_idempotency_key TEXT NOT NULL UNIQUE,
  quote_id TEXT NOT NULL,
  policy_holder_did TEXT NOT NULL,
  coverage_type TEXT NOT NULL,
  coverage_amount_minor TEXT NOT NULL,
  premium_minor TEXT NOT NULL,
  premium_bps INTEGER NOT NULL,
  risk_score INTEGER NOT NULL,
  term_days INTEGER NOT NULL,
  status TEXT NOT NULL,
  paid_out_minor TEXT NOT NULL,
  provider_bond_id TEXT,
  premium_transfer_event_id TEXT NOT NULL,
  source_refs_json TEXT,
  created_at TEXT NOT NULL,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS policies_provider_bond_id_idx ON policies (provider_bond_id);
CREATE INDEX IF NOT EXISTS policies_holder_created_idx ON policies (policy_holder_did, created_at DESC);

CREATE TABLE IF NOT EXISTS provider_bonds (
  bond_id TEXT PRIMARY KEY,
  policy_id TEXT NOT NULL UNIQUE,
  provider_did TEXT NOT NULL,
  bond_amount_minor TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS provider_bonds_provider_idx ON provider_bonds (provider_did, created_at DESC);

CREATE TABLE IF NOT EXISTS claims (
  claim_id TEXT PRIMARY KEY,
  create_idempotency_key TEXT NOT NULL UNIQUE,
  policy_id TEXT NOT NULL,
  claimant_did TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  requested_amount_minor TEXT NOT NULL,
  approved_amount_minor TEXT,
  trial_case_id TEXT,
  escrow_id TEXT,
  evidence_json TEXT NOT NULL,
  evidence_resolution_json TEXT,
  adjudicate_idempotency_key TEXT,
  adjudication_json TEXT,
  adjudicated_at TEXT,
  payout_idempotency_key TEXT,
  payout_transfer_event_id TEXT,
  payout_json TEXT,
  paid_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS claims_policy_created_idx ON claims (policy_id, created_at DESC);
CREATE INDEX IF NOT EXISTS claims_claimant_created_idx ON claims (claimant_did, created_at DESC);
CREATE INDEX IF NOT EXISTS claims_status_created_idx ON claims (status, created_at DESC);
