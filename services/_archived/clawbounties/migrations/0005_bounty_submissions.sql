-- Add bounty submissions table (CBT-US-021)

CREATE TABLE IF NOT EXISTS submissions (
  submission_id TEXT PRIMARY KEY,
  bounty_id TEXT NOT NULL,
  worker_did TEXT NOT NULL,
  status TEXT NOT NULL,

  idempotency_key TEXT,

  proof_bundle_envelope_json TEXT NOT NULL,
  proof_bundle_hash_b64u TEXT,
  proof_verify_status TEXT NOT NULL,
  proof_verify_reason TEXT,
  proof_verified_at TEXT,
  proof_tier TEXT,

  commit_proof_envelope_json TEXT,
  commit_proof_hash_b64u TEXT,
  commit_sha TEXT,
  repo_url TEXT,
  repo_claim_id TEXT,
  commit_proof_verify_status TEXT,
  commit_proof_verify_reason TEXT,
  commit_proof_verified_at TEXT,

  artifacts_json TEXT,
  agent_pack_json TEXT,
  result_summary TEXT,

  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS submissions_bounty_idx ON submissions(bounty_id);
CREATE INDEX IF NOT EXISTS submissions_worker_idx ON submissions(worker_did);
CREATE INDEX IF NOT EXISTS submissions_idempotency_idx ON submissions(idempotency_key);
CREATE UNIQUE INDEX IF NOT EXISTS submissions_idempotency_uniq ON submissions(idempotency_key) WHERE idempotency_key IS NOT NULL;
