-- Store Trust Pulse artifacts separately from submissions to avoid row bloat.
-- One Trust Pulse per submission_id.

CREATE TABLE IF NOT EXISTS submission_trust_pulse (
  submission_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  agent_did TEXT NOT NULL,

  trust_pulse_json TEXT NOT NULL,
  hash_b64u TEXT NOT NULL,
  status TEXT NOT NULL, -- 'verified' | 'unverified'
  created_at TEXT NOT NULL,

  FOREIGN KEY (submission_id) REFERENCES submissions(submission_id)
);

CREATE INDEX IF NOT EXISTS submission_trust_pulse_run_idx ON submission_trust_pulse(run_id);
CREATE INDEX IF NOT EXISTS submission_trust_pulse_agent_idx ON submission_trust_pulse(agent_did);
