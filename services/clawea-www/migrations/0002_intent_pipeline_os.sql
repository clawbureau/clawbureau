-- AEO-REV-006: Intent-to-Pipeline Operating System
-- Expands lead lifecycle, routing reliability, attribution and booking closure.

PRAGMA foreign_keys = ON;

ALTER TABLE leads ADD COLUMN score_band TEXT NOT NULL DEFAULT 'low';
ALTER TABLE leads ADD COLUMN segment TEXT NOT NULL DEFAULT 'smb';
ALTER TABLE leads ADD COLUMN campaign_id TEXT NOT NULL DEFAULT '';
ALTER TABLE leads ADD COLUMN variant_id TEXT NOT NULL DEFAULT '';
ALTER TABLE leads ADD COLUMN hero_variant TEXT NOT NULL DEFAULT '';
ALTER TABLE leads ADD COLUMN cta_variant TEXT NOT NULL DEFAULT '';
ALTER TABLE leads ADD COLUMN behavior_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE leads ADD COLUMN lifecycle_updated_at TEXT NOT NULL DEFAULT '';
ALTER TABLE leads ADD COLUMN routed_provider_id TEXT NOT NULL DEFAULT '';
ALTER TABLE leads ADD COLUMN route_status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE leads ADD COLUMN booked_at TEXT;
ALTER TABLE leads ADD COLUMN completed_at TEXT;
ALTER TABLE leads ADD COLUMN last_deny_code TEXT NOT NULL DEFAULT '';

UPDATE leads
SET lifecycle_updated_at = CASE
  WHEN lifecycle_updated_at = '' THEN updated_at
  ELSE lifecycle_updated_at
END;

UPDATE leads
SET status = 'scored'
WHERE status = 'enriched';

UPDATE leads
SET status = 'disqualified'
WHERE status = 'rejected';

UPDATE leads
SET status = 'booked'
WHERE status = 'closed';

UPDATE leads
SET score_band = CASE
  WHEN qualification_score >= 80 THEN 'high'
  WHEN qualification_score >= 55 THEN 'medium'
  ELSE 'low'
END;

UPDATE leads
SET segment = CASE
  WHEN team_size LIKE '%500%' OR team_size LIKE '%enterprise%' OR team_size LIKE '%1000%' THEN 'enterprise'
  ELSE 'smb'
END;

CREATE TABLE IF NOT EXISTS lead_state_transitions (
  transition_id TEXT PRIMARY KEY,
  lead_id TEXT NOT NULL,
  from_state TEXT,
  to_state TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  FOREIGN KEY (lead_id) REFERENCES leads(lead_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_lead_state_transitions_lead_id ON lead_state_transitions(lead_id);
CREATE INDEX IF NOT EXISTS idx_lead_state_transitions_to_state ON lead_state_transitions(to_state);
CREATE INDEX IF NOT EXISTS idx_lead_state_transitions_created_at ON lead_state_transitions(created_at DESC);

CREATE TABLE IF NOT EXISTS lead_submit_attempts (
  attempt_id TEXT PRIMARY KEY,
  lead_id TEXT,
  ip_hash TEXT NOT NULL,
  email_hash TEXT,
  idempotency_key TEXT,
  visitor_id TEXT,
  source TEXT NOT NULL DEFAULT 'direct',
  campaign_id TEXT NOT NULL DEFAULT '',
  page_family TEXT NOT NULL DEFAULT 'contact',
  outcome_code TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (lead_id) REFERENCES leads(lead_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_lead_submit_attempts_ip_hash ON lead_submit_attempts(ip_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_lead_submit_attempts_email_hash ON lead_submit_attempts(email_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_lead_submit_attempts_outcome ON lead_submit_attempts(outcome_code, created_at DESC);

CREATE TABLE IF NOT EXISTS lead_routing_jobs (
  job_id TEXT PRIMARY KEY,
  lead_id TEXT NOT NULL,
  segment TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_attempt_at TEXT,
  last_error_code TEXT NOT NULL DEFAULT '',
  last_error_message TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  idempotency_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  sent_at TEXT,
  dead_lettered_at TEXT,
  FOREIGN KEY (lead_id) REFERENCES leads(lead_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_lead_routing_jobs_state ON lead_routing_jobs(state, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_lead_routing_jobs_segment ON lead_routing_jobs(segment, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_lead_routing_jobs_lead_id ON lead_routing_jobs(lead_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS lead_handoff_deliveries (
  delivery_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  status TEXT NOT NULL,
  http_status INTEGER,
  response_snippet TEXT NOT NULL DEFAULT '',
  signature TEXT NOT NULL DEFAULT '',
  attempt INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  FOREIGN KEY (job_id) REFERENCES lead_routing_jobs(job_id) ON DELETE CASCADE,
  FOREIGN KEY (lead_id) REFERENCES leads(lead_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_lead_handoff_deliveries_job_id ON lead_handoff_deliveries(job_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_lead_handoff_deliveries_provider ON lead_handoff_deliveries(provider_id, created_at DESC);

CREATE TABLE IF NOT EXISTS lead_handoff_dead_letter (
  dead_letter_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  lead_id TEXT NOT NULL,
  segment TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  reason_message TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  replay_count INTEGER NOT NULL DEFAULT 0,
  replayed_at TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (job_id) REFERENCES lead_routing_jobs(job_id) ON DELETE CASCADE,
  FOREIGN KEY (lead_id) REFERENCES leads(lead_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_lead_handoff_dead_letter_job_id ON lead_handoff_dead_letter(job_id);
CREATE INDEX IF NOT EXISTS idx_lead_handoff_dead_letter_created_at ON lead_handoff_dead_letter(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_lead_handoff_dead_letter_replayed ON lead_handoff_dead_letter(replayed_at, created_at DESC);

CREATE TABLE IF NOT EXISTS booking_events (
  booking_id TEXT PRIMARY KEY,
  lead_id TEXT NOT NULL,
  status TEXT NOT NULL,
  slot_iso TEXT,
  notes TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'book-form',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  FOREIGN KEY (lead_id) REFERENCES leads(lead_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_booking_events_lead_id ON booking_events(lead_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_booking_events_status ON booking_events(status, updated_at DESC);

CREATE TABLE IF NOT EXISTS experiment_winner_recommendations (
  recommendation_id TEXT PRIMARY KEY,
  period_from TEXT NOT NULL,
  period_to TEXT NOT NULL,
  page_family TEXT NOT NULL,
  recommended_variant TEXT,
  support_impressions INTEGER NOT NULL DEFAULT 0,
  support_submits INTEGER NOT NULL DEFAULT 0,
  support_booked INTEGER NOT NULL DEFAULT 0,
  confidence REAL NOT NULL DEFAULT 0,
  guardrail_notes TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  approved_by TEXT,
  approved_at TEXT,
  applied_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_experiment_winner_recs_family ON experiment_winner_recommendations(page_family, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_experiment_winner_recs_period ON experiment_winner_recommendations(period_from, period_to);
