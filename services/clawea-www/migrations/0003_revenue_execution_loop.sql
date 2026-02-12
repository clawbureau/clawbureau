-- AEO-REV-007: Revenue Execution Loop
-- Adds source-intent lineage + deterministic operator alerts for SLA/routing health.

PRAGMA foreign_keys = ON;

ALTER TABLE leads ADD COLUMN source_intent TEXT NOT NULL DEFAULT 'direct';

UPDATE leads
SET source_intent = CASE
  WHEN lower(source) LIKE '%partner%' OR lower(campaign_id) LIKE '%partner%' THEN 'partner'
  WHEN lower(campaign_id) GLOB '*book*'
    OR lower(campaign_id) GLOB '*demo*'
    OR lower(campaign_id) GLOB '*buyer*'
    OR lower(campaign_id) GLOB '*enterprise*'
    OR lower(campaign_id) GLOB '*security*'
    OR lower(campaign_id) GLOB '*compliance*' THEN 'high-intent'
  WHEN lower(source) LIKE 'utm:%'
    OR lower(source) LIKE '%google%'
    OR lower(source) LIKE '%linkedin%'
    OR lower(source) LIKE '%paid%'
    OR lower(source) LIKE '%ads%' THEN 'paid-intent'
  WHEN lower(source) LIKE 'ref:%'
    OR lower(source) LIKE '%organic%'
    OR lower(source) LIKE '%seo%'
    OR lower(source) LIKE '%blog%' THEN 'organic'
  ELSE 'direct'
END;

CREATE INDEX IF NOT EXISTS idx_leads_source_intent ON leads(source_intent, created_at DESC);

CREATE TABLE IF NOT EXISTS lead_alerts (
  alert_id TEXT PRIMARY KEY,
  alert_key TEXT NOT NULL UNIQUE,
  alert_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'warning',
  lead_id TEXT,
  job_id TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  summary TEXT NOT NULL DEFAULT '',
  metadata_json TEXT NOT NULL DEFAULT '{}',
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  resolved_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (lead_id) REFERENCES leads(lead_id) ON DELETE SET NULL,
  FOREIGN KEY (job_id) REFERENCES lead_routing_jobs(job_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_lead_alerts_type_status ON lead_alerts(alert_type, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_lead_alerts_lead_id ON lead_alerts(lead_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_lead_alerts_job_id ON lead_alerts(job_id, updated_at DESC);
