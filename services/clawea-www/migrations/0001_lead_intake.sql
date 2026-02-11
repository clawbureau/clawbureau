-- AEO-REV-005: demand capture + qualification data model
-- Creates lead intake, idempotency, funnel telemetry, and lead lifecycle tables.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS leads (
  lead_id TEXT PRIMARY KEY,
  identity_hash TEXT NOT NULL UNIQUE,
  email_hash TEXT NOT NULL,
  email_hint TEXT NOT NULL DEFAULT '',

  full_name TEXT NOT NULL DEFAULT '',
  company TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT '',
  team_size TEXT NOT NULL DEFAULT '',
  timeline TEXT NOT NULL DEFAULT '',
  primary_use_case TEXT NOT NULL DEFAULT '',
  intent_note TEXT NOT NULL DEFAULT '',

  source TEXT NOT NULL DEFAULT 'direct',
  page TEXT NOT NULL DEFAULT '/contact',
  page_family TEXT NOT NULL DEFAULT 'contact',

  attribution_json TEXT NOT NULL DEFAULT '{}',
  first_touch_json TEXT NOT NULL DEFAULT '{}',
  assessment_json TEXT NOT NULL DEFAULT '{}',

  readiness_score INTEGER NOT NULL DEFAULT 0,
  roi_score INTEGER NOT NULL DEFAULT 0,
  risk_score INTEGER NOT NULL DEFAULT 50,
  intent_score INTEGER NOT NULL DEFAULT 0,
  qualification_score INTEGER NOT NULL DEFAULT 0,

  status TEXT NOT NULL DEFAULT 'new',
  dedupe_count INTEGER NOT NULL DEFAULT 0,

  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_leads_status ON leads(status);
CREATE INDEX IF NOT EXISTS idx_leads_source ON leads(source);
CREATE INDEX IF NOT EXISTS idx_leads_page_family ON leads(page_family);
CREATE INDEX IF NOT EXISTS idx_leads_last_seen_at ON leads(last_seen_at DESC);

CREATE TABLE IF NOT EXISTS lead_idempotency (
  idempotency_key TEXT PRIMARY KEY,
  lead_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (lead_id) REFERENCES leads(lead_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_lead_idempotency_lead_id ON lead_idempotency(lead_id);

CREATE TABLE IF NOT EXISTS lead_events (
  event_id TEXT PRIMARY KEY,
  lead_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  event_payload_json TEXT NOT NULL DEFAULT '{}',
  source TEXT NOT NULL DEFAULT 'direct',
  page TEXT NOT NULL DEFAULT '/contact',
  page_family TEXT NOT NULL DEFAULT 'contact',
  created_at TEXT NOT NULL,
  FOREIGN KEY (lead_id) REFERENCES leads(lead_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_lead_events_lead_id ON lead_events(lead_id);
CREATE INDEX IF NOT EXISTS idx_lead_events_type ON lead_events(event_type);
CREATE INDEX IF NOT EXISTS idx_lead_events_created_at ON lead_events(created_at DESC);

CREATE TABLE IF NOT EXISTS funnel_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  page TEXT NOT NULL,
  page_family TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'direct',
  cta_id TEXT,
  cta_variant TEXT,
  action_outcome TEXT,
  query TEXT,
  result_count INTEGER,
  target_path TEXT,
  variant_id TEXT,
  hero_variant TEXT,
  visitor_id TEXT,
  attribution_json TEXT NOT NULL DEFAULT '{}',
  event_ts TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_funnel_events_event_ts ON funnel_events(event_ts DESC);
CREATE INDEX IF NOT EXISTS idx_funnel_events_event_type ON funnel_events(event_type);
CREATE INDEX IF NOT EXISTS idx_funnel_events_page_family ON funnel_events(page_family);
CREATE INDEX IF NOT EXISTS idx_funnel_events_variant_id ON funnel_events(variant_id);
CREATE INDEX IF NOT EXISTS idx_funnel_events_cta_variant ON funnel_events(cta_variant);
CREATE INDEX IF NOT EXISTS idx_funnel_events_visitor_id ON funnel_events(visitor_id);
