-- CSC-US-007/008/009/010/011/012/013 observability + reporting stack

CREATE TABLE IF NOT EXISTS scope_observability_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  service TEXT NOT NULL,
  route TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  duration_ms REAL NOT NULL,
  token_hash TEXT,
  mission_id TEXT,
  scope_count INTEGER,
  trace_id TEXT NOT NULL,
  correlation_id TEXT,
  details_json TEXT,
  created_at INTEGER NOT NULL,
  created_at_iso TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scope_obs_events_created
  ON scope_observability_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scope_obs_events_route
  ON scope_observability_events(route, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scope_obs_events_mission
  ON scope_observability_events(mission_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scope_obs_events_trace
  ON scope_observability_events(trace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS scope_alert_rules (
  rule_id TEXT PRIMARY KEY,
  metric_name TEXT NOT NULL,
  comparison TEXT NOT NULL,
  threshold REAL NOT NULL,
  window_minutes INTEGER NOT NULL,
  service TEXT,
  route TEXT,
  mission_id TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scope_alert_rules_active
  ON scope_alert_rules(active, created_at DESC);

CREATE TABLE IF NOT EXISTS scope_alert_events (
  alert_event_id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  metric_name TEXT NOT NULL,
  metric_value REAL NOT NULL,
  comparison TEXT NOT NULL,
  threshold REAL NOT NULL,
  window_start INTEGER NOT NULL,
  window_end INTEGER NOT NULL,
  trace_id TEXT,
  details_json TEXT,
  triggered_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scope_alert_events_triggered
  ON scope_alert_events(triggered_at DESC);

CREATE TABLE IF NOT EXISTS scope_daily_usage_rollups (
  day TEXT NOT NULL,
  service TEXT NOT NULL,
  route TEXT NOT NULL,
  requests INTEGER NOT NULL,
  errors INTEGER NOT NULL,
  avg_latency_ms REAL NOT NULL,
  p95_latency_ms REAL NOT NULL,
  token_issues INTEGER NOT NULL,
  token_revocations INTEGER NOT NULL,
  generated_at INTEGER NOT NULL,
  PRIMARY KEY (day, service, route)
);

CREATE TABLE IF NOT EXISTS scope_daily_cost_rollups (
  day TEXT NOT NULL,
  service TEXT NOT NULL,
  requests INTEGER NOT NULL,
  est_compute_cost_usd REAL NOT NULL,
  est_storage_cost_usd REAL NOT NULL,
  generated_at INTEGER NOT NULL,
  PRIMARY KEY (day, service)
);

CREATE TABLE IF NOT EXISTS scope_daily_mission_rollups (
  day TEXT NOT NULL,
  mission_id TEXT NOT NULL,
  requests INTEGER NOT NULL,
  errors INTEGER NOT NULL,
  token_issues INTEGER NOT NULL,
  avg_latency_ms REAL NOT NULL,
  generated_at INTEGER NOT NULL,
  PRIMARY KEY (day, mission_id)
);

CREATE TABLE IF NOT EXISTS scope_sla_reports (
  day TEXT PRIMARY KEY,
  availability_ratio REAL NOT NULL,
  error_rate REAL NOT NULL,
  p95_latency_ms REAL NOT NULL,
  generated_at INTEGER NOT NULL,
  report_key TEXT
);

CREATE TABLE IF NOT EXISTS scope_trace_index (
  trace_id TEXT PRIMARY KEY,
  correlation_id TEXT,
  route TEXT,
  method TEXT,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  event_count INTEGER NOT NULL,
  latest_status_code INTEGER NOT NULL
);
