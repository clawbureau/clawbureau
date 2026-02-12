-- ECON-OPS-001: Ops alerting table for cron-triggered health checks.

CREATE TABLE IF NOT EXISTS ops_alerts (
  id            TEXT    PRIMARY KEY,
  alert_type    TEXT    NOT NULL,
  severity      TEXT    NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
  details_json  TEXT    NOT NULL,
  created_at    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ops_alerts_created
  ON ops_alerts (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ops_alerts_severity
  ON ops_alerts (severity, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ops_alerts_type
  ON ops_alerts (alert_type, created_at DESC);
