-- clawcuts D1 schema (CCU-OPS-001)

CREATE TABLE IF NOT EXISTS policy_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft', 'active', 'inactive')),
  policy_json TEXT NOT NULL,
  policy_hash_b64u TEXT NOT NULL,
  notes TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  activated_by TEXT,
  activated_at TEXT,
  deactivated_by TEXT,
  deactivated_at TEXT,
  UNIQUE(product, policy_id, version)
);

CREATE INDEX IF NOT EXISTS policy_versions_lookup_idx
  ON policy_versions(product, policy_id, version);

CREATE INDEX IF NOT EXISTS policy_versions_active_idx
  ON policy_versions(product, policy_id, status);

CREATE TABLE IF NOT EXISTS policy_audit_events (
  audit_id TEXT PRIMARY KEY,
  product TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  policy_version INTEGER,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  created_at TEXT NOT NULL,
  details_json TEXT
);

CREATE INDEX IF NOT EXISTS policy_audit_events_lookup_idx
  ON policy_audit_events(product, policy_id, created_at);

CREATE TABLE IF NOT EXISTS fee_apply_events (
  apply_id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  product TEXT NOT NULL,
  settlement_ref TEXT,
  month TEXT NOT NULL,
  currency TEXT NOT NULL,
  policy_id TEXT NOT NULL,
  policy_version INTEGER NOT NULL,
  policy_hash_b64u TEXT NOT NULL,
  principal_minor TEXT NOT NULL,
  buyer_total_minor TEXT NOT NULL,
  worker_net_minor TEXT NOT NULL,
  total_fee_minor TEXT NOT NULL,
  platform_fee_minor TEXT NOT NULL,
  referral_fee_minor TEXT NOT NULL,
  platform_retained_minor TEXT NOT NULL,
  transfer_plan_json TEXT NOT NULL,
  snapshot_json TEXT NOT NULL,
  context_json TEXT,
  ledger_fee_event_ids_json TEXT,
  ledger_referral_event_ids_json TEXT,
  created_at TEXT NOT NULL,
  finalized_at TEXT
);

CREATE INDEX IF NOT EXISTS fee_apply_events_month_idx
  ON fee_apply_events(month, product);

CREATE INDEX IF NOT EXISTS fee_apply_events_policy_idx
  ON fee_apply_events(product, policy_id, policy_version);
