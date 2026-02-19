ALTER TABLE runs ADD COLUMN reason_code TEXT;
ALTER TABLE runs ADD COLUMN failure_class TEXT;
ALTER TABLE runs ADD COLUMN verification_source TEXT;
ALTER TABLE runs ADD COLUMN auth_mode TEXT;

CREATE INDEX IF NOT EXISTS idx_runs_reason_code ON runs(reason_code);
