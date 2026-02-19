-- AGP-US-047
-- Persist contender registry/version pins + experiment controls for reproducible arena runs.

ALTER TABLE bounty_arena_runs ADD COLUMN registry_version TEXT;
ALTER TABLE bounty_arena_runs ADD COLUMN experiment_id TEXT;
ALTER TABLE bounty_arena_runs ADD COLUMN experiment_arm TEXT;

ALTER TABLE bounty_arena_contenders ADD COLUMN version_pin TEXT;
ALTER TABLE bounty_arena_contenders ADD COLUMN prompt_template TEXT;
ALTER TABLE bounty_arena_contenders ADD COLUMN experiment_arm TEXT;

CREATE INDEX IF NOT EXISTS bounty_arena_runs_experiment_idx
  ON bounty_arena_runs(experiment_id, experiment_arm, updated_at DESC);
