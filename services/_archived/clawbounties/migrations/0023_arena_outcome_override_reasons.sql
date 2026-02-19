-- AGP-US-045
-- Capture structured human override reasons for policy learning.

ALTER TABLE bounty_arena_outcomes ADD COLUMN override_reason_code TEXT;

CREATE INDEX IF NOT EXISTS bounty_arena_outcomes_override_reason_idx
  ON bounty_arena_outcomes(override_reason_code);
