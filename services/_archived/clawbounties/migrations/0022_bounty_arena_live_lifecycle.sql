-- AGP-US-043
-- Persist live arena lifecycle state directly on bounty rows for deterministic reads.

ALTER TABLE bounties ADD COLUMN arena_status TEXT NOT NULL DEFAULT 'idle';
ALTER TABLE bounties ADD COLUMN arena_id TEXT;
ALTER TABLE bounties ADD COLUMN arena_task_fingerprint TEXT;
ALTER TABLE bounties ADD COLUMN arena_winner_contender_id TEXT;
ALTER TABLE bounties ADD COLUMN arena_evidence_links_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE bounties ADD COLUMN arena_updated_at TEXT;

CREATE INDEX IF NOT EXISTS bounties_arena_status_idx ON bounties(arena_status);
CREATE INDEX IF NOT EXISTS bounties_arena_id_idx ON bounties(arena_id);
