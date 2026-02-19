ALTER TABLE bounty_arena_outcomes ADD COLUMN reviewer_decision TEXT NOT NULL DEFAULT 'request_changes';
ALTER TABLE bounty_arena_outcomes ADD COLUMN reviewer_rationale TEXT;
ALTER TABLE bounty_arena_outcomes ADD COLUMN decision_taxonomy_json TEXT NOT NULL DEFAULT '[]';

UPDATE bounty_arena_outcomes
SET reviewer_decision = CASE recommendation
  WHEN 'APPROVE' THEN 'approve'
  WHEN 'REQUEST_CHANGES' THEN 'request_changes'
  WHEN 'REJECT' THEN 'reject'
  ELSE 'request_changes'
END
WHERE reviewer_decision IS NULL OR TRIM(reviewer_decision) = '';

UPDATE bounty_arena_outcomes
SET decision_taxonomy_json = CASE
  WHEN decision_taxonomy_json IS NULL OR TRIM(decision_taxonomy_json) = '' OR decision_taxonomy_json = '[]'
    THEN CASE
      WHEN override_reason_code IS NOT NULL AND TRIM(override_reason_code) <> ''
        THEN json_array(
          'decision:' || lower(reviewer_decision),
          'outcome:' || lower(outcome_status),
          'override:' || lower(override_reason_code)
        )
      ELSE json_array(
        'decision:' || lower(reviewer_decision),
        'outcome:' || lower(outcome_status)
      )
    END
  ELSE decision_taxonomy_json
END;

CREATE INDEX IF NOT EXISTS idx_bounty_arena_outcomes_reviewer_decision
  ON bounty_arena_outcomes(reviewer_decision);
