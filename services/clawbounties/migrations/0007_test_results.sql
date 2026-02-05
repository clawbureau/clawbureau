CREATE TABLE IF NOT EXISTS test_results (
  test_result_id TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL,
  bounty_id TEXT NOT NULL,
  test_harness_id TEXT NOT NULL,
  passed INTEGER NOT NULL,
  total_tests INTEGER NOT NULL,
  passed_tests INTEGER NOT NULL,
  failed_tests INTEGER NOT NULL,
  execution_time_ms INTEGER NOT NULL,
  completed_at TEXT NOT NULL,
  error TEXT,
  test_results_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS test_results_submission_idx ON test_results (submission_id);
CREATE INDEX IF NOT EXISTS test_results_bounty_idx ON test_results (bounty_id);
CREATE INDEX IF NOT EXISTS test_results_harness_idx ON test_results (test_harness_id);
