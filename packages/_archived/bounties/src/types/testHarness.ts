import { z } from "zod";

/**
 * Individual test case result
 */
export const TestCaseResultSchema = z.object({
  name: z.string(),
  passed: z.boolean(),
  duration_ms: z.number().nonnegative().optional(),
  error_message: z.string().optional(),
});

export type TestCaseResult = z.infer<typeof TestCaseResultSchema>;

/**
 * Request to run a test harness against a submission
 */
export const RunTestHarnessRequestSchema = z.object({
  schema_version: z.literal("1"),
  test_harness_id: z.string(),
  submission_id: z.string(),
  bounty_id: z.string(),
  /** The submission output to test (could be URL, code, or structured data) */
  output: z.union([z.string(), z.record(z.unknown())]),
  /** Proof bundle hash for verification */
  proof_bundle_hash: z.string(),
  /** Timeout in milliseconds for test execution */
  timeout_ms: z.number().int().positive().default(60000),
});

export type RunTestHarnessRequest = z.infer<typeof RunTestHarnessRequestSchema>;

/**
 * Response from running a test harness
 */
export const RunTestHarnessResponseSchema = z.object({
  schema_version: z.literal("1"),
  test_harness_id: z.string(),
  submission_id: z.string(),
  /** Overall pass/fail status */
  passed: z.boolean(),
  /** Total number of tests */
  total_tests: z.number().int().nonnegative(),
  /** Number of passed tests */
  passed_tests: z.number().int().nonnegative(),
  /** Number of failed tests */
  failed_tests: z.number().int().nonnegative(),
  /** Individual test results */
  test_results: z.array(TestCaseResultSchema),
  /** Total execution time in milliseconds */
  execution_time_ms: z.number().nonnegative(),
  /** ISO timestamp when tests completed */
  completed_at: z.string().datetime(),
  /** Error message if harness failed to run */
  error: z.string().optional(),
});

export type RunTestHarnessResponse = z.infer<typeof RunTestHarnessResponseSchema>;

/**
 * Interface for the test harness service client
 */
export interface TestHarnessService {
  runTests(request: RunTestHarnessRequest): Promise<RunTestHarnessResponse>;
}
