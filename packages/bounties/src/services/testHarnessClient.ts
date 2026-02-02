import {
  TestHarnessService,
  RunTestHarnessRequest,
  RunTestHarnessResponse,
  RunTestHarnessResponseSchema,
} from "../types/testHarness.js";

/**
 * Configuration for the test harness client
 */
export interface TestHarnessClientConfig {
  baseUrl: string;
  timeout?: number;
}

/**
 * HTTP client for test harness service
 *
 * Implements the TestHarnessService interface for running test harnesses
 * against bounty submissions.
 */
export class TestHarnessClient implements TestHarnessService {
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(config: TestHarnessClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.timeout = config.timeout ?? 120000; // 2 minutes default for test execution
  }

  async runTests(request: RunTestHarnessRequest): Promise<RunTestHarnessResponse> {
    const controller = new AbortController();
    // Use request timeout if provided, otherwise use client default
    const requestTimeout = request.timeout_ms ?? this.timeout;
    const timeoutId = setTimeout(() => controller.abort(), requestTimeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/harness/run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.text();
        return {
          schema_version: "1",
          test_harness_id: request.test_harness_id,
          submission_id: request.submission_id,
          passed: false,
          total_tests: 0,
          passed_tests: 0,
          failed_tests: 0,
          test_results: [],
          execution_time_ms: 0,
          completed_at: new Date().toISOString(),
          error: `HTTP ${response.status}: ${errorBody}`,
        };
      }

      const data = await response.json();
      const parsed = RunTestHarnessResponseSchema.safeParse(data);

      if (!parsed.success) {
        return {
          schema_version: "1",
          test_harness_id: request.test_harness_id,
          submission_id: request.submission_id,
          passed: false,
          total_tests: 0,
          passed_tests: 0,
          failed_tests: 0,
          test_results: [],
          execution_time_ms: 0,
          completed_at: new Date().toISOString(),
          error: `Invalid response from test harness service: ${parsed.error.message}`,
        };
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);

      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      return {
        schema_version: "1",
        test_harness_id: request.test_harness_id,
        submission_id: request.submission_id,
        passed: false,
        total_tests: 0,
        passed_tests: 0,
        failed_tests: 0,
        test_results: [],
        execution_time_ms: 0,
        completed_at: new Date().toISOString(),
        error: `Test harness service error: ${errorMessage}`,
      };
    }
  }
}

/**
 * Create a test harness client with the given configuration
 */
export function createTestHarnessClient(
  config: TestHarnessClientConfig
): TestHarnessService {
  return new TestHarnessClient(config);
}
