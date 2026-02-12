import {
  Bounty,
  TestResult,
  AutoApproveRequest,
  AutoApproveRequestSchema,
  AutoApproveResponse,
} from "../types/bounty.js";
import { BountyRepository } from "../types/repository.js";
import { TestHarnessService, RunTestHarnessRequest } from "../types/testHarness.js";

/**
 * Generate a random UUID using crypto.randomUUID (available in modern runtimes)
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Error thrown when auto-approval fails
 */
export class AutoApproveError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "AutoApproveError";
  }
}

/**
 * Dependencies required for auto-approval
 */
export interface AutoApproveDeps {
  bountyRepository: BountyRepository;
  testHarnessService: TestHarnessService;
  generateId?: () => string;
  now?: () => Date;
}

/**
 * Auto-approve a submission based on test results
 *
 * This action:
 * 1. Validates the request
 * 2. Finds the submission and associated bounty
 * 3. Verifies the bounty uses test-based closure
 * 4. Runs the test harness against the submission
 * 5. Approves if tests pass, rejects if tests fail
 * 6. Stores the test result and updates bounty status
 * 7. Returns the approval/rejection decision
 *
 * @param request - The auto-approve request with submission ID
 * @param deps - Dependencies (repository, test harness service)
 * @returns The auto-approve response with decision and test results
 */
export async function autoApprove(
  request: AutoApproveRequest,
  deps: AutoApproveDeps
): Promise<AutoApproveResponse> {
  const generateId = deps.generateId ?? generateUUID;
  const now = deps.now ?? (() => new Date());

  // Validate request
  const parseResult = AutoApproveRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new AutoApproveError(
      "Invalid auto-approve request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  // Find submission
  const submission = await deps.bountyRepository.findSubmissionById(
    validatedRequest.submission_id
  );
  if (!submission) {
    throw new AutoApproveError(
      "Submission not found",
      "SUBMISSION_NOT_FOUND",
      { submission_id: validatedRequest.submission_id }
    );
  }

  // Find bounty
  const bounty = await deps.bountyRepository.findById(submission.bounty_id);
  if (!bounty) {
    throw new AutoApproveError(
      "Bounty not found",
      "BOUNTY_NOT_FOUND",
      { bounty_id: submission.bounty_id }
    );
  }

  // Verify bounty is in pending_review state
  if (bounty.status !== "pending_review") {
    throw new AutoApproveError(
      `Cannot auto-approve: bounty status is '${bounty.status}', expected 'pending_review'`,
      "BOUNTY_NOT_PENDING_REVIEW",
      { bounty_id: bounty.bounty_id, status: bounty.status }
    );
  }

  // Verify bounty uses test-based closure
  if (bounty.closure_type !== "test") {
    throw new AutoApproveError(
      `Cannot auto-approve: bounty closure type is '${bounty.closure_type}', expected 'test'`,
      "INVALID_CLOSURE_TYPE",
      { bounty_id: bounty.bounty_id, closure_type: bounty.closure_type }
    );
  }

  // Verify test harness is configured
  if (!bounty.test_harness_id) {
    throw new AutoApproveError(
      "Cannot auto-approve: bounty has no test harness configured",
      "NO_TEST_HARNESS",
      { bounty_id: bounty.bounty_id }
    );
  }

  // Build test harness request
  const testRequest: RunTestHarnessRequest = {
    schema_version: "1",
    test_harness_id: bounty.test_harness_id,
    submission_id: submission.submission_id,
    bounty_id: bounty.bounty_id,
    output: submission.output,
    proof_bundle_hash: submission.proof_bundle.hash,
    timeout_ms: 60000, // 1 minute default
  };

  // Run test harness
  const testResponse = await deps.testHarnessService.runTests(testRequest);

  // Determine result status
  const decidedAt = now().toISOString();
  const newStatus = testResponse.passed ? "approved" : "rejected";

  // Build test result record
  const testResult: TestResult = {
    schema_version: "1",
    test_result_id: generateId(),
    submission_id: submission.submission_id,
    bounty_id: bounty.bounty_id,
    test_harness_id: bounty.test_harness_id,
    passed: testResponse.passed,
    total_tests: testResponse.total_tests,
    passed_tests: testResponse.passed_tests,
    failed_tests: testResponse.failed_tests,
    execution_time_ms: testResponse.execution_time_ms,
    completed_at: testResponse.completed_at,
    error: testResponse.error,
  };

  // Update bounty status
  const updatedBounty: Bounty = {
    ...bounty,
    status: newStatus,
  };

  // Save test result and update bounty
  await deps.bountyRepository.saveTestResult(testResult);
  await deps.bountyRepository.save(updatedBounty);

  // Return response
  return {
    schema_version: "1",
    submission_id: submission.submission_id,
    bounty_id: bounty.bounty_id,
    status: newStatus,
    tests_passed: testResponse.passed,
    test_result: {
      total_tests: testResponse.total_tests,
      passed_tests: testResponse.passed_tests,
      failed_tests: testResponse.failed_tests,
      execution_time_ms: testResponse.execution_time_ms,
    },
    decided_at: decidedAt,
    error: testResponse.error,
  };
}
