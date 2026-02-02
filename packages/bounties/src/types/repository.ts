import { Bounty, AcceptanceReceipt, Submission, TestResult } from "./bounty.js";
import { QuorumState, ReviewerVote } from "./quorum.js";

/**
 * Repository interface for bounty persistence
 */
export interface BountyRepository {
  save(bounty: Bounty): Promise<void>;
  findById(bountyId: string): Promise<Bounty | null>;
  findByIdempotencyKey(key: string): Promise<Bounty | null>;
  findAcceptanceByIdempotencyKey(key: string): Promise<AcceptanceReceipt | null>;
  saveAcceptance(receipt: AcceptanceReceipt): Promise<void>;
  findSubmissionByIdempotencyKey(key: string): Promise<Submission | null>;
  findSubmissionById(submissionId: string): Promise<Submission | null>;
  saveSubmission(submission: Submission): Promise<void>;
  saveTestResult(testResult: TestResult): Promise<void>;
  // Quorum review methods
  saveQuorumState(quorumState: QuorumState): Promise<void>;
  findQuorumStateById(quorumId: string): Promise<QuorumState | null>;
  findQuorumStateBySubmissionId(submissionId: string): Promise<QuorumState | null>;
  saveVote(vote: ReviewerVote): Promise<void>;
  findVoteByReviewerAndSubmission(reviewerDid: string, submissionId: string): Promise<ReviewerVote | null>;
}
