import { Bounty, AcceptanceReceipt, Submission, TestResult, BountySortField, SortDirection } from "./bounty.js";
import { QuorumState, ReviewerVote } from "./quorum.js";

/**
 * Search filter options for bounties
 */
export interface BountySearchFilters {
  tags?: string[];
  status?: string;
  closure_type?: string;
  min_reward?: number;
  max_reward?: number;
  currency?: string;
  requester_did?: string;
  is_code_bounty?: boolean;
}

/**
 * Search options including sort and pagination
 */
export interface BountySearchOptions {
  filters: BountySearchFilters;
  sort_by: BountySortField;
  sort_direction: SortDirection;
  page: number;
  page_size: number;
}

/**
 * Search result with bounties and count
 */
export interface BountySearchResult {
  bounties: Bounty[];
  total_count: number;
}

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
  // Search methods
  search(options: BountySearchOptions): Promise<BountySearchResult>;
}
