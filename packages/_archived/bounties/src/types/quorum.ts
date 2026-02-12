import { z } from "zod";
import { ProofTierSchema, SignatureEnvelopeSchema } from "./bounty.js";

/**
 * Vote decision for quorum review
 */
export const VoteDecisionSchema = z.enum(["approve", "reject"]);

export type VoteDecision = z.infer<typeof VoteDecisionSchema>;

/**
 * Optional stake required for non-owner-verified vote fallback (CBT-US-014)
 */
export const VoteFallbackStakeSchema = z.object({
  amount: z.number().positive(),
  currency: z.enum(["CLAW", "USD"]),
});

export type VoteFallbackStake = z.infer<typeof VoteFallbackStakeSchema>;

/**
 * A signed vote from a reviewer
 */
export const ReviewerVoteSchema = z.object({
  schema_version: z.literal("1"),
  vote_id: z.string(),
  submission_id: z.string(),
  bounty_id: z.string(),
  /** DID of the reviewer casting the vote */
  reviewer_did: z.string(),
  /** The vote decision (approve or reject) */
  decision: VoteDecisionSchema,
  /** DID-signed envelope proving reviewer created this vote */
  signature_envelope: SignatureEnvelopeSchema,
  /** Optional comment explaining the vote */
  comment: z.string().max(1000).optional(),
  /** ISO timestamp when vote was cast */
  voted_at: z.string().datetime(),
  /** Whether the reviewer is owner-verified */
  is_owner_verified: z.boolean().optional(),
  /** Reference to owner attestation if owner-verified */
  owner_attestation_ref: z.string().optional(),
  /** Optional stake required when casting a non-owner-verified fallback vote */
  fallback_stake: VoteFallbackStakeSchema.optional(),
});

export type ReviewerVote = z.infer<typeof ReviewerVoteSchema>;

/**
 * Request to select reviewers by reputation
 */
export const SelectReviewersRequestSchema = z.object({
  bounty_id: z.string(),
  /** Difficulty scalar (K) for weighting/transparent scoring */
  difficulty_scalar: z.number().min(0.1).max(10.0),
  /** Number of reviewers needed for quorum */
  quorum_size: z.number().int().min(1).max(10),
  /** Minimum reputation score required for reviewers */
  min_reputation_score: z.number().min(0).optional(),
  /** Whether to require owner-verified reviewers */
  require_owner_verified: z.boolean().default(false),
  /** DIDs to exclude from selection (e.g., requester, worker) */
  exclude_dids: z.array(z.string()).optional(),
  /** Proof tier of the submission; can be used by clawrep to weight selection/scoring */
  submission_proof_tier: ProofTierSchema.optional(),
});

export type SelectReviewersRequest = z.infer<typeof SelectReviewersRequestSchema>;

/**
 * Reviewer info returned from reputation service
 */
export const ReviewerInfoSchema = z.object({
  reviewer_did: z.string(),
  reputation_score: z.number(),
  is_owner_verified: z.boolean(),
  owner_attestation_ref: z.string().optional(),
});

export type ReviewerInfo = z.infer<typeof ReviewerInfoSchema>;

/**
 * Response from reviewer selection
 */
export const SelectReviewersResponseSchema = z.object({
  bounty_id: z.string(),
  reviewers: z.array(ReviewerInfoSchema),
  selected_at: z.string().datetime(),
});

export type SelectReviewersResponse = z.infer<typeof SelectReviewersResponseSchema>;

/**
 * Interface for the reviewer service (clawrep)
 */
export interface ReviewerService {
  selectReviewers(request: SelectReviewersRequest): Promise<SelectReviewersResponse>;
  getReviewerInfo(reviewerDid: string): Promise<ReviewerInfo | null>;
}

/**
 * Quorum state tracking
 */
export const QuorumStateSchema = z.object({
  schema_version: z.literal("1"),
  quorum_id: z.string(),
  submission_id: z.string(),
  bounty_id: z.string(),
  /** Required number of votes to reach quorum */
  required_votes: z.number().int().min(1),
  /** Selected reviewers */
  selected_reviewers: z.array(ReviewerInfoSchema),
  /** Collected votes */
  votes: z.array(ReviewerVoteSchema),
  /** Whether quorum has been reached */
  quorum_reached: z.boolean(),
  /** Final decision once quorum is reached */
  final_decision: VoteDecisionSchema.optional(),
  /** ISO timestamp when quorum was initiated */
  initiated_at: z.string().datetime(),
  /** ISO timestamp when quorum was reached (if reached) */
  decided_at: z.string().datetime().optional(),
});

export type QuorumState = z.infer<typeof QuorumStateSchema>;

/**
 * Request to cast a vote in quorum review
 */
export const CastVoteRequestSchema = z.object({
  submission_id: z.string(),
  decision: VoteDecisionSchema,
  signature_envelope: SignatureEnvelopeSchema,
  comment: z.string().max(1000).optional(),
  /** Optional stake used to allow non-owner-verified voting fallback */
  fallback_stake: VoteFallbackStakeSchema.optional(),
});

export type CastVoteRequest = z.infer<typeof CastVoteRequestSchema>;

/**
 * Response after casting a vote
 */
export const CastVoteResponseSchema = z.object({
  schema_version: z.literal("1"),
  vote_id: z.string(),
  submission_id: z.string(),
  bounty_id: z.string(),
  decision: VoteDecisionSchema,
  voted_at: z.string().datetime(),
  /** Current vote counts */
  current_votes: z.object({
    approve: z.number().int().nonnegative(),
    reject: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
  }),
  /** Whether this vote caused quorum to be reached */
  quorum_reached: z.boolean(),
  /** Final decision if quorum was reached */
  final_decision: VoteDecisionSchema.optional(),
});

export type CastVoteResponse = z.infer<typeof CastVoteResponseSchema>;

/**
 * Request to initiate quorum review
 */
export const InitiateQuorumRequestSchema = z.object({
  submission_id: z.string(),
  /** Number of votes required for quorum (defaults to 3) */
  quorum_size: z.number().int().min(1).max(10).default(3),
});

export type InitiateQuorumRequest = z.infer<typeof InitiateQuorumRequestSchema>;

/**
 * Response after initiating quorum review
 */
export const InitiateQuorumResponseSchema = z.object({
  schema_version: z.literal("1"),
  quorum_id: z.string(),
  submission_id: z.string(),
  bounty_id: z.string(),
  required_votes: z.number().int().min(1),
  selected_reviewers: z.array(ReviewerInfoSchema),
  initiated_at: z.string().datetime(),
});

export type InitiateQuorumResponse = z.infer<typeof InitiateQuorumResponseSchema>;

/**
 * Request to finalize quorum when threshold is reached
 */
export const FinalizeQuorumRequestSchema = z.object({
  quorum_id: z.string(),
});

export type FinalizeQuorumRequest = z.infer<typeof FinalizeQuorumRequestSchema>;

/**
 * Response after finalizing quorum
 */
export const FinalizeQuorumResponseSchema = z.object({
  schema_version: z.literal("1"),
  quorum_id: z.string(),
  submission_id: z.string(),
  bounty_id: z.string(),
  /** Final decision (approve or reject) */
  final_decision: VoteDecisionSchema,
  /** Resulting bounty status */
  bounty_status: z.enum(["approved", "rejected"]),
  /** Vote counts */
  vote_counts: z.object({
    approve: z.number().int().nonnegative(),
    reject: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
  }),
  /** ISO timestamp when quorum was finalized */
  decided_at: z.string().datetime(),
});

export type FinalizeQuorumResponse = z.infer<typeof FinalizeQuorumResponseSchema>;
