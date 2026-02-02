import { Bounty } from "../types/bounty.js";
import { BountyRepository } from "../types/repository.js";
import { STAKE_RULES } from "../types/stake.js";
import {
  ReviewerService,
  ReviewerInfo,
  QuorumState,
  ReviewerVote,
  InitiateQuorumRequest,
  InitiateQuorumRequestSchema,
  InitiateQuorumResponse,
  CastVoteRequest,
  CastVoteRequestSchema,
  CastVoteResponse,
  FinalizeQuorumRequest,
  FinalizeQuorumRequestSchema,
  FinalizeQuorumResponse,
  VoteDecision,
} from "../types/quorum.js";

/**
 * Generate a random UUID using crypto.randomUUID (available in modern runtimes)
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Error thrown when quorum review operations fail
 */
export class QuorumReviewError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "QuorumReviewError";
  }
}

/**
 * Agent context for quorum operations
 */
export interface QuorumAgentContext {
  /** DID of the agent/reviewer performing the action */
  did: string;
  /** Whether the agent is owner-verified */
  is_owner_verified?: boolean;
  /** Reference to owner attestation if owner-verified */
  owner_attestation_ref?: string;
}

/**
 * Dependencies required for quorum review operations
 */
export interface QuorumReviewDeps {
  bountyRepository: BountyRepository;
  reviewerService: ReviewerService;
  generateId?: () => string;
  now?: () => Date;
}

/**
 * Initiate quorum review for a submission
 *
 * This action:
 * 1. Validates the request
 * 2. Finds the submission and associated bounty
 * 3. Verifies the bounty uses quorum-based closure
 * 4. Selects reviewers by reputation
 * 5. Creates quorum state to track votes
 * 6. Returns the initiated quorum with selected reviewers
 *
 * @param request - The initiate quorum request with submission ID
 * @param deps - Dependencies (repository, reviewer service)
 * @returns The initiate quorum response with selected reviewers
 */
export async function initiateQuorum(
  request: InitiateQuorumRequest,
  deps: QuorumReviewDeps
): Promise<InitiateQuorumResponse> {
  const generateId = deps.generateId ?? generateUUID;
  const now = deps.now ?? (() => new Date());

  // Validate request
  const parseResult = InitiateQuorumRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new QuorumReviewError(
      "Invalid initiate quorum request",
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
    throw new QuorumReviewError(
      "Submission not found",
      "SUBMISSION_NOT_FOUND",
      { submission_id: validatedRequest.submission_id }
    );
  }

  // Find bounty
  const bounty = await deps.bountyRepository.findById(submission.bounty_id);
  if (!bounty) {
    throw new QuorumReviewError("Bounty not found", "BOUNTY_NOT_FOUND", {
      bounty_id: submission.bounty_id,
    });
  }

  // Verify bounty is in pending_review state
  if (bounty.status !== "pending_review") {
    throw new QuorumReviewError(
      `Cannot initiate quorum: bounty status is '${bounty.status}', expected 'pending_review'`,
      "BOUNTY_NOT_PENDING_REVIEW",
      { bounty_id: bounty.bounty_id, status: bounty.status }
    );
  }

  // Verify bounty uses quorum-based closure
  if (bounty.closure_type !== "quorum") {
    throw new QuorumReviewError(
      `Cannot initiate quorum: bounty closure type is '${bounty.closure_type}', expected 'quorum'`,
      "INVALID_CLOSURE_TYPE",
      { bounty_id: bounty.bounty_id, closure_type: bounty.closure_type }
    );
  }

  // Check if quorum already exists for this submission
  const existingQuorum = await deps.bountyRepository.findQuorumStateBySubmissionId(
    submission.submission_id
  );
  if (existingQuorum) {
    throw new QuorumReviewError(
      "Quorum already initiated for this submission",
      "QUORUM_ALREADY_EXISTS",
      { quorum_id: existingQuorum.quorum_id, submission_id: submission.submission_id }
    );
  }

  // Select reviewers by reputation
  // CBT-US-014: if owner-verified votes are required, we prefer owner-verified reviewers,
  // but allow a fallback to non-owner-verified reviewers (who must later stake more to vote).
  const requireOwnerVerifiedVotes = bounty.require_owner_verified_votes ?? false;
  const excludeDids = [bounty.requester_did, submission.agent_did];

  let selectedReviewers: ReviewerInfo[] = [];

  if (requireOwnerVerifiedVotes) {
    const verifiedResponse = await deps.reviewerService.selectReviewers({
      bounty_id: bounty.bounty_id,
      difficulty_scalar: bounty.difficulty_scalar,
      quorum_size: validatedRequest.quorum_size,
      require_owner_verified: true,
      exclude_dids: excludeDids,
      submission_proof_tier: submission.proof_tier,
    });

    if (verifiedResponse.reviewers.length >= validatedRequest.quorum_size) {
      selectedReviewers = verifiedResponse.reviewers.slice(0, validatedRequest.quorum_size);
    } else {
      const anyResponse = await deps.reviewerService.selectReviewers({
        bounty_id: bounty.bounty_id,
        difficulty_scalar: bounty.difficulty_scalar,
        quorum_size: validatedRequest.quorum_size,
        require_owner_verified: false,
        exclude_dids: excludeDids,
        submission_proof_tier: submission.proof_tier,
      });

      const seen = new Set<string>();
      const merged = [] as typeof anyResponse.reviewers;

      for (const r of verifiedResponse.reviewers) {
        if (merged.length >= validatedRequest.quorum_size) break;
        if (seen.has(r.reviewer_did)) continue;
        merged.push(r);
        seen.add(r.reviewer_did);
      }

      for (const r of anyResponse.reviewers) {
        if (merged.length >= validatedRequest.quorum_size) break;
        if (seen.has(r.reviewer_did)) continue;
        merged.push(r);
        seen.add(r.reviewer_did);
      }

      selectedReviewers = merged;
    }
  } else {
    const anyResponse = await deps.reviewerService.selectReviewers({
      bounty_id: bounty.bounty_id,
      difficulty_scalar: bounty.difficulty_scalar,
      quorum_size: validatedRequest.quorum_size,
      require_owner_verified: false,
      exclude_dids: excludeDids,
      submission_proof_tier: submission.proof_tier,
    });

    selectedReviewers = anyResponse.reviewers;
  }

  // Verify we got enough reviewers
  if (selectedReviewers.length < validatedRequest.quorum_size) {
    throw new QuorumReviewError(
      `Not enough eligible reviewers: got ${selectedReviewers.length}, need ${validatedRequest.quorum_size}`,
      "INSUFFICIENT_REVIEWERS",
      {
        available: selectedReviewers.length,
        required: validatedRequest.quorum_size,
      }
    );
  }

  const initiatedAt = now().toISOString();
  const quorumId = generateId();

  // Create quorum state
  const quorumState: QuorumState = {
    schema_version: "1",
    quorum_id: quorumId,
    submission_id: submission.submission_id,
    bounty_id: bounty.bounty_id,
    required_votes: validatedRequest.quorum_size,
    selected_reviewers: selectedReviewers,
    votes: [],
    quorum_reached: false,
    initiated_at: initiatedAt,
  };

  // Save quorum state
  await deps.bountyRepository.saveQuorumState(quorumState);

  return {
    schema_version: "1",
    quorum_id: quorumId,
    submission_id: submission.submission_id,
    bounty_id: bounty.bounty_id,
    required_votes: validatedRequest.quorum_size,
    selected_reviewers: selectedReviewers,
    initiated_at: initiatedAt,
  };
}

/**
 * Cast a vote in quorum review
 *
 * This action:
 * 1. Validates the request and signature envelope
 * 2. Verifies the reviewer is eligible to vote
 * 3. Records the signed vote
 * 4. Checks if quorum is reached
 * 5. If quorum reached, finalizes and releases payment
 *
 * @param request - The cast vote request with decision and signature
 * @param context - Agent context with reviewer DID
 * @param deps - Dependencies (repository, reviewer service)
 * @returns The cast vote response with current vote counts
 */
export async function castVote(
  request: CastVoteRequest,
  context: QuorumAgentContext,
  deps: QuorumReviewDeps
): Promise<CastVoteResponse> {
  const generateId = deps.generateId ?? generateUUID;
  const now = deps.now ?? (() => new Date());

  // Validate request
  const parseResult = CastVoteRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new QuorumReviewError(
      "Invalid cast vote request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  // Verify signature envelope signer matches context
  if (validatedRequest.signature_envelope.signer_did !== context.did) {
    throw new QuorumReviewError(
      "Signature signer DID does not match reviewer context",
      "SIGNER_MISMATCH",
      {
        signer_did: validatedRequest.signature_envelope.signer_did,
        context_did: context.did,
      }
    );
  }

  // Find quorum state for this submission
  const quorumState = await deps.bountyRepository.findQuorumStateBySubmissionId(
    validatedRequest.submission_id
  );
  if (!quorumState) {
    throw new QuorumReviewError(
      "Quorum not found for this submission",
      "QUORUM_NOT_FOUND",
      { submission_id: validatedRequest.submission_id }
    );
  }

  // Check if quorum is already reached
  if (quorumState.quorum_reached) {
    throw new QuorumReviewError(
      "Quorum has already been reached",
      "QUORUM_ALREADY_REACHED",
      { quorum_id: quorumState.quorum_id }
    );
  }

  // Verify reviewer is selected for this quorum
  const isSelectedReviewer = quorumState.selected_reviewers.some(
    (r) => r.reviewer_did === context.did
  );
  if (!isSelectedReviewer) {
    throw new QuorumReviewError(
      "Reviewer not selected for this quorum",
      "REVIEWER_NOT_SELECTED",
      { reviewer_did: context.did, quorum_id: quorumState.quorum_id }
    );
  }

  // Check if reviewer has already voted
  const existingVote = await deps.bountyRepository.findVoteByReviewerAndSubmission(
    context.did,
    validatedRequest.submission_id
  );
  if (existingVote) {
    throw new QuorumReviewError(
      "Reviewer has already voted on this submission",
      "ALREADY_VOTED",
      { vote_id: existingVote.vote_id }
    );
  }

  // Get bounty to check owner-verified requirement
  const bounty = await deps.bountyRepository.findById(quorumState.bounty_id);
  if (!bounty) {
    throw new QuorumReviewError("Bounty not found", "BOUNTY_NOT_FOUND", {
      bounty_id: quorumState.bounty_id,
    });
  }

  const selectedReviewer = quorumState.selected_reviewers.find(
    (r) => r.reviewer_did === context.did
  );
  if (!selectedReviewer) {
    // Should be impossible given earlier checks; fail closed.
    throw new QuorumReviewError(
      "Reviewer not selected for this quorum",
      "REVIEWER_NOT_SELECTED",
      { reviewer_did: context.did, quorum_id: quorumState.quorum_id }
    );
  }

  // CBT-US-014: owner-verified voting
  // - If require_owner_verified_votes is enabled, we allow non-owner-verified votes only
  //   when an explicit fallback stake is provided.
  // - Always record owner attestation reference when available.
  const requireOwnerVerifiedVotes = bounty.require_owner_verified_votes ?? false;

  // Fail closed on mismatched identity/attestation claims from the caller.
  if (
    context.is_owner_verified !== undefined &&
    context.is_owner_verified !== selectedReviewer.is_owner_verified
  ) {
    throw new QuorumReviewError(
      "Owner verification status does not match selected reviewer info",
      "OWNER_VERIFICATION_MISMATCH",
      {
        reviewer_did: context.did,
        context_is_owner_verified: context.is_owner_verified,
        selected_is_owner_verified: selectedReviewer.is_owner_verified,
      }
    );
  }

  if (
    context.owner_attestation_ref !== undefined &&
    context.owner_attestation_ref !== selectedReviewer.owner_attestation_ref
  ) {
    throw new QuorumReviewError(
      "Owner attestation reference does not match selected reviewer info",
      "OWNER_ATTESTATION_MISMATCH",
      {
        reviewer_did: context.did,
        context_owner_attestation_ref: context.owner_attestation_ref,
        selected_owner_attestation_ref: selectedReviewer.owner_attestation_ref,
      }
    );
  }

  const NON_VERIFIED_FALLBACK_STAKE_PERCENT = 10;
  const requiredFallbackStakeAmount = (): number => {
    const minimum = STAKE_RULES.minimums[bounty.reward.currency] ?? 0;
    const pct = (bounty.reward.amount * NON_VERIFIED_FALLBACK_STAKE_PERCENT) / 100;
    return Math.max(minimum, pct);
  };

  if (requireOwnerVerifiedVotes) {
    if (selectedReviewer.is_owner_verified) {
      // If the reviewer is owner-verified, require an attestation reference so it can be recorded.
      if (!selectedReviewer.owner_attestation_ref) {
        throw new QuorumReviewError(
          "Owner-verified votes require owner_attestation_ref",
          "OWNER_ATTESTATION_REQUIRED",
          { reviewer_did: context.did, bounty_id: bounty.bounty_id }
        );
      }
    } else {
      // Fallback: allow non-owner-verified vote only with sufficient stake.
      const stake = validatedRequest.fallback_stake;
      if (!stake) {
        throw new QuorumReviewError(
          "This bounty requires owner-verified reviewers (or a fallback stake for non-owner-verified votes)",
          "FALLBACK_STAKE_REQUIRED",
          { bounty_id: bounty.bounty_id, reviewer_did: context.did }
        );
      }

      if (stake.currency !== bounty.reward.currency) {
        throw new QuorumReviewError(
          "Fallback stake currency must match bounty reward currency",
          "FALLBACK_STAKE_CURRENCY_MISMATCH",
          {
            bounty_id: bounty.bounty_id,
            reviewer_did: context.did,
            stake_currency: stake.currency,
            reward_currency: bounty.reward.currency,
          }
        );
      }

      const required = requiredFallbackStakeAmount();
      if (stake.amount < required) {
        throw new QuorumReviewError(
          `Fallback stake is insufficient: got ${stake.amount}, need at least ${required}`,
          "FALLBACK_STAKE_INSUFFICIENT",
          {
            bounty_id: bounty.bounty_id,
            reviewer_did: context.did,
            stake_amount: stake.amount,
            required_stake_amount: required,
            stake_currency: stake.currency,
          }
        );
      }
    }
  }

  const votedAt = now().toISOString();
  const voteId = generateId();

  // Create vote record
  const vote: ReviewerVote = {
    schema_version: "1",
    vote_id: voteId,
    submission_id: validatedRequest.submission_id,
    bounty_id: quorumState.bounty_id,
    reviewer_did: context.did,
    decision: validatedRequest.decision,
    signature_envelope: validatedRequest.signature_envelope,
    comment: validatedRequest.comment,
    voted_at: votedAt,
    is_owner_verified: selectedReviewer.is_owner_verified,
    owner_attestation_ref: selectedReviewer.owner_attestation_ref,
    fallback_stake: selectedReviewer.is_owner_verified
      ? undefined
      : validatedRequest.fallback_stake,
  };

  // Save vote
  await deps.bountyRepository.saveVote(vote);

  // Update quorum state with new vote
  const updatedVotes = [...quorumState.votes, vote];
  const approveCount = updatedVotes.filter((v) => v.decision === "approve").length;
  const rejectCount = updatedVotes.filter((v) => v.decision === "reject").length;
  const totalCount = updatedVotes.length;

  // Check if quorum is reached (majority of required votes)
  const majorityThreshold = Math.ceil(quorumState.required_votes / 2);
  const quorumReached = approveCount >= majorityThreshold || rejectCount >= majorityThreshold;
  let finalDecision: VoteDecision | undefined;

  if (quorumReached) {
    finalDecision = approveCount >= majorityThreshold ? "approve" : "reject";
  }

  // Update quorum state
  const updatedQuorum: QuorumState = {
    ...quorumState,
    votes: updatedVotes,
    quorum_reached: quorumReached,
    final_decision: finalDecision,
    decided_at: quorumReached ? votedAt : undefined,
  };

  await deps.bountyRepository.saveQuorumState(updatedQuorum);

  // If quorum reached, update bounty status
  if (quorumReached && finalDecision) {
    const newBountyStatus = finalDecision === "approve" ? "approved" : "rejected";
    const updatedBounty: Bounty = {
      ...bounty,
      status: newBountyStatus,
    };
    await deps.bountyRepository.save(updatedBounty);
  }

  return {
    schema_version: "1",
    vote_id: voteId,
    submission_id: validatedRequest.submission_id,
    bounty_id: quorumState.bounty_id,
    decision: validatedRequest.decision,
    voted_at: votedAt,
    current_votes: {
      approve: approveCount,
      reject: rejectCount,
      total: totalCount,
    },
    quorum_reached: quorumReached,
    final_decision: finalDecision,
  };
}

/**
 * Finalize quorum review and release payment
 *
 * This action is called when quorum is reached to finalize the decision
 * and trigger escrow release if approved.
 *
 * @param request - The finalize quorum request with quorum ID
 * @param deps - Dependencies (repository)
 * @returns The finalize quorum response with final decision
 */
export async function finalizeQuorum(
  request: FinalizeQuorumRequest,
  deps: QuorumReviewDeps
): Promise<FinalizeQuorumResponse> {
  const now = deps.now ?? (() => new Date());

  // Validate request
  const parseResult = FinalizeQuorumRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new QuorumReviewError(
      "Invalid finalize quorum request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  // Find quorum state
  const quorumState = await deps.bountyRepository.findQuorumStateById(
    validatedRequest.quorum_id
  );
  if (!quorumState) {
    throw new QuorumReviewError("Quorum not found", "QUORUM_NOT_FOUND", {
      quorum_id: validatedRequest.quorum_id,
    });
  }

  // Verify quorum has been reached
  if (!quorumState.quorum_reached || !quorumState.final_decision) {
    throw new QuorumReviewError(
      "Quorum has not been reached yet",
      "QUORUM_NOT_REACHED",
      { quorum_id: quorumState.quorum_id, votes: quorumState.votes.length }
    );
  }

  // Get bounty
  const bounty = await deps.bountyRepository.findById(quorumState.bounty_id);
  if (!bounty) {
    throw new QuorumReviewError("Bounty not found", "BOUNTY_NOT_FOUND", {
      bounty_id: quorumState.bounty_id,
    });
  }

  // Calculate vote counts
  const approveCount = quorumState.votes.filter((v) => v.decision === "approve").length;
  const rejectCount = quorumState.votes.filter((v) => v.decision === "reject").length;

  const decidedAt = quorumState.decided_at ?? now().toISOString();

  return {
    schema_version: "1",
    quorum_id: quorumState.quorum_id,
    submission_id: quorumState.submission_id,
    bounty_id: quorumState.bounty_id,
    final_decision: quorumState.final_decision,
    bounty_status: quorumState.final_decision === "approve" ? "approved" : "rejected",
    vote_counts: {
      approve: approveCount,
      reject: rejectCount,
      total: quorumState.votes.length,
    },
    decided_at: decidedAt,
  };
}
