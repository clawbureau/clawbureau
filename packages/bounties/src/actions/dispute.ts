import { Bounty } from "../types/bounty.js";
import { BountyRepository } from "../types/repository.js";
import { EscrowService } from "../types/escrow.js";
import {
  Dispute,
  TrialsService,
  OpenDisputeRequest,
  OpenDisputeRequestSchema,
  OpenDisputeResponse,
  RouteToTrialsRequest,
  RouteToTrialsRequestSchema,
  RouteToTrialsResponse,
  FreezePayoutRequest,
  FreezePayoutRequestSchema,
  FreezePayoutResponse,
} from "../types/dispute.js";

/**
 * Generate a random UUID using crypto.randomUUID (available in modern runtimes)
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Error thrown when dispute operations fail
 */
export class DisputeError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "DisputeError";
  }
}

/**
 * Agent context for dispute operations
 */
export interface DisputeAgentContext {
  /** DID of the agent performing the action */
  did: string;
}

/**
 * Dependencies required for dispute operations
 */
export interface DisputeDeps {
  bountyRepository: BountyRepository;
  escrowService: EscrowService;
  trialsService: TrialsService;
  generateId?: () => string;
  now?: () => Date;
}

/**
 * Open a dispute for a rejected bounty
 *
 * This action:
 * 1. Validates the request and signature envelope
 * 2. Verifies the bounty is in rejected status
 * 3. Verifies the disputer is the agent who submitted the work
 * 4. Creates the dispute record
 * 5. Freezes the escrow payout
 * 6. Updates bounty status to disputed
 *
 * @param request - The open dispute request with reason and signature
 * @param context - Agent context with disputer DID
 * @param deps - Dependencies (repository, escrow service)
 * @returns The open dispute response
 */
export async function openDispute(
  request: OpenDisputeRequest,
  context: DisputeAgentContext,
  deps: DisputeDeps
): Promise<OpenDisputeResponse> {
  const generateId = deps.generateId ?? generateUUID;
  const now = deps.now ?? (() => new Date());

  // Validate request
  const parseResult = OpenDisputeRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new DisputeError(
      "Invalid open dispute request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  // Verify signature envelope signer matches context
  if (validatedRequest.signature_envelope.signer_did !== context.did) {
    throw new DisputeError(
      "Signature signer DID does not match agent context",
      "SIGNER_MISMATCH",
      {
        signer_did: validatedRequest.signature_envelope.signer_did,
        context_did: context.did,
      }
    );
  }

  // Check for idempotency
  if (validatedRequest.idempotency_key) {
    const existingDispute = await deps.bountyRepository.findDisputeByIdempotencyKey(
      validatedRequest.idempotency_key
    );
    if (existingDispute) {
      return {
        schema_version: "1",
        dispute_id: existingDispute.dispute_id,
        bounty_id: existingDispute.bounty_id,
        submission_id: existingDispute.submission_id,
        status: "open",
        payout_frozen: true,
        opened_at: existingDispute.opened_at,
      };
    }
  }

  // Find the bounty
  const bounty = await deps.bountyRepository.findById(validatedRequest.bounty_id);
  if (!bounty) {
    throw new DisputeError("Bounty not found", "BOUNTY_NOT_FOUND", {
      bounty_id: validatedRequest.bounty_id,
    });
  }

  // Verify bounty is in rejected status
  if (bounty.status !== "rejected") {
    throw new DisputeError(
      `Cannot open dispute: bounty status is '${bounty.status}', expected 'rejected'`,
      "BOUNTY_NOT_REJECTED",
      { bounty_id: bounty.bounty_id, status: bounty.status }
    );
  }

  // Find the submission
  const submission = await deps.bountyRepository.findSubmissionById(
    validatedRequest.submission_id
  );
  if (!submission) {
    throw new DisputeError("Submission not found", "SUBMISSION_NOT_FOUND", {
      submission_id: validatedRequest.submission_id,
    });
  }

  // Verify submission belongs to the bounty
  if (submission.bounty_id !== bounty.bounty_id) {
    throw new DisputeError(
      "Submission does not belong to this bounty",
      "SUBMISSION_BOUNTY_MISMATCH",
      { submission_id: submission.submission_id, bounty_id: bounty.bounty_id }
    );
  }

  // Verify disputer is the agent who submitted the work
  if (submission.agent_did !== context.did) {
    throw new DisputeError(
      "Only the agent who submitted the work can open a dispute",
      "UNAUTHORIZED_DISPUTER",
      { agent_did: submission.agent_did, disputer_did: context.did }
    );
  }

  // Check if dispute already exists for this submission
  const existingDisputeForSubmission = await deps.bountyRepository.findDisputeBySubmissionId(
    submission.submission_id
  );
  if (existingDisputeForSubmission) {
    throw new DisputeError(
      "A dispute already exists for this submission",
      "DISPUTE_ALREADY_EXISTS",
      { dispute_id: existingDisputeForSubmission.dispute_id }
    );
  }

  const openedAt = now().toISOString();
  const disputeId = generateId();

  // Create dispute record
  const dispute: Dispute = {
    schema_version: "1",
    dispute_id: disputeId,
    bounty_id: bounty.bounty_id,
    submission_id: submission.submission_id,
    disputer_did: context.did,
    reason: validatedRequest.reason,
    explanation: validatedRequest.explanation,
    signature_envelope: validatedRequest.signature_envelope,
    status: "open",
    opened_at: openedAt,
    idempotency_key: validatedRequest.idempotency_key,
  };

  // Freeze the escrow payout
  const freezeResponse = await deps.escrowService.freezeHold({
    schema_version: "1",
    escrow_id: bounty.escrow_id,
    dispute_id: disputeId,
    reason: `Dispute opened: ${validatedRequest.reason}`,
  });

  if (!freezeResponse.frozen) {
    throw new DisputeError(
      "Failed to freeze escrow payout",
      "ESCROW_FREEZE_FAILED",
      { error: freezeResponse.error }
    );
  }

  // Save dispute
  await deps.bountyRepository.saveDispute(dispute);

  // Update bounty status to disputed
  const updatedBounty: Bounty = {
    ...bounty,
    status: "disputed",
  };
  await deps.bountyRepository.save(updatedBounty);

  return {
    schema_version: "1",
    dispute_id: disputeId,
    bounty_id: bounty.bounty_id,
    submission_id: submission.submission_id,
    status: "open",
    payout_frozen: true,
    opened_at: openedAt,
  };
}

/**
 * Route a dispute to the trials service
 *
 * This action:
 * 1. Validates the dispute exists and is in open status
 * 2. Creates a trial case via the trials service
 * 3. Updates the dispute status to routed_to_trials
 *
 * @param request - The route to trials request with dispute ID
 * @param deps - Dependencies (repository, trials service)
 * @returns The route to trials response
 */
export async function routeToTrials(
  request: RouteToTrialsRequest,
  deps: DisputeDeps
): Promise<RouteToTrialsResponse> {
  const now = deps.now ?? (() => new Date());

  // Validate request
  const parseResult = RouteToTrialsRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new DisputeError(
      "Invalid route to trials request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  // Find the dispute
  const dispute = await deps.bountyRepository.findDisputeById(validatedRequest.dispute_id);
  if (!dispute) {
    throw new DisputeError("Dispute not found", "DISPUTE_NOT_FOUND", {
      dispute_id: validatedRequest.dispute_id,
    });
  }

  // Verify dispute is in open status
  if (dispute.status !== "open") {
    throw new DisputeError(
      `Cannot route to trials: dispute status is '${dispute.status}', expected 'open'`,
      "DISPUTE_NOT_OPEN",
      { dispute_id: dispute.dispute_id, status: dispute.status }
    );
  }

  // Find the bounty to get requester DID
  const bounty = await deps.bountyRepository.findById(dispute.bounty_id);
  if (!bounty) {
    throw new DisputeError("Bounty not found", "BOUNTY_NOT_FOUND", {
      bounty_id: dispute.bounty_id,
    });
  }

  // Create trial case
  const trialResponse = await deps.trialsService.createCase({
    dispute_id: dispute.dispute_id,
    bounty_id: dispute.bounty_id,
    submission_id: dispute.submission_id,
    disputer_did: dispute.disputer_did,
    requester_did: bounty.requester_did,
    reason: dispute.reason,
    explanation: dispute.explanation,
  });

  const routedAt = now().toISOString();

  // Update dispute status
  const updatedDispute: Dispute = {
    ...dispute,
    status: "routed_to_trials",
    trial_case_id: trialResponse.trial_case_id,
    routed_at: routedAt,
  };

  await deps.bountyRepository.saveDispute(updatedDispute);

  return {
    schema_version: "1",
    dispute_id: dispute.dispute_id,
    trial_case_id: trialResponse.trial_case_id,
    status: "routed_to_trials",
    routed_at: routedAt,
  };
}

/**
 * Freeze payout for a bounty (used when opening disputes)
 *
 * This action freezes the escrow payout for a bounty, preventing
 * any release of funds until the dispute is resolved.
 *
 * @param request - The freeze payout request with bounty and dispute IDs
 * @param deps - Dependencies (repository, escrow service)
 * @returns The freeze payout response
 */
export async function freezePayout(
  request: FreezePayoutRequest,
  deps: DisputeDeps
): Promise<FreezePayoutResponse> {
  // Validate request
  const parseResult = FreezePayoutRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new DisputeError(
      "Invalid freeze payout request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  // Find the bounty
  const bounty = await deps.bountyRepository.findById(validatedRequest.bounty_id);
  if (!bounty) {
    throw new DisputeError("Bounty not found", "BOUNTY_NOT_FOUND", {
      bounty_id: validatedRequest.bounty_id,
    });
  }

  // Find the dispute
  const dispute = await deps.bountyRepository.findDisputeById(validatedRequest.dispute_id);
  if (!dispute) {
    throw new DisputeError("Dispute not found", "DISPUTE_NOT_FOUND", {
      dispute_id: validatedRequest.dispute_id,
    });
  }

  // Verify dispute is for this bounty
  if (dispute.bounty_id !== bounty.bounty_id) {
    throw new DisputeError(
      "Dispute does not belong to this bounty",
      "DISPUTE_BOUNTY_MISMATCH",
      { dispute_id: dispute.dispute_id, bounty_id: bounty.bounty_id }
    );
  }

  // Freeze the escrow payout
  const freezeResponse = await deps.escrowService.freezeHold({
    schema_version: "1",
    escrow_id: bounty.escrow_id,
    dispute_id: dispute.dispute_id,
    reason: `Dispute: ${dispute.reason}`,
  });

  if (!freezeResponse.frozen) {
    throw new DisputeError(
      "Failed to freeze escrow payout",
      "ESCROW_FREEZE_FAILED",
      { error: freezeResponse.error }
    );
  }

  return {
    schema_version: "1",
    bounty_id: bounty.bounty_id,
    escrow_id: bounty.escrow_id,
    dispute_id: dispute.dispute_id,
    frozen: true,
    frozen_at: freezeResponse.frozen_at,
  };
}
