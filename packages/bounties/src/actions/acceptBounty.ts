import {
  AcceptBountyRequest,
  AcceptBountyRequestSchema,
  AcceptBountyResponse,
  AcceptanceReceipt,
  Bounty,
} from "../types/bounty.js";
import { EligibilityService } from "../types/eligibility.js";
import { BountyRepository } from "../types/repository.js";

/**
 * Generate a random UUID using crypto.randomUUID (available in modern runtimes)
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Error thrown when bounty acceptance fails
 */
export class AcceptBountyError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "AcceptBountyError";
  }
}

/**
 * Dependencies required for accepting a bounty
 */
export interface AcceptBountyDeps {
  eligibilityService: EligibilityService;
  bountyRepository: BountyRepository;
  generateId?: () => string;
  now?: () => Date;
}

/**
 * Context for the accept bounty operation
 */
export interface AcceptBountyContext {
  agentDid: string;
}

/**
 * Accept a bounty
 *
 * This action:
 * 1. Validates the request
 * 2. Checks idempotency
 * 3. Finds the bounty and verifies it's open
 * 4. Checks agent eligibility (PoH tier) via clawtrust
 * 5. Reserves the slot by updating bounty status to "accepted"
 * 6. Returns an acceptance receipt
 *
 * @param request - The accept bounty request
 * @param context - Operation context including agent DID
 * @param deps - Dependencies (eligibility service, repository)
 * @returns The accept bounty response with acceptance receipt
 */
export async function acceptBounty(
  request: AcceptBountyRequest,
  context: AcceptBountyContext,
  deps: AcceptBountyDeps
): Promise<AcceptBountyResponse> {
  const generateId = deps.generateId ?? generateUUID;
  const now = deps.now ?? (() => new Date());

  // Validate request
  const parseResult = AcceptBountyRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new AcceptBountyError(
      "Invalid accept bounty request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  // Check idempotency - return existing acceptance if already processed
  if (validatedRequest.idempotency_key) {
    const existingReceipt = await deps.bountyRepository.findAcceptanceByIdempotencyKey(
      validatedRequest.idempotency_key
    );
    if (existingReceipt) {
      return {
        schema_version: "1",
        bounty_id: existingReceipt.bounty_id,
        status: "accepted",
        accepted_at: existingReceipt.accepted_at,
        receipt: existingReceipt,
      };
    }
  }

  // Find bounty
  const bounty = await deps.bountyRepository.findById(validatedRequest.bounty_id);
  if (!bounty) {
    throw new AcceptBountyError(
      "Bounty not found",
      "BOUNTY_NOT_FOUND",
      { bounty_id: validatedRequest.bounty_id }
    );
  }

  // Verify bounty is open
  if (bounty.status !== "open") {
    throw new AcceptBountyError(
      `Bounty cannot be accepted: current status is '${bounty.status}'`,
      "BOUNTY_NOT_OPEN",
      { bounty_id: bounty.bounty_id, status: bounty.status }
    );
  }

  // Check eligibility via clawtrust
  const requiredPoHTier = bounty.min_poh_tier ?? 0;
  const eligibilityResponse = await deps.eligibilityService.checkEligibility({
    agent_did: context.agentDid,
    required_poh_tier: requiredPoHTier,
  });

  if (!eligibilityResponse.is_eligible) {
    throw new AcceptBountyError(
      `Agent does not meet eligibility requirements: required PoH tier ${requiredPoHTier}, agent has tier ${eligibilityResponse.current_poh_tier}`,
      "ELIGIBILITY_FAILED",
      {
        agent_did: context.agentDid,
        required_poh_tier: requiredPoHTier,
        current_poh_tier: eligibilityResponse.current_poh_tier,
      }
    );
  }

  // Generate receipt ID and timestamp
  const receiptId = generateId();
  const acceptedAt = now().toISOString();

  // Build acceptance receipt
  const receipt: AcceptanceReceipt = {
    schema_version: "1",
    receipt_id: receiptId,
    bounty_id: bounty.bounty_id,
    agent_did: context.agentDid,
    accepted_at: acceptedAt,
    bounty_title: bounty.title,
    reward: bounty.reward,
    difficulty_scalar: bounty.difficulty_scalar,
    closure_type: bounty.closure_type,
  };

  // Reserve slot: update bounty status to accepted
  const updatedBounty: Bounty = {
    ...bounty,
    status: "accepted",
    accepted_at: acceptedAt,
    accepted_by: context.agentDid,
  };

  await deps.bountyRepository.save(updatedBounty);
  await deps.bountyRepository.saveAcceptance(receipt);

  // Return response with receipt
  return {
    schema_version: "1",
    bounty_id: bounty.bounty_id,
    status: "accepted",
    accepted_at: acceptedAt,
    receipt,
  };
}
