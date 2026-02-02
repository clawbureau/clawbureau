import {
  PostBountyRequest,
  PostBountyRequestSchema,
  PostBountyResponse,
  Bounty,
  AllInCost,
} from "../types/bounty.js";
import { EscrowService, EscrowHoldRequest } from "../types/escrow.js";
import { FeeService } from "../types/fees.js";
import { BountyRepository } from "../types/repository.js";

/**
 * Generate a random UUID using crypto.randomUUID (available in modern runtimes)
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Error thrown when bounty posting fails
 */
export class PostBountyError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "PostBountyError";
  }
}

/**
 * Dependencies required for posting a bounty
 */
export interface PostBountyDeps {
  escrowService: EscrowService;
  feeService: FeeService;
  bountyRepository: BountyRepository;
  generateId?: () => string;
  now?: () => Date;
}

/**
 * Context for the post bounty operation
 */
export interface PostBountyContext {
  requesterDid: string;
}

/**
 * Post a new bounty
 *
 * This action:
 * 1. Validates the request
 * 2. Calculates fees via clawcuts
 * 3. Creates an escrow hold via clawescrow
 * 4. Persists the bounty record
 *
 * @param request - The post bounty request
 * @param context - Operation context including requester DID
 * @param deps - Dependencies (escrow, fees, repository)
 * @returns The post bounty response with bounty_id and escrow details
 */
export async function postBounty(
  request: PostBountyRequest,
  context: PostBountyContext,
  deps: PostBountyDeps
): Promise<PostBountyResponse> {
  const generateId = deps.generateId ?? generateUUID;
  const now = deps.now ?? (() => new Date());

  // Validate request
  const parseResult = PostBountyRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new PostBountyError(
      "Invalid post bounty request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  // Check idempotency
  if (validatedRequest.idempotency_key) {
    const existing = await deps.bountyRepository.findByIdempotencyKey(
      validatedRequest.idempotency_key
    );
    if (existing) {
      // Return existing bounty for idempotent request
      return {
        schema_version: "1",
        bounty_id: existing.bounty_id,
        escrow_id: existing.escrow_id,
        status: "open",
        all_in_cost: existing.all_in_cost as AllInCost,
        fee_policy_version: existing.fee_policy_version,
        created_at: existing.created_at,
      };
    }
  }

  // Calculate fees via clawcuts
  const feeResponse = await deps.feeService.calculateFees({
    principal: validatedRequest.reward.amount,
    currency: validatedRequest.reward.currency,
    transaction_type: "bounty_post",
  });

  const allInCost: AllInCost = {
    principal: feeResponse.principal,
    platform_fee: feeResponse.platform_fee,
    total: feeResponse.total,
    currency: feeResponse.currency,
  };

  // Generate IDs
  const bountyId = generateId();
  const idempotencyKey = validatedRequest.idempotency_key ?? generateId();
  const createdAt = now().toISOString();

  // Create escrow hold via clawescrow
  const escrowRequest: EscrowHoldRequest = {
    schema_version: "1",
    requester_did: context.requesterDid,
    amount: allInCost.total,
    currency: allInCost.currency,
    bounty_id: bountyId,
    idempotency_key: `escrow:${idempotencyKey}`,
    metadata: {
      closure_type: validatedRequest.closure_type,
      difficulty_scalar: validatedRequest.difficulty_scalar,
      fee_policy_version: feeResponse.fee_policy_version,
    },
  };

  const escrowResponse = await deps.escrowService.createHold(escrowRequest);

  if (escrowResponse.status === "failed") {
    throw new PostBountyError(
      escrowResponse.error ?? "Failed to create escrow hold",
      "ESCROW_FAILED",
      { escrow_response: escrowResponse }
    );
  }

  // Build and persist bounty record
  const bounty: Bounty = {
    schema_version: "1",
    bounty_id: bountyId,
    requester_did: context.requesterDid,
    title: validatedRequest.title,
    description: validatedRequest.description,
    reward: validatedRequest.reward,
    closure_type: validatedRequest.closure_type,
    difficulty_scalar: validatedRequest.difficulty_scalar,
    escrow_id: escrowResponse.escrow_id,
    status: "open",
    min_poh_tier: validatedRequest.min_poh_tier,
    tags: validatedRequest.tags,
    require_owner_verified_votes: validatedRequest.require_owner_verified_votes,
    is_code_bounty: validatedRequest.is_code_bounty,
    test_harness_id: validatedRequest.test_harness_id,
    fee_policy_version: feeResponse.fee_policy_version,
    all_in_cost: allInCost,
    created_at: createdAt,
    idempotency_key: idempotencyKey,
    metadata: validatedRequest.metadata,
  };

  await deps.bountyRepository.save(bounty);

  // Return response
  return {
    schema_version: "1",
    bounty_id: bountyId,
    escrow_id: escrowResponse.escrow_id,
    status: "open",
    all_in_cost: allInCost,
    fee_policy_version: feeResponse.fee_policy_version,
    created_at: createdAt,
  };
}
