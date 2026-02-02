import { BountyRepository } from "../types/repository.js";
import {
  StakeService,
  StakeHold,
  CalculateStakeRequest,
  CalculateStakeRequestSchema,
  CalculateStakeResponse,
  ReleaseStakeRequest,
  ReleaseStakeResponse,
  SlashStakeResponse,
} from "../types/stake.js";

/**
 * Generate a random UUID using crypto.randomUUID (available in modern runtimes)
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

/**
 * Error thrown when stake operations fail
 */
export class StakeError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "StakeError";
  }
}

/**
 * Context for stake operations
 */
export interface StakeContext {
  /** DID of the party performing the action */
  did: string;
}

/**
 * Dependencies required for stake operations
 */
export interface StakeDeps {
  bountyRepository: BountyRepository;
  stakeService: StakeService;
  generateId?: () => string;
  now?: () => Date;
}

/**
 * Request to lock stakes for a bounty
 */
export interface LockBountyStakesRequest {
  bounty_id: string;
  requester_did: string;
  worker_did?: string;
  bounty_amount: number;
  currency: "CLAW" | "USD";
  idempotency_key?: string;
}

/**
 * Response after locking bounty stakes
 */
export interface LockBountyStakesResponse {
  schema_version: "1";
  bounty_id: string;
  requester_stake?: {
    stake_id: string;
    amount: number;
    currency: "CLAW" | "USD";
    ledger_tx_id: string;
  };
  worker_stake?: {
    stake_id: string;
    amount: number;
    currency: "CLAW" | "USD";
    ledger_tx_id: string;
  };
  locked_at: string;
}

/**
 * Calculate stake requirement for a party
 *
 * This action calculates the required stake based on the party's
 * trust tier and the bounty size.
 *
 * @param request - The calculate stake request
 * @param deps - Dependencies (stake service)
 * @returns The calculated stake requirement
 */
export async function calculateStake(
  request: CalculateStakeRequest,
  deps: StakeDeps
): Promise<CalculateStakeResponse> {
  // Validate request
  const parseResult = CalculateStakeRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new StakeError(
      "Invalid calculate stake request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  return await deps.stakeService.calculateStake(validatedRequest);
}

/**
 * Lock stakes for a bounty (both requester and optionally worker)
 *
 * This action:
 * 1. Calculates required stakes based on trust tiers
 * 2. Locks requester stake in ledger bonded bucket
 * 3. Optionally locks worker stake if worker_did is provided
 * 4. Saves stake records to repository
 *
 * @param request - The lock stakes request
 * @param deps - Dependencies (repository, stake service)
 * @returns The lock stakes response with stake IDs
 */
export async function lockBountyStakes(
  request: LockBountyStakesRequest,
  deps: StakeDeps
): Promise<LockBountyStakesResponse> {
  const generateId = deps.generateId ?? generateUUID;
  const now = deps.now ?? (() => new Date());

  // Check for idempotency
  if (request.idempotency_key) {
    const existingStake = await deps.bountyRepository.findStakeByIdempotencyKey(
      request.idempotency_key
    );
    if (existingStake) {
      // Find all stakes for this bounty
      const bountyStakes = await deps.bountyRepository.findStakesByBountyId(
        request.bounty_id
      );
      const requesterStake = bountyStakes.find((s) => s.role === "requester");
      const workerStake = bountyStakes.find((s) => s.role === "worker");

      return {
        schema_version: "1",
        bounty_id: request.bounty_id,
        requester_stake: requesterStake
          ? {
              stake_id: requesterStake.stake_id,
              amount: requesterStake.amount,
              currency: requesterStake.currency,
              ledger_tx_id: requesterStake.ledger_tx_id,
            }
          : undefined,
        worker_stake: workerStake
          ? {
              stake_id: workerStake.stake_id,
              amount: workerStake.amount,
              currency: workerStake.currency,
              ledger_tx_id: workerStake.ledger_tx_id,
            }
          : undefined,
        locked_at: requesterStake?.locked_at ?? now().toISOString(),
      };
    }
  }

  // Find the bounty
  const bounty = await deps.bountyRepository.findById(request.bounty_id);
  if (!bounty) {
    throw new StakeError("Bounty not found", "BOUNTY_NOT_FOUND", {
      bounty_id: request.bounty_id,
    });
  }

  const lockedAt = now().toISOString();
  const response: LockBountyStakesResponse = {
    schema_version: "1",
    bounty_id: request.bounty_id,
    locked_at: lockedAt,
  };

  // Calculate and lock requester stake
  const requesterCalc = await deps.stakeService.calculateStake({
    role: "requester",
    did: request.requester_did,
    bounty_amount: request.bounty_amount,
    currency: request.currency,
  });

  if (requesterCalc.requirement.stake_amount > 0) {
    const requesterIdempotencyKey = request.idempotency_key
      ? `stake:requester:${request.idempotency_key}`
      : `stake:requester:${request.bounty_id}:${generateId()}`;

    const lockResponse = await deps.stakeService.lockStake({
      schema_version: "1",
      bounty_id: request.bounty_id,
      staker_did: request.requester_did,
      role: "requester",
      amount: requesterCalc.requirement.stake_amount,
      currency: request.currency,
      idempotency_key: requesterIdempotencyKey,
    });

    if (lockResponse.error) {
      throw new StakeError(
        "Failed to lock requester stake",
        "REQUESTER_STAKE_LOCK_FAILED",
        { error: lockResponse.error }
      );
    }

    // Save requester stake record
    const requesterStake: StakeHold = {
      schema_version: "1",
      stake_id: lockResponse.stake_id,
      bounty_id: request.bounty_id,
      staker_did: request.requester_did,
      role: "requester",
      amount: lockResponse.amount_locked,
      currency: lockResponse.currency,
      ledger_tx_id: lockResponse.ledger_tx_id,
      status: "locked",
      locked_at: lockedAt,
      idempotency_key: requesterIdempotencyKey,
    };

    await deps.bountyRepository.saveStake(requesterStake);

    response.requester_stake = {
      stake_id: lockResponse.stake_id,
      amount: lockResponse.amount_locked,
      currency: lockResponse.currency,
      ledger_tx_id: lockResponse.ledger_tx_id,
    };
  }

  // Calculate and lock worker stake if worker_did provided
  if (request.worker_did) {
    const workerCalc = await deps.stakeService.calculateStake({
      role: "worker",
      did: request.worker_did,
      bounty_amount: request.bounty_amount,
      currency: request.currency,
    });

    if (workerCalc.requirement.stake_amount > 0) {
      const workerIdempotencyKey = request.idempotency_key
        ? `stake:worker:${request.idempotency_key}`
        : `stake:worker:${request.bounty_id}:${generateId()}`;

      const lockResponse = await deps.stakeService.lockStake({
        schema_version: "1",
        bounty_id: request.bounty_id,
        staker_did: request.worker_did,
        role: "worker",
        amount: workerCalc.requirement.stake_amount,
        currency: request.currency,
        idempotency_key: workerIdempotencyKey,
      });

      if (lockResponse.error) {
        throw new StakeError(
          "Failed to lock worker stake",
          "WORKER_STAKE_LOCK_FAILED",
          { error: lockResponse.error }
        );
      }

      // Save worker stake record
      const workerStake: StakeHold = {
        schema_version: "1",
        stake_id: lockResponse.stake_id,
        bounty_id: request.bounty_id,
        staker_did: request.worker_did,
        role: "worker",
        amount: lockResponse.amount_locked,
        currency: lockResponse.currency,
        ledger_tx_id: lockResponse.ledger_tx_id,
        status: "locked",
        locked_at: lockedAt,
        idempotency_key: workerIdempotencyKey,
      };

      await deps.bountyRepository.saveStake(workerStake);

      response.worker_stake = {
        stake_id: lockResponse.stake_id,
        amount: lockResponse.amount_locked,
        currency: lockResponse.currency,
        ledger_tx_id: lockResponse.ledger_tx_id,
      };
    }
  }

  return response;
}

/**
 * Release stakes for a completed or cancelled bounty
 *
 * This action:
 * 1. Finds all stakes for the bounty
 * 2. Releases each stake from the ledger bonded bucket
 * 3. Updates stake records with released status
 *
 * @param bountyId - The bounty ID to release stakes for
 * @param reason - Reason for release (bounty_completed or bounty_cancelled)
 * @param deps - Dependencies (repository, stake service)
 * @returns Array of release responses
 */
export async function releaseBountyStakes(
  bountyId: string,
  reason: "bounty_completed" | "bounty_cancelled",
  deps: StakeDeps
): Promise<ReleaseStakeResponse[]> {
  const bounty = await deps.bountyRepository.findById(bountyId);
  if (!bounty) {
    throw new StakeError("Bounty not found", "BOUNTY_NOT_FOUND", {
      bounty_id: bountyId,
    });
  }

  const stakes = await deps.bountyRepository.findStakesByBountyId(bountyId);
  const responses: ReleaseStakeResponse[] = [];

  for (const stake of stakes) {
    if (stake.status !== "locked") {
      continue; // Skip already released/slashed stakes
    }

    const releaseRequest: ReleaseStakeRequest = {
      schema_version: "1",
      stake_id: stake.stake_id,
      reason,
    };

    const releaseResponse = await deps.stakeService.releaseStake(releaseRequest);
    responses.push(releaseResponse);

    if (!releaseResponse.error) {
      // Update stake record
      const updatedStake: StakeHold = {
        ...stake,
        status: "released",
        released_at: releaseResponse.released_at,
        amount_released: releaseResponse.amount_released,
      };
      await deps.bountyRepository.saveStake(updatedStake);
    }
  }

  return responses;
}

/**
 * Resolve stakes based on trial outcome
 *
 * This action:
 * 1. Finds all stakes for the bounty
 * 2. Determines slash percentage based on trial outcome
 * 3. Slashes losing party's stake and releases winning party's stake
 * 4. Updates stake records
 *
 * Trial outcomes:
 * - "approve": Worker wins - slash requester stake, release worker stake
 * - "reject": Requester wins - slash worker stake, release requester stake
 * - "split": Both parties partially at fault - partial slash for both
 *
 * @param bountyId - The bounty ID to resolve stakes for
 * @param disputeId - The dispute ID
 * @param trialOutcome - The trial outcome (approve, reject, or split)
 * @param deps - Dependencies (repository, stake service)
 * @returns Object with slash and release responses
 */
export async function resolveStakesForTrial(
  bountyId: string,
  disputeId: string,
  trialOutcome: "approve" | "reject" | "split",
  deps: StakeDeps
): Promise<{
  requester_result?: SlashStakeResponse | ReleaseStakeResponse;
  worker_result?: SlashStakeResponse | ReleaseStakeResponse;
}> {
  const bounty = await deps.bountyRepository.findById(bountyId);
  if (!bounty) {
    throw new StakeError("Bounty not found", "BOUNTY_NOT_FOUND", {
      bounty_id: bountyId,
    });
  }

  const stakes = await deps.bountyRepository.findStakesByBountyId(bountyId);
  const requesterStake = stakes.find((s) => s.role === "requester" && s.status === "locked");
  const workerStake = stakes.find((s) => s.role === "worker" && s.status === "locked");

  const result: {
    requester_result?: SlashStakeResponse | ReleaseStakeResponse;
    worker_result?: SlashStakeResponse | ReleaseStakeResponse;
  } = {};

  if (trialOutcome === "approve") {
    // Worker wins - slash requester stake, release worker stake
    if (requesterStake) {
      const slashResponse = await deps.stakeService.slashStake({
        schema_version: "1",
        stake_id: requesterStake.stake_id,
        dispute_id: disputeId,
        trial_outcome: trialOutcome,
        slash_percentage: 100,
      });
      result.requester_result = slashResponse;

      if (!slashResponse.error) {
        const updatedStake: StakeHold = {
          ...requesterStake,
          status: "slashed",
          released_at: slashResponse.slashed_at,
          amount_slashed: slashResponse.amount_slashed,
          amount_released: slashResponse.amount_released,
          dispute_id: disputeId,
          trial_outcome: trialOutcome,
        };
        await deps.bountyRepository.saveStake(updatedStake);
      }
    }

    if (workerStake) {
      const releaseResponse = await deps.stakeService.releaseStake({
        schema_version: "1",
        stake_id: workerStake.stake_id,
        reason: "trial_resolved",
        trial_outcome: trialOutcome,
        dispute_id: disputeId,
      });
      result.worker_result = releaseResponse;

      if (!releaseResponse.error) {
        const updatedStake: StakeHold = {
          ...workerStake,
          status: "released",
          released_at: releaseResponse.released_at,
          amount_released: releaseResponse.amount_released,
          dispute_id: disputeId,
          trial_outcome: trialOutcome,
        };
        await deps.bountyRepository.saveStake(updatedStake);
      }
    }
  } else if (trialOutcome === "reject") {
    // Requester wins - slash worker stake, release requester stake
    if (workerStake) {
      const slashResponse = await deps.stakeService.slashStake({
        schema_version: "1",
        stake_id: workerStake.stake_id,
        dispute_id: disputeId,
        trial_outcome: trialOutcome,
        slash_percentage: 100,
      });
      result.worker_result = slashResponse;

      if (!slashResponse.error) {
        const updatedStake: StakeHold = {
          ...workerStake,
          status: "slashed",
          released_at: slashResponse.slashed_at,
          amount_slashed: slashResponse.amount_slashed,
          amount_released: slashResponse.amount_released,
          dispute_id: disputeId,
          trial_outcome: trialOutcome,
        };
        await deps.bountyRepository.saveStake(updatedStake);
      }
    }

    if (requesterStake) {
      const releaseResponse = await deps.stakeService.releaseStake({
        schema_version: "1",
        stake_id: requesterStake.stake_id,
        reason: "trial_resolved",
        trial_outcome: trialOutcome,
        dispute_id: disputeId,
      });
      result.requester_result = releaseResponse;

      if (!releaseResponse.error) {
        const updatedStake: StakeHold = {
          ...requesterStake,
          status: "released",
          released_at: releaseResponse.released_at,
          amount_released: releaseResponse.amount_released,
          dispute_id: disputeId,
          trial_outcome: trialOutcome,
        };
        await deps.bountyRepository.saveStake(updatedStake);
      }
    }
  } else {
    // Split outcome - partial slash for both (50%)
    if (requesterStake) {
      const slashResponse = await deps.stakeService.slashStake({
        schema_version: "1",
        stake_id: requesterStake.stake_id,
        dispute_id: disputeId,
        trial_outcome: trialOutcome,
        slash_percentage: 50,
      });
      result.requester_result = slashResponse;

      if (!slashResponse.error) {
        const updatedStake: StakeHold = {
          ...requesterStake,
          status: "partially_slashed",
          released_at: slashResponse.slashed_at,
          amount_slashed: slashResponse.amount_slashed,
          amount_released: slashResponse.amount_released,
          dispute_id: disputeId,
          trial_outcome: trialOutcome,
        };
        await deps.bountyRepository.saveStake(updatedStake);
      }
    }

    if (workerStake) {
      const slashResponse = await deps.stakeService.slashStake({
        schema_version: "1",
        stake_id: workerStake.stake_id,
        dispute_id: disputeId,
        trial_outcome: trialOutcome,
        slash_percentage: 50,
      });
      result.worker_result = slashResponse;

      if (!slashResponse.error) {
        const updatedStake: StakeHold = {
          ...workerStake,
          status: "partially_slashed",
          released_at: slashResponse.slashed_at,
          amount_slashed: slashResponse.amount_slashed,
          amount_released: slashResponse.amount_released,
          dispute_id: disputeId,
          trial_outcome: trialOutcome,
        };
        await deps.bountyRepository.saveStake(updatedStake);
      }
    }
  }

  return result;
}
