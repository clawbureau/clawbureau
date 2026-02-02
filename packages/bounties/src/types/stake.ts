import { z } from "zod";
import { TrialOutcomeSchema } from "./dispute.js";

/**
 * Stake status lifecycle
 */
export const StakeStatusSchema = z.enum([
  "locked",
  "released",
  "slashed",
  "partially_slashed",
]);

export type StakeStatus = z.infer<typeof StakeStatusSchema>;

/**
 * Role of the party who provided the stake
 */
export const StakeRoleSchema = z.enum(["requester", "worker"]);

export type StakeRole = z.infer<typeof StakeRoleSchema>;

/**
 * Stake requirement calculated based on trust tier and bounty size
 */
export const StakeRequirementSchema = z.object({
  /** Role of the party (requester or worker) */
  role: StakeRoleSchema,
  /** Trust tier of the party (0-5) */
  trust_tier: z.number().int().min(0).max(5),
  /** Bounty principal amount */
  bounty_amount: z.number().positive(),
  /** Currency of the bounty */
  currency: z.enum(["CLAW", "USD"]),
  /** Calculated stake amount */
  stake_amount: z.number().nonnegative(),
  /** Stake percentage (for reference) */
  stake_percentage: z.number().min(0).max(100),
});

export type StakeRequirement = z.infer<typeof StakeRequirementSchema>;

/**
 * Stake hold record stored in ledger bonded bucket
 */
export const StakeHoldSchema = z.object({
  schema_version: z.literal("1"),
  /** Unique identifier for this stake hold */
  stake_id: z.string(),
  /** Bounty this stake is associated with */
  bounty_id: z.string(),
  /** DID of the party who provided the stake */
  staker_did: z.string(),
  /** Role of the staker */
  role: StakeRoleSchema,
  /** Amount staked */
  amount: z.number().nonnegative(),
  /** Currency */
  currency: z.enum(["CLAW", "USD"]),
  /** Ledger transaction ID for the bonded bucket lock */
  ledger_tx_id: z.string(),
  /** Current status of the stake */
  status: StakeStatusSchema,
  /** ISO timestamp when stake was locked */
  locked_at: z.string().datetime(),
  /** ISO timestamp when stake was released/slashed */
  released_at: z.string().datetime().optional(),
  /** Amount released (if partially slashed) */
  amount_released: z.number().nonnegative().optional(),
  /** Amount slashed (if slashed or partially slashed) */
  amount_slashed: z.number().nonnegative().optional(),
  /** Dispute ID if stake was slashed due to trial */
  dispute_id: z.string().optional(),
  /** Trial outcome that triggered release/slash */
  trial_outcome: TrialOutcomeSchema.optional(),
  /** Idempotency key */
  idempotency_key: z.string().optional(),
});

export type StakeHold = z.infer<typeof StakeHoldSchema>;

/**
 * Request to calculate stake requirements
 */
export const CalculateStakeRequestSchema = z.object({
  /** Role (requester or worker) */
  role: StakeRoleSchema,
  /** DID of the party */
  did: z.string(),
  /** Bounty principal amount */
  bounty_amount: z.number().positive(),
  /** Currency */
  currency: z.enum(["CLAW", "USD"]),
});

export type CalculateStakeRequest = z.infer<typeof CalculateStakeRequestSchema>;

/**
 * Response with calculated stake requirement
 */
export const CalculateStakeResponseSchema = z.object({
  schema_version: z.literal("1"),
  requirement: StakeRequirementSchema,
  /** Trust tier used for calculation */
  trust_tier: z.number().int().min(0).max(5),
  calculated_at: z.string().datetime(),
});

export type CalculateStakeResponse = z.infer<typeof CalculateStakeResponseSchema>;

/**
 * Request to lock stake in ledger bonded bucket
 */
export const LockStakeRequestSchema = z.object({
  schema_version: z.literal("1"),
  /** Bounty ID this stake is for */
  bounty_id: z.string(),
  /** DID of the staker */
  staker_did: z.string(),
  /** Role of the staker */
  role: StakeRoleSchema,
  /** Amount to stake */
  amount: z.number().nonnegative(),
  /** Currency */
  currency: z.enum(["CLAW", "USD"]),
  /** Idempotency key */
  idempotency_key: z.string(),
});

export type LockStakeRequest = z.infer<typeof LockStakeRequestSchema>;

/**
 * Response after locking stake
 */
export const LockStakeResponseSchema = z.object({
  stake_id: z.string(),
  ledger_tx_id: z.string(),
  status: z.literal("locked"),
  amount_locked: z.number().nonnegative(),
  currency: z.enum(["CLAW", "USD"]),
  locked_at: z.string().datetime(),
  error: z.string().optional(),
});

export type LockStakeResponse = z.infer<typeof LockStakeResponseSchema>;

/**
 * Request to release stake from ledger bonded bucket
 */
export const ReleaseStakeRequestSchema = z.object({
  schema_version: z.literal("1"),
  /** Stake ID to release */
  stake_id: z.string(),
  /** Reason for release */
  reason: z.enum(["bounty_completed", "bounty_cancelled", "trial_resolved"]),
  /** Trial outcome if applicable */
  trial_outcome: TrialOutcomeSchema.optional(),
  /** Dispute ID if trial-related */
  dispute_id: z.string().optional(),
});

export type ReleaseStakeRequest = z.infer<typeof ReleaseStakeRequestSchema>;

/**
 * Response after releasing stake
 */
export const ReleaseStakeResponseSchema = z.object({
  stake_id: z.string(),
  status: StakeStatusSchema,
  amount_released: z.number().nonnegative(),
  amount_slashed: z.number().nonnegative(),
  currency: z.enum(["CLAW", "USD"]),
  ledger_tx_id: z.string(),
  released_at: z.string().datetime(),
  error: z.string().optional(),
});

export type ReleaseStakeResponse = z.infer<typeof ReleaseStakeResponseSchema>;

/**
 * Request to slash stake based on trial outcome
 */
export const SlashStakeRequestSchema = z.object({
  schema_version: z.literal("1"),
  /** Stake ID to slash */
  stake_id: z.string(),
  /** Dispute ID that triggered the slash */
  dispute_id: z.string(),
  /** Trial outcome */
  trial_outcome: TrialOutcomeSchema,
  /** Percentage to slash (0-100) */
  slash_percentage: z.number().min(0).max(100),
});

export type SlashStakeRequest = z.infer<typeof SlashStakeRequestSchema>;

/**
 * Response after slashing stake
 */
export const SlashStakeResponseSchema = z.object({
  stake_id: z.string(),
  status: StakeStatusSchema,
  amount_slashed: z.number().nonnegative(),
  amount_released: z.number().nonnegative(),
  currency: z.enum(["CLAW", "USD"]),
  ledger_tx_id: z.string(),
  slashed_at: z.string().datetime(),
  error: z.string().optional(),
});

export type SlashStakeResponse = z.infer<typeof SlashStakeResponseSchema>;

/**
 * Interface for stake service (interacts with ledger bonded bucket)
 */
export interface StakeService {
  /** Calculate required stake based on trust tier and bounty size */
  calculateStake(request: CalculateStakeRequest): Promise<CalculateStakeResponse>;
  /** Lock stake in ledger bonded bucket */
  lockStake(request: LockStakeRequest): Promise<LockStakeResponse>;
  /** Release stake from ledger bonded bucket */
  releaseStake(request: ReleaseStakeRequest): Promise<ReleaseStakeResponse>;
  /** Slash stake based on trial outcome */
  slashStake(request: SlashStakeRequest): Promise<SlashStakeResponse>;
}

/**
 * Stake rules by trust tier
 * Higher trust tiers require lower stake percentages
 */
export const STAKE_RULES = {
  /** Worker stake percentages by trust tier (0-5) */
  worker: {
    0: 25, // Unverified: 25% stake
    1: 20, // Tier 1: 20% stake
    2: 15, // Tier 2: 15% stake
    3: 10, // Tier 3: 10% stake
    4: 5,  // Tier 4: 5% stake
    5: 0,  // Tier 5: 0% stake (fully trusted)
  } as Record<number, number>,
  /** Requester stake percentages by trust tier (0-5) */
  requester: {
    0: 15, // Unverified: 15% stake
    1: 12, // Tier 1: 12% stake
    2: 10, // Tier 2: 10% stake
    3: 7,  // Tier 3: 7% stake
    4: 3,  // Tier 4: 3% stake
    5: 0,  // Tier 5: 0% stake (fully trusted)
  } as Record<number, number>,
  /** Minimum stake amounts by currency */
  minimums: {
    CLAW: 10,
    USD: 5,
  } as Record<string, number>,
  /** Maximum stake cap (percentage of bounty) */
  maxCap: 50,
} as const;

/**
 * Calculate stake amount based on trust tier and bounty size
 */
export function calculateStakeAmount(
  role: StakeRole,
  trustTier: number,
  bountyAmount: number,
  currency: "CLAW" | "USD"
): { amount: number; percentage: number } {
  const rules = role === "worker" ? STAKE_RULES.worker : STAKE_RULES.requester;
  const percentage = rules[trustTier] ?? rules[0];

  let amount = (bountyAmount * percentage) / 100;

  // Apply minimum stake
  const minimum = STAKE_RULES.minimums[currency] ?? 0;
  if (amount > 0 && amount < minimum) {
    amount = minimum;
  }

  // Apply maximum cap
  const maxAmount = (bountyAmount * STAKE_RULES.maxCap) / 100;
  if (amount > maxAmount) {
    amount = maxAmount;
  }

  return { amount, percentage };
}
