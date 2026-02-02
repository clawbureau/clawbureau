import { z } from "zod";
import { ClosureTypeSchema } from "./bounty.js";

/**
 * Request to create an escrow hold via clawescrow
 */
export const EscrowHoldRequestSchema = z.object({
  schema_version: z.literal("1"),
  requester_did: z.string(),
  amount: z.number().positive(),
  currency: z.enum(["CLAW", "USD"]),
  bounty_id: z.string(),
  idempotency_key: z.string(),
  metadata: z
    .object({
      closure_type: ClosureTypeSchema.optional(),
      difficulty_scalar: z.number().optional(),
      fee_policy_version: z.string().optional(),
    })
    .optional(),
});

export type EscrowHoldRequest = z.infer<typeof EscrowHoldRequestSchema>;

/**
 * Response from clawescrow after creating a hold
 */
export const EscrowHoldResponseSchema = z.object({
  escrow_id: z.string(),
  status: z.enum(["held", "failed"]),
  amount_held: z.number(),
  currency: z.enum(["CLAW", "USD"]),
  created_at: z.string().datetime(),
  error: z.string().optional(),
});

export type EscrowHoldResponse = z.infer<typeof EscrowHoldResponseSchema>;

/**
 * Request to freeze an escrow hold
 */
export const EscrowFreezeRequestSchema = z.object({
  schema_version: z.literal("1"),
  escrow_id: z.string(),
  dispute_id: z.string(),
  reason: z.string().optional(),
});

export type EscrowFreezeRequest = z.infer<typeof EscrowFreezeRequestSchema>;

/**
 * Response from clawescrow after freezing a hold
 */
export const EscrowFreezeResponseSchema = z.object({
  escrow_id: z.string(),
  dispute_id: z.string(),
  frozen: z.boolean(),
  frozen_at: z.string().datetime(),
  error: z.string().optional(),
});

export type EscrowFreezeResponse = z.infer<typeof EscrowFreezeResponseSchema>;

/**
 * Interface for the escrow service client
 */
export interface EscrowService {
  createHold(request: EscrowHoldRequest): Promise<EscrowHoldResponse>;
  freezeHold(request: EscrowFreezeRequest): Promise<EscrowFreezeResponse>;
}
