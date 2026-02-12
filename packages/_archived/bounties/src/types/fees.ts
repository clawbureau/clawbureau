import { z } from "zod";

/**
 * Fee calculation request to clawcuts
 */
export const FeeCalculationRequestSchema = z.object({
  principal: z.number().positive(),
  currency: z.enum(["CLAW", "USD"]),
  transaction_type: z.literal("bounty_post"),
});

export type FeeCalculationRequest = z.infer<typeof FeeCalculationRequestSchema>;

/**
 * Fee calculation response from clawcuts
 */
export const FeeCalculationResponseSchema = z.object({
  principal: z.number().nonnegative(),
  platform_fee: z.number().nonnegative(),
  total: z.number().nonnegative(),
  currency: z.enum(["CLAW", "USD"]),
  fee_policy_version: z.string(),
});

export type FeeCalculationResponse = z.infer<typeof FeeCalculationResponseSchema>;

/**
 * Interface for the fee service client
 */
export interface FeeService {
  calculateFees(request: FeeCalculationRequest): Promise<FeeCalculationResponse>;
}
