import { z } from "zod";

/**
 * Request to check agent eligibility via clawtrust
 */
export const EligibilityCheckRequestSchema = z.object({
  agent_did: z.string(),
  required_poh_tier: z.number().int().min(0).max(5),
});

export type EligibilityCheckRequest = z.infer<typeof EligibilityCheckRequestSchema>;

/**
 * Response from clawtrust eligibility check
 */
export const EligibilityCheckResponseSchema = z.object({
  agent_did: z.string(),
  current_poh_tier: z.number().int().min(0).max(5),
  is_eligible: z.boolean(),
  checked_at: z.string().datetime(),
});

export type EligibilityCheckResponse = z.infer<typeof EligibilityCheckResponseSchema>;

/**
 * Interface for the eligibility service client (clawtrust)
 */
export interface EligibilityService {
  checkEligibility(request: EligibilityCheckRequest): Promise<EligibilityCheckResponse>;
}
