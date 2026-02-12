import { z } from "zod";
import { SignatureEnvelopeSchema } from "./bounty.js";

/**
 * Dispute status lifecycle
 */
export const DisputeStatusSchema = z.enum([
  "open",
  "routed_to_trials",
  "resolved_approved",
  "resolved_rejected",
  "cancelled",
]);

export type DisputeStatus = z.infer<typeof DisputeStatusSchema>;

/**
 * Reason for opening a dispute
 */
export const DisputeReasonSchema = z.enum([
  "unfair_rejection",
  "incorrect_test_results",
  "quorum_manipulation",
  "scope_disagreement",
  "other",
]);

export type DisputeReason = z.infer<typeof DisputeReasonSchema>;

/**
 * Trial outcome from clawtrial service
 */
export const TrialOutcomeSchema = z.enum(["approve", "reject", "split"]);

export type TrialOutcome = z.infer<typeof TrialOutcomeSchema>;

/**
 * Dispute record as stored
 */
export const DisputeSchema = z.object({
  schema_version: z.literal("1"),
  dispute_id: z.string(),
  bounty_id: z.string(),
  submission_id: z.string(),
  /** DID of the agent opening the dispute */
  disputer_did: z.string(),
  /** Reason for the dispute */
  reason: DisputeReasonSchema,
  /** Detailed explanation of the dispute */
  explanation: z.string().min(1).max(5000),
  /** DID-signed envelope proving agent created this dispute */
  signature_envelope: SignatureEnvelopeSchema,
  /** Current dispute status */
  status: DisputeStatusSchema,
  /** ID of the trial case if routed to trials */
  trial_case_id: z.string().optional(),
  /** Outcome of the trial if resolved */
  trial_outcome: TrialOutcomeSchema.optional(),
  /** ISO timestamp when dispute was opened */
  opened_at: z.string().datetime(),
  /** ISO timestamp when routed to trials */
  routed_at: z.string().datetime().optional(),
  /** ISO timestamp when resolved */
  resolved_at: z.string().datetime().optional(),
  /** Idempotency key for duplicate prevention */
  idempotency_key: z.string().optional(),
});

export type Dispute = z.infer<typeof DisputeSchema>;

/**
 * Request to open a dispute
 */
export const OpenDisputeRequestSchema = z.object({
  bounty_id: z.string(),
  submission_id: z.string(),
  reason: DisputeReasonSchema,
  explanation: z.string().min(1).max(5000),
  signature_envelope: SignatureEnvelopeSchema,
  idempotency_key: z.string().optional(),
});

export type OpenDisputeRequest = z.infer<typeof OpenDisputeRequestSchema>;

/**
 * Response after opening a dispute
 */
export const OpenDisputeResponseSchema = z.object({
  schema_version: z.literal("1"),
  dispute_id: z.string(),
  bounty_id: z.string(),
  submission_id: z.string(),
  status: z.literal("open"),
  payout_frozen: z.boolean(),
  opened_at: z.string().datetime(),
});

export type OpenDisputeResponse = z.infer<typeof OpenDisputeResponseSchema>;

/**
 * Request to route dispute to trials
 */
export const RouteToTrialsRequestSchema = z.object({
  dispute_id: z.string(),
});

export type RouteToTrialsRequest = z.infer<typeof RouteToTrialsRequestSchema>;

/**
 * Trial case info returned from trials service
 */
export const TrialCaseInfoSchema = z.object({
  trial_case_id: z.string(),
  dispute_id: z.string(),
  bounty_id: z.string(),
  submission_id: z.string(),
  disputer_did: z.string(),
  requester_did: z.string(),
  created_at: z.string().datetime(),
  status: z.enum(["pending", "in_progress", "completed"]),
});

export type TrialCaseInfo = z.infer<typeof TrialCaseInfoSchema>;

/**
 * Response after routing to trials
 */
export const RouteToTrialsResponseSchema = z.object({
  schema_version: z.literal("1"),
  dispute_id: z.string(),
  trial_case_id: z.string(),
  status: z.literal("routed_to_trials"),
  routed_at: z.string().datetime(),
});

export type RouteToTrialsResponse = z.infer<typeof RouteToTrialsResponseSchema>;

/**
 * Request to freeze payout for a bounty
 */
export const FreezePayoutRequestSchema = z.object({
  bounty_id: z.string(),
  dispute_id: z.string(),
});

export type FreezePayoutRequest = z.infer<typeof FreezePayoutRequestSchema>;

/**
 * Response after freezing payout
 */
export const FreezePayoutResponseSchema = z.object({
  schema_version: z.literal("1"),
  bounty_id: z.string(),
  escrow_id: z.string(),
  dispute_id: z.string(),
  frozen: z.boolean(),
  frozen_at: z.string().datetime(),
});

export type FreezePayoutResponse = z.infer<typeof FreezePayoutResponseSchema>;

/**
 * Interface for the trials service (clawtrial)
 */
export interface TrialsService {
  createCase(request: CreateTrialCaseRequest): Promise<CreateTrialCaseResponse>;
  getCaseStatus(trialCaseId: string): Promise<TrialCaseInfo | null>;
}

/**
 * Request to create a trial case
 */
export const CreateTrialCaseRequestSchema = z.object({
  dispute_id: z.string(),
  bounty_id: z.string(),
  submission_id: z.string(),
  disputer_did: z.string(),
  requester_did: z.string(),
  reason: DisputeReasonSchema,
  explanation: z.string(),
});

export type CreateTrialCaseRequest = z.infer<typeof CreateTrialCaseRequestSchema>;

/**
 * Response from creating a trial case
 */
export const CreateTrialCaseResponseSchema = z.object({
  trial_case_id: z.string(),
  dispute_id: z.string(),
  status: z.literal("pending"),
  created_at: z.string().datetime(),
});

export type CreateTrialCaseResponse = z.infer<typeof CreateTrialCaseResponseSchema>;
