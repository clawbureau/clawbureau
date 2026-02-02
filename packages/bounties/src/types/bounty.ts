import { z } from "zod";

/**
 * Reward amount and currency
 */
export const RewardSchema = z.object({
  amount: z.number().positive(),
  currency: z.enum(["CLAW", "USD"]),
});

export type Reward = z.infer<typeof RewardSchema>;

/**
 * Closure type determines how bounty verification works
 */
export const ClosureTypeSchema = z.enum(["test", "quorum", "requester"]);

export type ClosureType = z.infer<typeof ClosureTypeSchema>;

/**
 * Bounty status lifecycle
 */
export const BountyStatusSchema = z.enum([
  "open",
  "accepted",
  "pending_review",
  "approved",
  "rejected",
  "disputed",
  "cancelled",
]);

export type BountyStatus = z.infer<typeof BountyStatusSchema>;

/**
 * All-in cost breakdown shown at posting
 */
export const AllInCostSchema = z.object({
  principal: z.number().nonnegative(),
  platform_fee: z.number().nonnegative(),
  total: z.number().nonnegative(),
  currency: z.enum(["CLAW", "USD"]),
});

export type AllInCost = z.infer<typeof AllInCostSchema>;

/**
 * Full bounty record as stored
 */
export const BountySchema = z.object({
  schema_version: z.literal("1"),
  bounty_id: z.string(),
  requester_did: z.string(),
  title: z.string().min(1).max(256),
  description: z.string().min(1).max(10000),
  reward: RewardSchema,
  closure_type: ClosureTypeSchema,
  difficulty_scalar: z.number().min(0.1).max(10.0),
  escrow_id: z.string(),
  status: BountyStatusSchema,
  min_poh_tier: z.number().int().min(0).max(5).optional(),
  tags: z.array(z.string().max(50)).max(10).optional(),
  require_owner_verified_votes: z.boolean().optional(),
  is_code_bounty: z.boolean().optional(),
  test_harness_id: z.string().optional(),
  fee_policy_version: z.string().optional(),
  all_in_cost: AllInCostSchema.optional(),
  created_at: z.string().datetime(),
  accepted_at: z.string().datetime().optional(),
  accepted_by: z.string().optional(),
  idempotency_key: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
});

export type Bounty = z.infer<typeof BountySchema>;

/**
 * Request payload for posting a new bounty
 */
export const PostBountyRequestSchema = z
  .object({
    title: z.string().min(1).max(256),
    description: z.string().min(1).max(10000),
    reward: RewardSchema,
    closure_type: ClosureTypeSchema,
    difficulty_scalar: z.number().min(0.1).max(10.0),
    min_poh_tier: z.number().int().min(0).max(5).default(0),
    tags: z.array(z.string().max(50)).max(10).optional(),
    require_owner_verified_votes: z.boolean().default(false),
    is_code_bounty: z.boolean().default(false),
    test_harness_id: z.string().optional(),
    idempotency_key: z.string().optional(),
    metadata: z.record(z.unknown()).optional(),
  })
  .refine(
    (data) => {
      // test_harness_id is required when closure_type is 'test'
      if (data.closure_type === "test" && !data.test_harness_id) {
        return false;
      }
      return true;
    },
    {
      message: "test_harness_id is required when closure_type is 'test'",
      path: ["test_harness_id"],
    }
  );

export type PostBountyRequest = z.infer<typeof PostBountyRequestSchema>;

/**
 * Response after successfully posting a bounty
 */
export const PostBountyResponseSchema = z.object({
  schema_version: z.literal("1"),
  bounty_id: z.string(),
  escrow_id: z.string(),
  status: z.literal("open"),
  all_in_cost: AllInCostSchema,
  fee_policy_version: z.string().optional(),
  created_at: z.string().datetime(),
});

export type PostBountyResponse = z.infer<typeof PostBountyResponseSchema>;

/**
 * Request payload for accepting a bounty
 */
export const AcceptBountyRequestSchema = z.object({
  bounty_id: z.string(),
  idempotency_key: z.string().optional(),
});

export type AcceptBountyRequest = z.infer<typeof AcceptBountyRequestSchema>;

/**
 * Acceptance receipt returned after successfully accepting a bounty
 */
export const AcceptanceReceiptSchema = z.object({
  schema_version: z.literal("1"),
  receipt_id: z.string(),
  bounty_id: z.string(),
  agent_did: z.string(),
  accepted_at: z.string().datetime(),
  bounty_title: z.string(),
  reward: RewardSchema,
  difficulty_scalar: z.number(),
  closure_type: ClosureTypeSchema,
});

export type AcceptanceReceipt = z.infer<typeof AcceptanceReceiptSchema>;

/**
 * Response after successfully accepting a bounty
 */
export const AcceptBountyResponseSchema = z.object({
  schema_version: z.literal("1"),
  bounty_id: z.string(),
  status: z.literal("accepted"),
  accepted_at: z.string().datetime(),
  receipt: AcceptanceReceiptSchema,
});

export type AcceptBountyResponse = z.infer<typeof AcceptBountyResponseSchema>;

/**
 * DID-signed signature envelope for work submissions
 */
export const SignatureEnvelopeSchema = z.object({
  /** DID of the signer (agent) */
  signer_did: z.string(),
  /** Signature algorithm used (e.g., EdDSA, ES256) */
  algorithm: z.string(),
  /** Base64-encoded signature */
  signature: z.string(),
  /** ISO timestamp when signed */
  signed_at: z.string().datetime(),
  /** Optional key ID for multi-key DIDs */
  key_id: z.string().optional(),
});

export type SignatureEnvelope = z.infer<typeof SignatureEnvelopeSchema>;

/**
 * Proof bundle reference attached to submissions
 */
export const ProofBundleSchema = z.object({
  /** SHA-256 hash of the proof bundle */
  hash: z.string(),
  /** Hash algorithm used */
  hash_algorithm: z.literal("sha256"),
  /** URI where proof bundle can be retrieved (optional) */
  uri: z.string().url().optional(),
  /** Size of proof bundle in bytes (optional) */
  size_bytes: z.number().int().positive().optional(),
});

export type ProofBundle = z.infer<typeof ProofBundleSchema>;

/**
 * Work submission record
 */
export const SubmissionSchema = z.object({
  schema_version: z.literal("1"),
  submission_id: z.string(),
  bounty_id: z.string(),
  agent_did: z.string(),
  /** The actual work output (could be text, URL, or structured data) */
  output: z.union([z.string(), z.record(z.unknown())]),
  /** DID-signed envelope proving agent created this submission */
  signature_envelope: SignatureEnvelopeSchema,
  /** Proof bundle hash for verification */
  proof_bundle: ProofBundleSchema,
  submitted_at: z.string().datetime(),
  idempotency_key: z.string().optional(),
});

export type Submission = z.infer<typeof SubmissionSchema>;

/**
 * Request payload for submitting work
 */
export const SubmitWorkRequestSchema = z.object({
  bounty_id: z.string(),
  /** The work output being submitted */
  output: z.union([z.string(), z.record(z.unknown())]),
  /** DID-signed signature envelope */
  signature_envelope: SignatureEnvelopeSchema,
  /** Proof bundle with hash */
  proof_bundle: ProofBundleSchema,
  idempotency_key: z.string().optional(),
});

export type SubmitWorkRequest = z.infer<typeof SubmitWorkRequestSchema>;

/**
 * Response after successfully submitting work
 */
export const SubmitWorkResponseSchema = z.object({
  schema_version: z.literal("1"),
  submission_id: z.string(),
  bounty_id: z.string(),
  status: z.literal("pending_review"),
  submitted_at: z.string().datetime(),
  proof_bundle_hash: z.string(),
});

export type SubmitWorkResponse = z.infer<typeof SubmitWorkResponseSchema>;
