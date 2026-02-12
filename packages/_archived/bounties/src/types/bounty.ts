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
  fee_policy_version: z.string(),
  all_in_cost: AllInCostSchema,
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
  fee_policy_version: z.string(),
  /** Difficulty scalar (K) used for downstream weighting */
  difficulty_scalar: z.number().min(0.1).max(10.0),
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
  /** Worker net payout shown at acceptance (typically equals reward principal) */
  worker_net: RewardSchema,
  /** Fee policy version used at posting (from clawcuts) */
  fee_policy_version: z.string(),
  /** All-in cost that the requester paid (principal + fees) */
  all_in_cost: AllInCostSchema,
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
 * did-work commit signature envelope (commit.sig.json)
 * Used for code bounties (CBT-US-012)
 */
export const CommitSigSchema = z.object({
  version: z.literal("m1"),
  type: z.literal("message_signature"),
  algo: z.literal("ed25519"),
  did: z.string().min(1),
  message: z.string().min(1),
  createdAt: z.string().datetime(),
  signature: z.string().min(1),
});

export type CommitSig = z.infer<typeof CommitSigSchema>;

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
 * Proof tier classification
 * - self: agent self-asserted work only
 * - gateway: work accompanied by gateway receipts
 * - sandbox: work accompanied by sandbox execution attestations
 */
export const ProofTierSchema = z.enum(["self", "gateway", "sandbox"]);

export type ProofTier = z.infer<typeof ProofTierSchema>;

/**
 * Evidence used to classify proof tier.
 * This does not attempt to verify receipts/attestations; it stores references that can
 * be verified out-of-band by specialized services.
 */
export const ProofEvidenceObjectSchema = z.object({
  /** References to gateway receipts (e.g., clawproxy receipts) */
  receipts: z.array(z.string().min(1)).max(50).optional(),
  /** References to sandbox execution attestations */
  attestations: z.array(z.string().min(1)).max(50).optional(),
});

export type ProofEvidence = z.infer<typeof ProofEvidenceObjectSchema>;

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
  /** Proof tier classification used for downstream reputation weighting */
  proof_tier: ProofTierSchema.default("self"),
  /** Optional evidence references used to classify proof tier */
  proof_evidence: ProofEvidenceObjectSchema.optional(),

  /** Optional commit signature for code bounties (commit.sig.json) */
  commit_sig: CommitSigSchema.optional(),
  /** Convenience: extracted commit SHA from commit_sig.message */
  commit_sha: z.string().optional(),

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
  /** Evidence references (receipts/attestations) for proof tier classification */
  proof_evidence: ProofEvidenceObjectSchema.optional(),
  /** Code bounties require a commit signature proof (commit.sig.json) */
  commit_sig: CommitSigSchema.optional(),
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
  proof_tier: ProofTierSchema,
});

export type SubmitWorkResponse = z.infer<typeof SubmitWorkResponseSchema>;

/**
 * Test result record stored after test-based auto-approval
 */
export const TestResultSchema = z.object({
  schema_version: z.literal("1"),
  test_result_id: z.string(),
  submission_id: z.string(),
  bounty_id: z.string(),
  test_harness_id: z.string(),
  /** Overall pass/fail status */
  passed: z.boolean(),
  /** Total number of tests */
  total_tests: z.number().int().nonnegative(),
  /** Number of passed tests */
  passed_tests: z.number().int().nonnegative(),
  /** Number of failed tests */
  failed_tests: z.number().int().nonnegative(),
  /** Total execution time in milliseconds */
  execution_time_ms: z.number().nonnegative(),
  /** ISO timestamp when tests completed */
  completed_at: z.string().datetime(),
  /** Error message if harness failed to run */
  error: z.string().optional(),
});

export type TestResult = z.infer<typeof TestResultSchema>;

/**
 * Request payload for auto-approval based on test results
 */
export const AutoApproveRequestSchema = z.object({
  submission_id: z.string(),
});

export type AutoApproveRequest = z.infer<typeof AutoApproveRequestSchema>;

/**
 * Response after auto-approval attempt
 */
export const AutoApproveResponseSchema = z.object({
  schema_version: z.literal("1"),
  submission_id: z.string(),
  bounty_id: z.string(),
  /** Resulting bounty status (approved or rejected) */
  status: z.enum(["approved", "rejected"]),
  /** Whether tests passed */
  tests_passed: z.boolean(),
  /** Test result summary */
  test_result: z.object({
    total_tests: z.number().int().nonnegative(),
    passed_tests: z.number().int().nonnegative(),
    failed_tests: z.number().int().nonnegative(),
    execution_time_ms: z.number().nonnegative(),
  }),
  /** ISO timestamp when decision was made */
  decided_at: z.string().datetime(),
  /** Error message if test harness failed */
  error: z.string().optional(),
});

export type AutoApproveResponse = z.infer<typeof AutoApproveResponseSchema>;

/**
 * Sort field options for bounty search
 */
export const BountySortFieldSchema = z.enum([
  "reward",
  "created_at",
  "difficulty_scalar",
]);

export type BountySortField = z.infer<typeof BountySortFieldSchema>;

/**
 * Sort direction options
 */
export const SortDirectionSchema = z.enum(["asc", "desc"]);

export type SortDirection = z.infer<typeof SortDirectionSchema>;

/**
 * Request payload for searching bounties
 */
export const SearchBountiesRequestSchema = z.object({
  /** Filter by tags (bounty must have at least one matching tag) */
  tags: z.array(z.string().max(50)).max(10).optional(),
  /** Filter by bounty status */
  status: BountyStatusSchema.optional(),
  /** Filter by closure type */
  closure_type: ClosureTypeSchema.optional(),
  /** Filter by minimum reward amount */
  min_reward: z.number().nonnegative().optional(),
  /** Filter by maximum reward amount */
  max_reward: z.number().nonnegative().optional(),
  /** Filter by currency */
  currency: z.enum(["CLAW", "USD"]).optional(),
  /** Filter by requester DID */
  requester_did: z.string().optional(),
  /** Filter by code bounty flag */
  is_code_bounty: z.boolean().optional(),
  /** Sort field */
  sort_by: BountySortFieldSchema.default("created_at"),
  /** Sort direction */
  sort_direction: SortDirectionSchema.default("desc"),
  /** Page number (1-indexed) */
  page: z.number().int().positive().default(1),
  /** Number of results per page */
  page_size: z.number().int().positive().max(100).default(20),
});

export type SearchBountiesRequest = z.infer<typeof SearchBountiesRequestSchema>;

/**
 * Trust requirements info shown in bounty listings
 */
export const TrustRequirementsSchema = z.object({
  /** Minimum PoH tier required (0-5) */
  min_poh_tier: z.number().int().min(0).max(5),
  /** Whether owner-verified votes are required for quorum */
  require_owner_verified_votes: z.boolean(),
});

export type TrustRequirements = z.infer<typeof TrustRequirementsSchema>;

/**
 * Bounty listing item in search results
 */
export const BountyListingSchema = z.object({
  bounty_id: z.string(),
  title: z.string(),
  description: z.string(),
  reward: RewardSchema,
  closure_type: ClosureTypeSchema,
  difficulty_scalar: z.number(),
  status: BountyStatusSchema,
  tags: z.array(z.string()).optional(),
  is_code_bounty: z.boolean().optional(),
  created_at: z.string().datetime(),
  trust_requirements: TrustRequirementsSchema,
});

export type BountyListing = z.infer<typeof BountyListingSchema>;

/**
 * Response for bounty search
 */
export const SearchBountiesResponseSchema = z.object({
  schema_version: z.literal("1"),
  bounties: z.array(BountyListingSchema),
  pagination: z.object({
    page: z.number().int().positive(),
    page_size: z.number().int().positive(),
    total_count: z.number().int().nonnegative(),
    total_pages: z.number().int().nonnegative(),
  }),
});

export type SearchBountiesResponse = z.infer<typeof SearchBountiesResponseSchema>;
