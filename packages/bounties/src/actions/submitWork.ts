import {
  Bounty,
  ProofEvidence,
  ProofTier,
  Submission,
  SubmitWorkRequest,
  SubmitWorkRequestSchema,
  SubmitWorkResponse,
} from "../types/bounty.js";
import { BountyRepository } from "../types/repository.js";

/**
 * Generate a random UUID using crypto.randomUUID (available in modern runtimes)
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

function classifyProofTier(evidence: ProofEvidence | undefined): ProofTier {
  // Highest assurance wins if multiple signals are present
  if (evidence?.attestations && evidence.attestations.length > 0) {
    return "sandbox";
  }

  if (evidence?.receipts && evidence.receipts.length > 0) {
    return "gateway";
  }

  return "self";
}

/**
 * Error thrown when work submission fails
 */
export class SubmitWorkError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "SubmitWorkError";
  }
}

/**
 * Dependencies required for submitting work
 */
export interface SubmitWorkDeps {
  bountyRepository: BountyRepository;
  generateId?: () => string;
  now?: () => Date;
}

/**
 * Context for the submit work operation
 */
export interface SubmitWorkContext {
  agentDid: string;
}

/**
 * Submit work for a bounty
 *
 * This action:
 * 1. Validates the request including signature envelope and proof bundle
 * 2. Checks idempotency
 * 3. Finds the bounty and verifies it's in accepted state
 * 4. Verifies the submitter is the agent who accepted the bounty
 * 5. Creates submission record with proof bundle hash
 * 6. Updates bounty status to pending_review
 * 7. Returns submission confirmation
 *
 * @param request - The submit work request with signature envelope and proof bundle
 * @param context - Operation context including agent DID
 * @param deps - Dependencies (repository)
 * @returns The submit work response with submission ID
 */
export async function submitWork(
  request: SubmitWorkRequest,
  context: SubmitWorkContext,
  deps: SubmitWorkDeps
): Promise<SubmitWorkResponse> {
  const generateId = deps.generateId ?? generateUUID;
  const now = deps.now ?? (() => new Date());

  // Validate request
  const parseResult = SubmitWorkRequestSchema.safeParse(request);
  if (!parseResult.success) {
    throw new SubmitWorkError(
      "Invalid submit work request",
      "VALIDATION_ERROR",
      { errors: parseResult.error.issues }
    );
  }
  const validatedRequest = parseResult.data;

  // Check idempotency - return existing submission if already processed
  if (validatedRequest.idempotency_key) {
    const existingSubmission = await deps.bountyRepository.findSubmissionByIdempotencyKey(
      validatedRequest.idempotency_key
    );
    if (existingSubmission) {
      return {
        schema_version: "1",
        submission_id: existingSubmission.submission_id,
        bounty_id: existingSubmission.bounty_id,
        status: "pending_review",
        submitted_at: existingSubmission.submitted_at,
        proof_bundle_hash: existingSubmission.proof_bundle.hash,
        proof_tier: existingSubmission.proof_tier,
      };
    }
  }

  // Find bounty
  const bounty = await deps.bountyRepository.findById(validatedRequest.bounty_id);
  if (!bounty) {
    throw new SubmitWorkError(
      "Bounty not found",
      "BOUNTY_NOT_FOUND",
      { bounty_id: validatedRequest.bounty_id }
    );
  }

  // Verify bounty is in accepted state
  if (bounty.status !== "accepted") {
    throw new SubmitWorkError(
      `Cannot submit work: bounty status is '${bounty.status}', expected 'accepted'`,
      "BOUNTY_NOT_ACCEPTED",
      { bounty_id: bounty.bounty_id, status: bounty.status }
    );
  }

  // Verify the submitter is the agent who accepted the bounty
  if (bounty.accepted_by !== context.agentDid) {
    throw new SubmitWorkError(
      "Only the agent who accepted the bounty can submit work",
      "UNAUTHORIZED_SUBMITTER",
      {
        bounty_id: bounty.bounty_id,
        accepted_by: bounty.accepted_by,
        submitter: context.agentDid,
      }
    );
  }

  // Verify signature envelope signer matches the agent
  if (validatedRequest.signature_envelope.signer_did !== context.agentDid) {
    throw new SubmitWorkError(
      "Signature envelope signer must match the submitting agent",
      "SIGNER_MISMATCH",
      {
        signer_did: validatedRequest.signature_envelope.signer_did,
        agent_did: context.agentDid,
      }
    );
  }

  // Generate submission ID and timestamp
  const submissionId = generateId();
  const submittedAt = now().toISOString();

  // Classify proof tier from provided receipts/attestations
  const proofTier = classifyProofTier(validatedRequest.proof_evidence);

  // Build submission record
  const submission: Submission = {
    schema_version: "1",
    submission_id: submissionId,
    bounty_id: bounty.bounty_id,
    agent_did: context.agentDid,
    output: validatedRequest.output,
    signature_envelope: validatedRequest.signature_envelope,
    proof_bundle: validatedRequest.proof_bundle,
    proof_tier: proofTier,
    proof_evidence: validatedRequest.proof_evidence,
    submitted_at: submittedAt,
    idempotency_key: validatedRequest.idempotency_key,
  };

  // Update bounty status to pending_review
  const updatedBounty: Bounty = {
    ...bounty,
    status: "pending_review",
  };

  await deps.bountyRepository.save(updatedBounty);
  await deps.bountyRepository.saveSubmission(submission);

  // Return response
  return {
    schema_version: "1",
    submission_id: submissionId,
    bounty_id: bounty.bounty_id,
    status: "pending_review",
    submitted_at: submittedAt,
    proof_bundle_hash: validatedRequest.proof_bundle.hash,
    proof_tier: proofTier,
  };
}
