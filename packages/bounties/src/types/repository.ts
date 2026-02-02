import { Bounty, AcceptanceReceipt, Submission } from "./bounty.js";

/**
 * Repository interface for bounty persistence
 */
export interface BountyRepository {
  save(bounty: Bounty): Promise<void>;
  findById(bountyId: string): Promise<Bounty | null>;
  findByIdempotencyKey(key: string): Promise<Bounty | null>;
  findAcceptanceByIdempotencyKey(key: string): Promise<AcceptanceReceipt | null>;
  saveAcceptance(receipt: AcceptanceReceipt): Promise<void>;
  findSubmissionByIdempotencyKey(key: string): Promise<Submission | null>;
  saveSubmission(submission: Submission): Promise<void>;
}
