/**
 * Escrow Service
 *
 * Handles escrow creation, holds, releases, and disputes for agent work.
 */

import { v4 as uuidv4 } from 'uuid';
import type {
  CreateEscrowRequest,
  CreateEscrowResult,
  Escrow,
  EscrowStore,
  LedgerClient,
  Milestone,
} from './types.js';

export class EscrowService {
  constructor(
    private readonly store: EscrowStore,
    private readonly ledger: LedgerClient
  ) {}

  /**
   * CES-US-001: Create escrow hold
   *
   * Creates a new escrow and places a hold on the requester's funds.
   *
   * Acceptance Criteria:
   * - Hold reduces balance
   * - Return escrow id
   * - Support metadata/terms
   */
  async createEscrow(request: CreateEscrowRequest): Promise<CreateEscrowResult> {
    // Validate request
    if (request.amount <= 0) {
      throw new EscrowError('INVALID_AMOUNT', 'Amount must be greater than 0');
    }

    if (!request.requester_did || !request.agent_did) {
      throw new EscrowError('INVALID_DID', 'Both requester_did and agent_did are required');
    }

    if (request.requester_did === request.agent_did) {
      throw new EscrowError('SAME_PARTY', 'Requester and agent cannot be the same');
    }

    // Generate escrow ID
    const escrow_id = `esc_${uuidv4()}`;
    const now = new Date().toISOString();

    // Generate idempotency key for ledger operation
    const idempotency_key = `escrow_hold_${escrow_id}`;

    // Create milestones if provided
    let milestones: Milestone[] | undefined;
    if (request.milestones && request.milestones.length > 0) {
      const milestonesTotal = request.milestones.reduce((sum, m) => sum + m.amount, 0);
      if (Math.abs(milestonesTotal - request.amount) > 0.001) {
        throw new EscrowError(
          'MILESTONE_MISMATCH',
          `Milestones total (${milestonesTotal}) must equal escrow amount (${request.amount})`
        );
      }

      milestones = request.milestones.map((m, idx) => ({
        milestone_id: `ms_${escrow_id}_${idx + 1}`,
        amount: m.amount,
        description: m.description,
        status: 'pending' as const,
      }));
    }

    // Create hold on ledger (reduces available balance)
    const holdResult = await this.ledger.createHold({
      account_did: request.requester_did,
      amount: request.amount,
      currency: request.currency ?? 'CLAW',
      reference_id: escrow_id,
      reference_type: 'escrow',
      idempotency_key,
    });

    if (!holdResult.success) {
      throw new EscrowError(
        'HOLD_FAILED',
        holdResult.error ?? 'Failed to create hold on funds'
      );
    }

    // Build escrow record
    const escrow: Escrow = {
      escrow_version: '1',
      escrow_id,
      requester_did: request.requester_did,
      agent_did: request.agent_did,
      amount: request.amount,
      currency: request.currency ?? 'CLAW',
      status: 'held',
      created_at: now,
      updated_at: now,
      held_at: now,
      dispute_window_hours: request.dispute_window_hours ?? 72,
      metadata: request.metadata,
      terms: request.terms,
      job_id: request.job_id,
      milestones,
    };

    // Persist escrow
    await this.store.save(escrow);

    return {
      escrow_id,
      escrow,
      balance_reduced: true,
      hold_event_id: holdResult.hold_event_id,
    };
  }

  /**
   * Get an escrow by ID
   */
  async getEscrow(escrow_id: string): Promise<Escrow | null> {
    return this.store.get(escrow_id);
  }
}

/**
 * Custom error class for escrow operations
 */
export class EscrowError extends Error {
  constructor(
    public readonly code: string,
    message: string
  ) {
    super(message);
    this.name = 'EscrowError';
  }
}
