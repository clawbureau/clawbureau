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
  LedgerClientV2,
  Milestone,
  ReleaseEscrowRequest,
  ReleaseEscrowResult,
  WebhookEmitter,
  WebhookEvent,
} from './types.js';

export interface EscrowServiceConfig {
  store: EscrowStore;
  ledger: LedgerClient | LedgerClientV2;
  webhookEmitter?: WebhookEmitter;
}

export class EscrowService {
  private readonly store: EscrowStore;
  private readonly ledger: LedgerClient | LedgerClientV2;
  private readonly webhookEmitter?: WebhookEmitter;

  constructor(config: EscrowServiceConfig) {
    this.store = config.store;
    this.ledger = config.ledger;
    this.webhookEmitter = config.webhookEmitter;
  }

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

  /**
   * CES-US-002: Release escrow
   *
   * Releases funds from escrow to the agent after work approval.
   *
   * Acceptance Criteria:
   * - Transfer to agent
   * - Record ledger event
   * - Emit webhook
   */
  async releaseEscrow(request: ReleaseEscrowRequest): Promise<ReleaseEscrowResult> {
    // Validate escrow exists
    const escrow = await this.store.get(request.escrow_id);
    if (!escrow) {
      throw new EscrowError('ESCROW_NOT_FOUND', `Escrow ${request.escrow_id} not found`);
    }

    // Only requester can release funds
    if (request.authorized_by_did !== escrow.requester_did) {
      throw new EscrowError(
        'UNAUTHORIZED',
        'Only the requester can release escrow funds'
      );
    }

    // Only held escrows can be released
    if (escrow.status !== 'held') {
      throw new EscrowError(
        'INVALID_STATUS',
        `Cannot release escrow in status '${escrow.status}'. Must be 'held'.`
      );
    }

    // Check ledger supports release
    if (!this.isLedgerV2(this.ledger)) {
      throw new EscrowError(
        'LEDGER_UNSUPPORTED',
        'Ledger client does not support release operations'
      );
    }

    const now = new Date().toISOString();
    const idempotency_key = `escrow_release_${escrow.escrow_id}`;

    // Release hold and transfer to agent
    const transferResult = await this.ledger.releaseHoldAndTransfer({
      from_account_did: escrow.requester_did,
      to_account_did: escrow.agent_did,
      amount: escrow.amount,
      currency: escrow.currency,
      reference_id: escrow.escrow_id,
      reference_type: 'escrow_release',
      idempotency_key,
    });

    if (!transferResult.success) {
      throw new EscrowError(
        'TRANSFER_FAILED',
        transferResult.error ?? 'Failed to transfer funds to agent'
      );
    }

    // Update escrow status
    const updatedEscrow: Escrow = {
      ...escrow,
      status: 'released',
      updated_at: now,
      released_at: now,
    };

    await this.store.save(updatedEscrow);

    // Emit webhook
    let webhookSent = false;
    if (this.webhookEmitter) {
      const webhookEvent: WebhookEvent = {
        event_id: `evt_${uuidv4()}`,
        event_type: 'escrow.released',
        escrow_id: escrow.escrow_id,
        timestamp: now,
        payload: {
          escrow_id: escrow.escrow_id,
          requester_did: escrow.requester_did,
          agent_did: escrow.agent_did,
          amount: escrow.amount,
          currency: escrow.currency,
          transfer_event_id: transferResult.transfer_event_id,
          reason: request.reason,
        },
      };

      const webhookResult = await this.webhookEmitter.emit(webhookEvent);
      webhookSent = webhookResult.sent;
    }

    return {
      escrow_id: escrow.escrow_id,
      escrow: updatedEscrow,
      transfer_event_id: transferResult.transfer_event_id!,
      amount_released: escrow.amount,
      webhook_sent: webhookSent,
    };
  }

  /**
   * Type guard to check if ledger supports V2 operations
   */
  private isLedgerV2(ledger: LedgerClient | LedgerClientV2): ledger is LedgerClientV2 {
    return 'releaseHoldAndTransfer' in ledger;
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
