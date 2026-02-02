/**
 * Escrow Service
 *
 * Handles escrow creation, holds, releases, and disputes for agent work.
 */

import { v4 as uuidv4 } from 'uuid';
import type {
  CreateEscrowRequest,
  CreateEscrowResult,
  Dispute,
  DisputeEscrowRequest,
  DisputeEscrowResult,
  DisputeStore,
  EscalateDisputeRequest,
  EscalateDisputeResult,
  Escrow,
  EscrowStore,
  LedgerClient,
  LedgerClientV2,
  Milestone,
  ReleaseEscrowRequest,
  ReleaseEscrowResult,
  TrialsClient,
  WebhookEmitter,
  WebhookEvent,
} from './types.js';

export interface EscrowServiceConfig {
  store: EscrowStore;
  ledger: LedgerClient | LedgerClientV2;
  webhookEmitter?: WebhookEmitter;
  disputeStore?: DisputeStore;
  trialsClient?: TrialsClient;
}

export class EscrowService {
  private readonly store: EscrowStore;
  private readonly ledger: LedgerClient | LedgerClientV2;
  private readonly webhookEmitter?: WebhookEmitter;
  private readonly disputeStore?: DisputeStore;
  private readonly trialsClient?: TrialsClient;

  constructor(config: EscrowServiceConfig) {
    this.store = config.store;
    this.ledger = config.ledger;
    this.webhookEmitter = config.webhookEmitter;
    this.disputeStore = config.disputeStore;
    this.trialsClient = config.trialsClient;
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
   * CES-US-003: Dispute escrow
   *
   * Initiates a dispute on an escrow, freezing funds and starting the dispute process.
   *
   * Acceptance Criteria:
   * - Configurable dispute window (via dispute_window_hours on escrow)
   * - Freeze escrow on dispute
   * - Escalate to trials (via escalateDispute method)
   */
  async disputeEscrow(request: DisputeEscrowRequest): Promise<DisputeEscrowResult> {
    // Validate escrow exists
    const escrow = await this.store.get(request.escrow_id);
    if (!escrow) {
      throw new EscrowError('ESCROW_NOT_FOUND', `Escrow ${request.escrow_id} not found`);
    }

    // Only requester or agent can dispute
    const isParty =
      request.disputed_by_did === escrow.requester_did ||
      request.disputed_by_did === escrow.agent_did;
    if (!isParty) {
      throw new EscrowError(
        'UNAUTHORIZED',
        'Only the requester or agent can dispute an escrow'
      );
    }

    // Only held escrows can be disputed
    if (escrow.status !== 'held') {
      throw new EscrowError(
        'INVALID_STATUS',
        `Cannot dispute escrow in status '${escrow.status}'. Must be 'held'.`
      );
    }

    // Check if within dispute window (if escrow was released, check held_at)
    if (escrow.held_at) {
      const heldAt = new Date(escrow.held_at);
      const disputeWindowMs = (escrow.dispute_window_hours ?? 72) * 60 * 60 * 1000;
      const windowEnd = new Date(heldAt.getTime() + disputeWindowMs);
      const now = new Date();

      if (now > windowEnd) {
        throw new EscrowError(
          'DISPUTE_WINDOW_EXPIRED',
          `Dispute window expired at ${windowEnd.toISOString()}`
        );
      }
    }

    // Require dispute store for dispute operations
    if (!this.disputeStore) {
      throw new EscrowError(
        'DISPUTE_STORE_REQUIRED',
        'Dispute store is required for dispute operations'
      );
    }

    const now = new Date().toISOString();
    const dispute_id = `dsp_${uuidv4()}`;

    // Create dispute record
    const dispute: Dispute = {
      dispute_id,
      escrow_id: escrow.escrow_id,
      disputed_by_did: request.disputed_by_did,
      reason: request.reason,
      description: request.description,
      evidence_urls: request.evidence_urls,
      status: 'open',
      created_at: now,
      updated_at: now,
    };

    await this.disputeStore.saveDispute(dispute);

    // Freeze escrow (change status to frozen)
    const frozenEscrow: Escrow = {
      ...escrow,
      status: 'frozen',
      updated_at: now,
    };

    await this.store.save(frozenEscrow);

    // Emit webhook
    let webhookSent = false;
    if (this.webhookEmitter) {
      const webhookEvent: WebhookEvent = {
        event_id: `evt_${uuidv4()}`,
        event_type: 'escrow.disputed',
        escrow_id: escrow.escrow_id,
        timestamp: now,
        payload: {
          escrow_id: escrow.escrow_id,
          dispute_id,
          requester_did: escrow.requester_did,
          agent_did: escrow.agent_did,
          disputed_by_did: request.disputed_by_did,
          reason: request.reason,
          amount: escrow.amount,
          currency: escrow.currency,
        },
      };

      const webhookResult = await this.webhookEmitter.emit(webhookEvent);
      webhookSent = webhookResult.sent;
    }

    return {
      escrow_id: escrow.escrow_id,
      escrow: frozenEscrow,
      dispute_id,
      disputed_at: now,
      frozen: true,
      webhook_sent: webhookSent,
    };
  }

  /**
   * CES-US-003: Escalate dispute to trials
   *
   * Escalates an open dispute to the trials service for resolution.
   */
  async escalateDispute(request: EscalateDisputeRequest): Promise<EscalateDisputeResult> {
    // Validate escrow exists
    const escrow = await this.store.get(request.escrow_id);
    if (!escrow) {
      throw new EscrowError('ESCROW_NOT_FOUND', `Escrow ${request.escrow_id} not found`);
    }

    // Require dispute store
    if (!this.disputeStore) {
      throw new EscrowError(
        'DISPUTE_STORE_REQUIRED',
        'Dispute store is required for dispute operations'
      );
    }

    // Validate dispute exists
    const dispute = await this.disputeStore.getDispute(request.dispute_id);
    if (!dispute) {
      throw new EscrowError('DISPUTE_NOT_FOUND', `Dispute ${request.dispute_id} not found`);
    }

    // Validate dispute belongs to escrow
    if (dispute.escrow_id !== request.escrow_id) {
      throw new EscrowError(
        'DISPUTE_MISMATCH',
        `Dispute ${request.dispute_id} does not belong to escrow ${request.escrow_id}`
      );
    }

    // Only parties can escalate
    const isParty =
      request.escalated_by_did === escrow.requester_did ||
      request.escalated_by_did === escrow.agent_did;
    if (!isParty) {
      throw new EscrowError(
        'UNAUTHORIZED',
        'Only the requester or agent can escalate a dispute'
      );
    }

    // Only open disputes can be escalated
    if (dispute.status !== 'open') {
      throw new EscrowError(
        'INVALID_STATUS',
        `Cannot escalate dispute in status '${dispute.status}'. Must be 'open'.`
      );
    }

    // Require trials client for escalation
    if (!this.trialsClient) {
      throw new EscrowError(
        'TRIALS_CLIENT_REQUIRED',
        'Trials client is required for dispute escalation'
      );
    }

    const now = new Date().toISOString();

    // Create case in trials service
    const trialsResult = await this.trialsClient.createCase({
      escrow_id: escrow.escrow_id,
      dispute_id: dispute.dispute_id,
      requester_did: escrow.requester_did,
      agent_did: escrow.agent_did,
      disputed_by_did: dispute.disputed_by_did,
      reason: dispute.reason,
      description: dispute.description,
      evidence_urls: dispute.evidence_urls,
      amount: escrow.amount,
      currency: escrow.currency,
      escalation_notes: request.escalation_notes,
    });

    if (!trialsResult.success) {
      throw new EscrowError(
        'ESCALATION_FAILED',
        trialsResult.error ?? 'Failed to escalate dispute to trials service'
      );
    }

    // Update dispute status
    const updatedDispute: Dispute = {
      ...dispute,
      status: 'escalated',
      escalated_at: now,
      updated_at: now,
    };

    await this.disputeStore.saveDispute(updatedDispute);

    // Emit webhook (reusing 'escrow.disputed' event type with escalation info)
    let webhookSent = false;
    if (this.webhookEmitter) {
      const webhookEvent: WebhookEvent = {
        event_id: `evt_${uuidv4()}`,
        event_type: 'escrow.disputed',
        escrow_id: escrow.escrow_id,
        timestamp: now,
        payload: {
          escrow_id: escrow.escrow_id,
          dispute_id: dispute.dispute_id,
          escalated: true,
          escalated_by_did: request.escalated_by_did,
          trials_case_id: trialsResult.case_id,
          amount: escrow.amount,
          currency: escrow.currency,
        },
      };

      const webhookResult = await this.webhookEmitter.emit(webhookEvent);
      webhookSent = webhookResult.sent;
    }

    return {
      escrow_id: escrow.escrow_id,
      dispute_id: dispute.dispute_id,
      escalated_at: now,
      trials_case_id: trialsResult.case_id!,
      webhook_sent: webhookSent,
    };
  }

  /**
   * Get a dispute by ID
   */
  async getDispute(dispute_id: string): Promise<Dispute | null> {
    if (!this.disputeStore) {
      throw new EscrowError(
        'DISPUTE_STORE_REQUIRED',
        'Dispute store is required for dispute operations'
      );
    }
    return this.disputeStore.getDispute(dispute_id);
  }

  /**
   * Get the dispute for an escrow (if any)
   */
  async getDisputeByEscrowId(escrow_id: string): Promise<Dispute | null> {
    if (!this.disputeStore) {
      throw new EscrowError(
        'DISPUTE_STORE_REQUIRED',
        'Dispute store is required for dispute operations'
      );
    }
    return this.disputeStore.getDisputeByEscrowId(escrow_id);
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
