/**
 * Escrow Service
 *
 * Handles escrow creation, holds, releases, and disputes for agent work.
 */

import { v4 as uuidv4 } from 'uuid';
import type {
  AuditLogEntry,
  AuditLogger,
  CancelEscrowRequest,
  CancelEscrowResult,
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
  GetEscrowStatusResponse,
  LedgerClient,
  LedgerClientV2,
  LedgerClientV3,
  LedgerClientV4,
  Milestone,
  ReleaseEscrowRequest,
  ReleaseEscrowResult,
  ReleaseMilestoneRequest,
  ReleaseMilestoneResult,
  TrialsClient,
  WebhookEmitter,
  WebhookEvent,
} from './types.js';

export interface EscrowServiceConfig {
  store: EscrowStore;
  ledger: LedgerClient | LedgerClientV2 | LedgerClientV3 | LedgerClientV4;
  webhookEmitter?: WebhookEmitter;
  disputeStore?: DisputeStore;
  trialsClient?: TrialsClient;
  auditLogger?: AuditLogger;
}

export class EscrowService {
  private readonly store: EscrowStore;
  private readonly ledger: LedgerClient | LedgerClientV2 | LedgerClientV3 | LedgerClientV4;
  private readonly webhookEmitter?: WebhookEmitter;
  private readonly disputeStore?: DisputeStore;
  private readonly trialsClient?: TrialsClient;
  private readonly auditLogger?: AuditLogger;

  constructor(config: EscrowServiceConfig) {
    this.store = config.store;
    this.ledger = config.ledger;
    this.webhookEmitter = config.webhookEmitter;
    this.disputeStore = config.disputeStore;
    this.trialsClient = config.trialsClient;
    this.auditLogger = config.auditLogger;
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
   * CES-US-006: Escrow status API
   *
   * Returns the status of an escrow with all relevant timestamps and progress.
   *
   * Acceptance Criteria:
   * - GET /escrow/{id} (provides data for endpoint)
   * - Status states (returns current status)
   * - Include timestamps (all relevant timestamps)
   */
  async getEscrowStatus(escrow_id: string): Promise<GetEscrowStatusResponse | null> {
    const escrow = await this.store.get(escrow_id);
    if (!escrow) {
      return null;
    }

    // Calculate dispute window expiration
    const disputeWindowHours = escrow.dispute_window_hours ?? 72;
    let disputeWindowExpired = false;
    let disputeWindowExpiresAt: string | undefined;

    if (escrow.held_at) {
      const heldAt = new Date(escrow.held_at);
      const disputeWindowMs = disputeWindowHours * 60 * 60 * 1000;
      const windowEnd = new Date(heldAt.getTime() + disputeWindowMs);
      disputeWindowExpiresAt = windowEnd.toISOString();
      disputeWindowExpired = new Date() > windowEnd;
    }

    // Check for dispute
    let hasDispute = false;
    let disputeId: string | undefined;

    if (this.disputeStore) {
      const dispute = await this.disputeStore.getDisputeByEscrowId(escrow_id);
      if (dispute) {
        hasDispute = true;
        disputeId = dispute.dispute_id;
      }
    }

    // Calculate milestone summary if milestones exist
    let milestones: GetEscrowStatusResponse['milestones'];

    if (escrow.milestones && escrow.milestones.length > 0) {
      const releasedMilestones = escrow.milestones.filter((m) => m.status === 'released');
      const pendingMilestones = escrow.milestones.filter((m) => m.status === 'pending');
      const disputedMilestones = escrow.milestones.filter((m) => m.status === 'disputed');
      const releasedAmount = releasedMilestones.reduce((sum, m) => sum + m.amount, 0);

      milestones = {
        total_milestones: escrow.milestones.length,
        pending_milestones: pendingMilestones.length,
        released_milestones: releasedMilestones.length,
        disputed_milestones: disputedMilestones.length,
        total_amount: escrow.amount,
        released_amount: releasedAmount,
        remaining_amount: escrow.amount - releasedAmount,
      };
    }

    return {
      escrow_id: escrow.escrow_id,
      status: escrow.status,
      requester_did: escrow.requester_did,
      agent_did: escrow.agent_did,
      amount: escrow.amount,
      currency: escrow.currency,
      timestamps: {
        created_at: escrow.created_at,
        updated_at: escrow.updated_at,
        held_at: escrow.held_at,
        released_at: escrow.released_at,
      },
      dispute_window_hours: disputeWindowHours,
      dispute_window_expired: disputeWindowExpired,
      dispute_window_expires_at: disputeWindowExpiresAt,
      job_id: escrow.job_id,
      milestones,
      has_dispute: hasDispute,
      dispute_id: disputeId,
    };
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
   * CES-US-004: Release milestone
   *
   * Releases funds for a specific milestone to the agent.
   * Supports partial releases and tracks remaining balance.
   *
   * Acceptance Criteria:
   * - Define milestones (done in createEscrow)
   * - Partial releases
   * - Track remaining
   */
  async releaseMilestone(request: ReleaseMilestoneRequest): Promise<ReleaseMilestoneResult> {
    // Validate escrow exists
    const escrow = await this.store.get(request.escrow_id);
    if (!escrow) {
      throw new EscrowError('ESCROW_NOT_FOUND', `Escrow ${request.escrow_id} not found`);
    }

    // Only requester can release funds
    if (request.authorized_by_did !== escrow.requester_did) {
      throw new EscrowError(
        'UNAUTHORIZED',
        'Only the requester can release milestone funds'
      );
    }

    // Only held escrows can have milestones released
    if (escrow.status !== 'held') {
      throw new EscrowError(
        'INVALID_STATUS',
        `Cannot release milestone for escrow in status '${escrow.status}'. Must be 'held'.`
      );
    }

    // Escrow must have milestones defined
    if (!escrow.milestones || escrow.milestones.length === 0) {
      throw new EscrowError(
        'NO_MILESTONES',
        'Escrow does not have milestones defined'
      );
    }

    // Find the milestone
    const milestoneIndex = escrow.milestones.findIndex(
      (m) => m.milestone_id === request.milestone_id
    );
    if (milestoneIndex === -1) {
      throw new EscrowError(
        'MILESTONE_NOT_FOUND',
        `Milestone ${request.milestone_id} not found in escrow ${request.escrow_id}`
      );
    }

    const milestone = escrow.milestones[milestoneIndex];

    // Milestone must be pending
    if (milestone.status !== 'pending') {
      throw new EscrowError(
        'MILESTONE_INVALID_STATUS',
        `Milestone ${request.milestone_id} is already '${milestone.status}'`
      );
    }

    // Check ledger supports partial release
    if (!this.isLedgerV3(this.ledger)) {
      throw new EscrowError(
        'LEDGER_UNSUPPORTED',
        'Ledger client does not support partial release operations (milestone payouts)'
      );
    }

    const now = new Date().toISOString();
    const idempotency_key = `escrow_milestone_release_${escrow.escrow_id}_${milestone.milestone_id}`;

    // Release partial hold and transfer to agent
    const transferResult = await this.ledger.releasePartialHoldAndTransfer({
      from_account_did: escrow.requester_did,
      to_account_did: escrow.agent_did,
      amount: milestone.amount,
      currency: escrow.currency,
      reference_id: milestone.milestone_id,
      reference_type: 'escrow_milestone_release',
      original_hold_reference_id: escrow.escrow_id,
      idempotency_key,
    });

    if (!transferResult.success) {
      throw new EscrowError(
        'TRANSFER_FAILED',
        transferResult.error ?? 'Failed to transfer milestone funds to agent'
      );
    }

    // Update milestone status
    const updatedMilestones: Milestone[] = escrow.milestones.map((m, idx) =>
      idx === milestoneIndex
        ? { ...m, status: 'released' as const, released_at: now }
        : m
    );

    // Calculate remaining
    const releasedMilestones = updatedMilestones.filter((m) => m.status === 'released');
    const pendingMilestones = updatedMilestones.filter((m) => m.status === 'pending');
    const releasedAmount = releasedMilestones.reduce((sum, m) => sum + m.amount, 0);
    const remainingAmount = escrow.amount - releasedAmount;
    const allMilestonesReleased = pendingMilestones.length === 0;

    // Update escrow (set to released if all milestones done)
    const updatedEscrow: Escrow = {
      ...escrow,
      milestones: updatedMilestones,
      status: allMilestonesReleased ? 'released' : 'held',
      updated_at: now,
      released_at: allMilestonesReleased ? now : escrow.released_at,
    };

    await this.store.save(updatedEscrow);

    // Emit webhook
    let webhookSent = false;
    if (this.webhookEmitter) {
      const webhookEvent: WebhookEvent = {
        event_id: `evt_${uuidv4()}`,
        event_type: 'escrow.milestone_released',
        escrow_id: escrow.escrow_id,
        timestamp: now,
        payload: {
          escrow_id: escrow.escrow_id,
          milestone_id: milestone.milestone_id,
          requester_did: escrow.requester_did,
          agent_did: escrow.agent_did,
          amount_released: milestone.amount,
          remaining_amount: remainingAmount,
          remaining_milestones: pendingMilestones.length,
          all_milestones_released: allMilestonesReleased,
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
      milestone_id: milestone.milestone_id,
      amount_released: milestone.amount,
      transfer_event_id: transferResult.transfer_event_id!,
      remaining_amount: remainingAmount,
      remaining_milestones: pendingMilestones.length,
      all_milestones_released: allMilestonesReleased,
      webhook_sent: webhookSent,
    };
  }

  /**
   * Get milestones for an escrow with their current status and remaining balance
   */
  async getMilestoneStatus(escrow_id: string): Promise<{
    milestones: Milestone[];
    total_amount: number;
    released_amount: number;
    remaining_amount: number;
    pending_milestones: number;
    released_milestones: number;
  } | null> {
    const escrow = await this.store.get(escrow_id);
    if (!escrow) {
      return null;
    }

    if (!escrow.milestones || escrow.milestones.length === 0) {
      return {
        milestones: [],
        total_amount: escrow.amount,
        released_amount: 0,
        remaining_amount: escrow.amount,
        pending_milestones: 0,
        released_milestones: 0,
      };
    }

    const releasedMilestones = escrow.milestones.filter((m) => m.status === 'released');
    const pendingMilestones = escrow.milestones.filter((m) => m.status === 'pending');
    const releasedAmount = releasedMilestones.reduce((sum, m) => sum + m.amount, 0);

    return {
      milestones: escrow.milestones,
      total_amount: escrow.amount,
      released_amount: releasedAmount,
      remaining_amount: escrow.amount - releasedAmount,
      pending_milestones: pendingMilestones.length,
      released_milestones: releasedMilestones.length,
    };
  }

  /**
   * CES-US-005: Cancel escrow
   *
   * Cancels an escrow if no work has been submitted, releasing the hold back to the requester.
   *
   * Acceptance Criteria:
   * - Cancel if no submission (must be in 'held' status, not disputed/frozen)
   * - Release hold (return funds to requester)
   * - Audit log entry
   */
  async cancelEscrow(request: CancelEscrowRequest): Promise<CancelEscrowResult> {
    // Validate escrow exists
    const escrow = await this.store.get(request.escrow_id);
    if (!escrow) {
      throw new EscrowError('ESCROW_NOT_FOUND', `Escrow ${request.escrow_id} not found`);
    }

    // Only requester can cancel escrow
    if (request.cancelled_by_did !== escrow.requester_did) {
      throw new EscrowError(
        'UNAUTHORIZED',
        'Only the requester can cancel an escrow'
      );
    }

    // Only held escrows can be cancelled (not disputed, frozen, released, etc.)
    if (escrow.status !== 'held') {
      throw new EscrowError(
        'INVALID_STATUS',
        `Cannot cancel escrow in status '${escrow.status}'. Must be 'held'.`
      );
    }

    // Check if escrow has any released milestones (partial work done)
    if (escrow.milestones && escrow.milestones.some((m) => m.status === 'released')) {
      throw new EscrowError(
        'PARTIAL_RELEASE',
        'Cannot cancel escrow with released milestones. Use dispute process instead.'
      );
    }

    // Check ledger supports hold release
    if (!this.isLedgerV4(this.ledger)) {
      throw new EscrowError(
        'LEDGER_UNSUPPORTED',
        'Ledger client does not support hold release operations (cancellation)'
      );
    }

    const now = new Date().toISOString();
    const idempotency_key = `escrow_cancel_${escrow.escrow_id}`;

    // Release hold back to requester
    const releaseResult = await this.ledger.releaseHold({
      account_did: escrow.requester_did,
      amount: escrow.amount,
      currency: escrow.currency,
      reference_id: escrow.escrow_id,
      reference_type: 'escrow_cancellation',
      idempotency_key,
    });

    if (!releaseResult.success) {
      throw new EscrowError(
        'RELEASE_FAILED',
        releaseResult.error ?? 'Failed to release hold on funds'
      );
    }

    // Update escrow status
    const updatedEscrow: Escrow = {
      ...escrow,
      status: 'cancelled',
      updated_at: now,
    };

    await this.store.save(updatedEscrow);

    // Create audit log entry
    let auditLogged = false;
    if (this.auditLogger) {
      const auditEntry: AuditLogEntry = {
        entry_id: `aud_${uuidv4()}`,
        action: 'escrow.cancelled',
        escrow_id: escrow.escrow_id,
        actor_did: request.cancelled_by_did,
        timestamp: now,
        details: {
          amount: escrow.amount,
          currency: escrow.currency,
          agent_did: escrow.agent_did,
          reason: request.reason,
          release_event_id: releaseResult.release_event_id,
        },
      };

      const auditResult = await this.auditLogger.log(auditEntry);
      auditLogged = auditResult.logged;
    }

    // Emit webhook
    let webhookSent = false;
    if (this.webhookEmitter) {
      const webhookEvent: WebhookEvent = {
        event_id: `evt_${uuidv4()}`,
        event_type: 'escrow.cancelled',
        escrow_id: escrow.escrow_id,
        timestamp: now,
        payload: {
          escrow_id: escrow.escrow_id,
          requester_did: escrow.requester_did,
          agent_did: escrow.agent_did,
          amount: escrow.amount,
          currency: escrow.currency,
          release_event_id: releaseResult.release_event_id,
          reason: request.reason,
        },
      };

      const webhookResult = await this.webhookEmitter.emit(webhookEvent);
      webhookSent = webhookResult.sent;
    }

    return {
      escrow_id: escrow.escrow_id,
      escrow: updatedEscrow,
      hold_released: true,
      release_event_id: releaseResult.release_event_id,
      audit_logged: auditLogged,
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
  private isLedgerV2(ledger: LedgerClient | LedgerClientV2 | LedgerClientV3 | LedgerClientV4): ledger is LedgerClientV2 {
    return 'releaseHoldAndTransfer' in ledger;
  }

  /**
   * Type guard to check if ledger supports V3 operations (partial releases)
   */
  private isLedgerV3(ledger: LedgerClient | LedgerClientV2 | LedgerClientV3 | LedgerClientV4): ledger is LedgerClientV3 {
    return 'releasePartialHoldAndTransfer' in ledger;
  }

  /**
   * Type guard to check if ledger supports V4 operations (hold release for cancellation)
   */
  private isLedgerV4(ledger: LedgerClient | LedgerClientV2 | LedgerClientV3 | LedgerClientV4): ledger is LedgerClientV4 {
    return 'releaseHold' in ledger;
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
