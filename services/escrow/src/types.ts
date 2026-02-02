/**
 * Escrow Types v1
 *
 * Core type definitions for the escrow service.
 * These types mirror the JSON schema in packages/schema/escrow/escrow.v1.json
 */

export type EscrowStatus =
  | 'pending'
  | 'held'
  | 'released'
  | 'disputed'
  | 'cancelled'
  | 'frozen';

export type MilestoneStatus = 'pending' | 'released' | 'disputed';

export interface Milestone {
  milestone_id: string;
  amount: number;
  description: string;
  status: MilestoneStatus;
  released_at?: string;
}

export interface Escrow {
  escrow_version: '1';
  escrow_id: string;
  requester_did: string;
  agent_did: string;
  amount: number;
  currency: string;
  status: EscrowStatus;
  created_at: string;
  updated_at?: string;
  held_at?: string;
  released_at?: string;
  dispute_window_hours?: number;
  metadata?: Record<string, unknown>;
  terms?: string;
  job_id?: string;
  milestones?: Milestone[];
}

export interface CreateEscrowRequest {
  requester_did: string;
  agent_did: string;
  amount: number;
  currency?: string;
  metadata?: Record<string, unknown>;
  terms?: string;
  job_id?: string;
  dispute_window_hours?: number;
  milestones?: Array<{
    amount: number;
    description: string;
  }>;
}

export interface CreateEscrowResult {
  escrow_id: string;
  escrow: Escrow;
  balance_reduced: boolean;
  hold_event_id?: string;
}

export interface LedgerHoldResult {
  success: boolean;
  hold_event_id?: string;
  error?: string;
  new_balance?: number;
}

/**
 * Interface for the ledger service client.
 * The escrow service depends on clawledger for balance operations.
 */
export interface LedgerClient {
  /**
   * Create a hold on funds in the requester's account.
   */
  createHold(params: {
    account_did: string;
    amount: number;
    currency: string;
    reference_id: string;
    reference_type: 'escrow';
    idempotency_key: string;
  }): Promise<LedgerHoldResult>;
}

export interface EscrowStore {
  save(escrow: Escrow): Promise<void>;
  get(escrow_id: string): Promise<Escrow | null>;
  list(filters?: { requester_did?: string; agent_did?: string; status?: EscrowStatus }): Promise<Escrow[]>;
}

/**
 * CES-US-002: Release escrow types
 */

export interface ReleaseEscrowRequest {
  escrow_id: string;
  /** DID of the party authorizing the release (must be requester) */
  authorized_by_did: string;
  /** Optional reason/note for the release */
  reason?: string;
}

export interface ReleaseEscrowResult {
  escrow_id: string;
  escrow: Escrow;
  transfer_event_id: string;
  amount_released: number;
  webhook_sent: boolean;
}

export interface LedgerTransferResult {
  success: boolean;
  transfer_event_id?: string;
  error?: string;
  new_balance?: number;
}

/**
 * Extended ledger client interface with transfer capability
 */
export interface LedgerClientV2 extends LedgerClient {
  /**
   * Release a hold and transfer funds to the recipient.
   */
  releaseHoldAndTransfer(params: {
    from_account_did: string;
    to_account_did: string;
    amount: number;
    currency: string;
    reference_id: string;
    reference_type: 'escrow_release';
    idempotency_key: string;
  }): Promise<LedgerTransferResult>;
}

/**
 * Webhook event types for escrow service
 */
export type WebhookEventType =
  | 'escrow.created'
  | 'escrow.released'
  | 'escrow.disputed'
  | 'escrow.cancelled'
  | 'escrow.milestone_released';

export interface WebhookEvent {
  event_id: string;
  event_type: WebhookEventType;
  escrow_id: string;
  timestamp: string;
  payload: Record<string, unknown>;
}

/**
 * Interface for webhook emitter
 */
export interface WebhookEmitter {
  emit(event: WebhookEvent): Promise<{ sent: boolean; error?: string }>;
}

/**
 * CES-US-003: Dispute window types
 */

export type DisputeReason =
  | 'work_not_delivered'
  | 'work_incomplete'
  | 'work_unsatisfactory'
  | 'fraud'
  | 'other';

export interface DisputeEscrowRequest {
  escrow_id: string;
  /** DID of the party initiating the dispute (must be requester or agent) */
  disputed_by_did: string;
  /** Reason for the dispute */
  reason: DisputeReason;
  /** Detailed description of the dispute */
  description: string;
  /** Optional evidence/documentation URLs */
  evidence_urls?: string[];
}

export interface DisputeEscrowResult {
  escrow_id: string;
  escrow: Escrow;
  dispute_id: string;
  disputed_at: string;
  frozen: boolean;
  webhook_sent: boolean;
}

export interface Dispute {
  dispute_id: string;
  escrow_id: string;
  disputed_by_did: string;
  reason: DisputeReason;
  description: string;
  evidence_urls?: string[];
  status: DisputeStatus;
  created_at: string;
  updated_at: string;
  escalated_at?: string;
  resolved_at?: string;
  resolution?: DisputeResolution;
}

export type DisputeStatus =
  | 'open'
  | 'escalated'
  | 'resolved';

export type DisputeResolution =
  | 'released_to_agent'
  | 'returned_to_requester'
  | 'split'
  | 'cancelled';

export interface EscalateDisputeRequest {
  escrow_id: string;
  dispute_id: string;
  /** DID of the party escalating (must be party to the dispute) */
  escalated_by_did: string;
  /** Additional notes for the trials service */
  escalation_notes?: string;
}

export interface EscalateDisputeResult {
  escrow_id: string;
  dispute_id: string;
  escalated_at: string;
  trials_case_id: string;
  webhook_sent: boolean;
}

/**
 * Interface for trials service client (for dispute escalation)
 */
export interface TrialsClient {
  /**
   * Create a case in the trials service for dispute resolution
   */
  createCase(params: {
    escrow_id: string;
    dispute_id: string;
    requester_did: string;
    agent_did: string;
    disputed_by_did: string;
    reason: DisputeReason;
    description: string;
    evidence_urls?: string[];
    amount: number;
    currency: string;
    escalation_notes?: string;
  }): Promise<TrialsCaseResult>;
}

export interface TrialsCaseResult {
  success: boolean;
  case_id?: string;
  error?: string;
}

/**
 * Extended store interface with dispute storage
 */
export interface DisputeStore {
  saveDispute(dispute: Dispute): Promise<void>;
  getDispute(dispute_id: string): Promise<Dispute | null>;
  getDisputeByEscrowId(escrow_id: string): Promise<Dispute | null>;
}

/**
 * CES-US-004: Milestone payout types
 */

export interface ReleaseMilestoneRequest {
  escrow_id: string;
  milestone_id: string;
  /** DID of the party authorizing the release (must be requester) */
  authorized_by_did: string;
  /** Optional reason/note for the milestone release */
  reason?: string;
}

export interface ReleaseMilestoneResult {
  escrow_id: string;
  escrow: Escrow;
  milestone_id: string;
  amount_released: number;
  transfer_event_id: string;
  /** Total amount remaining in escrow */
  remaining_amount: number;
  /** Number of milestones still pending */
  remaining_milestones: number;
  /** Whether all milestones have been released */
  all_milestones_released: boolean;
  webhook_sent: boolean;
}

/**
 * Extended ledger client interface with partial release capability
 */
export interface LedgerClientV3 extends LedgerClientV2 {
  /**
   * Release a partial hold and transfer funds to the recipient.
   * Used for milestone-based releases.
   */
  releasePartialHoldAndTransfer(params: {
    from_account_did: string;
    to_account_did: string;
    amount: number;
    currency: string;
    reference_id: string;
    reference_type: 'escrow_milestone_release';
    original_hold_reference_id: string;
    idempotency_key: string;
  }): Promise<LedgerTransferResult>;
}
