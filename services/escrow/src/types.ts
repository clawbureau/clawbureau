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
