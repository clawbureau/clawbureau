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
