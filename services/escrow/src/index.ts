/**
 * @clawbureau/escrow
 *
 * Escrow service for agent work - holds/releases/milestones.
 * Part of the Economy & Settlement pillar.
 */

export { EscrowService, EscrowError } from './escrow-service.js';
export type {
  Escrow,
  EscrowStatus,
  Milestone,
  MilestoneStatus,
  CreateEscrowRequest,
  CreateEscrowResult,
  LedgerClient,
  LedgerHoldResult,
  EscrowStore,
} from './types.js';
