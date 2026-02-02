/**
 * @clawbureau/escrow
 *
 * Escrow service for agent work - holds/releases/milestones.
 * Part of the Economy & Settlement pillar.
 */

export { EscrowService, EscrowError } from './escrow-service.js';
export type { EscrowServiceConfig } from './escrow-service.js';
export type {
  Escrow,
  EscrowStatus,
  Milestone,
  MilestoneStatus,
  CreateEscrowRequest,
  CreateEscrowResult,
  ReleaseEscrowRequest,
  ReleaseEscrowResult,
  LedgerClient,
  LedgerClientV2,
  LedgerHoldResult,
  LedgerTransferResult,
  EscrowStore,
  WebhookEmitter,
  WebhookEvent,
  WebhookEventType,
} from './types.js';
