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
  LedgerClientV3,
  LedgerClientV4,
  LedgerHoldResult,
  LedgerTransferResult,
  LedgerReleaseHoldResult,
  EscrowStore,
  WebhookEmitter,
  WebhookEvent,
  WebhookEventType,
  // CES-US-003: Dispute types
  Dispute,
  DisputeStatus,
  DisputeReason,
  DisputeResolution,
  DisputeEscrowRequest,
  DisputeEscrowResult,
  DisputeStore,
  EscalateDisputeRequest,
  EscalateDisputeResult,
  TrialsClient,
  TrialsCaseResult,
  // CES-US-004: Milestone payout types
  ReleaseMilestoneRequest,
  ReleaseMilestoneResult,
  // CES-US-005: Escrow cancellation types
  CancelEscrowRequest,
  CancelEscrowResult,
  AuditLogAction,
  AuditLogEntry,
  AuditLogger,
} from './types.js';
