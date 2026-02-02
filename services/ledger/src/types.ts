/**
 * Core types for the ClawLedger service
 * Event-sourced ledger for balances, holds, and transfers
 */

/** DID (Decentralized Identifier) for account ownership */
export type DID = string;

/** Balance in the smallest unit (e.g., microcredits) */
export type Balance = bigint;

/** ISO 8601 timestamp */
export type Timestamp = string;

/** Unique account identifier derived from DID */
export type AccountId = string;

/** Unique event identifier */
export type EventId = string;

/** Idempotency key for event deduplication */
export type IdempotencyKey = string;

/** SHA-256 hash for event chain */
export type EventHash = string;

/**
 * Core event types for ledger operations
 * mint - Create new credits (from reserves)
 * burn - Destroy credits (return to reserves)
 * transfer - Move credits between accounts
 * hold - Lock credits for pending transaction
 * release - Unlock held credits (complete or cancel)
 * stake_lock - Lock credits in bonded bucket for staking
 * stake_slash - Slash bonded credits (penalty)
 * fee_burn - Burn credits from fee pool
 * fee_transfer - Transfer credits to fee pool
 * promo_mint - Mint promotional credits
 * promo_burn - Burn promotional credits
 * clearing_deposit - Deposit to clearing account
 * clearing_withdraw - Withdraw from clearing account
 * settlement - Settlement between accounts with batch reference
 */
export type EventType =
  | 'mint'
  | 'burn'
  | 'transfer'
  | 'hold'
  | 'release'
  | 'stake_lock'
  | 'stake_slash'
  | 'fee_burn'
  | 'fee_transfer'
  | 'promo_mint'
  | 'promo_burn'
  | 'clearing_deposit'
  | 'clearing_withdraw'
  | 'settlement';

/**
 * Balance bucket names
 */
export type BucketName = 'available' | 'held' | 'bonded' | 'feePool' | 'promo';

/**
 * Balance buckets for tracking different types of funds
 * A = Available, H = Held, B = Bonded, F = Fee pool, P = Promo
 */
export interface BalanceBuckets {
  available: Balance;
  held: Balance;
  bonded: Balance;
  feePool: Balance;
  promo: Balance;
}

/**
 * Account entity representing a ledger account
 */
export interface Account {
  /** Unique account ID (derived from DID) */
  id: AccountId;

  /** DID of the account owner - must be unique */
  did: DID;

  /** Balance buckets */
  balances: BalanceBuckets;

  /** Account creation timestamp */
  createdAt: Timestamp;

  /** Last update timestamp */
  updatedAt: Timestamp;

  /** Account version for optimistic concurrency */
  version: number;
}

/**
 * Ledger event entity - immutable record of a balance change
 */
export interface LedgerEvent {
  /** Unique event ID */
  id: EventId;

  /** Client-provided idempotency key - must be unique */
  idempotencyKey: IdempotencyKey;

  /** Type of event */
  eventType: EventType;

  /** Source account ID */
  accountId: AccountId;

  /** Target account ID (for transfers) */
  toAccountId?: AccountId;

  /** Amount in smallest unit */
  amount: Balance;

  /** Which bucket this event affects */
  bucket: BucketName;

  /** Hash of the previous event (chain link) */
  previousHash: EventHash;

  /** Hash of this event (for chain verification) */
  eventHash: EventHash;

  /** Optional metadata (JSON) */
  metadata?: Record<string, unknown>;

  /** Event creation timestamp */
  createdAt: Timestamp;
}

/**
 * Event creation request
 */
export interface CreateEventRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;

  /** Type of event */
  eventType: EventType;

  /** Source account DID or ID */
  accountId: AccountId;

  /** Target account DID or ID (required for transfers) */
  toAccountId?: AccountId;

  /** Amount in smallest unit */
  amount: string;

  /** Which bucket this event affects (defaults to 'available') */
  bucket?: BucketName;

  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Hold creation request
 */
export interface CreateHoldRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;

  /** Account DID or ID to create hold on */
  accountId: AccountId;

  /** Amount to hold */
  amount: string;

  /** Optional metadata (e.g., escrow ID, reason) */
  metadata?: Record<string, unknown>;
}

/**
 * Hold response for API
 */
export interface HoldResponse {
  /** Hold ID (same as event ID) */
  id: EventId;
  idempotencyKey: IdempotencyKey;
  accountId: AccountId;
  amount: string;
  status: 'active' | 'released' | 'cancelled';
  createdAt: Timestamp;
  releasedAt?: Timestamp;
  metadata?: Record<string, unknown>;
}

/**
 * Release type for hold operations
 */
export type ReleaseType = 'complete' | 'cancel';

/**
 * Release hold request
 */
export interface ReleaseHoldRequest {
  /** Client-provided idempotency key for the release operation */
  idempotencyKey: IdempotencyKey;

  /** How to release: 'complete' transfers funds, 'cancel' returns to available */
  releaseType: ReleaseType;

  /** Target account for 'complete' (where funds go) */
  toAccountId?: AccountId;

  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Event response for API
 */
export interface EventResponse {
  id: EventId;
  idempotencyKey: IdempotencyKey;
  eventType: EventType;
  accountId: AccountId;
  toAccountId?: AccountId;
  amount: string;
  bucket: BucketName;
  previousHash: EventHash;
  eventHash: EventHash;
  metadata?: Record<string, unknown>;
  createdAt: Timestamp;
}

/**
 * Account creation request
 */
export interface CreateAccountRequest {
  /** DID of the account owner */
  did: DID;
}

/**
 * Account response for API
 */
export interface AccountResponse {
  id: AccountId;
  did: DID;
  balances: {
    available: string;
    held: string;
    bonded: string;
    feePool: string;
    promo: string;
    total: string;
  };
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

/**
 * Error response
 */
export interface ErrorResponse {
  error: string;
  code: string;
  details?: Record<string, unknown>;
}

/**
 * Environment bindings for Cloudflare Workers
 */
export interface Env {
  DB: D1Database;
  ACCOUNT_DO: DurableObjectNamespace;
  /** Optional webhook URL for reconciliation alerts */
  ALERT_WEBHOOK_URL?: string;
  /** Optional webhook URL for event notifications */
  EVENT_WEBHOOK_URL?: string;
}

/**
 * Reconciliation status
 */
export type ReconciliationStatus = 'success' | 'mismatch' | 'error';

/**
 * Balance mismatch detail for an account
 */
export interface BalanceMismatch {
  accountId: AccountId;
  bucket: BucketName;
  storedBalance: string;
  computedBalance: string;
  difference: string;
}

/**
 * Reconciliation report for audit trail
 */
export interface ReconciliationReport {
  /** Unique report ID */
  id: string;
  /** Report status */
  status: ReconciliationStatus;
  /** Timestamp when reconciliation started */
  startedAt: Timestamp;
  /** Timestamp when reconciliation completed */
  completedAt: Timestamp;
  /** Number of events replayed */
  eventsReplayed: number;
  /** Number of accounts checked */
  accountsChecked: number;
  /** Number of mismatches found */
  mismatchCount: number;
  /** Details of any mismatches */
  mismatches: BalanceMismatch[];
  /** Hash chain verification result */
  hashChainValid: boolean;
  /** Hash chain errors if any */
  hashChainErrors: string[];
  /** Error message if status is 'error' */
  errorMessage?: string;
}

/**
 * Reconciliation alert for webhooks
 */
export interface ReconciliationAlert {
  type: 'reconciliation_mismatch' | 'reconciliation_error';
  reportId: string;
  timestamp: Timestamp;
  mismatchCount: number;
  summary: string;
  details?: BalanceMismatch[];
}

/**
 * Reserve attestation - signed proof of reserve coverage
 */
export interface ReserveAttestation {
  /** Unique attestation ID */
  id: string;
  /** Attestation timestamp */
  timestamp: Timestamp;
  /** Total outstanding liabilities (sum of all user balances) */
  totalOutstanding: string;
  /** Breakdown of outstanding by bucket */
  outstandingByBucket: {
    available: string;
    held: string;
    bonded: string;
    feePool: string;
    promo: string;
  };
  /** Total reserves backing the liabilities */
  totalReserves: string;
  /** Coverage ratio (reserves / outstanding) as decimal string */
  coverageRatio: string;
  /** Whether coverage meets minimum threshold (>= 1.0) */
  isFullyBacked: boolean;
  /** Number of accounts included in calculation */
  accountCount: number;
  /** Hash of all account balances for verification */
  balanceHash: string;
  /** Signature over the attestation data */
  signature: string;
  /** Version of the attestation format */
  version: string;
}

/**
 * Reserve attestation request - for API
 */
export interface ReserveAttestationRequest {
  /** Optional: include detailed account breakdown (admin only) */
  includeDetails?: boolean;
}

/**
 * Reserve attestation response - public API format
 */
export interface ReserveAttestationResponse {
  attestation: ReserveAttestation;
  /** Latest event hash at time of attestation */
  latestEventHash: string;
  /** Human-readable summary */
  summary: string;
}

/**
 * Transfer request for API
 */
export interface TransferRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Source account ID or DID */
  fromAccountId: AccountId;
  /** Target account ID or DID */
  toAccountId: AccountId;
  /** Amount to transfer */
  amount: string;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Transfer response for API
 */
export interface TransferResponse {
  /** Transfer event ID */
  eventId: EventId;
  /** Idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Source account ID */
  fromAccountId: AccountId;
  /** Target account ID */
  toAccountId: AccountId;
  /** Amount transferred */
  amount: string;
  /** Event hash */
  eventHash: EventHash;
  /** Timestamp */
  createdAt: Timestamp;
}

/**
 * Balance list request query parameters
 */
export interface BalanceListQuery {
  /** Filter by account IDs (comma-separated) */
  accountIds?: string;
  /** Pagination limit */
  limit?: number;
  /** Pagination offset */
  offset?: number;
}

/**
 * Balance list response for API
 */
export interface BalanceListResponse {
  balances: AccountResponse[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * Webhook event payload
 */
export interface WebhookEventPayload {
  /** Event type identifier for webhook routing */
  webhookType: 'ledger.event.created';
  /** Event data */
  event: EventResponse;
  /** Timestamp when webhook was sent */
  sentAt: Timestamp;
  /** Idempotency key for webhook deduplication */
  webhookId: string;
}

/**
 * Stake event metadata - links to originating escrow/trial
 */
export interface StakeEventMetadata {
  /** Originating escrow ID (for stake_lock, stake_slash) */
  escrowId?: string;
  /** Originating trial ID (for stake events related to trials) */
  trialId?: string;
  /** Reason for the stake operation */
  reason?: string;
  /** Additional context data */
  context?: Record<string, unknown>;
}

/**
 * Fee event metadata - links to originating transaction/escrow
 */
export interface FeeEventMetadata {
  /** Originating escrow ID (for fee_transfer, fee_burn) */
  escrowId?: string;
  /** Originating transaction ID */
  transactionId?: string;
  /** Fee type (e.g., 'platform', 'evaluation', 'settlement') */
  feeType?: string;
  /** Reason for the fee operation */
  reason?: string;
  /** Additional context data */
  context?: Record<string, unknown>;
}

/**
 * Promo event metadata - links to campaign/promotion
 */
export interface PromoEventMetadata {
  /** Campaign ID for the promo credits */
  campaignId?: string;
  /** Promotion code if applicable */
  promoCode?: string;
  /** Reason for the promo operation */
  reason?: string;
  /** Expiration timestamp for promo credits */
  expiresAt?: Timestamp;
  /** Additional context data */
  context?: Record<string, unknown>;
}

/**
 * Stake lock request for API
 */
export interface StakeLockRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Account ID to stake from */
  accountId: AccountId;
  /** Amount to stake (move from available to bonded) */
  amount: string;
  /** Originating escrow ID */
  escrowId?: string;
  /** Originating trial ID */
  trialId?: string;
  /** Reason for staking */
  reason?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Stake slash request for API
 */
export interface StakeSlashRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Account ID to slash from */
  accountId: AccountId;
  /** Amount to slash from bonded bucket */
  amount: string;
  /** Originating escrow ID */
  escrowId?: string;
  /** Originating trial ID */
  trialId?: string;
  /** Reason for slashing */
  reason?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Fee burn request for API
 */
export interface FeeBurnRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Account ID to burn fees from */
  accountId: AccountId;
  /** Amount to burn from fee pool */
  amount: string;
  /** Originating escrow ID */
  escrowId?: string;
  /** Originating transaction ID */
  transactionId?: string;
  /** Fee type */
  feeType?: string;
  /** Reason for burning */
  reason?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Fee transfer request for API
 */
export interface FeeTransferRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Account ID to transfer fees from */
  accountId: AccountId;
  /** Amount to transfer to fee pool */
  amount: string;
  /** Source bucket to transfer from (defaults to 'available') */
  fromBucket?: BucketName;
  /** Originating escrow ID */
  escrowId?: string;
  /** Originating transaction ID */
  transactionId?: string;
  /** Fee type */
  feeType?: string;
  /** Reason for fee transfer */
  reason?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Promo mint request for API
 */
export interface PromoMintRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Account ID to mint promo credits to */
  accountId: AccountId;
  /** Amount to mint to promo bucket */
  amount: string;
  /** Campaign ID */
  campaignId?: string;
  /** Promotion code */
  promoCode?: string;
  /** Reason for minting */
  reason?: string;
  /** Expiration timestamp for promo credits */
  expiresAt?: Timestamp;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Promo burn request for API
 */
export interface PromoBurnRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Account ID to burn promo credits from */
  accountId: AccountId;
  /** Amount to burn from promo bucket */
  amount: string;
  /** Campaign ID */
  campaignId?: string;
  /** Reason for burning */
  reason?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Generic stake/fee event response for API
 */
export interface StakeFeeEventResponse {
  /** Event ID */
  eventId: EventId;
  /** Idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Event type */
  eventType: EventType;
  /** Account ID */
  accountId: AccountId;
  /** Amount affected */
  amount: string;
  /** Bucket affected */
  bucket: BucketName;
  /** Event hash */
  eventHash: EventHash;
  /** Timestamp */
  createdAt: Timestamp;
  /** Metadata including escrow/trial links */
  metadata?: Record<string, unknown>;
}

/**
 * Clearing account domain types for cross-service settlement
 * Each domain (e.g., 'escrow', 'marketplace', 'treasury') has its own clearing account
 */
export type ClearingDomain = string;

/**
 * Clearing account entity - special accounts for cross-service settlement
 * These are system accounts, not user accounts
 */
export interface ClearingAccount {
  /** Unique clearing account ID */
  id: AccountId;
  /** Domain identifier (e.g., 'escrow', 'marketplace', 'treasury') */
  domain: ClearingDomain;
  /** Human-readable name for the clearing account */
  name: string;
  /** Balance buckets (same structure as user accounts) */
  balances: BalanceBuckets;
  /** Whether this clearing account is active */
  isActive: boolean;
  /** Account creation timestamp */
  createdAt: Timestamp;
  /** Last update timestamp */
  updatedAt: Timestamp;
  /** Account version for optimistic concurrency */
  version: number;
}

/**
 * Clearing account creation request
 */
export interface CreateClearingAccountRequest {
  /** Domain identifier - must be unique */
  domain: ClearingDomain;
  /** Human-readable name */
  name: string;
}

/**
 * Clearing account response for API
 */
export interface ClearingAccountResponse {
  id: AccountId;
  domain: ClearingDomain;
  name: string;
  balances: {
    available: string;
    held: string;
    bonded: string;
    feePool: string;
    promo: string;
    total: string;
  };
  isActive: boolean;
  createdAt: Timestamp;
  updatedAt: Timestamp;
}

/**
 * Settlement event metadata - links to netting batch and originating transactions
 */
export interface SettlementEventMetadata {
  /** Netting batch ID for grouping related settlements */
  batchId: string;
  /** Originating escrow ID (if applicable) */
  escrowId?: string;
  /** Originating transaction ID (if applicable) */
  transactionId?: string;
  /** Settlement type (e.g., 'escrow_release', 'marketplace_payout', 'fee_collection') */
  settlementType?: string;
  /** Reason for the settlement */
  reason?: string;
  /** Additional context data */
  context?: Record<string, unknown>;
}

/**
 * Clearing deposit request - deposit funds to a clearing account
 */
export interface ClearingDepositRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Source user account ID */
  fromAccountId: AccountId;
  /** Clearing account ID (or domain to look up) */
  clearingAccountId?: AccountId;
  /** Clearing domain (alternative to clearingAccountId) */
  domain?: ClearingDomain;
  /** Amount to deposit */
  amount: string;
  /** Netting batch ID */
  batchId: string;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Clearing withdraw request - withdraw funds from a clearing account
 */
export interface ClearingWithdrawRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Clearing account ID (or domain to look up) */
  clearingAccountId?: AccountId;
  /** Clearing domain (alternative to clearingAccountId) */
  domain?: ClearingDomain;
  /** Destination user account ID */
  toAccountId: AccountId;
  /** Amount to withdraw */
  amount: string;
  /** Netting batch ID */
  batchId: string;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Settlement request - transfer between accounts with batch reference
 */
export interface SettlementRequest {
  /** Client-provided idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Source account ID (user or clearing) */
  fromAccountId: AccountId;
  /** Destination account ID (user or clearing) */
  toAccountId: AccountId;
  /** Amount to settle */
  amount: string;
  /** Netting batch ID - required for all settlements */
  batchId: string;
  /** Settlement type */
  settlementType?: string;
  /** Originating escrow ID */
  escrowId?: string;
  /** Originating transaction ID */
  transactionId?: string;
  /** Reason for settlement */
  reason?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Settlement response for API
 */
export interface SettlementResponse {
  /** Settlement event ID */
  eventId: EventId;
  /** Idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Source account ID */
  fromAccountId: AccountId;
  /** Destination account ID */
  toAccountId: AccountId;
  /** Amount settled */
  amount: string;
  /** Netting batch ID */
  batchId: string;
  /** Event hash */
  eventHash: EventHash;
  /** Timestamp */
  createdAt: Timestamp;
  /** Metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Clearing event response for API (deposit/withdraw)
 */
export interface ClearingEventResponse {
  /** Event ID */
  eventId: EventId;
  /** Idempotency key */
  idempotencyKey: IdempotencyKey;
  /** Event type */
  eventType: 'clearing_deposit' | 'clearing_withdraw';
  /** User account ID */
  userAccountId: AccountId;
  /** Clearing account ID */
  clearingAccountId: AccountId;
  /** Amount */
  amount: string;
  /** Netting batch ID */
  batchId: string;
  /** Event hash */
  eventHash: EventHash;
  /** Timestamp */
  createdAt: Timestamp;
  /** Metadata */
  metadata?: Record<string, unknown>;
}
