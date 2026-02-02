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
 */
export type EventType = 'mint' | 'burn' | 'transfer' | 'hold' | 'release';

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
}
