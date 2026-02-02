/**
 * Hold management for ClawLedger
 * Handles hold creation, release, and cancellation for escrow operations
 */

import type {
  AccountId,
  Balance,
  CreateHoldRequest,
  Env,
  EventId,
  HoldResponse,
  IdempotencyKey,
  ReleaseHoldRequest,
  ReleaseType,
  Timestamp,
} from './types';
import { AccountRepository, InsufficientFundsError } from './accounts';
import {
  computeEventHash,
  EventRepository,
  toEventResponse,
} from './events';

/** Hold status values */
export type HoldStatus = 'active' | 'released' | 'cancelled';

/**
 * Hold entity representing a locked funds hold
 */
export interface Hold {
  id: string;
  idempotencyKey: IdempotencyKey;
  accountId: AccountId;
  amount: Balance;
  status: HoldStatus;
  holdEventId: EventId;
  releaseEventId?: EventId;
  metadata?: Record<string, unknown>;
  createdAt: Timestamp;
  releasedAt?: Timestamp;
}

/**
 * Generate a unique hold ID
 */
export function generateHoldId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `hold_${timestamp}_${random}`;
}

/**
 * Parse Hold from database row
 */
export function parseHoldFromRow(row: Record<string, unknown>): Hold {
  let metadata: Record<string, unknown> | undefined;
  if (row.metadata) {
    try {
      metadata = JSON.parse(row.metadata as string);
    } catch {
      metadata = undefined;
    }
  }

  return {
    id: row.id as string,
    idempotencyKey: row.idempotency_key as string,
    accountId: row.account_id as string,
    amount: BigInt((row.amount as string) || '0'),
    status: row.status as HoldStatus,
    holdEventId: row.hold_event_id as string,
    releaseEventId: row.release_event_id as string | undefined,
    metadata,
    createdAt: row.created_at as string,
    releasedAt: row.released_at as string | undefined,
  };
}

/**
 * Convert Hold to API response format
 */
export function toHoldResponse(hold: Hold): HoldResponse {
  return {
    id: hold.id,
    idempotencyKey: hold.idempotencyKey,
    accountId: hold.accountId,
    amount: hold.amount.toString(),
    status: hold.status,
    createdAt: hold.createdAt,
    releasedAt: hold.releasedAt,
    metadata: hold.metadata,
  };
}

/**
 * Hold repository for database operations
 */
export class HoldRepository {
  constructor(private db: D1Database) {}

  /**
   * Find hold by idempotency key
   */
  async findByIdempotencyKey(idempotencyKey: IdempotencyKey): Promise<Hold | null> {
    const result = await this.db
      .prepare(
        `SELECT id, idempotency_key, account_id, amount, status, hold_event_id,
                release_event_id, metadata, created_at, released_at
         FROM holds WHERE idempotency_key = ?`
      )
      .bind(idempotencyKey)
      .first();

    if (!result) {
      return null;
    }

    return parseHoldFromRow(result);
  }

  /**
   * Find hold by ID
   */
  async findById(id: string): Promise<Hold | null> {
    const result = await this.db
      .prepare(
        `SELECT id, idempotency_key, account_id, amount, status, hold_event_id,
                release_event_id, metadata, created_at, released_at
         FROM holds WHERE id = ?`
      )
      .bind(id)
      .first();

    if (!result) {
      return null;
    }

    return parseHoldFromRow(result);
  }

  /**
   * Find active holds for an account
   */
  async findActiveByAccountId(accountId: AccountId): Promise<Hold[]> {
    const results = await this.db
      .prepare(
        `SELECT id, idempotency_key, account_id, amount, status, hold_event_id,
                release_event_id, metadata, created_at, released_at
         FROM holds
         WHERE account_id = ? AND status = 'active'
         ORDER BY created_at DESC`
      )
      .bind(accountId)
      .all();

    return (results.results || []).map((row) =>
      parseHoldFromRow(row as Record<string, unknown>)
    );
  }

  /**
   * Create a new hold
   */
  async create(
    idempotencyKey: IdempotencyKey,
    accountId: AccountId,
    amount: Balance,
    holdEventId: EventId,
    metadata?: Record<string, unknown>
  ): Promise<Hold> {
    // Check for existing hold with same idempotency key
    const existing = await this.findByIdempotencyKey(idempotencyKey);
    if (existing) {
      return existing;
    }

    const id = generateHoldId();
    const now = new Date().toISOString();
    const metadataJson = metadata ? JSON.stringify(metadata) : null;

    await this.db
      .prepare(
        `INSERT INTO holds (
          id, idempotency_key, account_id, amount, status, hold_event_id,
          metadata, created_at
        ) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)`
      )
      .bind(
        id,
        idempotencyKey,
        accountId,
        amount.toString(),
        holdEventId,
        metadataJson,
        now
      )
      .run();

    return {
      id,
      idempotencyKey,
      accountId,
      amount,
      status: 'active',
      holdEventId,
      metadata,
      createdAt: now,
    };
  }

  /**
   * Release a hold (mark as released or cancelled)
   */
  async release(
    holdId: string,
    releaseType: ReleaseType,
    releaseEventId: EventId
  ): Promise<Hold> {
    const hold = await this.findById(holdId);
    if (!hold) {
      throw new Error(`Hold not found: ${holdId}`);
    }

    if (hold.status !== 'active') {
      throw new Error(`Hold ${holdId} is already ${hold.status}`);
    }

    const now = new Date().toISOString();
    const newStatus: HoldStatus = releaseType === 'complete' ? 'released' : 'cancelled';

    await this.db
      .prepare(
        `UPDATE holds SET status = ?, release_event_id = ?, released_at = ?
         WHERE id = ?`
      )
      .bind(newStatus, releaseEventId, now, holdId)
      .run();

    return {
      ...hold,
      status: newStatus,
      releaseEventId,
      releasedAt: now,
    };
  }
}

/**
 * Hold service for business logic
 */
export class HoldService {
  private holdRepository: HoldRepository;
  private eventRepository: EventRepository;
  private accountRepository: AccountRepository;

  constructor(env: Env) {
    this.holdRepository = new HoldRepository(env.DB);
    this.eventRepository = new EventRepository(env.DB);
    this.accountRepository = new AccountRepository(env.DB);
  }

  /**
   * Create a new hold
   * Moves funds from available to held bucket
   */
  async createHold(request: CreateHoldRequest): Promise<HoldResponse> {
    // Validate amount
    let amount: Balance;
    try {
      amount = BigInt(request.amount);
      if (amount <= 0n) {
        throw new Error('Amount must be positive');
      }
    } catch {
      throw new Error(`Invalid amount: ${request.amount}. Must be a valid positive integer string`);
    }

    // Check for existing hold with same idempotency key
    const existingHold = await this.holdRepository.findByIdempotencyKey(
      request.idempotencyKey
    );
    if (existingHold) {
      return toHoldResponse(existingHold);
    }

    // Verify account exists
    const account = await this.accountRepository.findById(request.accountId);
    if (!account) {
      throw new Error(`Account not found: ${request.accountId}`);
    }

    // Get previous hash for event chain
    const previousHash = await this.eventRepository.getLastEventHash();
    const now = new Date().toISOString();

    // Compute event hash
    const eventHash = await computeEventHash(
      previousHash,
      'hold',
      request.accountId,
      undefined,
      amount,
      'held',
      request.idempotencyKey,
      now
    );

    // Create the hold event
    const event = await this.eventRepository.create(
      request.idempotencyKey,
      'hold',
      request.accountId,
      amount,
      'held',
      previousHash,
      eventHash,
      undefined,
      request.metadata
    );

    // Update account balances (move from available to held)
    try {
      await this.accountRepository.createHold(request.accountId, amount);
    } catch (err) {
      if (err instanceof InsufficientFundsError) {
        throw new Error(err.message);
      }
      throw err;
    }

    // Create the hold record
    const hold = await this.holdRepository.create(
      request.idempotencyKey,
      request.accountId,
      amount,
      event.id,
      request.metadata
    );

    return toHoldResponse(hold);
  }

  /**
   * Release a hold
   * Either cancels (returns to available) or completes (transfers to target account)
   */
  async releaseHold(
    holdId: string,
    request: ReleaseHoldRequest
  ): Promise<{ hold: HoldResponse; event: ReturnType<typeof toEventResponse> }> {
    // Get the hold
    const hold = await this.holdRepository.findById(holdId);
    if (!hold) {
      throw new Error(`Hold not found: ${holdId}`);
    }

    if (hold.status !== 'active') {
      throw new Error(`Hold ${holdId} is already ${hold.status}`);
    }

    // Validate release type
    if (request.releaseType !== 'complete' && request.releaseType !== 'cancel') {
      throw new Error(`Invalid release type: ${request.releaseType}. Must be 'complete' or 'cancel'`);
    }

    // Complete requires toAccountId
    if (request.releaseType === 'complete' && !request.toAccountId) {
      throw new Error('Complete release requires toAccountId');
    }

    // Check for existing event with same idempotency key
    const existingEvent = await this.eventRepository.findByIdempotencyKey(
      request.idempotencyKey
    );
    if (existingEvent) {
      // Return the already processed hold
      const updatedHold = await this.holdRepository.findById(holdId);
      return {
        hold: toHoldResponse(updatedHold!),
        event: toEventResponse(existingEvent),
      };
    }

    // Get previous hash for event chain
    const previousHash = await this.eventRepository.getLastEventHash();
    const now = new Date().toISOString();

    // Compute event hash
    const eventHash = await computeEventHash(
      previousHash,
      'release',
      hold.accountId,
      request.toAccountId,
      hold.amount,
      request.releaseType === 'cancel' ? 'available' : 'held',
      request.idempotencyKey,
      now
    );

    // Create the release event
    const event = await this.eventRepository.create(
      request.idempotencyKey,
      'release',
      hold.accountId,
      hold.amount,
      request.releaseType === 'cancel' ? 'available' : 'held',
      previousHash,
      eventHash,
      request.toAccountId,
      {
        ...request.metadata,
        holdId: hold.id,
        releaseType: request.releaseType,
      }
    );

    // Update account balances based on release type
    if (request.releaseType === 'cancel') {
      // Return funds to available bucket
      await this.accountRepository.releaseHoldToAvailable(hold.accountId, hold.amount);
    } else {
      // Complete: remove from held and credit target account
      await this.accountRepository.completeHold(hold.accountId, hold.amount);
      await this.accountRepository.creditAvailable(request.toAccountId!, hold.amount);
    }

    // Update the hold record
    const releasedHold = await this.holdRepository.release(
      holdId,
      request.releaseType,
      event.id
    );

    return {
      hold: toHoldResponse(releasedHold),
      event: toEventResponse(event),
    };
  }

  /**
   * Get hold by ID
   */
  async getHold(holdId: string): Promise<HoldResponse | null> {
    const hold = await this.holdRepository.findById(holdId);
    if (!hold) {
      return null;
    }
    return toHoldResponse(hold);
  }

  /**
   * Get active holds for an account
   */
  async getActiveHolds(accountId: AccountId): Promise<HoldResponse[]> {
    const holds = await this.holdRepository.findActiveByAccountId(accountId);
    return holds.map(toHoldResponse);
  }
}
