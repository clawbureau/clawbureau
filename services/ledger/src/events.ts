/**
 * Event management for ClawLedger
 * Handles append-only event log with hash chain for audit trail
 */

import type {
  AccountId,
  Balance,
  BucketName,
  CreateEventRequest,
  Env,
  EventHash,
  EventId,
  EventResponse,
  EventType,
  IdempotencyKey,
  LedgerEvent,
} from './types';

/** Genesis hash for the first event in the chain */
const GENESIS_HASH = '0'.repeat(64);

/**
 * Generate a unique event ID
 */
export function generateEventId(): EventId {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `evt_${timestamp}_${random}`;
}

/**
 * Compute SHA-256 hash for event chain
 * Uses Web Crypto API available in Cloudflare Workers
 */
export async function computeEventHash(
  previousHash: EventHash,
  eventType: EventType,
  accountId: AccountId,
  toAccountId: AccountId | undefined,
  amount: Balance,
  bucket: BucketName,
  idempotencyKey: IdempotencyKey,
  timestamp: string
): Promise<EventHash> {
  const data = [
    previousHash,
    eventType,
    accountId,
    toAccountId ?? '',
    amount.toString(),
    bucket,
    idempotencyKey,
    timestamp,
  ].join('|');

  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);

  // Convert to hex string
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Validate event type
 */
export function isValidEventType(type: string): type is EventType {
  return [
    'mint',
    'burn',
    'transfer',
    'hold',
    'release',
    'stake_lock',
    'stake_slash',
    'fee_burn',
    'fee_transfer',
    'promo_mint',
    'promo_burn',
  ].includes(type);
}

/**
 * Check if event type is a stake-related event
 */
export function isStakeEventType(type: string): boolean {
  return ['stake_lock', 'stake_slash'].includes(type);
}

/**
 * Check if event type is a fee-related event
 */
export function isFeeEventType(type: string): boolean {
  return ['fee_burn', 'fee_transfer'].includes(type);
}

/**
 * Check if event type is a promo-related event
 */
export function isPromoEventType(type: string): boolean {
  return ['promo_mint', 'promo_burn'].includes(type);
}

/**
 * Validate bucket name
 */
export function isValidBucket(bucket: string): bucket is BucketName {
  return ['available', 'held', 'bonded', 'feePool', 'promo'].includes(bucket);
}

/**
 * Parse LedgerEvent from database row
 */
export function parseEventFromRow(row: Record<string, unknown>): LedgerEvent {
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
    eventType: row.event_type as EventType,
    accountId: row.account_id as string,
    toAccountId: row.to_account_id as string | undefined,
    amount: BigInt((row.amount as string) || '0'),
    bucket: (row.bucket as BucketName) || 'available',
    previousHash: row.previous_hash as string,
    eventHash: row.event_hash as string,
    metadata,
    createdAt: row.created_at as string,
  };
}

/**
 * Convert LedgerEvent to API response format
 */
export function toEventResponse(event: LedgerEvent): EventResponse {
  return {
    id: event.id,
    idempotencyKey: event.idempotencyKey,
    eventType: event.eventType,
    accountId: event.accountId,
    toAccountId: event.toAccountId,
    amount: event.amount.toString(),
    bucket: event.bucket,
    previousHash: event.previousHash,
    eventHash: event.eventHash,
    metadata: event.metadata,
    createdAt: event.createdAt,
  };
}

/**
 * Event repository for database operations
 */
export class EventRepository {
  constructor(private db: D1Database) {}

  /**
   * Find event by idempotency key
   * Used for deduplication
   */
  async findByIdempotencyKey(
    idempotencyKey: IdempotencyKey
  ): Promise<LedgerEvent | null> {
    const result = await this.db
      .prepare(
        `SELECT id, idempotency_key, event_type, account_id, to_account_id,
                amount, bucket, previous_hash, event_hash, metadata, created_at
         FROM events WHERE idempotency_key = ?`
      )
      .bind(idempotencyKey)
      .first();

    if (!result) {
      return null;
    }

    return parseEventFromRow(result);
  }

  /**
   * Find event by ID
   */
  async findById(id: EventId): Promise<LedgerEvent | null> {
    const result = await this.db
      .prepare(
        `SELECT id, idempotency_key, event_type, account_id, to_account_id,
                amount, bucket, previous_hash, event_hash, metadata, created_at
         FROM events WHERE id = ?`
      )
      .bind(id)
      .first();

    if (!result) {
      return null;
    }

    return parseEventFromRow(result);
  }

  /**
   * Get the last event hash for the chain
   * Returns genesis hash if no events exist
   */
  async getLastEventHash(): Promise<EventHash> {
    const result = await this.db
      .prepare(
        `SELECT event_hash FROM events ORDER BY created_at DESC, id DESC LIMIT 1`
      )
      .first();

    if (!result) {
      return GENESIS_HASH;
    }

    return result.event_hash as string;
  }

  /**
   * Get events for an account
   */
  async findByAccountId(
    accountId: AccountId,
    limit = 100
  ): Promise<LedgerEvent[]> {
    const results = await this.db
      .prepare(
        `SELECT id, idempotency_key, event_type, account_id, to_account_id,
                amount, bucket, previous_hash, event_hash, metadata, created_at
         FROM events
         WHERE account_id = ? OR to_account_id = ?
         ORDER BY created_at DESC, id DESC
         LIMIT ?`
      )
      .bind(accountId, accountId, limit)
      .all();

    return (results.results || []).map((row) =>
      parseEventFromRow(row as Record<string, unknown>)
    );
  }

  /**
   * Create a new event
   * Returns existing event if idempotency key already exists
   */
  async create(
    idempotencyKey: IdempotencyKey,
    eventType: EventType,
    accountId: AccountId,
    amount: Balance,
    bucket: BucketName,
    previousHash: EventHash,
    eventHash: EventHash,
    toAccountId?: AccountId,
    metadata?: Record<string, unknown>
  ): Promise<LedgerEvent> {
    // Check for existing event with same idempotency key
    const existing = await this.findByIdempotencyKey(idempotencyKey);
    if (existing) {
      return existing;
    }

    const id = generateEventId();
    const now = new Date().toISOString();
    const metadataJson = metadata ? JSON.stringify(metadata) : null;

    await this.db
      .prepare(
        `INSERT INTO events (
          id, idempotency_key, event_type, account_id, to_account_id,
          amount, bucket, previous_hash, event_hash, metadata, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        id,
        idempotencyKey,
        eventType,
        accountId,
        toAccountId ?? null,
        amount.toString(),
        bucket,
        previousHash,
        eventHash,
        metadataJson,
        now
      )
      .run();

    return {
      id,
      idempotencyKey,
      eventType,
      accountId,
      toAccountId,
      amount,
      bucket,
      previousHash,
      eventHash,
      metadata,
      createdAt: now,
    };
  }
}

/**
 * Event service for business logic
 */
export class EventService {
  private repository: EventRepository;

  constructor(env: Env) {
    this.repository = new EventRepository(env.DB);
  }

  /**
   * Create a new ledger event
   * Idempotent: returns existing event if idempotency key already exists
   */
  async createEvent(request: CreateEventRequest): Promise<EventResponse> {
    // Validate event type
    if (!isValidEventType(request.eventType)) {
      throw new Error(
        `Invalid event type: ${request.eventType}. Must be one of: mint, burn, transfer, hold, release`
      );
    }

    // Validate bucket
    const bucket = request.bucket ?? 'available';
    if (!isValidBucket(bucket)) {
      throw new Error(
        `Invalid bucket: ${bucket}. Must be one of: available, held, bonded, feePool, promo`
      );
    }

    // Validate amount
    let amount: Balance;
    try {
      amount = BigInt(request.amount);
      if (amount < 0n) {
        throw new Error('Amount must be non-negative');
      }
    } catch {
      throw new Error(`Invalid amount: ${request.amount}. Must be a valid integer string`);
    }

    // Transfer requires toAccountId
    if (request.eventType === 'transfer' && !request.toAccountId) {
      throw new Error('Transfer events require toAccountId');
    }

    // Check for existing event with same idempotency key
    const existing = await this.repository.findByIdempotencyKey(
      request.idempotencyKey
    );
    if (existing) {
      return toEventResponse(existing);
    }

    // Get previous hash for chain
    const previousHash = await this.repository.getLastEventHash();
    const now = new Date().toISOString();

    // Compute event hash
    const eventHash = await computeEventHash(
      previousHash,
      request.eventType,
      request.accountId,
      request.toAccountId,
      amount,
      bucket,
      request.idempotencyKey,
      now
    );

    // Create the event
    const event = await this.repository.create(
      request.idempotencyKey,
      request.eventType,
      request.accountId,
      amount,
      bucket,
      previousHash,
      eventHash,
      request.toAccountId,
      request.metadata
    );

    return toEventResponse(event);
  }

  /**
   * Get event by ID
   */
  async getEvent(id: EventId): Promise<EventResponse | null> {
    const event = await this.repository.findById(id);
    if (!event) {
      return null;
    }
    return toEventResponse(event);
  }

  /**
   * Get event by idempotency key
   */
  async getEventByIdempotencyKey(
    idempotencyKey: IdempotencyKey
  ): Promise<EventResponse | null> {
    const event = await this.repository.findByIdempotencyKey(idempotencyKey);
    if (!event) {
      return null;
    }
    return toEventResponse(event);
  }

  /**
   * Get events for an account
   */
  async getAccountEvents(
    accountId: AccountId,
    limit = 100
  ): Promise<EventResponse[]> {
    const events = await this.repository.findByAccountId(accountId, limit);
    return events.map(toEventResponse);
  }

  /**
   * Verify hash chain integrity from a given event
   */
  async verifyHashChain(_startEventId?: EventId): Promise<{
    valid: boolean;
    errors: string[];
    eventsChecked: number;
  }> {
    const errors: string[] = [];
    let eventsChecked = 0;

    // Get all events in order
    const results = await this.repository['db']
      .prepare(
        `SELECT id, idempotency_key, event_type, account_id, to_account_id,
                amount, bucket, previous_hash, event_hash, metadata, created_at
         FROM events
         ORDER BY created_at ASC, id ASC`
      )
      .all();

    const events = (results.results || []).map((row) =>
      parseEventFromRow(row as Record<string, unknown>)
    );

    let expectedPreviousHash = GENESIS_HASH;

    for (const event of events) {
      eventsChecked++;

      // Check previous hash link
      if (event.previousHash !== expectedPreviousHash) {
        errors.push(
          `Event ${event.id}: Previous hash mismatch. Expected ${expectedPreviousHash}, got ${event.previousHash}`
        );
      }

      // Recompute event hash
      const computedHash = await computeEventHash(
        event.previousHash,
        event.eventType,
        event.accountId,
        event.toAccountId,
        event.amount,
        event.bucket,
        event.idempotencyKey,
        event.createdAt
      );

      if (event.eventHash !== computedHash) {
        errors.push(
          `Event ${event.id}: Hash mismatch. Expected ${computedHash}, got ${event.eventHash}`
        );
      }

      expectedPreviousHash = event.eventHash;
    }

    return {
      valid: errors.length === 0,
      errors,
      eventsChecked,
    };
  }
}
