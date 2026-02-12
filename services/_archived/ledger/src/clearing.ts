/**
 * Clearing account management for ClawLedger
 * Handles per-domain clearing accounts for cross-service settlement
 */

import { createEmptyBalances, parseBalancesFromRow, InsufficientFundsError } from './accounts';
import { EventRepository, computeEventHash } from './events';
import type {
  AccountId,
  BalanceBuckets,
  BucketName,
  ClearingAccount,
  ClearingAccountResponse,
  ClearingDepositRequest,
  ClearingDomain,
  ClearingEventResponse,
  ClearingWithdrawRequest,
  CreateClearingAccountRequest,
  Env,
  EventType,
  SettlementRequest,
  SettlementResponse,
} from './types';

/**
 * Derive a deterministic clearing account ID from a domain
 */
export function deriveClearingAccountId(domain: ClearingDomain): AccountId {
  // Prefix with 'clr_' to distinguish from user accounts
  let hash = 0;
  for (let i = 0; i < domain.length; i++) {
    const char = domain.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  return `clr_${Math.abs(hash).toString(16).padStart(8, '0')}`;
}

/**
 * Parse ClearingAccount from database row
 */
export function parseClearingAccountFromRow(row: Record<string, unknown>): ClearingAccount {
  return {
    id: row.id as string,
    domain: row.domain as string,
    name: row.name as string,
    balances: parseBalancesFromRow(row),
    isActive: Boolean(row.is_active),
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    version: row.version as number,
  };
}

/**
 * Calculate total balance across all buckets
 */
function calculateTotalBalance(balances: BalanceBuckets): bigint {
  return (
    balances.available +
    balances.held +
    balances.bonded +
    balances.feePool +
    balances.promo
  );
}

/**
 * Convert ClearingAccount to API response format
 */
export function toClearingAccountResponse(account: ClearingAccount): ClearingAccountResponse {
  const total = calculateTotalBalance(account.balances);
  return {
    id: account.id,
    domain: account.domain,
    name: account.name,
    balances: {
      available: account.balances.available.toString(),
      held: account.balances.held.toString(),
      bonded: account.balances.bonded.toString(),
      feePool: account.balances.feePool.toString(),
      promo: account.balances.promo.toString(),
      total: total.toString(),
    },
    isActive: account.isActive,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  };
}

/**
 * Clearing account repository for database operations
 */
export class ClearingAccountRepository {
  constructor(private db: D1Database) {}

  /**
   * Find clearing account by domain
   */
  async findByDomain(domain: ClearingDomain): Promise<ClearingAccount | null> {
    const result = await this.db
      .prepare(
        `SELECT id, domain, name, balance_available, balance_held, balance_bonded,
                balance_fee_pool, balance_promo, is_active, created_at, updated_at, version
         FROM clearing_accounts WHERE domain = ?`
      )
      .bind(domain)
      .first();

    if (!result) {
      return null;
    }

    return parseClearingAccountFromRow(result);
  }

  /**
   * Find clearing account by ID
   */
  async findById(id: AccountId): Promise<ClearingAccount | null> {
    const result = await this.db
      .prepare(
        `SELECT id, domain, name, balance_available, balance_held, balance_bonded,
                balance_fee_pool, balance_promo, is_active, created_at, updated_at, version
         FROM clearing_accounts WHERE id = ?`
      )
      .bind(id)
      .first();

    if (!result) {
      return null;
    }

    return parseClearingAccountFromRow(result);
  }

  /**
   * Create a new clearing account
   * Returns existing account if domain already exists (idempotent)
   */
  async create(request: CreateClearingAccountRequest): Promise<ClearingAccount> {
    const { domain, name } = request;

    // Check if clearing account already exists for this domain
    const existing = await this.findByDomain(domain);
    if (existing) {
      return existing;
    }

    const id = deriveClearingAccountId(domain);
    const now = new Date().toISOString();
    const balances = createEmptyBalances();

    await this.db
      .prepare(
        `INSERT INTO clearing_accounts (
          id, domain, name, balance_available, balance_held, balance_bonded,
          balance_fee_pool, balance_promo, is_active, created_at, updated_at, version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        id,
        domain,
        name,
        balances.available.toString(),
        balances.held.toString(),
        balances.bonded.toString(),
        balances.feePool.toString(),
        balances.promo.toString(),
        1, // is_active
        now,
        now,
        1
      )
      .run();

    return {
      id,
      domain,
      name,
      balances,
      isActive: true,
      createdAt: now,
      updatedAt: now,
      version: 1,
    };
  }

  /**
   * List all clearing accounts
   */
  async list(): Promise<ClearingAccount[]> {
    const results = await this.db
      .prepare(
        `SELECT id, domain, name, balance_available, balance_held, balance_bonded,
                balance_fee_pool, balance_promo, is_active, created_at, updated_at, version
         FROM clearing_accounts
         ORDER BY domain ASC`
      )
      .all();

    return (results.results || []).map((row) =>
      parseClearingAccountFromRow(row as Record<string, unknown>)
    );
  }

  /**
   * Credit available balance of a clearing account
   */
  async creditAvailable(id: AccountId, amount: bigint): Promise<ClearingAccount> {
    const account = await this.findById(id);
    if (!account) {
      throw new Error(`Clearing account not found: ${id}`);
    }

    const newAvailable = account.balances.available + amount;
    const now = new Date().toISOString();
    const newVersion = account.version + 1;

    await this.db
      .prepare(
        `UPDATE clearing_accounts
         SET balance_available = ?, updated_at = ?, version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newAvailable.toString(),
        now,
        newVersion,
        id,
        account.version
      )
      .run();

    return {
      ...account,
      balances: {
        ...account.balances,
        available: newAvailable,
      },
      updatedAt: now,
      version: newVersion,
    };
  }

  /**
   * Debit available balance of a clearing account
   */
  async debitAvailable(id: AccountId, amount: bigint): Promise<ClearingAccount> {
    const account = await this.findById(id);
    if (!account) {
      throw new Error(`Clearing account not found: ${id}`);
    }

    if (account.balances.available < amount) {
      throw new InsufficientFundsError(
        id,
        'available',
        amount,
        account.balances.available
      );
    }

    const newAvailable = account.balances.available - amount;
    const now = new Date().toISOString();
    const newVersion = account.version + 1;

    await this.db
      .prepare(
        `UPDATE clearing_accounts
         SET balance_available = ?, updated_at = ?, version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newAvailable.toString(),
        now,
        newVersion,
        id,
        account.version
      )
      .run();

    return {
      ...account,
      balances: {
        ...account.balances,
        available: newAvailable,
      },
      updatedAt: now,
      version: newVersion,
    };
  }

  /**
   * Generic bucket operation - credit a specific bucket.
   */
  async creditBucket(
    id: AccountId,
    bucket: BucketName,
    amount: bigint
  ): Promise<ClearingAccount> {
    if (amount < 0n) {
      throw new Error('Amount must be non-negative');
    }

    const account = await this.findById(id);
    if (!account) {
      throw new Error(`Clearing account not found: ${id}`);
    }

    const newBalances = { ...account.balances };
    newBalances[bucket] = account.balances[bucket] + amount;

    const columnMap: Record<BucketName, string> = {
      available: 'balance_available',
      held: 'balance_held',
      bonded: 'balance_bonded',
      feePool: 'balance_fee_pool',
      promo: 'balance_promo',
    };

    const now = new Date().toISOString();
    const newVersion = account.version + 1;

    await this.db
      .prepare(
        `UPDATE clearing_accounts
         SET ${columnMap[bucket]} = ?, updated_at = ?, version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newBalances[bucket].toString(),
        now,
        newVersion,
        id,
        account.version
      )
      .run();

    return {
      ...account,
      balances: newBalances,
      updatedAt: now,
      version: newVersion,
    };
  }

  /**
   * Generic bucket operation - debit a specific bucket.
   */
  async debitBucket(
    id: AccountId,
    bucket: BucketName,
    amount: bigint
  ): Promise<ClearingAccount> {
    if (amount < 0n) {
      throw new Error('Amount must be non-negative');
    }

    const account = await this.findById(id);
    if (!account) {
      throw new Error(`Clearing account not found: ${id}`);
    }

    if (account.balances[bucket] < amount) {
      throw new InsufficientFundsError(id, bucket, amount, account.balances[bucket]);
    }

    const newBalances = { ...account.balances };
    newBalances[bucket] = account.balances[bucket] - amount;

    const columnMap: Record<BucketName, string> = {
      available: 'balance_available',
      held: 'balance_held',
      bonded: 'balance_bonded',
      feePool: 'balance_fee_pool',
      promo: 'balance_promo',
    };

    const now = new Date().toISOString();
    const newVersion = account.version + 1;

    await this.db
      .prepare(
        `UPDATE clearing_accounts
         SET ${columnMap[bucket]} = ?, updated_at = ?, version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newBalances[bucket].toString(),
        now,
        newVersion,
        id,
        account.version
      )
      .run();

    return {
      ...account,
      balances: newBalances,
      updatedAt: now,
      version: newVersion,
    };
  }

  /**
   * Move funds between buckets within the same clearing account.
   */
  async moveBetweenBuckets(
    id: AccountId,
    fromBucket: BucketName,
    toBucket: BucketName,
    amount: bigint
  ): Promise<ClearingAccount> {
    if (amount < 0n) {
      throw new Error('Amount must be non-negative');
    }

    if (fromBucket === toBucket) {
      throw new Error('Source and destination buckets must be different');
    }

    const account = await this.findById(id);
    if (!account) {
      throw new Error(`Clearing account not found: ${id}`);
    }

    if (account.balances[fromBucket] < amount) {
      throw new InsufficientFundsError(id, fromBucket, amount, account.balances[fromBucket]);
    }

    const newBalances = { ...account.balances };
    newBalances[fromBucket] = account.balances[fromBucket] - amount;
    newBalances[toBucket] = account.balances[toBucket] + amount;

    const columnMap: Record<BucketName, string> = {
      available: 'balance_available',
      held: 'balance_held',
      bonded: 'balance_bonded',
      feePool: 'balance_fee_pool',
      promo: 'balance_promo',
    };

    const now = new Date().toISOString();
    const newVersion = account.version + 1;

    await this.db
      .prepare(
        `UPDATE clearing_accounts
         SET ${columnMap[fromBucket]} = ?,
             ${columnMap[toBucket]} = ?,
             updated_at = ?,
             version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newBalances[fromBucket].toString(),
        newBalances[toBucket].toString(),
        now,
        newVersion,
        id,
        account.version
      )
      .run();

    return {
      ...account,
      balances: newBalances,
      updatedAt: now,
      version: newVersion,
    };
  }
}

/**
 * Clearing service for business logic
 */
export class ClearingService {
  private clearingRepo: ClearingAccountRepository;
  private eventRepo: EventRepository;
  private db: D1Database;

  constructor(env: Env) {
    this.db = env.DB;
    this.clearingRepo = new ClearingAccountRepository(this.db);
    this.eventRepo = new EventRepository(this.db);
  }

  /**
   * Create a new clearing account for a domain
   */
  async createClearingAccount(
    request: CreateClearingAccountRequest
  ): Promise<ClearingAccountResponse> {
    if (!request.domain || request.domain.trim() === '') {
      throw new Error('Domain is required');
    }
    if (!request.name || request.name.trim() === '') {
      throw new Error('Name is required');
    }

    const account = await this.clearingRepo.create(request);
    return toClearingAccountResponse(account);
  }

  /**
   * Get clearing account by domain
   */
  async getClearingAccountByDomain(
    domain: ClearingDomain
  ): Promise<ClearingAccountResponse | null> {
    const account = await this.clearingRepo.findByDomain(domain);
    if (!account) {
      return null;
    }
    return toClearingAccountResponse(account);
  }

  /**
   * Get clearing account by ID
   */
  async getClearingAccountById(id: AccountId): Promise<ClearingAccountResponse | null> {
    const account = await this.clearingRepo.findById(id);
    if (!account) {
      return null;
    }
    return toClearingAccountResponse(account);
  }

  /**
   * List all clearing accounts
   */
  async listClearingAccounts(): Promise<ClearingAccountResponse[]> {
    const accounts = await this.clearingRepo.list();
    return accounts.map(toClearingAccountResponse);
  }

  /**
   * Resolve clearing account from ID or domain
   */
  private async resolveClearingAccount(
    clearingAccountId?: AccountId,
    domain?: ClearingDomain
  ): Promise<ClearingAccount> {
    if (clearingAccountId) {
      const account = await this.clearingRepo.findById(clearingAccountId);
      if (!account) {
        throw new Error(`Clearing account not found: ${clearingAccountId}`);
      }
      return account;
    }

    if (domain) {
      const account = await this.clearingRepo.findByDomain(domain);
      if (!account) {
        throw new Error(`Clearing account not found for domain: ${domain}`);
      }
      return account;
    }

    throw new Error('Either clearingAccountId or domain is required');
  }

  /**
   * Deposit funds from a user account to a clearing account
   */
  async deposit(request: ClearingDepositRequest): Promise<ClearingEventResponse> {
    // Validate request
    if (!request.idempotencyKey) {
      throw new Error('Idempotency key is required');
    }
    if (!request.fromAccountId) {
      throw new Error('Source account ID is required');
    }
    if (!request.batchId) {
      throw new Error('Batch ID is required');
    }

    let amount: bigint;
    try {
      amount = BigInt(request.amount);
      if (amount <= 0n) {
        throw new Error('Amount must be positive');
      }
    } catch {
      throw new Error(`Invalid amount: ${request.amount}`);
    }

    // Check for existing event (idempotency)
    const existingEvent = await this.eventRepo.findByIdempotencyKey(request.idempotencyKey);
    if (existingEvent) {
      return {
        eventId: existingEvent.id,
        idempotencyKey: existingEvent.idempotencyKey,
        eventType: 'clearing_deposit',
        userAccountId: existingEvent.accountId,
        clearingAccountId: existingEvent.toAccountId!,
        amount: existingEvent.amount.toString(),
        batchId: request.batchId,
        eventHash: existingEvent.eventHash,
        createdAt: existingEvent.createdAt,
        metadata: existingEvent.metadata,
      };
    }

    // Resolve clearing account
    const clearingAccount = await this.resolveClearingAccount(
      request.clearingAccountId,
      request.domain
    );

    // Debit user account (using raw SQL for now since we need to update user accounts table)
    const userAccountResult = await this.db
      .prepare(
        `SELECT id, balance_available, version FROM accounts WHERE id = ?`
      )
      .bind(request.fromAccountId)
      .first();

    if (!userAccountResult) {
      throw new Error(`User account not found: ${request.fromAccountId}`);
    }

    const userBalance = BigInt((userAccountResult.balance_available as string) || '0');
    if (userBalance < amount) {
      throw new InsufficientFundsError(
        request.fromAccountId,
        'available',
        amount,
        userBalance
      );
    }

    const newUserBalance = userBalance - amount;
    const now = new Date().toISOString();
    const userVersion = userAccountResult.version as number;

    // Update user account balance
    await this.db
      .prepare(
        `UPDATE accounts
         SET balance_available = ?, updated_at = ?, version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newUserBalance.toString(),
        now,
        userVersion + 1,
        request.fromAccountId,
        userVersion
      )
      .run();

    // Credit clearing account
    await this.clearingRepo.creditAvailable(clearingAccount.id, amount);

    // Create event with hash chain
    const previousHash = await this.eventRepo.getLastEventHash();
    const eventType: EventType = 'clearing_deposit';
    const bucket: BucketName = 'available';

    const metadata: Record<string, unknown> = {
      batchId: request.batchId,
      ...request.metadata,
    };

    const eventHash = await computeEventHash(
      previousHash,
      eventType,
      request.fromAccountId,
      clearingAccount.id,
      amount,
      bucket,
      request.idempotencyKey,
      now
    );

    const event = await this.eventRepo.create(
      request.idempotencyKey,
      eventType,
      request.fromAccountId,
      amount,
      bucket,
      previousHash,
      eventHash,
      clearingAccount.id,
      metadata
    );

    return {
      eventId: event.id,
      idempotencyKey: event.idempotencyKey,
      eventType: 'clearing_deposit',
      userAccountId: request.fromAccountId,
      clearingAccountId: clearingAccount.id,
      amount: amount.toString(),
      batchId: request.batchId,
      eventHash: event.eventHash,
      createdAt: event.createdAt,
      metadata,
    };
  }

  /**
   * Withdraw funds from a clearing account to a user account
   */
  async withdraw(request: ClearingWithdrawRequest): Promise<ClearingEventResponse> {
    // Validate request
    if (!request.idempotencyKey) {
      throw new Error('Idempotency key is required');
    }
    if (!request.toAccountId) {
      throw new Error('Destination account ID is required');
    }
    if (!request.batchId) {
      throw new Error('Batch ID is required');
    }

    let amount: bigint;
    try {
      amount = BigInt(request.amount);
      if (amount <= 0n) {
        throw new Error('Amount must be positive');
      }
    } catch {
      throw new Error(`Invalid amount: ${request.amount}`);
    }

    // Check for existing event (idempotency)
    const existingEvent = await this.eventRepo.findByIdempotencyKey(request.idempotencyKey);
    if (existingEvent) {
      return {
        eventId: existingEvent.id,
        idempotencyKey: existingEvent.idempotencyKey,
        eventType: 'clearing_withdraw',
        userAccountId: existingEvent.toAccountId!,
        clearingAccountId: existingEvent.accountId,
        amount: existingEvent.amount.toString(),
        batchId: request.batchId,
        eventHash: existingEvent.eventHash,
        createdAt: existingEvent.createdAt,
        metadata: existingEvent.metadata,
      };
    }

    // Resolve clearing account
    const clearingAccount = await this.resolveClearingAccount(
      request.clearingAccountId,
      request.domain
    );

    // Verify user account exists
    const userAccountResult = await this.db
      .prepare(
        `SELECT id, balance_available, version FROM accounts WHERE id = ?`
      )
      .bind(request.toAccountId)
      .first();

    if (!userAccountResult) {
      throw new Error(`User account not found: ${request.toAccountId}`);
    }

    // Debit clearing account (throws if insufficient funds)
    await this.clearingRepo.debitAvailable(clearingAccount.id, amount);

    // Credit user account
    const userBalance = BigInt((userAccountResult.balance_available as string) || '0');
    const newUserBalance = userBalance + amount;
    const now = new Date().toISOString();
    const userVersion = userAccountResult.version as number;

    await this.db
      .prepare(
        `UPDATE accounts
         SET balance_available = ?, updated_at = ?, version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newUserBalance.toString(),
        now,
        userVersion + 1,
        request.toAccountId,
        userVersion
      )
      .run();

    // Create event with hash chain
    const previousHash = await this.eventRepo.getLastEventHash();
    const eventType: EventType = 'clearing_withdraw';
    const bucket: BucketName = 'available';

    const metadata: Record<string, unknown> = {
      batchId: request.batchId,
      ...request.metadata,
    };

    const eventHash = await computeEventHash(
      previousHash,
      eventType,
      clearingAccount.id,
      request.toAccountId,
      amount,
      bucket,
      request.idempotencyKey,
      now
    );

    const event = await this.eventRepo.create(
      request.idempotencyKey,
      eventType,
      clearingAccount.id,
      amount,
      bucket,
      previousHash,
      eventHash,
      request.toAccountId,
      metadata
    );

    return {
      eventId: event.id,
      idempotencyKey: event.idempotencyKey,
      eventType: 'clearing_withdraw',
      userAccountId: request.toAccountId,
      clearingAccountId: clearingAccount.id,
      amount: amount.toString(),
      batchId: request.batchId,
      eventHash: event.eventHash,
      createdAt: event.createdAt,
      metadata,
    };
  }

  /**
   * Execute a settlement transfer between any accounts (user or clearing)
   * with required batch reference
   */
  async settle(request: SettlementRequest): Promise<SettlementResponse> {
    // Validate request
    if (!request.idempotencyKey) {
      throw new Error('Idempotency key is required');
    }
    if (!request.fromAccountId) {
      throw new Error('Source account ID is required');
    }
    if (!request.toAccountId) {
      throw new Error('Destination account ID is required');
    }
    if (!request.batchId) {
      throw new Error('Batch ID is required for settlements');
    }
    if (request.fromAccountId === request.toAccountId) {
      throw new Error('Cannot settle to the same account');
    }

    let amount: bigint;
    try {
      amount = BigInt(request.amount);
      if (amount <= 0n) {
        throw new Error('Amount must be positive');
      }
    } catch {
      throw new Error(`Invalid amount: ${request.amount}`);
    }

    // Check for existing event (idempotency)
    const existingEvent = await this.eventRepo.findByIdempotencyKey(request.idempotencyKey);
    if (existingEvent) {
      return {
        eventId: existingEvent.id,
        idempotencyKey: existingEvent.idempotencyKey,
        fromAccountId: existingEvent.accountId,
        toAccountId: existingEvent.toAccountId!,
        amount: existingEvent.amount.toString(),
        batchId: request.batchId,
        eventHash: existingEvent.eventHash,
        createdAt: existingEvent.createdAt,
        metadata: existingEvent.metadata,
      };
    }

    const now = new Date().toISOString();

    // Determine if source is clearing or user account
    const isSourceClearing = request.fromAccountId.startsWith('clr_');
    const isDestClearing = request.toAccountId.startsWith('clr_');

    // Debit source account
    if (isSourceClearing) {
      await this.clearingRepo.debitAvailable(request.fromAccountId, amount);
    } else {
      // User account
      const sourceResult = await this.db
        .prepare(
          `SELECT id, balance_available, version FROM accounts WHERE id = ?`
        )
        .bind(request.fromAccountId)
        .first();

      if (!sourceResult) {
        throw new Error(`Source account not found: ${request.fromAccountId}`);
      }

      const sourceBalance = BigInt((sourceResult.balance_available as string) || '0');
      if (sourceBalance < amount) {
        throw new InsufficientFundsError(
          request.fromAccountId,
          'available',
          amount,
          sourceBalance
        );
      }

      await this.db
        .prepare(
          `UPDATE accounts
           SET balance_available = ?, updated_at = ?, version = ?
           WHERE id = ? AND version = ?`
        )
        .bind(
          (sourceBalance - amount).toString(),
          now,
          (sourceResult.version as number) + 1,
          request.fromAccountId,
          sourceResult.version
        )
        .run();
    }

    // Credit destination account
    if (isDestClearing) {
      await this.clearingRepo.creditAvailable(request.toAccountId, amount);
    } else {
      // User account
      const destResult = await this.db
        .prepare(
          `SELECT id, balance_available, version FROM accounts WHERE id = ?`
        )
        .bind(request.toAccountId)
        .first();

      if (!destResult) {
        throw new Error(`Destination account not found: ${request.toAccountId}`);
      }

      const destBalance = BigInt((destResult.balance_available as string) || '0');

      await this.db
        .prepare(
          `UPDATE accounts
           SET balance_available = ?, updated_at = ?, version = ?
           WHERE id = ? AND version = ?`
        )
        .bind(
          (destBalance + amount).toString(),
          now,
          (destResult.version as number) + 1,
          request.toAccountId,
          destResult.version
        )
        .run();
    }

    // Create settlement event with hash chain
    const previousHash = await this.eventRepo.getLastEventHash();
    const eventType: EventType = 'settlement';
    const bucket: BucketName = 'available';

    const metadata: Record<string, unknown> = {
      batchId: request.batchId,
      escrowId: request.escrowId,
      transactionId: request.transactionId,
      settlementType: request.settlementType,
      reason: request.reason,
      ...request.metadata,
    };

    const eventHash = await computeEventHash(
      previousHash,
      eventType,
      request.fromAccountId,
      request.toAccountId,
      amount,
      bucket,
      request.idempotencyKey,
      now
    );

    const event = await this.eventRepo.create(
      request.idempotencyKey,
      eventType,
      request.fromAccountId,
      amount,
      bucket,
      previousHash,
      eventHash,
      request.toAccountId,
      metadata
    );

    return {
      eventId: event.id,
      idempotencyKey: event.idempotencyKey,
      fromAccountId: request.fromAccountId,
      toAccountId: request.toAccountId,
      amount: amount.toString(),
      batchId: request.batchId,
      eventHash: event.eventHash,
      createdAt: event.createdAt,
      metadata,
    };
  }
}
