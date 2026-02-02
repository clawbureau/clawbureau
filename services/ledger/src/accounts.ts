/**
 * Account management for ClawLedger
 * Handles account creation, retrieval, and balance management
 */

import type {
  Account,
  AccountId,
  AccountResponse,
  BalanceBuckets,
  CreateAccountRequest,
  DID,
  Env,
} from './types';

/**
 * Derive a deterministic account ID from a DID
 * Uses a simple hash for now; in production, use a proper crypto hash
 */
export function deriveAccountId(did: DID): AccountId {
  // Simple hash using the DID string - deterministic and reproducible
  // In production, use crypto.subtle.digest('SHA-256', ...) for security
  let hash = 0;
  for (let i = 0; i < did.length; i++) {
    const char = did.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  return `acc_${Math.abs(hash).toString(16).padStart(8, '0')}`;
}

/**
 * Create zero-balance buckets for new accounts
 */
export function createEmptyBalances(): BalanceBuckets {
  return {
    available: 0n,
    held: 0n,
    bonded: 0n,
    feePool: 0n,
    promo: 0n,
  };
}

/**
 * Calculate total balance across all buckets
 */
export function calculateTotalBalance(balances: BalanceBuckets): bigint {
  return (
    balances.available +
    balances.held +
    balances.bonded +
    balances.feePool +
    balances.promo
  );
}

/**
 * Convert Account to API response format
 */
export function toAccountResponse(account: Account): AccountResponse {
  const total = calculateTotalBalance(account.balances);
  return {
    id: account.id,
    did: account.did,
    balances: {
      available: account.balances.available.toString(),
      held: account.balances.held.toString(),
      bonded: account.balances.bonded.toString(),
      feePool: account.balances.feePool.toString(),
      promo: account.balances.promo.toString(),
      total: total.toString(),
    },
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  };
}

/**
 * Parse balance buckets from database row
 */
export function parseBalancesFromRow(row: Record<string, unknown>): BalanceBuckets {
  return {
    available: BigInt((row.balance_available as string) || '0'),
    held: BigInt((row.balance_held as string) || '0'),
    bonded: BigInt((row.balance_bonded as string) || '0'),
    feePool: BigInt((row.balance_fee_pool as string) || '0'),
    promo: BigInt((row.balance_promo as string) || '0'),
  };
}

/**
 * Parse Account from database row
 */
export function parseAccountFromRow(row: Record<string, unknown>): Account {
  return {
    id: row.id as string,
    did: row.did as string,
    balances: parseBalancesFromRow(row),
    createdAt: row.created_at as string,
    updatedAt: row.updated_at as string,
    version: row.version as number,
  };
}

/**
 * Validate DID format
 * DIDs should follow the pattern: did:method:identifier
 */
export function isValidDid(did: string): boolean {
  if (!did || typeof did !== 'string') {
    return false;
  }
  // Basic DID format validation: did:method:identifier
  const didPattern = /^did:[a-z0-9]+:[a-zA-Z0-9._%-]+$/;
  return didPattern.test(did);
}

/**
 * Error thrown when an operation would result in a negative balance
 */
export class InsufficientFundsError extends Error {
  constructor(
    public accountId: string,
    public bucket: string,
    public requested: bigint,
    public available: bigint
  ) {
    super(
      `Insufficient funds in ${bucket} bucket for account ${accountId}: requested ${requested}, available ${available}`
    );
    this.name = 'InsufficientFundsError';
  }
}

/**
 * Account repository for database operations
 */
export class AccountRepository {
  constructor(private db: D1Database) {}

  /**
   * Find account by DID
   */
  async findByDid(did: DID): Promise<Account | null> {
    const result = await this.db
      .prepare(
        `SELECT id, did, balance_available, balance_held, balance_bonded,
                balance_fee_pool, balance_promo, created_at, updated_at, version
         FROM accounts WHERE did = ?`
      )
      .bind(did)
      .first();

    if (!result) {
      return null;
    }

    return parseAccountFromRow(result);
  }

  /**
   * Find account by ID
   */
  async findById(id: AccountId): Promise<Account | null> {
    const result = await this.db
      .prepare(
        `SELECT id, did, balance_available, balance_held, balance_bonded,
                balance_fee_pool, balance_promo, created_at, updated_at, version
         FROM accounts WHERE id = ?`
      )
      .bind(id)
      .first();

    if (!result) {
      return null;
    }

    return parseAccountFromRow(result);
  }

  /**
   * Create a new account
   * Returns existing account if DID already exists (idempotent)
   */
  async create(request: CreateAccountRequest): Promise<Account> {
    const { did } = request;

    // Check if account already exists for this DID
    const existing = await this.findByDid(did);
    if (existing) {
      return existing;
    }

    const id = deriveAccountId(did);
    const now = new Date().toISOString();
    const balances = createEmptyBalances();

    await this.db
      .prepare(
        `INSERT INTO accounts (
          id, did, balance_available, balance_held, balance_bonded,
          balance_fee_pool, balance_promo, created_at, updated_at, version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        id,
        did,
        balances.available.toString(),
        balances.held.toString(),
        balances.bonded.toString(),
        balances.feePool.toString(),
        balances.promo.toString(),
        now,
        now,
        1
      )
      .run();

    return {
      id,
      did,
      balances,
      createdAt: now,
      updatedAt: now,
      version: 1,
    };
  }

  /**
   * Get or create account for DID (create on first use)
   */
  async getOrCreate(did: DID): Promise<Account> {
    const existing = await this.findByDid(did);
    if (existing) {
      return existing;
    }
    return this.create({ did });
  }

  /**
   * Create a hold: move funds from available to held bucket
   * Validates sufficient funds before the operation
   */
  async createHold(accountId: AccountId, amount: bigint): Promise<Account> {
    const account = await this.findById(accountId);
    if (!account) {
      throw new Error(`Account not found: ${accountId}`);
    }

    if (account.balances.available < amount) {
      throw new InsufficientFundsError(
        accountId,
        'available',
        amount,
        account.balances.available
      );
    }

    const newAvailable = account.balances.available - amount;
    const newHeld = account.balances.held + amount;
    const now = new Date().toISOString();
    const newVersion = account.version + 1;

    await this.db
      .prepare(
        `UPDATE accounts
         SET balance_available = ?, balance_held = ?, updated_at = ?, version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newAvailable.toString(),
        newHeld.toString(),
        now,
        newVersion,
        accountId,
        account.version
      )
      .run();

    return {
      ...account,
      balances: {
        ...account.balances,
        available: newAvailable,
        held: newHeld,
      },
      updatedAt: now,
      version: newVersion,
    };
  }

  /**
   * Release a hold: move funds from held back to available (cancel)
   * Validates sufficient held funds before the operation
   */
  async releaseHoldToAvailable(accountId: AccountId, amount: bigint): Promise<Account> {
    const account = await this.findById(accountId);
    if (!account) {
      throw new Error(`Account not found: ${accountId}`);
    }

    if (account.balances.held < amount) {
      throw new InsufficientFundsError(
        accountId,
        'held',
        amount,
        account.balances.held
      );
    }

    const newHeld = account.balances.held - amount;
    const newAvailable = account.balances.available + amount;
    const now = new Date().toISOString();
    const newVersion = account.version + 1;

    await this.db
      .prepare(
        `UPDATE accounts
         SET balance_available = ?, balance_held = ?, updated_at = ?, version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newAvailable.toString(),
        newHeld.toString(),
        now,
        newVersion,
        accountId,
        account.version
      )
      .run();

    return {
      ...account,
      balances: {
        ...account.balances,
        available: newAvailable,
        held: newHeld,
      },
      updatedAt: now,
      version: newVersion,
    };
  }

  /**
   * Complete a hold: remove funds from held bucket (for transfer to another account)
   * Validates sufficient held funds before the operation
   */
  async completeHold(accountId: AccountId, amount: bigint): Promise<Account> {
    const account = await this.findById(accountId);
    if (!account) {
      throw new Error(`Account not found: ${accountId}`);
    }

    if (account.balances.held < amount) {
      throw new InsufficientFundsError(
        accountId,
        'held',
        amount,
        account.balances.held
      );
    }

    const newHeld = account.balances.held - amount;
    const now = new Date().toISOString();
    const newVersion = account.version + 1;

    await this.db
      .prepare(
        `UPDATE accounts
         SET balance_held = ?, updated_at = ?, version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newHeld.toString(),
        now,
        newVersion,
        accountId,
        account.version
      )
      .run();

    return {
      ...account,
      balances: {
        ...account.balances,
        held: newHeld,
      },
      updatedAt: now,
      version: newVersion,
    };
  }

  /**
   * Credit an account's available balance (for receiving transfers)
   */
  async creditAvailable(accountId: AccountId, amount: bigint): Promise<Account> {
    const account = await this.findById(accountId);
    if (!account) {
      throw new Error(`Account not found: ${accountId}`);
    }

    const newAvailable = account.balances.available + amount;
    const now = new Date().toISOString();
    const newVersion = account.version + 1;

    await this.db
      .prepare(
        `UPDATE accounts
         SET balance_available = ?, updated_at = ?, version = ?
         WHERE id = ? AND version = ?`
      )
      .bind(
        newAvailable.toString(),
        now,
        newVersion,
        accountId,
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
}

/**
 * Account service for business logic
 */
export class AccountService {
  private repository: AccountRepository;

  constructor(env: Env) {
    this.repository = new AccountRepository(env.DB);
  }

  /**
   * Create or get account for a DID
   * Idempotent: returns existing account if DID already exists
   */
  async createAccount(request: CreateAccountRequest): Promise<AccountResponse> {
    if (!isValidDid(request.did)) {
      throw new Error('Invalid DID format. Expected: did:method:identifier');
    }

    const account = await this.repository.getOrCreate(request.did);
    return toAccountResponse(account);
  }

  /**
   * Get account by DID
   */
  async getAccount(did: DID): Promise<AccountResponse | null> {
    const account = await this.repository.findByDid(did);
    if (!account) {
      return null;
    }
    return toAccountResponse(account);
  }

  /**
   * Get account by ID
   */
  async getAccountById(id: AccountId): Promise<AccountResponse | null> {
    const account = await this.repository.findById(id);
    if (!account) {
      return null;
    }
    return toAccountResponse(account);
  }
}
