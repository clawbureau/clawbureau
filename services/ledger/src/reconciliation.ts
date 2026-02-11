/**
 * Balance reconciliation for ClawLedger
 * Replays events to verify stored balances match computed balances
 */

import type {
  AccountId,
  Balance,
  BalanceBuckets,
  BalanceMismatch,
  BucketName,
  Env,
  EventType,
  ReconciliationAlert,
  ReconciliationReport,
  ReconciliationStatus,
} from './types';
import { computeEventHash, parseEventFromRow } from './events';
import { createEmptyBalances, parseAccountFromRow } from './accounts';

/** Genesis hash for the first event in the chain */
const GENESIS_HASH = '0'.repeat(64);

/**
 * Generate a unique report ID
 */
function generateReportId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `rec_${timestamp}_${random}`;
}

/**
 * Reconciliation repository for storing reports
 */
export class ReconciliationRepository {
  constructor(private db: D1Database) {}

  /**
   * Save a reconciliation report
   */
  async save(report: ReconciliationReport): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO reconciliation_reports (
          id, status, started_at, completed_at, events_replayed,
          accounts_checked, mismatch_count, mismatches, hash_chain_valid,
          hash_chain_errors, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        report.id,
        report.status,
        report.startedAt,
        report.completedAt,
        report.eventsReplayed,
        report.accountsChecked,
        report.mismatchCount,
        JSON.stringify(report.mismatches),
        report.hashChainValid ? 1 : 0,
        JSON.stringify(report.hashChainErrors),
        report.errorMessage ?? null
      )
      .run();
  }

  /**
   * Get a report by ID
   */
  async findById(id: string): Promise<ReconciliationReport | null> {
    const result = await this.db
      .prepare(
        `SELECT id, status, started_at, completed_at, events_replayed,
                accounts_checked, mismatch_count, mismatches, hash_chain_valid,
                hash_chain_errors, error_message
         FROM reconciliation_reports WHERE id = ?`
      )
      .bind(id)
      .first();

    if (!result) {
      return null;
    }

    return this.parseReport(result);
  }

  /**
   * Get the most recent report
   */
  async findLatest(): Promise<ReconciliationReport | null> {
    const result = await this.db
      .prepare(
        `SELECT id, status, started_at, completed_at, events_replayed,
                accounts_checked, mismatch_count, mismatches, hash_chain_valid,
                hash_chain_errors, error_message
         FROM reconciliation_reports
         ORDER BY completed_at DESC LIMIT 1`
      )
      .first();

    if (!result) {
      return null;
    }

    return this.parseReport(result);
  }

  /**
   * Get recent reports
   */
  async findRecent(limit = 10): Promise<ReconciliationReport[]> {
    const results = await this.db
      .prepare(
        `SELECT id, status, started_at, completed_at, events_replayed,
                accounts_checked, mismatch_count, mismatches, hash_chain_valid,
                hash_chain_errors, error_message
         FROM reconciliation_reports
         ORDER BY completed_at DESC LIMIT ?`
      )
      .bind(limit)
      .all();

    return (results.results || []).map((row) =>
      this.parseReport(row as Record<string, unknown>)
    );
  }

  private parseReport(row: Record<string, unknown>): ReconciliationReport {
    let mismatches: BalanceMismatch[] = [];
    let hashChainErrors: string[] = [];

    try {
      mismatches = JSON.parse(row.mismatches as string) || [];
    } catch {
      mismatches = [];
    }

    try {
      hashChainErrors = JSON.parse(row.hash_chain_errors as string) || [];
    } catch {
      hashChainErrors = [];
    }

    return {
      id: row.id as string,
      status: row.status as ReconciliationStatus,
      startedAt: row.started_at as string,
      completedAt: row.completed_at as string,
      eventsReplayed: row.events_replayed as number,
      accountsChecked: row.accounts_checked as number,
      mismatchCount: row.mismatch_count as number,
      mismatches,
      hashChainValid: (row.hash_chain_valid as number) === 1,
      hashChainErrors,
      errorMessage: row.error_message as string | undefined,
    };
  }
}

/**
 * Replay service for balance reconciliation
 * Replays all events and computes expected balances
 */
export class ReconciliationService {
  private repository: ReconciliationRepository;

  constructor(private env: Env) {
    this.repository = new ReconciliationRepository(env.DB);
  }

  /**
   * Run a full balance reconciliation
   * Replays all events, computes balances, and compares to stored balances
   */
  async runReconciliation(): Promise<ReconciliationReport> {
    const reportId = generateReportId();
    const startedAt = new Date().toISOString();

    try {
      // Step 1: Verify hash chain integrity
      const hashChainResult = await this.verifyHashChain();

      // Step 2: Replay all events to compute balances
      const computedBalances = await this.replayEvents();

      // Step 3: Get all stored account balances
      const storedBalances = await this.getStoredBalances();

      // Step 4: Compare computed vs stored balances
      const mismatches = this.compareBalances(computedBalances, storedBalances);

      const completedAt = new Date().toISOString();
      const status: ReconciliationStatus =
        mismatches.length > 0 || !hashChainResult.valid ? 'mismatch' : 'success';

      const report: ReconciliationReport = {
        id: reportId,
        status,
        startedAt,
        completedAt,
        eventsReplayed: hashChainResult.eventsChecked,
        accountsChecked: Object.keys(storedBalances).length,
        mismatchCount: mismatches.length,
        mismatches,
        hashChainValid: hashChainResult.valid,
        hashChainErrors: hashChainResult.errors,
      };

      // Save the report
      await this.repository.save(report);

      // Send alert if mismatches found
      if (status === 'mismatch') {
        await this.sendAlert(report);
      }

      return report;
    } catch (err) {
      const completedAt = new Date().toISOString();
      const errorMessage = err instanceof Error ? err.message : 'Unknown error';

      const report: ReconciliationReport = {
        id: reportId,
        status: 'error',
        startedAt,
        completedAt,
        eventsReplayed: 0,
        accountsChecked: 0,
        mismatchCount: 0,
        mismatches: [],
        hashChainValid: false,
        hashChainErrors: [],
        errorMessage,
      };

      // Save error report
      await this.repository.save(report);

      // Send error alert
      await this.sendAlert(report);

      return report;
    }
  }

  /**
   * Verify hash chain integrity
   */
  private async verifyHashChain(): Promise<{
    valid: boolean;
    errors: string[];
    eventsChecked: number;
  }> {
    const errors: string[] = [];
    let eventsChecked = 0;

    // Get all events in order
    const results = await this.env.DB
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
          `Event ${event.id}: Previous hash mismatch. Expected ${expectedPreviousHash.slice(0, 16)}..., got ${event.previousHash.slice(0, 16)}...`
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
          `Event ${event.id}: Hash mismatch. Expected ${computedHash.slice(0, 16)}..., got ${event.eventHash.slice(0, 16)}...`
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

  /**
   * Replay all events and compute expected balances per account
   */
  private async replayEvents(): Promise<Map<AccountId, BalanceBuckets>> {
    const balances = new Map<AccountId, BalanceBuckets>();

    // Get all events in chronological order
    const results = await this.env.DB
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

    for (const event of events) {
      this.applyEvent(
        balances,
        event.eventType,
        event.accountId,
        event.toAccountId,
        event.amount,
        event.bucket
      );
    }

    return balances;
  }

  /**
   * Apply an event to the computed balances
   */
  private applyEvent(
    balances: Map<AccountId, BalanceBuckets>,
    eventType: EventType,
    accountId: AccountId,
    toAccountId: AccountId | undefined,
    amount: Balance,
    bucket: BucketName
  ): void {
    // Ensure account exists in map
    if (!balances.has(accountId)) {
      balances.set(accountId, createEmptyBalances());
    }

    const accountBalance = balances.get(accountId)!;

    switch (eventType) {
      case 'mint':
        // Mint adds to the specified bucket
        accountBalance[bucket] += amount;
        break;

      case 'burn':
        // Burn removes from the specified bucket
        accountBalance[bucket] -= amount;
        break;

      case 'transfer':
        // Transfer: deduct from source, credit to target
        accountBalance[bucket] -= amount;
        if (toAccountId) {
          if (!balances.has(toAccountId)) {
            balances.set(toAccountId, createEmptyBalances());
          }
          const toBalance = balances.get(toAccountId)!;
          toBalance[bucket] += amount;
        }
        break;

      case 'hold':
        // Hold: move from available to held
        accountBalance.available -= amount;
        accountBalance.held += amount;
        break;

      case 'release':
        // Release: move from held back to available (for cancel)
        // For complete transfers, this would be paired with a transfer event
        accountBalance.held -= amount;
        accountBalance.available += amount;
        break;

      case 'payin_settle':
        // Confirmed inbound settlement credits available funds.
        accountBalance.available += amount;
        break;

      case 'payin_reverse':
        // Reversal/refund settlement debits available funds.
        accountBalance.available -= amount;
        break;

      case 'payout_settle':
        // Settlement marker only; no implicit balance mutation here.
        break;
    }
  }

  /**
   * Get all stored account balances from the database
   */
  private async getStoredBalances(): Promise<Map<AccountId, BalanceBuckets>> {
    const balances = new Map<AccountId, BalanceBuckets>();

    const results = await this.env.DB
      .prepare(
        `SELECT id, did, balance_available, balance_held, balance_bonded,
                balance_fee_pool, balance_promo, created_at, updated_at, version
         FROM accounts`
      )
      .all();

    for (const row of results.results || []) {
      const account = parseAccountFromRow(row as Record<string, unknown>);
      balances.set(account.id, account.balances);
    }

    return balances;
  }

  /**
   * Compare computed balances vs stored balances
   */
  private compareBalances(
    computed: Map<AccountId, BalanceBuckets>,
    stored: Map<AccountId, BalanceBuckets>
  ): BalanceMismatch[] {
    const mismatches: BalanceMismatch[] = [];
    const buckets: BucketName[] = ['available', 'held', 'bonded', 'feePool', 'promo'];

    // Check all accounts in both maps
    const allAccountIds = new Set([...computed.keys(), ...stored.keys()]);

    for (const accountId of allAccountIds) {
      const computedBal = computed.get(accountId) || createEmptyBalances();
      const storedBal = stored.get(accountId) || createEmptyBalances();

      for (const bucket of buckets) {
        const computedValue = computedBal[bucket];
        const storedValue = storedBal[bucket];

        if (computedValue !== storedValue) {
          mismatches.push({
            accountId,
            bucket,
            storedBalance: storedValue.toString(),
            computedBalance: computedValue.toString(),
            difference: (storedValue - computedValue).toString(),
          });
        }
      }
    }

    return mismatches;
  }

  /**
   * Send alert webhook for reconciliation issues
   */
  private async sendAlert(report: ReconciliationReport): Promise<void> {
    const webhookUrl = this.env.ALERT_WEBHOOK_URL;
    if (!webhookUrl) {
      console.log('No ALERT_WEBHOOK_URL configured, skipping alert');
      return;
    }

    const alert: ReconciliationAlert = {
      type: report.status === 'error' ? 'reconciliation_error' : 'reconciliation_mismatch',
      reportId: report.id,
      timestamp: new Date().toISOString(),
      mismatchCount: report.mismatchCount,
      summary: this.buildAlertSummary(report),
      details: report.mismatches.length > 0 ? report.mismatches.slice(0, 10) : undefined,
    };

    try {
      await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(alert),
      });
    } catch (err) {
      console.error('Failed to send reconciliation alert:', err);
    }
  }

  /**
   * Build a human-readable summary for alerts
   */
  private buildAlertSummary(report: ReconciliationReport): string {
    if (report.status === 'error') {
      return `Reconciliation failed: ${report.errorMessage}`;
    }

    const parts: string[] = [];

    if (report.mismatchCount > 0) {
      parts.push(`${report.mismatchCount} balance mismatch(es) found`);
    }

    if (!report.hashChainValid) {
      parts.push(`Hash chain integrity check failed with ${report.hashChainErrors.length} error(s)`);
    }

    if (parts.length === 0) {
      return 'Reconciliation completed successfully';
    }

    return parts.join('. ');
  }

  /**
   * Get a report by ID
   */
  async getReport(id: string): Promise<ReconciliationReport | null> {
    return this.repository.findById(id);
  }

  /**
   * Get the most recent report
   */
  async getLatestReport(): Promise<ReconciliationReport | null> {
    return this.repository.findLatest();
  }

  /**
   * Get recent reports
   */
  async getRecentReports(limit = 10): Promise<ReconciliationReport[]> {
    return this.repository.findRecent(limit);
  }
}
