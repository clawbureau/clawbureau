import { describe, expect, it } from 'vitest';

import { ClawSettleError } from '../src/stripe';
import { PayoutService } from '../src/payouts';
import type {
  Env,
  PayoutConnectAccount,
  PayoutLifecycleHookInput,
  PayoutRecord,
  PayoutStatus,
} from '../src/types';

interface TestLedgerEvent {
  id: string;
  idempotencyKey: string;
}

interface TestAccount {
  id: string;
  did: string;
  balances: {
    available: bigint;
    held: bigint;
  };
}

function clonePayout(record: PayoutRecord): PayoutRecord {
  return {
    ...record,
    metadata: record.metadata ? { ...record.metadata } : undefined,
  };
}

class InMemoryPayoutRepository {
  private connectByAccount = new Map<string, PayoutConnectAccount>();
  private payoutsById = new Map<string, PayoutRecord>();
  private payoutIdByIdem = new Map<string, string>();
  private payoutIdByExternal = new Map<string, string>();
  private auditRows: Array<{
    id: number;
    payout_id: string;
    event_type: string;
    event_idempotency_key?: string;
    details: Record<string, unknown>;
    created_at: string;
  }> = [];
  private auditUniq = new Set<string>();
  private auditId = 0;

  async findConnectAccountByAccountId(accountId: string): Promise<PayoutConnectAccount | null> {
    const row = this.connectByAccount.get(accountId);
    return row ? { ...row } : null;
  }

  async upsertConnectAccount(record: PayoutConnectAccount): Promise<void> {
    this.connectByAccount.set(record.account_id, { ...record });
  }

  async findById(id: string): Promise<PayoutRecord | null> {
    const row = this.payoutsById.get(id);
    return row ? clonePayout(row) : null;
  }

  async findByIdempotencyKey(idempotencyKey: string): Promise<PayoutRecord | null> {
    const payoutId = this.payoutIdByIdem.get(idempotencyKey);
    if (!payoutId) {
      return null;
    }

    const row = this.payoutsById.get(payoutId);
    return row ? clonePayout(row) : null;
  }

  async findByExternalPayoutId(externalPayoutId: string): Promise<PayoutRecord | null> {
    const payoutId = this.payoutIdByExternal.get(externalPayoutId);
    if (!payoutId) {
      return null;
    }

    const row = this.payoutsById.get(payoutId);
    return row ? clonePayout(row) : null;
  }

  async create(record: PayoutRecord): Promise<void> {
    if (this.payoutsById.has(record.id)) {
      throw new Error('UNIQUE constraint failed: payouts.id');
    }

    if (this.payoutIdByIdem.has(record.idempotency_key)) {
      throw new Error('UNIQUE constraint failed: payouts.idempotency_key');
    }

    this.payoutsById.set(record.id, clonePayout(record));
    this.payoutIdByIdem.set(record.idempotency_key, record.id);

    if (record.external_payout_id) {
      this.payoutIdByExternal.set(record.external_payout_id, record.id);
    }
  }

  async setLockEventIfMissing(payoutId: string, lockEventId: string, updatedAt: string): Promise<void> {
    const payout = this.payoutsById.get(payoutId);
    if (!payout) return;

    if (!payout.lock_event_id) {
      payout.lock_event_id = lockEventId;
    }

    payout.updated_at = updatedAt;
  }

  async markSubmittedIfInitiated(params: {
    payoutId: string;
    externalPayoutId: string;
    updatedAt: string;
    submittedAt: string;
  }): Promise<boolean> {
    const payout = this.payoutsById.get(params.payoutId);
    if (!payout || payout.status !== 'initiated') {
      return false;
    }

    payout.status = 'submitted';
    if (!payout.external_payout_id) {
      payout.external_payout_id = params.externalPayoutId;
      this.payoutIdByExternal.set(params.externalPayoutId, payout.id);
    }
    payout.submitted_at = payout.submitted_at ?? params.submittedAt;
    payout.updated_at = params.updatedAt;
    payout.last_error_code = undefined;
    payout.last_error_message = undefined;

    return true;
  }

  async updateStatusIfCurrent(params: {
    payoutId: string;
    fromStatus: PayoutStatus;
    toStatus: PayoutStatus;
    updatedAt: string;
    finalizedAt?: string;
    failedAt?: string;
    clearErrors?: boolean;
  }): Promise<boolean> {
    const payout = this.payoutsById.get(params.payoutId);
    if (!payout || payout.status !== params.fromStatus) {
      return false;
    }

    payout.status = params.toStatus;
    payout.updated_at = params.updatedAt;
    if (params.finalizedAt) {
      payout.finalized_at = params.finalizedAt;
    }
    if (params.failedAt) {
      payout.failed_at = params.failedAt;
    }

    if (params.clearErrors) {
      payout.last_error_code = undefined;
      payout.last_error_message = undefined;
    }

    return true;
  }

  async setFinalizeEventIfMissing(payoutId: string, eventId: string, updatedAt: string): Promise<void> {
    const payout = this.payoutsById.get(payoutId);
    if (!payout) return;

    if (!payout.finalize_event_id) {
      payout.finalize_event_id = eventId;
    }
    payout.updated_at = updatedAt;
  }

  async setRollbackEventIfMissing(payoutId: string, eventId: string, updatedAt: string): Promise<void> {
    const payout = this.payoutsById.get(payoutId);
    if (!payout) return;

    if (!payout.rollback_event_id) {
      payout.rollback_event_id = eventId;
    }
    payout.updated_at = updatedAt;
  }

  async setLifecycleError(payoutId: string, code: string, message: string, updatedAt: string): Promise<void> {
    const payout = this.payoutsById.get(payoutId);
    if (!payout) return;

    payout.last_error_code = code;
    payout.last_error_message = message;
    payout.updated_at = updatedAt;
  }

  async appendAuditEvent(params: {
    payoutId: string;
    eventType: string;
    eventIdempotencyKey?: string;
    details: Record<string, unknown>;
    createdAt: string;
  }): Promise<void> {
    const uniq = `${params.payoutId}:${params.eventType}:${params.eventIdempotencyKey ?? ''}`;
    if (this.auditUniq.has(uniq)) {
      return;
    }

    this.auditUniq.add(uniq);
    this.auditId += 1;
    this.auditRows.push({
      id: this.auditId,
      payout_id: params.payoutId,
      event_type: params.eventType,
      event_idempotency_key: params.eventIdempotencyKey,
      details: { ...params.details },
      created_at: params.createdAt,
    });
  }

  async listAuditEvents(payoutId: string): Promise<Array<Record<string, unknown>>> {
    return this.auditRows
      .filter((row) => row.payout_id === payoutId)
      .map((row) => ({
        id: row.id,
        payout_id: row.payout_id,
        event_type: row.event_type,
        event_idempotency_key: row.event_idempotency_key,
        details: { ...row.details },
        created_at: row.created_at,
      }));
  }

  async listStuck(params: {
    statuses: PayoutStatus[];
    beforeOrAtIso: string;
    limit: number;
  }): Promise<PayoutRecord[]> {
    const cutoff = Date.parse(params.beforeOrAtIso);
    const statuses = new Set(params.statuses);

    return Array.from(this.payoutsById.values())
      .filter((row) => statuses.has(row.status))
      .filter((row) => Date.parse(row.updated_at) <= cutoff)
      .sort((a, b) => a.updated_at.localeCompare(b.updated_at) || a.id.localeCompare(b.id))
      .slice(0, params.limit)
      .map((row) => clonePayout(row));
  }

  async listFailed(limit: number): Promise<PayoutRecord[]> {
    return Array.from(this.payoutsById.values())
      .filter((row) => row.status === 'failed')
      .sort((a, b) => (b.failed_at ?? '').localeCompare(a.failed_at ?? '') || b.id.localeCompare(a.id))
      .slice(0, limit)
      .map((row) => clonePayout(row));
  }

  async listByCreatedRange(params: {
    startIso: string;
    endIso: string;
    limit: number;
  }): Promise<PayoutRecord[]> {
    return Array.from(this.payoutsById.values())
      .filter((row) => row.created_at >= params.startIso && row.created_at < params.endIso)
      .sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id))
      .slice(0, params.limit)
      .map((row) => clonePayout(row));
  }
}

class MockLedgerClient {
  private accountById = new Map<string, TestAccount>();
  private didToAccountId = new Map<string, string>();
  private clearingBalances = new Map<string, { available: bigint; held: bigint }>();
  private eventsByIdem = new Map<string, TestLedgerEvent>();
  private eventCounter = 0;
  private failOnceByIdem = new Set<string>();

  seedAccount(account: { id: string; did: string; available: bigint; held?: bigint }): void {
    const row: TestAccount = {
      id: account.id,
      did: account.did,
      balances: {
        available: account.available,
        held: account.held ?? 0n,
      },
    };
    this.accountById.set(row.id, row);
    this.didToAccountId.set(row.did, row.id);
  }

  setFailOnce(idempotencyKey: string): void {
    this.failOnceByIdem.add(idempotencyKey);
  }

  getAccountState(accountId: string): { available: bigint; held: bigint } {
    const account = this.accountById.get(accountId);
    if (!account) {
      throw new Error(`Unknown account ${accountId}`);
    }

    return {
      available: account.balances.available,
      held: account.balances.held,
    };
  }

  async getAccountById(accountId: string): Promise<{ id: string; did: string; balances: { available: string; held: string } }> {
    const account = this.accountById.get(accountId);
    if (!account) {
      throw new ClawSettleError('Account not found', 'NOT_FOUND', 404, { account_id: accountId });
    }

    return {
      id: account.id,
      did: account.did,
      balances: {
        available: account.balances.available.toString(),
        held: account.balances.held.toString(),
      },
    };
  }

  async findEventByIdempotencyKey(idempotencyKey: string): Promise<{ id: string; idempotencyKey: string } | null> {
    const event = this.eventsByIdem.get(idempotencyKey);
    return event ? { ...event } : null;
  }

  private resolveAccountRef(ref: string): { kind: 'user' | 'clearing'; accountId: string } {
    if (ref.startsWith('did:')) {
      const accountId = this.didToAccountId.get(ref);
      if (!accountId) {
        throw new ClawSettleError('Account not found', 'NOT_FOUND', 404, {
          did: ref,
        });
      }
      return { kind: 'user', accountId };
    }

    if (ref.startsWith('clearing:')) {
      const domain = ref.slice('clearing:'.length);
      if (!this.clearingBalances.has(domain)) {
        this.clearingBalances.set(domain, { available: 0n, held: 0n });
      }
      return { kind: 'clearing', accountId: domain };
    }

    throw new ClawSettleError('Unsupported account ref', 'INVALID_REQUEST', 400, { ref });
  }

  private debit(target: { kind: 'user' | 'clearing'; accountId: string }, bucket: 'A' | 'H', amount: bigint): void {
    if (target.kind === 'user') {
      const account = this.accountById.get(target.accountId);
      if (!account) {
        throw new ClawSettleError('Account not found', 'NOT_FOUND', 404, {
          account_id: target.accountId,
        });
      }

      if (bucket === 'A') {
        if (account.balances.available < amount) {
          throw new ClawSettleError('Insufficient funds', 'INSUFFICIENT_FUNDS', 400);
        }
        account.balances.available -= amount;
      } else {
        if (account.balances.held < amount) {
          throw new ClawSettleError('Insufficient funds', 'INSUFFICIENT_FUNDS', 400);
        }
        account.balances.held -= amount;
      }
      return;
    }

    const clearing = this.clearingBalances.get(target.accountId);
    if (!clearing) {
      throw new ClawSettleError('Clearing not found', 'NOT_FOUND', 404);
    }

    if (bucket === 'A') {
      if (clearing.available < amount) {
        throw new ClawSettleError('Insufficient funds', 'INSUFFICIENT_FUNDS', 400);
      }
      clearing.available -= amount;
    } else {
      if (clearing.held < amount) {
        throw new ClawSettleError('Insufficient funds', 'INSUFFICIENT_FUNDS', 400);
      }
      clearing.held -= amount;
    }
  }

  private credit(target: { kind: 'user' | 'clearing'; accountId: string }, bucket: 'A' | 'H', amount: bigint): void {
    if (target.kind === 'user') {
      const account = this.accountById.get(target.accountId);
      if (!account) {
        throw new ClawSettleError('Account not found', 'NOT_FOUND', 404, {
          account_id: target.accountId,
        });
      }

      if (bucket === 'A') {
        account.balances.available += amount;
      } else {
        account.balances.held += amount;
      }
      return;
    }

    const clearing = this.clearingBalances.get(target.accountId);
    if (!clearing) {
      throw new ClawSettleError('Clearing not found', 'NOT_FOUND', 404);
    }

    if (bucket === 'A') {
      clearing.available += amount;
    } else {
      clearing.held += amount;
    }
  }

  async transferV1(input: {
    idempotencyKey: string;
    currency: 'USD';
    from: { account: string; bucket: 'A' | 'H' | 'B' | 'F' | 'P' };
    to: { account: string; bucket: 'A' | 'H' | 'B' | 'F' | 'P' };
    amountMinor: string;
    metadata?: Record<string, unknown>;
  }): Promise<{ event_id: string; status: 'applied' }> {
    const existing = this.eventsByIdem.get(input.idempotencyKey);
    if (existing) {
      return { event_id: existing.id, status: 'applied' };
    }

    if (this.failOnceByIdem.has(input.idempotencyKey)) {
      this.failOnceByIdem.delete(input.idempotencyKey);
      throw new ClawSettleError('Ledger transfer failed', 'LEDGER_INGEST_FAILED', 502);
    }

    if (input.currency !== 'USD') {
      throw new ClawSettleError('Unsupported currency', 'UNSUPPORTED_CURRENCY', 400);
    }

    if (!/^[0-9]+$/.test(input.amountMinor)) {
      throw new ClawSettleError('Invalid amount', 'INVALID_REQUEST', 400);
    }

    if (input.from.bucket !== 'A' && input.from.bucket !== 'H') {
      throw new ClawSettleError('Unsupported from bucket in test ledger', 'INVALID_REQUEST', 400);
    }

    if (input.to.bucket !== 'A' && input.to.bucket !== 'H') {
      throw new ClawSettleError('Unsupported to bucket in test ledger', 'INVALID_REQUEST', 400);
    }

    const amount = BigInt(input.amountMinor);
    const from = this.resolveAccountRef(input.from.account);
    const to = this.resolveAccountRef(input.to.account);

    this.debit(from, input.from.bucket, amount);
    this.credit(to, input.to.bucket, amount);

    this.eventCounter += 1;
    const eventId = `evt_ledger_${this.eventCounter}`;
    this.eventsByIdem.set(input.idempotencyKey, {
      id: eventId,
      idempotencyKey: input.idempotencyKey,
    });

    return {
      event_id: eventId,
      status: 'applied',
    };
  }
}

function makeServiceFixture() {
  const repo = new InMemoryPayoutRepository();
  const ledger = new MockLedgerClient();

  let now = Date.parse('2026-02-11T12:00:00.000Z');
  const nowFn = () => new Date(now).toISOString();

  const env: Env = {
    DB: {} as D1Database,
    SETTLE_ENV: 'staging',
    STRIPE_WEBHOOK_SIGNING_SECRET: 'whsec_test',
    LEDGER_BASE_URL: 'https://example-ledger.invalid',
    LEDGER_ADMIN_KEY: 'ledger_admin',
    PAYOUTS_CLEARING_DOMAIN: 'clawsettle.payouts',
    PAYOUT_STUCK_MINUTES_DEFAULT: '60',
    STRIPE_CONNECT_ONBOARD_BASE_URL: 'https://dashboard.stripe.test/connect/accounts',
  };

  const service = new PayoutService(env, {
    repository: repo,
    ledgerClient: ledger,
    now: nowFn,
  });

  return {
    service,
    repo,
    ledger,
    setNowIso(value: string) {
      now = Date.parse(value);
    },
    advanceMs(delta: number) {
      now += delta;
    },
  };
}

describe('payout service', () => {
  it('onboards payout destination and initiates payout with deterministic idempotency and lock semantics', async () => {
    const fx = makeServiceFixture();
    fx.ledger.seedAccount({
      id: 'acc_payout_1',
      did: 'did:key:acc_payout_1',
      available: 5000n,
      held: 0n,
    });

    const onboard = await fx.service.onboardConnectAccount({
      account_id: 'acc_payout_1',
      refresh_url: 'https://example.com/refresh',
      return_url: 'https://example.com/return',
    });

    expect(onboard.ok).toBe(true);
    expect(onboard.deduped).toBe(false);
    expect(onboard.account.connect_account_id.startsWith('acct_')).toBe(true);

    const payout1 = await fx.service.createPayout(
      {
        account_id: 'acc_payout_1',
        amount_minor: '1200',
        currency: 'USD',
        metadata: { invoice: 'inv_1' },
      },
      'idem_payout_1'
    );

    expect(payout1.ok).toBe(true);
    expect(payout1.deduped).toBe(false);
    expect(payout1.payout.status).toBe('submitted');
    expect(payout1.payout.lock_event_id).toBeTruthy();
    expect(payout1.payout.external_payout_id).toBeTruthy();

    const balanceAfterLock = fx.ledger.getAccountState('acc_payout_1');
    expect(balanceAfterLock.available).toBe(3800n);
    expect(balanceAfterLock.held).toBe(1200n);

    const replay = await fx.service.createPayout(
      {
        account_id: 'acc_payout_1',
        amount_minor: '1200',
        currency: 'USD',
        metadata: { invoice: 'inv_1' },
      },
      'idem_payout_1'
    );

    expect(replay.deduped).toBe(true);
    expect(replay.payout.id).toBe(payout1.payout.id);

    await expect(
      fx.service.createPayout(
        {
          account_id: 'acc_payout_1',
          amount_minor: '1300',
          currency: 'USD',
          metadata: { invoice: 'inv_1' },
        },
        'idem_payout_1'
      )
    ).rejects.toMatchObject({
      code: 'IDEMPOTENCY_KEY_REUSED',
      status: 409,
    });
  });

  it('applies payout.paid lifecycle exactly once under replay', async () => {
    const fx = makeServiceFixture();
    fx.ledger.seedAccount({
      id: 'acc_paid_1',
      did: 'did:key:acc_paid_1',
      available: 4000n,
      held: 0n,
    });

    await fx.service.onboardConnectAccount({ account_id: 'acc_paid_1' });
    const created = await fx.service.createPayout(
      {
        account_id: 'acc_paid_1',
        amount_minor: '1000',
        currency: 'USD',
      },
      'idem_paid_1'
    );

    const externalId = created.payout.external_payout_id;
    expect(externalId).toBeTruthy();

    const paidHook: PayoutLifecycleHookInput = {
      event_id: 'evt_paid_1',
      event_type: 'payout.paid',
      idempotency_key: 'stripe:event:evt_paid_1',
      payload: {
        provider: 'stripe',
        external_payment_id: String(externalId),
        direction: 'payout',
        status: 'confirmed',
        account_id: 'acc_paid_1',
        amount_minor: '1000',
        currency: 'USD',
      },
      ledger_status: 200,
      settlement_id: 'set_paid_1',
    };

    await fx.service.applyStripeLifecycle(paidHook);
    await fx.service.applyStripeLifecycle(paidHook);

    const payout = await fx.service.getPayoutById(created.payout.id);
    expect(payout.payout.status).toBe('paid');
    expect(payout.payout.finalize_event_id).toBeTruthy();

    const balance = fx.ledger.getAccountState('acc_paid_1');
    expect(balance.available).toBe(3000n);
    expect(balance.held).toBe(0n);

    await expect(
      fx.service.applyStripeLifecycle({
        ...paidHook,
        event_id: 'evt_failed_after_paid',
        event_type: 'payout.failed',
        idempotency_key: 'stripe:event:evt_failed_after_paid',
        payload: {
          ...paidHook.payload,
          status: 'failed',
        },
      })
    ).rejects.toMatchObject({
      code: 'INVALID_STATUS_TRANSITION',
      status: 409,
    });
  });

  it('applies payout.failed rollback exactly once and supports targeted retry for stuck finalizing state', async () => {
    const fx = makeServiceFixture();
    fx.ledger.seedAccount({
      id: 'acc_failed_1',
      did: 'did:key:acc_failed_1',
      available: 5000n,
      held: 0n,
    });

    await fx.service.onboardConnectAccount({ account_id: 'acc_failed_1' });
    const created = await fx.service.createPayout(
      {
        account_id: 'acc_failed_1',
        amount_minor: '900',
        currency: 'USD',
      },
      'idem_failed_1'
    );

    fx.ledger.setFailOnce(created.payout.rollback_idempotency_key);

    const failedHook: PayoutLifecycleHookInput = {
      event_id: 'evt_failed_1',
      event_type: 'payout.failed',
      idempotency_key: 'stripe:event:evt_failed_1',
      payload: {
        provider: 'stripe',
        external_payment_id: String(created.payout.external_payout_id),
        direction: 'payout',
        status: 'failed',
        account_id: 'acc_failed_1',
        amount_minor: '900',
        currency: 'USD',
      },
      ledger_status: 200,
      settlement_id: 'set_failed_1',
    };

    await expect(fx.service.applyStripeLifecycle(failedHook)).rejects.toMatchObject({
      code: 'LEDGER_INGEST_FAILED',
    });

    const stuckBeforeRetry = await fx.service.getPayoutById(created.payout.id);
    expect(stuckBeforeRetry.payout.status).toBe('finalizing_failed');

    const retry = await fx.service.retryPayout(created.payout.id);
    expect(retry.retried).toBe(true);
    expect(retry.status).toBe('failed');

    const replay = await fx.service.applyStripeLifecycle(failedHook);
    expect(replay).toBeUndefined();

    const failed = await fx.service.getPayoutById(created.payout.id);
    expect(failed.payout.status).toBe('failed');
    expect(failed.payout.rollback_event_id).toBeTruthy();

    const balance = fx.ledger.getAccountState('acc_failed_1');
    expect(balance.available).toBe(5000n);
    expect(balance.held).toBe(0n);

    fx.advanceMs(2 * 60_000);
    const stuck = await fx.service.listStuckPayouts({ olderThanMinutes: '1', limit: '50' });
    expect(stuck.payouts.find((row) => row.id === created.payout.id)).toBeUndefined();

    const failedList = await fx.service.listFailedPayouts({ limit: '50' });
    expect(failedList.payouts.some((row) => row.id === created.payout.id)).toBe(true);
  });

  it('builds deterministic daily reconciliation report and csv export', async () => {
    const fx = makeServiceFixture();
    fx.ledger.seedAccount({
      id: 'acc_recon_1',
      did: 'did:key:acc_recon_1',
      available: 8000n,
      held: 0n,
    });

    await fx.service.onboardConnectAccount({ account_id: 'acc_recon_1' });

    const payoutA = await fx.service.createPayout(
      { account_id: 'acc_recon_1', amount_minor: '1500', currency: 'USD' },
      'idem_recon_a'
    );

    const payoutB = await fx.service.createPayout(
      { account_id: 'acc_recon_1', amount_minor: '600', currency: 'USD' },
      'idem_recon_b'
    );

    await fx.service.applyStripeLifecycle({
      event_id: 'evt_recon_paid',
      event_type: 'payout.paid',
      idempotency_key: 'stripe:event:evt_recon_paid',
      payload: {
        provider: 'stripe',
        external_payment_id: String(payoutA.payout.external_payout_id),
        direction: 'payout',
        status: 'confirmed',
        account_id: 'acc_recon_1',
        amount_minor: '1500',
        currency: 'USD',
      },
    });

    await fx.service.applyStripeLifecycle({
      event_id: 'evt_recon_failed',
      event_type: 'payout.failed',
      idempotency_key: 'stripe:event:evt_recon_failed',
      payload: {
        provider: 'stripe',
        external_payment_id: String(payoutB.payout.external_payout_id),
        direction: 'payout',
        status: 'failed',
        account_id: 'acc_recon_1',
        amount_minor: '600',
        currency: 'USD',
      },
    });

    fx.setNowIso('2026-02-11T18:00:00.000Z');

    const report = await fx.service.buildDailyReconciliationReport('2026-02-11');

    expect(report.rows.length).toBe(2);
    expect(report.totals.payout_count).toBe(2);
    expect(report.totals.amount_minor_total).toBe('2100');
    expect(report.totals.amount_minor_by_status.paid).toBe('1500');
    expect(report.totals.amount_minor_by_status.failed).toBe('600');
    expect(typeof report.artifact_sha256).toBe('string');
    expect(report.artifact_sha256.length).toBe(64);

    const csv = fx.service.toDailyReconciliationCsv(report);
    expect(csv.split('\n')[0]).toContain('payout_id,account_id,external_payout_id');
    expect(csv).toContain(payoutA.payout.id);
    expect(csv).toContain(payoutB.payout.id);
  });
});
