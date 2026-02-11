import { describe, expect, it } from 'vitest';

import { NettingService } from '../src/netting';
import { ClawSettleError } from '../src/stripe';
import type {
  Env,
  NettingEntryRecord,
  NettingEntryStatus,
  NettingRunRecord,
  NettingRunStatus,
} from '../src/types';

interface CandidatePayout {
  payout_id: string;
  connect_account_id: string;
  currency: string;
  amount_minor: string;
  finalized_at: string;
}

function cloneRun(run: NettingRunRecord): NettingRunRecord {
  return { ...run };
}

function cloneEntry(entry: NettingEntryRecord): NettingEntryRecord {
  return {
    ...entry,
    payout_ids: [...entry.payout_ids],
  };
}

class InMemoryNettingRepository {
  private runsById = new Map<string, NettingRunRecord>();
  private runByIdempotency = new Map<string, string>();
  private entriesById = new Map<string, NettingEntryRecord>();
  private entriesByRun = new Map<string, string[]>();
  private payoutLocks = new Map<string, string>();
  private candidates: CandidatePayout[] = [];
  public ignoreExistingPayoutLocks = false;

  seedCandidates(candidates: CandidatePayout[]): void {
    this.candidates = [...candidates];
  }

  async findRunById(id: string): Promise<NettingRunRecord | null> {
    const run = this.runsById.get(id);
    return run ? cloneRun(run) : null;
  }

  async findRunByIdempotencyKey(idempotencyKey: string): Promise<NettingRunRecord | null> {
    const runId = this.runByIdempotency.get(idempotencyKey);
    if (!runId) {
      return null;
    }

    const run = this.runsById.get(runId);
    return run ? cloneRun(run) : null;
  }

  async createRun(run: NettingRunRecord): Promise<void> {
    if (this.runsById.has(run.id)) {
      throw new Error('UNIQUE constraint failed: netting_runs.id');
    }

    if (this.runByIdempotency.has(run.idempotency_key)) {
      throw new Error('UNIQUE constraint failed: netting_runs.idempotency_key');
    }

    this.runsById.set(run.id, cloneRun(run));
    this.runByIdempotency.set(run.idempotency_key, run.id);
  }

  async transitionRunStatusIfCurrent(params: {
    runId: string;
    from: NettingRunStatus;
    to: NettingRunStatus;
    updatedAt: string;
  }): Promise<boolean> {
    const run = this.runsById.get(params.runId);
    if (!run || run.status !== params.from) {
      return false;
    }

    run.status = params.to;
    run.updated_at = params.updatedAt;
    return true;
  }

  async setRunSummary(params: {
    runId: string;
    candidateCount: number;
    totalAmountMinor: string;
    updatedAt: string;
  }): Promise<void> {
    const run = this.runsById.get(params.runId);
    if (!run) {
      return;
    }

    run.candidate_count = params.candidateCount;
    run.total_amount_minor = params.totalAmountMinor;
    run.updated_at = params.updatedAt;
  }

  async completeRun(params: {
    runId: string;
    status: NettingRunStatus;
    appliedCount: number;
    failedCount: number;
    reportHash: string;
    updatedAt: string;
    completedAt: string;
    lastErrorCode?: string;
    lastErrorMessage?: string;
  }): Promise<void> {
    const run = this.runsById.get(params.runId);
    if (!run) {
      return;
    }

    run.status = params.status;
    run.applied_count = params.appliedCount;
    run.failed_count = params.failedCount;
    run.report_hash = params.reportHash;
    run.updated_at = params.updatedAt;
    run.completed_at = params.completedAt;

    if (params.status === 'applied') {
      run.last_error_code = undefined;
      run.last_error_message = undefined;
    } else {
      run.last_error_code = params.lastErrorCode ?? run.last_error_code;
      run.last_error_message = params.lastErrorMessage ?? run.last_error_message;
    }
  }

  async setRunError(params: {
    runId: string;
    code: string;
    message: string;
    updatedAt: string;
  }): Promise<void> {
    const run = this.runsById.get(params.runId);
    if (!run) {
      return;
    }

    run.status = 'failed';
    run.last_error_code = params.code;
    run.last_error_message = params.message;
    run.updated_at = params.updatedAt;
  }

  async listEntriesByRun(runId: string): Promise<NettingEntryRecord[]> {
    const ids = this.entriesByRun.get(runId) ?? [];
    return ids
      .map((id) => this.entriesById.get(id))
      .filter((entry): entry is NettingEntryRecord => Boolean(entry))
      .map((entry) => cloneEntry(entry));
  }

  async createEntry(entry: NettingEntryRecord): Promise<void> {
    if (this.entriesById.has(entry.id)) {
      throw new Error('UNIQUE constraint failed: netting_entries.id');
    }

    for (const existing of this.entriesById.values()) {
      if (existing.idempotency_key === entry.idempotency_key) {
        throw new Error('UNIQUE constraint failed: netting_entries.idempotency_key');
      }
      if (existing.run_id === entry.run_id && existing.entry_key === entry.entry_key) {
        throw new Error('UNIQUE constraint failed: netting_entries.run_id, netting_entries.entry_key');
      }
    }

    this.entriesById.set(entry.id, cloneEntry(entry));

    const runEntries = this.entriesByRun.get(entry.run_id) ?? [];
    runEntries.push(entry.id);
    runEntries.sort();
    this.entriesByRun.set(entry.run_id, runEntries);
  }

  async deleteEntryById(entryId: string): Promise<void> {
    const entry = this.entriesById.get(entryId);
    if (!entry) {
      return;
    }

    this.entriesById.delete(entryId);

    const runEntries = this.entriesByRun.get(entry.run_id) ?? [];
    this.entriesByRun.set(
      entry.run_id,
      runEntries.filter((id) => id !== entryId)
    );
  }

  async createEntryPayoutMappings(params: {
    runId: string;
    entryId: string;
    payouts: Array<{ payoutId: string; amountMinor: string }>;
    createdAt: string;
  }): Promise<void> {
    void params.runId;
    void params.createdAt;
    for (const payout of params.payouts) {
      if (this.payoutLocks.has(payout.payoutId)) {
        throw new Error('UNIQUE constraint failed: netting_entry_payouts.payout_id');
      }
    }

    for (const payout of params.payouts) {
      this.payoutLocks.set(payout.payoutId, params.entryId);
    }
  }

  async transitionEntryStatusIfCurrent(params: {
    entryId: string;
    from: NettingEntryStatus;
    to: NettingEntryStatus;
    updatedAt: string;
  }): Promise<boolean> {
    const entry = this.entriesById.get(params.entryId);
    if (!entry || entry.status !== params.from) {
      return false;
    }

    entry.status = params.to;
    entry.updated_at = params.updatedAt;
    return true;
  }

  async markEntryApplied(params: {
    entryId: string;
    ledgerEventId: string;
    updatedAt: string;
    appliedAt: string;
  }): Promise<boolean> {
    const entry = this.entriesById.get(params.entryId);
    if (!entry || entry.status !== 'applying') {
      return false;
    }

    entry.status = 'applied';
    entry.ledger_event_id = entry.ledger_event_id ?? params.ledgerEventId;
    entry.applied_at = entry.applied_at ?? params.appliedAt;
    entry.updated_at = params.updatedAt;
    entry.last_error_code = undefined;
    entry.last_error_message = undefined;
    return true;
  }

  async markEntryFailed(params: {
    entryId: string;
    code: string;
    message: string;
    updatedAt: string;
  }): Promise<boolean> {
    const entry = this.entriesById.get(params.entryId);
    if (!entry || entry.status !== 'applying') {
      return false;
    }

    entry.status = 'failed';
    entry.last_error_code = params.code;
    entry.last_error_message = params.message;
    entry.updated_at = params.updatedAt;
    return true;
  }

  async listEligiblePaidPayoutCandidates(params: {
    currency: string;
    selectionBefore: string;
    limit: number;
  }): Promise<CandidatePayout[]> {
    const selected = this.candidates
      .filter((candidate) => candidate.currency === params.currency)
      .filter((candidate) => candidate.finalized_at <= params.selectionBefore)
      .filter((candidate) => this.ignoreExistingPayoutLocks || !this.payoutLocks.has(candidate.payout_id))
      .sort((a, b) => a.finalized_at.localeCompare(b.finalized_at) || a.payout_id.localeCompare(b.payout_id))
      .slice(0, params.limit)
      .map((candidate) => ({ ...candidate }));

    return selected;
  }
}

class MockLedgerForNetting {
  private eventsByIdempotency = new Map<string, { id: string; idempotencyKey: string }>();
  private failNextTransfer = false;
  private eventCounter = 0;
  private clearingBalances = new Map<string, bigint>();

  setClearingBalance(domain: string, amountMinor: bigint): void {
    this.clearingBalances.set(domain, amountMinor);
  }

  getClearingBalance(domain: string): bigint {
    return this.clearingBalances.get(domain) ?? 0n;
  }

  triggerFailNextTransfer(): void {
    this.failNextTransfer = true;
  }

  private parseClearingRef(account: string): string {
    if (!account.startsWith('clearing:')) {
      throw new ClawSettleError('Only clearing refs supported in test ledger', 'INVALID_REQUEST', 400);
    }

    return account.slice('clearing:'.length);
  }

  async findEventByIdempotencyKey(idempotencyKey: string): Promise<{ id: string; idempotencyKey: string } | null> {
    const event = this.eventsByIdempotency.get(idempotencyKey);
    return event ? { ...event } : null;
  }

  async transferV1(input: {
    idempotencyKey: string;
    currency: 'USD';
    from: { account: string; bucket: 'A' | 'H' | 'B' | 'F' | 'P' };
    to: { account: string; bucket: 'A' | 'H' | 'B' | 'F' | 'P' };
    amountMinor: string;
    metadata?: Record<string, unknown>;
  }): Promise<{ event_id: string; status: 'applied' }> {
    void input.metadata;

    const existing = this.eventsByIdempotency.get(input.idempotencyKey);
    if (existing) {
      return {
        event_id: existing.id,
        status: 'applied',
      };
    }

    if (this.failNextTransfer) {
      this.failNextTransfer = false;
      throw new ClawSettleError('Simulated ledger failure', 'LEDGER_INGEST_FAILED', 502);
    }

    if (input.currency !== 'USD') {
      throw new ClawSettleError('Unsupported currency', 'UNSUPPORTED_CURRENCY', 400);
    }

    if (input.from.bucket !== 'A' || input.to.bucket !== 'A') {
      throw new ClawSettleError('Unsupported bucket in test ledger', 'INVALID_REQUEST', 400);
    }

    if (!/^[0-9]+$/.test(input.amountMinor)) {
      throw new ClawSettleError('Invalid amount_minor', 'INVALID_REQUEST', 400);
    }

    const amount = BigInt(input.amountMinor);
    const fromDomain = this.parseClearingRef(input.from.account);
    const toDomain = this.parseClearingRef(input.to.account);

    const fromBalance = this.getClearingBalance(fromDomain);
    if (fromBalance < amount) {
      throw new ClawSettleError('Insufficient funds', 'INSUFFICIENT_FUNDS', 400);
    }

    this.clearingBalances.set(fromDomain, fromBalance - amount);
    this.clearingBalances.set(toDomain, this.getClearingBalance(toDomain) + amount);

    this.eventCounter += 1;
    const eventId = `evt_netting_${this.eventCounter}`;
    this.eventsByIdempotency.set(input.idempotencyKey, {
      id: eventId,
      idempotencyKey: input.idempotencyKey,
    });

    return {
      event_id: eventId,
      status: 'applied',
    };
  }
}

function makeFixture() {
  const repo = new InMemoryNettingRepository();
  const ledger = new MockLedgerForNetting();

  let nowMs = Date.parse('2026-02-11T10:00:00.000Z');
  const now = () => new Date(nowMs).toISOString();

  const env: Env = {
    DB: {} as D1Database,
    SETTLE_ENV: 'staging',
    LEDGER_BASE_URL: 'https://example-ledger.invalid',
    LEDGER_ADMIN_KEY: 'ledger_admin',
    PAYOUTS_CLEARING_DOMAIN: 'clawsettle.payouts',
    NETTING_TARGET_CLEARING_DOMAIN: 'clawsettle.netting',
    NETTING_RUN_DEFAULT_LIMIT: '100',
  };

  const service = new NettingService(env, {
    repository: repo,
    ledgerClient: ledger,
    now,
  });

  return {
    repo,
    ledger,
    service,
    setNowIso(value: string) {
      nowMs = Date.parse(value);
    },
  };
}

describe('netting service', () => {
  it('selects deterministic payout candidates and entry ordering', async () => {
    const fx = makeFixture();

    fx.repo.seedCandidates([
      {
        payout_id: 'p_3',
        connect_account_id: 'acct_B',
        currency: 'USD',
        amount_minor: '700',
        finalized_at: '2026-02-11T09:59:59.000Z',
      },
      {
        payout_id: 'p_1',
        connect_account_id: 'acct_A',
        currency: 'USD',
        amount_minor: '200',
        finalized_at: '2026-02-11T09:00:00.000Z',
      },
      {
        payout_id: 'p_2',
        connect_account_id: 'acct_A',
        currency: 'USD',
        amount_minor: '300',
        finalized_at: '2026-02-11T09:30:00.000Z',
      },
    ]);

    fx.ledger.setClearingBalance('clawsettle.payouts', 1200n);

    const result = await fx.service.createAndExecuteRun(
      {
        currency: 'USD',
        limit: 10,
      },
      'idem_netting_deterministic'
    );

    expect(result.ok).toBe(true);
    expect(result.deduped).toBe(false);
    expect(result.run.status).toBe('applied');
    expect(result.run.candidate_count).toBe(3);
    expect(result.run.total_amount_minor).toBe('1200');

    expect(result.entries).toHaveLength(2);

    const byConnect = [...result.entries].sort((a, b) =>
      a.connect_account_id.localeCompare(b.connect_account_id)
    );

    expect(byConnect[0]?.connect_account_id).toBe('acct_A');
    expect(byConnect[0]?.amount_minor).toBe('500');
    expect(byConnect[0]?.payout_ids).toEqual(['p_1', 'p_2']);

    expect(byConnect[1]?.connect_account_id).toBe('acct_B');
    expect(byConnect[1]?.amount_minor).toBe('700');
    expect(byConnect[1]?.payout_ids).toEqual(['p_3']);

    expect(fx.ledger.getClearingBalance('clawsettle.payouts')).toBe(0n);
    expect(fx.ledger.getClearingBalance('clawsettle.netting')).toBe(1200n);
  });

  it('is exact-once under retry/replay and does not double-apply ledger side effects', async () => {
    const fx = makeFixture();

    fx.repo.seedCandidates([
      {
        payout_id: 'p_retry_1',
        connect_account_id: 'acct_R',
        currency: 'USD',
        amount_minor: '500',
        finalized_at: '2026-02-11T09:00:00.000Z',
      },
    ]);

    fx.ledger.setClearingBalance('clawsettle.payouts', 500n);
    fx.ledger.triggerFailNextTransfer();

    const first = await fx.service.createAndExecuteRun({}, 'idem_netting_retry');
    expect(first.run.status).toBe('failed');
    expect(first.run.failed_count).toBe(1);
    expect(fx.ledger.getClearingBalance('clawsettle.payouts')).toBe(500n);
    expect(fx.ledger.getClearingBalance('clawsettle.netting')).toBe(0n);

    const retry = await fx.service.createAndExecuteRun({}, 'idem_netting_retry');
    expect(retry.run.status).toBe('applied');
    expect(retry.run.failed_count).toBe(0);
    expect(retry.run.applied_count).toBe(1);

    expect(fx.ledger.getClearingBalance('clawsettle.payouts')).toBe(0n);
    expect(fx.ledger.getClearingBalance('clawsettle.netting')).toBe(500n);

    const replay = await fx.service.createAndExecuteRun({}, 'idem_netting_retry');
    expect(replay.deduped).toBe(true);
    expect(replay.run.status).toBe('applied');

    expect(fx.ledger.getClearingBalance('clawsettle.payouts')).toBe(0n);
    expect(fx.ledger.getClearingBalance('clawsettle.netting')).toBe(500n);
  });

  it('fails closed with DUPLICATE_CONFLICT on overlapping netting run collision', async () => {
    const fx = makeFixture();

    fx.repo.seedCandidates([
      {
        payout_id: 'p_overlap_1',
        connect_account_id: 'acct_overlap',
        currency: 'USD',
        amount_minor: '400',
        finalized_at: '2026-02-11T09:00:00.000Z',
      },
    ]);

    fx.ledger.setClearingBalance('clawsettle.payouts', 400n);

    const first = await fx.service.createAndExecuteRun({}, 'idem_netting_overlap_first');
    expect(first.run.status).toBe('applied');

    fx.repo.ignoreExistingPayoutLocks = true;

    await expect(
      fx.service.createAndExecuteRun({}, 'idem_netting_overlap_second')
    ).rejects.toMatchObject({
      code: 'DUPLICATE_CONFLICT',
      status: 409,
    });
  });

  it('produces stable report hashes and consistent csv/json artifacts', async () => {
    const fx = makeFixture();

    fx.repo.seedCandidates([
      {
        payout_id: 'p_hash_1',
        connect_account_id: 'acct_hash',
        currency: 'USD',
        amount_minor: '250',
        finalized_at: '2026-02-11T08:00:00.000Z',
      },
      {
        payout_id: 'p_hash_2',
        connect_account_id: 'acct_hash',
        currency: 'USD',
        amount_minor: '150',
        finalized_at: '2026-02-11T08:30:00.000Z',
      },
    ]);

    fx.ledger.setClearingBalance('clawsettle.payouts', 400n);

    const run = await fx.service.createAndExecuteRun({}, 'idem_netting_report_hash');
    expect(run.run.status).toBe('applied');

    fx.setNowIso('2026-02-11T10:30:00.000Z');
    const report1 = await fx.service.buildRunReport(run.run.id);

    fx.setNowIso('2026-02-11T11:00:00.000Z');
    const report2 = await fx.service.buildRunReport(run.run.id);

    expect(report1.artifact_sha256).toBe(report2.artifact_sha256);
    expect(report1.summary).toEqual(report2.summary);
    expect(report1.entries).toEqual(report2.entries);

    const csv1 = fx.service.toRunReportCsv(report1);
    const csv2 = fx.service.toRunReportCsv(report2);

    expect(csv1).toBe(csv2);
    expect(csv1.split('\n')[0]).toContain('entry_id,connect_account_id,payout_count');
  });
});
