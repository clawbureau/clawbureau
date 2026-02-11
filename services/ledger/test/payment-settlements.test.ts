import { describe, expect, it } from 'vitest';

import { InsufficientFundsError } from '../src/accounts';
import { computeEventHash, isValidEventType } from '../src/events';
import {
  PaymentSettlementError,
  PaymentSettlementService,
  type PaymentSettlementIngestionRecord,
  type PaymentSettlementRepositoryLike,
} from '../src/payment-settlements';
import type {
  LedgerEvent,
  MachinePaymentSettlement,
  PaymentSettlementDirection,
  PaymentSettlementIngestRequest,
  PaymentSettlementListQuery,
  PaymentSettlementListResponse,
} from '../src/types';

function makeNowClock(start = '2026-02-11T00:00:00.000Z'): () => string {
  let current = Date.parse(start);

  return () => {
    const out = new Date(current).toISOString();
    current += 1;
    return out;
  };
}

function settlementKey(
  provider: string,
  externalPaymentId: string,
  direction: PaymentSettlementDirection
): string {
  return `${provider}::${externalPaymentId}::${direction}`;
}

class InMemorySettlementRepository implements PaymentSettlementRepositoryLike {
  private settlements = new Map<string, MachinePaymentSettlement>();
  private byNatural = new Map<string, string>();
  private ingestions = new Map<string, PaymentSettlementIngestionRecord>();

  async findByNaturalKey(
    provider: string,
    externalPaymentId: string,
    direction: PaymentSettlementDirection
  ): Promise<MachinePaymentSettlement | null> {
    const id = this.byNatural.get(settlementKey(provider, externalPaymentId, direction));
    return id ? { ...this.settlements.get(id)! } : null;
  }

  async findByProviderExternal(
    provider: string,
    externalPaymentId: string,
    direction?: PaymentSettlementDirection
  ): Promise<MachinePaymentSettlement[]> {
    const out: MachinePaymentSettlement[] = [];

    for (const settlement of this.settlements.values()) {
      if (settlement.provider !== provider) continue;
      if (settlement.external_payment_id !== externalPaymentId) continue;
      if (direction && settlement.direction !== direction) continue;
      out.push({ ...settlement });
    }

    out.sort((a, b) => {
      if (a.created_at === b.created_at) {
        return a.id < b.id ? 1 : -1;
      }
      return a.created_at < b.created_at ? 1 : -1;
    });

    return out;
  }

  async createSettlement(settlement: MachinePaymentSettlement): Promise<void> {
    this.settlements.set(settlement.id, { ...settlement });
    this.byNatural.set(
      settlementKey(
        settlement.provider,
        settlement.external_payment_id,
        settlement.direction
      ),
      settlement.id
    );
  }

  async updateSettlement(settlement: MachinePaymentSettlement): Promise<void> {
    this.settlements.set(settlement.id, { ...settlement });
  }

  async listSettlements(_query: PaymentSettlementListQuery): Promise<PaymentSettlementListResponse> {
    return {
      settlements: [...this.settlements.values()].map((x) => ({ ...x })),
      next_cursor: undefined,
    };
  }

  async findIngestionByIdempotencyKey(
    idempotencyKey: string
  ): Promise<PaymentSettlementIngestionRecord | null> {
    const row = this.ingestions.get(idempotencyKey);
    return row ? { ...row } : null;
  }

  async createIngestion(record: PaymentSettlementIngestionRecord): Promise<void> {
    if (this.ingestions.has(record.idempotency_key)) {
      throw new Error('UNIQUE constraint failed: payment_settlement_ingestions.idempotency_key');
    }

    this.ingestions.set(record.idempotency_key, { ...record });
  }
}

class InMemoryAccountRepository {
  private balances = new Map<string, bigint>();

  createAccount(id: string, available = 0n): void {
    this.balances.set(id, available);
  }

  setAvailable(id: string, available: bigint): void {
    this.balances.set(id, available);
  }

  getAvailable(id: string): bigint {
    return this.balances.get(id) ?? 0n;
  }

  async findById(id: string): Promise<{ id: string } | null> {
    return this.balances.has(id) ? { id } : null;
  }

  async creditAvailable(id: string, amount: bigint): Promise<void> {
    const current = this.balances.get(id);
    if (current === undefined) {
      throw new Error(`Account not found: ${id}`);
    }

    this.balances.set(id, current + amount);
  }

  async debitAvailable(id: string, amount: bigint): Promise<void> {
    const current = this.balances.get(id);
    if (current === undefined) {
      throw new Error(`Account not found: ${id}`);
    }

    if (current < amount) {
      throw new InsufficientFundsError(id, 'available', amount, current);
    }

    this.balances.set(id, current - amount);
  }
}

class InMemoryEventRepository {
  public readonly events: LedgerEvent[] = [];
  private byIdempotency = new Map<string, LedgerEvent>();
  private byId = new Map<string, LedgerEvent>();

  async findById(id: string): Promise<LedgerEvent | null> {
    return this.byId.get(id) ?? null;
  }

  async getLastEventHash(): Promise<string> {
    return this.events.length === 0
      ? '0'.repeat(64)
      : this.events[this.events.length - 1]!.eventHash;
  }

  async create(
    idempotencyKey: string,
    eventType: LedgerEvent['eventType'],
    accountId: string,
    amount: bigint,
    bucket: 'available',
    previousHash: string,
    eventHash: string,
    toAccountId?: string,
    metadata?: Record<string, unknown>,
    createdAt?: string
  ): Promise<LedgerEvent> {
    const existing = this.byIdempotency.get(idempotencyKey);
    if (existing) {
      return existing;
    }

    const id = `evt_${this.events.length + 1}`;
    const event: LedgerEvent = {
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
      createdAt: createdAt ?? new Date().toISOString(),
    };

    this.events.push(event);
    this.byIdempotency.set(idempotencyKey, event);
    this.byId.set(id, event);

    return event;
  }
}

function makePayinRequest(
  overrides: Partial<PaymentSettlementIngestRequest> = {}
): PaymentSettlementIngestRequest {
  return {
    provider: 'provider_sim',
    external_payment_id: 'pay_sim_001',
    direction: 'payin',
    status: 'confirmed',
    account_id: 'acc_test_001',
    amount_minor: '1000',
    currency: 'USD',
    ...overrides,
  };
}

describe('machine payment settlements', () => {
  it('supports idempotency replay for same key + same payload', async () => {
    const settlementRepo = new InMemorySettlementRepository();
    const accountRepo = new InMemoryAccountRepository();
    const eventRepo = new InMemoryEventRepository();

    accountRepo.createAccount('acc_test_001', 0n);

    const service = new PaymentSettlementService(
      { DB: {} as D1Database },
      {
        settlementRepository: settlementRepo,
        accountRepository: accountRepo,
        eventRepository: eventRepo,
        now: makeNowClock(),
      }
    );

    const request = makePayinRequest();

    const first = await service.ingest(request, 'idem_payin_001');
    const replay = await service.ingest(request, 'idem_payin_001');

    expect(first.idempotency.replayed).toBe(false);
    expect(replay.idempotency.replayed).toBe(true);
    expect(replay.settlement.id).toBe(first.settlement.id);
    expect(accountRepo.getAvailable('acc_test_001')).toBe(1000n);
    expect(eventRepo.events).toHaveLength(1);
  });

  it('dedupes duplicate natural-key ingest without replay side effects', async () => {
    const settlementRepo = new InMemorySettlementRepository();
    const accountRepo = new InMemoryAccountRepository();
    const eventRepo = new InMemoryEventRepository();

    accountRepo.createAccount('acc_test_001', 0n);

    const service = new PaymentSettlementService(
      { DB: {} as D1Database },
      {
        settlementRepository: settlementRepo,
        accountRepository: accountRepo,
        eventRepository: eventRepo,
        now: makeNowClock(),
      }
    );

    const request = makePayinRequest();

    const first = await service.ingest(request, 'idem_payin_002_a');
    const duplicate = await service.ingest(request, 'idem_payin_002_b');

    expect(first.idempotency.deduped).toBe(false);
    expect(duplicate.idempotency.replayed).toBe(false);
    expect(duplicate.idempotency.deduped).toBe(true);
    expect(accountRepo.getAvailable('acc_test_001')).toBe(1000n);
    expect(eventRepo.events).toHaveLength(1);
  });

  it('rejects invalid status transitions fail-closed', async () => {
    const settlementRepo = new InMemorySettlementRepository();
    const accountRepo = new InMemoryAccountRepository();
    const eventRepo = new InMemoryEventRepository();

    accountRepo.createAccount('acc_test_001', 0n);

    const service = new PaymentSettlementService(
      { DB: {} as D1Database },
      {
        settlementRepository: settlementRepo,
        accountRepository: accountRepo,
        eventRepository: eventRepo,
        now: makeNowClock(),
      }
    );

    const pending = makePayinRequest({ status: 'pending' });
    const failed = makePayinRequest({ status: 'failed' });
    const confirmed = makePayinRequest({ status: 'confirmed' });

    await service.ingest(pending, 'idem_transition_001');
    await service.ingest(failed, 'idem_transition_002');

    await expect(service.ingest(confirmed, 'idem_transition_003')).rejects.toMatchObject({
      code: 'INVALID_STATUS_TRANSITION',
    });
  });

  it('fails closed when reversal/refund exceeds available balance', async () => {
    const settlementRepo = new InMemorySettlementRepository();
    const accountRepo = new InMemoryAccountRepository();
    const eventRepo = new InMemoryEventRepository();

    accountRepo.createAccount('acc_test_001', 0n);

    const service = new PaymentSettlementService(
      { DB: {} as D1Database },
      {
        settlementRepository: settlementRepo,
        accountRepository: accountRepo,
        eventRepository: eventRepo,
        now: makeNowClock(),
      }
    );

    const confirmed = makePayinRequest({ status: 'confirmed', amount_minor: '1000' });
    await service.ingest(confirmed, 'idem_reverse_001');
    expect(accountRepo.getAvailable('acc_test_001')).toBe(1000n);

    accountRepo.setAvailable('acc_test_001', 200n);

    const reversal = makePayinRequest({ status: 'reversed', amount_minor: '1000' });

    await expect(service.ingest(reversal, 'idem_reverse_002')).rejects.toMatchObject({
      code: 'INSUFFICIENT_FUNDS',
    });

    const records = await service.getByProviderExternal('provider_sim', 'pay_sim_001', 'payin');
    expect(records).toHaveLength(1);
    expect(records[0]?.status).toBe('confirmed');
    expect(eventRepo.events).toHaveLength(1);
  });

  it('keeps hash-chain integrity for payin_settle/payin_reverse/payout_settle', async () => {
    const settlementRepo = new InMemorySettlementRepository();
    const accountRepo = new InMemoryAccountRepository();
    const eventRepo = new InMemoryEventRepository();

    accountRepo.createAccount('acc_test_001', 0n);

    const service = new PaymentSettlementService(
      { DB: {} as D1Database },
      {
        settlementRepository: settlementRepo,
        accountRepository: accountRepo,
        eventRepository: eventRepo,
        now: makeNowClock('2026-02-11T00:00:10.000Z'),
      }
    );

    await service.ingest(
      makePayinRequest({
        external_payment_id: 'pay_chain_001',
        status: 'confirmed',
        amount_minor: '700',
      }),
      'idem_chain_001'
    );

    await service.ingest(
      makePayinRequest({
        external_payment_id: 'pay_chain_001',
        status: 'reversed',
        amount_minor: '700',
      }),
      'idem_chain_002'
    );

    await service.ingest(
      {
        provider: 'provider_sim',
        external_payment_id: 'pay_chain_002',
        direction: 'payout',
        status: 'confirmed',
        account_id: 'acc_test_001',
        amount_minor: '300',
        currency: 'USD',
      },
      'idem_chain_003'
    );

    const types = eventRepo.events.map((evt) => evt.eventType);
    expect(types).toEqual(['payin_settle', 'payin_reverse', 'payout_settle']);

    expect(isValidEventType('payin_settle')).toBe(true);
    expect(isValidEventType('payin_reverse')).toBe(true);
    expect(isValidEventType('payout_settle')).toBe(true);

    let expectedPrev = '0'.repeat(64);

    for (const event of eventRepo.events) {
      expect(event.previousHash).toBe(expectedPrev);

      const expectedHash = await computeEventHash(
        event.previousHash,
        event.eventType,
        event.accountId,
        event.toAccountId,
        event.amount,
        event.bucket,
        event.idempotencyKey,
        event.createdAt
      );

      expect(event.eventHash).toBe(expectedHash);
      expectedPrev = event.eventHash;
    }

    // payout_settle path must not apply an implicit extra debit in ingestion.
    expect(accountRepo.getAvailable('acc_test_001')).toBe(0n);
  });

  it('throws a structured idempotency-key reuse error for payload mismatch', async () => {
    const settlementRepo = new InMemorySettlementRepository();
    const accountRepo = new InMemoryAccountRepository();
    const eventRepo = new InMemoryEventRepository();

    accountRepo.createAccount('acc_test_001', 0n);

    const service = new PaymentSettlementService(
      { DB: {} as D1Database },
      {
        settlementRepository: settlementRepo,
        accountRepository: accountRepo,
        eventRepository: eventRepo,
        now: makeNowClock(),
      }
    );

    await service.ingest(makePayinRequest({ amount_minor: '1000' }), 'idem_conflict_001');

    await expect(
      service.ingest(makePayinRequest({ amount_minor: '999' }), 'idem_conflict_001')
    ).rejects.toBeInstanceOf(PaymentSettlementError);

    await expect(
      service.ingest(makePayinRequest({ amount_minor: '999' }), 'idem_conflict_001')
    ).rejects.toMatchObject({ code: 'IDEMPOTENCY_KEY_REUSED' });
  });
});
