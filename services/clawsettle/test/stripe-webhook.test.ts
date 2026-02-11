import { describe, expect, it } from 'vitest';

import {
  ClawSettleError,
  StripeWebhookService,
  computeStripeV1Signature,
  type LedgerSettlementClientLike,
  type StripeWebhookOutboxRepositoryLike,
  type StripeWebhookRepositoryLike,
} from '../src/stripe';
import type {
  Env,
  PaymentSettlementIngestPayload,
  StripeWebhookOutboxRecord,
  StripeWebhookRecord,
} from '../src/types';

class InMemoryWebhookRepository implements StripeWebhookRepositoryLike {
  private rows = new Map<string, StripeWebhookRecord>();

  async findByEventId(eventId: string): Promise<StripeWebhookRecord | null> {
    const row = this.rows.get(eventId);
    return row ? { ...row } : null;
  }

  async create(record: StripeWebhookRecord): Promise<void> {
    if (this.rows.has(record.event_id)) {
      throw new Error('UNIQUE constraint failed: stripe_webhook_events.event_id');
    }
    this.rows.set(record.event_id, { ...record });
  }
}

class InMemoryOutboxRepository implements StripeWebhookOutboxRepositoryLike {
  private rows = new Map<string, StripeWebhookOutboxRecord>();

  async findByEventId(eventId: string): Promise<StripeWebhookOutboxRecord | null> {
    const row = this.rows.get(eventId);
    return row ? { ...row } : null;
  }

  async create(record: StripeWebhookOutboxRecord): Promise<void> {
    if (this.rows.has(record.event_id)) {
      throw new Error('UNIQUE constraint failed: stripe_webhook_outbox.event_id');
    }
    this.rows.set(record.event_id, { ...record });
  }

  async incrementAttempt(eventId: string, attemptedAt: string, updatedAt: string): Promise<void> {
    const row = this.rows.get(eventId);
    if (!row || row.status === 'forwarded') {
      return;
    }

    this.rows.set(eventId, {
      ...row,
      attempts: row.attempts + 1,
      last_attempted_at: attemptedAt,
      updated_at: updatedAt,
    });
  }

  async markForwarded(params: {
    eventId: string;
    settlementId?: string | undefined;
    ledgerStatus?: number | undefined;
    forwardedAt: string;
    updatedAt: string;
  }): Promise<void> {
    const row = this.rows.get(params.eventId);
    if (!row || row.status === 'forwarded') {
      return;
    }

    this.rows.set(params.eventId, {
      ...row,
      status: 'forwarded',
      settlement_id: params.settlementId,
      ledger_status: params.ledgerStatus,
      forwarded_at: params.forwardedAt,
      updated_at: params.updatedAt,
      next_retry_at: undefined,
      last_error_code: undefined,
      last_error_message: undefined,
    });
  }

  async markFailed(params: {
    eventId: string;
    ledgerStatus?: number | undefined;
    nextRetryAt: string;
    errorCode: string;
    errorMessage: string;
    updatedAt: string;
  }): Promise<void> {
    const row = this.rows.get(params.eventId);
    if (!row || row.status === 'forwarded') {
      return;
    }

    this.rows.set(params.eventId, {
      ...row,
      status: 'failed',
      ledger_status: params.ledgerStatus,
      next_retry_at: params.nextRetryAt,
      last_error_code: params.errorCode,
      last_error_message: params.errorMessage,
      updated_at: params.updatedAt,
    });
  }

  async listRetryable(nowIso: string, limit: number): Promise<StripeWebhookOutboxRecord[]> {
    const nowMs = Date.parse(nowIso);
    const rows = Array.from(this.rows.values())
      .filter((row) => row.status === 'pending' || row.status === 'failed')
      .filter((row) => {
        if (!row.next_retry_at) {
          return true;
        }
        const retryAtMs = Date.parse(row.next_retry_at);
        return Number.isFinite(retryAtMs) ? retryAtMs <= nowMs : false;
      })
      .sort((a, b) => a.created_at.localeCompare(b.created_at))
      .slice(0, limit)
      .map((row) => ({ ...row }));

    return rows;
  }
}

class MockLedgerClient implements LedgerSettlementClientLike {
  public calls: Array<{ payload: PaymentSettlementIngestPayload; idempotencyKey: string }> = [];

  constructor(
    private response: { status: number; json: Record<string, unknown> | null; text: string }
  ) {}

  async ingest(
    payload: PaymentSettlementIngestPayload,
    idempotencyKey: string
  ): Promise<{ status: number; json: Record<string, unknown> | null; text: string }> {
    this.calls.push({ payload, idempotencyKey });
    return this.response;
  }
}

class SequenceLedgerClient implements LedgerSettlementClientLike {
  public calls: Array<{ payload: PaymentSettlementIngestPayload; idempotencyKey: string }> = [];
  private cursor = 0;

  constructor(
    private responses: Array<{ status: number; json: Record<string, unknown> | null; text: string }>
  ) {}

  async ingest(
    payload: PaymentSettlementIngestPayload,
    idempotencyKey: string
  ): Promise<{ status: number; json: Record<string, unknown> | null; text: string }> {
    this.calls.push({ payload, idempotencyKey });

    const index = Math.min(this.cursor, this.responses.length - 1);
    const response = this.responses[index];
    this.cursor += 1;
    return response;
  }
}

function makeService(opts?: {
  signingSecret?: string;
  repository?: StripeWebhookRepositoryLike;
  outboxRepository?: StripeWebhookOutboxRepositoryLike;
  ledgerClient?: LedgerSettlementClientLike;
  onForwarded?: (input: {
    event_id: string;
    event_type: string;
    idempotency_key: string;
    payload: PaymentSettlementIngestPayload;
    ledger_status?: number;
    settlement_id?: string;
  }) => Promise<void>;
  now?: () => string;
  nowMs?: () => number;
  settleEnv?: 'staging' | 'production';
  allowTestmodeInProd?: string;
}) {
  const env: Env = {
    DB: {} as D1Database,
    SETTLE_ENV: opts?.settleEnv ?? 'staging',
    STRIPE_ALLOW_TESTMODE_EVENTS_IN_PROD: opts?.allowTestmodeInProd,
    STRIPE_WEBHOOK_SIGNING_SECRET: opts?.signingSecret ?? 'whsec_test',
    LEDGER_BASE_URL: 'https://example-ledger.com',
    LEDGER_ADMIN_KEY: 'ledger_admin_test',
    FORWARDING_RETRY_BATCH_LIMIT: '25',
    FORWARDING_RETRY_BASE_SECONDS: '15',
    FORWARDING_RETRY_MAX_SECONDS: '300',
  };

  return new StripeWebhookService(env, {
    repository: opts?.repository,
    outboxRepository: opts?.outboxRepository,
    ledgerClient: opts?.ledgerClient,
    onForwarded: opts?.onForwarded,
    now: opts?.now,
    nowMs: opts?.nowMs,
  });
}

function makeStripeEventPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'evt_test_001',
    type: 'payment_intent.succeeded',
    created: 1739290000,
    livemode: false,
    data: {
      object: {
        id: 'pi_test_001',
        amount_received: 2500,
        currency: 'usd',
        payment_method_types: ['card'],
        created: 1739290000,
        metadata: {
          account_id: 'acc_test_001',
        },
      },
    },
    ...overrides,
  };
}

async function makeSignatureHeader(secret: string, timestamp: number, rawBody: string): Promise<string> {
  const v1 = await computeStripeV1Signature(secret, timestamp, rawBody);
  return `t=${timestamp},v1=${v1}`;
}

describe('stripe webhook service', () => {
  it('accepts valid signature and forwards mapped settlement to ledger', async () => {
    const repo = new InMemoryWebhookRepository();
    const outbox = new InMemoryOutboxRepository();
    const ledger = new MockLedgerClient({
      status: 201,
      json: {
        settlement: {
          id: 'set_test_001',
        },
      },
      text: '{"ok":true}',
    });

    const timestamp = 1739290005;
    const nowMs = () => timestamp * 1000;

    const service = makeService({
      repository: repo,
      outboxRepository: outbox,
      ledgerClient: ledger,
      now: () => '2026-02-12T00:00:00.000Z',
      nowMs,
    });

    const payload = makeStripeEventPayload();
    const rawBody = JSON.stringify(payload);
    const signature = await makeSignatureHeader('whsec_test', timestamp, rawBody);

    const result = await service.processWebhook(rawBody, signature);

    expect(result.ok).toBe(true);
    expect(result.deduped).toBe(false);
    expect(result.forwarded_to_ledger).toBe(true);
    expect(result.idempotency_key).toBe('stripe:event:evt_test_001');
    expect(result.settlement_id).toBe('set_test_001');

    expect(ledger.calls).toHaveLength(1);
    expect(ledger.calls[0]?.idempotencyKey).toBe('stripe:event:evt_test_001');
    expect(ledger.calls[0]?.payload).toMatchObject({
      provider: 'stripe',
      external_payment_id: 'pi_test_001',
      direction: 'payin',
      status: 'confirmed',
      account_id: 'acc_test_001',
      amount_minor: '2500',
      currency: 'USD',
    });
  });

  it('rejects tampered signature fail-closed', async () => {
    const repo = new InMemoryWebhookRepository();
    const outbox = new InMemoryOutboxRepository();
    const ledger = new MockLedgerClient({
      status: 201,
      json: { settlement: { id: 'set_test_001' } },
      text: '{"ok":true}',
    });

    const timestamp = 1739290005;
    const service = makeService({
      repository: repo,
      outboxRepository: outbox,
      ledgerClient: ledger,
      nowMs: () => timestamp * 1000,
    });

    const payload = makeStripeEventPayload();
    const rawBody = JSON.stringify(payload);
    const signature = await makeSignatureHeader('whsec_test', timestamp, rawBody);

    const tamperedBody = `${rawBody} `;

    await expect(service.processWebhook(tamperedBody, signature)).rejects.toBeInstanceOf(
      ClawSettleError
    );

    await expect(service.processWebhook(tamperedBody, signature)).rejects.toMatchObject({
      code: 'SIGNATURE_INVALID',
      status: 401,
    });

    expect(ledger.calls).toHaveLength(0);
  });

  it('dedupes replayed event id and does not forward twice to ledger', async () => {
    const repo = new InMemoryWebhookRepository();
    const outbox = new InMemoryOutboxRepository();
    const ledger = new MockLedgerClient({
      status: 200,
      json: {
        settlement: {
          id: 'set_test_002',
        },
      },
      text: '{"ok":true}',
    });

    const timestamp = 1739290005;
    const service = makeService({
      repository: repo,
      outboxRepository: outbox,
      ledgerClient: ledger,
      now: () => '2026-02-12T00:00:00.000Z',
      nowMs: () => timestamp * 1000,
    });

    const payload = makeStripeEventPayload({ id: 'evt_replay_001', type: 'payment_intent.succeeded' });
    const rawBody = JSON.stringify(payload);
    const signature = await makeSignatureHeader('whsec_test', timestamp, rawBody);

    const first = await service.processWebhook(rawBody, signature);
    const replay = await service.processWebhook(rawBody, signature);

    expect(first.deduped).toBe(false);
    expect(replay.deduped).toBe(true);
    expect(first.idempotency_key).toBe('stripe:event:evt_replay_001');
    expect(replay.idempotency_key).toBe('stripe:event:evt_replay_001');

    expect(ledger.calls).toHaveLength(1);
  });

  it('retries lifecycle hook failures through forwarding outbox without double side effects', async () => {
    const repo = new InMemoryWebhookRepository();
    const outbox = new InMemoryOutboxRepository();
    const ledger = new SequenceLedgerClient([
      {
        status: 201,
        json: { settlement: { id: 'set_hook_retry_1' } },
        text: '{"ok":true}',
      },
      {
        status: 201,
        json: { settlement: { id: 'set_hook_retry_2' } },
        text: '{"ok":true}',
      },
    ]);

    const hookCalls: string[] = [];
    let failFirstHook = true;

    const timestamp = 1739290005;
    const service = makeService({
      repository: repo,
      outboxRepository: outbox,
      ledgerClient: ledger,
      onForwarded: async (input) => {
        hookCalls.push(input.event_id);
        if (failFirstHook) {
          failFirstHook = false;
          throw new ClawSettleError('Lifecycle hook failed', 'INVALID_STATUS_TRANSITION', 409);
        }
      },
      now: () => '2026-02-12T00:00:00.000Z',
      nowMs: () => timestamp * 1000,
    });

    const payload = makeStripeEventPayload({ id: 'evt_hook_retry_001' });
    const rawBody = JSON.stringify(payload);
    const signature = await makeSignatureHeader('whsec_test', timestamp, rawBody);

    await expect(service.processWebhook(rawBody, signature)).rejects.toMatchObject({
      code: 'LEDGER_INGEST_FAILED',
      status: 502,
    });

    const retry = await service.retryFailedForwarding(undefined, true, 'evt_hook_retry_001');
    expect(retry).toMatchObject({
      ok: true,
      attempted: 1,
      forwarded: 1,
      failed: 0,
    });

    const replay = await service.processWebhook(rawBody, signature);
    expect(replay.deduped).toBe(true);
    expect(replay.forwarded_to_ledger).toBe(true);

    expect(hookCalls).toEqual(['evt_hook_retry_001', 'evt_hook_retry_001']);
    expect(ledger.calls).toHaveLength(2);
  });

  it('persists failed forwarding and retries exactly once after recovery', async () => {
    const repo = new InMemoryWebhookRepository();
    const outbox = new InMemoryOutboxRepository();
    const ledger = new SequenceLedgerClient([
      {
        status: 404,
        json: {
          error: 'Account not found',
        },
        text: '{"error":"Account not found"}',
      },
      {
        status: 201,
        json: {
          settlement: {
            id: 'set_retry_001',
          },
        },
        text: '{"ok":true}',
      },
    ]);

    let nowMsValue = 1739290005000;
    const now = () => new Date(nowMsValue).toISOString();

    const service = makeService({
      repository: repo,
      outboxRepository: outbox,
      ledgerClient: ledger,
      now,
      nowMs: () => nowMsValue,
    });

    const payload = makeStripeEventPayload({ id: 'evt_retry_001' });
    const rawBody = JSON.stringify(payload);
    const signature = await makeSignatureHeader('whsec_test', Math.floor(nowMsValue / 1000), rawBody);

    let caught: unknown;
    try {
      await service.processWebhook(rawBody, signature);
    } catch (err) {
      caught = err;
    }

    expect(caught).toBeInstanceOf(ClawSettleError);
    const clawErr = caught as ClawSettleError;
    expect(clawErr.code).toBe('LEDGER_INGEST_FAILED');
    expect(clawErr.status).toBe(502);
    expect(clawErr.details?.retry_scheduled).toBe(true);
    expect(clawErr.details?.ledger_status).toBe(404);
    expect(typeof clawErr.details?.next_retry_at).toBe('string');

    const failedOutbox = await outbox.findByEventId('evt_retry_001');
    expect(failedOutbox?.status).toBe('failed');
    expect(failedOutbox?.attempts).toBe(1);

    nowMsValue += 60_000;

    const retry1 = await service.retryFailedForwarding();
    expect(retry1).toMatchObject({
      ok: true,
      attempted: 1,
      forwarded: 1,
      failed: 0,
    });

    const forwardedOutbox = await outbox.findByEventId('evt_retry_001');
    expect(forwardedOutbox?.status).toBe('forwarded');
    expect(forwardedOutbox?.attempts).toBe(2);
    expect(forwardedOutbox?.settlement_id).toBe('set_retry_001');

    const replay = await service.processWebhook(rawBody, signature);
    expect(replay.deduped).toBe(true);
    expect(replay.forwarded_to_ledger).toBe(true);
    expect(replay.settlement_id).toBe('set_retry_001');

    const retry2 = await service.retryFailedForwarding();
    expect(retry2).toMatchObject({
      ok: true,
      attempted: 0,
      forwarded: 0,
      failed: 0,
    });

    expect(ledger.calls).toHaveLength(2);
  });

  it('rejects live Stripe events on staging with deterministic livemode mismatch', async () => {
    const repo = new InMemoryWebhookRepository();
    const outbox = new InMemoryOutboxRepository();
    const ledger = new MockLedgerClient({
      status: 201,
      json: { settlement: { id: 'set_staging_live' } },
      text: '{"ok":true}',
    });

    const timestamp = 1739290005;
    const service = makeService({
      repository: repo,
      outboxRepository: outbox,
      ledgerClient: ledger,
      settleEnv: 'staging',
      nowMs: () => timestamp * 1000,
    });

    const payload = makeStripeEventPayload({ id: 'evt_staging_live', livemode: true });
    const rawBody = JSON.stringify(payload);
    const signature = await makeSignatureHeader('whsec_test', timestamp, rawBody);

    await expect(service.processWebhook(rawBody, signature)).rejects.toMatchObject({
      code: 'LIVEMODE_MISMATCH',
      status: 422,
    });

    expect(ledger.calls).toHaveLength(0);
  });

  it('rejects Stripe test-mode events on production by default', async () => {
    const repo = new InMemoryWebhookRepository();
    const outbox = new InMemoryOutboxRepository();
    const ledger = new MockLedgerClient({
      status: 201,
      json: { settlement: { id: 'set_prod_test' } },
      text: '{"ok":true}',
    });

    const timestamp = 1739290005;
    const service = makeService({
      repository: repo,
      outboxRepository: outbox,
      ledgerClient: ledger,
      settleEnv: 'production',
      nowMs: () => timestamp * 1000,
    });

    const payload = makeStripeEventPayload({ id: 'evt_prod_test', livemode: false });
    const rawBody = JSON.stringify(payload);
    const signature = await makeSignatureHeader('whsec_test', timestamp, rawBody);

    await expect(service.processWebhook(rawBody, signature)).rejects.toMatchObject({
      code: 'LIVEMODE_MISMATCH',
      status: 422,
    });

    expect(ledger.calls).toHaveLength(0);
  });

  it('allows Stripe test-mode events on production when override flag is enabled', async () => {
    const repo = new InMemoryWebhookRepository();
    const outbox = new InMemoryOutboxRepository();
    const ledger = new MockLedgerClient({
      status: 201,
      json: { settlement: { id: 'set_prod_override' } },
      text: '{"ok":true}',
    });

    const timestamp = 1739290005;
    const service = makeService({
      repository: repo,
      outboxRepository: outbox,
      ledgerClient: ledger,
      settleEnv: 'production',
      allowTestmodeInProd: 'true',
      nowMs: () => timestamp * 1000,
    });

    const payload = makeStripeEventPayload({ id: 'evt_prod_override', livemode: false });
    const rawBody = JSON.stringify(payload);
    const signature = await makeSignatureHeader('whsec_test', timestamp, rawBody);

    const result = await service.processWebhook(rawBody, signature);

    expect(result.ok).toBe(true);
    expect(result.forwarded_to_ledger).toBe(true);
    expect(ledger.calls).toHaveLength(1);
  });
});
