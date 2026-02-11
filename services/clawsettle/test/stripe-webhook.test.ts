import { describe, expect, it } from 'vitest';

import {
  ClawSettleError,
  StripeWebhookService,
  computeStripeV1Signature,
  type LedgerSettlementClientLike,
  type StripeWebhookRepositoryLike,
} from '../src/stripe';
import type {
  Env,
  PaymentSettlementIngestPayload,
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

function makeService(opts?: {
  signingSecret?: string;
  repository?: StripeWebhookRepositoryLike;
  ledgerClient?: LedgerSettlementClientLike;
  now?: () => string;
  nowMs?: () => number;
}) {
  const env: Env = {
    DB: {} as D1Database,
    STRIPE_WEBHOOK_SIGNING_SECRET: opts?.signingSecret ?? 'whsec_test',
    LEDGER_BASE_URL: 'https://example-ledger.com',
    LEDGER_ADMIN_KEY: 'ledger_admin_test',
  };

  return new StripeWebhookService(env, {
    repository: opts?.repository,
    ledgerClient: opts?.ledgerClient,
    now: opts?.now,
    nowMs: opts?.nowMs,
  });
}

function makeStripeEventPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'evt_test_001',
    type: 'payment_intent.succeeded',
    created: 1739290000,
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
    const ledger = new MockLedgerClient({
      status: 201,
      json: { settlement: { id: 'set_test_001' } },
      text: '{"ok":true}',
    });

    const timestamp = 1739290005;
    const service = makeService({
      repository: repo,
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
});
