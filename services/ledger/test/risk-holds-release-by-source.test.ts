import { describe, expect, it } from 'vitest';

import worker from '../src/index';
import type { Env } from '../src/types';

type RiskHoldRow = {
  hold_id: string;
  idempotency_key: string;
  source_loss_event_id: string;
  account_ref: string;
  account_id: string | null;
  amount_minor: string;
  currency: string;
  reason: string;
  status: 'active' | 'released';
  hold_transfer_event_id: string;
  release_idempotency_key: string | null;
  release_transfer_event_id: string | null;
  metadata: string | null;
  created_at: string;
  updated_at: string;
  released_at: string | null;
};

function createRiskHoldDb(initial: RiskHoldRow[]): D1Database {
  const byHoldId = new Map<string, RiskHoldRow>();
  const bySource = new Map<string, RiskHoldRow>();

  for (const row of initial) {
    byHoldId.set(row.hold_id, row);
    bySource.set(row.source_loss_event_id, row);
  }

  const db = {
    prepare(sql: string) {
      return {
        bind(...args: unknown[]) {
          return {
            async first<T = Record<string, unknown>>() {
              if (sql.includes('FROM risk_holds') && sql.includes('WHERE source_loss_event_id = ?')) {
                const source = String(args[0] ?? '');
                return (bySource.get(source) ?? null) as unknown as T | null;
              }

              if (sql.includes('FROM risk_holds') && sql.includes('WHERE hold_id = ?')) {
                const holdId = String(args[0] ?? '');
                return (byHoldId.get(holdId) ?? null) as unknown as T | null;
              }

              return null;
            },
          };
        },
      };
    },
  };

  return db as unknown as D1Database;
}

function makeRequest(token: string, body: Record<string, unknown>) {
  return new Request('https://clawledger.com/v1/risk/holds/release-by-source', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify(body),
  });
}

describe('risk hold release-by-source endpoint', () => {
  it('returns 404 when source_loss_event_id is unknown', async () => {
    const env = {
      DB: createRiskHoldDb([]),
      LEDGER_RISK_KEY: 'risk-token',
    };

    const res = await worker.fetch(
      makeRequest('risk-token', {
        idempotency_key: 'release-idem-1',
        source_loss_event_id: 'lse_missing',
      }),
      env as unknown as Env,
      {} as ExecutionContext
    );

    expect(res.status).toBe(404);
    const json = await res.json();
    expect(json?.code).toBe('NOT_FOUND');
  });

  it('replays deterministically when hold already released with same idempotency_key', async () => {
    const row: RiskHoldRow = {
      hold_id: 'rsk_test_1',
      idempotency_key: 'apply-idem-1',
      source_loss_event_id: 'lse_test_1',
      account_ref: 'did:key:zTest',
      account_id: 'acc_test',
      amount_minor: '10',
      currency: 'USD',
      reason: 'chargeback',
      status: 'released',
      hold_transfer_event_id: 'evt_apply',
      release_idempotency_key: 'release-idem-1',
      release_transfer_event_id: 'evt_release',
      metadata: JSON.stringify({}),
      created_at: '2026-02-12T00:00:00.000Z',
      updated_at: '2026-02-12T00:00:01.000Z',
      released_at: '2026-02-12T00:00:02.000Z',
    };

    const env = {
      DB: createRiskHoldDb([row]),
      LEDGER_RISK_KEY: 'risk-token',
    };

    const res = await worker.fetch(
      makeRequest('risk-token', {
        idempotency_key: 'release-idem-1',
        source_loss_event_id: 'lse_test_1',
      }),
      env as unknown as Env,
      {} as ExecutionContext
    );

    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json?.replay).toBe(true);
    expect(json?.hold?.hold_id).toBe('rsk_test_1');
    expect(json?.hold?.status).toBe('released');
  });

  it('fails closed with 409 when hold already released with different idempotency_key', async () => {
    const row: RiskHoldRow = {
      hold_id: 'rsk_test_2',
      idempotency_key: 'apply-idem-2',
      source_loss_event_id: 'lse_test_2',
      account_ref: 'did:key:zTest',
      account_id: 'acc_test',
      amount_minor: '10',
      currency: 'USD',
      reason: 'chargeback',
      status: 'released',
      hold_transfer_event_id: 'evt_apply',
      release_idempotency_key: 'release-idem-original',
      release_transfer_event_id: 'evt_release',
      metadata: JSON.stringify({}),
      created_at: '2026-02-12T00:00:00.000Z',
      updated_at: '2026-02-12T00:00:01.000Z',
      released_at: '2026-02-12T00:00:02.000Z',
    };

    const env = {
      DB: createRiskHoldDb([row]),
      LEDGER_RISK_KEY: 'risk-token',
    };

    const res = await worker.fetch(
      makeRequest('risk-token', {
        idempotency_key: 'release-idem-different',
        source_loss_event_id: 'lse_test_2',
      }),
      env as unknown as Env,
      {} as ExecutionContext
    );

    expect(res.status).toBe(409);
    const json = await res.json();
    expect(json?.code).toBe('IDEMPOTENCY_CONFLICT');
  });
});
