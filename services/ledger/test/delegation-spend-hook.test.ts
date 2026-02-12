import { describe, expect, it } from 'vitest';

import worker from '../src/index';
import type { Env } from '../src/types';

type HookRow = {
  event_id: string;
  idempotency_key: string;
  delegation_id: string;
  operation: 'reserve' | 'consume' | 'release';
  request_fingerprint: string;
  response_json: string;
};

function createDelegationHookDb(): D1Database {
  const hooks = new Map<string, HookRow>();

  const db = {
    prepare(sql: string) {
      return {
        bind(...args: unknown[]) {
          return {
            async first<T = Record<string, unknown>>() {
              if (sql.includes('FROM delegation_spend_hooks') && sql.includes('WHERE idempotency_key = ?')) {
                const key = String(args[0] ?? '');
                const row = hooks.get(key);
                return (row ?? null) as T | null;
              }
              return null;
            },
            async run() {
              if (sql.startsWith('INSERT OR IGNORE INTO delegation_spend_hooks')) {
                const [
                  event_id,
                  idempotency_key,
                  delegation_id,
                  operation,
                  _delegator_did,
                  _actor_did,
                  _amount_minor,
                  _token_hash,
                  request_fingerprint,
                  response_json,
                ] = args as string[];

                if (!hooks.has(idempotency_key)) {
                  hooks.set(idempotency_key, {
                    event_id,
                    idempotency_key,
                    delegation_id,
                    operation: operation as HookRow['operation'],
                    request_fingerprint,
                    response_json,
                  });
                }
              }
              return { success: true };
            },
          };
        },
      };
    },
  };

  return db as unknown as D1Database;
}

function makeEnv(overrides: Record<string, unknown> = {}) {
  return {
    DB: createDelegationHookDb(),
    LEDGER_ADMIN_KEY: 'ledger-admin-token',
    ...overrides,
  };
}

function makeRequest(body: Record<string, unknown>) {
  return new Request('https://clawledger.com/v1/delegations/spend/reserve', {
    method: 'POST',
    headers: {
      authorization: 'Bearer ledger-admin-token',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

describe('delegation spend hook endpoint', () => {
  it('persists and replays idempotent delegation spend mutations', async () => {
    const env = makeEnv();
    const body = {
      idempotency_key: 'dlg-hook-idempotency-1',
      delegation_id: 'dlg_11111111-1111-1111-1111-111111111111',
      delegator_did: 'did:key:z6MkDelegator111',
      actor_did: 'did:key:z6MkActor111',
      amount_minor: '5',
      token_hash: 'a'.repeat(64),
    };

    const first = await worker.fetch(makeRequest(body), env as unknown as Env, {} as ExecutionContext);
    expect(first.status).toBe(201);
    const firstJson = await first.json();
    expect(firstJson?.status).toBe('applied');
    expect(typeof firstJson?.event_id).toBe('string');

    const replay = await worker.fetch(makeRequest(body), env as unknown as Env, {} as ExecutionContext);
    expect(replay.status).toBe(200);
    const replayJson = await replay.json();
    expect(replayJson?.status).toBe('applied');
    expect(replayJson?.event_id).toBe(firstJson?.event_id);
  });

  it('rejects malformed payloads fail-closed', async () => {
    const env = makeEnv();

    const response = await worker.fetch(
      makeRequest({
        idempotency_key: 'dlg-hook-idempotency-2',
        delegation_id: 'not-a-delegation-id',
        delegator_did: 'did:key:z6MkDelegator222',
        actor_did: 'did:key:z6MkActor222',
        amount_minor: '5',
      }),
      env as unknown as Env,
      {} as ExecutionContext
    );

    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json?.code).toBe('INVALID_REQUEST');
  });
});
