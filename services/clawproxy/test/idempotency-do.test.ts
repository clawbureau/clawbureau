import { describe, expect, it } from 'vitest';

import { IdempotencyDurableObject } from '../src/idempotency';

class MockStorage {
  private readonly map = new Map<string, unknown>();

  async get(key: string): Promise<unknown> {
    return this.map.get(key);
  }

  async put(key: string, value: unknown, _opts?: unknown): Promise<void> {
    this.map.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    const had = this.map.has(key);
    this.map.delete(key);
    return had;
  }

  async deleteAll(): Promise<void> {
    this.map.clear();
  }
}

function makeDo(storage: MockStorage): IdempotencyDurableObject {
  const state: any = {
    storage,
    blockConcurrencyWhile: async (fn: () => Promise<Response>) => fn(),
  };

  return new IdempotencyDurableObject(state as any, {});
}

function post(path: string, body: unknown): Request {
  return new Request(`https://idempotency${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('CPX-US-031: IdempotencyDurableObject', () => {
  it('locks inflight, commits, replays, and detects fingerprint mismatch', async () => {
    const storage = new MockStorage();
    const ido = makeDo(storage);

    const r1 = await ido.fetch(post('/check', { fingerprint: 'fp_1' }));
    expect(await r1.json()).toEqual({ ok: true, kind: 'new' });

    const r2 = await ido.fetch(post('/check', { fingerprint: 'fp_1' }));
    expect(await r2.json()).toEqual({ ok: true, kind: 'inflight' });

    const commit = await ido.fetch(
      post('/commit', { fingerprint: 'fp_1', receipt: { ok: true } })
    );
    expect(await commit.json()).toEqual({ ok: true, kind: 'committed' });

    const replay = await ido.fetch(post('/check', { fingerprint: 'fp_1' }));
    expect(await replay.json()).toEqual({
      ok: true,
      kind: 'replay',
      receipt: { ok: true },
    });

    const mismatch = await ido.fetch(post('/check', { fingerprint: 'fp_other' }));
    expect(await mismatch.json()).toEqual({ ok: true, kind: 'mismatch' });
  });

  it('persists across object instances (simulated restart)', async () => {
    const storage = new MockStorage();

    const ido1 = makeDo(storage);
    await ido1.fetch(post('/check', { fingerprint: 'fp_1' }));
    await ido1.fetch(post('/commit', { fingerprint: 'fp_1', receipt: { v: 1 } }));

    const ido2 = makeDo(storage);
    const replay = await ido2.fetch(post('/check', { fingerprint: 'fp_1' }));
    expect(await replay.json()).toEqual({ ok: true, kind: 'replay', receipt: { v: 1 } });
  });

  it('releases inflight locks when asked', async () => {
    const storage = new MockStorage();
    const ido = makeDo(storage);

    const r1 = await ido.fetch(post('/check', { fingerprint: 'fp_1' }));
    expect(await r1.json()).toEqual({ ok: true, kind: 'new' });

    const rel = await ido.fetch(post('/release', { fingerprint: 'fp_1' }));
    expect(await rel.json()).toEqual({ ok: true, kind: 'released' });

    const r2 = await ido.fetch(post('/check', { fingerprint: 'fp_1' }));
    expect(await r2.json()).toEqual({ ok: true, kind: 'new' });
  });
});
