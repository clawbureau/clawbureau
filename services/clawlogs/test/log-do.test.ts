import { describe, expect, it } from 'vitest';

import { sha256B64u } from '../src/crypto';
import { LogDurableObject } from '../src/log-do';
import { verifyMerkleProof } from '../src/merkle';

class MockStorage {
  private readonly map = new Map<string, unknown>();

  async get<T = unknown>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }

  async put(key: string, value: unknown): Promise<void> {
    this.map.set(key, value);
  }
}

function makeDo(storage: MockStorage): LogDurableObject {
  const state: any = {
    storage,
    blockConcurrencyWhile: async (fn: () => Promise<Response>) => fn(),
  };

  return new LogDurableObject(state as DurableObjectState);
}

function post(url: string, body: unknown): Request {
  return new Request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body),
  });
}

describe('clawlogs durable object', () => {
  it('supports append/root/proof flow and rejects duplicate leaves', async () => {
    const storage = new MockStorage();
    const logDo = makeDo(storage);

    const leafA = await sha256B64u('leaf-A');
    const leafB = await sha256B64u('leaf-B');

    const appendA = await logDo.fetch(post('https://do.local/append', { leaf_hash_b64u: leafA }));
    expect(appendA.status).toBe(201);
    const appendABody = (await appendA.json()) as any;
    expect(appendABody.ok).toBe(true);
    expect(appendABody.leaf_index).toBe(0);
    expect(appendABody.tree_size).toBe(1);

    const duplicate = await logDo.fetch(post('https://do.local/append', { leaf_hash_b64u: leafA }));
    expect(duplicate.status).toBe(409);
    const duplicateBody = (await duplicate.json()) as any;
    expect(duplicateBody.ok).toBe(false);
    expect(duplicateBody.error?.code).toBe('LEAF_ALREADY_EXISTS');

    const appendB = await logDo.fetch(post('https://do.local/append', { leaf_hash_b64u: leafB }));
    expect(appendB.status).toBe(201);
    const appendBBody = (await appendB.json()) as any;
    expect(appendBBody.ok).toBe(true);
    expect(appendBBody.leaf_index).toBe(1);
    expect(appendBBody.tree_size).toBe(2);

    const rootRes = await logDo.fetch(new Request('https://do.local/root'));
    expect(rootRes.status).toBe(200);
    const rootBody = (await rootRes.json()) as any;
    expect(rootBody.ok).toBe(true);
    expect(rootBody.tree_size).toBe(2);
    expect(typeof rootBody.root_hash_b64u).toBe('string');

    const proofRes = await logDo.fetch(new Request(`https://do.local/proof/${encodeURIComponent(leafB)}`));
    expect(proofRes.status).toBe(200);
    const proofBody = (await proofRes.json()) as any;
    expect(proofBody.ok).toBe(true);
    expect(proofBody.leaf_hash_b64u).toBe(leafB);
    expect(proofBody.tree_size).toBe(2);
    expect(Array.isArray(proofBody.audit_path)).toBe(true);

    const validProof = await verifyMerkleProof({
      leaf_hash_b64u: proofBody.leaf_hash_b64u,
      leaf_index: proofBody.leaf_index,
      tree_size: proofBody.tree_size,
      audit_path: proofBody.audit_path,
      root_hash_b64u: proofBody.root_hash_b64u,
    });
    expect(validProof).toBe(true);
  });
});
