import { describe, expect, it } from 'vitest';

import { sha256B64u } from '../src/crypto';
import { LogDurableObject } from '../src/log-do';
import { verifyMerkleProof } from '../src/merkle';

/**
 * RT (Receipt Transparency) endpoint tests.
 *
 * These tests exercise the Durable Object directly (same as log-do.test.ts)
 * to validate the RT flow: submit receipt hash -> get proof -> get root.
 * The RT endpoints in index.ts are thin wrappers around the same DO,
 * so validating the DO flow covers the core logic.
 */

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

describe('RT (Receipt Transparency) flow via DO', () => {
  it('submit -> proof -> root cycle works end-to-end', async () => {
    const storage = new MockStorage();
    const logDo = makeDo(storage);

    // Simulate receipt hashes (sha256 of receipt envelope payloads)
    const hash1 = await sha256B64u('receipt-envelope-payload-1');
    const hash2 = await sha256B64u('receipt-envelope-payload-2');
    const hash3 = await sha256B64u('receipt-envelope-payload-3');

    // Submit three receipt hashes
    for (const [i, h] of [hash1, hash2, hash3].entries()) {
      const res = await logDo.fetch(post('https://do.local/append', { leaf_hash_b64u: h }));
      expect(res.status).toBe(201);
      const body = (await res.json()) as any;
      expect(body.ok).toBe(true);
      expect(body.leaf_index).toBe(i);
      expect(body.tree_size).toBe(i + 1);
    }

    // Duplicate is rejected
    const dup = await logDo.fetch(post('https://do.local/append', { leaf_hash_b64u: hash1 }));
    expect(dup.status).toBe(409);

    // Root reflects tree_size 3
    const rootRes = await logDo.fetch(new Request('https://do.local/root'));
    const rootBody = (await rootRes.json()) as any;
    expect(rootBody.ok).toBe(true);
    expect(rootBody.tree_size).toBe(3);

    // Proof for hash2
    const proofRes = await logDo.fetch(
      new Request(`https://do.local/proof/${encodeURIComponent(hash2)}`),
    );
    const proofBody = (await proofRes.json()) as any;
    expect(proofBody.ok).toBe(true);
    expect(proofBody.leaf_hash_b64u).toBe(hash2);
    expect(proofBody.leaf_index).toBe(1);
    expect(proofBody.tree_size).toBe(3);

    // Verify the proof cryptographically
    const valid = await verifyMerkleProof({
      leaf_hash_b64u: proofBody.leaf_hash_b64u,
      leaf_index: proofBody.leaf_index,
      tree_size: proofBody.tree_size,
      audit_path: proofBody.audit_path,
      root_hash_b64u: proofBody.root_hash_b64u,
    });
    expect(valid).toBe(true);

    // Root hash from proof matches root endpoint
    expect(proofBody.root_hash_b64u).toBe(rootBody.root_hash_b64u);
  });

  it('rejects invalid leaf hash format', async () => {
    const storage = new MockStorage();
    const logDo = makeDo(storage);

    const res = await logDo.fetch(post('https://do.local/append', { leaf_hash_b64u: 'bad' }));
    expect(res.status).toBe(400);
    const body = (await res.json()) as any;
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('INVALID_LEAF_HASH');
  });

  it('returns 404 for proof of non-existent hash', async () => {
    const storage = new MockStorage();
    const logDo = makeDo(storage);

    const fakeHash = await sha256B64u('does-not-exist');
    const res = await logDo.fetch(
      new Request(`https://do.local/proof/${encodeURIComponent(fakeHash)}`),
    );
    expect(res.status).toBe(404);
    const body = (await res.json()) as any;
    expect(body.ok).toBe(false);
    expect(body.error.code).toBe('LEAF_NOT_FOUND');
  });

  it('single-leaf tree produces valid proof', async () => {
    const storage = new MockStorage();
    const logDo = makeDo(storage);

    const hash = await sha256B64u('solo-receipt');
    await logDo.fetch(post('https://do.local/append', { leaf_hash_b64u: hash }));

    const proofRes = await logDo.fetch(
      new Request(`https://do.local/proof/${encodeURIComponent(hash)}`),
    );
    const proofBody = (await proofRes.json()) as any;
    expect(proofBody.ok).toBe(true);
    expect(proofBody.tree_size).toBe(1);
    expect(proofBody.leaf_index).toBe(0);

    const valid = await verifyMerkleProof({
      leaf_hash_b64u: proofBody.leaf_hash_b64u,
      leaf_index: proofBody.leaf_index,
      tree_size: proofBody.tree_size,
      audit_path: proofBody.audit_path,
      root_hash_b64u: proofBody.root_hash_b64u,
    });
    expect(valid).toBe(true);
  });
});
