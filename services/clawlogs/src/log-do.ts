import type { LogAppendResult, LogProofResult } from './types';
import { buildMerkleProof, computeMerkleRootB64u, isBase64urlString } from './merkle';

const STORAGE_KEY_LEAVES = 'leaves';

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
  });
}

async function readLeaves(state: DurableObjectState): Promise<string[]> {
  const value = await state.storage.get<string[]>(STORAGE_KEY_LEAVES);
  return Array.isArray(value) ? value : [];
}

async function writeLeaves(state: DurableObjectState, leaves: string[]): Promise<void> {
  await state.storage.put(STORAGE_KEY_LEAVES, leaves);
}

function getLeafHashFromPath(pathname: string): string | null {
  const match = pathname.match(/^\/proof\/([^/]+)$/);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]!);
  } catch {
    return null;
  }
}

export class LogDurableObject {
  constructor(private readonly state: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'POST' && url.pathname === '/append') {
      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return json(
          { ok: false, error: { code: 'INVALID_JSON', message: 'Body must be valid JSON' } },
          400,
        );
      }

      if (typeof body !== 'object' || body === null || !('leaf_hash_b64u' in body)) {
        return json(
          {
            ok: false,
            error: {
              code: 'MISSING_REQUIRED_FIELD',
              message: 'Body must contain leaf_hash_b64u',
              field: 'leaf_hash_b64u',
            },
          },
          400,
        );
      }

      const leafHash = (body as Record<string, unknown>).leaf_hash_b64u;
      if (!isBase64urlString(leafHash, { minLen: 8 })) {
        return json(
          {
            ok: false,
            error: {
              code: 'INVALID_LEAF_HASH',
              message: 'leaf_hash_b64u must be base64url with length >= 8',
              field: 'leaf_hash_b64u',
            },
          },
          400,
        );
      }

      return this.state.blockConcurrencyWhile(async () => {
        const leaves = await readLeaves(this.state);

        const existingIndex = leaves.indexOf(leafHash);
        if (existingIndex !== -1) {
          return json(
            {
              ok: false,
              error: {
                code: 'LEAF_ALREADY_EXISTS',
                message: 'Leaf hash already exists in this log (proof-by-hash would be ambiguous)',
                field: 'leaf_hash_b64u',
              },
              leaf_hash_b64u: leafHash,
              leaf_index: existingIndex,
              tree_size: leaves.length,
            },
            409,
          );
        }

        leaves.push(leafHash);
        await writeLeaves(this.state, leaves);

        const root = await computeMerkleRootB64u(leaves);
        const result: LogAppendResult = {
          leaf_hash_b64u: leafHash,
          leaf_index: leaves.length - 1,
          tree_size: leaves.length,
          root_hash_b64u: root,
        };

        return json({ ok: true, ...result }, 201);
      });
    }

    if (request.method === 'GET' && url.pathname === '/root') {
      const leaves = await readLeaves(this.state);
      const root = await computeMerkleRootB64u(leaves);

      return json({
        ok: true,
        tree_size: leaves.length,
        root_hash_b64u: root,
      });
    }

    if (request.method === 'GET' && url.pathname.startsWith('/proof/')) {
      const leafHash = getLeafHashFromPath(url.pathname);
      if (!leafHash) {
        return json(
          {
            ok: false,
            error: {
              code: 'INVALID_LEAF_HASH',
              message: 'Invalid or missing leaf hash path segment',
              field: 'leaf_hash_b64u',
            },
          },
          400,
        );
      }

      if (!isBase64urlString(leafHash, { minLen: 8 })) {
        return json(
          {
            ok: false,
            error: {
              code: 'INVALID_LEAF_HASH',
              message: 'leaf_hash_b64u must be base64url with length >= 8',
              field: 'leaf_hash_b64u',
            },
          },
          400,
        );
      }

      const leaves = await readLeaves(this.state);
      if (leaves.length === 0) {
        return json(
          {
            ok: false,
            error: {
              code: 'LEAF_NOT_FOUND',
              message: 'Log is empty',
              field: 'leaf_hash_b64u',
            },
          },
          404,
        );
      }

      let proof;
      try {
        proof = await buildMerkleProof(leaves, leafHash);
      } catch (err) {
        return json(
          {
            ok: false,
            error: {
              code: 'INCLUSION_PROOF_ERROR',
              message: err instanceof Error ? err.message : 'Failed to build inclusion proof',
            },
          },
          422,
        );
      }

      if (!proof) {
        return json(
          {
            ok: false,
            error: {
              code: 'LEAF_NOT_FOUND',
              message: 'Leaf hash not present in log',
              field: 'leaf_hash_b64u',
            },
          },
          404,
        );
      }

      const result: LogProofResult = {
        leaf_hash_b64u: proof.leaf_hash_b64u,
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_size,
        audit_path: proof.audit_path,
        root_hash_b64u: proof.root_hash_b64u,
      };

      return json({ ok: true, ...result });
    }

    return json({ ok: false, error: { code: 'NOT_FOUND', message: 'not found' } }, 404);
  }
}
