import type { Env, RootSignature } from './types';
import { importEd25519Signer, signEd25519 } from './crypto';
import { isBase64urlString } from './merkle';
import { LogDurableObject } from './log-do';
import { anchorMerkleRoot } from './cron-anchor';

export { LogDurableObject };

interface ParsedLogRoute {
  logId: string;
  action: 'append' | 'root' | 'proof';
  leafHash?: string;
}

/** Dedicated log ID for Receipt Transparency (RT). */
const RT_LOG_ID = 'receipt-transparency';

interface ParsedRtRoute {
  action: 'submit' | 'root' | 'proof';
  hash?: string;
}

function json(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      ...extraHeaders,
    },
  });
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'public, max-age=300',
      'x-robots-tag': 'noindex',
    },
  });
}

function text(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'access-control-allow-origin': '*',
    },
  });
}

function safeDecode(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function parseLogRoute(pathname: string): ParsedLogRoute | null {
  const append = pathname.match(/^\/v1\/logs\/([^/]+)\/append$/);
  if (append) {
    const logId = safeDecode(append[1]!);
    return logId ? { logId, action: 'append' } : null;
  }

  const root = pathname.match(/^\/v1\/logs\/([^/]+)\/root$/);
  if (root) {
    const logId = safeDecode(root[1]!);
    return logId ? { logId, action: 'root' } : null;
  }

  const proof = pathname.match(/^\/v1\/logs\/([^/]+)\/proof\/([^/]+)$/);
  if (proof) {
    const logId = safeDecode(proof[1]!);
    const leafHash = safeDecode(proof[2]!);
    if (!logId || !leafHash) return null;

    return {
      logId,
      action: 'proof',
      leafHash,
    };
  }

  return null;
}

function parseRtRoute(pathname: string): ParsedRtRoute | null {
  if (pathname === '/v1/rt/submit') return { action: 'submit' };
  if (pathname === '/v1/rt/root') return { action: 'root' };

  const proofMatch = pathname.match(/^\/v1\/rt\/proof\/([^/]+)$/);
  if (proofMatch) {
    const hash = safeDecode(proofMatch[1]!);
    return hash ? { action: 'proof', hash } : null;
  }

  return null;
}

function isAdminAuthed(request: Request, env: Env):
  | { ok: true }
  | { ok: false; status: number; code: string; message: string } {
  const expected = env.ADMIN_TOKEN;

  if (!expected || expected.trim().length === 0) {
    return {
      ok: false,
      status: 503,
      code: 'DEPENDENCY_NOT_CONFIGURED',
      message: 'ADMIN_TOKEN is not configured',
    };
  }

  const auth = request.headers.get('authorization');
  if (!auth) {
    return {
      ok: false,
      status: 401,
      code: 'UNAUTHORIZED',
      message: 'Authorization header required',
    };
  }

  const parts = auth.trim().split(/\s+/g);
  if (parts.length < 2 || parts[0]!.toLowerCase() !== 'bearer') {
    return {
      ok: false,
      status: 401,
      code: 'UNAUTHORIZED',
      message: 'Authorization must use Bearer token',
    };
  }

  const token = parts.slice(1).join(' ').trim();
  if (token !== expected.trim()) {
    return {
      ok: false,
      status: 401,
      code: 'UNAUTHORIZED',
      message: 'Invalid admin token',
    };
  }

  return { ok: true };
}

let signerCache: { key: string; signer: Awaited<ReturnType<typeof importEd25519Signer>> } | null = null;

async function getRootSigner(env: Env): Promise<Awaited<ReturnType<typeof importEd25519Signer>>> {
  const key = env.LOGS_SIGNING_KEY?.trim();
  if (!key) {
    throw new Error('LOGS_SIGNING_KEY is not configured');
  }

  if (signerCache && signerCache.key === key) {
    return signerCache.signer;
  }

  const signer = await importEd25519Signer(key);
  signerCache = { key, signer };
  return signer;
}

async function signRootHash(env: Env, rootHashB64u: string): Promise<RootSignature> {
  const signer = await getRootSigner(env);
  const sig_b64u = await signEd25519(signer.privateKey, rootHashB64u);
  return {
    signer_did: signer.did,
    sig_b64u,
  };
}

function getLogStub(env: Env, logId: string): DurableObjectStub {
  const id = env.LOGS.idFromName(logId);
  return env.LOGS.get(id);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET, POST, OPTIONS',
          'access-control-allow-headers': 'content-type, authorization',
        },
      });
    }

    // Landing
    if (request.method === 'GET' && url.pathname === '/') {
      return html(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawlogs</title>
  </head>
  <body>
    <main style="max-width: 840px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5;">
      <h1>clawlogs</h1>
      <p>Transparency log service for append-only leaf hashes and portable inclusion proofs.</p>
      <ul>
        <li><a href="/docs">Docs</a></li>
        <li><a href="/health">Health</a></li>
      </ul>
      <p><small>Version: ${env.SERVICE_VERSION}</small></p>
    </main>
  </body>
</html>`);
    }

    if (request.method === 'GET' && url.pathname === '/docs') {
      return html(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawlogs docs</title>
  </head>
  <body>
    <main style="max-width: 900px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5;">
      <h1>clawlogs docs</h1>

      <h2>Endpoints</h2>
      <ul>
        <li><code>POST /v1/logs/:log_id/append</code> — append one leaf hash (admin-gated).</li>
        <li><code>GET /v1/logs/:log_id/root</code> — current signed Merkle root.</li>
        <li><code>GET /v1/logs/:log_id/proof/:leaf_hash_b64u</code> — returns <code>log_inclusion_proof.v1</code>.</li>
      </ul>

      <h2>Receipt Transparency (RT)</h2>
      <ul>
        <li><code>POST /v1/rt/submit</code> — submit receipt hash to RT Merkle tree (admin-gated). Returns <code>log_inclusion_proof.v1</code>.</li>
        <li><code>GET /v1/rt/root</code> — current signed RT Merkle root + tree size + timestamp.</li>
        <li><code>GET /v1/rt/proof/:receipt_hash_b64u</code> — inclusion proof for a previously submitted receipt hash.</li>
      </ul>

      <h2>Append</h2>
      <pre>curl -sS -X POST "${url.origin}/v1/logs/audit-main/append" \\
  -H "Authorization: Bearer $ADMIN_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"leaf_hash_b64u":"z0nfrD8QEk5DBQYn0HJgGithUqlcvGYnZ9bqXrlgYA4"}'</pre>

      <h2>Root</h2>
      <pre>curl -sS "${url.origin}/v1/logs/audit-main/root" | jq .</pre>

      <h2>Proof</h2>
      <pre>curl -sS "${url.origin}/v1/logs/audit-main/proof/$LEAF_HASH_B64U" | jq .</pre>

      <p><small>Version: ${env.SERVICE_VERSION}</small></p>
    </main>
  </body>
</html>`);
    }

    // Health
    if (request.method === 'GET' && url.pathname === '/health') {
      return json({
        status: 'ok',
        version: env.SERVICE_VERSION,
        rootSigningEnabled: !!(env.LOGS_SIGNING_KEY && env.LOGS_SIGNING_KEY.trim().length > 0),
        appendAdminEnabled: !!(env.ADMIN_TOKEN && env.ADMIN_TOKEN.trim().length > 0),
      });
    }

    // --- Receipt Transparency (RT) endpoints ---
    const rt = parseRtRoute(url.pathname);
    if (rt) {
      const rtStub = getLogStub(env, RT_LOG_ID);

      // POST /v1/rt/submit — append receipt hash to RT Merkle tree
      if (request.method === 'POST' && rt.action === 'submit') {
        const admin = isAdminAuthed(request, env);
        if (!admin.ok) {
          return json({ ok: false, error: { code: admin.code, message: admin.message } }, admin.status);
        }

        let body: unknown;
        try {
          body = await request.json();
        } catch {
          return json({ ok: false, error: { code: 'INVALID_JSON', message: 'Body must be valid JSON' } }, 400);
        }

        if (typeof body !== 'object' || body === null || !('receipt_hash_b64u' in body)) {
          return json(
            { ok: false, error: { code: 'MISSING_REQUIRED_FIELD', message: 'Body must contain receipt_hash_b64u', field: 'receipt_hash_b64u' } },
            400,
          );
        }

        const receiptHash = (body as Record<string, unknown>).receipt_hash_b64u;
        if (!isBase64urlString(receiptHash, { minLen: 8 })) {
          return json(
            { ok: false, error: { code: 'INVALID_RECEIPT_HASH', message: 'receipt_hash_b64u must be base64url with length >= 8', field: 'receipt_hash_b64u' } },
            400,
          );
        }

        // Forward to DO as a standard leaf append
        const doResponse = await rtStub.fetch(
          new Request('https://do.local/append', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ leaf_hash_b64u: receiptHash }),
          }),
        );

        const doBody = (await doResponse.json().catch(() => null)) as Record<string, unknown> | null;

        if (!doBody || !doBody.ok) {
          // Pass through error (e.g. LEAF_ALREADY_EXISTS)
          return json({ log_id: RT_LOG_ID, ...(doBody ?? {}) }, doResponse.status);
        }

        // Build full inclusion proof with signature
        let rootSignature: RootSignature;
        try {
          rootSignature = await signRootHash(env, doBody.root_hash_b64u as string);
        } catch (err) {
          return json(
            { ok: false, error: { code: 'DEPENDENCY_NOT_CONFIGURED', message: err instanceof Error ? err.message : 'LOGS_SIGNING_KEY is not configured', field: 'env.LOGS_SIGNING_KEY' } },
            503,
          );
        }

        // Return log_inclusion_proof.v1 shaped response
        const publishedAt = new Date().toISOString();

        // Build audit_path by fetching the proof for the just-appended leaf
        const proofResponse = await rtStub.fetch(
          new Request(`https://do.local/proof/${encodeURIComponent(receiptHash)}`, { method: 'GET' }),
        );
        const proofBody = (await proofResponse.json().catch(() => null)) as Record<string, unknown> | null;

        if (!proofBody || !proofBody.ok) {
          return json(
            { ok: false, error: { code: 'INTERNAL_ERROR', message: 'Failed to build inclusion proof after append' } },
            500,
          );
        }

        return json({
          ok: true,
          log_inclusion_proof: {
            proof_version: '1',
            log_id: RT_LOG_ID,
            tree_size: proofBody.tree_size,
            leaf_hash_b64u: receiptHash,
            root_hash_b64u: proofBody.root_hash_b64u,
            audit_path: proofBody.audit_path,
            root_published_at: publishedAt,
            root_signature: rootSignature,
            metadata: {
              leaf_index: proofBody.leaf_index,
              merkle_algorithm: 'sha256(left||right), duplicate-last for odd levels',
            },
          },
        }, 201);
      }

      // GET /v1/rt/root — current signed Merkle root of RT log
      if (request.method === 'GET' && rt.action === 'root') {
        const doResponse = await rtStub.fetch(new Request('https://do.local/root', { method: 'GET' }));
        const body = (await doResponse.json().catch(() => null)) as
          | { ok?: boolean; root_hash_b64u?: string; tree_size?: number }
          | null;

        if (!body || !body.ok || typeof body.root_hash_b64u !== 'string' || typeof body.tree_size !== 'number') {
          return json({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'Failed to resolve RT root from storage' } }, 500);
        }

        if (!isBase64urlString(body.root_hash_b64u, { minLen: 8 })) {
          return json({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'Computed RT root is invalid' } }, 500);
        }

        let signature: RootSignature;
        try {
          signature = await signRootHash(env, body.root_hash_b64u);
        } catch (err) {
          return json(
            { ok: false, error: { code: 'DEPENDENCY_NOT_CONFIGURED', message: err instanceof Error ? err.message : 'LOGS_SIGNING_KEY is not configured', field: 'env.LOGS_SIGNING_KEY' } },
            503,
          );
        }

        return json({
          ok: true,
          log_id: RT_LOG_ID,
          root_hash_b64u: body.root_hash_b64u,
          tree_size: body.tree_size,
          published_at: new Date().toISOString(),
          signature,
        });
      }

      // GET /v1/rt/proof/{hash} — inclusion proof for a receipt hash
      if (request.method === 'GET' && rt.action === 'proof') {
        const leafHash = rt.hash;
        if (!leafHash || !isBase64urlString(leafHash, { minLen: 8 })) {
          return json(
            { ok: false, error: { code: 'INVALID_RECEIPT_HASH', message: 'receipt hash must be base64url with length >= 8', field: 'receipt_hash_b64u' } },
            400,
          );
        }

        const doResponse = await rtStub.fetch(new Request(`https://do.local/proof/${encodeURIComponent(leafHash)}`, { method: 'GET' }));
        const body = (await doResponse.json().catch(() => null)) as
          | { ok?: boolean; leaf_hash_b64u?: string; leaf_index?: number; tree_size?: number; audit_path?: string[]; root_hash_b64u?: string; error?: unknown }
          | null;

        if (!body) {
          return json({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'DO proof response was not JSON' } }, 500);
        }

        if (!body.ok) {
          return json({ log_id: RT_LOG_ID, ...body }, doResponse.status);
        }

        if (
          typeof body.leaf_hash_b64u !== 'string' ||
          typeof body.leaf_index !== 'number' ||
          typeof body.tree_size !== 'number' ||
          !Array.isArray(body.audit_path) ||
          typeof body.root_hash_b64u !== 'string'
        ) {
          return json({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'Malformed proof payload from storage' } }, 500);
        }

        let rootSignature: RootSignature;
        try {
          rootSignature = await signRootHash(env, body.root_hash_b64u);
        } catch (err) {
          return json(
            { ok: false, error: { code: 'DEPENDENCY_NOT_CONFIGURED', message: err instanceof Error ? err.message : 'LOGS_SIGNING_KEY is not configured', field: 'env.LOGS_SIGNING_KEY' } },
            503,
          );
        }

        return json({
          proof_version: '1',
          log_id: RT_LOG_ID,
          tree_size: body.tree_size,
          leaf_hash_b64u: body.leaf_hash_b64u,
          root_hash_b64u: body.root_hash_b64u,
          audit_path: body.audit_path,
          root_published_at: new Date().toISOString(),
          root_signature: rootSignature,
          metadata: {
            leaf_index: body.leaf_index,
            merkle_algorithm: 'sha256(left||right), duplicate-last for odd levels',
          },
        });
      }

      return text('method not allowed', 405);
    }

    const parsed = parseLogRoute(url.pathname);
    if (!parsed) {
      return text('not found', 404);
    }

    if (!parsed.logId || parsed.logId.trim().length === 0) {
      return json({ ok: false, error: { code: 'INVALID_LOG_ID', message: 'log_id is required' } }, 400);
    }

    const stub = getLogStub(env, parsed.logId);

    if (request.method === 'POST' && parsed.action === 'append') {
      const admin = isAdminAuthed(request, env);
      if (!admin.ok) {
        return json({ ok: false, error: { code: admin.code, message: admin.message } }, admin.status);
      }

      const doResponse = await stub.fetch(
        new Request('https://do.local/append', {
          method: 'POST',
          headers: { 'content-type': request.headers.get('content-type') ?? 'application/json' },
          body: await request.text(),
        }),
      );

      const body = await doResponse.json().catch(() => null);
      return json({ log_id: parsed.logId, ...(body ?? {}) }, doResponse.status);
    }

    if (request.method === 'GET' && parsed.action === 'root') {
      const doResponse = await stub.fetch(new Request('https://do.local/root', { method: 'GET' }));
      const body = (await doResponse.json().catch(() => null)) as
        | { ok?: boolean; root_hash_b64u?: string; tree_size?: number; error?: unknown }
        | null;

      if (!body || !body.ok || typeof body.root_hash_b64u !== 'string' || typeof body.tree_size !== 'number') {
        return json({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'Failed to resolve root from storage' } }, 500);
      }

      if (!isBase64urlString(body.root_hash_b64u, { minLen: 8 })) {
        return json({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'Computed root is invalid' } }, 500);
      }

      let signature: RootSignature;
      try {
        signature = await signRootHash(env, body.root_hash_b64u);
      } catch (err) {
        return json(
          {
            ok: false,
            error: {
              code: 'DEPENDENCY_NOT_CONFIGURED',
              message: err instanceof Error ? err.message : 'LOGS_SIGNING_KEY is not configured',
              field: 'env.LOGS_SIGNING_KEY',
            },
          },
          503,
        );
      }

      const publishedAt = new Date().toISOString();
      return json({
        ok: true,
        log_id: parsed.logId,
        root_hash_b64u: body.root_hash_b64u,
        tree_size: body.tree_size,
        published_at: publishedAt,
        signature,
      });
    }

    if (request.method === 'GET' && parsed.action === 'proof') {
      const leafHash = parsed.leafHash;
      if (!leafHash || !isBase64urlString(leafHash, { minLen: 8 })) {
        return json(
          {
            ok: false,
            error: {
              code: 'INVALID_LEAF_HASH',
              message: 'leaf_hash_b64u path segment must be base64url with length >= 8',
              field: 'leaf_hash_b64u',
            },
          },
          400,
        );
      }

      const doResponse = await stub.fetch(new Request(`https://do.local/proof/${encodeURIComponent(leafHash)}`, { method: 'GET' }));
      const body = (await doResponse.json().catch(() => null)) as
        | {
            ok?: boolean;
            leaf_hash_b64u?: string;
            leaf_index?: number;
            tree_size?: number;
            audit_path?: string[];
            root_hash_b64u?: string;
            error?: unknown;
          }
        | null;

      if (!body) {
        return json({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'DO proof response was not JSON' } }, 500);
      }

      if (!body.ok) {
        return json({ log_id: parsed.logId, ...body }, doResponse.status);
      }

      if (
        typeof body.leaf_hash_b64u !== 'string' ||
        typeof body.leaf_index !== 'number' ||
        typeof body.tree_size !== 'number' ||
        !Array.isArray(body.audit_path) ||
        typeof body.root_hash_b64u !== 'string'
      ) {
        return json({ ok: false, error: { code: 'INTERNAL_ERROR', message: 'Malformed proof payload from storage' } }, 500);
      }

      let rootSignature: RootSignature;
      try {
        rootSignature = await signRootHash(env, body.root_hash_b64u);
      } catch (err) {
        return json(
          {
            ok: false,
            error: {
              code: 'DEPENDENCY_NOT_CONFIGURED',
              message: err instanceof Error ? err.message : 'LOGS_SIGNING_KEY is not configured',
              field: 'env.LOGS_SIGNING_KEY',
            },
          },
          503,
        );
      }

      const rootPublishedAt = new Date().toISOString();

      return json({
        proof_version: '1',
        log_id: parsed.logId,
        tree_size: body.tree_size,
        leaf_hash_b64u: body.leaf_hash_b64u,
        root_hash_b64u: body.root_hash_b64u,
        audit_path: body.audit_path,
        root_published_at: rootPublishedAt,
        root_signature: rootSignature,
        metadata: {
          leaf_index: body.leaf_index,
          merkle_algorithm: 'sha256(left||right), duplicate-last for odd levels',
        },
      });
    }

    return text('method not allowed', 405);
  },

  /**
   * Red Team Fix #3: Daily cron trigger anchors the RT Merkle root
   * to the ClawsigRTAnchor contract on Base L2.
   * Configured via [triggers] crons = ["0 0 * * *"] in wrangler.toml.
   */
  async scheduled(
    _event: ScheduledEvent,
    env: Env,
    ctx: ExecutionContext
  ): Promise<void> {
    ctx.waitUntil(anchorMerkleRoot(env as Parameters<typeof anchorMerkleRoot>[0]));
  },
};
