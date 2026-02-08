/**
 * Local shim proxy for external harnesses.
 *
 * Many agent harness CLIs (Claude Code, Pi, Codex, Opencode, etc.) can be
 * pointed at an alternate provider base URL, but they generally do NOT expose:
 *   - PoH binding headers (X-Run-Id/X-Event-Hash/X-Idempotency-Key)
 *   - access to the raw JSON responses (to extract `_receipt_envelope`)
 *
 * The shim solves this by running a local HTTP server that:
 *   1) Receives provider-compatible requests from the harness SDK
 *   2) Forwards them to clawproxy via session.proxyLLMCall() (adds binding)
 *   3) Captures receipts + records llm_call events
 *   4) Returns a clean provider-shaped JSON response back to the harness
 */

import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { IncomingMessage, Server } from 'node:http';

import type { AdapterSession } from './types';

export type ShimProvider = 'openai' | 'anthropic' | 'google';

export interface ShimServer {
  /** Base URL that harnesses should use for provider base URL overrides. */
  readonly baseUrl: string;
  /** Close the server and stop accepting requests. */
  close(): Promise<void>;
}

export interface StartShimOptions {
  session: AdapterSession;
  host?: string;
  port?: number;
  /** Optional debug logger. */
  log?: (msg: string) => void;
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  if (!value) return undefined;
  return Array.isArray(value) ? value[0] : value;
}

function stripBearer(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const m = trimmed.match(/^Bearer\s+/i);
  return m ? trimmed.slice(m[0].length).trim() : trimmed;
}

async function readJsonBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString('utf-8');
  if (!raw.trim()) return null;
  return JSON.parse(raw);
}

function sendJson(res: import('node:http').ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function inferProvider(pathname: string): ShimProvider | null {
  const p = pathname.toLowerCase();

  // OpenAI-compatible endpoints
  if (p.endsWith('/chat/completions')) return 'openai';
  if (p.endsWith('/responses')) return 'openai';

  // Anthropic-compatible endpoints
  if (p.endsWith('/messages')) return 'anthropic';

  // Gemini-compatible endpoints (best-effort; may evolve)
  if (p.includes(':generatecontent')) return 'google';

  return null;
}

function cleanProviderResponse(status: number, body: unknown): unknown {
  if (!body || typeof body !== 'object') return body;

  const obj = body as Record<string, unknown>;
  const cleaned: Record<string, unknown> = { ...obj };

  // Remove clawproxy receipt side-channel fields.
  delete cleaned._receipt;
  delete cleaned._receipt_envelope;

  // clawproxy wraps provider errors as: { error: <providerError>, status: <code>, _receipt... }
  // External SDKs typically expect the raw provider error JSON, so unwrap.
  if (status >= 400 && 'error' in cleaned && 'status' in cleaned) {
    const s = cleaned.status;
    if (typeof s === 'number' && s === status) {
      return cleaned.error;
    }
  }

  return cleaned;
}

function extractUpstreamKey(provider: ShimProvider, req: IncomingMessage): string | undefined {
  const headers = req.headers;

  if (provider === 'openai') {
    // OpenAI SDKs usually use Authorization: Bearer <key>
    const auth = firstHeader(headers['authorization']);
    return stripBearer(auth);
  }

  if (provider === 'anthropic') {
    // Anthropic uses x-api-key, sometimes anthropic-api-key.
    const xApiKey = firstHeader(headers['x-api-key']);
    if (xApiKey) return xApiKey.trim();

    const anthropicApiKey = firstHeader(headers['anthropic-api-key']);
    if (anthropicApiKey) return anthropicApiKey.trim();

    // Some clients may still use Authorization.
    const auth = firstHeader(headers['authorization']);
    return stripBearer(auth);
  }

  if (provider === 'google') {
    const xGoog = firstHeader(headers['x-goog-api-key']);
    if (xGoog) return xGoog.trim();

    const auth = firstHeader(headers['authorization']);
    return stripBearer(auth);
  }

  return undefined;
}

/**
 * Start a local shim server.
 */
export async function startShim(options: StartShimOptions): Promise<ShimServer> {
  const host = options.host ?? '127.0.0.1';
  const port = options.port ?? 0;
  const log = options.log;

  // Serialize proxyLLMCall() to keep a linear event chain.
  let chainLock: Promise<void> = Promise.resolve();
  const withChainLock = async <T>(fn: () => Promise<T>): Promise<T> => {
    const run = chainLock.then(fn, fn);
    chainLock = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  };

  const server = createServer(async (req, res) => {
    try {
      const method = req.method ?? 'GET';
      const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
      const pathname = url.pathname;

      if (method === 'GET' && pathname === '/health') {
        sendJson(res, 200, { status: 'ok' });
        return;
      }

      if (method !== 'POST') {
        sendJson(res, 405, { error: 'METHOD_NOT_ALLOWED' });
        return;
      }

      const provider = inferProvider(pathname);
      if (!provider) {
        sendJson(res, 404, { error: 'NOT_FOUND', path: pathname });
        return;
      }

      const body = await readJsonBody(req);
      if (!body || typeof body !== 'object') {
        sendJson(res, 400, { error: 'INVALID_REQUEST', message: 'Expected JSON object body' });
        return;
      }

      const model = (body as Record<string, unknown>)['model'];
      if (typeof model !== 'string' || model.trim().length === 0) {
        // Google Gemini can encode model in path, but for now we align with clawproxy
        // which requires model in the request body.
        sendJson(res, 400, { error: 'INVALID_REQUEST', message: 'Missing required field: model' });
        return;
      }

      const upstreamKey = extractUpstreamKey(provider, req);
      const extraHeaders: Record<string, string> = {};
      if (upstreamKey) {
        extraHeaders['X-Provider-API-Key'] = upstreamKey;
      }

      // Forward through clawproxy with PoH binding headers (via the session).
      const result = await withChainLock(() =>
        options.session.proxyLLMCall({
          provider,
          model,
          body,
          headers: extraHeaders,
        }),
      );

      const cleaned = cleanProviderResponse(result.status, result.response);
      sendJson(res, result.status, cleaned);

      if (log) {
        log(`shim: ${provider} ${pathname} → ${result.status}`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      sendJson(res, 500, { error: 'INTERNAL_ERROR', message: msg });
      return;
    }
  });

  await listen(server, port, host);

  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    // Should not happen for TCP servers.
    throw new Error('Failed to determine shim server address');
  }

  const baseUrl = `http://${host}:${(addr as AddressInfo).port}`;
  if (log) log(`shim: listening at ${baseUrl}`);

  return {
    baseUrl,
    async close() {
      await closeServer(server);
      if (log) log('shim: closed');
    },
  };
}

async function listen(server: Server, port: number, host: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}
