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
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';

import { base64UrlDecode } from './crypto';
import type {
  AdapterSession,
  ClawproxyReceipt,
  ReceiptArtifact,
  SignedEnvelope,
  GatewayReceiptPayload,
} from './types';

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

function isStreamingShimRequest(body: Record<string, unknown>, req: IncomingMessage): boolean {
  if (body.stream === true) return true;
  const accept = firstHeader(req.headers['accept']);
  return typeof accept === 'string' && accept.toLowerCase().includes('text/event-stream');
}

function decodeB64uJson(value: string): unknown {
  const bytes = base64UrlDecode(value);
  const text = new TextDecoder().decode(bytes);
  return JSON.parse(text) as unknown;
}

class ClawproxyReceiptTrailerStripper extends Transform {
  receiptB64u: string | null = null;
  receiptEnvelopeB64u: string | null = null;

  private pending = '';
  private suppressNextBlank = false;

  constructor() {
    super();
  }

  _transform(chunk: Buffer, _enc: BufferEncoding, cb: (error?: Error | null) => void) {
    try {
      this.pending += chunk.toString('utf8');

      while (true) {
        const idx = this.pending.indexOf('\n');
        if (idx === -1) break;

        const line = this.pending.slice(0, idx);
        this.pending = this.pending.slice(idx + 1);

        const clean = line.endsWith('\r') ? line.slice(0, -1) : line;

        if (clean.startsWith(':')) {
          const comment = clean.slice(1).trimStart();

          if (comment.startsWith('clawproxy_receipt_envelope_b64u=')) {
            this.receiptEnvelopeB64u = comment
              .slice('clawproxy_receipt_envelope_b64u='.length)
              .trim();
            this.suppressNextBlank = true;
            continue;
          }

          if (comment.startsWith('clawproxy_receipt_b64u=')) {
            this.receiptB64u = comment
              .slice('clawproxy_receipt_b64u='.length)
              .trim();
            this.suppressNextBlank = true;
            continue;
          }
        }

        // Skip the blank line terminating the trailer comment event.
        if (this.suppressNextBlank && clean === '') {
          this.suppressNextBlank = false;
          continue;
        }
        this.suppressNextBlank = false;

        this.push(Buffer.from(line + '\n', 'utf8'));
      }

      cb();
    } catch (err) {
      cb(err instanceof Error ? err : new Error(String(err)));
    }
  }

  _flush(cb: (error?: Error | null) => void) {
    try {
      if (this.pending.length > 0) {
        this.push(Buffer.from(this.pending, 'utf8'));
      }
      cb();
    } catch (err) {
      cb(err instanceof Error ? err : new Error(String(err)));
    }
  }
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

      const streaming = isStreamingShimRequest(body as Record<string, unknown>, req);

      if (!streaming) {
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
        return;
      }

      // Streaming path (POH-US-019): forward SSE without buffering full bodies.
      await withChainLock(async () => {
        // Record the LLM call event to get binding context (run_id/event_hash/nonce).
        const { binding } = await options.session.recordEvent({
          eventType: 'llm_call',
          payload: { provider, model },
        });

        const proxyUrl = `${options.session.proxyBaseUrl.replace(/\/+$/, '')}/v1/proxy/${provider}`;

        const proxyHeaders: Record<string, string> = {
          'Content-Type': 'application/json',
          Accept: firstHeader(req.headers['accept']) ?? 'text/event-stream',
          'X-Run-Id': binding.runId,
          ...(binding.eventHash ? { 'X-Event-Hash': binding.eventHash } : {}),
          ...(binding.nonce ? { 'X-Idempotency-Key': binding.nonce } : {}),
          ...extraHeaders,
        };

        // Proxy auth token (CST/JWT)
        if (options.session.proxyToken) {
          proxyHeaders['Authorization'] = `Bearer ${options.session.proxyToken}`;
        }

        // Forward a few provider-specific headers that clawproxy may forward upstream.
        const anthropicVersion = firstHeader(req.headers['anthropic-version']);
        if (anthropicVersion) proxyHeaders['anthropic-version'] = anthropicVersion;
        const anthropicBeta = firstHeader(req.headers['anthropic-beta']);
        if (anthropicBeta) proxyHeaders['anthropic-beta'] = anthropicBeta;

        let proxyRes: Response;
        try {
          proxyRes = await fetch(proxyUrl, {
            method: 'POST',
            headers: proxyHeaders,
            body: JSON.stringify(body),
          });
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          sendJson(res, 502, { error: 'UPSTREAM_FETCH_FAILED', message: msg });
          return;
        }

        res.statusCode = proxyRes.status;

        const ct = proxyRes.headers.get('content-type');
        if (ct) res.setHeader('Content-Type', ct);

        const xver = proxyRes.headers.get('x-proxy-version');
        if (xver) res.setHeader('X-Proxy-Version', xver);

        if (!proxyRes.body) {
          res.end();
          return;
        }

        const stripper = new ClawproxyReceiptTrailerStripper();

        try {
          await pipeline(Readable.fromWeb(proxyRes.body as any), stripper, res);
        } catch {
          // If the client disconnects mid-stream, we still attempt receipt recovery below via nonce receipt lookup.
        }

        let receipt: ClawproxyReceipt | undefined;
        let receiptEnvelope: SignedEnvelope<GatewayReceiptPayload> | undefined;

        try {
          if (stripper.receiptB64u) {
            receipt = decodeB64uJson(stripper.receiptB64u) as ClawproxyReceipt;
          }
          if (stripper.receiptEnvelopeB64u) {
            receiptEnvelope = decodeB64uJson(stripper.receiptEnvelopeB64u) as SignedEnvelope<GatewayReceiptPayload>;
          }
        } catch {
          // ignore; fallback to replay below
        }

        if (!receipt || !receiptEnvelope) {
          // Deterministic fallback: fetch stored receipts by nonce (no full-body replay).
          if (binding.nonce) {
            const base = options.session.proxyBaseUrl.replace(/\/+$/, '');
            const receiptUrl = new URL(
              `${base}/v1/receipt/${encodeURIComponent(binding.nonce)}`,
            );
            receiptUrl.searchParams.set('run_id', binding.runId);
            if (binding.eventHash) {
              receiptUrl.searchParams.set('event_hash_b64u', binding.eventHash);
            }

            const lookupHeaders: Record<string, string> = {
              Accept: 'application/json',
            };

            // Proxy auth token (CST/JWT) if configured.
            if (options.session.proxyToken) {
              lookupHeaders['Authorization'] = `Bearer ${options.session.proxyToken}`;
            }

            for (let attempt = 0; attempt < 5 && (!receipt || !receiptEnvelope); attempt++) {
              try {
                const lookupRes = await fetch(receiptUrl.toString(), {
                  method: 'GET',
                  headers: lookupHeaders,
                });

                if (lookupRes.ok) {
                  const data = await lookupRes.json().catch(() => null);
                  if (data && typeof data === 'object') {
                    const obj = data as Record<string, unknown>;
                    const r = obj['receipt'];
                    const re = obj['receipt_envelope'];
                    if (r && typeof r === 'object') receipt = r as ClawproxyReceipt;
                    if (re && typeof re === 'object') receiptEnvelope = re as SignedEnvelope<GatewayReceiptPayload>;
                  }
                  break;
                }

                // If the DO commit is still inflight, retry briefly.
                if (lookupRes.status === 409) {
                  await new Promise((r) => setTimeout(r, 50 * (attempt + 1)));
                  continue;
                }

                // For 404/other errors, stop trying.
                break;
              } catch {
                // transient fetch error
                await new Promise((r) => setTimeout(r, 50 * (attempt + 1)));
              }
            }
          }
        }

        if (receipt) {
          const artifact: ReceiptArtifact = {
            type: 'clawproxy_receipt',
            collectedAt: new Date().toISOString(),
            model,
            receipt,
            receiptEnvelope: receiptEnvelope ?? undefined,
          };
          options.session.addReceipt(artifact);
        }

        if (log) {
          log(`shim: ${provider} ${pathname} (stream) → ${proxyRes.status}`);
        }
      });

      return;
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
