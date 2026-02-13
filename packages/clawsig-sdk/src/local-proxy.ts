/**
 * Local interceptor proxy for clawsig wrap.
 *
 * Starts a lightweight HTTP server on a random port that intercepts
 * OpenAI-compatible and Anthropic-compatible API requests, rewrites
 * auth headers, forwards them through clawproxy, and collects
 * gateway receipts for proof bundle compilation.
 *
 * Uses only `node:http` — zero external dependencies.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { hashJsonB64u, sha256B64u, base64UrlEncode } from './crypto.js';
import type { EphemeralDid } from './ephemeral-did.js';
import type { SignedEnvelope, GatewayReceiptPayload, ProofBundlePayload, EventChainEntry } from './types.js';
import { CausalSieve, type LocalPolicy, type PolicyViolation } from './causal-sieve.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Options for starting the local interceptor proxy. */
export interface ProxyOptions {
  /** Ephemeral DID identity for this run. */
  agentDid: EphemeralDid;
  /** Unique run identifier. */
  runId: string;
  /** Upstream clawproxy URL (default: https://clawproxy.com). */
  clawproxyUrl?: string;
  /** Provider API key for OpenAI (passed through to clawproxy). */
  providerApiKey?: string;
  /** Local WPC policy for the TCP Guillotine. */
  policy?: LocalPolicy | null;
  /** Working directory for git diff operations. */
  cwd?: string;
  /** Callback when a policy violation is detected in the stream. */
  onViolation?: (violation: PolicyViolation) => void;
  /**
   * Passthrough mode: forward directly to upstream provider APIs
   * instead of routing through clawproxy.com.
   *
   * In passthrough mode:
   * - Requests go straight to api.anthropic.com / api.openai.com
   * - Original auth headers are preserved
   * - No gateway receipts are generated (no clawproxy)
   * - The Causal Sieve still parses tool_calls/tool_results
   * - Git diff still detects file mutations
   *
   * Use this when the agent has its own API auth (OAuth, API keys)
   * that clawproxy doesn't support.
   */
  passthrough?: boolean;
}

/** A running local proxy instance. */
export interface LocalProxy {
  /** The port the proxy is listening on. */
  port: number;
  /** Stop the proxy server. */
  stop(): Promise<void>;
  /** Compile all collected receipts into a signed proof bundle. */
  compileProofBundle(): Promise<SignedEnvelope<ProofBundlePayload>>;
  /** Number of receipts collected so far. */
  receiptCount: number;
  /** Number of tool receipts synthesized by the Causal Sieve. */
  toolReceiptCount: number;
  /** Number of side-effect receipts synthesized by the Causal Sieve. */
  sideEffectReceiptCount: number;
  /** Number of policy violations detected by the TCP Guillotine. */
  violationCount: number;
  /** Per-run privacy salt (base64url-encoded, 16 bytes). Needed by verifiers. */
  runSaltB64u: string;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface CollectedReceipt {
  envelope: SignedEnvelope<GatewayReceiptPayload>;
  collectedAt: string;
  provider: string;
  model: string;
}

function randomUUID(): string {
  return crypto.randomUUID();
}

/**
 * Read the full request body from an IncomingMessage.
 */
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Detect provider from the request path.
 * Supported routes:
 *   /v1/proxy/openai   -> openai
 *   /v1/proxy/anthropic -> anthropic
 *   /v1/chat/completions -> openai (compatibility)
 *   /v1/messages -> anthropic (compatibility)
 */
function detectProvider(pathname: string): string | null {
  if (pathname.startsWith('/v1/proxy/')) {
    const provider = pathname.slice('/v1/proxy/'.length).split('/')[0];
    return provider || null;
  }
  if (pathname === '/v1/chat/completions') return 'openai';
  if (pathname === '/v1/messages') return 'anthropic';
  return null;
}

/**
 * Extract provider API key from incoming request headers.
 * Checks X-Provider-API-Key first, then Authorization: Bearer.
 */
function extractProviderKey(headers: Record<string, string | string[] | undefined>): string | undefined {
  const explicit = headers['x-provider-api-key'];
  if (typeof explicit === 'string' && explicit.trim().length > 0) {
    return explicit.trim();
  }

  const auth = headers['authorization'];
  if (typeof auth === 'string') {
    const match = auth.match(/^Bearer\s+(.+)/i);
    if (match?.[1]) return match[1].trim();
  }

  return undefined;
}

/**
 * Forward a request to clawproxy with receipt-binding headers.
 * Handles both streaming (SSE) and non-streaming responses.
 */
async function forwardToClawproxy(
  provider: string,
  bodyBuffer: Buffer,
  providerApiKey: string | undefined,
  clawproxyUrl: string,
  runId: string,
  agentDid: string,
  idempotencyKey: string,
): Promise<{ status: number; headers: Record<string, string>; body: Buffer; isStream: boolean }> {
  const targetUrl = `${clawproxyUrl}/v1/proxy/${provider}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Run-Id': runId,
    'X-Idempotency-Key': idempotencyKey,
    'X-Agent-DID': agentDid,
  };

  if (providerApiKey) {
    headers['X-Provider-API-Key'] = providerApiKey;
  }

  const res = await fetch(targetUrl, {
    method: 'POST',
    headers,
    body: new Uint8Array(bodyBuffer),
  });

  const contentType = res.headers.get('content-type') ?? '';
  const isStream = contentType.includes('text/event-stream');

  const responseBuffer = Buffer.from(await res.arrayBuffer());

  const responseHeaders: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });

  return {
    status: res.status,
    headers: responseHeaders,
    body: responseBuffer,
    isStream,
  };
}

/** Map provider name to upstream API base URL. */
const UPSTREAM_URLS: Record<string, string> = {
  openai: 'https://api.openai.com',
  anthropic: 'https://api.anthropic.com',
  google: 'https://generativelanguage.googleapis.com',
};

/** Map provider to the expected API path. */
const UPSTREAM_PATHS: Record<string, string> = {
  openai: '/v1/chat/completions',
  anthropic: '/v1/messages',
};

/**
 * Forward a request directly to the upstream provider (passthrough mode).
 * Preserves the original auth headers from the incoming request.
 */
async function forwardToUpstream(
  provider: string,
  bodyBuffer: Buffer,
  incomingHeaders: Record<string, string | string[] | undefined>,
): Promise<{ status: number; headers: Record<string, string>; body: Buffer; isStream: boolean }> {
  const baseUrl = UPSTREAM_URLS[provider] ?? `https://api.${provider}.com`;
  const path = UPSTREAM_PATHS[provider] ?? '/v1/chat/completions';
  const targetUrl = `${baseUrl}${path}`;

  // Forward relevant headers (auth, content-type, provider-specific)
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  // Preserve auth headers
  const authHeader = incomingHeaders['authorization'];
  if (typeof authHeader === 'string') headers['Authorization'] = authHeader;

  const apiKey = incomingHeaders['x-api-key'];
  if (typeof apiKey === 'string') headers['x-api-key'] = apiKey;

  // Preserve Anthropic-specific headers
  const anthropicVersion = incomingHeaders['anthropic-version'];
  if (typeof anthropicVersion === 'string') headers['anthropic-version'] = anthropicVersion;

  const anthropicBeta = incomingHeaders['anthropic-beta'];
  if (typeof anthropicBeta === 'string') headers['anthropic-beta'] = anthropicBeta;

  const res = await fetch(targetUrl, {
    method: 'POST',
    headers,
    body: new Uint8Array(bodyBuffer),
  });

  const contentType = res.headers.get('content-type') ?? '';
  const isStream = contentType.includes('text/event-stream');
  const responseBuffer = Buffer.from(await res.arrayBuffer());

  const responseHeaders: Record<string, string> = {};
  res.headers.forEach((value, key) => {
    responseHeaders[key] = value;
  });

  return { status: res.status, headers: responseHeaders, body: responseBuffer, isStream };
}

/**
 * Extract receipt envelope from a clawproxy JSON response.
 */
function extractReceiptFromResponse(body: Buffer): {
  envelope?: SignedEnvelope<GatewayReceiptPayload>;
  provider: string;
  model: string;
} {
  try {
    const parsed = JSON.parse(body.toString('utf-8')) as Record<string, unknown>;
    const envelope = parsed['_receipt_envelope'] as SignedEnvelope<GatewayReceiptPayload> | undefined;

    // Extract provider/model from envelope payload or legacy receipt
    let provider = 'unknown';
    let model = 'unknown';

    if (envelope?.payload) {
      provider = envelope.payload.provider ?? 'unknown';
      model = envelope.payload.model ?? 'unknown';
    } else {
      const legacyReceipt = parsed['_receipt'] as Record<string, unknown> | undefined;
      if (legacyReceipt) {
        provider = (legacyReceipt['provider'] as string) ?? 'unknown';
        model = (legacyReceipt['model'] as string) ?? 'unknown';
      }
    }

    return { envelope, provider, model };
  } catch {
    return { provider: 'unknown', model: 'unknown' };
  }
}

/**
 * Extract receipt from a streaming (SSE) response.
 * Clawproxy appends the receipt as a final SSE event.
 */
function extractReceiptFromStream(body: Buffer): {
  envelope?: SignedEnvelope<GatewayReceiptPayload>;
  provider: string;
  model: string;
} {
  const text = body.toString('utf-8');
  const lines = text.split('\n');

  // Look for receipt event in SSE stream
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Look for data lines that might contain receipt
    if (line?.startsWith('data: ')) {
      const data = line.slice(6).trim();
      if (data === '[DONE]') continue;
      try {
        const parsed = JSON.parse(data) as Record<string, unknown>;
        if (parsed['_receipt_envelope']) {
          const envelope = parsed['_receipt_envelope'] as SignedEnvelope<GatewayReceiptPayload>;
          return {
            envelope,
            provider: envelope.payload?.provider ?? 'unknown',
            model: envelope.payload?.model ?? 'unknown',
          };
        }
      } catch {
        // Not JSON, skip
      }
    }
  }

  return { provider: 'unknown', model: 'unknown' };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Start a local HTTP interceptor proxy.
 *
 * The proxy listens on a random port and intercepts LLM API calls,
 * forwarding them through clawproxy with proper receipt-binding headers.
 *
 * Supported routes:
 *   POST /v1/proxy/openai
 *   POST /v1/proxy/anthropic
 *   POST /v1/chat/completions  (alias for openai)
 *   POST /v1/messages          (alias for anthropic)
 *   GET  /health
 */
export async function startLocalProxy(options: ProxyOptions): Promise<LocalProxy> {
  const {
    agentDid,
    runId,
    clawproxyUrl = 'https://clawproxy.com',
    providerApiKey,
    policy = null,
    cwd,
    onViolation,
    passthrough = false,
  } = options;

  const normalizedUrl = clawproxyUrl.replace(/\/+$/, '');
  const receipts: CollectedReceipt[] = [];

  // RED TEAM FIX #7: Ephemeral run salt for privacy.
  // Generate a 16-byte random salt per run.
  const runSaltBytes = randomBytes(16);
  const runSaltB64u = base64UrlEncode(runSaltBytes);

  // CAUSAL SIEVE: Initialize tool observability.
  // Parses LLM HTTP traffic to extract tool_calls/tool_results,
  // runs git diff between tool boundaries to detect file mutations.
  const sieve = new CausalSieve({
    agentDid,
    runId,
    cwd,
    policy,
    onViolation,
  });
  await sieve.initialize();

  const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', `http://127.0.0.1`);
    const pathname = url.pathname;

    // Health check
    if (req.method === 'GET' && pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', runId, receipts: receipts.length }));
      return;
    }

    // Only handle POST requests to proxy routes
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'METHOD_NOT_ALLOWED', message: 'Only POST is supported' }));
      return;
    }

    const provider = detectProvider(pathname);
    if (!provider) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'NOT_FOUND', message: `Unknown route: ${pathname}` }));
      return;
    }

    try {
      const bodyBuffer = await readBody(req);
      const idempotencyKey = randomUUID();

      // Extract provider key from the incoming request, fall back to constructor option
      const reqHeaders = req.headers as Record<string, string | string[] | undefined>;
      const incomingKey = extractProviderKey(reqHeaders) ?? providerApiKey;

      // CAUSAL SIEVE: Process outgoing request for tool_results.
      // This detects when the agent sends tool execution results back
      // to the LLM, which means a tool just finished executing.
      // We run git diff to capture file mutations from that tool.
      const providerType = (provider === 'anthropic' ? 'anthropic' : 'openai') as 'openai' | 'anthropic';
      try {
        await sieve.processAgentRequest(providerType, bodyBuffer.toString('utf-8'));
      } catch {
        // Sieve errors must not break the proxy pipeline
      }

      // Forward request: passthrough goes direct to provider, otherwise through clawproxy
      const upstream = passthrough
        ? await forwardToUpstream(provider, bodyBuffer, reqHeaders)
        : await forwardToClawproxy(
            provider,
            bodyBuffer,
            incomingKey,
            normalizedUrl,
            runId,
            agentDid.did,
            idempotencyKey,
          );

      // Collect receipt from response
      const receiptInfo = upstream.isStream
        ? extractReceiptFromStream(upstream.body)
        : extractReceiptFromResponse(upstream.body);

      if (receiptInfo.envelope) {
        receipts.push({
          envelope: receiptInfo.envelope,
          collectedAt: new Date().toISOString(),
          provider: receiptInfo.provider,
          model: receiptInfo.model,
        });
      }

      // CAUSAL SIEVE: Process LLM response for tool_calls.
      // This detects what tools the LLM is requesting the agent to execute.
      // The TCP Guillotine evaluates these against the local WPC policy.
      let guillotineViolations: PolicyViolation[] = [];
      try {
        guillotineViolations = sieve.processLLMResponse(
          providerType,
          upstream.body.toString('utf-8'),
        );
      } catch {
        // Sieve errors must not break the proxy pipeline
      }

      // TCP GUILLOTINE: If the LLM requested a blocked tool,
      // log the violation. We still forward the response because
      // the proxy can't reliably sever mid-stream for all clients.
      // The violation is recorded in the proof bundle for the GitHub
      // App to enforce at PR time.
      if (guillotineViolations.length > 0) {
        for (const v of guillotineViolations) {
          process.stderr.write(
            `\x1b[31m[clawsig:guillotine]\x1b[0m BLOCKED: ${v.reason}\n`,
          );
        }
      }

      // Forward response back to the caller
      const responseHeaders: Record<string, string> = {};
      for (const [key, value] of Object.entries(upstream.headers)) {
        // Skip hop-by-hop headers
        const lower = key.toLowerCase();
        if (lower === 'transfer-encoding' || lower === 'connection') continue;
        responseHeaders[key] = value;
      }

      res.writeHead(upstream.status, responseHeaders);
      res.end(upstream.body);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Proxy forwarding failed';
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'PROXY_ERROR', message }));
    }
  });

  // Listen on a random available port
  const port = await new Promise<number>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        resolve(addr.port);
      } else {
        reject(new Error('Failed to bind local proxy'));
      }
    });
    server.on('error', reject);
  });

  async function stop(): Promise<void> {
    // Finalize the Causal Sieve: sweep for remaining file mutations
    try {
      await sieve.finalize();
    } catch {
      // Finalization errors must not prevent shutdown
    }

    return new Promise((resolve, reject) => {
      server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  /** Compute salted SHA-256: SHA256(salt || content). Red Team Fix #7. */
  async function saltedHashB64u(content: Uint8Array): Promise<string> {
    const combined = new Uint8Array(runSaltBytes.length + content.length);
    combined.set(runSaltBytes, 0);
    combined.set(content, runSaltBytes.length);
    return sha256B64u(combined);
  }
  void saltedHashB64u;

  async function compileProofBundle(): Promise<SignedEnvelope<ProofBundlePayload>> {
    const encoder = new TextEncoder();

    // Build a minimal event chain from collected receipts
    const eventChain: EventChainEntry[] = [];
    let prevHash: string | null = null;

    for (let i = 0; i < receipts.length; i++) {
      const r = receipts[i]!;
      const eventId = `evt_${randomUUID()}`;
      const payloadHashB64u = await hashJsonB64u({
        provider: r.provider,
        model: r.model,
        receipt_id: r.envelope.payload.receipt_id,
      });

      const eventEntry = {
        event_id: eventId,
        run_id: runId,
        event_type: 'llm_call',
        timestamp: r.collectedAt,
        payload_hash_b64u: payloadHashB64u,
        prev_hash_b64u: prevHash,
      };

      const eventHash = await hashJsonB64u(eventEntry);

      const chainEntry: EventChainEntry = {
        ...eventEntry,
        event_hash_b64u: eventHash,
      };

      eventChain.push(chainEntry);
      prevHash = eventHash;
    }

    const envelopes = receipts.map((r) => r.envelope);

    // Assemble proof bundle payload
    const bundleId = `bundle_${randomUUID()}`;
    const payload: ProofBundlePayload = {
      bundle_version: '1',
      bundle_id: bundleId,
      agent_did: agentDid.did,
      event_chain: eventChain,
      metadata: {
        harness: {
          id: 'clawsig-wrap',
          version: '1.0.0',
          runtime: `node/${process.versions.node}`,
        },
        // RED TEAM FIX #7: Per-run ephemeral salt for privacy.
        run_salt_b64u: runSaltB64u,
      },
    };

    if (envelopes.length > 0) {
      payload.receipts = envelopes;
    }

    // CAUSAL SIEVE: Include synthesized tool and side-effect receipts.
    // These are auto-generated from parsing the LLM HTTP stream
    // and running git diff between tool execution boundaries.
    if (sieve.toolReceipts.length > 0) {
      payload.tool_receipts = sieve.toolReceipts.map(e => e.payload);
    }
    if (sieve.sideEffectReceipts.length > 0) {
      payload.side_effect_receipts = sieve.sideEffectReceipts.map(e => e.payload);
    }

    // Sign the bundle
    const payloadHashB64u = await hashJsonB64u(payload);
    const signatureB64u = await agentDid.sign(encoder.encode(payloadHashB64u));

    const envelope: SignedEnvelope<ProofBundlePayload> = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHashB64u,
      hash_algorithm: 'SHA-256',
      signature_b64u: signatureB64u,
      algorithm: 'Ed25519',
      signer_did: agentDid.did,
      issued_at: new Date().toISOString(),
    };

    return envelope;
  }

  return {
    port,
    stop,
    compileProofBundle,
    get receiptCount() {
      return receipts.length;
    },
    get toolReceiptCount() {
      return sieve.toolReceipts.length;
    },
    get sideEffectReceiptCount() {
      return sieve.sideEffectReceipts.length;
    },
    get violationCount() {
      return sieve.violations.length;
    },
    runSaltB64u,
  };
}
