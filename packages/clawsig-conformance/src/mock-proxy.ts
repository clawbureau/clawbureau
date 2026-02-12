/**
 * Mock LLM Proxy Server
 *
 * Lightweight HTTP server that mimics OpenAI and Anthropic APIs.
 * Returns deterministic canned responses, records all requests,
 * and generates self-signed mock gateway receipts.
 *
 * Self-contained: no external network calls.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import type { RecordedRequest, MockReceipt, MockProxyState } from './types.js';

// -- Deterministic mock signing (self-tier) ----------------------------------

// Fixed mock gateway DID and key material for conformance testing.
// These are NOT real keys; bundles signed with these produce "self" tier.
const MOCK_GATEWAY_ID = 'gw_conformance_mock';
const MOCK_GATEWAY_DID = 'did:key:z6MkConformanceMockGateway000000000000000000000';
const MOCK_SIGNATURE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

// -- Canned LLM responses ----------------------------------------------------

const OPENAI_CHAT_RESPONSE = {
  id: 'chatcmpl-conformance-mock',
  object: 'chat.completion',
  created: Math.floor(Date.now() / 1000),
  model: 'gpt-4-conformance-mock',
  choices: [
    {
      index: 0,
      message: {
        role: 'assistant',
        content: 'Hello, I am a test agent. This is a conformance test response.',
      },
      finish_reason: 'stop',
    },
  ],
  usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 },
};

const ANTHROPIC_MESSAGES_RESPONSE = {
  id: 'msg_conformance_mock',
  type: 'message',
  role: 'assistant',
  content: [
    {
      type: 'text',
      text: 'Hello, I am a test agent. This is a conformance test response.',
    },
  ],
  model: 'claude-conformance-mock',
  stop_reason: 'end_turn',
  usage: { input_tokens: 10, output_tokens: 20 },
};

const OPENAI_MODELS_RESPONSE = {
  object: 'list',
  data: [
    { id: 'gpt-4-conformance-mock', object: 'model', created: 0, owned_by: 'conformance' },
  ],
};

// -- Hash helper (sync, for receipt payloads) ---------------------------------

async function sha256B64u(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(data));
  const bytes = new Uint8Array(hashBuffer);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// -- Mock receipt builder -----------------------------------------------------

async function buildMockReceipt(
  provider: string,
  model: string,
  requestBody: string,
  responseBody: string,
  binding?: { run_id?: string; event_hash_b64u?: string; nonce?: string },
): Promise<MockReceipt> {
  const now = new Date().toISOString();
  const requestHash = await sha256B64u(requestBody);
  const responseHash = await sha256B64u(responseBody);

  const payload = {
    receipt_version: '1' as const,
    receipt_id: `rcpt_mock_${randomUUID().slice(0, 8)}`,
    gateway_id: MOCK_GATEWAY_ID,
    provider,
    model,
    request_hash_b64u: requestHash,
    response_hash_b64u: responseHash,
    tokens_input: 10,
    tokens_output: 20,
    latency_ms: 1,
    timestamp: now,
    ...(binding && Object.keys(binding).length > 0 ? { binding } : {}),
  };

  const payloadHash = await sha256B64u(JSON.stringify(payload));

  return {
    envelope_version: '1',
    envelope_type: 'gateway_receipt',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: MOCK_SIGNATURE,
    algorithm: 'Ed25519',
    signer_did: MOCK_GATEWAY_DID,
    issued_at: now,
  };
}

// -- Request body reader ------------------------------------------------------

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    req.on('error', reject);
  });
}

// -- Route matching -----------------------------------------------------------

function isOpenAIChatRoute(path: string): boolean {
  return /\/v1\/(chat\/completions|proxy\/openai\/chat\/completions)/.test(path);
}

function isOpenAIModelsRoute(path: string): boolean {
  return /\/v1\/(models|proxy\/openai\/models)/.test(path);
}

function isAnthropicRoute(path: string): boolean {
  return /\/(v1\/(messages|proxy\/anthropic\/messages))/.test(path);
}

// -- Server -------------------------------------------------------------------

export interface MockProxyHandle {
  /** The port the server is listening on. */
  port: number;
  /** URL base (e.g., http://127.0.0.1:PORT). */
  baseUrl: string;
  /** Gracefully shut down the server and return recorded state. */
  shutdown(): Promise<MockProxyState>;
}

export async function startMockProxy(port = 0): Promise<MockProxyHandle> {
  const requests: RecordedRequest[] = [];
  const receipts: MockReceipt[] = [];

  const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const method = req.method ?? 'GET';
    const url = req.url ?? '/';

    // Record every request
    const body = method === 'POST' || method === 'PUT' ? await readBody(req) : '';
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (typeof v === 'string') headers[k] = v;
      else if (Array.isArray(v)) headers[k] = v.join(', ');
    }

    let parsedBody: unknown;
    try {
      parsedBody = body ? JSON.parse(body) : null;
    } catch {
      parsedBody = body;
    }

    requests.push({
      method,
      path: url,
      headers,
      body: parsedBody,
      timestamp: new Date().toISOString(),
    });

    // Health check
    if (url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', mode: 'conformance-mock' }));
      return;
    }

    // Extract binding from headers (clawsig protocol headers)
    const binding: { run_id?: string; event_hash_b64u?: string; nonce?: string } = {};
    if (headers['x-run-id']) binding.run_id = headers['x-run-id'];
    if (headers['x-event-hash']) binding.event_hash_b64u = headers['x-event-hash'];
    if (headers['x-idempotency-key']) binding.nonce = headers['x-idempotency-key'];

    // OpenAI chat completions
    if (isOpenAIChatRoute(url) && method === 'POST') {
      const responseJson = JSON.stringify(OPENAI_CHAT_RESPONSE);
      const receipt = await buildMockReceipt(
        'openai', 'gpt-4-conformance-mock', body, responseJson, binding,
      );
      receipts.push(receipt);

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-Clawsig-Receipt': JSON.stringify(receipt),
      });
      res.end(responseJson);
      return;
    }

    // OpenAI models list
    if (isOpenAIModelsRoute(url) && method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(OPENAI_MODELS_RESPONSE));
      return;
    }

    // Anthropic messages
    if (isAnthropicRoute(url) && method === 'POST') {
      const responseJson = JSON.stringify(ANTHROPIC_MESSAGES_RESPONSE);
      const receipt = await buildMockReceipt(
        'anthropic', 'claude-conformance-mock', body, responseJson, binding,
      );
      receipts.push(receipt);

      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-Clawsig-Receipt': JSON.stringify(receipt),
      });
      res.end(responseJson);
      return;
    }

    // Receipt fetch endpoint (for harnesses that poll for receipts)
    if (url.startsWith('/v1/receipt/') && method === 'GET') {
      const nonce = url.split('/v1/receipt/')[1];
      const found = receipts.find(r => r.payload.binding?.nonce === nonce);
      if (found) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(found));
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'receipt_not_found' }));
      }
      return;
    }

    // Catch-all: 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not_found', path: url }));
  });

  // Start listening
  const actualPort = await new Promise<number>((resolve, reject) => {
    server.listen(port, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        resolve(addr.port);
      } else {
        reject(new Error('Failed to bind mock proxy'));
      }
    });
    server.on('error', reject);
  });

  return {
    port: actualPort,
    baseUrl: `http://127.0.0.1:${actualPort}`,
    shutdown: () =>
      new Promise<MockProxyState>((resolve, reject) => {
        server.close((err) => {
          if (err) reject(err);
          else resolve({ requests, receipts, port: actualPort });
        });
      }),
  };
}
