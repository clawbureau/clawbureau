import { afterEach, describe, expect, it } from 'vitest';

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { once } from 'node:events';

import { createSession } from '../src/session';
import { startShim } from '../src/shim';
import { base64UrlEncode, didFromPublicKey, generateKeyPair, hashJsonB64u } from '../src/crypto';

function b64uJson(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  return base64UrlEncode(bytes);
}

async function listen(server: Server): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');

  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('unexpected listen address');
  }

  const baseUrl = `http://127.0.0.1:${addr.port}`;

  return {
    baseUrl,
    close: async () => {
      server.close();
      await once(server, 'close');
    },
  };
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(body));
}

function sendSse(res: ServerResponse, chunks: string[]): void {
  res.statusCode = 200;
  res.setHeader('content-type', 'text/event-stream; charset=utf-8');
  for (const c of chunks) res.write(c);
  res.end();
}

function makeMockClawproxy(options: { includeTrailer: boolean }): Server {
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

    if (req.method !== 'POST' || url.pathname !== '/v1/proxy/openai') {
      sendJson(res, 404, { error: 'NOT_FOUND' });
      return;
    }

    const accept = String(req.headers['accept'] ?? '');

    // Build deterministic (but fake) receipt objects.
    const binding = {
      runId: String(req.headers['x-run-id'] ?? ''),
      eventHash: String(req.headers['x-event-hash'] ?? ''),
      nonce: String(req.headers['x-idempotency-key'] ?? ''),
    };

    const receipt = {
      version: '1.0',
      provider: 'openai',
      model: 'gpt-test',
      requestHash: '0'.repeat(64),
      responseHash: '1'.repeat(64),
      timestamp: new Date().toISOString(),
      latencyMs: 1,
      proxyDid: 'did:web:clawproxy.com',
      kid: 'kid_test',
      signature: 'sig_test',
      binding,
      privacyMode: 'hash_only',
    };

    const receiptEnvelope = {
      envelope_version: '1',
      envelope_type: 'gateway_receipt',
      payload: {
        receipt_version: '1',
        receipt_id: 'rcpt_test',
        gateway_id: 'did:web:clawproxy.com',
        provider: 'openai',
        model: 'gpt-test',
        request_hash_b64u: 'req_hash',
        response_hash_b64u: 'res_hash',
        tokens_input: 0,
        tokens_output: 0,
        latency_ms: 1,
        timestamp: receipt.timestamp,
        binding: {
          run_id: binding.runId,
          event_hash_b64u: binding.eventHash,
          nonce: binding.nonce,
        },
      },
      payload_hash_b64u: 'payload_hash',
      hash_algorithm: 'SHA-256',
      signature_b64u: 'sig_b64u',
      algorithm: 'Ed25519',
      signer_did: 'did:key:zMock',
      issued_at: receipt.timestamp,
    };

    // Replay path (shim fallback): return a compact JSON response with receipts.
    if (accept.toLowerCase().includes('application/json')) {
      sendJson(res, 200, {
        streaming: true,
        _receipt: receipt,
        _receipt_envelope: receiptEnvelope,
      });
      return;
    }

    // Streaming path: SSE response.
    const sse: string[] = [
      'data: {"id":"chunk_1"}\n\n',
      'data: [DONE]\n\n',
    ];

    if (options.includeTrailer) {
      sse.push(
        `:clawproxy_receipt_envelope_b64u=${b64uJson(receiptEnvelope)}\n` +
          `:clawproxy_receipt_b64u=${b64uJson(receipt)}\n\n`,
      );
    }

    sendSse(res, sse);

    // Ensure we actually consume the request body (avoid hanging clients waiting for backpressure).
    await readBody(req).catch(() => undefined);
  });
}

async function makeSession(proxyBaseUrl: string) {
  const keyPair = await generateKeyPair();
  const agentDid = await didFromPublicKey(keyPair.publicKey);

  const session = await createSession({
    proxyBaseUrl,
    proxyToken: undefined,
    keyPair,
    agentDid,
    harness: { id: 'test-harness', version: '0.0.0', runtime: 'node' },
    outputDir: '.clawproof-test',
  });

  return { session, agentDid };
}

describe('POH-US-019: shim streaming/SSE support', () => {
  const toClose: Array<() => Promise<void>> = [];

  afterEach(async () => {
    while (toClose.length > 0) {
      const close = toClose.pop();
      if (close) await close();
    }
  });

  it('captures receipts from SSE trailer comments and strips them from the harness stream', async () => {
    const mock = makeMockClawproxy({ includeTrailer: true });
    const mockListen = await listen(mock);
    toClose.push(mockListen.close);

    const { session } = await makeSession(mockListen.baseUrl);
    const shim = await startShim({ session });
    toClose.push(shim.close);

    const res = await fetch(`${shim.baseUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        accept: 'text/event-stream',
        authorization: 'Bearer sk-test',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-test',
        stream: true,
        messages: [{ role: 'user', content: 'hi' }],
      }),
    });

    expect(res.status).toBe(200);
    const text = await res.text();

    // The shim must not leak clawproxy receipt side-channel fields to the harness.
    expect(text).toContain('data: [DONE]');
    expect(text).not.toContain('clawproxy_receipt_envelope_b64u');
    expect(text).not.toContain('clawproxy_receipt_b64u');

    const proof = await session.finalize({
      inputs: [{ type: 'test', hashB64u: await hashJsonB64u('in') }],
      outputs: [{ type: 'test', hashB64u: await hashJsonB64u('out') }],
    });

    expect(proof.envelope.payload.receipts?.length).toBe(1);
    expect(proof.envelope.payload.receipts?.[0]?.envelope_type).toBe('gateway_receipt');
  });

  it('falls back to deterministic idempotency replay when trailers are missing', async () => {
    const mock = makeMockClawproxy({ includeTrailer: false });
    const mockListen = await listen(mock);
    toClose.push(mockListen.close);

    const { session } = await makeSession(mockListen.baseUrl);
    const shim = await startShim({ session });
    toClose.push(shim.close);

    const res = await fetch(`${shim.baseUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        accept: 'text/event-stream',
        authorization: 'Bearer sk-test',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-test',
        stream: true,
        messages: [{ role: 'user', content: 'hi' }],
      }),
    });

    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain('data: [DONE]');

    const proof = await session.finalize({
      inputs: [{ type: 'test', hashB64u: await hashJsonB64u('in') }],
      outputs: [{ type: 'test', hashB64u: await hashJsonB64u('out') }],
    });

    expect(proof.envelope.payload.receipts?.length).toBe(1);
    expect(proof.envelope.payload.receipts?.[0]?.envelope_type).toBe('gateway_receipt');
  });
});
