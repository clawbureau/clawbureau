import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import plugin from '../dist/openclaw.js';

function b64u(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function b64uJson(obj) {
  return b64u(JSON.stringify(obj));
}

async function main() {
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'clawproof-openclaw-plugin-'));
  const stateDir = path.join(tmpRoot, 'state');

  const storedByNonce = new Map();
  let receiptLookupHits = 0;
  let lastHeaders = null;

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1');

      if (req.method === 'GET' && url.pathname.startsWith('/v1/receipt/')) {
        receiptLookupHits++;

        const nonce = decodeURIComponent(url.pathname.slice('/v1/receipt/'.length));
        const stored = storedByNonce.get(nonce);

        if (!stored) {
          res.statusCode = 404;
          res.setHeader('content-type', 'application/json; charset=utf-8');
          res.end(JSON.stringify({ ok: false, error: 'RECEIPT_NOT_FOUND' }));
          return;
        }

        const expectedRunId = url.searchParams.get('run_id') ?? '';
        const expectedEventHash = url.searchParams.get('event_hash_b64u') ?? '';

        const binding = stored?._receipt_envelope?.payload?.binding ?? {};

        if (expectedRunId && binding.run_id !== expectedRunId) {
          res.statusCode = 409;
          res.setHeader('content-type', 'application/json; charset=utf-8');
          res.end(JSON.stringify({ ok: false, error: 'RECEIPT_BINDING_MISMATCH' }));
          return;
        }

        if (expectedEventHash && binding.event_hash_b64u !== expectedEventHash) {
          res.statusCode = 409;
          res.setHeader('content-type', 'application/json; charset=utf-8');
          res.end(JSON.stringify({ ok: false, error: 'RECEIPT_BINDING_MISMATCH' }));
          return;
        }

        res.statusCode = 200;
        res.setHeader('content-type', 'application/json; charset=utf-8');
        res.end(
          JSON.stringify({
            ok: true,
            nonce,
            status: 200,
            truncated: false,
            receipt_envelope: stored._receipt_envelope,
            receipt: stored._receipt,
          }),
        );
        return;
      }

      if (req.method !== 'POST' || url.pathname !== '/v1/proxy/openai') {
        res.statusCode = 404;
        res.end('not found');
        return;
      }

      const chunks = [];
      for await (const c of req) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
      const bodyText = Buffer.concat(chunks).toString('utf8');
      const body = JSON.parse(bodyText);

      const runId = req.headers['x-run-id'];
      const eventHash = req.headers['x-event-hash'];
      const nonce = req.headers['x-idempotency-key'];
      const providerKey = req.headers['x-provider-api-key'];
      const openaiApi = req.headers['x-openai-api'];

      lastHeaders = {
        runId,
        eventHash,
        nonce,
        providerKey,
        openaiApi,
        accept: req.headers['accept'],
      };

      assert.equal(typeof runId, 'string');
      assert.equal(typeof eventHash, 'string');
      assert.equal(typeof nonce, 'string');
      assert.equal(providerKey, 'sk-test');

      const now = new Date().toISOString();

      const legacyReceipt = {
        version: '1.0',
        provider: 'openai',
        model: body.model ?? 'unknown',
        requestHash: '0x' + '00'.repeat(32),
        responseHash: '0x' + '11'.repeat(32),
        timestamp: now,
        latencyMs: 1,
        binding: {
          runId,
          eventHash,
          nonce,
        },
      };

      const envelopePayload = {
        receipt_version: '1',
        receipt_id: 'rcpt_test',
        gateway_id: 'clawproxy_test',
        provider: 'openai',
        model: body.model ?? 'unknown',
        request_hash_b64u: 'AAAAAAAAAAAA',
        response_hash_b64u: 'BBBBBBBBBBBB',
        tokens_input: 0,
        tokens_output: 0,
        latency_ms: 1,
        timestamp: now,
        binding: {
          run_id: runId,
          event_hash_b64u: eventHash,
          nonce,
        },
      };

      const envelope = {
        envelope_version: '1',
        envelope_type: 'gateway_receipt',
        payload: envelopePayload,
        payload_hash_b64u: 'CCCCCCCCCCCC',
        hash_algorithm: 'SHA-256',
        signature_b64u: 'DDDDDDDDDDDD',
        algorithm: 'Ed25519',
        signer_did: 'did:key:zFake',
        issued_at: now,
      };

      // Idempotency replay support (simulate DO): if Accept JSON and we have stored, return stored body.
      const accept = String(req.headers['accept'] ?? '').toLowerCase();
      if (accept.includes('application/json') && storedByNonce.has(nonce)) {
        res.statusCode = 200;
        res.setHeader('content-type', 'application/json; charset=utf-8');
        res.end(JSON.stringify(storedByNonce.get(nonce)));
        return;
      }

      const isStreaming = body.stream === true || accept.includes('text/event-stream');

      if (isStreaming) {
        const stored = { streaming: true, _receipt: legacyReceipt, _receipt_envelope: envelope };
        storedByNonce.set(nonce, stored);

        const omitTrailer = body.noTrailer === true;

        res.statusCode = 200;
        res.setHeader('content-type', 'text/event-stream; charset=utf-8');

        res.write(`data: {"ok":true}\n\n`);
        res.write(`data: [DONE]\n\n`);

        if (!omitTrailer) {
          // Append clawproxy-style trailer comments.
          const trailer =
            `:clawproxy_receipt_envelope_b64u=${b64uJson(envelope)}\n` +
            `:clawproxy_receipt_b64u=${b64uJson(legacyReceipt)}\n\n`;
          res.end(trailer);
        } else {
          res.end();
        }
        return;
      }

      const responseBody = {
        id: 'chatcmpl_test',
        object: 'chat.completion',
        choices: [{ index: 0, message: { role: 'assistant', content: 'hello' }, finish_reason: 'stop' }],
        _receipt: legacyReceipt,
        _receipt_envelope: envelope,
      };

      res.statusCode = 200;
      res.setHeader('content-type', 'application/json; charset=utf-8');
      res.end(JSON.stringify(responseBody));
    } catch (err) {
      res.statusCode = 500;
      res.setHeader('content-type', 'text/plain; charset=utf-8');
      res.end(String(err));
    }
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const addr = server.address();
  assert.ok(addr && typeof addr === 'object');
  const port = addr.port;
  const proxyBaseUrl = `http://127.0.0.1:${port}`;

  const internalHooks = new Map();
  const hooks = new Map();

  const api = {
    id: 'provider-clawproxy',
    version: '0.1.0-test',
    pluginConfig: {
      baseUrl: proxyBaseUrl,
      mode: 'enforce',
      outputDir: path.join('.clawproof', 'openclaw'),
      keyFile: path.join(stateDir, 'agent-key.jwk.json'),
      intercept: { openai: true, anthropic: false, google: false },
      includePromptPack: true,
      includeToolEvents: true,
    },
    config: {},
    runtime: {
      version: 'openclaw-test',
      state: {
        resolveStateDir: () => stateDir,
      },
    },
    logger: {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {},
    },
    resolvePath: (input) => input,
    registerHook: (events, handler) => {
      internalHooks.set(events, handler);
    },
    on: (hookName, handler) => {
      hooks.set(hookName, handler);
    },
  };

  plugin.register(api);

  // --- Non-stream run ---
  {
    const workspaceDir = path.join(tmpRoot, 'ws-nonstream');
    const sessionKey = 'agent:main:test:1';

    const bootstrapHandler = internalHooks.get('agent:bootstrap');
    assert.equal(typeof bootstrapHandler, 'function');

    await bootstrapHandler({
      type: 'agent',
      action: 'bootstrap',
      sessionKey,
      context: {
        sessionKey,
        workspaceDir,
        bootstrapFiles: [{ name: 'AGENTS.md', content: 'hello bootstrap' }],
      },
      timestamp: new Date(),
      messages: [],
    });

    const beforeAgentStart = hooks.get('before_agent_start');
    assert.equal(typeof beforeAgentStart, 'function');

    await beforeAgentStart(
      { prompt: 'do the thing', messages: [] },
      { agentId: 'main', sessionKey, workspaceDir },
    );

    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        authorization: 'Bearer sk-test',
      },
      body: JSON.stringify({
        model: 'gpt-test',
        messages: [{ role: 'system', content: 'SYS_PROMPT' }, { role: 'user', content: 'hi' }],
      }),
    });

    assert.equal(res.status, 200);
    const json = await res.json();
    assert.ok(json && typeof json === 'object');
    assert.ok('choices' in json);
    assert.ok(!('_receipt' in json));
    assert.ok(!('_receipt_envelope' in json));

    const agentEnd = hooks.get('agent_end');
    assert.equal(typeof agentEnd, 'function');

    await agentEnd(
      { messages: [], success: true, durationMs: 5 },
      { agentId: 'main', sessionKey, workspaceDir },
    );

    const outDir = path.join(workspaceDir, '.clawproof', 'openclaw');
    const files = await readdir(outDir);
    const bundle = files.find((f) => f.endsWith('-bundle.json'));
    assert.ok(bundle, `expected bundle.json in ${outDir}`);

    const envelope = JSON.parse(await readFile(path.join(outDir, bundle), 'utf8'));
    assert.equal(envelope.envelope_type, 'proof_bundle');

    const md = envelope.payload?.metadata;
    assert.ok(md?.prompt_pack, 'expected prompt_pack');
    assert.ok(md?.system_prompt_report, 'expected system_prompt_report');

    assert.ok(Array.isArray(envelope.payload?.receipts) && envelope.payload.receipts.length >= 1);
    assert.equal(lastHeaders?.openaiApi, 'chat_completions');
  }

  // --- Non-stream OpenAI Responses API run ---
  {
    const workspaceDir = path.join(tmpRoot, 'ws-responses');
    const sessionKey = 'agent:main:test:3';

    const bootstrapHandler = internalHooks.get('agent:bootstrap');
    await bootstrapHandler({
      type: 'agent',
      action: 'bootstrap',
      sessionKey,
      context: {
        sessionKey,
        workspaceDir,
        bootstrapFiles: [{ name: 'AGENTS.md', content: 'hello bootstrap 3' }],
      },
      timestamp: new Date(),
      messages: [],
    });

    const beforeAgentStart = hooks.get('before_agent_start');
    await beforeAgentStart(
      { prompt: 'responses', messages: [] },
      { agentId: 'main', sessionKey, workspaceDir },
    );

    const res = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        authorization: 'Bearer sk-test',
      },
      body: JSON.stringify({
        model: 'gpt-test',
        instructions: 'SYS_PROMPT_RESP',
        input: [{ role: 'user', content: 'hi' }],
      }),
    });

    assert.equal(res.status, 200);
    const json = await res.json();
    assert.ok(json && typeof json === 'object');
    assert.ok(!('_receipt' in json));
    assert.ok(!('_receipt_envelope' in json));

    assert.equal(lastHeaders?.openaiApi, 'responses');

    const agentEnd = hooks.get('agent_end');
    await agentEnd(
      { messages: [], success: true, durationMs: 5 },
      { agentId: 'main', sessionKey, workspaceDir },
    );

    const outDir = path.join(workspaceDir, '.clawproof', 'openclaw');
    const files = await readdir(outDir);
    const bundle = files.find((f) => f.endsWith('-bundle.json'));
    assert.ok(bundle);

    const envelope = JSON.parse(await readFile(path.join(outDir, bundle), 'utf8'));
    const md = envelope.payload?.metadata;
    assert.ok(md?.system_prompt_report, 'expected system_prompt_report for responses run');
    assert.ok(Array.isArray(envelope.payload?.receipts) && envelope.payload.receipts.length >= 1);
  }

  // --- Streaming run (cancel early; receipts must still be captured) ---
  {
    const workspaceDir = path.join(tmpRoot, 'ws-stream');
    const sessionKey = 'agent:main:test:2';

    const bootstrapHandler = internalHooks.get('agent:bootstrap');
    await bootstrapHandler({
      type: 'agent',
      action: 'bootstrap',
      sessionKey,
      context: {
        sessionKey,
        workspaceDir,
        bootstrapFiles: [{ name: 'AGENTS.md', content: 'hello bootstrap 2' }],
      },
      timestamp: new Date(),
      messages: [],
    });

    const beforeAgentStart = hooks.get('before_agent_start');
    await beforeAgentStart(
      { prompt: 'stream', messages: [] },
      { agentId: 'main', sessionKey, workspaceDir },
    );

    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        authorization: 'Bearer sk-test',
        accept: 'text/event-stream',
      },
      body: JSON.stringify({
        model: 'gpt-test',
        stream: true,
        messages: [{ role: 'system', content: 'SYS_PROMPT_STREAM' }, { role: 'user', content: 'hi' }],
      }),
    });

    assert.equal(res.status, 200);
    assert.ok(res.body);

    // Read one chunk and cancel.
    const reader = res.body.getReader();
    await reader.read();
    await reader.cancel();

    const agentEnd = hooks.get('agent_end');
    await agentEnd(
      { messages: [], success: true, durationMs: 5 },
      { agentId: 'main', sessionKey, workspaceDir },
    );

    const outDir = path.join(workspaceDir, '.clawproof', 'openclaw');
    const files = await readdir(outDir);
    const bundle = files.find((f) => f.endsWith('-bundle.json'));
    assert.ok(bundle);

    const envelope = JSON.parse(await readFile(path.join(outDir, bundle), 'utf8'));
    assert.ok(Array.isArray(envelope.payload?.receipts) && envelope.payload.receipts.length >= 1);
  }

  // --- Streaming run without trailers (receipt lookup fallback) ---
  {
    const workspaceDir = path.join(tmpRoot, 'ws-stream-lookup');
    const sessionKey = 'agent:main:test:4';

    const bootstrapHandler = internalHooks.get('agent:bootstrap');
    await bootstrapHandler({
      type: 'agent',
      action: 'bootstrap',
      sessionKey,
      context: {
        sessionKey,
        workspaceDir,
        bootstrapFiles: [{ name: 'AGENTS.md', content: 'hello bootstrap 4' }],
      },
      timestamp: new Date(),
      messages: [],
    });

    const beforeAgentStart = hooks.get('before_agent_start');
    await beforeAgentStart(
      { prompt: 'stream lookup', messages: [] },
      { agentId: 'main', sessionKey, workspaceDir },
    );

    const beforeHits = receiptLookupHits;

    const res = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        authorization: 'Bearer sk-test',
        accept: 'text/event-stream',
      },
      body: JSON.stringify({
        model: 'gpt-test',
        stream: true,
        noTrailer: true,
        messages: [{ role: 'system', content: 'SYS_PROMPT_STREAM_LOOKUP' }, { role: 'user', content: 'hi' }],
      }),
    });

    assert.equal(res.status, 200);
    assert.ok(res.body);

    // Read one chunk and cancel.
    const reader = res.body.getReader();
    await reader.read();
    await reader.cancel();

    const agentEnd = hooks.get('agent_end');
    await agentEnd(
      { messages: [], success: true, durationMs: 5 },
      { agentId: 'main', sessionKey, workspaceDir },
    );

    assert.ok(receiptLookupHits > beforeHits, 'expected GET /v1/receipt/:nonce lookup');

    const outDir = path.join(workspaceDir, '.clawproof', 'openclaw');
    const files = await readdir(outDir);
    const bundle = files.find((f) => f.endsWith('-bundle.json'));
    assert.ok(bundle);

    const envelope = JSON.parse(await readFile(path.join(outDir, bundle), 'utf8'));
    assert.ok(Array.isArray(envelope.payload?.receipts) && envelope.payload.receipts.length >= 1);
  }

  server.close();
  await once(server, 'close');

  await rm(tmpRoot, { recursive: true, force: true });

  console.log('smoke-openclaw-plugin: OK');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
