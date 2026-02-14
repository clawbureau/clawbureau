/**
 * Nuclear LLM Call Interception Preload (Node 24 / Undici Dispatcher)
 *
 * Patches THREE layers:
 *   1. undici.Dispatcher.prototype.dispatch() — the chokepoint ALL HTTP flows through in Node 24
 *   2. globalThis.fetch — belt-and-suspenders for direct fetch() calls
 *   3. http/https.request — legacy code path
 *
 * Handles streaming SSE tool_call reassembly across all three LLM providers.
 * Auto-discovers LLM endpoints from env vars.
 * Uses a raw fd for trace output (bypasses own hooks).
 *
 * Loaded via NODE_OPTIONS="--import /path/to/preload.mjs"
 */

import http from 'node:http';
import https from 'node:https';
import cp from 'node:child_process';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { URL, fileURLToPath } from 'node:url';

// ---------------------------------------------------------------------------
// Trace output — uses raw fd to avoid triggering our own fs hooks
// ---------------------------------------------------------------------------
const traceFile = process.env.CLAWSIG_TRACE_FILE;
let traceFd = null;
if (traceFile) {
  try { traceFd = fs.openSync(traceFile, 'a'); } catch { /* skip */ }
}

function emitTrace(payload) {
  if (traceFd === null) return;
  try {
    const line = Buffer.from(
      JSON.stringify({ layer: 'preload', ts: new Date().toISOString(), ...payload }) + '\n',
    );
    fs.writeSync(traceFd, line);
  } catch { /* best effort */ }
}

// ---------------------------------------------------------------------------
// LLM Domain Discovery
// ---------------------------------------------------------------------------
const LLM_DOMAINS = new Set([
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.groq.com',
  'openrouter.ai',
  'api.together.xyz',
  'api.mistral.ai',
  'api.cohere.com',
  'api.deepseek.com',
]);

// Auto-discover endpoints from env
for (const [k, v] of Object.entries(process.env)) {
  if (!v) continue;
  if ((k.endsWith('_BASE_URL') || k.endsWith('_API_BASE')) && v.startsWith('http')) {
    try { LLM_DOMAINS.add(new URL(v).hostname); } catch { /* skip */ }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function hashString(str) {
  return crypto.createHash('sha256').update(str).digest('base64url');
}

function redactHeaders(headers) {
  if (!headers) return {};
  const redacted = {};

  // undici passes headers as a flat [key, value, key, value, ...] Buffer array
  if (Array.isArray(headers)) {
    for (let i = 0; i < headers.length; i += 2) {
      const key = Buffer.isBuffer(headers[i]) ? headers[i].toString('utf8') : String(headers[i]);
      const val = Buffer.isBuffer(headers[i + 1]) ? headers[i + 1].toString('utf8') : String(headers[i + 1]);
      const lk = key.toLowerCase();
      redacted[key] = (lk === 'authorization' || lk.includes('api-key') || lk.includes('api_key'))
        ? '[REDACTED]'
        : val;
    }
    return redacted;
  }

  // Headers object or plain object
  const entries = typeof headers.entries === 'function'
    ? Array.from(headers.entries())
    : Object.entries(headers);
  for (const [key, value] of entries) {
    const lk = key.toLowerCase();
    redacted[key] = (lk === 'authorization' || lk.includes('api-key') || lk.includes('api_key'))
      ? '[REDACTED]'
      : value;
  }
  return redacted;
}

// ---------------------------------------------------------------------------
// SSE Streaming Tool Call Reassembly State Machine
// ---------------------------------------------------------------------------
class SseToolParser {
  constructor() {
    this.buffer = '';
    this.tools = new Map(); // index → { name, args }
  }

  /** Feed a chunk of SSE text (may contain partial lines) */
  push(chunk) {
    this.buffer += chunk;
    const lines = this.buffer.split('\n');
    // Keep the last (possibly partial) line
    this.buffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) continue;
      const data = trimmed.slice(5).trim();
      if (data === '[DONE]' || !data) continue;

      try {
        const parsed = JSON.parse(data);

        // OpenAI: delta.tool_calls with index-based multiplexing
        for (const choice of parsed.choices || []) {
          for (const tc of choice.delta?.tool_calls || []) {
            const idx = tc.index ?? 0;
            if (!this.tools.has(idx)) this.tools.set(idx, { name: '', args: '' });
            const t = this.tools.get(idx);
            if (tc.function?.name) t.name += tc.function.name;
            if (tc.function?.arguments) t.args += tc.function.arguments;
          }
          // Non-streaming: message.tool_calls (complete)
          for (const tc of choice.message?.tool_calls || []) {
            if (tc.function?.name) {
              const idx = tc.index ?? this.tools.size;
              this.tools.set(idx, { name: tc.function.name, args: tc.function.arguments || '{}' });
            }
          }
        }

        // Anthropic: content_block_start + content_block_delta
        if (parsed.type === 'content_block_start' && parsed.content_block?.type === 'tool_use') {
          const idx = parsed.index ?? this.tools.size;
          this.tools.set(idx, { name: parsed.content_block.name || '', args: '' });
        } else if (parsed.type === 'content_block_delta' && parsed.delta?.type === 'input_json_delta') {
          const idx = parsed.index ?? 0;
          if (this.tools.has(idx)) {
            this.tools.get(idx).args += parsed.delta.partial_json || '';
          }
        }

        // Gemini: complete functionCall in each candidate
        for (const candidate of parsed.candidates || []) {
          for (const part of candidate.content?.parts || []) {
            if (part.functionCall?.name) {
              const idx = this.tools.size;
              this.tools.set(idx, {
                name: part.functionCall.name,
                args: JSON.stringify(part.functionCall.args || {}),
              });
            }
          }
        }
      } catch { /* skip partial/invalid JSON */ }
    }
  }

  /** Extract all completed tool calls */
  finalize() {
    // Flush any remaining buffer
    if (this.buffer.trim()) {
      this.push('\n');
    }
    const extracted = [];
    for (const t of this.tools.values()) {
      if (t.name) extracted.push({ name: t.name, args: t.args || '{}' });
    }
    return extracted;
  }
}

/** Also handle non-streaming JSON responses */
function extractToolCallsFromJson(body) {
  const tools = [];
  try {
    const parsed = JSON.parse(body);
    // OpenAI
    for (const c of parsed.choices || []) {
      for (const tc of c.message?.tool_calls || []) {
        if (tc.function?.name) tools.push({ name: tc.function.name, args: tc.function.arguments || '{}' });
      }
    }
    // Anthropic
    for (const c of parsed.content || []) {
      if (c.type === 'tool_use' && c.name) {
        tools.push({ name: c.name, args: JSON.stringify(c.input || {}) });
      }
    }
    // Gemini
    for (const c of parsed.candidates || []) {
      for (const part of c.content?.parts || []) {
        if (part.functionCall?.name) {
          tools.push({ name: part.functionCall.name, args: JSON.stringify(part.functionCall.args || {}) });
        }
      }
    }
  } catch { /* skip */ }
  return tools;
}

function isLlmDomain(hostname) {
  return hostname && LLM_DOMAINS.has(hostname);
}

// ---------------------------------------------------------------------------
// LAYER 1: Undici Dispatcher (Node 24 core HTTP path)
// ---------------------------------------------------------------------------
async function patchUndici() {
  let undici;
  try {
    undici = await import('undici');
  } catch {
    return; // undici not available (Node < 18)
  }
  if (!undici?.Dispatcher?.prototype?.dispatch) return;

  const origDispatch = undici.Dispatcher.prototype.dispatch;

  undici.Dispatcher.prototype.dispatch = function patchedDispatch(opts, handler) {
    let hostname;
    try {
      if (typeof opts.origin === 'string') {
        hostname = new URL(opts.origin).hostname;
      } else if (opts.origin && typeof opts.origin === 'object') {
        hostname = opts.origin.hostname;
      }
    } catch {
      return origDispatch.call(this, opts, handler);
    }

    if (!isLlmDomain(hostname)) {
      return origDispatch.call(this, opts, handler);
    }

    // Extract request body
    let reqBodyStr = '';
    if (typeof opts.body === 'string') {
      reqBodyStr = opts.body;
    } else if (Buffer.isBuffer(opts.body)) {
      reqBodyStr = opts.body.toString('utf8');
    }

    let model = 'unknown';
    try { model = JSON.parse(reqBodyStr).model || 'unknown'; } catch { /* skip */ }

    const url = `${opts.origin}${opts.path}`;

    emitTrace({
      type: 'llm_request',
      url,
      method: opts.method,
      headers: redactHeaders(opts.headers),
      model,
      messages_hash: reqBodyStr ? hashString(reqBodyStr) : '',
    });

    // Wrap the handler to intercept response
    const parser = new SseToolParser();
    const origOnHeaders = handler.onHeaders;
    const origOnData = handler.onData;
    const origOnComplete = handler.onComplete;
    const origOnError = handler.onError;

    const wrappedHandler = Object.create(handler);

    wrappedHandler.onHeaders = function (statusCode, headers, resume, statusMessage) {
      try {
        emitTrace({ type: 'llm_response_status', url, status: statusCode });
      } catch { /* skip */ }
      if (origOnHeaders) return origOnHeaders.call(handler, statusCode, headers, resume, statusMessage);
      return true;
    };

    wrappedHandler.onData = function (chunk) {
      try {
        parser.push(chunk.toString('utf8'));
      } catch { /* skip */ }
      if (origOnData) return origOnData.call(handler, chunk);
      return true;
    };

    wrappedHandler.onComplete = function (trailers) {
      try {
        const tools = parser.finalize();
        for (const tc of tools) {
          emitTrace({ type: 'tool_call', tool_name: tc.name, args_hash: hashString(tc.args) });
        }
      } catch { /* skip */ }
      if (origOnComplete) return origOnComplete.call(handler, trailers);
    };

    wrappedHandler.onError = function (err) {
      if (origOnError) return origOnError.call(handler, err);
    };

    return origDispatch.call(this, opts, wrappedHandler);
  };
}

// Fire and forget — don't block module loading
patchUndici().catch(() => {});

// ---------------------------------------------------------------------------
// LAYER 2: globalThis.fetch (belt-and-suspenders)
// ---------------------------------------------------------------------------
if (typeof globalThis.fetch === 'function') {
  const origFetch = globalThis.fetch;

  globalThis.fetch = async function clawsigFetch(input, init) {
    let urlStr = '';
    let method = 'GET';
    let headers = {};

    if (typeof input === 'string') {
      urlStr = input;
    } else if (input instanceof URL) {
      urlStr = input.toString();
    } else if (input instanceof Request) {
      urlStr = input.url;
      method = input.method;
      input.headers.forEach((v, k) => { headers[k] = v; });
    }
    if (init) {
      method = init.method || method;
      if (init.headers) headers = init.headers;
    }

    let hostname;
    try { hostname = new URL(urlStr).hostname; } catch { return origFetch.apply(this, arguments); }

    if (!isLlmDomain(hostname)) {
      return origFetch.apply(this, arguments);
    }

    // Extract request body
    let reqBody = '';
    if (init?.body && typeof init.body === 'string') {
      reqBody = init.body;
    } else if (input instanceof Request && !input.bodyUsed) {
      try { reqBody = await input.clone().text(); } catch { /* skip */ }
    }

    let model = 'unknown';
    try { model = JSON.parse(reqBody).model || 'unknown'; } catch { /* skip */ }

    emitTrace({
      type: 'llm_request',
      url: urlStr,
      method,
      headers: redactHeaders(headers),
      model,
      messages_hash: reqBody ? hashString(reqBody) : '',
    });

    const res = await origFetch.apply(this, arguments);

    // Tee the body stream to capture tool calls without breaking the caller
    if (res.body && typeof res.body.tee === 'function') {
      try {
        const [stream1, stream2] = res.body.tee();
        const parser = new SseToolParser();
        const decoder = new TextDecoder('utf-8');

        // Consume the tee'd stream in the background
        (async () => {
          try {
            const reader = stream2.getReader();
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              if (value) parser.push(decoder.decode(value, { stream: true }));
            }
            const tools = parser.finalize();
            for (const tc of tools) {
              emitTrace({ type: 'tool_call', tool_name: tc.name, args_hash: hashString(tc.args) });
            }
          } catch { /* skip */ }
        })();

        return new Response(stream1, {
          status: res.status,
          statusText: res.statusText,
          headers: res.headers,
        });
      } catch {
        return res; // Tee failed, return original
      }
    }

    return res;
  };
}

// ---------------------------------------------------------------------------
// LAYER 3: Legacy http/https.request
// ---------------------------------------------------------------------------
function patchHttp(mod, defaultProtocol) {
  const origRequest = mod.request;

  mod.request = function clawsigHttpRequest(...args) {
    let urlStr = '';
    let options = {};
    if (typeof args[0] === 'string' || args[0] instanceof URL) {
      urlStr = args[0].toString();
      options = args[1] || {};
    } else {
      options = args[0] || {};
      const protocol = options.protocol || defaultProtocol;
      const host = options.hostname || options.host || 'localhost';
      const path = options.path || '/';
      urlStr = `${protocol}//${host}${path}`;
    }

    let hostname;
    try { hostname = new URL(urlStr).hostname; } catch { return origRequest.apply(this, args); }
    if (!isLlmDomain(hostname)) return origRequest.apply(this, args);

    const req = origRequest.apply(this, args);
    const reqHeaders = typeof req.getHeaders === 'function' ? req.getHeaders() : (options.headers || {});
    const reqBodyChunks = [];

    const origWrite = req.write;
    const origEnd = req.end;

    req.write = function (chunk) {
      if (chunk) reqBodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      return origWrite.apply(this, arguments);
    };

    req.end = function (chunk) {
      if (chunk && typeof chunk !== 'function') {
        reqBodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      }
      return origEnd.apply(this, arguments);
    };

    req.on('response', (res) => {
      const parser = new SseToolParser();
      let isStreaming = false;
      const jsonChunks = [];

      res.on('data', (chunk) => {
        const str = Buffer.from(chunk).toString('utf8');
        if (str.includes('data:') || isStreaming) {
          isStreaming = true;
          parser.push(str);
        } else {
          jsonChunks.push(str);
        }
      });

      res.on('end', () => {
        try {
          const reqBody = Buffer.concat(reqBodyChunks).toString('utf8');
          let model = 'unknown';
          try { model = JSON.parse(reqBody).model || 'unknown'; } catch { /* skip */ }

          emitTrace({
            type: 'llm_request',
            url: urlStr,
            method: options.method || 'GET',
            headers: redactHeaders(reqHeaders),
            status: res.statusCode,
            model,
            messages_hash: reqBody ? hashString(reqBody) : '',
          });

          let tools;
          if (isStreaming) {
            tools = parser.finalize();
          } else {
            tools = extractToolCallsFromJson(jsonChunks.join(''));
          }
          for (const tc of tools) {
            emitTrace({ type: 'tool_call', tool_name: tc.name, args_hash: hashString(tc.args) });
          }
        } catch { /* skip */ }
      });
    });

    return req;
  };

  const origGet = mod.get;
  mod.get = function clawsigHttpGet(...args) {
    const req = mod.request.apply(this, args);
    req.end();
    return req;
  };
}

patchHttp(http, 'http:');
patchHttp(https, 'https:');

// ---------------------------------------------------------------------------
// LAYER 4: Propagate NODE_OPTIONS to ALL child processes
// ---------------------------------------------------------------------------
const origCpSpawn = cp.ChildProcess.prototype.spawn;
cp.ChildProcess.prototype.spawn = function clawsigCpSpawn(options) {
  if (options?.envPairs) {
    let myPath = import.meta.url;
    if (myPath.startsWith('file://')) myPath = fileURLToPath(myPath);
    const sentinelPath = myPath.replace(/preload\.mjs$/, 'node-preload-sentinel.mjs');

    const importPreload = `--import ${myPath}`;
    const importSentinel = `--import ${sentinelPath}`;

    let hasNodeOptions = false;
    let hasTraceFile = false;

    for (let i = 0; i < options.envPairs.length; i++) {
      const pair = options.envPairs[i];
      if (pair.startsWith('NODE_OPTIONS=')) {
        hasNodeOptions = true;
        let newPair = pair;
        if (!pair.includes('preload.mjs')) newPair += ` ${importPreload}`;
        if (!pair.includes('node-preload-sentinel.mjs')) newPair += ` ${importSentinel}`;
        options.envPairs[i] = newPair;
      }
      if (pair.startsWith('CLAWSIG_TRACE_FILE=')) hasTraceFile = true;
    }

    if (!hasNodeOptions) {
      options.envPairs.push(`NODE_OPTIONS=${importPreload} ${importSentinel}`);
    }
    if (!hasTraceFile && traceFile) {
      options.envPairs.push(`CLAWSIG_TRACE_FILE=${traceFile}`);
    }
  }
  return origCpSpawn.apply(this, arguments);
};
