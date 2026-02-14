/**
 * Nuclear LLM Call Interception Preload (Node 24 / Undici + globalThis.fetch)
 *
 * Loaded via NODE_OPTIONS="--import /path/to/preload.mjs"
 *
 * Three interception layers:
 * 1. diagnostics_channel — hooks undici internals, fires for ALL HTTP regardless
 *    of how fetch was obtained. Solves the Anthropic SDK construction-time capture.
 * 2. globalThis.fetch — patches the global fetch for direct callers, captures
 *    request bodies and tees response streams for SSE tool_call extraction.
 * 3. http/https — patches Node's legacy HTTP modules for belt-and-suspenders.
 *
 * All layers write to CLAWSIG_TRACE_FILE as JSONL using raw fd (no re-entrancy).
 */

import http from 'node:http';
import https from 'node:https';
import cp from 'node:child_process';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { URL, fileURLToPath } from 'node:url';
import diagnostics_channel from 'node:diagnostics_channel';

// ---------------------------------------------------------------------------
// Trace file setup — raw fd to avoid re-entrancy with our own hooks
// ---------------------------------------------------------------------------

const traceFile = process.env.CLAWSIG_TRACE_FILE;
let traceFd = null;

if (traceFile) {
  try { traceFd = fs.openSync(traceFile, 'a'); } catch { /* ignore */ }
}

// ---------------------------------------------------------------------------
// LLM domain registry
// ---------------------------------------------------------------------------

const LLM_DOMAINS = new Set([
  'api.openai.com', 'api.anthropic.com', 'generativelanguage.googleapis.com',
  'api.groq.com', 'openrouter.ai', 'api.together.xyz', 'api.mistral.ai',
  'api.cohere.com', 'api.fireworks.ai', 'api.deepseek.com',
]);

// Auto-discover from env vars
for (const [k, v] of Object.entries(process.env)) {
  if (v && (k.endsWith('_BASE_URL') || k.endsWith('_API_BASE')) && v.startsWith('http')) {
    try { LLM_DOMAINS.add(new URL(v).hostname); } catch { /* ignore */ }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emitTrace(payload) {
  if (traceFd === null) return;
  try {
    const line = Buffer.from(JSON.stringify({
      layer: 'preload',
      ts: new Date().toISOString(),
      ...payload,
    }) + '\n');
    fs.writeSync(traceFd, line);
  } catch { /* never throw from instrumentation */ }
}

function hashString(str) {
  if (!str) return '';
  return crypto.createHash('sha256').update(str).digest('base64url');
}

function redactHeaders(headers) {
  if (!headers) return {};
  const redacted = {};

  if (Array.isArray(headers)) {
    for (let i = 0; i < headers.length; i += 2) {
      const key = Buffer.isBuffer(headers[i]) ? headers[i].toString('utf8') : String(headers[i] ?? '');
      const val = Buffer.isBuffer(headers[i + 1]) ? headers[i + 1].toString('utf8') : String(headers[i + 1] ?? '');
      const lk = key.toLowerCase();
      redacted[key] = (lk === 'authorization' || lk.includes('api-key') || lk.includes('api_key')) ? '[REDACTED]' : val;
    }
  } else {
    const entries = typeof headers.entries === 'function' ? Array.from(headers.entries()) : Object.entries(headers || {});
    for (const [key, value] of entries) {
      const lk = String(key).toLowerCase();
      redacted[key] = (lk === 'authorization' || lk.includes('api-key') || lk.includes('api_key')) ? '[REDACTED]' : value;
    }
  }
  return redacted;
}

// ---------------------------------------------------------------------------
// SSE Tool Call State Machine
// Handles OpenAI (index-based delta), Anthropic (content_block_delta),
// and Google (complete functionCall objects).
// ---------------------------------------------------------------------------

class SseToolParser {
  constructor() {
    this.buffer = '';
    this.tools = new Map(); // index → { name, args }
    this.model = 'unknown';
  }

  push(chunk) {
    this.buffer += chunk;
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || '';

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data:')) continue;
      const data = trimmed.slice(5).trim();
      if (data === '[DONE]' || !data) continue;

      try {
        const parsed = JSON.parse(data);

        // Extract model from first chunk
        if (parsed.model && this.model === 'unknown') {
          this.model = parsed.model;
        }

        // OpenAI format: choices[].delta.tool_calls[{index, function: {name, arguments}}]
        for (const choice of parsed.choices || []) {
          for (const tc of choice.delta?.tool_calls || []) {
            const idx = tc.index ?? 0;
            if (!this.tools.has(idx)) this.tools.set(idx, { name: '', args: '' });
            const t = this.tools.get(idx);
            if (tc.function?.name) t.name += tc.function.name;
            if (tc.function?.arguments) t.args += tc.function.arguments;
          }
        }

        // Anthropic format: content_block_start / content_block_delta
        if (parsed.type === 'content_block_start' && parsed.content_block?.type === 'tool_use') {
          const idx = parsed.index ?? this.tools.size;
          this.tools.set(idx, { name: parsed.content_block.name || '', args: '' });
        } else if (parsed.type === 'content_block_delta' && parsed.delta?.type === 'input_json_delta') {
          const idx = parsed.index ?? 0;
          if (this.tools.has(idx)) {
            this.tools.get(idx).args += parsed.delta.partial_json || '';
          }
        }

        // Google format: candidates[].content.parts[].functionCall
        for (const candidate of parsed.candidates || []) {
          for (const part of candidate.content?.parts || []) {
            if (part.functionCall) {
              const idx = this.tools.size;
              this.tools.set(idx, {
                name: part.functionCall.name || '',
                args: JSON.stringify(part.functionCall.args || {}),
              });
            }
          }
        }
      } catch { /* Skip unparseable JSON */ }
    }
  }

  finalize() {
    const extracted = [];
    for (const t of this.tools.values()) {
      if (t.name) extracted.push({ name: t.name, args: t.args || '{}' });
    }
    return extracted;
  }
}

// ---------------------------------------------------------------------------
// LAYER 1: diagnostics_channel — guaranteed interception of ALL undici HTTP
//
// This solves the Anthropic SDK problem: the SDK captures `fetch` at
// construction time before our globalThis.fetch patch runs. But
// diagnostics_channel hooks into undici's Client internals, firing for
// every request regardless of how it was initiated.
// ---------------------------------------------------------------------------

// Dedup: track which requests the diagnostics_channel already captured
// so globalThis.fetch and http/https patches don't double-emit.
const _dcCapturedUrls = new Set();
const _dcActiveRequests = new Map();

try {
  if (typeof diagnostics_channel.subscribe === 'function') {
    diagnostics_channel.subscribe('undici:request:create', ({ request }) => {
      let hostname;
      try {
        const origin = typeof request.origin === 'string' ? request.origin : String(request.origin ?? '');
        hostname = new URL(origin).hostname;
      } catch { return; }

      if (!LLM_DOMAINS.has(hostname)) return;

      const url = `${request.origin}${request.path}`;
      _dcActiveRequests.set(request, {
        url,
        method: request.method,
        hostname,
        startTime: Date.now(),
      });
    });

    diagnostics_channel.subscribe('undici:request:headers', ({ request, response }) => {
      const data = _dcActiveRequests.get(request);
      if (!data) return;

      // Record status code for the emit at trailers
      data.statusCode = response?.statusCode;
    });

    diagnostics_channel.subscribe('undici:request:trailers', ({ request }) => {
      const data = _dcActiveRequests.get(request);
      if (!data) return;
      _dcActiveRequests.delete(request);

      // Mark as captured by diagnostics_channel so fetch patch doesn't double-emit
      const dedupKey = `${data.method}:${data.url}:${data.startTime}`;
      _dcCapturedUrls.add(dedupKey);
      // Clean up dedup after 5s
      setTimeout(() => _dcCapturedUrls.delete(dedupKey), 5000);

      emitTrace({
        type: 'llm_request',
        source: 'diagnostics_channel',
        url: data.url,
        method: data.method,
        status: data.statusCode ?? 0,
        model: 'unknown', // Body not available via DC; fetch patch provides model
      });
    });

    diagnostics_channel.subscribe('undici:request:error', ({ request, error }) => {
      const data = _dcActiveRequests.get(request);
      if (!data) return;
      _dcActiveRequests.delete(request);

      emitTrace({
        type: 'llm_request_error',
        source: 'diagnostics_channel',
        url: data.url,
        method: data.method,
        error: error?.message || 'unknown',
      });
    });
  }
} catch {
  // diagnostics_channel not available in this Node version — fall through to fetch patch
}

// ---------------------------------------------------------------------------
// LAYER 2: globalThis.fetch — synchronous override for body extraction
//
// Even with diagnostics_channel, we still need the fetch patch to:
// - Extract request bodies (model name, messages)
// - Tee response streams for SSE tool_call extraction
// - Capture model + messages_hash that DC can't provide
// ---------------------------------------------------------------------------

if (typeof globalThis.fetch === 'function') {
  const origFetch = globalThis.fetch;

  globalThis.fetch = async function clawsigFetch(input, init) {
    let urlStr = '';
    let method = 'GET';
    const headers = {};

    if (typeof input === 'string') {
      urlStr = input;
    } else if (input instanceof URL) {
      urlStr = input.toString();
    } else if (input && typeof input === 'object' && 'url' in input) {
      urlStr = input.url;
      method = input.method || method;
      if (input.headers && typeof input.headers.forEach === 'function') {
        input.headers.forEach((v, k) => { headers[k] = v; });
      }
    }
    if (init) {
      method = init.method || method;
      if (init.headers) {
        const h = init.headers;
        if (typeof h.forEach === 'function') h.forEach((v, k) => { headers[k] = v; });
        else if (typeof h === 'object') Object.assign(headers, h);
      }
    }

    let urlObj;
    try { urlObj = new URL(urlStr); } catch { return origFetch.apply(this, arguments); }

    if (!LLM_DOMAINS.has(urlObj.hostname)) {
      return origFetch.apply(this, arguments);
    }

    // Extract request body for model identification
    let reqBody = '';
    if (init?.body && typeof init.body === 'string') {
      reqBody = init.body;
    } else if (input && typeof input === 'object' && 'clone' in input && !input.bodyUsed) {
      try { reqBody = await input.clone().text(); } catch { /* ignore */ }
    }

    let model = 'unknown';
    try { model = JSON.parse(reqBody).model || 'unknown'; } catch { /* ignore */ }

    const startTime = Date.now();
    const res = await origFetch.apply(this, arguments);

    // Check dedup — if diagnostics_channel already captured this, skip the metadata emit
    // but still tee for body extraction
    const dedupKey = `${method}:${urlStr}:${startTime}`;
    const alreadyCaptured = _dcCapturedUrls.has(dedupKey);

    // Tee response stream for SSE tool_call extraction
    if (res.body && typeof res.body.tee === 'function') {
      try {
        const [stream1, stream2] = res.body.tee();
        const parser = new SseToolParser();
        const decoder = new TextDecoder('utf8');

        // Background: read stream2 for tool extraction
        (async () => {
          try {
            const reader = stream2.getReader();
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              if (value) parser.push(decoder.decode(value, { stream: true }));
            }

            // Emit (or supplement DC's emit with body details)
            emitTrace({
              type: 'llm_request',
              source: alreadyCaptured ? 'fetch_supplement' : 'fetch',
              url: urlStr,
              method,
              headers: redactHeaders(headers),
              status: res.status,
              model: parser.model !== 'unknown' ? parser.model : model,
              messages_hash: reqBody ? hashString(reqBody) : '',
            });

            const tools = parser.finalize();
            for (const tc of tools) {
              emitTrace({
                type: 'tool_call',
                tool_name: tc.name,
                args_hash: hashString(tc.args),
              });
            }
          } catch { /* never throw from instrumentation */ }
        })();

        // Strip content-encoding from the wrapped Response.
        // Bun (and some Node versions) auto-decompress the body but keep
        // the original Content-Encoding header. If we create a new Response
        // with the same headers, consumers see "Content-Encoding: br" and
        // try to decompress the already-decompressed body → ZlibError.
        const safeHeaders = new Headers(res.headers);
        safeHeaders.delete('content-encoding');
        safeHeaders.delete('content-length');
        safeHeaders.delete('transfer-encoding');

        return new Response(stream1, {
          status: res.status,
          statusText: res.statusText,
          headers: safeHeaders,
        });
      } catch {
        return res;
      }
    }

    // Non-streaming response
    if (!alreadyCaptured) {
      emitTrace({
        type: 'llm_request',
        source: 'fetch',
        url: urlStr,
        method,
        headers: redactHeaders(headers),
        status: res.status,
        model,
        messages_hash: reqBody ? hashString(reqBody) : '',
      });
    }

    return res;
  };
}

// ---------------------------------------------------------------------------
// LAYER 3: http/https — legacy Node HTTP module patches
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

    let urlObj;
    try { urlObj = new URL(urlStr); } catch { return origRequest.apply(this, args); }
    if (!LLM_DOMAINS.has(urlObj.hostname)) return origRequest.apply(this, args);

    const req = origRequest.apply(this, args);
    const reqHeaders = typeof req.getHeaders === 'function' ? req.getHeaders() : (options.headers || {});

    const reqBodyChunks = [];
    const origWrite = req.write;
    const origEnd = req.end;

    req.write = function(chunk) {
      if (chunk) reqBodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      return origWrite.apply(this, arguments);
    };

    req.end = function(chunk) {
      if (chunk && typeof chunk !== 'function') {
        reqBodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      }
      return origEnd.apply(this, arguments);
    };

    req.on('response', (res) => {
      let isStreaming = false;
      const jsonChunks = [];
      const sseParser = new SseToolParser();

      res.on('data', (chunk) => {
        const str = Buffer.from(chunk).toString('utf8');
        if (str.includes('data:') || isStreaming) {
          isStreaming = true;
          sseParser.push(str);
        } else {
          jsonChunks.push(str);
        }
      });

      res.on('end', () => {
        try {
          const reqBody = Buffer.concat(reqBodyChunks).toString('utf8');
          let model = sseParser.model !== 'unknown' ? sseParser.model : 'unknown';
          try { model = model === 'unknown' ? (JSON.parse(reqBody).model || 'unknown') : model; } catch { /* ignore */ }

          emitTrace({
            type: 'llm_request',
            source: 'http',
            url: urlStr,
            method: options.method || 'GET',
            headers: redactHeaders(reqHeaders),
            status: res.statusCode,
            model,
            messages_hash: reqBody ? hashString(reqBody) : '',
          });

          let tools;
          if (isStreaming) {
            tools = sseParser.finalize();
          } else {
            try {
              const parsed = JSON.parse(jsonChunks.join(''));
              tools = [];
              for (const c of parsed.choices || []) {
                for (const tc of c.message?.tool_calls || []) {
                  if (tc.function?.name) tools.push({ name: tc.function.name, args: tc.function.arguments || '{}' });
                }
              }
            } catch { tools = []; }
          }

          for (const tc of tools) {
            emitTrace({ type: 'tool_call', tool_name: tc.name, args_hash: hashString(tc.args) });
          }
        } catch { /* never throw from instrumentation */ }
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
// LAYER 4: Child Process Propagation
// Injects NODE_OPTIONS + CLAWSIG_TRACE_FILE into child processes.
// ---------------------------------------------------------------------------

const cpMethods = ['spawn', 'fork', 'exec', 'execFile', 'spawnSync', 'execSync', 'execFileSync'];
for (const method of cpMethods) {
  if (typeof cp[method] === 'function') {
    const orig = cp[method];
    cp[method] = function clawsigCpMethod(...args) {
      let optsIndex = -1;

      if (['spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork'].includes(method)) {
        if (args.length >= 3 && typeof args[2] === 'object' && args[2] !== null) optsIndex = 2;
        else if (args.length === 2 && !Array.isArray(args[1]) && typeof args[1] === 'object' && args[1] !== null) optsIndex = 1;
      } else if (['exec', 'execSync'].includes(method)) {
        if (args.length >= 2 && typeof args[1] === 'object' && args[1] !== null && !Array.isArray(args[1]) && typeof args[1] !== 'function') optsIndex = 1;
      }

      if (optsIndex !== -1) {
        const opts = args[optsIndex] = args[optsIndex] || {};
        const env = opts.env || { ...process.env };
        let myPath = import.meta.url;
        if (myPath.startsWith('file://')) myPath = fileURLToPath(myPath);

        const sentinelPath = myPath.replace(/preload\.mjs$/, 'node-preload-sentinel.mjs');
        const importFlags = `--import ${myPath} --import ${sentinelPath}`;

        let nodeOpts = env.NODE_OPTIONS || '';
        if (!nodeOpts.includes('preload.mjs')) nodeOpts = `${nodeOpts} ${importFlags}`.trim();

        opts.env = { ...env, NODE_OPTIONS: nodeOpts, CLAWSIG_TRACE_FILE: traceFile };
      }

      return orig.apply(this, args);
    };
  }
}

// Also patch ChildProcess.prototype.spawn for envPairs injection
const origCpSpawn = cp.ChildProcess.prototype.spawn;
cp.ChildProcess.prototype.spawn = function(options) {
  if (options && options.envPairs) {
    let myPath = import.meta.url;
    if (myPath.startsWith('file://')) myPath = fileURLToPath(myPath);
    const sentinelPath = myPath.replace('preload.mjs', 'node-preload-sentinel.mjs');

    const importFlag1 = `--import ${myPath}`;
    const importFlag2 = `--import ${sentinelPath}`;

    let hasNodeOptions = false;
    let hasTraceFile = false;

    for (let i = 0; i < options.envPairs.length; i++) {
      const pair = options.envPairs[i];
      if (typeof pair !== 'string') continue;
      if (pair.startsWith('NODE_OPTIONS=')) {
        hasNodeOptions = true;
        let newPair = pair;
        if (!pair.includes('preload.mjs')) newPair += ` ${importFlag1}`;
        if (!pair.includes('node-preload-sentinel.mjs')) newPair += ` ${importFlag2}`;
        options.envPairs[i] = newPair;
      }
      if (pair.startsWith('CLAWSIG_TRACE_FILE=')) hasTraceFile = true;
    }

    if (!hasNodeOptions) options.envPairs.push(`NODE_OPTIONS=${importFlag1} ${importFlag2}`);
    if (!hasTraceFile && traceFile) options.envPairs.push(`CLAWSIG_TRACE_FILE=${traceFile}`);
  }
  return origCpSpawn.apply(this, arguments);
};
