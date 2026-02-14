/**
 * Native LLM Call Interception Preload (No HTTP_PROXY required)
 *
 * Patches fetch, http, and https natively. Captures payloads and logs
 * tool_call extractions to CLAWSIG_TRACE_FILE.
 *
 * Loaded via NODE_OPTIONS="--import preload.mjs"
 */

import http from 'node:http';
import https from 'node:https';
import cp from 'node:child_process';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { URL, fileURLToPath } from 'node:url';

const traceFile = process.env.CLAWSIG_TRACE_FILE;

const LLM_DOMAINS = new Set([
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.groq.com',
  'openrouter.ai',
  'api.together.xyz',
  'api.mistral.ai',
  'api.cohere.com',
]);

let inHook = false;

function emitTrace(payload) {
  if (!traceFile || inHook) return;
  inHook = true;
  try {
    const line = JSON.stringify({ layer: 'preload', ts: new Date().toISOString(), ...payload }) + '\n';
    fs.appendFileSync(traceFile, line, { encoding: 'utf8' });
  } catch {
    // Fail silently
  } finally {
    inHook = false;
  }
}

function hashString(str) {
  return crypto.createHash('sha256').update(str).digest('base64url');
}

function redactHeaders(headers) {
  if (!headers) return {};
  const redacted = {};
  for (const [key, value] of Object.entries(headers)) {
    const lk = key.toLowerCase();
    if (lk === 'authorization' || lk.includes('api-key') || lk.includes('api_key')) {
      redacted[key] = '[REDACTED]';
    } else {
      redacted[key] = value;
    }
  }
  return redacted;
}

function extractToolCalls(resBody) {
  const toolCalls = [];
  try {
    if (resBody.trim().startsWith('{')) {
      const resJson = JSON.parse(resBody);
      // OpenAI
      for (const c of (resJson.choices || [])) {
        for (const tc of (c.message?.tool_calls || [])) {
          if (tc.function?.name) toolCalls.push({ name: tc.function.name, args: tc.function.arguments || '{}' });
        }
      }
      // Anthropic
      for (const c of (resJson.content || [])) {
        if (c.type === 'tool_use' && c.name) {
          toolCalls.push({ name: c.name, args: JSON.stringify(c.input || {}) });
        }
      }
      // Google Gemini
      for (const c of (resJson.candidates || [])) {
        for (const part of (c.content?.parts || [])) {
          if (part.functionCall?.name) {
            toolCalls.push({ name: part.functionCall.name, args: JSON.stringify(part.functionCall.args || {}) });
          }
        }
      }
    } else {
      // SSE streaming
      const lines = resBody.split('\n');
      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6).trim();
          if (data === '[DONE]') continue;
          try {
            const parsed = JSON.parse(data);
            for (const c of (parsed.choices || [])) {
              for (const tc of (c.delta?.tool_calls || [])) {
                if (tc.function?.name) toolCalls.push({ name: tc.function.name, args: tc.function.arguments || '{}' });
              }
            }
          } catch { /* skip partial JSON */ }
        }
      }
    }
  } catch { /* skip parse errors */ }
  return toolCalls;
}

function processLlmRequest(url, method, headers, reqBody, status, resBody) {
  let model = 'unknown';
  try {
    if (reqBody) {
      const parsed = JSON.parse(reqBody);
      if (parsed.model) model = parsed.model;
    }
  } catch { /* skip */ }

  const messagesHash = reqBody ? hashString(reqBody) : '';

  emitTrace({
    type: 'llm_request',
    url,
    method,
    headers: redactHeaders(headers),
    status,
    model,
    messages_hash: messagesHash,
  });

  const toolCalls = extractToolCalls(resBody);
  for (const tc of toolCalls) {
    emitTrace({ type: 'tool_call', tool_name: tc.name, args_hash: hashString(tc.args) });
  }
}

// 1. Hook HTTP/HTTPS
function patchHttp(mod, defaultProtocol) {
  const origRequest = mod.request;

  mod.request = function(...args) {
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

    if (!LLM_DOMAINS.has(urlObj.hostname)) {
      return origRequest.apply(this, args);
    }

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
      if (chunk && typeof chunk !== 'function') reqBodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
      return origEnd.apply(this, arguments);
    };

    req.on('response', (res) => {
      const resBodyChunks = [];
      res.on('data', chunk => resBodyChunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        try {
          const reqBody = Buffer.concat(reqBodyChunks).toString('utf8');
          const resBody = Buffer.concat(resBodyChunks).toString('utf8');
          processLlmRequest(urlStr, options.method || 'GET', reqHeaders, reqBody, res.statusCode, resBody);
        } catch { /* skip */ }
      });
    });

    return req;
  };

  const origGet = mod.get;
  mod.get = function(...args) {
    const req = mod.request.apply(this, args);
    req.end();
    return req;
  };
}

patchHttp(http, 'http:');
patchHttp(https, 'https:');

// 2. Hook globalThis.fetch
if (typeof globalThis.fetch === 'function') {
  const origFetch = globalThis.fetch;
  globalThis.fetch = async function(input, init) {
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
      headers = init.headers || headers;
    }

    let urlObj;
    try { urlObj = new URL(urlStr); } catch { return origFetch.apply(this, arguments); }

    if (!LLM_DOMAINS.has(urlObj.hostname)) {
      return origFetch.apply(this, arguments);
    }

    let reqBody = '';
    if (init?.body && typeof init.body === 'string') {
      reqBody = init.body;
    } else if (input instanceof Request && !input.bodyUsed) {
      try { reqBody = await input.clone().text(); } catch { /* skip */ }
    }

    const res = await origFetch.apply(this, arguments);

    try {
      const resClone = res.clone();
      resClone.text().then(resBody => {
        processLlmRequest(urlStr, method, headers, reqBody, res.status, resBody);
      }).catch(() => {});
    } catch { /* skip */ }

    return res;
  };
}

// 3. Propagate NODE_OPTIONS to child processes
const origCpSpawn = cp.ChildProcess.prototype.spawn;
cp.ChildProcess.prototype.spawn = function(options) {
  if (options?.envPairs) {
    let myPath = import.meta.url;
    if (myPath.startsWith('file://')) myPath = fileURLToPath(myPath);
    const importFlag = `--import ${myPath}`;

    let hasNodeOptions = false;
    let hasTraceFile = false;

    for (let i = 0; i < options.envPairs.length; i++) {
      const pair = options.envPairs[i];
      if (pair.startsWith('NODE_OPTIONS=')) {
        hasNodeOptions = true;
        if (!pair.includes('preload.mjs')) options.envPairs[i] = `${pair} ${importFlag}`;
      }
      if (pair.startsWith('CLAWSIG_TRACE_FILE=')) hasTraceFile = true;
    }

    if (!hasNodeOptions) options.envPairs.push(`NODE_OPTIONS=${importFlag}`);
    if (!hasTraceFile && traceFile) options.envPairs.push(`CLAWSIG_TRACE_FILE=${traceFile}`);
  }
  return origCpSpawn.apply(this, arguments);
};
