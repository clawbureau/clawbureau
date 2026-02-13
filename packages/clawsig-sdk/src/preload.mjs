/**
 * Socket-level LLM API interception preload (Red Team Fix #6).
 *
 * Load via NODE_OPTIONS="--import @clawbureau/clawsig-sdk/preload"
 *
 * Monkey-patches node:https and node:http request/get methods to
 * intercept outgoing requests to known LLM API domains and rewrite
 * them to the local clawsig proxy.
 *
 * If CLAWSIG_PROXY_PORT is not set, all requests pass through unchanged
 * (graceful no-op). Zero external dependencies.
 */

import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';

const LLM_DOMAINS = new Set([
  'api.openai.com',
  'api.anthropic.com',
  'generativelanguage.googleapis.com',
  'api.together.xyz',
  'openrouter.ai',
]);

const DOMAIN_TO_PROVIDER = {
  'api.openai.com': 'openai',
  'api.anthropic.com': 'anthropic',
  'generativelanguage.googleapis.com': 'google',
  'api.together.xyz': 'together',
  'openrouter.ai': 'openrouter',
};

const proxyPort = process.env.CLAWSIG_PROXY_PORT;

if (proxyPort) {
  const port = parseInt(proxyPort, 10);
  if (!Number.isNaN(port) && port > 0 && port < 65536) {
    patchModule(https, port);
    patchModule(http, port);
    patchGlobalFetch(port);
    // Belt-and-suspenders: try undici dispatcher for Node 18-22 where
    // undici is importable. The synchronous fetch patch above is primary.
    tryUndiciDispatcher(port).catch(() => {});
  }
}

const _originalHttpRequest = http.request;

function patchModule(mod, port) {
  const originalRequest = mod.request;

  mod.request = function patchedRequest(urlOrOptions, optionsOrCallback, callback) {
    const { rewritten, args } = maybeRewrite(urlOrOptions, optionsOrCallback, callback, port);
    if (rewritten) {
      return _originalHttpRequest.apply(http, args);
    }
    return originalRequest.apply(mod, [urlOrOptions, optionsOrCallback, callback]);
  };

  mod.get = function patchedGet(urlOrOptions, optionsOrCallback, callback) {
    const req = mod.request(urlOrOptions, optionsOrCallback, callback);
    req.end();
    return req;
  };
}

function maybeRewrite(urlOrOptions, optionsOrCallback, callback, port) {
  let hostname = null;
  let originalPath = '/';
  let options = null;
  let cb = callback;

  if (typeof urlOrOptions === 'string' || urlOrOptions instanceof URL) {
    const parsed = typeof urlOrOptions === 'string' ? new URL(urlOrOptions) : urlOrOptions;
    hostname = parsed.hostname;
    originalPath = parsed.pathname + parsed.search;
    if (typeof optionsOrCallback === 'function') {
      cb = optionsOrCallback;
      options = {};
    } else {
      options = optionsOrCallback || {};
    }
  } else if (typeof urlOrOptions === 'object' && urlOrOptions !== null) {
    options = urlOrOptions;
    hostname = options.hostname || options.host;
    originalPath = options.path || '/';
    if (typeof optionsOrCallback === 'function') {
      cb = optionsOrCallback;
    }
  }

  if (hostname && hostname.includes(':')) {
    hostname = hostname.split(':')[0];
  }

  if (!hostname || !LLM_DOMAINS.has(hostname)) {
    return { rewritten: false, args: [] };
  }

  const provider = DOMAIN_TO_PROVIDER[hostname] || 'unknown';

  const rewrittenOptions = {
    ...(options || {}),
    protocol: 'http:',
    hostname: '127.0.0.1',
    host: `127.0.0.1:${port}`,
    port: port,
    path: `/v1/proxy/${provider}`,
    cert: undefined,
    key: undefined,
    ca: undefined,
    rejectUnauthorized: undefined,
  };

  if (!rewrittenOptions.headers) {
    rewrittenOptions.headers = {};
  }
  rewrittenOptions.headers['X-Original-Host'] = hostname;
  rewrittenOptions.headers['X-Original-Path'] = originalPath;

  const args = cb ? [rewrittenOptions, cb] : [rewrittenOptions];
  return { rewritten: true, args };
}

// ---------------------------------------------------------------------------
// Bug 1 Fix: Intercept globalThis.fetch (undici-backed in Node 18+)
// ---------------------------------------------------------------------------
// The @anthropic-ai/sdk and openai SDK v4+ use globalThis.fetch() exclusively.
// Node 18+ backs fetch with undici, which bypasses http/https monkey-patching.
// This patch rewrites fetch calls to LLM API domains through the local proxy.

/**
 * Monkey-patch globalThis.fetch to redirect LLM API domain requests
 * through the local clawsig proxy. Selective: only intercepts requests
 * to known LLM domains (api.openai.com, api.anthropic.com, etc.).
 */
function patchGlobalFetch(port) {
  if (typeof globalThis.fetch !== 'function') return;

  const originalFetch = globalThis.fetch;

  globalThis.fetch = function clawsigFetch(input, init) {
    let url;
    try {
      if (typeof input === 'string') {
        url = new URL(input);
      } else if (input instanceof URL) {
        url = input;
      } else if (input instanceof Request) {
        url = new URL(input.url);
      } else {
        return originalFetch.apply(this, arguments);
      }
    } catch {
      return originalFetch.apply(this, arguments);
    }

    const hostname = url.hostname;
    if (!LLM_DOMAINS.has(hostname)) {
      return originalFetch.apply(this, arguments);
    }

    const provider = DOMAIN_TO_PROVIDER[hostname] || 'unknown';
    const originalPath = url.pathname + url.search;
    const proxyUrl = `http://127.0.0.1:${port}/v1/proxy/${provider}`;

    // Build headers with proxy routing info
    const baseHeaders = init?.headers
      ?? (input instanceof Request ? input.headers : undefined);
    const headers = new Headers(baseHeaders ?? undefined);
    headers.set('X-Original-Host', hostname);
    headers.set('X-Original-Path', originalPath);

    // For Request inputs, preserve method/body/signal
    if (input instanceof Request) {
      return originalFetch.call(this, proxyUrl, {
        method: init?.method ?? input.method,
        headers,
        body: init?.body !== undefined ? init.body : input.body,
        signal: init?.signal ?? input.signal,
        duplex: 'half',
      });
    }

    // For string/URL inputs, swap URL and merge headers
    return originalFetch.call(this, proxyUrl, { ...init, headers });
  };
}

/**
 * Attempt to configure undici's global dispatcher to route through the proxy.
 * Available on Node 18-22 where undici is a directly importable built-in.
 * On Node 24+ the import fails silently — the globalThis.fetch patch above
 * provides full coverage in that case.
 */
async function tryUndiciDispatcher(port) {
  try {
    const undici = await import('undici');
    if (typeof undici.setGlobalDispatcher === 'function' &&
        typeof undici.EnvHttpProxyAgent === 'function') {
      // EnvHttpProxyAgent reads HTTP_PROXY / HTTPS_PROXY from process.env.
      // Only set if not already provided (wrap.ts sets these via Bug 2 fix).
      process.env.HTTPS_PROXY = process.env.HTTPS_PROXY || `http://127.0.0.1:${port}`;
      process.env.HTTP_PROXY = process.env.HTTP_PROXY || `http://127.0.0.1:${port}`;
      process.env.NO_PROXY = process.env.NO_PROXY || 'localhost,127.0.0.1';
      process.env.no_proxy = process.env.no_proxy || 'localhost,127.0.0.1';
      undici.setGlobalDispatcher(new undici.EnvHttpProxyAgent());
    }
  } catch {
    // undici not importable (Node 24+ removed direct import).
    // The synchronous globalThis.fetch patch covers this case.
    if (process.env.CLAWSIG_DEBUG) {
      process.stderr.write(
        '[clawsig:preload] undici not importable in this Node version; ' +
        'using fetch/http monkey-patching for LLM API interception\n'
      );
    }
  }
}
