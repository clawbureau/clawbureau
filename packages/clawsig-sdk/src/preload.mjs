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
