/**
 * clawcontrols — Policy Controls (WPC registry)
 *
 * CCO-US-021: Work Policy Contract (WPC) registry API (signed policies).
 */

import type { Env } from './types';
import { WpcRegistryDurableObject } from './wpc-registry-do';

export { WpcRegistryDurableObject };

function json(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      ...extraHeaders,
    },
  });
}

function text(body: string, contentType: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
    },
  });
}

function html(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'public, max-age=300',
      'x-robots-tag': 'noindex',
    },
  });
}

function isAdminAuthed(request: Request, env: Env): boolean {
  const expected = env.ADMIN_TOKEN;
  if (!expected || expected.trim().length === 0) return false;

  const auth = request.headers.get('authorization');
  if (!auth) return false;
  return auth === `Bearer ${expected}`;
}

function getRegistryStub(env: Env): DurableObjectStub {
  const id = env.WPC_REGISTRY.idFromName('wpc-registry');
  return env.WPC_REGISTRY.get(id);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET, POST, OPTIONS',
          'access-control-allow-headers': 'content-type, authorization',
        },
      });
    }

    // Landing
    if (request.method === 'GET' && path === '/') {
      return html(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawcontrols</title>
  </head>
  <body>
    <main style="max-width: 820px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5;">
      <h1>clawcontrols</h1>
      <p>Policy controls service (Work Policy Contract registry).</p>
      <ul>
        <li><a href="/docs">Docs</a></li>
        <li><a href="/health">Health</a></li>
      </ul>
      <p><small>Version: ${env.SERVICE_VERSION}</small></p>
    </main>
  </body>
</html>`);
    }

    if (request.method === 'GET' && path === '/docs') {
      return html(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawcontrols docs</title>
  </head>
  <body>
    <main style="max-width: 820px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5;">
      <h1>clawcontrols docs</h1>

      <h2>Endpoints</h2>
      <ul>
        <li><code>POST /v1/wpc</code> — Create a Work Policy Contract (admin-gated). Returns a signed envelope + policy_hash_b64u.</li>
        <li><code>GET /v1/wpc/:policy_hash_b64u</code> — Fetch a previously created WPC by hash.</li>
        <li><code>GET /health</code> — Health check.</li>
      </ul>

      <h2>Hashing</h2>
      <p>WPCs are addressed by <code>policy_hash_b64u</code>:</p>
      <pre>policy_hash_b64u = sha256( JCS(wpc_payload) )  // base64url, no padding</pre>

      <h2>Create (admin)</h2>
      <pre>curl -sS -X POST "${url.origin}/v1/wpc" \\
  -H "Authorization: Bearer $ADMIN_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{"wpc":{"policy_version":"1","policy_id":"pol_example","issuer_did":"did:key:z...","allowed_providers":["openai"],"allowed_models":["gpt-5.*"],"redaction_rules":[{"path":"$.messages[*].content","action":"hash"}],"receipt_privacy_mode":"hash_only","egress_allowlist":[]}}'</pre>

      <h2>Fetch</h2>
      <pre>curl -sS "${url.origin}/v1/wpc/$POLICY_HASH_B64U" | jq .</pre>

      <p><small>Version: ${env.SERVICE_VERSION}</small></p>
    </main>
  </body>
</html>`);
    }

    // Health
    if (request.method === 'GET' && path === '/health') {
      return json({
        status: 'ok',
        version: env.SERVICE_VERSION,
        signingEnabled: !!(env.CONTROLS_SIGNING_KEY && env.CONTROLS_SIGNING_KEY.trim().length > 0),
      });
    }

    // API: WPC registry
    if (path === '/v1/wpc' || path.startsWith('/v1/wpc/')) {
      if (request.method === 'POST' && path === '/v1/wpc') {
        if (!isAdminAuthed(request, env)) {
          return json({ ok: false, error: { code: 'UNAUTHORIZED', message: 'Admin token required' } }, 401);
        }
      }

      const stub = getRegistryStub(env);
      return stub.fetch(request);
    }

    // Fallback
    return text('not found', 'text/plain; charset=utf-8', 404);
  },
};
