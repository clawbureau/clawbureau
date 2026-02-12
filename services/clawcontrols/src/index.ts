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

function parseDefaultTrueFlag(raw: string | undefined): boolean {
  if (raw === undefined) return true;
  const normalized = raw.trim().toLowerCase();
  if (normalized.length === 0) return true;
  return !['0', 'false', 'no', 'n', 'off'].includes(normalized);
}

function parseIntOrDefault(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function parseBearer(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;

  if (trimmed.toLowerCase().startsWith('bearer ')) {
    const token = trimmed.slice(7).trim();
    return token.length > 0 ? token : null;
  }

  return trimmed;
}

function isAdminAuthed(request: Request, env: Env): boolean {
  const expected = env.ADMIN_TOKEN;
  if (!expected || expected.trim().length === 0) return false;

  const auth = request.headers.get('authorization');
  if (!auth) return false;

  const parts = auth.trim().split(/\s+/g);
  if (parts.length < 2) return false;

  const scheme = parts[0]!.toLowerCase();
  const token = parts.slice(1).join(' ').trim();

  if (scheme !== 'bearer') return false;
  if (token.length === 0) return false;

  return token === expected.trim();
}

interface VerifyTokenControlError {
  code: string;
  message: string;
}

interface VerifyTokenControlResult {
  result?: { status?: string; reason?: string };
  error?: VerifyTokenControlError;
}

function normalizeBaseUrl(raw: string): string {
  return raw.replace(/\/+$/, '');
}

async function requireCanonicalCstForWrite(request: Request, env: Env): Promise<Response | null> {
  const baseUrlRaw = env.CLAWVERIFY_BASE_URL?.trim();
  if (!baseUrlRaw) {
    return json(
      {
        ok: false,
        error: {
          code: 'DEPENDENCY_NOT_CONFIGURED',
          message: 'CLAWVERIFY_BASE_URL is required when CONTROL_REQUIRE_CANONICAL_CST=true',
        },
      },
      503
    );
  }

  const tokenFromXCst = parseBearer(request.headers.get('x-cst'));
  const tokenFromXScoped = parseBearer(request.headers.get('x-scoped-token'));
  const authHeader = request.headers.get('authorization');

  if (tokenFromXCst && tokenFromXScoped && tokenFromXCst !== tokenFromXScoped) {
    return json(
      {
        ok: false,
        error: {
          code: 'TOKEN_MALFORMED',
          message: 'Conflicting CST headers: X-CST and X-Scoped-Token differ',
        },
      },
      401
    );
  }

  const token = tokenFromXCst ?? tokenFromXScoped;
  if (!token) {
    if (authHeader && authHeader.trim().length > 0) {
      return json(
        {
          ok: false,
          error: {
            code: 'LEGACY_AUTH_FORBIDDEN',
            message: 'Authorization header admin tokens are not accepted; provide canonical CST via X-CST',
          },
        },
        401
      );
    }

    return json(
      {
        ok: false,
        error: {
          code: 'TOKEN_REQUIRED',
          message: 'Canonical CST token is required (X-CST or X-Scoped-Token)',
        },
      },
      401
    );
  }

  const timeoutMs = Math.max(500, parseIntOrDefault(env.CONTROL_VERIFY_TIMEOUT_MS, 5000));
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const url = new URL(request.url);
    const requiredAudience = Array.from(new Set([url.hostname, 'clawcontrols.com']));

    const response = await fetch(`${normalizeBaseUrl(baseUrlRaw)}/v1/verify/token-control`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify({
        token,
        required_scope: ['control:policy:update'],
        required_transitions: ['controller.policy.update'],
        required_audience: requiredAudience,
      }),
      signal: controller.signal,
    });

    const textBody = await response.text();
    let payload: VerifyTokenControlResult | null = null;

    try {
      payload = textBody ? (JSON.parse(textBody) as VerifyTokenControlResult) : null;
    } catch {
      payload = null;
    }

    if (!response.ok || !payload || payload.result?.status !== 'VALID') {
      const code = payload?.error?.code ?? 'UNAUTHORIZED';
      const message =
        payload?.error?.message ??
        payload?.result?.reason ??
        (response.status >= 500
          ? 'Token-control verification dependency failed'
          : 'Token-control verification rejected this request');

      return json(
        {
          ok: false,
          error: {
            code,
            message,
          },
        },
        response.status >= 500 ? 503 : 401
      );
    }

    return null;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return json(
      {
        ok: false,
        error: {
          code: 'DEPENDENCY_NOT_CONFIGURED',
          message: `Token-control verification failed: ${message}`,
        },
      },
      503
    );
  } finally {
    clearTimeout(timeout);
  }
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
          'access-control-allow-headers':
            'content-type, authorization, x-cst, x-scoped-token',
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
      const requiresCanonical = parseDefaultTrueFlag(env.CONTROL_REQUIRE_CANONICAL_CST);

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
        <li><code>POST /v1/wpc</code> — Create a Work Policy Contract (write-protected). Returns a signed envelope + policy_hash_b64u.</li>
        <li><code>GET /v1/wpc/:policy_hash_b64u</code> — Fetch a previously created WPC by hash.</li>
        <li><code>GET /health</code> — Health check.</li>
      </ul>

      <h2>Hashing</h2>
      <p>WPCs are addressed by <code>policy_hash_b64u</code>:</p>
      <pre>policy_hash_b64u = sha256( JCS(wpc_payload) )  // base64url, no padding</pre>

      <h2>Create (write-protected)</h2>
      <p>Current auth mode: <strong>${requiresCanonical ? 'canonical CST required' : 'legacy admin token fallback'}</strong></p>
      <pre>curl -sS -X POST "${url.origin}/v1/wpc" \\
  -H "X-CST: $CANONICAL_CST" \\
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
        control_require_canonical_cst: parseDefaultTrueFlag(env.CONTROL_REQUIRE_CANONICAL_CST),
      });
    }

    // API: WPC registry
    if (path === '/v1/wpc' || path.startsWith('/v1/wpc/')) {
      if (request.method === 'POST' && path === '/v1/wpc') {
        const requireCanonical = parseDefaultTrueFlag(env.CONTROL_REQUIRE_CANONICAL_CST);

        if (requireCanonical) {
          const cstErr = await requireCanonicalCstForWrite(request, env);
          if (cstErr) return cstErr;
        } else if (!isAdminAuthed(request, env)) {
          return json({ ok: false, error: { code: 'UNAUTHORIZED', message: 'Admin token required' } }, 401);
        }
      }

      const stub = getRegistryStub(env);
      const doResponse = await stub.fetch(request);

      const headers = new Headers(doResponse.headers);
      if (!headers.has('access-control-allow-origin')) {
        headers.set('access-control-allow-origin', '*');
      }

      return new Response(doResponse.body, {
        status: doResponse.status,
        statusText: doResponse.statusText,
        headers,
      });
    }

    // Fallback
    return text('not found', 'text/plain; charset=utf-8', 404);
  },
};
