import { ClawSettleError, StripeWebhookService } from './stripe';
import type { Env, ErrorResponse } from './types';

function jsonResponse<T>(data: T, status = 200, version = '0.1.0'): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-clawsettle-version': version,
    },
  });
}

function errorResponse(
  message: string,
  code: string,
  status: number,
  details?: Record<string, unknown>,
  version = '0.1.0'
): Response {
  const body: ErrorResponse = {
    error: message,
    code,
    details,
  };

  return jsonResponse(body, status, version);
}

function textResponse(body: string, contentType: string, status = 200, version = '0.1.0'): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'x-clawsettle-version': version,
    },
  });
}

function htmlResponse(body: string, status = 200, version = '0.1.0'): Response {
  return textResponse(body, 'text/html; charset=utf-8', status, version);
}

function resolveVersion(env: Env): string {
  const value = env.SETTLE_VERSION?.trim();
  return value && value.length > 0 ? value : '0.1.0';
}

function parseBearerToken(value: string | null): string | null {
  if (!value) {
    return null;
  }

  const [scheme, token] = value.trim().split(/\s+/, 2);
  if (!scheme || !token) {
    return null;
  }

  return scheme.toLowerCase() === 'bearer' ? token : null;
}

function assertSettleAdmin(request: Request, env: Env): void {
  const expected = env.SETTLE_ADMIN_KEY?.trim();
  if (!expected) {
    throw new ClawSettleError(
      'Settlement admin key not configured',
      'DEPENDENCY_NOT_CONFIGURED',
      503,
      { field: 'env.SETTLE_ADMIN_KEY' }
    );
  }

  const token = parseBearerToken(request.headers.get('authorization'));
  if (!token || token !== expected) {
    throw new ClawSettleError('Unauthorized', 'UNAUTHORIZED', 401);
  }
}

async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  const signature = request.headers.get('stripe-signature');
  const rawBody = await request.text();

  const service = new StripeWebhookService(env);
  const response = await service.processWebhook(rawBody, signature);

  return jsonResponse(response, 200, resolveVersion(env));
}

async function handleRetryForwarding(request: Request, env: Env): Promise<Response> {
  assertSettleAdmin(request, env);

  let limit: number | undefined;
  let force = false;
  let eventId: string | undefined;

  const contentType = request.headers.get('content-type') ?? '';
  if (contentType.toLowerCase().includes('application/json')) {
    const raw = await request.text();
    if (raw.trim().length > 0) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
      }

      if (typeof parsed === 'object' && parsed !== null) {
        if ('limit' in parsed) {
          const candidate = (parsed as { limit?: unknown }).limit;
          if (typeof candidate !== 'number' || !Number.isFinite(candidate)) {
            throw new ClawSettleError('Invalid retry limit', 'INVALID_REQUEST', 400, {
              field: 'limit',
            });
          }
          limit = candidate;
        }

        if ('force' in parsed) {
          const candidate = (parsed as { force?: unknown }).force;
          if (typeof candidate !== 'boolean') {
            throw new ClawSettleError('Invalid force flag', 'INVALID_REQUEST', 400, {
              field: 'force',
            });
          }
          force = candidate;
        }

        if ('event_id' in parsed) {
          const candidate = (parsed as { event_id?: unknown }).event_id;
          if (typeof candidate !== 'string' || candidate.trim().length === 0) {
            throw new ClawSettleError('Invalid event_id', 'INVALID_REQUEST', 400, {
              field: 'event_id',
            });
          }
          eventId = candidate.trim();
        }
      }
    }
  }

  const service = new StripeWebhookService(env);
  const response = await service.retryFailedForwarding(limit, force, eventId);

  return jsonResponse(response, 200, resolveVersion(env));
}

async function router(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === 'GET' && path === '/health') {
    return jsonResponse({ status: 'ok', service: 'clawsettle' }, 200, resolveVersion(env));
  }

  if (request.method === 'GET' && path === '/') {
    return htmlResponse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawsettle</title>
  </head>
  <body>
    <main style="max-width: 800px; margin: 2rem auto; font-family: system-ui, sans-serif; line-height: 1.5;">
      <h1>clawsettle</h1>
      <p>Settlement rail adapter service.</p>
      <ul>
        <li><code>GET /health</code></li>
        <li><code>POST /v1/stripe/webhook</code></li>
        <li><code>POST /v1/stripe/forwarding/retry</code> (admin)</li>
      </ul>
    </main>
  </body>
</html>`, 200, resolveVersion(env));
  }

  if (request.method === 'POST' && path === '/v1/stripe/webhook') {
    return handleStripeWebhook(request, env);
  }

  if (request.method === 'POST' && path === '/v1/stripe/forwarding/retry') {
    return handleRetryForwarding(request, env);
  }

  return errorResponse('Not found', 'NOT_FOUND', 404, undefined, resolveVersion(env));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await router(request, env);
    } catch (err) {
      if (err instanceof ClawSettleError) {
        return errorResponse(
          err.message,
          err.code,
          err.status,
          err.details,
          resolveVersion(env)
        );
      }

      const message = err instanceof Error ? err.message : 'Internal error';
      return errorResponse(message, 'INTERNAL_ERROR', 500, undefined, resolveVersion(env));
    }
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const service = new StripeWebhookService(env);
    ctx.waitUntil(
      service.retryFailedForwarding().catch((err) => {
        console.error('scheduled-forwarding-retry-failed', err);
      })
    );
  },
};
