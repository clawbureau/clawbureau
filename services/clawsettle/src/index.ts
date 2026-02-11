import { ClawSettleError, StripeWebhookService } from './stripe';
import type { Env, ErrorResponse } from './types';

function jsonResponse<T>(data: T, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-clawsettle-version': '0.1.0',
    },
  });
}

function errorResponse(
  message: string,
  code: string,
  status: number,
  details?: Record<string, unknown>
): Response {
  const body: ErrorResponse = {
    error: message,
    code,
    details,
  };

  return jsonResponse(body, status);
}

function textResponse(body: string, contentType: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'x-clawsettle-version': '0.1.0',
    },
  });
}

function htmlResponse(body: string, status = 200): Response {
  return textResponse(body, 'text/html; charset=utf-8', status);
}

async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  const signature = request.headers.get('stripe-signature');
  const rawBody = await request.text();

  const service = new StripeWebhookService(env);
  const response = await service.processWebhook(rawBody, signature);

  return jsonResponse(response, 200);
}

async function router(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === 'GET' && path === '/health') {
    return jsonResponse({ status: 'ok', service: 'clawsettle' });
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
      </ul>
    </main>
  </body>
</html>`);
  }

  if (request.method === 'POST' && path === '/v1/stripe/webhook') {
    return handleStripeWebhook(request, env);
  }

  return errorResponse('Not found', 'NOT_FOUND', 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await router(request, env);
    } catch (err) {
      if (err instanceof ClawSettleError) {
        return errorResponse(err.message, err.code, err.status, err.details);
      }

      const message = err instanceof Error ? err.message : 'Internal error';
      return errorResponse(message, 'INTERNAL_ERROR', 500);
    }
  },
};
