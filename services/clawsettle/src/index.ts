import { ClawSettleError, StripeWebhookService } from './stripe';
import {
  PayoutService,
  extractIdempotencyKey,
  parseJsonRequestBody,
} from './payouts';
import {
  NettingService,
  parseNettingRequestBody,
} from './netting';
import {
  LossEventService,
  assertLossEventAuth,
  resolveLossEventRetryLimit,
  shouldInlineLossEventForwarding,
} from './loss-events';
import type { Env, ErrorResponse, PayoutLifecycleHookInput } from './types';

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

function createStripeWebhookService(env: Env): StripeWebhookService {
  const payoutService = new PayoutService(env);
  return new StripeWebhookService(env, {
    onForwarded: async (input: PayoutLifecycleHookInput) => {
      await payoutService.applyStripeLifecycle(input);
    },
  });
}

async function handleStripeWebhook(request: Request, env: Env): Promise<Response> {
  const signature = request.headers.get('stripe-signature');
  const rawBody = await request.text();

  const service = createStripeWebhookService(env);
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

  const service = createStripeWebhookService(env);
  const response = await service.retryFailedForwarding(limit, force, eventId);

  return jsonResponse(response, 200, resolveVersion(env));
}

async function handleConnectOnboard(request: Request, env: Env): Promise<Response> {
  const body = await parseJsonRequestBody(request);
  const service = new PayoutService(env);
  const response = await service.onboardConnectAccount(body);
  const status = response.deduped ? 200 : 201;
  return jsonResponse(response, status, resolveVersion(env));
}

async function handleCreatePayout(request: Request, env: Env): Promise<Response> {
  const idempotencyKey = extractIdempotencyKey(request);
  if (!idempotencyKey) {
    throw new ClawSettleError('Missing idempotency key', 'INVALID_REQUEST', 400, {
      field: 'idempotency_key',
    });
  }

  const body = await parseJsonRequestBody(request);
  const service = new PayoutService(env);
  const response = await service.createPayout(body, idempotencyKey);
  const status = response.deduped ? 200 : 201;
  return jsonResponse(response, status, resolveVersion(env));
}

async function handleGetPayout(payoutId: string, env: Env): Promise<Response> {
  const service = new PayoutService(env);
  const response = await service.getPayoutById(payoutId);
  return jsonResponse(response, 200, resolveVersion(env));
}

async function handleRetryPayout(payoutId: string, request: Request, env: Env): Promise<Response> {
  assertSettleAdmin(request, env);
  const service = new PayoutService(env);
  const response = await service.retryPayout(payoutId);
  return jsonResponse(response, 200, resolveVersion(env));
}

async function handleListStuckPayouts(url: URL, request: Request, env: Env): Promise<Response> {
  assertSettleAdmin(request, env);

  const service = new PayoutService(env);
  const response = await service.listStuckPayouts({
    olderThanMinutes: url.searchParams.get('older_than_minutes'),
    limit: url.searchParams.get('limit'),
  });

  return jsonResponse(response, 200, resolveVersion(env));
}

async function handleListFailedPayouts(url: URL, request: Request, env: Env): Promise<Response> {
  assertSettleAdmin(request, env);

  const service = new PayoutService(env);
  const response = await service.listFailedPayouts({
    limit: url.searchParams.get('limit'),
  });

  return jsonResponse(response, 200, resolveVersion(env));
}

async function handleListPayouts(url: URL, request: Request, env: Env): Promise<Response> {
  assertSettleAdmin(request, env);

  const accountDid = url.searchParams.get('account_did');
  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');

  if (!from || from.trim().length === 0) {
    throw new ClawSettleError('Missing required query parameter: from', 'INVALID_REQUEST', 400, {
      field: 'from',
    });
  }

  if (!to || to.trim().length === 0) {
    throw new ClawSettleError('Missing required query parameter: to', 'INVALID_REQUEST', 400, {
      field: 'to',
    });
  }

  const service = new PayoutService(env);
  const response = await service.listPayoutsByRange({
    accountDid,
    from: from.trim(),
    to: to.trim(),
    cursor: url.searchParams.get('cursor'),
    limit: url.searchParams.get('limit'),
    status: url.searchParams.get('status'),
  });

  return jsonResponse(response, 200, resolveVersion(env));
}

async function handleDailyReconciliation(url: URL, request: Request, env: Env): Promise<Response> {
  assertSettleAdmin(request, env);

  const date = url.searchParams.get('date');
  if (!date || date.trim().length === 0) {
    throw new ClawSettleError('Missing required query parameter: date', 'INVALID_REQUEST', 400, {
      field: 'date',
    });
  }

  const format = (url.searchParams.get('format') || 'json').trim().toLowerCase();

  const service = new PayoutService(env);
  const report = await service.buildDailyReconciliationReport(date.trim());

  if (format === 'csv') {
    const csv = service.toDailyReconciliationCsv(report);
    return new Response(csv, {
      status: 200,
      headers: {
        'content-type': 'text/csv; charset=utf-8',
        'x-clawsettle-version': resolveVersion(env),
        'x-clawsettle-report-sha256': report.artifact_sha256,
      },
    });
  }

  if (format !== 'json') {
    throw new ClawSettleError('format must be json or csv', 'INVALID_REQUEST', 400, {
      field: 'format',
    });
  }

  return jsonResponse(report, 200, resolveVersion(env));
}

async function handleCreateNettingRun(request: Request, env: Env): Promise<Response> {
  assertSettleAdmin(request, env);

  const idempotencyKey = extractIdempotencyKey(request);
  if (!idempotencyKey) {
    throw new ClawSettleError('Missing idempotency key', 'INVALID_REQUEST', 400, {
      field: 'idempotency_key',
    });
  }

  const rawBody = await parseJsonRequestBody(request);
  const body = parseNettingRequestBody(rawBody);

  const service = new NettingService(env);
  const response = await service.createAndExecuteRun(body, idempotencyKey);
  const status = response.deduped ? 200 : 201;

  return jsonResponse(response, status, resolveVersion(env));
}

async function handleGetNettingRun(runId: string, request: Request, env: Env): Promise<Response> {
  assertSettleAdmin(request, env);

  const service = new NettingService(env);
  const response = await service.getRun(runId);
  return jsonResponse(response, 200, resolveVersion(env));
}

async function handleGetNettingRunReport(
  runId: string,
  url: URL,
  request: Request,
  env: Env
): Promise<Response> {
  assertSettleAdmin(request, env);

  const format = (url.searchParams.get('format') || 'json').trim().toLowerCase();

  const service = new NettingService(env);
  const report = await service.buildRunReport(runId);

  if (format === 'csv') {
    const csv = service.toRunReportCsv(report);
    return new Response(csv, {
      status: 200,
      headers: {
        'content-type': 'text/csv; charset=utf-8',
        'x-clawsettle-version': resolveVersion(env),
        'x-clawsettle-report-sha256': report.artifact_sha256,
      },
    });
  }

  if (format !== 'json') {
    throw new ClawSettleError('format must be json or csv', 'INVALID_REQUEST', 400, {
      field: 'format',
    });
  }

  return jsonResponse(report, 200, resolveVersion(env));
}

async function router(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;

  const lossEventService = new LossEventService(env);

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
        <li><code>POST /v1/payouts/connect/onboard</code></li>
        <li><code>POST /v1/payouts</code> (idempotency required)</li>
        <li><code>GET /v1/payouts?account_did=...&amp;from=...&amp;to=...&amp;cursor=...&amp;limit=...</code> (admin)</li>
        <li><code>GET /v1/payouts/:id</code></li>
        <li><code>POST /v1/payouts/:id/retry</code> (admin)</li>
        <li><code>GET /v1/payouts/ops/stuck</code> (admin)</li>
        <li><code>GET /v1/payouts/ops/failed</code> (admin)</li>
        <li><code>GET /v1/reconciliation/payouts/daily?date=YYYY-MM-DD&amp;format=json|csv</code> (admin)</li>
        <li><code>POST /v1/netting/runs</code> (admin, idempotency required)</li>
        <li><code>GET /v1/netting/runs/:id</code> (admin)</li>
        <li><code>GET /v1/netting/runs/:id/report?format=json|csv</code> (admin)</li>
        <li><code>POST /v1/loss-events</code> (admin, idempotency required)</li>
        <li><code>GET /v1/loss-events</code> (admin or SETTLE_LOSS_READ_TOKEN)</li>
        <li><code>GET /v1/loss-events/:id</code> (admin or SETTLE_LOSS_READ_TOKEN)</li>
        <li><code>GET /v1/loss-events/outbox</code> (admin or SETTLE_LOSS_READ_TOKEN)</li>
        <li><code>POST /v1/loss-events/ops/retry</code> (admin)</li>
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

  if (request.method === 'POST' && path === '/v1/payouts/connect/onboard') {
    return handleConnectOnboard(request, env);
  }

  if (request.method === 'POST' && path === '/v1/payouts') {
    return handleCreatePayout(request, env);
  }

  if (request.method === 'GET' && path === '/v1/payouts') {
    return handleListPayouts(url, request, env);
  }

  if (request.method === 'GET' && path === '/v1/payouts/ops/stuck') {
    return handleListStuckPayouts(url, request, env);
  }

  if (request.method === 'GET' && path === '/v1/payouts/ops/failed') {
    return handleListFailedPayouts(url, request, env);
  }

  if (request.method === 'GET' && path === '/v1/reconciliation/payouts/daily') {
    return handleDailyReconciliation(url, request, env);
  }

  const payoutById = path.match(/^\/v1\/payouts\/([^/]+)$/);
  if (payoutById && request.method === 'GET') {
    return handleGetPayout(decodeURIComponent(payoutById[1] ?? ''), env);
  }

  const payoutRetry = path.match(/^\/v1\/payouts\/([^/]+)\/retry$/);
  if (payoutRetry && request.method === 'POST') {
    return handleRetryPayout(decodeURIComponent(payoutRetry[1] ?? ''), request, env);
  }

  if (request.method === 'POST' && path === '/v1/netting/runs') {
    return handleCreateNettingRun(request, env);
  }

  // === Loss events (adverse financial event normalization) ===
  if (path === '/v1/loss-events' && request.method === 'POST') {
    assertSettleAdmin(request, env);

    const idempotencyKey = extractIdempotencyKey(request);
    if (!idempotencyKey) {
      throw new ClawSettleError('Missing idempotency key', 'INVALID_REQUEST', 400, {
        field: 'idempotency_key',
      });
    }

    const bodyRaw = await parseJsonRequestBody(request);
    const response = await lossEventService.createLossEvent(bodyRaw, idempotencyKey);

    if (shouldInlineLossEventForwarding(env)) {
      // Best-effort forwarding attempt; durable state persists in outbox.
      await lossEventService.retryForwarding({
        limit: resolveLossEventRetryLimit(env),
        loss_event_id: response.event.loss_event_id,
      });
    }

    return jsonResponse(response, response.deduped ? 200 : 201, resolveVersion(env));
  }

  if (path === '/v1/loss-events' && request.method === 'GET') {
    assertLossEventAuth(request, env, request.method, path);
    const response = await lossEventService.listLossEvents(url);
    return jsonResponse(response, 200, resolveVersion(env));
  }

  if (path === '/v1/loss-events/outbox' && request.method === 'GET') {
    assertLossEventAuth(request, env, request.method, path);
    const response = await lossEventService.listOutbox(url);
    return jsonResponse(response, 200, resolveVersion(env));
  }

  const lossEventByIdMatch = path.match(/^\/v1\/loss-events\/([^/]+)$/);
  if (lossEventByIdMatch && request.method === 'GET') {
    assertLossEventAuth(request, env, request.method, path);
    const response = await lossEventService.getLossEvent(decodeURIComponent(lossEventByIdMatch[1] ?? ''));
    return jsonResponse(response, 200, resolveVersion(env));
  }

  if (path === '/v1/loss-events/ops/retry' && request.method === 'POST') {
    assertSettleAdmin(request, env);

    const contentType = request.headers.get('content-type') ?? '';
    let parsedBody: unknown = null;
    if (contentType.toLowerCase().includes('application/json')) {
      const raw = await request.text();
      if (raw.trim().length > 0) {
        try {
          parsedBody = JSON.parse(raw);
        } catch {
          throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
        }
      }
    }

    const body = LossEventService.parseRetryBody(parsedBody);
    const response = await lossEventService.retryForwarding(body);
    return jsonResponse(response, 200, resolveVersion(env));
  }

  const nettingRunById = path.match(/^\/v1\/netting\/runs\/([^/]+)$/);
  if (nettingRunById && request.method === 'GET') {
    return handleGetNettingRun(decodeURIComponent(nettingRunById[1] ?? ''), request, env);
  }

  const nettingRunReport = path.match(/^\/v1\/netting\/runs\/([^/]+)\/report$/);
  if (nettingRunReport && request.method === 'GET') {
    return handleGetNettingRunReport(
      decodeURIComponent(nettingRunReport[1] ?? ''),
      url,
      request,
      env
    );
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

  async queue(batch: MessageBatch<unknown>, env: Env, _ctx: ExecutionContext): Promise<void> {
    const lossEvents = new LossEventService(env);

    for (const message of batch.messages) {
      try {
        await lossEvents.processQueueMessage(message.body);
        message.ack();
      } catch (error) {
        const messageText = error instanceof Error ? error.message : String(error);
        console.error('[clawsettle] loss-event queue processing failed', messageText);

        const permanent =
          messageText.includes('INVALID_REQUEST') ||
          messageText.includes('NOT_FOUND') ||
          messageText.includes('UNSUPPORTED_CURRENCY');

        if (permanent) {
          message.ack();
        } else {
          message.retry({ delaySeconds: 30 });
        }
      }
    }
  },

  async scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    const stripeService = createStripeWebhookService(env);
    const lossService = new LossEventService(env);

    ctx.waitUntil(
      stripeService.retryFailedForwarding().catch((err) => {
        console.error('scheduled-forwarding-retry-failed', err);
      })
    );

    ctx.waitUntil(
      lossService
        .retryForwarding({
          limit: resolveLossEventRetryLimit(env),
        })
        .catch((err) => {
          console.error('scheduled-loss-forwarding-retry-failed', err);
        })
    );
  },
};
