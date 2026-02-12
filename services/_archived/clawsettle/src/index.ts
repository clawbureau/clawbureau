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
import {
  classifyDisputeAction,
  DisputeLossEventBridge,
  getDisputeAgingReport,
  getDisputeReconReport,
} from './disputes';
import {
  getEconomyHealth,
  queryOpsAlerts,
  runOpsAlertChecks,
} from './economy-health';
import {
  createPaymentIntent,
} from './stripe-api';
import {
  captureHealthSnapshot,
  queryHealthHistory,
  queryHealthTrends,
  queryWebhookSla,
  queryWebhookFailures,
  queryActiveAlerts,
  evaluateAlertRules,
  logWebhookDelivery,
} from './ops-intelligence';
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

  // Parse the event first for dispute classification (before processWebhook
  // which may reject unknown event types with a non-forwarded response).
  let parsedEvent: import('./types').StripeEvent | null = null;
  try {
    parsedEvent = (await import('./stripe')).parseStripeEvent(rawBody);
  } catch {
    // If parsing fails, processWebhook will handle the error.
  }

  const webhookReceivedAt = new Date().toISOString();
  const webhookT0 = Date.now();
  let webhookDeliveryStatus: 'success' | 'failed' | 'timeout' = 'success';
  let webhookErrorCode: string | undefined;

  let response: import('./types').StripeWebhookResponse;
  try {
    response = await service.processWebhook(rawBody, signature);
  } catch (err) {
    webhookDeliveryStatus = 'failed';
    webhookErrorCode = err instanceof ClawSettleError ? err.code : 'UNKNOWN';
    // Log delivery before re-throwing
    try {
      await logWebhookDelivery(env.DB, {
        event_type: parsedEvent?.type ?? 'unknown',
        source: 'stripe',
        received_at: webhookReceivedAt,
        processing_ms: Date.now() - webhookT0,
        status: webhookDeliveryStatus,
        error_code: webhookErrorCode,
        idempotency_key: parsedEvent?.id ? `stripe:event:${parsedEvent.id}` : undefined,
      });
    } catch { /* best-effort logging */ }
    throw err;
  }

  // Log successful delivery (best-effort, don't fail webhook on logging error)
  try {
    await logWebhookDelivery(env.DB, {
      event_type: response.event_type ?? parsedEvent?.type ?? 'unknown',
      source: 'stripe',
      received_at: webhookReceivedAt,
      processing_ms: Date.now() - webhookT0,
      status: 'success',
      idempotency_key: response.idempotency_key ?? (parsedEvent?.id ? `stripe:event:${parsedEvent.id}` : undefined),
    });
  } catch { /* best-effort */ }

  // After successful webhook processing, check if this is a dispute event
  // and bridge to the loss-event pipeline.
  if (parsedEvent) {
    const disputeAction = classifyDisputeAction(parsedEvent);
    if (disputeAction) {
      const bridge = new DisputeLossEventBridge(env);
      const bridgeResult = await bridge.execute(disputeAction);

      // If the bridge created a loss event and inline forwarding is enabled,
      // trigger best-effort forwarding for the new loss event.
      if (
        bridgeResult.loss_event_id &&
        disputeAction.action === 'create_loss_event' &&
        !bridgeResult.deduped &&
        shouldInlineLossEventForwarding(env)
      ) {
        const lossEventService = new LossEventService(env);
        await lossEventService.retryForwarding({
          limit: resolveLossEventRetryLimit(env),
          loss_event_id: bridgeResult.loss_event_id,
        });
      }

      // If the bridge resolved a loss event and inline forwarding is enabled,
      // trigger best-effort resolve forwarding.
      if (
        bridgeResult.loss_event_id &&
        disputeAction.action === 'resolve_loss_event' &&
        !bridgeResult.deduped &&
        shouldInlineLossEventForwarding(env)
      ) {
        const lossEventService = new LossEventService(env);
        await lossEventService.retryForwarding({
          operation: 'resolve',
          limit: resolveLossEventRetryLimit(env),
          loss_event_id: bridgeResult.loss_event_id,
        });
      }

      return jsonResponse(
        { ...response, dispute_bridge: bridgeResult },
        200,
        resolveVersion(env)
      );
    }
  }

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
        <li><code>POST /v1/loss-events/:id/resolve</code> (admin, idempotency required)</li>
        <li><code>GET /v1/loss-events</code> (admin or SETTLE_LOSS_READ_TOKEN)</li>
        <li><code>GET /v1/loss-events/:id</code> (admin or SETTLE_LOSS_READ_TOKEN)</li>
        <li><code>GET /v1/loss-events/outbox?operation=apply|resolve</code> (admin or SETTLE_LOSS_READ_TOKEN)</li>
        <li><code>POST /v1/loss-events/ops/retry</code> (admin)</li>
      </ul>
      <h3>Stripe dispute automation (ECON-RISK-MAX-003)</h3>
      <p>Dispute events received via <code>POST /v1/stripe/webhook</code> are automatically bridged to the loss-event pipeline:</p>
      <ul>
        <li><code>charge.dispute.created</code> &rarr; creates loss event (apply freeze)</li>
        <li><code>charge.dispute.closed</code> (status=won) &rarr; resolves loss event (unfreeze)</li>
        <li><code>charge.dispute.closed</code> (status=lost) &rarr; marks permanent loss (stays frozen)</li>
        <li><code>charge.dispute.updated</code> &rarr; updates bridge metadata (no state change)</li>
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

  const lossEventResolveMatch = path.match(/^\/v1\/loss-events\/([^/]+)\/resolve$/);
  if (lossEventResolveMatch && request.method === 'POST') {
    assertSettleAdmin(request, env);

    const idempotencyKey = extractIdempotencyKey(request);
    if (!idempotencyKey) {
      throw new ClawSettleError('Missing idempotency key', 'INVALID_REQUEST', 400, {
        field: 'idempotency_key',
      });
    }

    const bodyRaw = await parseJsonRequestBody(request);
    const response = await lossEventService.resolveLossEvent(
      decodeURIComponent(lossEventResolveMatch[1] ?? ''),
      bodyRaw,
      idempotencyKey
    );

    if (shouldInlineLossEventForwarding(env)) {
      await lossEventService.retryForwarding({
        operation: 'resolve',
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

  // ---------------------------------------------------------------------------
  // Dispute aging + reconciliation (MPY-US-015)
  // ---------------------------------------------------------------------------

  if (request.method === 'GET' && path === '/v1/disputes/aging') {
    assertSettleAdmin(request, env);
    const report = await getDisputeAgingReport(env.DB);
    return jsonResponse(report, 200, resolveVersion(env));
  }

  if (request.method === 'GET' && path === '/v1/reconciliation/disputes') {
    assertSettleAdmin(request, env);
    const report = await getDisputeReconReport(env.DB, env);
    return jsonResponse(report, 200, resolveVersion(env));
  }

  if (request.method === 'GET' && path === '/v1/disputes/fees') {
    assertSettleAdmin(request, env);
    const limitParam = url.searchParams.get('limit');
    const statusParam = url.searchParams.get('status');
    const limit = limitParam ? Math.min(Math.max(1, parseInt(limitParam, 10) || 50), 200) : 50;

    let query = 'SELECT * FROM dispute_fees';
    const binds: unknown[] = [];

    if (statusParam && ['pending', 'recorded', 'failed'].includes(statusParam)) {
      query += ' WHERE status = ?';
      binds.push(statusParam);
    }
    query += ' ORDER BY created_at DESC LIMIT ?';
    binds.push(limit);

    const stmt = env.DB.prepare(query);
    const rows = binds.length === 2
      ? await stmt.bind(binds[0], binds[1]).all()
      : await stmt.bind(binds[0]).all();

    return jsonResponse({
      ok: true,
      fees: rows.results ?? [],
      count: (rows.results ?? []).length,
    }, 200, resolveVersion(env));
  }

  // ---------------------------------------------------------------------------
  // Economy health dashboard (ECON-OPS-001)
  // ---------------------------------------------------------------------------

  if (request.method === 'GET' && path === '/v1/economy/health') {
    assertSettleAdmin(request, env);
    const report = await getEconomyHealth(env);
    return jsonResponse(report, 200, resolveVersion(env));
  }

  // ---------------------------------------------------------------------------
  // Ops alerts (ECON-OPS-001 Task 2)
  // ---------------------------------------------------------------------------

  if (request.method === 'GET' && path === '/v1/ops/alerts') {
    assertSettleAdmin(request, env);
    const since = url.searchParams.get('since') ?? undefined;
    const severity = url.searchParams.get('severity') ?? undefined;
    const limitParam = url.searchParams.get('limit');
    const limit = limitParam ? Math.min(Math.max(1, parseInt(limitParam, 10) || 50), 200) : 50;
    const alerts = await queryOpsAlerts(env.DB, { since, severity, limit });
    return jsonResponse({ ok: true, alerts, count: alerts.length }, 200, resolveVersion(env));
  }

  if (request.method === 'POST' && path === '/v1/ops/alerts/check') {
    assertSettleAdmin(request, env);
    const result = await runOpsAlertChecks(env.DB);
    return jsonResponse({ ok: true, ...result }, 200, resolveVersion(env));
  }

  // ---------------------------------------------------------------------------
  // Stripe PaymentIntent creation for escrow funding (ECON-SETTLE-002)
  // ---------------------------------------------------------------------------

  if (request.method === 'POST' && path === '/v1/funding/payment-intent') {
    assertSettleAdmin(request, env);
    const body = await request.json().catch(() => null);
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return errorResponse('Invalid JSON', 'INVALID_REQUEST', 400, undefined, resolveVersion(env));
    }

    const b = body as Record<string, unknown>;
    const escrowId = typeof b.escrow_id === 'string' ? b.escrow_id.trim() : '';
    const accountId = typeof b.account_id === 'string' ? b.account_id.trim() : '';
    const amountMinor = typeof b.amount_minor === 'string' ? b.amount_minor.trim() : '';
    const currency = typeof b.currency === 'string' ? b.currency.trim() : 'USD';
    const idempotencyKey = typeof b.idempotency_key === 'string' ? b.idempotency_key.trim() : '';

    if (!escrowId || !accountId || !amountMinor || !idempotencyKey) {
      return errorResponse(
        'Missing required fields: escrow_id, account_id, amount_minor, idempotency_key',
        'INVALID_REQUEST', 400, undefined, resolveVersion(env)
      );
    }

    if (!/^[0-9]+$/.test(amountMinor) || BigInt(amountMinor) <= 0n) {
      return errorResponse('amount_minor must be a positive integer', 'INVALID_REQUEST', 400, undefined, resolveVersion(env));
    }

    const result = await createPaymentIntent(env, {
      amount_minor: amountMinor,
      currency,
      escrow_id: escrowId,
      account_id: accountId,
      idempotency_key: idempotencyKey,
    });

    return jsonResponse({ ok: true, ...result }, 201, resolveVersion(env));
  }

  // ---------------------------------------------------------------------------
  // ECON-OPS-002: Operational intelligence endpoints
  // ---------------------------------------------------------------------------

  if (request.method === 'GET' && path === '/v1/ops/health/history') {
    assertSettleAdmin(request, env);
    const url = new URL(request.url);
    const hours = parseInt(url.searchParams.get('hours') ?? '24', 10);
    const snapshots = await queryHealthHistory(env.DB, hours);
    return jsonResponse({ ok: true, snapshots, count: snapshots.length }, 200, resolveVersion(env));
  }

  if (request.method === 'GET' && path === '/v1/ops/health/trends') {
    assertSettleAdmin(request, env);
    const url = new URL(request.url);
    const days = parseInt(url.searchParams.get('days') ?? '7', 10);
    const trends = await queryHealthTrends(env.DB, days);
    return jsonResponse({ ok: true, ...trends }, 200, resolveVersion(env));
  }

  if (request.method === 'GET' && path === '/v1/ops/webhooks/sla') {
    assertSettleAdmin(request, env);
    const url = new URL(request.url);
    const hours = parseInt(url.searchParams.get('hours') ?? '24', 10);
    const sla = await queryWebhookSla(env.DB, hours);
    return jsonResponse({ ok: true, ...sla }, 200, resolveVersion(env));
  }

  if (request.method === 'GET' && path === '/v1/ops/webhooks/failures') {
    assertSettleAdmin(request, env);
    const url = new URL(request.url);
    const since = url.searchParams.get('since') ?? new Date(Date.now() - 86400000).toISOString();
    const failures = await queryWebhookFailures(env.DB, since);
    return jsonResponse({ ok: true, failures, count: failures.length }, 200, resolveVersion(env));
  }

  if (request.method === 'GET' && path === '/v1/ops/alerts/active') {
    assertSettleAdmin(request, env);
    const active = await queryActiveAlerts(env.DB);
    return jsonResponse({ ok: true, alerts: active, count: active.length }, 200, resolveVersion(env));
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

    const lossLimit = resolveLossEventRetryLimit(env);

    ctx.waitUntil(
      lossService
        .retryForwarding({
          operation: 'apply',
          limit: lossLimit,
        })
        .catch((err) => {
          console.error('scheduled-loss-forwarding-retry-failed', err);
        })
    );

    ctx.waitUntil(
      lossService
        .retryForwarding({
          operation: 'resolve',
          limit: lossLimit,
        })
        .catch((err) => {
          console.error('scheduled-loss-resolution-forwarding-retry-failed', err);
        })
    );

    // ECON-OPS-001: cron-triggered ops alert checks
    ctx.waitUntil(
      runOpsAlertChecks(env.DB).catch((err) => {
        console.error('scheduled-ops-alert-checks-failed', err);
      })
    );

    // ECON-OPS-002: health snapshot capture (every cron tick = every 2 min)
    ctx.waitUntil(
      captureHealthSnapshot(env).catch((err) => {
        console.error('scheduled-health-snapshot-failed', err);
      })
    );

    // ECON-OPS-002: threshold-based alert evaluation
    ctx.waitUntil(
      evaluateAlertRules(env).catch((err) => {
        console.error('scheduled-alert-rules-failed', err);
      })
    );
  },
};
