/**
 * ClawLedger - Event-sourced ledger for balances, holds, and transfers
 * Cloudflare Worker entry point
 */

import { AccountService, isValidDid } from './accounts';
import { EventService, isValidEventType, isValidBucket } from './events';
import type {
  CreateAccountRequest,
  CreateEventRequest,
  Env,
  ErrorResponse,
} from './types';

/**
 * JSON response helper
 */
function jsonResponse<T>(data: T, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Ledger-Version': '1.0.0',
    },
  });
}

/**
 * Error response helper
 */
function errorResponse(
  error: string,
  code: string,
  status: number,
  details?: Record<string, unknown>
): Response {
  const body: ErrorResponse = { error, code, details };
  return jsonResponse(body, status);
}

/**
 * Parse JSON body safely
 */
async function parseJsonBody<T>(request: Request): Promise<T | null> {
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

/**
 * Handle POST /accounts - Create or get account
 */
async function handleCreateAccount(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<CreateAccountRequest>(request);

  if (!body || !body.did) {
    return errorResponse(
      'Missing required field: did',
      'INVALID_REQUEST',
      400
    );
  }

  if (!isValidDid(body.did)) {
    return errorResponse(
      'Invalid DID format. Expected: did:method:identifier',
      'INVALID_DID',
      400
    );
  }

  const service = new AccountService(env);

  try {
    const account = await service.createAccount(body);
    return jsonResponse(account, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'CREATE_FAILED', 500);
  }
}

/**
 * Handle GET /accounts/:did - Get account by DID
 */
async function handleGetAccount(
  did: string,
  env: Env
): Promise<Response> {
  if (!isValidDid(did)) {
    return errorResponse(
      'Invalid DID format. Expected: did:method:identifier',
      'INVALID_DID',
      400
    );
  }

  const service = new AccountService(env);
  const account = await service.getAccount(did);

  if (!account) {
    return errorResponse('Account not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(account);
}

/**
 * Handle GET /accounts/id/:id - Get account by account ID
 */
async function handleGetAccountById(
  id: string,
  env: Env
): Promise<Response> {
  const service = new AccountService(env);
  const account = await service.getAccountById(id);

  if (!account) {
    return errorResponse('Account not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(account);
}

/**
 * Handle POST /events - Create a new ledger event
 */
async function handleCreateEvent(
  request: Request,
  env: Env
): Promise<Response> {
  const body = await parseJsonBody<CreateEventRequest>(request);

  if (!body) {
    return errorResponse('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  // Validate required fields
  if (!body.idempotencyKey) {
    return errorResponse(
      'Missing required field: idempotencyKey',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.eventType) {
    return errorResponse(
      'Missing required field: eventType',
      'INVALID_REQUEST',
      400
    );
  }

  if (!isValidEventType(body.eventType)) {
    return errorResponse(
      `Invalid eventType: ${body.eventType}. Must be one of: mint, burn, transfer, hold, release`,
      'INVALID_EVENT_TYPE',
      400
    );
  }

  if (!body.accountId) {
    return errorResponse(
      'Missing required field: accountId',
      'INVALID_REQUEST',
      400
    );
  }

  if (!body.amount) {
    return errorResponse(
      'Missing required field: amount',
      'INVALID_REQUEST',
      400
    );
  }

  // Validate bucket if provided
  if (body.bucket && !isValidBucket(body.bucket)) {
    return errorResponse(
      `Invalid bucket: ${body.bucket}. Must be one of: available, held, bonded, feePool, promo`,
      'INVALID_BUCKET',
      400
    );
  }

  // Transfer requires toAccountId
  if (body.eventType === 'transfer' && !body.toAccountId) {
    return errorResponse(
      'Transfer events require toAccountId',
      'INVALID_REQUEST',
      400
    );
  }

  const service = new EventService(env);

  try {
    const event = await service.createEvent(body);
    return jsonResponse(event, 201);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse(message, 'CREATE_FAILED', 500);
  }
}

/**
 * Handle GET /events/:id - Get event by ID
 */
async function handleGetEvent(id: string, env: Env): Promise<Response> {
  const service = new EventService(env);
  const event = await service.getEvent(id);

  if (!event) {
    return errorResponse('Event not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(event);
}

/**
 * Handle GET /events/idempotency/:key - Get event by idempotency key
 */
async function handleGetEventByIdempotencyKey(
  key: string,
  env: Env
): Promise<Response> {
  const service = new EventService(env);
  const event = await service.getEventByIdempotencyKey(key);

  if (!event) {
    return errorResponse('Event not found', 'NOT_FOUND', 404);
  }

  return jsonResponse(event);
}

/**
 * Handle GET /accounts/:accountId/events - Get events for an account
 */
async function handleGetAccountEvents(
  accountId: string,
  env: Env,
  url: URL
): Promise<Response> {
  const limitParam = url.searchParams.get('limit');
  const limit = limitParam ? Math.min(parseInt(limitParam, 10), 1000) : 100;

  const service = new EventService(env);
  const events = await service.getAccountEvents(accountId, limit);

  return jsonResponse({ events });
}

/**
 * Handle GET /events/verify - Verify hash chain integrity
 */
async function handleVerifyHashChain(env: Env): Promise<Response> {
  const service = new EventService(env);
  const result = await service.verifyHashChain();

  return jsonResponse(result);
}

/**
 * Router for handling requests
 */
async function router(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // Health check
  if (path === '/health' && method === 'GET') {
    return jsonResponse({ status: 'ok', service: 'ledger' });
  }

  // POST /accounts - Create account
  if (path === '/accounts' && method === 'POST') {
    return handleCreateAccount(request, env);
  }

  // GET /accounts/id/:id - Get account by ID
  const accountByIdMatch = path.match(/^\/accounts\/id\/([^/]+)$/);
  if (accountByIdMatch && method === 'GET') {
    return handleGetAccountById(accountByIdMatch[1], env);
  }

  // GET /accounts/:did - Get account by DID
  // Note: DID format is did:method:identifier, so we need to capture the whole thing
  const accountByDidMatch = path.match(/^\/accounts\/(did:[^/]+)$/);
  if (accountByDidMatch && method === 'GET') {
    return handleGetAccount(decodeURIComponent(accountByDidMatch[1]), env);
  }

  // POST /events - Create event
  if (path === '/events' && method === 'POST') {
    return handleCreateEvent(request, env);
  }

  // GET /events/verify - Verify hash chain
  if (path === '/events/verify' && method === 'GET') {
    return handleVerifyHashChain(env);
  }

  // GET /events/idempotency/:key - Get event by idempotency key
  const eventByIdempotencyMatch = path.match(/^\/events\/idempotency\/([^/]+)$/);
  if (eventByIdempotencyMatch && method === 'GET') {
    return handleGetEventByIdempotencyKey(
      decodeURIComponent(eventByIdempotencyMatch[1]),
      env
    );
  }

  // GET /events/:id - Get event by ID
  const eventByIdMatch = path.match(/^\/events\/([^/]+)$/);
  if (eventByIdMatch && method === 'GET') {
    return handleGetEvent(eventByIdMatch[1], env);
  }

  // GET /accounts/:accountId/events - Get events for an account
  const accountEventsMatch = path.match(/^\/accounts\/([^/]+)\/events$/);
  if (accountEventsMatch && method === 'GET') {
    return handleGetAccountEvents(accountEventsMatch[1], env, url);
  }

  // 404 for unknown routes
  return errorResponse('Not found', 'NOT_FOUND', 404);
}

/**
 * Main worker export
 */
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await router(request, env);
    } catch (err) {
      console.error('Unhandled error:', err);
      const message = err instanceof Error ? err.message : 'Internal server error';
      return errorResponse(message, 'INTERNAL_ERROR', 500);
    }
  },
};
