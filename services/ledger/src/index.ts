/**
 * ClawLedger - Event-sourced ledger for balances, holds, and transfers
 * Cloudflare Worker entry point
 */

import { AccountService, isValidDid } from './accounts';
import type {
  CreateAccountRequest,
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
