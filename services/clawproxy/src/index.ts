/**
 * Clawproxy - Gateway proxy that issues signed receipts for LLM model calls
 *
 * POST /v1/proxy/:provider - Proxy request to provider and return with receipt
 */

import type { Env, ErrorResponse, Provider } from './types';
import { isValidProvider, getProviderConfig, buildAuthHeader, extractModel } from './providers';
import { generateReceipt, attachReceipt } from './receipt';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Health check endpoint
    if (path === '/health' && request.method === 'GET') {
      return jsonResponse({ status: 'ok', version: env.PROXY_VERSION });
    }

    // Proxy endpoint: POST /v1/proxy/:provider
    const proxyMatch = path.match(/^\/v1\/proxy\/([^/]+)$/);
    if (proxyMatch && request.method === 'POST') {
      const provider = proxyMatch[1];
      if (!provider) {
        return errorResponse('INVALID_PATH', 'Provider not specified', 400);
      }
      return handleProxy(request, env, provider);
    }

    return errorResponse('NOT_FOUND', `Unknown endpoint: ${path}`, 404);
  },
};

/**
 * Handle proxy request to LLM provider
 */
async function handleProxy(
  request: Request,
  _env: Env,
  providerParam: string
): Promise<Response> {
  const startTime = Date.now();

  // Validate provider
  if (!isValidProvider(providerParam)) {
    return errorResponse(
      'UNKNOWN_PROVIDER',
      `Provider '${providerParam}' is not supported. Supported: anthropic, openai`,
      400
    );
  }

  const provider: Provider = providerParam;
  const config = getProviderConfig(provider);

  // Extract API key from Authorization header
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) {
    return errorResponse('UNAUTHORIZED', 'Authorization header required', 401);
  }

  // Parse API key (supports both "Bearer <key>" and raw key formats)
  const apiKey = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : authHeader;

  if (!apiKey) {
    return errorResponse('UNAUTHORIZED', 'API key not provided', 401);
  }

  // Read and validate request body
  let requestBody: string;
  let parsedBody: unknown;

  try {
    requestBody = await request.text();
    parsedBody = JSON.parse(requestBody);
  } catch {
    return errorResponse('INVALID_REQUEST', 'Request body must be valid JSON', 400);
  }

  // Extract model for receipt
  const model = extractModel(provider, parsedBody);

  // Forward request to provider
  let providerResponse: Response;
  try {
    providerResponse = await fetch(config.baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': config.contentType,
        ...buildAuthHeader(provider, apiKey),
      },
      body: requestBody,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('PROVIDER_ERROR', `Failed to reach provider: ${message}`, 502);
  }

  // Read provider response
  const responseBody = await providerResponse.text();

  // Generate receipt
  const receipt = await generateReceipt({
    provider,
    model,
    requestBody,
    responseBody,
    startTime,
  });

  // If provider returned an error, pass it through with receipt
  if (!providerResponse.ok) {
    let errorObj: unknown;
    try {
      errorObj = JSON.parse(responseBody);
    } catch {
      errorObj = { raw: responseBody };
    }

    const withReceipt = attachReceipt(
      { error: errorObj, status: providerResponse.status },
      receipt
    );

    return jsonResponse(withReceipt, providerResponse.status);
  }

  // Parse successful response and attach receipt
  let responseObj: object;
  try {
    responseObj = JSON.parse(responseBody) as object;
  } catch {
    // If response isn't JSON, wrap it
    responseObj = { data: responseBody };
  }

  const withReceipt = attachReceipt(responseObj, receipt);
  return jsonResponse(withReceipt);
}

/**
 * Create a JSON response
 */
function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Proxy-Version': '0.1.0',
    },
  });
}

/**
 * Create an error response
 */
function errorResponse(code: string, message: string, status: number): Response {
  const error: ErrorResponse = {
    error: { code, message },
  };
  return jsonResponse(error, status);
}
