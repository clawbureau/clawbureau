/**
 * Clawproxy - Gateway proxy that issues signed receipts for LLM model calls
 *
 * POST /v1/proxy/:provider - Proxy request to provider and return with receipt
 * GET /v1/did - Get proxy DID and public key for verification
 * POST /v1/verify-receipt - Validate receipt signature and return claims
 */

import type { Env, ErrorResponse, Provider, DidResponse, Receipt, VerifyReceiptRequest, VerifyReceiptResponse } from './types';
import { isValidProvider, getProviderConfig, buildAuthHeader, buildProviderUrl, extractModel, getSupportedProviders } from './providers';
import { generateReceipt, attachReceipt, createSigningPayload, type SigningContext } from './receipt';
import { importEd25519Key, computeKeyId, base64urlEncode, verifyEd25519 } from './crypto';
import { logBlockedProvider } from './logging';

/** Proxy DID identifier */
const PROXY_DID = 'did:web:clawproxy.com';

/** Cached signing context (initialized on first request) */
let cachedSigningContext: SigningContext | null = null;

/**
 * Initialize signing context from environment
 * Returns null if signing key is not configured
 */
async function initSigningContext(env: Env): Promise<SigningContext | null> {
  if (cachedSigningContext) {
    return cachedSigningContext;
  }

  if (!env.PROXY_SIGNING_KEY) {
    return null;
  }

  const keyPair = await importEd25519Key(env.PROXY_SIGNING_KEY);
  const kid = await computeKeyId(keyPair.publicKeyBytes);

  cachedSigningContext = {
    keyPair,
    did: PROXY_DID,
    kid,
  };

  return cachedSigningContext;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Health check endpoint
    if (path === '/health' && request.method === 'GET') {
      const signingContext = await initSigningContext(env);
      return jsonResponse({
        status: 'ok',
        version: env.PROXY_VERSION,
        signingEnabled: signingContext !== null,
      });
    }

    // DID endpoint: GET /v1/did
    if (path === '/v1/did' && request.method === 'GET') {
      return handleDidEndpoint(env);
    }

    // Verify receipt endpoint: POST /v1/verify-receipt
    if (path === '/v1/verify-receipt' && request.method === 'POST') {
      return handleVerifyReceipt(request, env);
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
 * Handle GET /v1/did - Return proxy DID and public key
 */
async function handleDidEndpoint(env: Env): Promise<Response> {
  const signingContext = await initSigningContext(env);

  if (!signingContext) {
    // Fail closed: signing must be configured
    return errorResponse(
      'SIGNING_NOT_CONFIGURED',
      'Proxy signing key is not configured. Receipt signing is required.',
      503
    );
  }

  const publicKeyBase64url = base64urlEncode(signingContext.keyPair.publicKeyBytes);

  const didResponse: DidResponse = {
    did: signingContext.did,
    publicKey: publicKeyBase64url,
    kid: signingContext.kid,
    algorithm: 'Ed25519',
    deployment: {
      version: env.PROXY_VERSION,
      signingEnabled: true,
    },
  };

  // Cache-Control: public, max-age=3600 (1 hour)
  return new Response(JSON.stringify(didResponse), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600',
      'X-Proxy-Version': env.PROXY_VERSION,
    },
  });
}

/**
 * Handle POST /v1/verify-receipt - Validate receipt signature and return claims
 */
async function handleVerifyReceipt(request: Request, env: Env): Promise<Response> {
  // Initialize signing context to get the public key
  const signingContext = await initSigningContext(env);

  if (!signingContext) {
    return errorResponse(
      'SIGNING_NOT_CONFIGURED',
      'Proxy signing key is not configured. Cannot verify receipts.',
      503
    );
  }

  // Parse request body
  let body: VerifyReceiptRequest;
  try {
    body = await request.json() as VerifyReceiptRequest;
  } catch {
    return errorResponse('INVALID_REQUEST', 'Request body must be valid JSON', 400);
  }

  // Validate receipt structure
  const receipt = body.receipt;
  if (!receipt) {
    return errorResponse('INVALID_REQUEST', 'Missing "receipt" field in request body', 400);
  }

  // Verify required fields exist
  const validationResult = validateReceiptStructure(receipt);
  if (!validationResult.valid) {
    const response: VerifyReceiptResponse = {
      valid: false,
      error: validationResult.error,
    };
    return jsonResponse(response);
  }

  // Verify the receipt was signed by this proxy
  if (receipt.proxyDid !== signingContext.did) {
    const response: VerifyReceiptResponse = {
      valid: false,
      error: `Receipt was not signed by this proxy. Expected DID: ${signingContext.did}, got: ${receipt.proxyDid}`,
    };
    return jsonResponse(response);
  }

  // Verify the key ID matches
  if (receipt.kid !== signingContext.kid) {
    const response: VerifyReceiptResponse = {
      valid: false,
      error: `Receipt was signed with unknown key. Expected kid: ${signingContext.kid}, got: ${receipt.kid}`,
    };
    return jsonResponse(response);
  }

  // Verify the signature
  const payloadToVerify = createSigningPayload(receipt);
  let signatureValid: boolean;

  try {
    signatureValid = await verifyEd25519(
      signingContext.keyPair.publicKey,
      receipt.signature as string,
      payloadToVerify
    );
  } catch {
    const response: VerifyReceiptResponse = {
      valid: false,
      error: 'Failed to verify signature: invalid signature format',
    };
    return jsonResponse(response);
  }

  if (!signatureValid) {
    const response: VerifyReceiptResponse = {
      valid: false,
      error: 'Signature verification failed',
    };
    return jsonResponse(response);
  }

  // Return verified claims
  const response: VerifyReceiptResponse = {
    valid: true,
    claims: {
      provider: receipt.provider,
      model: receipt.model,
      proxyDid: receipt.proxyDid as string,
      timestamp: receipt.timestamp,
      kid: receipt.kid as string,
    },
  };

  return jsonResponse(response);
}

/**
 * Validate receipt structure has all required fields for verification
 */
function validateReceiptStructure(receipt: Receipt): { valid: true } | { valid: false; error: string } {
  if (!receipt.version) {
    return { valid: false, error: 'Missing required field: version' };
  }
  if (!receipt.provider) {
    return { valid: false, error: 'Missing required field: provider' };
  }
  if (!receipt.requestHash) {
    return { valid: false, error: 'Missing required field: requestHash' };
  }
  if (!receipt.responseHash) {
    return { valid: false, error: 'Missing required field: responseHash' };
  }
  if (!receipt.timestamp) {
    return { valid: false, error: 'Missing required field: timestamp' };
  }
  if (receipt.latencyMs === undefined) {
    return { valid: false, error: 'Missing required field: latencyMs' };
  }
  if (!receipt.proxyDid) {
    return { valid: false, error: 'Missing required field: proxyDid (receipt is unsigned)' };
  }
  if (!receipt.kid) {
    return { valid: false, error: 'Missing required field: kid' };
  }
  if (!receipt.signature) {
    return { valid: false, error: 'Missing required field: signature' };
  }

  return { valid: true };
}

/**
 * Handle proxy request to LLM provider
 */
async function handleProxy(
  request: Request,
  env: Env,
  providerParam: string
): Promise<Response> {
  const startTime = Date.now();

  // Initialize signing context - fail closed if not configured
  const signingContext = await initSigningContext(env);
  if (!signingContext) {
    return errorResponse(
      'SIGNING_NOT_CONFIGURED',
      'Proxy signing key is not configured. Receipt signing is required for all proxy requests.',
      503
    );
  }

  // Validate provider against allowlist (SSRF prevention)
  if (!isValidProvider(providerParam)) {
    // Log blocked attempt for security monitoring
    logBlockedProvider(request, providerParam);

    const supported = getSupportedProviders().join(', ');
    return errorResponse(
      'UNKNOWN_PROVIDER',
      `Provider '${providerParam}' is not allowed. Only known provider endpoints are permitted. Supported: ${supported}`,
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

  // Google Gemini requires model in the URL path
  if (provider === 'google' && !model) {
    return errorResponse(
      'INVALID_REQUEST',
      'Model field is required for Google Gemini API. Specify "model" in the request body.',
      400
    );
  }

  // Build provider-specific URL (Gemini needs model in path)
  let providerUrl: string;
  try {
    providerUrl = buildProviderUrl(provider, model);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('INVALID_REQUEST', message, 400);
  }

  // Forward request to provider
  let providerResponse: Response;
  try {
    providerResponse = await fetch(providerUrl, {
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

  // Generate signed receipt
  const receipt = await generateReceipt(
    {
      provider,
      model,
      requestBody,
      responseBody,
      startTime,
    },
    signingContext
  );

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
