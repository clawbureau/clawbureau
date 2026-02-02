/**
 * Clawproxy - Gateway proxy that issues signed receipts for LLM model calls
 *
 * POST /v1/proxy/:provider - Proxy request to provider and return with receipt
 * GET /v1/did - Get proxy DID and public key for verification
 * POST /v1/verify-receipt - Validate receipt signature and return claims
 */

import type { Env, ErrorResponse, Provider, DidResponse, VerificationMethod, Receipt, VerifyReceiptRequest, VerifyReceiptResponse } from './types';
import { isValidProvider, getProviderConfig, buildAuthHeader, buildProviderUrl, extractModel, getSupportedProviders } from './providers';
import { generateReceipt, attachReceipt, createSigningPayload, type SigningContext, type EncryptionContext } from './receipt';
import { importEd25519Key, computeKeyId, base64urlEncode, verifyEd25519, importAesKey } from './crypto';
import { logBlockedProvider, logRateLimited, logPolicyViolation, logPolicyMissing, logConfidentialRequest, logTokenUsed } from './logging';
import { checkRateLimit, buildRateLimitHeaders, type RateLimitInfo } from './ratelimit';
import { extractBindingFromHeaders, checkIdempotency, recordNonce } from './idempotency';
import { validateScopedToken } from './scoped-token';
import {
  extractPolicyFromHeaders,
  enforceProviderAllowlist,
  applyRedactionRules,
  stripUndefined,
  type WorkPolicyContract,
} from './policy';

/** Proxy DID identifier */
const PROXY_DID = 'did:web:clawproxy.com';

/** Cached signing context (initialized on first request) */
let cachedSigningContext: SigningContext | null = null;

/** Cached encryption context (initialized on first request) */
let cachedEncryptionContext: EncryptionContext | null = null;

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

/**
 * Initialize encryption context from environment
 * Returns null if encryption key is not configured
 */
async function initEncryptionContext(env: Env): Promise<EncryptionContext | null> {
  if (cachedEncryptionContext) {
    return cachedEncryptionContext;
  }

  if (!env.PROXY_ENCRYPTION_KEY) {
    return null;
  }

  const aesKey = await importAesKey(env.PROXY_ENCRYPTION_KEY);

  cachedEncryptionContext = {
    key: aesKey.key,
  };

  return cachedEncryptionContext;
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
      return handleDidEndpoint(env, request);
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
 * Handle GET /v1/did - Return proxy DID document with public keys
 * Follows W3C DID Core specification with extensions for proxy metadata
 */
async function handleDidEndpoint(env: Env, request: Request): Promise<Response> {
  const signingContext = await initSigningContext(env);

  if (!signingContext) {
    // Fail closed: signing must be configured
    return errorResponse(
      'SIGNING_NOT_CONFIGURED',
      'Proxy signing key is not configured. Receipt signing is required.',
      503
    );
  }

  // Build full key ID in DID#fragment format
  const fullKeyId = `${signingContext.did}#${signingContext.kid}`;

  // Encode public key in multibase format (base64url with 'u' prefix)
  const publicKeyMultibase = 'u' + base64urlEncode(signingContext.keyPair.publicKeyBytes);

  // Check if encryption is available
  const encryptionEnabled = !!env.PROXY_ENCRYPTION_KEY;

  // Extract region from Cloudflare headers if available
  const cfColo = request.cf?.colo as string | undefined;

  const didResponse: DidResponse = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: signingContext.did,
    verificationMethod: [
      {
        id: fullKeyId,
        type: 'Ed25519VerificationKey2020',
        controller: signingContext.did,
        publicKeyMultibase,
      },
    ],
    authentication: [fullKeyId],
    assertionMethod: [fullKeyId],
    deployment: {
      version: env.PROXY_VERSION,
      signingEnabled: true,
      encryptionEnabled,
      runtime: 'cloudflare-workers',
      region: cfColo,
      service: 'clawproxy',
    },
  };

  // Cache-Control: public, max-age=3600 (1 hour)
  // ETag based on kid for cache validation
  return new Response(JSON.stringify(didResponse), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=3600',
      'ETag': `"${signingContext.kid}"`,
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

  // Return verified claims (including binding fields if present)
  const response: VerifyReceiptResponse = {
    valid: true,
    claims: {
      provider: receipt.provider,
      model: receipt.model,
      proxyDid: receipt.proxyDid as string,
      timestamp: receipt.timestamp,
      kid: receipt.kid as string,
      binding: receipt.binding,
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

  // Check rate limit before processing
  const rateLimitInfo = await checkRateLimit(request, env);
  if (!rateLimitInfo.allowed) {
    // Log rate limited request for monitoring
    logRateLimited(request, rateLimitInfo.key);
    return rateLimitedResponse(rateLimitInfo);
  }

  // Extract binding fields from headers (for proof chaining)
  const binding = extractBindingFromHeaders(request);

  // Scoped token (CST) authentication
  // "Authenticated" calls are those that provide X-Client-DID (used for rate limiting)
  // Fail closed: if X-Client-DID is present, a valid CST must also be present.
  const clientDidHeader = request.headers.get('X-Client-DID');
  const rawCstHeader = request.headers.get('X-CST') ?? request.headers.get('X-Scoped-Token');
  const cstToken = rawCstHeader?.startsWith('Bearer ') ? rawCstHeader.slice(7) : rawCstHeader;

  let validatedCst:
    | {
        token_hash: string;
        claims: {
          sub: string;
          aud: string | string[];
          scope: string[];
          token_scope_hash_b64u: string;
        };
      }
    | undefined;

  if (clientDidHeader && !cstToken) {
    return errorResponseWithRateLimit(
      'TOKEN_REQUIRED',
      'X-CST header required for authenticated requests (when X-Client-DID is set)',
      401,
      rateLimitInfo
    );
  }

  if (cstToken) {
    const url = new URL(request.url);
    const expectedAudiences = Array.from(
      new Set([
        env.CST_AUDIENCE ?? url.hostname,
        url.hostname,
        url.origin,
      ])
    );

    const tokenValidation = await validateScopedToken({
      token: cstToken,
      env,
      expectedAudiences,
      provider: providerParam,
      requiredScopes: ['proxy:call', 'clawproxy:call'],
    });

    if (!tokenValidation.valid) {
      return errorResponseWithRateLimit(
        tokenValidation.code,
        tokenValidation.message,
        tokenValidation.status,
        rateLimitInfo
      );
    }

    // Ensure DID header matches the token subject when both are present
    if (clientDidHeader) {
      const normalizeDid = (did: string): string =>
        did.startsWith('did:') ? did : `did:${did}`;

      if (normalizeDid(clientDidHeader) !== normalizeDid(tokenValidation.claims.sub)) {
        return errorResponseWithRateLimit(
          'TOKEN_SUB_MISMATCH',
          'X-Client-DID does not match CST subject (sub)',
          401,
          rateLimitInfo
        );
      }
    }

    if (typeof tokenValidation.claims.token_scope_hash_b64u !== 'string' || tokenValidation.claims.token_scope_hash_b64u.length === 0) {
      return errorResponseWithRateLimit(
        'TOKEN_SCOPE_HASH_REQUIRED',
        'Token is missing required claim token_scope_hash_b64u (needed for receipt binding)',
        401,
        rateLimitInfo
      );
    }

    validatedCst = {
      token_hash: tokenValidation.token_hash,
      claims: {
        sub: tokenValidation.claims.sub,
        aud: tokenValidation.claims.aud,
        scope: tokenValidation.claims.scope,
        token_scope_hash_b64u: tokenValidation.claims.token_scope_hash_b64u,
      },
    };
  }

  // Check idempotency if nonce is provided
  const idempotencyCheck = checkIdempotency(binding?.nonce);
  if (idempotencyCheck.isDuplicate) {
    // Return previously issued receipt for duplicate request
    return jsonResponseWithRateLimit(idempotencyCheck.existingReceipt, 200, rateLimitInfo);
  }

  // Extract policy information for WPC enforcement
  const policyResult = extractPolicyFromHeaders(request);

  // Fail closed in confidential mode if policy is missing or invalid
  if (policyResult.error) {
    logPolicyMissing(request, policyResult.error);
    return errorResponseWithRateLimit(
      'POLICY_REQUIRED',
      policyResult.error,
      400,
      rateLimitInfo
    );
  }

  // Initialize signing context - fail closed if not configured
  const signingContext = await initSigningContext(env);
  if (!signingContext) {
    return errorResponseWithRateLimit(
      'SIGNING_NOT_CONFIGURED',
      'Proxy signing key is not configured. Receipt signing is required for all proxy requests.',
      503,
      rateLimitInfo
    );
  }

  // Validate provider against allowlist (SSRF prevention)
  if (!isValidProvider(providerParam)) {
    // Log blocked attempt for security monitoring
    logBlockedProvider(request, providerParam);

    const supported = getSupportedProviders().join(', ');
    return errorResponseWithRateLimit(
      'UNKNOWN_PROVIDER',
      `Provider '${providerParam}' is not allowed. Only known provider endpoints are permitted. Supported: ${supported}`,
      400,
      rateLimitInfo
    );
  }

  const provider: Provider = providerParam;
  const config = getProviderConfig(provider);

  // Extract API key from Authorization header
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) {
    return errorResponseWithRateLimit('UNAUTHORIZED', 'Authorization header required', 401, rateLimitInfo);
  }

  // Parse API key (supports both "Bearer <key>" and raw key formats)
  const apiKey = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : authHeader;

  if (!apiKey) {
    return errorResponseWithRateLimit('UNAUTHORIZED', 'API key not provided', 401, rateLimitInfo);
  }

  // Read and validate request body
  let requestBody: string;
  let parsedBody: unknown;

  try {
    requestBody = await request.text();
    parsedBody = JSON.parse(requestBody);
  } catch {
    return errorResponseWithRateLimit('INVALID_REQUEST', 'Request body must be valid JSON', 400, rateLimitInfo);
  }

  // Extract model for receipt
  const model = extractModel(provider, parsedBody);

  // Google Gemini requires model in the URL path
  if (provider === 'google' && !model) {
    return errorResponseWithRateLimit(
      'INVALID_REQUEST',
      'Model field is required for Google Gemini API. Specify "model" in the request body.',
      400,
      rateLimitInfo
    );
  }

  // Enforce WPC provider/model allowlist if policy is active
  if (policyResult.policy) {
    const allowlistResult = enforceProviderAllowlist(provider, model, policyResult.policy);
    if (!allowlistResult.allowed) {
      logPolicyViolation(
        request,
        policyResult.policyHash ?? 'unknown',
        allowlistResult.errorCode ?? 'POLICY_VIOLATION',
        allowlistResult.error ?? 'Policy enforcement failed'
      );
      return errorResponseWithRateLimit(
        allowlistResult.errorCode ?? 'POLICY_VIOLATION',
        allowlistResult.error ?? 'Policy enforcement failed',
        403,
        rateLimitInfo
      );
    }
  }

  // Apply redaction rules to request body if policy specifies them
  let finalRequestBody = requestBody;
  if (policyResult.policy?.redactionRules && policyResult.policy.redactionRules.length > 0) {
    const redactedBody = applyRedactionRules(parsedBody, policyResult.policy.redactionRules);
    const strippedBody = stripUndefined(redactedBody);
    finalRequestBody = JSON.stringify(strippedBody);
  }

  // Build provider-specific URL (Gemini needs model in path)
  let providerUrl: string;
  try {
    providerUrl = buildProviderUrl(provider, model);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponseWithRateLimit('INVALID_REQUEST', message, 400, rateLimitInfo);
  }

  // Forward request to provider (with redacted body if policy requires)
  let providerResponse: Response;
  try {
    providerResponse = await fetch(providerUrl, {
      method: 'POST',
      headers: {
        'Content-Type': config.contentType,
        ...buildAuthHeader(provider, apiKey),
      },
      body: finalRequestBody,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponseWithRateLimit('PROVIDER_ERROR', `Failed to reach provider: ${message}`, 502, rateLimitInfo);
  }

  // Read provider response
  const responseBody = await providerResponse.text();

  // Extend binding with policy hash and CST token scope hash (when present)
  const finalBinding = {
    ...binding,
    policyHash: policyResult.policyHash,
    tokenScopeHashB64u: validatedCst?.claims.token_scope_hash_b64u,
  };

  // Initialize encryption context for encrypted receipts (if privacy mode requests it)
  let encryptionContext: EncryptionContext | null = null;
  if (policyResult.privacyMode === 'encrypted') {
    encryptionContext = await initEncryptionContext(env);
    // If encryption requested but not available, fall back to hash_only
    // This ensures receipts are never left without privacy protection
  }

  // Log confidential requests WITHOUT plaintext (only metadata)
  if (policyResult.confidentialMode) {
    logConfidentialRequest(request, provider, model, policyResult.policyHash);
  }

  // Generate signed receipt with binding fields and privacy mode
  // Note: requestBody here is the final (possibly redacted) body sent to provider
  const receipt = await generateReceipt(
    {
      provider,
      model,
      requestBody: finalRequestBody,
      responseBody,
      startTime,
      binding: finalBinding,
      privacyMode: encryptionContext ? policyResult.privacyMode : 'hash_only',
    },
    signingContext,
    encryptionContext ?? undefined
  );

  // Log token hash with receipt metadata (never log token itself)
  if (validatedCst) {
    logTokenUsed(request, {
      token_hash: validatedCst.token_hash,
      sub: validatedCst.claims.sub,
      aud: validatedCst.claims.aud,
      scope: validatedCst.claims.scope,
      provider,
      model,
      receipt_request_hash: receipt.requestHash,
      receipt_timestamp: receipt.timestamp,
    });
  }

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

    // Record nonce for idempotency (even for provider errors)
    recordNonce(binding?.nonce, withReceipt);

    return jsonResponseWithRateLimit(withReceipt, providerResponse.status, rateLimitInfo);
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

  // Record nonce for idempotency enforcement (if provided)
  recordNonce(binding?.nonce, withReceipt);

  return jsonResponseWithRateLimit(withReceipt, 200, rateLimitInfo);
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

/**
 * Create an error response with rate limit headers
 */
function errorResponseWithRateLimit(
  code: string,
  message: string,
  status: number,
  rateLimitInfo: RateLimitInfo
): Response {
  const error: ErrorResponse = {
    error: { code, message },
  };
  return jsonResponseWithRateLimit(error, status, rateLimitInfo);
}

/**
 * Create a JSON response with rate limit headers
 */
function jsonResponseWithRateLimit(
  data: unknown,
  status: number,
  rateLimitInfo: RateLimitInfo
): Response {
  const rateLimitHeaders = buildRateLimitHeaders(rateLimitInfo);
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Proxy-Version': '0.1.0',
      ...rateLimitHeaders,
    },
  });
}

/**
 * Create a 429 rate limited response
 */
function rateLimitedResponse(rateLimitInfo: RateLimitInfo): Response {
  const error: ErrorResponse = {
    error: {
      code: 'RATE_LIMITED',
      message: 'Rate limit exceeded. Please try again later.',
    },
  };
  const rateLimitHeaders = buildRateLimitHeaders(rateLimitInfo);
  return new Response(JSON.stringify(error), {
    status: 429,
    headers: {
      'Content-Type': 'application/json',
      'X-Proxy-Version': '0.1.0',
      'Retry-After': String(rateLimitInfo.resetTime - Math.floor(Date.now() / 1000)),
      ...rateLimitHeaders,
    },
  });
}
