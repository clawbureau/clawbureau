/**
 * Clawproxy - Gateway proxy that issues signed receipts for LLM model calls
 *
 * POST /v1/proxy/:provider - Proxy request to provider and return with receipt
 * GET /v1/did - Get proxy DID and public key for verification
 * POST /v1/verify-receipt - Validate receipt signature and return claims
 */

import type {
  Env,
  ErrorResponse,
  Provider,
  DidResponse,
  VerificationMethod,
  Receipt,
  ReceiptPayment,
  VerifyReceiptRequest,
  VerifyReceiptResponse,
} from './types';
import { isValidProvider, getProviderConfig, buildAuthHeader, buildProviderUrl, extractModel, getSupportedProviders } from './providers';
import {
  generateReceipt,
  attachReceipt,
  createSigningPayload,
  generateReceiptEnvelope,
  attachReceiptEnvelope,
  type SigningContext,
  type EncryptionContext,
} from './receipt';
import {
  importEd25519Key,
  computeKeyId,
  base64urlEncode,
  verifyEd25519,
  importAesKey,
  didKeyFromEd25519PublicKeyBytes,
} from './crypto';
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
  const didKey = didKeyFromEd25519PublicKeyBytes(keyPair.publicKeyBytes);

  cachedSigningContext = {
    keyPair,
    did: PROXY_DID,
    kid,
    didKey,
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

function stripBearer(value: string | null | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return trimmed.startsWith('Bearer ') ? trimmed.slice(7).trim() : trimmed;
}

function looksLikeJwt(token: string): boolean {
  // JWT (JWS compact) has 3 dot-separated parts.
  const parts = token.split('.');
  return parts.length === 3 && parts.every((p) => p.length > 0);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CPX-US-014: Public landing + docs
    if (request.method === 'GET') {
      if (path === '/') {
        return htmlResponse(
          `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawproxy</title>
  </head>
  <body>
    <main style="max-width: 820px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5;">
      <h1>clawproxy</h1>
      <p>Gateway proxy that issues signed receipts (proof-of-harness) for LLM model calls.</p>
      <ul>
        <li><a href="/docs">Docs</a></li>
        <li><a href="/skill.md">OpenClaw skill</a></li>
        <li><a href="/v1/did">Proxy DID document</a></li>
      </ul>
      <p><small>Version: ${escapeHtml(env.PROXY_VERSION)}</small></p>
    </main>
  </body>
</html>`,
          200,
          env.PROXY_VERSION
        );
      }

      if (path === '/docs') {
        const origin = url.origin;
        return htmlResponse(
          `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawproxy docs</title>
  </head>
  <body>
    <main style="max-width: 820px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5;">
      <h1>clawproxy docs</h1>
      <p>Minimal HTTP API documentation.</p>

      <h2>Endpoints</h2>
      <ul>
        <li><code>POST /v1/proxy/:provider</code> — Proxy a request to a provider and return provider response + <code>_receipt</code> (legacy) + <code>_receipt_envelope</code> (canonical).</li>
        <li><code>GET /v1/did</code> — DID document (public key material for receipt verification).</li>
        <li><code>POST /v1/verify-receipt</code> — Verify a receipt signature and return claims.</li>
        <li><code>GET /health</code> — Health check.</li>
      </ul>

      <h2>Quick start</h2>
      <pre># Recommended (proxy auth via CST + BYOK provider key)
curl -sS -X POST "${escapeHtml(origin)}/v1/proxy/openai" \
  -H "Authorization: Bearer $CST_TOKEN" \
  -H "X-Provider-API-Key: $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'

# Legacy (provider key in Authorization)
curl -sS -X POST "${escapeHtml(origin)}/v1/proxy/openai" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'</pre>

      <p>See also: <a href="/skill.md">/skill.md</a></p>
    </main>
  </body>
</html>`,
          200,
          env.PROXY_VERSION
        );
      }

      if (path === '/skill.md') {
        const metadata = {
          name: 'clawproxy',
          version: '1',
          description:
            'Gateway proxy that issues signed receipts (proof-of-harness) for LLM model calls.',
          endpoints: [
            { method: 'POST', path: '/v1/proxy/:provider' },
            { method: 'GET', path: '/v1/did' },
            { method: 'POST', path: '/v1/verify-receipt' },
          ],
        };

        const md = `---
metadata: '${JSON.stringify(metadata)}'
---

# clawproxy

Proxy requests to supported LLM providers and receive a signed receipt for each call.

## HTTP API

- POST /v1/proxy/:provider
- GET /v1/did
- POST /v1/verify-receipt

## Authentication

### Proxy auth (CST)
- \`Authorization: Bearer <CST>\` (recommended)
- \`X-CST: <CST>\` or \`X-Scoped-Token: <CST>\` (alternate)
- When \`X-Client-DID\` is set, a valid CST token is required (fail-closed).

### BYOK provider keys
- Recommended: \`X-Provider-API-Key: <provider api key>\` (raw or \`Bearer <key>\`)
- Legacy: \`Authorization: Bearer <provider api key>\` (only when Authorization is not used for CST)

## Receipt Binding Headers

Harnesses SHOULD send these headers when routing LLM calls through the proxy to bind receipts to runs and events:

| Header | Description | Example |
|--------|-------------|---------|
| X-Run-Id | Run identifier correlating receipts to a specific agent run | \`run_abc123\` |
| X-Event-Hash | Base64url hash of the event-chain entry that triggered this call | \`dGVzdA\` |
| X-Idempotency-Key | Unique nonce to prevent duplicate receipt issuance | \`nonce_xyz\` |

Binding fields are embedded in the signed receipt and are tamper-proof. The proxy also injects:
- \`policy_hash\`: Work Policy Contract hash (when a WPC is enforced)
- \`token_scope_hash_b64u\`: CST token scope hash (when a scoped token is validated)

See: receipt_binding.v1.json schema for the full specification.

## Notes

- Receipts are signed with the proxy Ed25519 key; retrieve the public key from /v1/did.
- When X-Client-DID is set, a scoped token (CST) may be required, depending on deployment config.
`;

        return textResponse(md, 'text/markdown; charset=utf-8', 200, env.PROXY_VERSION);
      }

      if (path === '/robots.txt') {
        const txt = `User-agent: *
Allow: /
Sitemap: ${url.origin}/sitemap.xml
`;
        return textResponse(txt, 'text/plain; charset=utf-8', 200, env.PROXY_VERSION);
      }

      if (path === '/sitemap.xml') {
        const base = url.origin;
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${escapeXml(base)}/</loc></url>
  <url><loc>${escapeXml(base)}/docs</loc></url>
  <url><loc>${escapeXml(base)}/skill.md</loc></url>
</urlset>
`;
        return textResponse(xml, 'application/xml; charset=utf-8', 200, env.PROXY_VERSION);
      }

      if (path === '/.well-known/security.txt') {
        const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
        const txt = `Contact: mailto:security@clawproxy.com
Preferred-Languages: en
Expires: ${expires}
Canonical: ${url.origin}/.well-known/security.txt
`;
        return textResponse(txt, 'text/plain; charset=utf-8', 200, env.PROXY_VERSION);
      }
    }

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
      receiptSignerDidKey: signingContext.didKey,
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
      payment: receipt.payment,
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

  // Use a stable, server-defined gateway identifier for signed receipts.
  // Do NOT derive this from request host headers, which can be user-controlled.
  const gatewayId = PROXY_DID;

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
  const authorizationHeader = request.headers.get('Authorization');

  const rawCstHeader = request.headers.get('X-CST') ?? request.headers.get('X-Scoped-Token');
  const explicitCstToken = stripBearer(rawCstHeader);
  const authToken = stripBearer(authorizationHeader);

  // Prefer explicit X-CST/X-Scoped-Token. Fall back to Authorization when it looks like a JWT.
  const authorizationIsCst = !explicitCstToken && !!authToken && looksLikeJwt(authToken);

  const cstToken = explicitCstToken ?? (authorizationIsCst ? authToken : undefined);

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
      'CST token required for authenticated requests (when X-Client-DID is set). Provide Authorization: Bearer <CST> or X-CST.',
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

  // CPX-US-013: Platform-paid inference mode (reserve-backed)
  // Provider API keys are accepted via:
  // - X-Provider-API-Key / X-Provider-Authorization (recommended)
  // - Authorization (legacy BYOK mode, when Authorization is NOT used for CST)
  const providerApiKeyHeader =
    request.headers.get('X-Provider-API-Key') ??
    request.headers.get('X-Provider-Key') ??
    request.headers.get('X-Provider-Authorization');

  const explicitProviderApiKey = stripBearer(providerApiKeyHeader);

  // Back-compat: if Authorization is not being used as CST, treat it as a legacy provider API key.
  const legacyProviderApiKey =
    !explicitProviderApiKey && !authorizationIsCst ? authToken : undefined;

  const apiKeyCandidate = explicitProviderApiKey ?? legacyProviderApiKey;

  let apiKey: string;
  let payment: ReceiptPayment;

  if (apiKeyCandidate) {
    apiKey = apiKeyCandidate;
    payment = { mode: 'user', paid: false };
  } else {
    if (env.PLATFORM_PAID_ENABLED !== 'true') {
      return errorResponseWithRateLimit(
        'UNAUTHORIZED',
        'Provider API key required (set X-Provider-API-Key or legacy Authorization). Platform-paid mode is disabled.',
        401,
        rateLimitInfo
      );
    }

    // Fail closed: platform-paid calls must be attributable to an authenticated DID.
    if (!clientDidHeader) {
      return errorResponseWithRateLimit(
        'PLATFORM_PAID_REQUIRES_DID',
        'X-Client-DID is required for platform-paid requests',
        401,
        rateLimitInfo
      );
    }

    const platformApiKey =
      provider === 'anthropic'
        ? env.PLATFORM_ANTHROPIC_API_KEY
        : provider === 'openai'
          ? env.PLATFORM_OPENAI_API_KEY
          : env.PLATFORM_GOOGLE_API_KEY;

    if (!platformApiKey || platformApiKey.trim().length === 0) {
      return errorResponseWithRateLimit(
        'PLATFORM_API_KEY_NOT_CONFIGURED',
        `Platform API key not configured for provider '${provider}'`,
        503,
        rateLimitInfo
      );
    }

    apiKey = platformApiKey;

    const ledgerRef = binding?.nonce
      ? `clawledger:reserve:${binding.nonce}`
      : `clawledger:reserve:${crypto.randomUUID()}`;

    payment = { mode: 'platform', paid: true, ledgerRef };
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
      payment,
      privacyMode: encryptionContext ? policyResult.privacyMode : 'hash_only',
    },
    signingContext,
    encryptionContext ?? undefined
  );

  const receiptEnvelope = await generateReceiptEnvelope(receipt, signingContext, {
    gatewayId,
  });

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

    const withReceipt = attachReceiptEnvelope(
      attachReceipt({ error: errorObj, status: providerResponse.status }, receipt),
      receiptEnvelope
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

  const withReceipt = attachReceiptEnvelope(
    attachReceipt(responseObj, receipt),
    receiptEnvelope
  );

  // Record nonce for idempotency enforcement (if provided)
  recordNonce(binding?.nonce, withReceipt);

  return jsonResponseWithRateLimit(withReceipt, 200, rateLimitInfo);
}

/**
 * Escape text for HTML contexts
 */
function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Escape text for XML contexts
 */
function escapeXml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function textResponse(
  body: string,
  contentType: string,
  status: number,
  version: string
): Response {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': contentType,
      'X-Proxy-Version': version,
    },
  });
}

function htmlResponse(html: string, status: number, version: string): Response {
  return textResponse(html, 'text/html; charset=utf-8', status, version);
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
