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
  PlatformFundingCheckContext,
  PlatformPaymentAccountBindingContext,
  DelegationSpendCheckContext,
  PaymentAccountDidSource,
  VerifyReceiptRequest,
  VerifyReceiptResponse,
} from './types';
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import {
  isValidProvider,
  getProviderConfig,
  buildAuthHeader,
  buildProviderUrl,
  extractModel,
  getSupportedProviders,
  isFalOpenrouterModel,
  stripOpenrouterModelPrefix,
  buildFalOpenrouterUrl,
  buildFalOpenrouterAuthHeader,
  type OpenAIUpstreamApi,
} from './providers';
import {
  generateReceipt,
  generateReceiptFromHashes,
  attachReceipt,
  createSigningPayload,
  generateReceiptEnvelope,
  attachReceiptEnvelope,
  type SigningContext,
  type EncryptionContext,
} from './receipt';
import { isRtEnabled, submitReceiptToRt } from './rt';
import { buildReceiptMetadataWithModelIdentity } from './model-identity';
import {
  importEd25519Key,
  computeKeyId,
  base64urlEncode,
  base64urlDecode,
  sha256,
  verifyEd25519,
  importAesKey,
  didKeyFromEd25519PublicKeyBytes,
} from './crypto';
import { logBlockedProvider, logRateLimited, logPolicyViolation, logPolicyMissing, logConfidentialRequest, logTokenUsed } from './logging';
import {
  isX402Enabled,
  hasX402Payment,
  buildPaymentRequiredResponse,
  verifyX402Payment,
  settleX402Payment,
  buildX402ReceiptMetadata,
  type X402PaymentPayload,
  type X402PaymentRequirements,
  type X402PaymentContext,
} from './x402';
import { checkRateLimit, buildRateLimitHeaders, type RateLimitInfo } from './ratelimit';
import {
  extractBindingFromHeaders,
  computeIdempotencyFingerprint,
  checkIdempotencyAndLock,
  readIdempotencyReceipt,
  commitIdempotency,
  releaseIdempotency,
} from './idempotency';

// Durable Object export (wrangler binding class_name = "IdempotencyDurableObject")
export { IdempotencyDurableObject } from './idempotency';

import { validateScopedToken } from './scoped-token';
import { computeTokenScopeHashB64uV1 } from './token-scope-hash';
import {
  extractPolicyFromHeaders,
  enforceProviderAllowlist,
  enforceMinimumModelIdentityTier,
  applyRedactionRules,
  stripUndefined,
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

  const m = trimmed.match(/^Bearer\s+/i);
  return m ? trimmed.slice(m[0].length).trim() : trimmed;
}

const JWT_TOKEN_MAX_LEN = 8192;
const JWT_HEADER_B64U_MAX_LEN = 2048;

function looksLikeJwt(token: string): boolean {
  // Minimal strict JWT (JWS compact) check (cheap + UTF-8 correct):
  // - cap token length (avoid expensive parsing work)
  // - 3 dot-separated parts
  // - header part base64url-decodes
  // - header bytes decode as UTF-8 JSON with string "alg"
  if (token.length > JWT_TOKEN_MAX_LEN) return false;

  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [headerB64u] = parts;
  if (!headerB64u) return false;
  if (headerB64u.length > JWT_HEADER_B64U_MAX_LEN) return false;

  let headerBytes: Uint8Array;
  try {
    headerBytes = base64urlDecode(headerB64u);
  } catch {
    return false;
  }

  try {
    const headerJson = new TextDecoder('utf-8', {
      fatal: false,
      ignoreBOM: true,
    }).decode(headerBytes);
    const header = JSON.parse(headerJson) as { alg?: unknown };
    return typeof header.alg === 'string' && header.alg.trim().length > 0;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Streaming helpers
// ---------------------------------------------------------------------------

function isStreamingRequested(body: unknown, request: Request): boolean {
  // Prefer explicit stream flag in JSON body (OpenAI/Anthropic).
  if (body && typeof body === 'object') {
    const maybe = body as Record<string, unknown>;
    if (maybe.stream === true) return true;
  }

  const accept = request.headers.get('accept');
  return typeof accept === 'string' && accept.toLowerCase().includes('text/event-stream');
}

function isEventStreamContentType(contentType: string | null): boolean {
  if (!contentType) return false;
  return contentType.toLowerCase().includes('text/event-stream');
}

function base64urlEncodeJson(value: unknown): string {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  return base64urlEncode(bytes);
}

function inferOpenAiUpstreamApi(request: Request, body: unknown): OpenAIUpstreamApi {
  const path = new URL(request.url).pathname;

  // Provider-compatible routes (explicit)
  if (path === '/v1/responses') return 'responses';
  if (path === '/v1/chat/completions') return 'chat_completions';

  // Optional explicit override header for power users.
  const explicit =
    request.headers.get('X-OpenAI-API') ??
    request.headers.get('X-OpenAI-Endpoint') ??
    request.headers.get('X-Upstream-Endpoint');

  if (explicit) {
    const v = explicit.trim().toLowerCase();
    if (v === 'responses' || v === '/v1/responses') return 'responses';
    if (v === 'chat_completions' || v === 'chat/completions' || v === '/v1/chat/completions') {
      return 'chat_completions';
    }
  }

  // Heuristic for /v1/proxy/openai: OpenAI Responses uses `input`, chat completions uses `messages`.
  if (body && typeof body === 'object') {
    const b = body as Record<string, unknown>;
    const hasInput = Object.prototype.hasOwnProperty.call(b, 'input');
    const hasMessages = Object.prototype.hasOwnProperty.call(b, 'messages');
    if (hasInput && !hasMessages) return 'responses';
  }

  return 'chat_completions';
}

type PlatformFundingCheckResult =
  | {
      ok: true;
      context: PlatformFundingCheckContext;
    }
  | {
      ok: false;
      code: 'PAYMENT_REQUIRED' | 'PAYMENT_CHECK_UNAVAILABLE';
      status: 402 | 503;
      message: string;
    };

type PlatformPaymentAccountBindingResult =
  | {
      ok: true;
      accountDid: string;
      accountDidSource: PaymentAccountDidSource;
      context: PlatformPaymentAccountBindingContext;
    }
  | {
      ok: false;
      code:
        | 'PAYMENT_ACCOUNT_BINDING_REQUIRED'
        | 'PAYMENT_ACCOUNT_CLAIM_MISMATCH'
        | 'PAYMENT_ACCOUNT_CLAIM_INVALID'
        | 'PAYMENT_REQUIRED';
      status: 401 | 402;
      message: string;
    };

function readNonEmptyHeader(request: Request, name: string): string | undefined {
  const raw = request.headers.get(name);
  if (!raw) return undefined;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function isNonNegativeIntegerString(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9]+$/.test(value);
}

function normalizeBaseUrl(urlRaw: string): string {
  return urlRaw.replace(/\/+$/, '');
}

function parsePlatformPaidMinimumMinor(raw: string | undefined): bigint {
  if (!raw || raw.trim().length === 0) {
    return 1n;
  }

  const trimmed = raw.trim();
  if (!/^[0-9]+$/.test(trimmed)) {
    throw new Error('PLATFORM_PAID_MIN_AVAILABLE_MINOR must be a non-negative integer string');
  }

  return BigInt(trimmed);
}

function parseBooleanFlag(raw: string | undefined): boolean {
  if (!raw) return false;
  const normalized = raw.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'y';
}

type DelegatedSpendAuthorizeResult =
  | {
      ok: true;
      context: DelegationSpendCheckContext;
    }
  | {
      ok: false;
      code:
        | 'DELEGATION_BINDING_REQUIRED'
        | 'DELEGATION_BINDING_INVALID'
        | 'DELEGATION_SPEND_CHECK_UNAVAILABLE'
        | 'DELEGATION_SPEND_CAP_EXCEEDED';
      status: 401 | 402 | 503;
      message: string;
    };

function parsePositiveMinor(value: string, label: string): bigint {
  const trimmed = value.trim();
  if (!/^[0-9]+$/.test(trimmed)) {
    throw new Error(`${label} must be an integer string`);
  }

  const amount = BigInt(trimmed);
  if (amount <= 0n) {
    throw new Error(`${label} must be > 0`);
  }

  return amount;
}

function parseDefaultDelegatedSpendMinor(raw: string | undefined): bigint {
  if (!raw || raw.trim().length === 0) return 1n;
  return parsePositiveMinor(raw, 'CLAWDELEGATE_DEFAULT_SPEND_MINOR');
}

function parseDelegatedSpendMinorFromRequest(request: Request, fallback: bigint): bigint {
  const header = request.headers.get('X-Delegation-Spend-Minor');
  if (!header || header.trim().length === 0) return fallback;
  return parsePositiveMinor(header, 'X-Delegation-Spend-Minor');
}

function parseDelegateTimeoutMs(raw: string | undefined): number {
  const parsed = Number.parseInt(raw ?? '5000', 10);
  if (!Number.isFinite(parsed) || parsed < 500) return 5000;
  return parsed;
}

async function fetchWithAbort(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function runDelegatedSpendAuthorize(params: {
  env: Env;
  delegationId: string;
  actorDid: string;
  tokenHash: string;
  tokenScopeHashB64u: string;
  amountMinor: string;
  idempotencyKey: string;
  provider: string;
  model?: string;
}): Promise<DelegatedSpendAuthorizeResult> {
  const baseUrlRaw = params.env.CLAWDELEGATE_BASE_URL?.trim();
  const serviceKey = params.env.CLAWDELEGATE_PROXY_KEY?.trim();

  if (!baseUrlRaw || !serviceKey) {
    return {
      ok: false,
      code: 'DELEGATION_SPEND_CHECK_UNAVAILABLE',
      status: 503,
      message: 'clawdelegate spend checks are not configured',
    };
  }

  const baseUrl = normalizeBaseUrl(baseUrlRaw);
  const timeoutMs = parseDelegateTimeoutMs(params.env.CLAWDELEGATE_TIMEOUT_MS);

  try {
    const response = await fetchWithAbort(
      `${baseUrl}/v1/delegations/${encodeURIComponent(params.delegationId)}/spend/authorize`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json; charset=utf-8',
          authorization: `Bearer ${serviceKey}`,
        },
        body: JSON.stringify({
          idempotency_key: params.idempotencyKey,
          actor_did: params.actorDid,
          token_hash: params.tokenHash,
          token_scope_hash_b64u: params.tokenScopeHashB64u,
          amount_minor: params.amountMinor,
          reason: `proxy:${params.provider}:${params.model ?? 'unknown'}`,
        }),
      },
      timeoutMs
    );

    const text = await response.text();
    let payload: Record<string, unknown> | null = null;
    try {
      payload = text ? (JSON.parse(text) as Record<string, unknown>) : null;
    } catch {
      payload = null;
    }

    if (!response.ok || !payload) {
      const upstreamCode =
        payload && typeof payload.error === 'string' && payload.error.trim().length > 0
          ? payload.error.trim()
          : 'DELEGATION_SPEND_CHECK_UNAVAILABLE';

      if (upstreamCode === 'DELEGATION_SPEND_CAP_EXCEEDED') {
        return {
          ok: false,
          code: 'DELEGATION_SPEND_CAP_EXCEEDED',
          status: 402,
          message: 'Delegation spend cap exceeded',
        };
      }

      const message =
        payload && typeof payload.message === 'string' && payload.message.trim().length > 0
          ? payload.message.trim()
          : `delegation spend authorization failed with status ${response.status}`;

      return {
        ok: false,
        code: 'DELEGATION_SPEND_CHECK_UNAVAILABLE',
        status: response.status >= 500 ? 503 : 401,
        message,
      };
    }

    const result = payload.result;
    if (!result || typeof result !== 'object') {
      return {
        ok: false,
        code: 'DELEGATION_SPEND_CHECK_UNAVAILABLE',
        status: 503,
        message: 'delegation spend response is invalid',
      };
    }

    const row = result as Record<string, unknown>;
    const status = typeof row.status === 'string' ? row.status : null;
    const reservedMinor = typeof row.reserved_minor === 'string' ? row.reserved_minor : null;
    const consumedMinor = typeof row.consumed_minor === 'string' ? row.consumed_minor : null;
    const spendCapMinor = typeof row.spend_cap_minor === 'string' ? row.spend_cap_minor : null;
    const amountMinor = typeof row.amount_minor === 'string' ? row.amount_minor : null;
    const idempotencyKey = typeof row.idempotency_key === 'string' ? row.idempotency_key : null;

    if (
      (status !== 'applied' && status !== 'already_applied') ||
      !reservedMinor ||
      !consumedMinor ||
      !spendCapMinor ||
      !amountMinor ||
      !idempotencyKey
    ) {
      return {
        ok: false,
        code: 'DELEGATION_SPEND_CHECK_UNAVAILABLE',
        status: 503,
        message: 'delegation spend response is malformed',
      };
    }

    const normalizedStatus: DelegationSpendCheckContext['status'] =
      status === 'applied' ? 'authorized' : 'already_applied';

    return {
      ok: true,
      context: {
        status: normalizedStatus,
        delegationId: params.delegationId,
        amountMinor,
        idempotencyKey,
        reservedMinor,
        consumedMinor,
        spendCapMinor,
        checkedAt: new Date().toISOString(),
      },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error';
    return {
      ok: false,
      code: 'DELEGATION_SPEND_CHECK_UNAVAILABLE',
      status: 503,
      message,
    };
  }
}

const DID_RE = /^did:[a-z0-9]+:[a-zA-Z0-9._%-]+$/;

function normalizeDid(did: string): string {
  const trimmed = did.trim();
  return trimmed.startsWith('did:') ? trimmed : `did:${trimmed}`;
}

function isDid(value: string): boolean {
  return DID_RE.test(normalizeDid(value));
}

function resolvePaymentAccountDid(params: {
  request: Request;
  clientDidHeader: string | null;
  cstSub?: string;
}): { accountDid?: string; source?: PaymentAccountDidSource } {
  const fromPaymentHeader = readNonEmptyHeader(params.request, 'X-Payment-Account-DID');
  if (fromPaymentHeader) {
    return { accountDid: fromPaymentHeader, source: 'x-payment-account-did' };
  }

  const fromClientDid = params.clientDidHeader?.trim();
  if (fromClientDid && fromClientDid.length > 0) {
    return { accountDid: fromClientDid, source: 'x-client-did' };
  }

  const fromCstSub = params.cstSub?.trim();
  if (fromCstSub && fromCstSub.length > 0) {
    return { accountDid: fromCstSub, source: 'cst-sub' };
  }

  return {};
}

function resolvePlatformPaymentAccountBinding(params: {
  resolvedRequestAccount: { accountDid?: string; source?: PaymentAccountDidSource };
  claimPaymentAccountDid?: string;
  claimRequired: boolean;
}): PlatformPaymentAccountBindingResult {
  const claimRaw = params.claimPaymentAccountDid?.trim();
  const claimPresent = !!claimRaw && claimRaw.length > 0;

  if (claimPresent) {
    if (!isDid(claimRaw)) {
      return {
        ok: false,
        code: 'PAYMENT_ACCOUNT_CLAIM_INVALID',
        status: 401,
        message: 'CST payment_account_did claim is invalid',
      };
    }

    const normalizedClaimDid = normalizeDid(claimRaw);

    const requestAccountRaw = params.resolvedRequestAccount.accountDid?.trim();
    const requestAccountSource = params.resolvedRequestAccount.source;

    if (requestAccountRaw && requestAccountRaw.length > 0) {
      if (!isDid(requestAccountRaw)) {
        return {
          ok: false,
          code: 'PAYMENT_ACCOUNT_CLAIM_INVALID',
          status: 401,
          message: 'Payment account context is invalid',
        };
      }

      const normalizedRequestDid = normalizeDid(requestAccountRaw);
      if (normalizedRequestDid !== normalizedClaimDid) {
        return {
          ok: false,
          code: 'PAYMENT_ACCOUNT_CLAIM_MISMATCH',
          status: 401,
          message: 'CST payment_account_did claim does not match request payment account context',
        };
      }
    }

    return {
      ok: true,
      accountDid: normalizedClaimDid,
      accountDidSource: 'cst-payment-account-did',
      context: {
        status: 'matched',
        claimRequired: params.claimRequired,
        claimPresent: true,
        claimAccountDid: normalizedClaimDid,
        requestAccountDid: requestAccountRaw ? normalizeDid(requestAccountRaw) : undefined,
        requestAccountDidSource: requestAccountSource,
        effectiveAccountDid: normalizedClaimDid,
        effectiveAccountDidSource: 'cst-payment-account-did',
      },
    };
  }

  if (params.claimRequired) {
    return {
      ok: false,
      code: 'PAYMENT_ACCOUNT_BINDING_REQUIRED',
      status: 401,
      message: 'CST payment_account_did claim is required for platform-paid requests',
    };
  }

  const fallbackDid = params.resolvedRequestAccount.accountDid?.trim();
  const fallbackSource = params.resolvedRequestAccount.source;

  if (!fallbackDid || !fallbackSource) {
    return {
      ok: false,
      code: 'PAYMENT_REQUIRED',
      status: 402,
      message: 'Payment account context is required for platform-paid requests',
    };
  }

  if (!isDid(fallbackDid)) {
    return {
      ok: false,
      code: 'PAYMENT_ACCOUNT_CLAIM_INVALID',
      status: 401,
      message: 'Payment account context is invalid',
    };
  }

  const normalizedFallbackDid = normalizeDid(fallbackDid);

  return {
    ok: true,
    accountDid: normalizedFallbackDid,
    accountDidSource: fallbackSource,
    context: {
      status: 'matched',
      claimRequired: false,
      claimPresent: false,
      requestAccountDid: normalizedFallbackDid,
      requestAccountDidSource: fallbackSource,
      effectiveAccountDid: normalizedFallbackDid,
      effectiveAccountDidSource: fallbackSource,
    },
  };
}

async function verifyPlatformPaidFunding(params: {
  env: Env;
  accountDid: string;
  accountDidSource: PaymentAccountDidSource;
}): Promise<PlatformFundingCheckResult> {
  const ledgerBaseUrlRaw = params.env.LEDGER_BASE_URL?.trim();
  if (!ledgerBaseUrlRaw) {
    return {
      ok: false,
      code: 'PAYMENT_CHECK_UNAVAILABLE',
      status: 503,
      message: 'Platform-paid funding check is not configured (missing LEDGER_BASE_URL)',
    };
  }

  const ledgerAdminKey = params.env.LEDGER_ADMIN_KEY?.trim();
  if (!ledgerAdminKey) {
    return {
      ok: false,
      code: 'PAYMENT_CHECK_UNAVAILABLE',
      status: 503,
      message: 'Platform-paid funding check is not configured (missing LEDGER_ADMIN_KEY)',
    };
  }

  let minimumRequiredMinor: bigint;
  try {
    minimumRequiredMinor = parsePlatformPaidMinimumMinor(
      params.env.PLATFORM_PAID_MIN_AVAILABLE_MINOR
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid platform-paid minimum balance config';
    return {
      ok: false,
      code: 'PAYMENT_CHECK_UNAVAILABLE',
      status: 503,
      message,
    };
  }

  const ledgerBaseUrl = normalizeBaseUrl(ledgerBaseUrlRaw);

  let response: Response;
  try {
    response = await fetch(
      `${ledgerBaseUrl}/accounts/${params.accountDid}`,
      {
        method: 'GET',
        headers: {
          authorization: `Bearer ${ledgerAdminKey}`,
        },
      }
    );
  } catch {
    return {
      ok: false,
      code: 'PAYMENT_CHECK_UNAVAILABLE',
      status: 503,
      message: 'Failed to reach clawledger for funding check',
    };
  }

  if (response.status === 404) {
    return {
      ok: false,
      code: 'PAYMENT_REQUIRED',
      status: 402,
      message: 'Platform-paid account is not bound in ledger',
    };
  }

  if (response.status < 200 || response.status >= 300) {
    return {
      ok: false,
      code: 'PAYMENT_CHECK_UNAVAILABLE',
      status: 503,
      message: `Funding check dependency returned HTTP ${response.status}`,
    };
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return {
      ok: false,
      code: 'PAYMENT_CHECK_UNAVAILABLE',
      status: 503,
      message: 'Funding check dependency returned non-JSON account payload',
    };
  }

  if (!isRecord(body)) {
    return {
      ok: false,
      code: 'PAYMENT_CHECK_UNAVAILABLE',
      status: 503,
      message: 'Funding check dependency returned invalid account payload',
    };
  }

  const accountId = body.id;
  const balances = body.balances;

  if (typeof accountId !== 'string' || accountId.trim().length === 0 || !isRecord(balances)) {
    return {
      ok: false,
      code: 'PAYMENT_CHECK_UNAVAILABLE',
      status: 503,
      message: 'Funding check dependency returned incomplete account payload',
    };
  }

  const availableMinorRaw = balances.available;
  if (!isNonNegativeIntegerString(availableMinorRaw)) {
    return {
      ok: false,
      code: 'PAYMENT_CHECK_UNAVAILABLE',
      status: 503,
      message: 'Funding check dependency returned invalid available balance',
    };
  }

  const availableMinor = BigInt(availableMinorRaw);

  if (availableMinor < minimumRequiredMinor) {
    return {
      ok: false,
      code: 'PAYMENT_REQUIRED',
      status: 402,
      message: 'Platform-paid account has insufficient available balance',
    };
  }

  return {
    ok: true,
    context: {
      status: 'funded',
      source: 'clawledger',
      accountDid: params.accountDid,
      accountDidSource: params.accountDidSource,
      accountId: accountId.trim(),
      availableMinor: availableMinorRaw,
      minimumRequiredMinor: minimumRequiredMinor.toString(),
      checkedAt: new Date().toISOString(),
      ledgerBaseUrl,
    },
  };
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
        <li><code>POST /v1/chat/completions</code> — OpenAI-compatible alias for <code>/v1/proxy/openai</code>.</li>
        <li><code>POST /v1/responses</code> — OpenAI Responses API alias (routes to OpenAI <code>/v1/responses</code> upstream).</li>
        <li><code>POST /v1/messages</code> — Anthropic-compatible alias for <code>/v1/proxy/anthropic</code>.</li>
        <li><code>GET /v1/receipt/:nonce</code> — Fetch stored receipts for an idempotency nonce (streaming recovery helper).</li>
        <li><code>GET /v1/did</code> — DID document (public key material for receipt verification).</li>
        <li><code>POST /v1/verify-receipt</code> — Verify a receipt signature and return claims.</li>
        <li><code>GET /health</code> — Health check.</li>
      </ul>

      <h2>Quick start</h2>
      <pre># Recommended (proxy auth via CST + BYOK provider key)
curl -sS -X POST "${escapeHtml(origin)}/v1/proxy/openai" \
  -H "X-CST: $CST_TOKEN" \
  -H "X-Provider-API-Key: $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'

# BYOK (no proxy auth; strict-mode compatible)
curl -sS -X POST "${escapeHtml(origin)}/v1/proxy/openai" \
  -H "X-Provider-API-Key: $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'

# Legacy (non-strict mode only; provider key in Authorization)
curl -sS -X POST "${escapeHtml(origin)}/v1/proxy/openai" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'

# Gemini (google provider; OpenAI-compatible request body)
curl -sS -X POST "${escapeHtml(origin)}/v1/proxy/google" \
  -H "X-Provider-API-Key: $GEMINI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gemini-3-flash-preview","messages":[{"role":"user","content":"hello"}]}'

# OpenRouter via fal (OpenAI-compatible; model prefix openrouter/)
curl -sS -X POST "${escapeHtml(origin)}/v1/chat/completions" \
  -H "X-Provider-API-Key: $FAL_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"openrouter/openai/gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'

# Platform-paid (no BYOK key): requires funded ledger account context
curl -sS -X POST "${escapeHtml(origin)}/v1/proxy/openai" \
  -H "X-CST: $CST_TOKEN" \
  -H "X-Client-DID: did:key:..." \
  -H "X-Payment-Account-DID: did:key:..." \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'</pre>

      <p>Platform-paid calls fail-closed: account-claim binding errors return deterministic <code>401</code> codes, and unbound/unfunded accounts return <code>402 PAYMENT_REQUIRED</code>.</p>
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
            { method: 'POST', path: '/v1/chat/completions' },
            { method: 'POST', path: '/v1/responses' },
            { method: 'POST', path: '/v1/messages' },
            { method: 'GET', path: '/v1/receipt/:nonce' },
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
- POST /v1/chat/completions (OpenAI-compatible)
- POST /v1/responses (OpenAI Responses API)
- POST /v1/messages (Anthropic-compatible)
- GET /v1/receipt/:nonce
- GET /v1/did
- POST /v1/verify-receipt

## Authentication

### Proxy auth (CST)
- \`X-CST: <CST>\` (recommended)
- \`X-Scoped-Token: <CST>\` (alternate)
- \`Authorization: Bearer <CST>\` (legacy fallback; only when \`STRICT_AUTH_HEADERS=false\`)
- A valid CST token is required for proxy calls when \`PROXY_REQUIRE_CST=true\` (default fail-closed).
- Canonical chain claims are required when \`PROXY_REQUIRE_CANONICAL_CST=true\` (default fail-closed): \`owner_did\`, \`controller_did\`, \`agent_did\`, \`token_lane=canonical\`.
- The gateway recomputes and verifies \`token_scope_hash_b64u\` from canonical token claims (including chain claims + \`payment_account_did\` when present) (fail-closed).

### BYOK provider keys
- Recommended (all providers): \`X-Provider-API-Key: <provider api key>\` (raw or \`Bearer <key>\`)
- Legacy provider-compatible headers (non-strict mode only):
  - \`Authorization: Bearer <openai api key>\` (OpenAI-compatible routes)
  - \`x-api-key: <anthropic api key>\` (or \`anthropic-api-key\`)
  - \`x-goog-api-key: <gemini api key>\` (Gemini OpenAI-compat upstream)
  - \`Authorization: Bearer <provider api key>\` (only when Authorization is not used for CST)

### Strict auth headers mode
When \`STRICT_AUTH_HEADERS=true\` (default):
- Rejects \`Authorization\` header entirely
- Rejects provider-compatible BYOK headers (\`x-api-key\`, \`anthropic-api-key\`, \`x-goog-api-key\`)
- Requires CST via \`X-CST\`/\`X-Scoped-Token\` and provider keys via \`X-Provider-API-Key\`

### Platform-paid funding precheck
For platform-paid calls (no provider BYOK key), clawproxy performs fail-closed payment account binding + funding checks before provider routing:
- Payment account DID request context is read from \`X-Payment-Account-DID\` (fallback: \`X-Client-DID\`, then CST \`sub\`)
- CST claim \`payment_account_did\` is authoritative when present
  - mismatch with request account context => deterministic \`401\` \`PAYMENT_ACCOUNT_CLAIM_MISMATCH\`
  - invalid claim format => deterministic \`401\` \`PAYMENT_ACCOUNT_CLAIM_INVALID\`
  - when \`PLATFORM_PAID_REQUIRE_PAYMENT_ACCOUNT_CLAIM=true\`, missing claim => deterministic \`401\` \`PAYMENT_ACCOUNT_BINDING_REQUIRED\`
- Account must be bound in clawledger and have enough available balance (default minimum: \`1\` minor unit)
- If unbound or unfunded, clawproxy returns deterministic \`402\` with code \`PAYMENT_REQUIRED\`
- Successful platform-paid receipts include signed payment binding + funding context in:
  - \`_receipt.payment.accountBinding\`
  - \`_receipt.payment.fundingCheck\`
  - \`_receipt_envelope.payload.metadata.payment_account_binding\`
  - \`_receipt_envelope.payload.metadata.payment_funding_check\`

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
- Google/Gemini: call \`POST /v1/proxy/google\` with an OpenAI-compatible body (\`{ model, messages, ... }\`).
- OpenRouter (via fal): set \`model\` to \`openrouter/...\` and call \`POST /v1/chat/completions\` (or \`POST /v1/proxy/openai\`) with \`X-Provider-API-Key: $FAL_KEY\`. The proxy sends \`Authorization: Key ...\` upstream.
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

    // Receipt lookup endpoint: GET /v1/receipt/:nonce
    const receiptMatch = path.match(/^\/v1\/receipt\/([^/]+)$/);
    if (receiptMatch && request.method === 'GET') {
      const nonce = receiptMatch[1];
      if (!nonce) {
        return errorResponse('INVALID_PATH', 'Receipt nonce not specified', 400);
      }
      return handleReceiptLookup(request, env, nonce);
    }

    // Provider-compatible endpoints (drop-in SDK support)
    if (request.method === 'POST') {
      if (path === '/v1/chat/completions') {
        return handleProxy(request, env, 'openai');
      }
      if (path === '/v1/responses') {
        return handleProxy(request, env, 'openai');
      }
      if (path === '/v1/messages') {
        return handleProxy(request, env, 'anthropic');
      }
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function tryGetString(obj: Record<string, unknown> | undefined, key: string): string | undefined {
  if (!obj) return undefined;
  const v = obj[key];
  return typeof v === 'string' && v.trim().length > 0 ? v.trim() : undefined;
}

function sanitizeLegacyReceiptForOutput(receipt: unknown): Record<string, unknown> | undefined {
  if (!isRecord(receipt)) return undefined;

  const keep = [
    'version',
    'proxyDid',
    'provider',
    'model',
    'requestHash',
    'responseHash',
    'timestamp',
    'latencyMs',
    'signature',
    'kid',
    'binding',
    'payment',
    'privacyMode',
  ];

  const out: Record<string, unknown> = {};
  for (const k of keep) {
    if (k in receipt) out[k] = receipt[k];
  }
  return out;
}

function extractStoredResponseBody(stored: unknown): { status?: number; body: Record<string, unknown> | null } {
  if (!isRecord(stored)) return { body: null };

  if (typeof stored.status === 'number' && 'body' in stored) {
    const body = (stored as { body?: unknown }).body;
    return { status: stored.status, body: isRecord(body) ? body : null };
  }

  return { body: stored };
}

function extractBindingFromReceiptEnvelope(envelope: unknown): {
  run_id?: string;
  event_hash_b64u?: string;
  nonce?: string;
} {
  if (!isRecord(envelope)) return {};

  const payload = envelope.payload;
  if (!isRecord(payload)) return {};

  const binding = payload.binding;
  if (!isRecord(binding)) return {};

  return {
    run_id: tryGetString(binding, 'run_id'),
    event_hash_b64u: tryGetString(binding, 'event_hash_b64u'),
    nonce: tryGetString(binding, 'nonce'),
  };
}

function extractBindingFromLegacyReceipt(receipt: unknown): {
  run_id?: string;
  event_hash_b64u?: string;
  nonce?: string;
} {
  if (!isRecord(receipt)) return {};

  const binding = receipt.binding;
  if (!isRecord(binding)) return {};

  return {
    run_id: tryGetString(binding, 'runId'),
    event_hash_b64u: tryGetString(binding, 'eventHash'),
    nonce: tryGetString(binding, 'nonce'),
  };
}

async function handleReceiptLookup(request: Request, env: Env, nonce: string): Promise<Response> {
  // Rate limit receipt lookups as well (DO reads can still be abused).
  const rateLimitInfo = await checkRateLimit(request, env);
  if (!rateLimitInfo.allowed) {
    logRateLimited(request, rateLimitInfo.key);
    return rateLimitedResponse(rateLimitInfo);
  }

  const normalizedNonce = nonce.trim();
  if (!normalizedNonce) {
    return errorResponseWithRateLimit(
      'INVALID_NONCE',
      'Receipt nonce must be non-empty',
      400,
      rateLimitInfo
    );
  }

  if (normalizedNonce.length > 256) {
    return errorResponseWithRateLimit(
      'INVALID_NONCE',
      'Receipt nonce is too long',
      400,
      rateLimitInfo
    );
  }

  const url = new URL(request.url);

  const expectedRunId = (url.searchParams.get('run_id') ?? url.searchParams.get('runId') ?? '').trim() || undefined;
  const expectedEventHash =
    (url.searchParams.get('event_hash_b64u') ??
      url.searchParams.get('event_hash') ??
      url.searchParams.get('eventHash') ??
      '').trim() || undefined;

  const fingerprintHeader =
    request.headers.get('X-Idempotency-Fingerprint') ?? request.headers.get('X-Fingerprint');
  const fingerprint = fingerprintHeader?.trim() || undefined;

  let read;
  try {
    read = await readIdempotencyReceipt(env, normalizedNonce, {
      fingerprint,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'unknown error';
    return errorResponseWithRateLimit(
      'IDEMPOTENCY_STORE_ERROR',
      `Idempotency store error: ${message}`,
      503,
      rateLimitInfo
    );
  }

  if (read.kind === 'missing') {
    return errorResponseWithRateLimit(
      'RECEIPT_NOT_FOUND',
      'Receipt not found (idempotency key unknown or expired)',
      404,
      rateLimitInfo
    );
  }

  if (read.kind === 'inflight') {
    return errorResponseWithRateLimit(
      'RECEIPT_INFLIGHT',
      'Receipt not yet committed for this nonce. Retry later.',
      409,
      rateLimitInfo
    );
  }

  if (read.kind === 'mismatch') {
    return errorResponseWithRateLimit(
      'IDEMPOTENCY_FINGERPRINT_MISMATCH',
      'Idempotency fingerprint mismatch for this nonce',
      409,
      rateLimitInfo
    );
  }

  const stored = read.receipt;
  const { status, body } = extractStoredResponseBody(stored);

  if (!body) {
    return errorResponseWithRateLimit(
      'RECEIPT_CORRUPTED',
      'Stored receipt is not an object',
      500,
      rateLimitInfo
    );
  }

  const receiptEnvelope = body['_receipt_envelope'];
  const legacyReceiptRaw = body['_receipt'];
  const legacyReceipt = sanitizeLegacyReceiptForOutput(legacyReceiptRaw);

  if (!receiptEnvelope && !legacyReceipt) {
    return errorResponseWithRateLimit(
      'RECEIPT_NOT_FOUND',
      'Stored entry does not contain a receipt',
      404,
      rateLimitInfo
    );
  }

  const bindingEnvelope = extractBindingFromReceiptEnvelope(receiptEnvelope);
  const bindingLegacy = extractBindingFromLegacyReceipt(legacyReceiptRaw);

  const actualRunId = bindingEnvelope.run_id ?? bindingLegacy.run_id;
  const actualEventHash = bindingEnvelope.event_hash_b64u ?? bindingLegacy.event_hash_b64u;
  const actualNonce = bindingEnvelope.nonce ?? bindingLegacy.nonce;

  if (expectedRunId) {
    if (!actualRunId) {
      return errorResponseWithRateLimit(
        'RECEIPT_BINDING_MISSING',
        'Receipt is missing binding.run_id',
        422,
        rateLimitInfo
      );
    }

    if (actualRunId !== expectedRunId) {
      return errorResponseWithRateLimit(
        'RECEIPT_BINDING_MISMATCH',
        'Receipt binding.run_id does not match',
        409,
        rateLimitInfo
      );
    }
  }

  if (expectedEventHash) {
    if (!actualEventHash) {
      return errorResponseWithRateLimit(
        'RECEIPT_BINDING_MISSING',
        'Receipt is missing binding.event_hash_b64u',
        422,
        rateLimitInfo
      );
    }

    if (actualEventHash !== expectedEventHash) {
      return errorResponseWithRateLimit(
        'RECEIPT_BINDING_MISMATCH',
        'Receipt binding.event_hash_b64u does not match',
        409,
        rateLimitInfo
      );
    }
  }

  if (actualNonce && actualNonce !== normalizedNonce) {
    return errorResponseWithRateLimit(
      'RECEIPT_BINDING_MISMATCH',
      'Receipt binding.nonce does not match requested nonce',
      409,
      rateLimitInfo
    );
  }

  return jsonResponseWithRateLimit(
    {
      ok: true,
      nonce: normalizedNonce,
      status: status ?? null,
      truncated: read.truncated,
      receipt_envelope: receiptEnvelope ?? null,
      receipt: legacyReceipt ?? null,
      binding: {
        run_id: actualRunId ?? null,
        event_hash_b64u: actualEventHash ?? null,
      },
    },
    200,
    rateLimitInfo
  );
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
  // M6 enforcement defaults are fail-closed:
  // - STRICT_AUTH_HEADERS defaults to true
  // - PROXY_REQUIRE_CST defaults to true
  // - PROXY_REQUIRE_CANONICAL_CST defaults to true
  const strictAuthHeaders = parseBooleanFlag(env.STRICT_AUTH_HEADERS);
  const requireCst = parseBooleanFlag(env.PROXY_REQUIRE_CST);
  const requireCanonicalCst = parseBooleanFlag(env.PROXY_REQUIRE_CANONICAL_CST);

  const clientDidHeader = request.headers.get('X-Client-DID');
  const authorizationHeader = request.headers.get('Authorization');

  const cstTokenFromXCst = stripBearer(request.headers.get('X-CST'));
  const cstTokenFromXScopedToken = stripBearer(request.headers.get('X-Scoped-Token'));

  if (strictAuthHeaders) {
    const auth = authorizationHeader?.trim();
    if (auth) {
      return errorResponseWithRateLimit(
        'STRICT_AUTH_HEADERS',
        'Authorization header is not allowed when STRICT_AUTH_HEADERS=true. Provide CST via X-CST (or X-Scoped-Token) and provider keys via X-Provider-API-Key.',
        400,
        rateLimitInfo
      );
    }

    if (cstTokenFromXCst && cstTokenFromXScopedToken && cstTokenFromXCst !== cstTokenFromXScopedToken) {
      return errorResponseWithRateLimit(
        'STRICT_AUTH_HEADERS',
        'Conflicting CST headers: X-CST and X-Scoped-Token differ.',
        400,
        rateLimitInfo
      );
    }

    const forbiddenProviderKeyHeaders = [
      'X-Provider-Key',
      'X-Provider-Authorization',
      // Provider-compatible BYOK headers
      'x-api-key',
      'anthropic-api-key',
      'x-goog-api-key',
    ];

    for (const h of forbiddenProviderKeyHeaders) {
      const v = request.headers.get(h);
      if (typeof v === 'string' && v.trim().length > 0) {
        return errorResponseWithRateLimit(
          'STRICT_AUTH_HEADERS',
          `Provider API keys must be provided via X-Provider-API-Key when STRICT_AUTH_HEADERS=true (do not use ${h}).`,
          400,
          rateLimitInfo
        );
      }
    }
  }

  const authToken = stripBearer(authorizationHeader);

  const explicitCstToken = cstTokenFromXCst ?? cstTokenFromXScopedToken;

  // Prefer explicit X-CST/X-Scoped-Token. Fall back to Authorization when it looks like a JWT.
  // (Strict mode disables this fallback to avoid Authorization overload.)
  const authorizationIsCst =
    !strictAuthHeaders && !explicitCstToken && !!authToken && looksLikeJwt(authToken);

  const cstToken = explicitCstToken ?? (authorizationIsCst ? authToken : undefined);

  let validatedCst:
    | {
        token_hash: string;
        claims: {
          sub: string;
          aud: string | string[];
          scope: string[];
          token_scope_hash_b64u: string;
          policy_hash_b64u?: string;
          payment_account_did?: string;
          owner_ref?: string;
          owner_did?: string;
          controller_did?: string;
          agent_did?: string;
          control_plane_policy_hash_b64u?: string;
          spend_cap?: number;
          mission_id?: string;
          delegation_id?: string;
          delegator_did?: string;
          delegate_did?: string;
          delegation_policy_hash_b64u?: string;
          delegation_spend_cap_minor?: string;
          delegation_expires_at?: number;
          token_lane?: 'legacy' | 'canonical';
        };
      }
    | undefined;

  const cstRequired = requireCst || Boolean(clientDidHeader);
  if (cstRequired && !cstToken) {
    return errorResponseWithRateLimit(
      'TOKEN_REQUIRED',
      strictAuthHeaders
        ? 'Canonical CST token is required. Provide X-CST (or X-Scoped-Token).'
        : 'Canonical CST token is required. Provide X-CST (or X-Scoped-Token).',
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
      if (normalizeDid(clientDidHeader) !== normalizeDid(tokenValidation.claims.sub)) {
        return errorResponseWithRateLimit(
          'TOKEN_SUB_MISMATCH',
          'X-Client-DID does not match CST subject (sub)',
          401,
          rateLimitInfo
        );
      }
    }

    const ownerDidFromToken =
      typeof tokenValidation.claims.owner_did === 'string' && tokenValidation.claims.owner_did.trim().length > 0
        ? tokenValidation.claims.owner_did.trim()
        : undefined;

    const controllerDidFromToken =
      typeof tokenValidation.claims.controller_did === 'string' &&
      tokenValidation.claims.controller_did.trim().length > 0
        ? tokenValidation.claims.controller_did.trim()
        : undefined;

    const agentDidFromToken =
      typeof tokenValidation.claims.agent_did === 'string' && tokenValidation.claims.agent_did.trim().length > 0
        ? tokenValidation.claims.agent_did.trim()
        : undefined;

    const tokenLane = tokenValidation.claims.token_lane;

    if (requireCanonicalCst) {
      if (!ownerDidFromToken || !controllerDidFromToken || !agentDidFromToken || tokenLane !== 'canonical') {
        return errorResponseWithRateLimit(
          'TOKEN_CONTROL_CHAIN_MISSING',
          'Canonical chain claims are required: owner_did, controller_did, agent_did, token_lane=canonical',
          401,
          rateLimitInfo
        );
      }

      if (normalizeDid(agentDidFromToken) !== normalizeDid(tokenValidation.claims.sub)) {
        return errorResponseWithRateLimit(
          'TOKEN_CONTROL_SUBJECT_MISMATCH',
          'agent_did claim must match token subject (sub)',
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

    const ownerRefFromToken =
      typeof tokenValidation.claims.owner_ref === 'string' && tokenValidation.claims.owner_ref.trim().length > 0
        ? tokenValidation.claims.owner_ref.trim()
        : undefined;

    const policyHashFromToken =
      typeof tokenValidation.claims.policy_hash_b64u === 'string' &&
      tokenValidation.claims.policy_hash_b64u.trim().length > 0
        ? tokenValidation.claims.policy_hash_b64u.trim()
        : undefined;

    const controlPlanePolicyHashFromToken =
      typeof tokenValidation.claims.control_plane_policy_hash_b64u === 'string' &&
      tokenValidation.claims.control_plane_policy_hash_b64u.trim().length > 0
        ? tokenValidation.claims.control_plane_policy_hash_b64u.trim()
        : undefined;

    const paymentAccountDidFromToken =
      typeof tokenValidation.claims.payment_account_did === 'string' &&
      tokenValidation.claims.payment_account_did.trim().length > 0
        ? tokenValidation.claims.payment_account_did.trim()
        : undefined;

    const missionIdFromToken =
      typeof tokenValidation.claims.mission_id === 'string' && tokenValidation.claims.mission_id.trim().length > 0
        ? tokenValidation.claims.mission_id.trim()
        : undefined;

    const spendCapFromToken =
      typeof tokenValidation.claims.spend_cap === 'number' ? tokenValidation.claims.spend_cap : undefined;

    const delegationIdFromToken =
      typeof tokenValidation.claims.delegation_id === 'string' &&
      tokenValidation.claims.delegation_id.trim().length > 0
        ? tokenValidation.claims.delegation_id.trim()
        : undefined;

    const delegatorDidFromToken =
      typeof tokenValidation.claims.delegator_did === 'string' &&
      tokenValidation.claims.delegator_did.trim().length > 0
        ? tokenValidation.claims.delegator_did.trim()
        : undefined;

    const delegateDidFromToken =
      typeof tokenValidation.claims.delegate_did === 'string' &&
      tokenValidation.claims.delegate_did.trim().length > 0
        ? tokenValidation.claims.delegate_did.trim()
        : undefined;

    const delegationPolicyHashFromToken =
      typeof tokenValidation.claims.delegation_policy_hash_b64u === 'string' &&
      tokenValidation.claims.delegation_policy_hash_b64u.trim().length > 0
        ? tokenValidation.claims.delegation_policy_hash_b64u.trim()
        : undefined;

    const delegationSpendCapMinorFromToken =
      typeof tokenValidation.claims.delegation_spend_cap_minor === 'string' &&
      tokenValidation.claims.delegation_spend_cap_minor.trim().length > 0
        ? tokenValidation.claims.delegation_spend_cap_minor.trim()
        : undefined;

    const delegationExpiresAtFromToken =
      typeof tokenValidation.claims.delegation_expires_at === 'number' &&
      Number.isFinite(tokenValidation.claims.delegation_expires_at)
        ? Math.floor(tokenValidation.claims.delegation_expires_at)
        : undefined;

    if (
      delegationIdFromToken ||
      delegatorDidFromToken ||
      delegateDidFromToken ||
      delegationPolicyHashFromToken ||
      delegationSpendCapMinorFromToken ||
      delegationExpiresAtFromToken !== undefined
    ) {
      if (!delegationIdFromToken || !delegatorDidFromToken || !delegateDidFromToken) {
        return errorResponseWithRateLimit(
          'TOKEN_DELEGATION_BINDING_INVALID',
          'Delegated CST requires delegation_id, delegator_did, and delegate_did claims',
          401,
          rateLimitInfo
        );
      }

      if (delegateDidFromToken !== tokenValidation.claims.sub) {
        return errorResponseWithRateLimit(
          'TOKEN_DELEGATION_BINDING_INVALID',
          'delegate_did claim must match token subject',
          401,
          rateLimitInfo
        );
      }

      if (!ownerDidFromToken || ownerDidFromToken !== delegatorDidFromToken) {
        return errorResponseWithRateLimit(
          'TOKEN_DELEGATION_BINDING_INVALID',
          'delegator_did must match owner_did claim for delegated CST',
          401,
          rateLimitInfo
        );
      }

      if (delegationPolicyHashFromToken && policyHashFromToken && delegationPolicyHashFromToken !== policyHashFromToken) {
        return errorResponseWithRateLimit(
          'TOKEN_DELEGATION_BINDING_INVALID',
          'delegation_policy_hash_b64u must match policy_hash_b64u when both are present',
          401,
          rateLimitInfo
        );
      }

      if (delegationSpendCapMinorFromToken && !isNonNegativeIntegerString(delegationSpendCapMinorFromToken)) {
        return errorResponseWithRateLimit(
          'TOKEN_DELEGATION_BINDING_INVALID',
          'delegation_spend_cap_minor claim is invalid',
          401,
          rateLimitInfo
        );
      }

      if (
        delegationExpiresAtFromToken !== undefined &&
        delegationExpiresAtFromToken <= Math.floor(Date.now() / 1000)
      ) {
        return errorResponseWithRateLimit(
          'TOKEN_DELEGATION_EXPIRED',
          'delegation_expires_at claim is expired',
          401,
          rateLimitInfo
        );
      }
    }

    const tokenScopeHashFromToken = tokenValidation.claims.token_scope_hash_b64u.trim();

    // CPX-US-035 + ICP-M6.1: Recompute token_scope_hash_b64u from canonical claims (fail-closed).
    let expectedTokenScopeHash: string;
    try {
      expectedTokenScopeHash = await computeTokenScopeHashB64uV1({
        sub: tokenValidation.claims.sub,
        aud: tokenValidation.claims.aud,
        scope: tokenValidation.claims.scope,
        owner_ref: ownerRefFromToken,
        owner_did: ownerDidFromToken,
        controller_did: controllerDidFromToken,
        agent_did: agentDidFromToken,
        policy_hash_b64u: policyHashFromToken,
        control_plane_policy_hash_b64u: controlPlanePolicyHashFromToken,
        payment_account_did: paymentAccountDidFromToken,
        spend_cap: spendCapFromToken,
        mission_id: missionIdFromToken,
        delegation_id: delegationIdFromToken,
        delegator_did: delegatorDidFromToken,
        delegate_did: delegateDidFromToken,
        delegation_policy_hash_b64u: delegationPolicyHashFromToken,
        delegation_spend_cap_minor: delegationSpendCapMinorFromToken,
        delegation_expires_at: delegationExpiresAtFromToken,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unknown error';
      return errorResponseWithRateLimit(
        'TOKEN_SCOPE_HASH_INVALID',
        `Failed to compute token_scope_hash_b64u from claims: ${message}`,
        401,
        rateLimitInfo
      );
    }

    if (expectedTokenScopeHash !== tokenScopeHashFromToken) {
      return errorResponseWithRateLimit(
        'TOKEN_SCOPE_HASH_MISMATCH',
        'Token token_scope_hash_b64u does not match the deterministic hash of its claims',
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
        token_scope_hash_b64u: tokenScopeHashFromToken,
        policy_hash_b64u: policyHashFromToken,
        payment_account_did: paymentAccountDidFromToken,
        owner_ref: ownerRefFromToken,
        owner_did: ownerDidFromToken,
        controller_did: controllerDidFromToken,
        agent_did: agentDidFromToken,
        control_plane_policy_hash_b64u: controlPlanePolicyHashFromToken,
        spend_cap: spendCapFromToken,
        mission_id: missionIdFromToken,
        delegation_id: delegationIdFromToken,
        delegator_did: delegatorDidFromToken,
        delegate_did: delegateDidFromToken,
        delegation_policy_hash_b64u: delegationPolicyHashFromToken,
        delegation_spend_cap_minor: delegationSpendCapMinorFromToken,
        delegation_expires_at: delegationExpiresAtFromToken,
        token_lane: tokenLane,
      },
    };
  }


  // Extract policy information for WPC enforcement
  const policyResult = await extractPolicyFromHeaders(request, env, {
    policyHashOverride: validatedCst?.claims.policy_hash_b64u,
  });

  // Fail closed if policy is missing/invalid when required.
  if (policyResult.error) {
    logPolicyMissing(request, policyResult.error);
    return errorResponseWithRateLimit(
      policyResult.errorCode ?? 'POLICY_REQUIRED',
      policyResult.error,
      policyResult.errorStatus ?? 400,
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
  // - X-Provider-API-Key (recommended)
  // - Provider-compatible BYOK headers (SDK drop-in; disabled when STRICT_AUTH_HEADERS=true)
  // - Authorization (legacy BYOK mode; disabled when STRICT_AUTH_HEADERS=true)
  const providerApiKeyHeader = strictAuthHeaders
    ? request.headers.get('X-Provider-API-Key')
    : request.headers.get('X-Provider-API-Key') ??
      request.headers.get('X-Provider-Key') ??
      request.headers.get('X-Provider-Authorization') ??
      // Provider-compatible BYOK headers (SDK drop-in)
      (provider === 'anthropic'
        ? request.headers.get('x-api-key') ?? request.headers.get('anthropic-api-key')
        : provider === 'google'
          ? request.headers.get('x-goog-api-key')
          : null);

  const explicitProviderApiKey = stripBearer(providerApiKeyHeader);

  // Back-compat: if Authorization is not being used as CST, treat it as a legacy provider API key.
  const legacyProviderApiKey =
    !strictAuthHeaders && !explicitProviderApiKey && !authorizationIsCst ? authToken : undefined;

  const apiKeyCandidate = explicitProviderApiKey ?? legacyProviderApiKey;

  let apiKey: string;
  let payment: ReceiptPayment;
  let platformFundingCheckMeta: Record<string, unknown> | undefined;
  let delegatedSpendContext: DelegationSpendCheckContext | undefined;

  if (apiKeyCandidate) {
    apiKey = apiKeyCandidate;
    payment = { mode: 'user', paid: false };
  } else {
    if (env.PLATFORM_PAID_ENABLED !== 'true') {
      return errorResponseWithRateLimit(
        'UNAUTHORIZED',
        strictAuthHeaders
          ? 'Provider API key required (set X-Provider-API-Key). Platform-paid mode is disabled.'
          : 'Provider API key required (set X-Provider-API-Key or legacy Authorization). Platform-paid mode is disabled.',
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

    const resolvedPaymentAccount = resolvePaymentAccountDid({
      request,
      clientDidHeader,
      cstSub: validatedCst?.claims.sub,
    });

    const paymentAccountClaimRequired = parseBooleanFlag(
      env.PLATFORM_PAID_REQUIRE_PAYMENT_ACCOUNT_CLAIM
    );

    const accountBinding = resolvePlatformPaymentAccountBinding({
      resolvedRequestAccount: resolvedPaymentAccount,
      claimPaymentAccountDid: validatedCst?.claims.payment_account_did,
      claimRequired: paymentAccountClaimRequired,
    });

    if (!accountBinding.ok) {
      return errorResponseWithRateLimit(
        accountBinding.code,
        accountBinding.message,
        accountBinding.status,
        rateLimitInfo
      );
    }

    const fundingCheck = await verifyPlatformPaidFunding({
      env,
      accountDid: accountBinding.accountDid,
      accountDidSource: accountBinding.accountDidSource,
    });

    if (!fundingCheck.ok) {
      return errorResponseWithRateLimit(
        fundingCheck.code,
        fundingCheck.message,
        fundingCheck.status,
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

    payment = {
      mode: 'platform',
      paid: true,
      ledgerRef,
      accountBinding: accountBinding.context,
      fundingCheck: fundingCheck.context,
    };

    platformFundingCheckMeta = {
      payment_mode: 'platform',
      payment_ledger_ref: ledgerRef,
      payment_account_binding: {
        status: accountBinding.context.status,
        claim_required: accountBinding.context.claimRequired,
        claim_present: accountBinding.context.claimPresent,
        claim_account_did: accountBinding.context.claimAccountDid,
        request_account_did: accountBinding.context.requestAccountDid,
        request_account_did_source: accountBinding.context.requestAccountDidSource,
        effective_account_did: accountBinding.context.effectiveAccountDid,
        effective_account_did_source: accountBinding.context.effectiveAccountDidSource,
      },
      payment_funding_check: {
        status: fundingCheck.context.status,
        source: fundingCheck.context.source,
        account_did: fundingCheck.context.accountDid,
        account_did_source: fundingCheck.context.accountDidSource,
        account_id: fundingCheck.context.accountId,
        available_minor: fundingCheck.context.availableMinor,
        minimum_required_minor: fundingCheck.context.minimumRequiredMinor,
        checked_at: fundingCheck.context.checkedAt,
        ledger_base_url: fundingCheck.context.ledgerBaseUrl,
      },
    };
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

  const streamRequested = isStreamingRequested(parsedBody, request);

  // Extract model for receipt
  const model = extractModel(provider, parsedBody);

  // OpenRouter-through-fal uses OpenAI-compatible endpoints but a different upstream base + auth.
  const falOpenrouter = provider === 'openai' && isFalOpenrouterModel(model);

  const falOpenrouterUpstreamModel =
    falOpenrouter && typeof model === 'string' ? stripOpenrouterModelPrefix(model) : null;

  if (falOpenrouter && (!falOpenrouterUpstreamModel || falOpenrouterUpstreamModel.length === 0)) {
    return errorResponseWithRateLimit(
      'INVALID_REQUEST',
      'Invalid OpenRouter model id (expected openrouter/<provider>/<model>)',
      400,
      rateLimitInfo
    );
  }

  // Fail closed: platform-paid OpenAI keys are not valid for the fal OpenRouter router.
  if (falOpenrouter && payment.mode !== 'user') {
    return errorResponseWithRateLimit(
      'UNAUTHORIZED',
      'Provider API key required for openrouter/* models (set X-Provider-API-Key to your FAL key).',
      401,
      rateLimitInfo
    );
  }

  // Google Gemini requires model in the URL path
  if (provider === 'google' && !model) {
    return errorResponseWithRateLimit(
      'INVALID_REQUEST',
      'Model field is required for Google Gemini API. Specify "model" in the request body.',
      400,
      rateLimitInfo
    );
  }

  // Optional receipt metadata about policy checks (hash-only; no prompt/plaintext).
  let wpcModelIdentityMeta: Record<string, unknown> | undefined;

  // Enforce WPC constraints if policy is active
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

    const modelIdentityResult = enforceMinimumModelIdentityTier(provider, model, policyResult.policy);
    if (!modelIdentityResult.allowed) {
      logPolicyViolation(
        request,
        policyResult.policyHash ?? 'unknown',
        modelIdentityResult.errorCode ?? 'POLICY_VIOLATION',
        modelIdentityResult.error ?? 'Policy enforcement failed'
      );
      return errorResponseWithRateLimit(
        modelIdentityResult.errorCode ?? 'POLICY_VIOLATION',
        modelIdentityResult.error ?? 'Policy enforcement failed',
        403,
        rateLimitInfo
      );
    }

    if (modelIdentityResult.requiredTier) {
      wpcModelIdentityMeta = {
        wpc_minimum_model_identity_tier: modelIdentityResult.requiredTier,
        wpc_model_identity_requirement_met: true,
      };
    }
  }

  // Apply redaction rules to request body if policy specifies them
  let finalRequestBody = requestBody;
  if (policyResult.policy?.redaction_rules && policyResult.policy.redaction_rules.length > 0) {
    const redactedBody = applyRedactionRules(parsedBody, policyResult.policy.redaction_rules);
    const strippedBody = stripUndefined(redactedBody);
    finalRequestBody = JSON.stringify(strippedBody);
  }

  // OpenRouter-through-fal: rewrite model id for upstream call (strip leading `openrouter/`).
  // The original `model` string is still used in receipts for auditability.
  if (falOpenrouter && falOpenrouterUpstreamModel) {
    try {
      const obj = JSON.parse(finalRequestBody) as Record<string, unknown>;
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
        throw new Error('Request body must be a JSON object');
      }

      obj.model = falOpenrouterUpstreamModel;
      finalRequestBody = JSON.stringify(obj);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unknown error';
      return errorResponseWithRateLimit(
        'INVALID_REQUEST',
        `Failed to rewrite OpenRouter model id: ${message}`,
        400,
        rateLimitInfo
      );
    }
  }

  // Build provider-specific URL (Gemini needs model in path)
  let providerUrl: string;
  try {
    const openaiApi: OpenAIUpstreamApi | undefined =
      provider === 'openai' || provider === 'google'
        ? inferOpenAiUpstreamApi(request, parsedBody)
        : undefined;

    providerUrl = falOpenrouter
      ? buildFalOpenrouterUrl({ openaiApi })
      : buildProviderUrl(provider, model, { openaiApi });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponseWithRateLimit('INVALID_REQUEST', message, 400, rateLimitInfo);
  }

  // Extend binding with policy hash and CST token scope hash (when present)
  // NOTE: policyHash is only included when a policy was actually fetched+verified.
  const finalBinding = {
    ...binding,
    policyHash: policyResult.policy ? policyResult.policyHash : undefined,
    tokenScopeHashB64u: validatedCst?.claims.token_scope_hash_b64u,
  };

  // CPX-US-031: durable idempotency (nonce-based) with request fingerprinting
  let idempotency: { nonce: string; fingerprint: string } | null = null;

  if (typeof binding?.nonce === 'string' && binding.nonce.trim().length > 0) {
    const nonce = binding.nonce;

    let fingerprint: string;
    try {
      fingerprint = await computeIdempotencyFingerprint({
        provider,
        provider_url: providerUrl,
        model: model ?? null,
        request_body: finalRequestBody,
        binding: {
          run_id: finalBinding.runId ?? null,
          event_hash_b64u: finalBinding.eventHash ?? null,
          policy_hash: finalBinding.policyHash ?? null,
          token_scope_hash_b64u: finalBinding.tokenScopeHashB64u ?? null,
        },
        payment: {
          mode: payment?.mode ?? null,
        },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unknown error';
      return errorResponseWithRateLimit(
        'IDEMPOTENCY_FINGERPRINT_ERROR',
        `Failed to compute idempotency fingerprint: ${message}`,
        500,
        rateLimitInfo
      );
    }

    let check;
    try {
      check = await checkIdempotencyAndLock(env, nonce, fingerprint);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unknown error';
      return errorResponseWithRateLimit(
        'IDEMPOTENCY_STORE_ERROR',
        `Idempotency store error: ${message}`,
        503,
        rateLimitInfo
      );
    }

    if (check.kind === 'replay') {
      const stored = check.receipt as any;
      if (
        stored &&
        typeof stored === 'object' &&
        typeof stored.status === 'number' &&
        'body' in stored
      ) {
        return jsonResponseWithRateLimit(stored.body, stored.status, rateLimitInfo);
      }

      // Back-compat: older stored entries may have persisted only the response body.
      return jsonResponseWithRateLimit(check.receipt, 200, rateLimitInfo);
    }

    if (check.kind === 'mismatch') {
      return errorResponseWithRateLimit(
        'IDEMPOTENCY_FINGERPRINT_MISMATCH',
        'Idempotency key was reused with a different request fingerprint',
        409,
        rateLimitInfo
      );
    }

    if (check.kind === 'inflight') {
      return errorResponseWithRateLimit(
        'IDEMPOTENCY_KEY_IN_USE',
        'Idempotency key is currently in use for an in-flight request. Retry later.',
        409,
        rateLimitInfo
      );
    }

    idempotency = { nonce, fingerprint };
  }

  if (validatedCst?.claims.delegation_id) {
    if (!idempotency) {
      return errorResponseWithRateLimit(
        'DELEGATION_IDEMPOTENCY_REQUIRED',
        'Delegated CST calls require X-Idempotency-Key (nonce) for spend governance replay safety',
        400,
        rateLimitInfo
      );
    }

    const releaseDelegationIdempotency = async (): Promise<Response | null> => {
      try {
        await releaseIdempotency(env, idempotency.nonce, idempotency.fingerprint);
        return null;
      } catch (releaseErr) {
        const msg = releaseErr instanceof Error ? releaseErr.message : 'unknown error';
        return errorResponseWithRateLimit(
          'IDEMPOTENCY_STORE_ERROR',
          `Idempotency store release failed: ${msg}`,
          503,
          rateLimitInfo
        );
      }
    };

    if (!validatedCst.claims.delegator_did || !validatedCst.claims.delegate_did) {
      const releaseErr = await releaseDelegationIdempotency();
      if (releaseErr) return releaseErr;

      return errorResponseWithRateLimit(
        'DELEGATION_BINDING_INVALID',
        'Delegated CST is missing required delegation binding claims',
        401,
        rateLimitInfo
      );
    }

    if (validatedCst.claims.delegate_did !== validatedCst.claims.sub) {
      const releaseErr = await releaseDelegationIdempotency();
      if (releaseErr) return releaseErr;

      return errorResponseWithRateLimit(
        'DELEGATION_BINDING_INVALID',
        'delegate_did must match token subject for delegated CST',
        401,
        rateLimitInfo
      );
    }

    if (validatedCst.claims.delegation_policy_hash_b64u) {
      if (!finalBinding.policyHash) {
        const releaseErr = await releaseDelegationIdempotency();
        if (releaseErr) return releaseErr;

        return errorResponseWithRateLimit(
          'DELEGATION_POLICY_REQUIRED',
          'Delegated CST requires a resolved policy hash when delegation_policy_hash_b64u is set',
          400,
          rateLimitInfo
        );
      }

      if (validatedCst.claims.delegation_policy_hash_b64u !== finalBinding.policyHash) {
        const releaseErr = await releaseDelegationIdempotency();
        if (releaseErr) return releaseErr;

        return errorResponseWithRateLimit(
          'DELEGATION_POLICY_MISMATCH',
          'Delegated CST policy pin does not match resolved policy hash',
          403,
          rateLimitInfo
        );
      }
    }

    let amountMinor: bigint;
    try {
      const fallback = parseDefaultDelegatedSpendMinor(env.CLAWDELEGATE_DEFAULT_SPEND_MINOR);
      amountMinor = parseDelegatedSpendMinorFromRequest(request, fallback);
    } catch (err) {
      const releaseErr = await releaseDelegationIdempotency();
      if (releaseErr) return releaseErr;

      const message = err instanceof Error ? err.message : 'invalid delegated spend amount';
      return errorResponseWithRateLimit('DELEGATION_SPEND_AMOUNT_INVALID', message, 400, rateLimitInfo);
    }

    const spendCheck = await runDelegatedSpendAuthorize({
      env,
      delegationId: validatedCst.claims.delegation_id,
      actorDid: validatedCst.claims.sub,
      tokenHash: validatedCst.token_hash,
      tokenScopeHashB64u: validatedCst.claims.token_scope_hash_b64u,
      amountMinor: amountMinor.toString(),
      idempotencyKey: `proxy:${idempotency.nonce}:${idempotency.fingerprint}`,
      provider,
      model: model ?? undefined,
    });

    if (!spendCheck.ok) {
      const releaseErr = await releaseDelegationIdempotency();
      if (releaseErr) return releaseErr;

      return errorResponseWithRateLimit(
        spendCheck.code,
        spendCheck.message,
        spendCheck.status,
        rateLimitInfo
      );
    }

    delegatedSpendContext = spendCheck.context;
    payment = {
      ...payment,
      delegationSpend: spendCheck.context,
    };
  }

  // Forward request to provider (with redacted body if policy requires)
  let providerResponse: Response;
  try {
    const providerHeaders: Record<string, string> = {
      'Content-Type': config.contentType,
      ...(falOpenrouter ? buildFalOpenrouterAuthHeader(apiKey) : buildAuthHeader(provider, apiKey)),
    };

    // For streaming requests, explicitly request SSE from the upstream provider.
    if (streamRequested) {
      providerHeaders['Accept'] = request.headers.get('accept') ?? 'text/event-stream';
    }

    // Anthropic requires an API version header.
    if (provider === 'anthropic') {
      providerHeaders['anthropic-version'] = request.headers.get('anthropic-version') ?? '2023-06-01';
      const beta = request.headers.get('anthropic-beta');
      if (beta) providerHeaders['anthropic-beta'] = beta;
    }

    providerResponse = await fetch(providerUrl, {
      method: 'POST',
      headers: providerHeaders,
      body: finalRequestBody,
    });
  } catch (err) {
    if (idempotency) {
      try {
        await releaseIdempotency(
          env,
          idempotency.nonce,
          idempotency.fingerprint
        );
      } catch (releaseErr) {
        const msg =
          releaseErr instanceof Error ? releaseErr.message : 'unknown error';
        return errorResponseWithRateLimit(
          'IDEMPOTENCY_STORE_ERROR',
          `Idempotency store release failed: ${msg}`,
          503,
          rateLimitInfo
        );
      }
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponseWithRateLimit(
      'PROVIDER_ERROR',
      `Failed to reach provider: ${message}`,
      502,
      rateLimitInfo
    );
  }

  // Streaming/SSE support (POH-US-019): do not buffer full bodies.
  // We stream the provider response through while hashing it incrementally to
  // produce a signed gateway receipt at the end.
  const upstreamContentType = providerResponse.headers.get('content-type');
  const upstreamIsEventStream = isEventStreamContentType(upstreamContentType);

  if (streamRequested && providerResponse.ok && upstreamIsEventStream && providerResponse.body) {
    let requestHash: string;
    try {
      requestHash = await sha256(finalRequestBody);
    } catch (err) {
      if (idempotency) {
        try {
          await releaseIdempotency(env, idempotency.nonce, idempotency.fingerprint);
        } catch {
          // ignore (best-effort)
        }
      }

      const message = err instanceof Error ? err.message : 'unknown error';
      return errorResponseWithRateLimit(
        'RECEIPT_HASH_ERROR',
        `Failed to hash request body: ${message}`,
        500,
        rateLimitInfo
      );
    }

    const rateLimitHeaders = buildRateLimitHeaders(rateLimitInfo);

    // Start streaming immediately; receipt is appended as SSE comments at end.
    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        const reader = providerResponse.body!.getReader();
        const hasher = nobleSha256.create();

        try {
          while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            if (!value) continue;

            hasher.update(value);
            controller.enqueue(value);
          }

          const responseHash = bytesToHex(hasher.digest());

          // Log confidential requests WITHOUT plaintext (only metadata)
          if (policyResult.confidentialMode) {
            logConfidentialRequest(request, provider, model, policyResult.policyHash);
          }

          // Streaming receipts are always hash-only (no encrypted payloads).
          const receipt = await generateReceiptFromHashes(
            {
              provider,
              model,
              requestHash,
              responseHash,
              startTime,
              binding: finalBinding,
              payment,
              privacyMode: 'hash_only',
            },
            signingContext
          );

          const modelLabel = receipt.model && receipt.model.trim().length > 0 ? receipt.model : 'unknown';

          const receiptMetadata = await buildReceiptMetadataWithModelIdentity({
            provider,
            model: modelLabel,
            existing: {
              ...(falOpenrouter
                ? { upstream: 'fal_openrouter', upstream_model: falOpenrouterUpstreamModel }
                : {}),
              ...(wpcModelIdentityMeta ?? {}),
              ...(platformFundingCheckMeta ?? {}),
            },
          });

          const receiptEnvelope = await generateReceiptEnvelope(receipt, signingContext, {
            gatewayId,
            metadata: receiptMetadata,
          });

          // RT: submit receipt hash to Receipt Transparency log (best-effort, non-blocking)
          if (isRtEnabled(env)) {
            try {
              const rtProof = await submitReceiptToRt(env, receiptEnvelope.payload_hash_b64u);
              if (rtProof) {
                receiptEnvelope.payload.metadata = {
                  ...(receiptEnvelope.payload.metadata ?? {}),
                  log_inclusion_proof: rtProof,
                };
              }
            } catch (err) {
              console.error('[RT] streaming receipt RT submission failed (non-fatal):', err);
            }
          }

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

          // CPX-US-031: commit idempotency (store receipt only; streaming bodies are not stored)
          if (idempotency) {
            try {
              await commitIdempotency(env, idempotency.nonce, idempotency.fingerprint, {
                status: providerResponse.status,
                body: {
                  streaming: true,
                  _receipt: receipt,
                  _receipt_envelope: receiptEnvelope,
                },
              });
            } catch (err) {
              // Best-effort: still deliver receipt via trailer comments so shims can capture it.
              console.error('idempotency commit failed for streaming response', err);
            }
          }

          // Append clawproxy receipt trailer comments for shim extraction.
          // NOTE: response_hash in the receipt covers ONLY the upstream provider bytes.
          try {
            const trailerText =
              `:clawproxy_receipt_envelope_b64u=${base64urlEncodeJson(receiptEnvelope)}\n` +
              `:clawproxy_receipt_b64u=${base64urlEncodeJson(receipt)}\n\n`;
            controller.enqueue(new TextEncoder().encode(trailerText));
          } catch (err) {
            console.error('failed to append receipt trailer comments', err);
          }

          controller.close();
        } catch (err) {
          try {
            await reader.cancel();
          } catch {
            // ignore
          }

          if (idempotency) {
            try {
              await releaseIdempotency(env, idempotency.nonce, idempotency.fingerprint);
            } catch (releaseErr) {
              console.error('idempotency release failed after streaming error', releaseErr);
            }
          }

          controller.error(err);
        }
      },
    });

    const headers = new Headers({
      'Content-Type': upstreamContentType ?? 'text/event-stream',
      'Cache-Control': 'no-cache',
      'X-Proxy-Version': env.PROXY_VERSION,
      ...rateLimitHeaders,
    });

    return new Response(stream, {
      status: providerResponse.status,
      headers,
    });
  }

  let responseBody: string;
  let encryptionContext: EncryptionContext | null = null;
  let receipt: Awaited<ReturnType<typeof generateReceipt>>;
  let receiptEnvelope: Awaited<ReturnType<typeof generateReceiptEnvelope>>;

  try {
    // Read provider response
    responseBody = await providerResponse.text();

    // Initialize encryption context for encrypted receipts (if privacy mode requests it)
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
    receipt = await generateReceipt(
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

    const modelLabel = receipt.model && receipt.model.trim().length > 0 ? receipt.model : 'unknown';

    const receiptMetadata = await buildReceiptMetadataWithModelIdentity({
      provider,
      model: modelLabel,
      existing: {
        ...(falOpenrouter
          ? { upstream: 'fal_openrouter', upstream_model: falOpenrouterUpstreamModel }
          : {}),
        ...(wpcModelIdentityMeta ?? {}),
        ...(platformFundingCheckMeta ?? {}),
      },
    });

    receiptEnvelope = await generateReceiptEnvelope(receipt, signingContext, {
      gatewayId,
      metadata: receiptMetadata,
    });

    // RT: submit receipt hash to Receipt Transparency log (best-effort, non-blocking)
    if (isRtEnabled(env)) {
      try {
        const rtProof = await submitReceiptToRt(env, receiptEnvelope.payload_hash_b64u);
        if (rtProof) {
          receiptEnvelope.payload.metadata = {
            ...(receiptEnvelope.payload.metadata ?? {}),
            log_inclusion_proof: rtProof,
          };
        }
      } catch (err) {
        console.error('[RT] non-streaming receipt RT submission failed (non-fatal):', err);
      }
    }
  } catch (err) {
    if (idempotency) {
      try {
        await releaseIdempotency(
          env,
          idempotency.nonce,
          idempotency.fingerprint
        );
      } catch (releaseErr) {
        const msg =
          releaseErr instanceof Error ? releaseErr.message : 'unknown error';
        return errorResponseWithRateLimit(
          'IDEMPOTENCY_STORE_ERROR',
          `Idempotency store release failed: ${msg}`,
          503,
          rateLimitInfo
        );
      }
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponseWithRateLimit(
      'PROXY_ERROR',
      `Failed to process provider response: ${message}`,
      502,
      rateLimitInfo
    );
  }

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

    // CPX-US-031: commit idempotency (even for provider errors)
    if (idempotency) {
      try {
        await commitIdempotency(
          env,
          idempotency.nonce,
          idempotency.fingerprint,
          {
            status: providerResponse.status,
            body: withReceipt,
          }
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : 'unknown error';
        return errorResponseWithRateLimit(
          'IDEMPOTENCY_STORE_ERROR',
          `Idempotency store commit failed: ${message}`,
          503,
          rateLimitInfo
        );
      }
    }

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

  // CPX-US-031: commit idempotency
  if (idempotency) {
    try {
      await commitIdempotency(
        env,
        idempotency.nonce,
        idempotency.fingerprint,
        {
          status: 200,
          body: withReceipt,
        }
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : 'unknown error';
      return errorResponseWithRateLimit(
        'IDEMPOTENCY_STORE_ERROR',
        `Idempotency store commit failed: ${message}`,
        503,
        rateLimitInfo
      );
    }
  }

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
