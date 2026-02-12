import {
  base64urlDecode,
  base64urlEncode,
  computeKeyId,
  importEd25519Key,
  importEd25519PublicKey,
  sha256,
  sha256B64u,
  signEd25519,
  verifyEd25519,
} from './crypto';
import {
  ScopeObservabilityCoordinator,
  emitScopeObservabilityEvent,
  handleScopeObservabilityRoutes,
  makeScopeEventFromResponse,
  processScopeObservabilityQueueBatch,
  runScopeObservabilityScheduled,
} from './observability';
import { hasRequiredScope, validateCanonicalControlContext } from '../../../packages/identity-auth/src/index';
import { computeTokenScopeHashB64u } from './token-scope-hash';

const SCOPE_DID = 'did:web:clawscope.com';

export { ScopeObservabilityCoordinator };

export interface Env {
  SCOPE_VERSION: string;

  // policy knobs
  SCOPE_POLICY_VERSION?: string;
  SCOPE_POLICY_JSON?: string;
  SCOPE_POLICY_TIER?: string;
  SCOPE_MAX_TTL_SECONDS?: string;
  SCOPE_MAX_SCOPE_ITEMS?: string;
  SCOPE_MAX_SCOPE_LENGTH?: string;
  SCOPE_ALLOW_WILDCARDS?: string;
  SCOPE_ALLOWED_SCOPES?: string;
  SCOPE_ALLOWED_SCOPE_PREFIXES?: string;

  // canonical CST / migration controls
  SCOPE_LEGACY_EXCHANGE_MODE?: string; // enabled|migration|disabled
  SCOPE_SENSITIVE_SCOPE_PREFIXES?: string;
  SCOPE_KEY_ROTATION_OVERLAP_SECONDS?: string;
  SCOPE_PROTECTED_AUTH_MODE?: string; // canonical_cst|admin_token (default canonical_cst)
  SCOPE_KEY_TRANSPARENCY_REFRESH_SECONDS?: string;
  SCOPE_REVOCATION_SLO_TARGET_SECONDS?: string;

  // control-plane dependency (clawclaim)
  CLAIM_CONTROL_BASE_URL?: string;
  CLAIM_CONTROL_TIMEOUT_MS?: string;

  // revocation storage knobs
  SCOPE_REVOCATION_TTL_SECONDS?: string;

  // storage (optional bindings)
  SCOPE_REVOCATIONS?: KVNamespace;
  SCOPE_OBS_CACHE?: KVNamespace;
  SCOPE_REPORTS_BUCKET?: R2Bucket;

  // observability / reporting stack
  SCOPE_OBSERVABILITY_DB?: D1Database;
  SCOPE_OBS_EVENTS?: Queue<any>;
  SCOPE_METRICS?: AnalyticsEngineDataset;
  SCOPE_OBS_COORDINATOR?: DurableObjectNamespace;
  SCOPE_ALERT_DEFAULT_ERROR_RATE_PERCENT?: string;
  SCOPE_ALERT_DEFAULT_P95_MS?: string;
  SCOPE_ALERT_DEFAULT_REQUEST_COUNT?: string;

  // secrets
  SCOPE_SIGNING_KEY?: string;
  SCOPE_SIGNING_KEYS_JSON?: string;
  SCOPE_VERIFY_PUBLIC_KEYS_JSON?: string;
  SCOPE_ADMIN_KEY?: string;
  SCOPE_ADMIN_KEYS_JSON?: string;
}

export interface ScopedTokenClaims {
  token_version: '1';
  sub: string;
  aud: string | string[];
  scope: string[];
  iat: number;
  exp: number;
  owner_ref?: string;
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  policy_hash_b64u?: string;
  control_plane_policy_hash_b64u?: string;
  token_scope_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
  delegation_id?: string;
  delegator_did?: string;
  delegate_did?: string;
  delegation_policy_hash_b64u?: string;
  delegation_spend_cap_minor?: string;
  delegation_expires_at?: number;
  token_lane?: 'legacy' | 'canonical';
  jti?: string;
  nonce?: string;
}

export interface IssueTokenRequest {
  sub: string;
  aud: string | string[];
  scope: string[];
  ttl_sec?: number;
  exp?: number;
  owner_ref?: string;
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  policy_hash_b64u?: string;
  control_plane_policy_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
  delegation_id?: string;
  delegator_did?: string;
  delegate_did?: string;
  delegation_policy_hash_b64u?: string;
  delegation_spend_cap_minor?: string;
  delegation_expires_at?: number;
  token_lane?: 'legacy' | 'canonical';
  tier?: string;
}

export interface RevokeTokenRequest {
  token?: string;
  token_hash?: string;
  reason?: string;
}

interface RevocationRecord {
  token_hash: string;
  revoked_at: number;
  revoked_at_iso: string;
  reason?: string;
  revoked_by?: string;
}

const REVOCATION_RECORD_PREFIX = 'revoked:hash:';
const REVOCATION_EVENT_PREFIX = 'events:revocations:';

const MAX_REVOCATION_REASON_LENGTH = 256;
// Maximum 10-digit Unix timestamp used to invert timestamps for newest-first KV sorting.
const MAX_TIMESTAMP_FOR_INVERSION = 9_999_999_999;

function revokedRecordKey(token_hash: string): string {
  return `${REVOCATION_RECORD_PREFIX}${token_hash}`;
}

function revocationEventKey(revokedAtSec: number, token_hash: string): string {
  // Invert timestamp so KV list() returns newest-first for the prefix.
  const invTs = String(MAX_TIMESTAMP_FOR_INVERSION - revokedAtSec).padStart(10, '0');
  return `${REVOCATION_EVENT_PREFIX}${invTs}:${token_hash}`;
}

async function getRevocationRecord(env: Env, token_hash: string): Promise<RevocationRecord | null> {
  const kv = env.SCOPE_REVOCATIONS;
  if (!kv) return null;

  const raw = await kv.get(revokedRecordKey(token_hash));
  if (!raw) return null;

  try {
    const rec = JSON.parse(raw) as RevocationRecord;
    if (rec && typeof rec === 'object' && rec.token_hash === token_hash) return rec;
    return { token_hash, revoked_at: 0, revoked_at_iso: '', reason: 'invalid_record' };
  } catch {
    return { token_hash, revoked_at: 0, revoked_at_iso: '', reason: 'unparseable_record' };
  }
}

interface IssuanceRecord {
  token_hash: string;
  issued_at: number;
  issued_at_iso: string;
  sub: string;
  aud: string | string[];
  scope: string[];
  iat: number;
  exp: number;
  kid: string;
  policy_version: string;
  policy_tier?: string;
  owner_ref?: string;
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  policy_hash_b64u?: string;
  control_plane_policy_hash_b64u?: string;
  token_scope_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
  delegation_id?: string;
  delegator_did?: string;
  delegate_did?: string;
  delegation_policy_hash_b64u?: string;
  delegation_spend_cap_minor?: string;
  delegation_expires_at?: number;
  token_lane?: 'legacy' | 'canonical';
  jti?: string;
}

const ISSUANCE_RECORD_PREFIX = 'issued:hash:';
const ISSUANCE_EVENT_PREFIX = 'events:issuance:';

function issuanceRecordKey(token_hash: string): string {
  return `${ISSUANCE_RECORD_PREFIX}${token_hash}`;
}

function issuanceEventKey(issuedAtSec: number, token_hash: string): string {
  const invTs = String(MAX_TIMESTAMP_FOR_INVERSION - issuedAtSec).padStart(10, '0');
  return `${ISSUANCE_EVENT_PREFIX}${invTs}:${token_hash}`;
}

interface IssuerKey {
  privateKey?: CryptoKey;
  publicKey: CryptoKey;
  publicKeyBytes: Uint8Array;
  kid: string;
  jwkX: string;
  signing_enabled: boolean;
  verify_only: boolean;
  source: 'signing' | 'verify_public';
  not_after_unix?: number;
}

interface IssuerKeySet {
  active: IssuerKey;
  keys: IssuerKey[];
  signingKeys: IssuerKey[];
  byKid: Map<string, IssuerKey>;
}

let cachedKeysetRaw: string | null = null;
let cachedKeyset: IssuerKeySet | null = null;

function parseIntOrDefault(value: string | undefined, d: number): number {
  if (!value) return d;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : d;
}

interface VerifyOnlyKeySpec {
  x: string;
  kid?: string;
  not_after_unix?: number;
  source_label?: string;
}

function parseVerifyOnlyKeySpecs(raw: string | undefined): VerifyOnlyKeySpec[] {
  const trimmed = raw?.trim();
  if (!trimmed) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed) as unknown;
  } catch {
    throw new Error('SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID');
  }

  if (!Array.isArray(parsed)) {
    throw new Error('SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID');
  }

  const specs: VerifyOnlyKeySpec[] = [];
  for (const item of parsed) {
    if (typeof item === 'string') {
      const x = item.trim();
      if (!isSha256B64u(x)) {
        throw new Error('SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID');
      }
      specs.push({ x });
      continue;
    }

    if (!item || typeof item !== 'object') {
      throw new Error('SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID');
    }

    const obj = item as Record<string, unknown>;
    const x = typeof obj.x === 'string' ? obj.x.trim() : '';
    const kid = typeof obj.kid === 'string' ? obj.kid.trim() : undefined;
    const notAfter = obj.not_after_unix;
    const sourceLabel = typeof obj.source_label === 'string' ? obj.source_label.trim() : undefined;

    if (!isSha256B64u(x)) {
      throw new Error('SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID');
    }

    if (kid !== undefined && kid.length === 0) {
      throw new Error('SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID');
    }

    if (
      notAfter !== undefined &&
      (typeof notAfter !== 'number' || !Number.isFinite(notAfter) || notAfter <= 0)
    ) {
      throw new Error('SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID');
    }

    specs.push({
      x,
      kid,
      not_after_unix: typeof notAfter === 'number' ? Math.floor(notAfter) : undefined,
      source_label: sourceLabel && sourceLabel.length > 0 ? sourceLabel : undefined,
    });
  }

  return specs;
}

function isKeyAcceptedNow(key: IssuerKey, nowSec: number): boolean {
  if (!key.not_after_unix) return true;
  return nowSec <= key.not_after_unix;
}

function jsonResponse(body: unknown, status = 200, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('content-type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(body, null, 2), { status, headers });
}

function textResponse(body: string, contentType: string, status = 200, version?: string): Response {
  const headers = new Headers({ 'content-type': contentType });
  if (version) headers.set('X-Scope-Version', version);
  return new Response(body, { status, headers });
}

function errorResponse(code: string, message: string, status = 400): Response {
  return jsonResponse({ error: code, message }, status);
}

async function emitScopeObservabilityBestEffort(
  env: Env,
  event: Parameters<typeof emitScopeObservabilityEvent>[1]
): Promise<void> {
  try {
    await emitScopeObservabilityEvent(env, event);
  } catch (err) {
    console.error('SCOPE_OBSERVABILITY_EMIT_FAILED', err);
  }
}

function getBearerToken(header: string | null): string | null {
  if (!header) return null;
  const trimmed = header.trim();
  if (!trimmed) return null;
  if (trimmed.toLowerCase().startsWith('bearer ')) return trimmed.slice(7).trim();
  return trimmed;
}

function resolveAdminKeys(env: Env): { ok: true; keys: string[] } | { ok: false; error: Response } {
  const keys = new Set<string>();

  if (isNonEmptyString(env.SCOPE_ADMIN_KEY)) {
    keys.add(env.SCOPE_ADMIN_KEY.trim());
  }

  const additionalRaw = env.SCOPE_ADMIN_KEYS_JSON?.trim();
  if (additionalRaw) {
    try {
      const parsed = JSON.parse(additionalRaw) as unknown;
      if (!Array.isArray(parsed)) {
        return {
          ok: false,
          error: errorResponse('ADMIN_KEY_CONFIG_INVALID', 'SCOPE_ADMIN_KEYS_JSON must be a JSON array', 503),
        };
      }

      for (const raw of parsed) {
        if (!isNonEmptyString(raw)) {
          return {
            ok: false,
            error: errorResponse(
              'ADMIN_KEY_CONFIG_INVALID',
              'SCOPE_ADMIN_KEYS_JSON entries must be non-empty strings',
              503
            ),
          };
        }
        keys.add(raw.trim());
      }
    } catch {
      return {
        ok: false,
        error: errorResponse('ADMIN_KEY_CONFIG_INVALID', 'SCOPE_ADMIN_KEYS_JSON must be valid JSON', 503),
      };
    }
  }

  if (keys.size === 0) {
    return {
      ok: false,
      error: errorResponse(
        'ADMIN_KEY_NOT_CONFIGURED',
        'SCOPE_ADMIN_KEY or SCOPE_ADMIN_KEYS_JSON is required',
        503
      ),
    };
  }

  return { ok: true, keys: Array.from(keys) };
}

function requireAdmin(request: Request, env: Env): Response | null {
  const resolved = resolveAdminKeys(env);
  if (!resolved.ok) return resolved.error;

  const token = getBearerToken(request.headers.get('Authorization'));
  if (!token) {
    return errorResponse('UNAUTHORIZED', 'Missing Authorization header', 401);
  }

  if (!resolved.keys.includes(token)) {
    return errorResponse('UNAUTHORIZED', 'Invalid admin token', 401);
  }

  return null;
}

type ScopeProtectedAuthMode = 'canonical_cst' | 'admin_token';

function parseProtectedAuthMode(env: Env): ScopeProtectedAuthMode {
  const raw = env.SCOPE_PROTECTED_AUTH_MODE?.trim().toLowerCase();
  if (raw === 'admin_token') return 'admin_token';
  return 'canonical_cst';
}

function looksLikeJwt(token: string): boolean {
  return token.split('.').length === 3;
}

function getScopedTokenFromHeaders(request: Request):
  | { ok: true; token: string }
  | { ok: false; response: Response } {
  const xCst = getBearerToken(request.headers.get('x-cst'));
  const xScoped = getBearerToken(request.headers.get('x-scoped-token'));

  if (xCst && xScoped && xCst !== xScoped) {
    return {
      ok: false,
      response: errorResponse('TOKEN_MALFORMED', 'Conflicting CST headers: X-CST and X-Scoped-Token differ', 401),
    };
  }

  const explicit = xCst ?? xScoped;
  if (explicit) return { ok: true, token: explicit };

  const auth = getBearerToken(request.headers.get('authorization'));
  if (auth && looksLikeJwt(auth)) {
    return { ok: true, token: auth };
  }

  if (auth) {
    return {
      ok: false,
      response: errorResponse(
        'LEGACY_AUTH_FORBIDDEN',
        'Admin token headers are not accepted in canonical auth mode; provide X-CST',
        401
      ),
    };
  }

  return {
    ok: false,
    response: errorResponse('TOKEN_REQUIRED', 'Canonical CST token is required (X-CST or X-Scoped-Token)', 401),
  };
}

interface ProtectedAccessContext {
  token_hash: string;
  claims: ScopedTokenClaims;
  matrix?: ReturnType<typeof evaluateTransitionMatrix>;
}

async function requireProtectedAccess(
  request: Request,
  env: Env,
  options?: {
    requiredScopes?: string[];
    requiredTransitions?: string[];
  }
): Promise<{ ok: true; context: ProtectedAccessContext } | { ok: false; response: Response }> {
  const mode = parseProtectedAuthMode(env);
  if (mode === 'admin_token') {
    const adminErr = requireAdmin(request, env);
    if (adminErr) return { ok: false, response: adminErr };
    return {
      ok: true,
      context: {
        token_hash: 'admin_token',
        claims: {
          token_version: '1',
          sub: 'did:system:scope-admin',
          aud: ['clawscope.com'],
          scope: [
            'control:token:revoke',
            'control:token:issue_sensitive',
            'control:policy:update',
            'control:key:rotate',
            'control:audit:read',
          ],
          iat: Math.floor(Date.now() / 1000),
          exp: Math.floor(Date.now() / 1000) + 60,
          owner_did: 'did:system:scope-admin',
          controller_did: 'did:system:scope-admin',
          agent_did: 'did:system:scope-admin',
          token_lane: 'canonical',
        },
      },
    };
  }

  const token = getScopedTokenFromHeaders(request);
  if (!token.ok) return { ok: false, response: token.response };

  const introspection = await getIntrospectionResult(token.token, env);
  if (!introspection.ok) {
    return { ok: false, response: introspection.res };
  }

  if (introspection.revoked) {
    return {
      ok: false,
      response: errorResponse('TOKEN_REVOKED', 'Token is revoked and cannot authorize protected operations', 401),
    };
  }

  const canonical = validateCanonicalControlContext(
    {
      owner_did: introspection.claims.owner_did,
      controller_did: introspection.claims.controller_did,
      agent_did: introspection.claims.agent_did,
      token_lane: introspection.claims.token_lane,
    },
    undefined
  );

  if (!canonical.ok) {
    return {
      ok: false,
      response: errorResponse(
        canonical.code ?? 'TOKEN_CONTROL_CHAIN_MISSING',
        canonical.message ?? 'Canonical control-chain claims are required',
        401
      ),
    };
  }

  const requiredScopes = options?.requiredScopes ?? [];
  if (requiredScopes.length > 0 && !hasRequiredScope(introspection.claims.scope, requiredScopes)) {
    return {
      ok: false,
      response: errorResponse(
        'TOKEN_INSUFFICIENT_SCOPE',
        `Token does not include required scope(s): ${requiredScopes.join(', ')}`,
        403
      ),
    };
  }

  const requiredTransitions = (options?.requiredTransitions ?? []).filter((value) => value.trim().length > 0);
  let matrix: ReturnType<typeof evaluateTransitionMatrix> | undefined;
  if (requiredTransitions.length > 0) {
    matrix = evaluateTransitionMatrix(introspection.claims);

    const denied = requiredTransitions.filter((transition) => matrix?.[transition]?.allowed !== true);
    if (denied.length > 0) {
      return {
        ok: false,
        response: errorResponse(
          'TOKEN_CONTROL_TRANSITION_FORBIDDEN',
          `Token is not authorized for transition(s): ${denied.join(', ')}`,
          403
        ),
      };
    }
  }

  return {
    ok: true,
    context: {
      token_hash: introspection.token_hash,
      claims: introspection.claims,
      matrix,
    },
  };
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

const SHA256_B64U_RE = /^[A-Za-z0-9_-]{43}$/;
const DID_RE = /^did:[a-z0-9]+:[a-zA-Z0-9._%-]+$/;

function isSha256B64u(value: string): boolean {
  return SHA256_B64U_RE.test(value);
}

function isDid(value: string): boolean {
  return DID_RE.test(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === 'string');
}

function validateAud(value: unknown): value is string | string[] {
  if (typeof value === 'string' && value.length > 0) return true;
  if (Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === 'string' && v.length > 0)) {
    return true;
  }
  return false;
}

function parseCsvList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined) return defaultValue;
  const v = value.trim().toLowerCase();
  if (v === '1' || v === 'true' || v === 'yes' || v === 'y') return true;
  if (v === '0' || v === 'false' || v === 'no' || v === 'n') return false;
  return defaultValue;
}

type LegacyExchangeMode = 'enabled' | 'migration' | 'disabled';

interface ControlChainPolicy {
  policy_version: '1';
  mode: 'owner_bound';
  owner_did: string;
  allowed_sensitive_scopes: string[];
  policy_hash_b64u: string;
  updated_at: number;
  updated_at_iso: string;
}

interface ControlChainRecord {
  status: 'ok';
  owner_did: string;
  chain: {
    owner_did: string;
    controller_did: string;
    agent_did: string;
    policy_hash_b64u: string;
    active: boolean;
  };
  controller: {
    controller_did: string;
    owner_did: string;
    active: boolean;
    policy: ControlChainPolicy;
  };
  agent_binding: {
    binding_version: '1';
    controller_did: string;
    agent_did: string;
    owner_did: string;
    active: boolean;
    policy_hash_b64u: string;
  };
}

function parseLegacyExchangeMode(env: Env): LegacyExchangeMode {
  const raw = env.SCOPE_LEGACY_EXCHANGE_MODE?.trim().toLowerCase();
  if (raw === 'enabled' || raw === 'migration' || raw === 'disabled') return raw;
  return 'migration';
}

function parseSensitiveScopePrefixes(env: Env): string[] {
  const parsed = parseCsvList(env.SCOPE_SENSITIVE_SCOPE_PREFIXES);
  if (parsed.length > 0) return parsed;
  return ['control:'];
}

function collectSensitiveScopes(scopes: string[], prefixes: string[]): string[] {
  return scopes.filter((scope) => prefixes.some((prefix) => scope.startsWith(prefix)));
}

async function fetchControlChainRecord(
  env: Env,
  controllerDid: string,
  agentDid: string,
  fetcher: typeof fetch = fetch
): Promise<
  | { ok: true; record: ControlChainRecord }
  | { ok: false; code: string; message: string; status: number; details?: Record<string, unknown> }
> {
  const baseUrl = env.CLAIM_CONTROL_BASE_URL?.trim();
  if (!baseUrl) {
    return {
      ok: false,
      code: 'CONTROL_PLANE_NOT_CONFIGURED',
      message: 'CLAIM_CONTROL_BASE_URL is not configured',
      status: 503,
    };
  }

  const timeoutMs = parseIntOrDefault(env.CLAIM_CONTROL_TIMEOUT_MS, 5000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const target = `${baseUrl.replace(/\/$/, '')}/v1/control-plane/controllers/${encodeURIComponent(controllerDid)}/agents/${encodeURIComponent(agentDid)}`;
    const response = await fetcher(target, {
      method: 'GET',
      headers: {
        'accept': 'application/json',
      },
      signal: controller.signal,
    });

    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = text ? (JSON.parse(text) as unknown) : null;
    } catch {
      parsed = null;
    }

    if (response.status !== 200) {
      const details =
        parsed && typeof parsed === 'object'
          ? {
              upstream_error: (parsed as Record<string, unknown>).error ?? null,
              upstream_message: (parsed as Record<string, unknown>).message ?? null,
              upstream_status: response.status,
            }
          : { upstream_status: response.status };

      return {
        ok: false,
        code: response.status === 404 ? 'CONTROL_CHAIN_NOT_FOUND' : 'CONTROL_CHAIN_LOOKUP_FAILED',
        message:
          response.status === 404
            ? 'Controller/agent control chain was not found'
            : 'Unable to resolve control chain from clawclaim',
        status: response.status === 404 ? 404 : 502,
        details,
      };
    }

    if (!parsed || typeof parsed !== 'object') {
      return {
        ok: false,
        code: 'CONTROL_CHAIN_LOOKUP_FAILED',
        message: 'Invalid control chain response payload',
        status: 502,
      };
    }

    const record = parsed as ControlChainRecord;
    if (!record.chain || !record.controller || !record.agent_binding) {
      return {
        ok: false,
        code: 'CONTROL_CHAIN_LOOKUP_FAILED',
        message: 'Control chain response missing required fields',
        status: 502,
      };
    }

    return { ok: true, record };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      code: 'CONTROL_CHAIN_LOOKUP_FAILED',
      message: msg.includes('aborted') ? 'Control chain lookup timed out' : 'Control chain lookup failed',
      status: 502,
    };
  } finally {
    clearTimeout(timer);
  }
}

interface ScopeTierPolicy {
  max_ttl_seconds?: number;
  allow_wildcards?: boolean;
  allowed_scopes?: string[];
  allowed_scope_prefixes?: string[];
}

interface ScopePolicyConfig {
  version?: string;
  tiers?: Record<string, ScopeTierPolicy>;
}

interface ResolvedScopePolicy {
  tier: string;
  policy_version: string;
  max_ttl_seconds: number;
  allow_wildcards: boolean;
  allowed_scopes: string[];
  allowed_scope_prefixes: string[];
}

let cachedPolicyRaw: string | null = null;
let cachedPolicy: ScopePolicyConfig | null = null;

function getPolicyConfig(env: Env): ScopePolicyConfig | null {
  const raw = env.SCOPE_POLICY_JSON;
  if (!raw || raw.trim().length === 0) return null;

  if (cachedPolicy && cachedPolicyRaw === raw) return cachedPolicy;

  const parsed = JSON.parse(raw) as unknown;
  if (typeof parsed !== 'object' || parsed === null) {
    throw new Error('POLICY_JSON_INVALID');
  }

  cachedPolicyRaw = raw;
  cachedPolicy = parsed as ScopePolicyConfig;
  return cachedPolicy;
}

function resolveScopePolicy(env: Env, requestedTier: string): ResolvedScopePolicy {
  const baseMaxTtl = parseIntOrDefault(env.SCOPE_MAX_TTL_SECONDS, 3600);

  const fallback: ResolvedScopePolicy = {
    tier: requestedTier,
    policy_version: env.SCOPE_POLICY_VERSION ?? '1',
    max_ttl_seconds: baseMaxTtl,
    allow_wildcards: parseBoolean(env.SCOPE_ALLOW_WILDCARDS, false),
    allowed_scopes: parseCsvList(env.SCOPE_ALLOWED_SCOPES),
    allowed_scope_prefixes: parseCsvList(env.SCOPE_ALLOWED_SCOPE_PREFIXES),
  };

  const config = getPolicyConfig(env);
  if (!config) return fallback;

  if (!config.tiers || typeof config.tiers !== 'object') {
    throw new Error('POLICY_JSON_INVALID');
  }

  const tierPolicy = config.tiers[requestedTier] ?? config.tiers.default;
  if (!tierPolicy) {
    throw new Error('POLICY_TIER_NOT_FOUND');
  }

  return {
    tier: requestedTier,
    policy_version: config.version ?? fallback.policy_version,
    max_ttl_seconds:
      typeof tierPolicy.max_ttl_seconds === 'number' ? tierPolicy.max_ttl_seconds : fallback.max_ttl_seconds,
    allow_wildcards:
      typeof tierPolicy.allow_wildcards === 'boolean' ? tierPolicy.allow_wildcards : fallback.allow_wildcards,
    allowed_scopes: Array.isArray(tierPolicy.allowed_scopes)
      ? tierPolicy.allowed_scopes.filter((s) => typeof s === 'string')
      : fallback.allowed_scopes,
    allowed_scope_prefixes: Array.isArray(tierPolicy.allowed_scope_prefixes)
      ? tierPolicy.allowed_scope_prefixes.filter((s) => typeof s === 'string')
      : fallback.allowed_scope_prefixes,
  };
}

function enforceScopePolicy(
  scopes: string[],
  policy: ResolvedScopePolicy
): { ok: true } | { ok: false; res: Response } {
  if (!policy.allow_wildcards) {
    for (const s of scopes) {
      if (s.includes('*')) {
        return {
          ok: false,
          res: errorResponse(
            'SCOPE_WILDCARD_NOT_ALLOWED',
            'wildcard scopes are not allowed by policy',
            400
          ),
        };
      }
    }
  }

  if (policy.allowed_scopes.length > 0) {
    for (const s of scopes) {
      if (!policy.allowed_scopes.includes(s)) {
        return {
          ok: false,
          res: errorResponse('SCOPE_NOT_ALLOWED', `scope '${s}' is not allowed for tier '${policy.tier}'`, 400),
        };
      }
    }
  } else if (policy.allowed_scope_prefixes.length > 0) {
    for (const s of scopes) {
      if (!policy.allowed_scope_prefixes.some((p) => s.startsWith(p))) {
        return {
          ok: false,
          res: errorResponse('SCOPE_NOT_ALLOWED', `scope '${s}' is not allowed for tier '${policy.tier}'`, 400),
        };
      }
    }
  }

  return { ok: true };
}

function validateIssueRequest(body: unknown, env: Env): { ok: true; req: IssueTokenRequest } | { ok: false; res: Response } {
  if (typeof body !== 'object' || body === null) {
    return { ok: false, res: errorResponse('INVALID_REQUEST', 'Request body must be a JSON object', 400) };
  }

  const b = body as Record<string, unknown>;

  const tierInput = typeof b.tier === 'string' ? b.tier.trim() : '';
  const envTier = typeof env.SCOPE_POLICY_TIER === 'string' ? env.SCOPE_POLICY_TIER.trim() : '';
  const tier = tierInput || envTier || 'default';

  if (!isNonEmptyString(b.sub)) {
    return { ok: false, res: errorResponse('INVALID_REQUEST', 'sub is required', 400) };
  }
  if (!validateAud(b.aud)) {
    return { ok: false, res: errorResponse('INVALID_REQUEST', 'aud is required', 400) };
  }
  if (!isStringArray(b.scope) || b.scope.length === 0) {
    return { ok: false, res: errorResponse('INVALID_REQUEST', 'scope must be a non-empty array of strings', 400) };
  }

  const maxItems = parseIntOrDefault(env.SCOPE_MAX_SCOPE_ITEMS, 64);
  if (b.scope.length > maxItems) {
    return {
      ok: false,
      res: errorResponse('SCOPE_TOO_LARGE', `scope must have <= ${maxItems} items`, 400),
    };
  }

  const maxLen = parseIntOrDefault(env.SCOPE_MAX_SCOPE_LENGTH, 128);
  for (const s of b.scope) {
    if (!s || s.length > maxLen) {
      return {
        ok: false,
        res: errorResponse('SCOPE_ITEM_TOO_LONG', `scope entries must be <= ${maxLen} chars`, 400),
      };
    }
  }

  const ttl = typeof b.ttl_sec === 'number' ? b.ttl_sec : undefined;
  const exp = typeof b.exp === 'number' ? b.exp : undefined;

  if (ttl !== undefined && (!Number.isFinite(ttl) || ttl <= 0)) {
    return { ok: false, res: errorResponse('INVALID_TTL', 'ttl_sec must be a positive number', 400) };
  }
  if (exp !== undefined && (!Number.isFinite(exp) || exp <= 0)) {
    return { ok: false, res: errorResponse('INVALID_EXP', 'exp must be a positive number', 400) };
  }

  const scopes = (b.scope as string[])
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  if (scopes.length === 0) {
    return {
      ok: false,
      res: errorResponse('INVALID_REQUEST', 'scope must contain at least one non-empty string', 400),
    };
  }

  const req: IssueTokenRequest = {
    sub: b.sub.trim(),
    aud: b.aud as string | string[],
    scope: scopes,
    tier,
  };

  if (ttl !== undefined) req.ttl_sec = ttl;
  if (exp !== undefined) req.exp = exp;
  if (typeof b.owner_ref === 'string') req.owner_ref = b.owner_ref;

  const ownerDidInput = typeof b.owner_did === 'string' ? b.owner_did.trim() : '';
  if (ownerDidInput) {
    if (!isDid(ownerDidInput)) {
      return {
        ok: false,
        res: errorResponse('OWNER_DID_INVALID', 'owner_did must be a valid DID string', 400),
      };
    }
    req.owner_did = ownerDidInput;
  }

  const controllerDidInput = typeof b.controller_did === 'string' ? b.controller_did.trim() : '';
  if (controllerDidInput) {
    if (!isDid(controllerDidInput)) {
      return {
        ok: false,
        res: errorResponse('CONTROLLER_DID_INVALID', 'controller_did must be a valid DID string', 400),
      };
    }
    req.controller_did = controllerDidInput;
  }

  const agentDidInput = typeof b.agent_did === 'string' ? b.agent_did.trim() : '';
  if (agentDidInput) {
    if (!isDid(agentDidInput)) {
      return {
        ok: false,
        res: errorResponse('AGENT_DID_INVALID', 'agent_did must be a valid DID string', 400),
      };
    }
    req.agent_did = agentDidInput;
  }

  const laneInput = typeof b.token_lane === 'string' ? b.token_lane.trim() : '';
  if (laneInput) {
    if (laneInput !== 'legacy' && laneInput !== 'canonical') {
      return {
        ok: false,
        res: errorResponse('TOKEN_LANE_INVALID', 'token_lane must be "legacy" or "canonical"', 400),
      };
    }
    req.token_lane = laneInput;
  }

  const policyHashInput = typeof b.policy_hash_b64u === 'string' ? b.policy_hash_b64u.trim() : '';
  if (policyHashInput) {
    if (!isSha256B64u(policyHashInput)) {
      return {
        ok: false,
        res: errorResponse(
          'POLICY_HASH_INVALID',
          'policy_hash_b64u must be a SHA-256 base64url hash (length 43)',
          400
        ),
      };
    }
    req.policy_hash_b64u = policyHashInput;
  }

  const controlPolicyHashInput =
    typeof b.control_plane_policy_hash_b64u === 'string' ? b.control_plane_policy_hash_b64u.trim() : '';
  if (controlPolicyHashInput) {
    if (!isSha256B64u(controlPolicyHashInput)) {
      return {
        ok: false,
        res: errorResponse(
          'CONTROL_POLICY_HASH_INVALID',
          'control_plane_policy_hash_b64u must be a SHA-256 base64url hash (length 43)',
          400
        ),
      };
    }
    req.control_plane_policy_hash_b64u = controlPolicyHashInput;
  }

  const paymentAccountDidInput =
    typeof b.payment_account_did === 'string' ? b.payment_account_did.trim() : '';
  if (paymentAccountDidInput) {
    if (!isDid(paymentAccountDidInput)) {
      return {
        ok: false,
        res: errorResponse(
          'PAYMENT_ACCOUNT_CLAIM_INVALID',
          'payment_account_did must be a valid DID string',
          400
        ),
      };
    }
    req.payment_account_did = paymentAccountDidInput;
  }

  if (typeof b.spend_cap === 'number') req.spend_cap = b.spend_cap;
  if (typeof b.mission_id === 'string') req.mission_id = b.mission_id;

  const delegationIdInput = typeof b.delegation_id === 'string' ? b.delegation_id.trim() : '';
  if (delegationIdInput) {
    req.delegation_id = delegationIdInput;
  }

  const delegatorDidInput = typeof b.delegator_did === 'string' ? b.delegator_did.trim() : '';
  if (delegatorDidInput) {
    if (!isDid(delegatorDidInput)) {
      return {
        ok: false,
        res: errorResponse('DELEGATOR_DID_INVALID', 'delegator_did must be a valid DID string', 400),
      };
    }
    req.delegator_did = delegatorDidInput;
  }

  const delegateDidInput = typeof b.delegate_did === 'string' ? b.delegate_did.trim() : '';
  if (delegateDidInput) {
    if (!isDid(delegateDidInput)) {
      return {
        ok: false,
        res: errorResponse('DELEGATE_DID_INVALID', 'delegate_did must be a valid DID string', 400),
      };
    }
    req.delegate_did = delegateDidInput;
  }

  const delegationPolicyHashInput =
    typeof b.delegation_policy_hash_b64u === 'string' ? b.delegation_policy_hash_b64u.trim() : '';
  if (delegationPolicyHashInput) {
    if (!isSha256B64u(delegationPolicyHashInput)) {
      return {
        ok: false,
        res: errorResponse(
          'DELEGATION_POLICY_HASH_INVALID',
          'delegation_policy_hash_b64u must be a SHA-256 base64url hash (length 43)',
          400
        ),
      };
    }
    req.delegation_policy_hash_b64u = delegationPolicyHashInput;
  }

  const delegationSpendCapInput =
    typeof b.delegation_spend_cap_minor === 'string' ? b.delegation_spend_cap_minor.trim() : '';
  if (delegationSpendCapInput) {
    if (!/^[0-9]+$/.test(delegationSpendCapInput)) {
      return {
        ok: false,
        res: errorResponse(
          'DELEGATION_SPEND_CAP_INVALID',
          'delegation_spend_cap_minor must be an integer string',
          400
        ),
      };
    }
    req.delegation_spend_cap_minor = delegationSpendCapInput;
  }

  if (typeof b.delegation_expires_at === 'number' && Number.isFinite(b.delegation_expires_at)) {
    req.delegation_expires_at = Math.floor(b.delegation_expires_at);
  }

  if (req.delegate_did && req.delegate_did !== req.sub) {
    return {
      ok: false,
      res: errorResponse('DELEGATE_DID_SUB_MISMATCH', 'delegate_did must match sub for delegated tokens', 400),
    };
  }

  if (req.delegator_did && req.owner_did && req.delegator_did !== req.owner_did) {
    return {
      ok: false,
      res: errorResponse('DELEGATOR_OWNER_MISMATCH', 'delegator_did must match owner_did when both are set', 400),
    };
  }

  if (
    req.delegation_id ||
    req.delegator_did ||
    req.delegate_did ||
    req.delegation_policy_hash_b64u ||
    req.delegation_spend_cap_minor ||
    req.delegation_expires_at !== undefined
  ) {
    if (req.token_lane !== 'canonical') {
      return {
        ok: false,
        res: errorResponse('DELEGATION_CANONICAL_REQUIRED', 'delegation claims require token_lane=canonical', 400),
      };
    }
  }

  try {
    const policy = resolveScopePolicy(env, tier);
    const enforced = enforceScopePolicy(req.scope, policy);
    if (!enforced.ok) return { ok: false, res: enforced.res };
  } catch {
    return { ok: false, res: errorResponse('POLICY_CONFIG_INVALID', 'Token policy configuration is invalid', 503) };
  }

  return { ok: true, req };
}

function buildTransitionRequirements(): Record<string, string[]> {
  return {
    'controller.policy.update': ['control:policy:update'],
    'token.issue.sensitive': ['control:token:issue_sensitive'],
    'token.revoke': ['control:token:revoke'],
    'key.rotate': ['control:key:rotate'],
  };
}

function evaluateTransitionMatrix(claims: ScopedTokenClaims): Record<string, {
  allowed: boolean;
  reason_code: string;
  reason: string;
}> {
  const requirements = buildTransitionRequirements();
  const scopeSet = new Set(claims.scope.map((s) => s.trim()));
  const hasChain =
    typeof claims.owner_did === 'string' && claims.owner_did.length > 0 &&
    typeof claims.controller_did === 'string' && claims.controller_did.length > 0 &&
    typeof claims.agent_did === 'string' && claims.agent_did.length > 0;

  const out: Record<string, { allowed: boolean; reason_code: string; reason: string }> = {};

  for (const [transition, requiredScopes] of Object.entries(requirements)) {
    if (!hasChain) {
      out[transition] = {
        allowed: false,
        reason_code: 'TOKEN_CONTROL_CHAIN_MISSING',
        reason: 'Token is missing owner/controller/agent chain claims',
      };
      continue;
    }

    if (claims.token_lane !== 'canonical') {
      out[transition] = {
        allowed: false,
        reason_code: 'TOKEN_LANE_LEGACY_FORBIDDEN',
        reason: 'Sensitive transitions require canonical token lane',
      };
      continue;
    }

    const missing = requiredScopes.filter(
      (scope) => !scopeSet.has(scope) && !scopeSet.has('control:*') && !scopeSet.has('*')
    );
    if (missing.length > 0) {
      out[transition] = {
        allowed: false,
        reason_code: 'TOKEN_SCOPE_MISSING',
        reason: `Missing required scope(s): ${missing.join(', ')}`,
      };
      continue;
    }

    out[transition] = {
      allowed: true,
      reason_code: 'ALLOWED',
      reason: 'Transition requirements satisfied',
    };
  }

  return out;
}

async function getIntrospectionResult(
  token: string,
  env: Env
): Promise<
  | {
      ok: true;
      claims: ScopedTokenClaims;
      token_hash: string;
      revoked: boolean;
      revoked_at?: number;
      revoked_at_iso?: string;
      kid?: string;
      kid_source?: 'header' | 'recovered';
    }
  | { ok: false; res: Response }
> {
  const token_hash = await sha256(token);
  const parts = token.split('.');
  if (parts.length !== 3) {
    return {
      ok: false,
      res: errorResponse('TOKEN_MALFORMED', 'CST token must be a JWT (header.payload.signature)', 401),
    };
  }

  const headerB64u = parts[0]!;
  const payloadB64u = parts[1]!;
  const signatureB64u = parts[2]!;

  let header: unknown;
  try {
    header = decodeJwtJsonSegment(headerB64u);
  } catch {
    return { ok: false, res: errorResponse('TOKEN_MALFORMED', 'Invalid JWT header encoding', 401) };
  }

  if (typeof header !== 'object' || header === null) {
    return { ok: false, res: errorResponse('TOKEN_MALFORMED', 'Invalid JWT header', 401) };
  }

  const h = header as Record<string, unknown>;
  if (h.alg !== 'EdDSA') {
    return {
      ok: false,
      res: errorResponse('TOKEN_UNSUPPORTED_ALG', 'Unsupported token algorithm (expected EdDSA)', 401),
    };
  }

  let payload: unknown;
  try {
    payload = decodeJwtJsonSegment(payloadB64u);
  } catch {
    return { ok: false, res: errorResponse('TOKEN_MALFORMED', 'Invalid JWT payload encoding', 401) };
  }

  if (typeof payload === 'object' && payload !== null) {
    const pv = (payload as Record<string, unknown>).token_version;
    if (pv !== undefined && pv !== '1') {
      return { ok: false, res: errorResponse('TOKEN_UNKNOWN_VERSION', 'Unknown token_version', 401) };
    }
  }

  if (!validateClaimsShape(payload)) {
    return {
      ok: false,
      res: errorResponse('TOKEN_INVALID_CLAIMS', 'Token claims do not match scoped_token_claims.v1 schema', 401),
    };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (payload.exp <= nowSec) {
    return { ok: false, res: errorResponse('TOKEN_EXPIRED', 'Token has expired', 401) };
  }

  let keyset: IssuerKeySet | null;
  try {
    keyset = await getIssuerKeySet(env);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg === 'SCOPE_SIGNING_KEY_NOT_CONFIGURED') {
      return { ok: false, res: errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503) };
    }
    return { ok: false, res: errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503) };
  }

  if (!keyset) {
    return { ok: false, res: errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503) };
  }

  let verifyKey: CryptoKey | null = null;
  let matchedKid: string | undefined;
  let kidSource: 'header' | 'recovered' | undefined;

  if (typeof h.kid === 'string' && h.kid.trim().length > 0) {
    const headerKid = h.kid.trim();
    const key = keyset.byKid.get(headerKid);
    if (!key) {
      return { ok: false, res: errorResponse('TOKEN_UNKNOWN_KID', 'Unknown token kid', 401) };
    }

    if (!isKeyAcceptedNow(key, nowSec)) {
      return {
        ok: false,
        res: errorResponse('TOKEN_KID_EXPIRED', 'Token kid is no longer within accepted overlap window', 401),
      };
    }

    verifyKey = key.publicKey;
    matchedKid = headerKid;
    kidSource = 'header';
  }

  const signingInput = `${headerB64u}.${payloadB64u}`;
  let sigValid = false;

  try {
    if (verifyKey) {
      sigValid = await verifyEd25519(verifyKey, signatureB64u, signingInput);
    } else {
      for (const k of keyset.keys) {
        if (!isKeyAcceptedNow(k, nowSec)) continue;
        if (await verifyEd25519(k.publicKey, signatureB64u, signingInput)) {
          sigValid = true;
          matchedKid = k.kid;
          kidSource = 'recovered';
          break;
        }
      }
    }
  } catch {
    return { ok: false, res: errorResponse('TOKEN_SIGNATURE_INVALID', 'Token signature verification failed', 401) };
  }

  if (!sigValid) {
    return { ok: false, res: errorResponse('TOKEN_SIGNATURE_INVALID', 'Token signature verification failed', 401) };
  }

  const revocation = await getRevocationRecord(env, token_hash);
  if (revocation) {
    return {
      ok: true,
      claims: payload,
      token_hash,
      revoked: true,
      revoked_at: revocation.revoked_at,
      revoked_at_iso: revocation.revoked_at_iso,
      kid: matchedKid,
      kid_source: kidSource,
    };
  }

  return {
    ok: true,
    claims: payload,
    token_hash,
    revoked: false,
    kid: matchedKid,
    kid_source: kidSource,
  };
}

async function getIssuerKeySet(env: Env): Promise<IssuerKeySet | null> {
  const jsonText = env.SCOPE_SIGNING_KEYS_JSON?.trim();
  const verifyJsonText = env.SCOPE_VERIFY_PUBLIC_KEYS_JSON?.trim();
  const cacheKeyParts = [
    jsonText
      ? `json:${jsonText}`
      : env.SCOPE_SIGNING_KEY
        ? `single:${env.SCOPE_SIGNING_KEY}`
        : null,
    verifyJsonText ? `verify:${verifyJsonText}` : null,
  ].filter((v): v is string => Boolean(v));
  const cacheKey = cacheKeyParts.join('|');

  if (!cacheKey) return null;

  if (cachedKeyset && cachedKeysetRaw === cacheKey) {
    return cachedKeyset;
  }

  let keyStrings: string[];

  if (jsonText) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(jsonText) as unknown;
    } catch {
      throw new Error('SCOPE_SIGNING_KEYS_JSON_INVALID');
    }

    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new Error('SCOPE_SIGNING_KEYS_JSON_INVALID');
    }

    keyStrings = parsed.map((v) => (typeof v === 'string' ? v.trim() : ''));
    if (keyStrings.some((k) => k.length === 0)) {
      throw new Error('SCOPE_SIGNING_KEYS_JSON_INVALID');
    }
  } else if (env.SCOPE_SIGNING_KEY && env.SCOPE_SIGNING_KEY.trim().length > 0) {
    // Single-key mode
    keyStrings = [env.SCOPE_SIGNING_KEY.trim()];
  } else {
    keyStrings = [];
  }

  const keys: IssuerKey[] = [];
  const signingKeys: IssuerKey[] = [];
  const byKid = new Map<string, IssuerKey>();

  for (const keyStr of keyStrings) {
    const kp = await importEd25519Key(keyStr);
    const kid = await computeKeyId(kp.publicKeyBytes);
    const jwkX = base64urlEncode(kp.publicKeyBytes);

    const k: IssuerKey = {
      privateKey: kp.privateKey,
      publicKey: kp.publicKey,
      publicKeyBytes: kp.publicKeyBytes,
      kid,
      jwkX,
      signing_enabled: true,
      verify_only: false,
      source: 'signing',
    };

    if (byKid.has(kid)) {
      throw new Error('SCOPE_SIGNING_KEYS_DUPLICATE_KID');
    }

    keys.push(k);
    signingKeys.push(k);
    byKid.set(kid, k);
  }

  const verifyOnlySpecs = parseVerifyOnlyKeySpecs(env.SCOPE_VERIFY_PUBLIC_KEYS_JSON);
  for (const spec of verifyOnlySpecs) {
    const imported = await importEd25519PublicKey(spec.x);
    const computedKid = await computeKeyId(imported.publicKeyBytes);
    const kid = spec.kid ?? computedKid;

    if (kid !== computedKid) {
      throw new Error('SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID');
    }

    const existing = byKid.get(kid);
    if (existing) {
      if (existing.jwkX !== spec.x) {
        throw new Error('SCOPE_VERIFY_PUBLIC_KEYS_DUPLICATE_KID');
      }
      // Same key already available through signing keys; keep deterministic signing source.
      continue;
    }

    const verifyOnly: IssuerKey = {
      privateKey: undefined,
      publicKey: imported.publicKey,
      publicKeyBytes: imported.publicKeyBytes,
      kid,
      jwkX: spec.x,
      signing_enabled: false,
      verify_only: true,
      source: 'verify_public',
      not_after_unix: spec.not_after_unix,
    };

    keys.push(verifyOnly);
    byKid.set(kid, verifyOnly);
  }

  const active = signingKeys[0];
  if (!active) {
    throw new Error('SCOPE_SIGNING_KEY_NOT_CONFIGURED');
  }

  const keyset: IssuerKeySet = {
    active,
    keys,
    signingKeys,
    byKid,
  };

  cachedKeysetRaw = cacheKey;
  cachedKeyset = keyset;

  return keyset;
}

interface KeyTransparencySnapshot {
  snapshot_version: '1';
  snapshot_id: string;
  generated_at: number;
  generated_at_iso: string;
  active_kid: string;
  accepted_kids: string[];
  signing_kids: string[];
  verify_only_kids: string[];
  expiring_kids: Array<{ kid: string; not_after_unix: number }>;
  overlap_seconds: number;
  snapshot_hash_b64u: string;
  signer_kid: string;
  signature_b64u: string;
  r2_object_key?: string;
}

interface RevocationSloReport {
  report_version: '1';
  generated_at: number;
  generated_at_iso: string;
  window_hours: number;
  slo_target_seconds: number;
  total_revocations: number;
  observed_revocations: number;
  pending_revocations: number;
  compliance_ratio: number;
  latency_seconds: {
    min: number;
    p50: number;
    p95: number;
    p99: number;
    max: number;
  };
  r2_object_key?: string;
}

let governanceSchemaInitialized = false;

async function ensureScopeGovernanceSchema(db: D1Database): Promise<void> {
  if (governanceSchemaInitialized) return;

  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS scope_key_transparency_snapshots (
        snapshot_id TEXT PRIMARY KEY,
        generated_at INTEGER NOT NULL,
        generated_at_iso TEXT NOT NULL,
        active_kid TEXT NOT NULL,
        accepted_kids_json TEXT NOT NULL,
        signing_kids_json TEXT NOT NULL,
        verify_only_kids_json TEXT NOT NULL,
        expiring_kids_json TEXT NOT NULL,
        overlap_seconds INTEGER NOT NULL,
        snapshot_hash_b64u TEXT NOT NULL,
        signer_kid TEXT NOT NULL,
        signature_b64u TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        r2_object_key TEXT,
        persisted_at INTEGER NOT NULL
      )
    `),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_scope_key_transparency_generated ON scope_key_transparency_snapshots(generated_at DESC)`
    ),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS scope_revocation_slo_tokens (
        token_hash TEXT PRIMARY KEY,
        revoked_at INTEGER NOT NULL,
        revoked_at_iso TEXT NOT NULL,
        first_observed_revoked_at INTEGER,
        last_observed_revoked_at INTEGER,
        observed_count INTEGER NOT NULL DEFAULT 0
      )
    `),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_scope_revocation_slo_revoked_at ON scope_revocation_slo_tokens(revoked_at DESC)`
    ),
  ]);

  governanceSchemaInitialized = true;
}

function quantile(values: number[], q: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.max(0, Math.min(sorted.length - 1, Math.ceil(sorted.length * q) - 1));
  return Number(sorted[idx] ?? 0);
}

async function buildKeyTransparencySnapshot(env: Env, keyset: IssuerKeySet): Promise<KeyTransparencySnapshot> {
  const nowSec = Math.floor(Date.now() / 1000);
  const nowIso = new Date(nowSec * 1000).toISOString();
  const overlapSeconds = parseIntOrDefault(env.SCOPE_KEY_ROTATION_OVERLAP_SECONDS, 3600);

  const acceptedKeys = keyset.keys.filter((key) => isKeyAcceptedNow(key, nowSec));
  const expiringKeys = acceptedKeys
    .filter((key) => key.not_after_unix !== undefined)
    .map((key) => ({
      kid: key.kid,
      not_after_unix: key.not_after_unix as number,
    }));

  const payload = {
    snapshot_version: '1' as const,
    generated_at: nowSec,
    generated_at_iso: nowIso,
    active_kid: keyset.active.kid,
    accepted_kids: acceptedKeys.map((key) => key.kid),
    signing_kids: keyset.signingKeys.map((key) => key.kid),
    verify_only_kids: acceptedKeys.filter((key) => key.verify_only).map((key) => key.kid),
    expiring_kids: expiringKeys,
    overlap_seconds: overlapSeconds,
  };

  if (!keyset.active.privateKey) {
    throw new Error('SCOPE_SIGNING_KEY_NOT_CONFIGURED');
  }

  const payloadJson = JSON.stringify(payload);
  const snapshotHashB64u = await sha256B64u(payloadJson);
  const signatureB64u = await signEd25519(keyset.active.privateKey, payloadJson);

  const snapshotId = `kts_${nowSec}_${keyset.active.kid}`;

  return {
    ...payload,
    snapshot_id: snapshotId,
    snapshot_hash_b64u: snapshotHashB64u,
    signer_kid: keyset.active.kid,
    signature_b64u: signatureB64u,
  };
}

async function parseSnapshotRow(row: unknown): Promise<KeyTransparencySnapshot | null> {
  if (!row || typeof row !== 'object') return null;
  const r = row as Record<string, unknown>;

  const snapshotJson = typeof r.snapshot_json === 'string' ? r.snapshot_json : undefined;
  if (!snapshotJson) return null;

  try {
    return JSON.parse(snapshotJson) as KeyTransparencySnapshot;
  } catch {
    return null;
  }
}

async function readLatestKeyTransparencySnapshot(env: Env): Promise<KeyTransparencySnapshot | null> {
  const db = env.SCOPE_OBSERVABILITY_DB;
  if (!db) return null;

  await ensureScopeGovernanceSchema(db);
  const row = await db
    .prepare(
      `SELECT snapshot_json FROM scope_key_transparency_snapshots ORDER BY generated_at DESC LIMIT 1`
    )
    .first();

  return parseSnapshotRow(row);
}

async function persistKeyTransparencySnapshot(
  env: Env,
  snapshot: KeyTransparencySnapshot
): Promise<KeyTransparencySnapshot> {
  const persistedAt = Math.floor(Date.now() / 1000);
  let r2ObjectKey: string | undefined;

  if (env.SCOPE_REPORTS_BUCKET) {
    const key = `identity-control-plane/key-transparency/${snapshot.generated_at_iso}-${snapshot.snapshot_id}.json`;
    await env.SCOPE_REPORTS_BUCKET.put(key, JSON.stringify(snapshot, null, 2), {
      httpMetadata: { contentType: 'application/json; charset=utf-8' },
    });
    r2ObjectKey = key;
  }

  const db = env.SCOPE_OBSERVABILITY_DB;
  if (db) {
    await ensureScopeGovernanceSchema(db);
    await db
      .prepare(
        `INSERT OR REPLACE INTO scope_key_transparency_snapshots (
          snapshot_id,
          generated_at,
          generated_at_iso,
          active_kid,
          accepted_kids_json,
          signing_kids_json,
          verify_only_kids_json,
          expiring_kids_json,
          overlap_seconds,
          snapshot_hash_b64u,
          signer_kid,
          signature_b64u,
          snapshot_json,
          r2_object_key,
          persisted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        snapshot.snapshot_id,
        snapshot.generated_at,
        snapshot.generated_at_iso,
        snapshot.active_kid,
        JSON.stringify(snapshot.accepted_kids),
        JSON.stringify(snapshot.signing_kids),
        JSON.stringify(snapshot.verify_only_kids),
        JSON.stringify(snapshot.expiring_kids),
        snapshot.overlap_seconds,
        snapshot.snapshot_hash_b64u,
        snapshot.signer_kid,
        snapshot.signature_b64u,
        JSON.stringify({ ...snapshot, r2_object_key: r2ObjectKey ?? snapshot.r2_object_key }),
        r2ObjectKey ?? null,
        persistedAt
      )
      .run();
  }

  return {
    ...snapshot,
    r2_object_key: r2ObjectKey ?? snapshot.r2_object_key,
  };
}

async function getOrCreateKeyTransparencySnapshot(
  env: Env,
  forceRefresh = false
): Promise<KeyTransparencySnapshot> {
  const refreshSeconds = parseIntOrDefault(env.SCOPE_KEY_TRANSPARENCY_REFRESH_SECONDS, 300);

  if (!forceRefresh) {
    const latest = await readLatestKeyTransparencySnapshot(env);
    if (latest) {
      const ageSec = Math.floor(Date.now() / 1000) - latest.generated_at;
      if (ageSec >= 0 && ageSec <= refreshSeconds) {
        return latest;
      }
    }
  }

  const keyset = await getIssuerKeySet(env);
  if (!keyset) {
    throw new Error('SCOPE_SIGNING_KEY_NOT_CONFIGURED');
  }

  const snapshot = await buildKeyTransparencySnapshot(env, keyset);
  return persistKeyTransparencySnapshot(env, snapshot);
}

async function seedRevocationSloToken(
  env: Env,
  tokenHash: string,
  revokedAtSec: number,
  revokedAtIso: string
): Promise<void> {
  const db = env.SCOPE_OBSERVABILITY_DB;
  if (!db) return;

  await ensureScopeGovernanceSchema(db);

  await db
    .prepare(
      `INSERT INTO scope_revocation_slo_tokens (
        token_hash,
        revoked_at,
        revoked_at_iso,
        first_observed_revoked_at,
        last_observed_revoked_at,
        observed_count
      ) VALUES (?, ?, ?, NULL, NULL, 0)
      ON CONFLICT(token_hash) DO UPDATE SET
        revoked_at = MIN(scope_revocation_slo_tokens.revoked_at, excluded.revoked_at),
        revoked_at_iso = CASE
          WHEN excluded.revoked_at < scope_revocation_slo_tokens.revoked_at THEN excluded.revoked_at_iso
          ELSE scope_revocation_slo_tokens.revoked_at_iso
        END`
    )
    .bind(tokenHash, revokedAtSec, revokedAtIso)
    .run();
}

async function observeRevocationSloToken(env: Env, tokenHash: string, observedAtSec: number): Promise<void> {
  const db = env.SCOPE_OBSERVABILITY_DB;
  if (!db) return;

  await ensureScopeGovernanceSchema(db);

  await db
    .prepare(
      `INSERT INTO scope_revocation_slo_tokens (
        token_hash,
        revoked_at,
        revoked_at_iso,
        first_observed_revoked_at,
        last_observed_revoked_at,
        observed_count
      ) VALUES (?, ?, ?, ?, ?, 1)
      ON CONFLICT(token_hash) DO UPDATE SET
        first_observed_revoked_at = COALESCE(scope_revocation_slo_tokens.first_observed_revoked_at, excluded.first_observed_revoked_at),
        last_observed_revoked_at = excluded.last_observed_revoked_at,
        observed_count = scope_revocation_slo_tokens.observed_count + 1`
    )
    .bind(
      tokenHash,
      observedAtSec,
      new Date(observedAtSec * 1000).toISOString(),
      observedAtSec,
      observedAtSec
    )
    .run();
}

async function buildRevocationSloReport(env: Env, windowHours: number): Promise<RevocationSloReport> {
  const db = env.SCOPE_OBSERVABILITY_DB;
  if (!db) {
    throw new Error('OBSERVABILITY_DB_NOT_CONFIGURED');
  }

  await ensureScopeGovernanceSchema(db);

  const nowSec = Math.floor(Date.now() / 1000);
  const fromSec = nowSec - windowHours * 60 * 60;

  const rows = await db
    .prepare(
      `SELECT token_hash, revoked_at, first_observed_revoked_at
       FROM scope_revocation_slo_tokens
       WHERE revoked_at >= ?
       ORDER BY revoked_at DESC`
    )
    .bind(fromSec)
    .all();

  const results = rows.results ?? [];
  const latencies: number[] = [];

  for (const row of results) {
    const record = row as Record<string, unknown>;
    const revokedAt = typeof record.revoked_at === 'number' ? record.revoked_at : Number(record.revoked_at);
    const firstObservedRaw = record.first_observed_revoked_at;
    const firstObserved =
      typeof firstObservedRaw === 'number' ? firstObservedRaw : Number(firstObservedRaw ?? Number.NaN);

    if (Number.isFinite(revokedAt) && Number.isFinite(firstObserved) && firstObserved >= revokedAt) {
      latencies.push(firstObserved - revokedAt);
    }
  }

  const totalRevocations = results.length;
  const observedRevocations = latencies.length;
  const pendingRevocations = totalRevocations - observedRevocations;
  const sloTargetSeconds = parseIntOrDefault(env.SCOPE_REVOCATION_SLO_TARGET_SECONDS, 60);
  const compliant = latencies.filter((latency) => latency <= sloTargetSeconds).length;

  return {
    report_version: '1',
    generated_at: nowSec,
    generated_at_iso: new Date(nowSec * 1000).toISOString(),
    window_hours: windowHours,
    slo_target_seconds: sloTargetSeconds,
    total_revocations: totalRevocations,
    observed_revocations: observedRevocations,
    pending_revocations: pendingRevocations,
    compliance_ratio: observedRevocations > 0 ? compliant / observedRevocations : 1,
    latency_seconds: {
      min: observedRevocations > 0 ? Math.min(...latencies) : 0,
      p50: quantile(latencies, 0.5),
      p95: quantile(latencies, 0.95),
      p99: quantile(latencies, 0.99),
      max: observedRevocations > 0 ? Math.max(...latencies) : 0,
    },
  };
}

async function persistRevocationSloReport(
  env: Env,
  report: RevocationSloReport
): Promise<RevocationSloReport> {
  if (!env.SCOPE_REPORTS_BUCKET) return report;

  const key = `identity-control-plane/revocation-slo/${report.generated_at_iso}.json`;
  await env.SCOPE_REPORTS_BUCKET.put(key, JSON.stringify(report, null, 2), {
    httpMetadata: { contentType: 'application/json; charset=utf-8' },
  });

  return {
    ...report,
    r2_object_key: key,
  };
}

async function runScopeGovernanceScheduled(env: Env): Promise<void> {
  try {
    await getOrCreateKeyTransparencySnapshot(env, true);
  } catch (error) {
    console.error('SCOPE_KEY_TRANSPARENCY_SCHEDULED_FAILED', error);
  }

  try {
    const report = await buildRevocationSloReport(env, 24);
    await persistRevocationSloReport(env, report);
  } catch (error) {
    console.error('SCOPE_REVOCATION_SLO_SCHEDULED_FAILED', error);
  }
}

function encodeJwtJson(obj: unknown): string {
  const json = JSON.stringify(obj);
  return base64urlEncode(new TextEncoder().encode(json));
}

function decodeJwtJsonSegment(segmentB64u: string): unknown {
  const bytes = base64urlDecode(segmentB64u);
  const json = new TextDecoder().decode(bytes);
  return JSON.parse(json) as unknown;
}

function validateClaimsShape(payload: unknown): payload is ScopedTokenClaims {
  if (typeof payload !== 'object' || payload === null) return false;
  const p = payload as Record<string, unknown>;

  if (p.token_version !== '1') return false;
  if (!isNonEmptyString(p.sub)) return false;
  if (!validateAud(p.aud)) return false;
  if (!isStringArray(p.scope) || p.scope.length === 0) return false;
  if (typeof p.iat !== 'number' || !Number.isFinite(p.iat)) return false;
  if (typeof p.exp !== 'number' || !Number.isFinite(p.exp)) return false;

  if (p.payment_account_did !== undefined) {
    if (!isNonEmptyString(p.payment_account_did)) return false;
    if (!isDid(p.payment_account_did.trim())) return false;
  }

  if (p.owner_did !== undefined) {
    if (!isNonEmptyString(p.owner_did) || !isDid(p.owner_did.trim())) return false;
  }

  if (p.controller_did !== undefined) {
    if (!isNonEmptyString(p.controller_did) || !isDid(p.controller_did.trim())) return false;
  }

  if (p.agent_did !== undefined) {
    if (!isNonEmptyString(p.agent_did) || !isDid(p.agent_did.trim())) return false;
  }

  if (p.control_plane_policy_hash_b64u !== undefined) {
    if (!isNonEmptyString(p.control_plane_policy_hash_b64u)) return false;
    if (!isSha256B64u(p.control_plane_policy_hash_b64u.trim())) return false;
  }

  if (p.delegation_id !== undefined && !isNonEmptyString(p.delegation_id)) return false;

  if (p.delegator_did !== undefined) {
    if (!isNonEmptyString(p.delegator_did) || !isDid(p.delegator_did.trim())) return false;
  }

  if (p.delegate_did !== undefined) {
    if (!isNonEmptyString(p.delegate_did) || !isDid(p.delegate_did.trim())) return false;
  }

  if (p.delegation_policy_hash_b64u !== undefined) {
    if (!isNonEmptyString(p.delegation_policy_hash_b64u) || !isSha256B64u(p.delegation_policy_hash_b64u.trim())) {
      return false;
    }
  }

  if (p.delegation_spend_cap_minor !== undefined) {
    if (
      !isNonEmptyString(p.delegation_spend_cap_minor) ||
      !/^[0-9]+$/.test(p.delegation_spend_cap_minor.trim())
    ) {
      return false;
    }
  }

  if (p.delegation_expires_at !== undefined) {
    if (typeof p.delegation_expires_at !== 'number' || !Number.isFinite(p.delegation_expires_at)) return false;
  }

  if (p.token_lane !== undefined) {
    if (p.token_lane !== 'legacy' && p.token_lane !== 'canonical') return false;
  }

  return true;
}

async function issueToken(
  req: IssueTokenRequest,
  env: Env,
  maxTtlSeconds: number
): Promise<{ token: string; token_hash: string; claims: ScopedTokenClaims; kid: string }> {
  const keyset = await getIssuerKeySet(env);
  if (!keyset) {
    throw new Error('SCOPE_SIGNING_KEY_NOT_CONFIGURED');
  }

  const keys = keyset.active;
  if (!keys.privateKey) {
    throw new Error('SCOPE_SIGNING_KEY_NOT_CONFIGURED');
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const maxTtl = maxTtlSeconds;

  let exp: number;
  if (typeof req.exp === 'number') {
    exp = Math.floor(req.exp);
  } else {
    const ttl = Math.floor(req.ttl_sec ?? Math.min(600, maxTtl));
    exp = nowSec + ttl;
  }

  const ttl = exp - nowSec;
  if (ttl <= 0) {
    return Promise.reject(new Error('TTL_EXPIRED'));
  }
  if (ttl > maxTtl) {
    return Promise.reject(new Error('TTL_TOO_LONG'));
  }

  const token_scope_hash_b64u = await computeTokenScopeHashB64u({
    sub: req.sub,
    aud: req.aud,
    scope: req.scope,
    owner_ref: req.owner_ref,
    owner_did: req.owner_did,
    controller_did: req.controller_did,
    agent_did: req.agent_did,
    policy_hash_b64u: req.policy_hash_b64u,
    control_plane_policy_hash_b64u: req.control_plane_policy_hash_b64u,
    payment_account_did: req.payment_account_did,
    spend_cap: req.spend_cap,
    mission_id: req.mission_id,
    delegation_id: req.delegation_id,
    delegator_did: req.delegator_did,
    delegate_did: req.delegate_did,
    delegation_policy_hash_b64u: req.delegation_policy_hash_b64u,
    delegation_spend_cap_minor: req.delegation_spend_cap_minor,
    delegation_expires_at: req.delegation_expires_at,
  });

  const claims: ScopedTokenClaims = {
    token_version: '1',
    sub: req.sub,
    aud: req.aud,
    scope: req.scope,
    iat: nowSec,
    exp,
    owner_ref: req.owner_ref,
    owner_did: req.owner_did,
    controller_did: req.controller_did,
    agent_did: req.agent_did,
    policy_hash_b64u: req.policy_hash_b64u,
    control_plane_policy_hash_b64u: req.control_plane_policy_hash_b64u,
    token_scope_hash_b64u,
    payment_account_did: req.payment_account_did,
    spend_cap: req.spend_cap,
    mission_id: req.mission_id,
    delegation_id: req.delegation_id,
    delegator_did: req.delegator_did,
    delegate_did: req.delegate_did,
    delegation_policy_hash_b64u: req.delegation_policy_hash_b64u,
    delegation_spend_cap_minor: req.delegation_spend_cap_minor,
    delegation_expires_at: req.delegation_expires_at,
    token_lane: req.token_lane,
    jti: crypto.randomUUID(),
    nonce: crypto.randomUUID(),
  };

  // Remove undefined fields for compactness
  for (const [k, v] of Object.entries(claims)) {
    if (v === undefined) {
      // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
      delete (claims as unknown as Record<string, unknown>)[k];
    }
  }

  const header = {
    alg: 'EdDSA',
    typ: 'JWT',
    kid: keys.kid,
  };

  const headerB64u = encodeJwtJson(header);
  const payloadB64u = encodeJwtJson(claims);
  const signingInput = `${headerB64u}.${payloadB64u}`;

  const sigB64u = await signEd25519(keys.privateKey, signingInput);
  const token = `${signingInput}.${sigB64u}`;
  const token_hash = await sha256(token);

  return { token, token_hash, claims, kid: keys.kid };
}

async function persistIssuanceAuditRecord(
  env: Env,
  record: IssuanceRecord
): Promise<void> {
  const kv = env.SCOPE_REVOCATIONS;
  if (!kv) return;

  const ttl = parseIntOrDefault(env.SCOPE_REVOCATION_TTL_SECONDS, 60 * 60 * 24 * 30);
  await kv.put(issuanceRecordKey(record.token_hash), JSON.stringify(record), { expirationTtl: ttl });
  await kv.put(issuanceEventKey(record.issued_at, record.token_hash), JSON.stringify(record), { expirationTtl: ttl });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Health
    if (request.method === 'GET' && url.pathname === '/health') {
      return jsonResponse({ status: 'ok', service: 'clawscope', version: env.SCOPE_VERSION });
    }

    // DID + key discovery
    if (request.method === 'GET' && url.pathname === '/v1/did') {
      let keyset: IssuerKeySet | null;
      try {
        keyset = await getIssuerKeySet(env);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'SCOPE_SIGNING_KEY_NOT_CONFIGURED') {
          return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);
        }
        return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
      }

      if (!keyset) return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);

      const active = keyset.active;
      return jsonResponse({ did: SCOPE_DID, kid: active.kid, public_key_b64u: active.jwkX });
    }

    // JWKS (Ed25519 OKP)
    if (request.method === 'GET' && url.pathname === '/v1/jwks') {
      let keyset: IssuerKeySet | null;
      try {
        keyset = await getIssuerKeySet(env);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'SCOPE_SIGNING_KEY_NOT_CONFIGURED') {
          return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);
        }
        return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
      }

      if (!keyset) return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);

      const nowSec = Math.floor(Date.now() / 1000);
      const acceptedKeys = keyset.keys.filter((k) => isKeyAcceptedNow(k, nowSec));

      return jsonResponse(
        {
          keys: acceptedKeys.map((k) => ({
            kty: 'OKP',
            crv: 'Ed25519',
            x: k.jwkX,
            kid: k.kid,
            alg: 'EdDSA',
            use: 'sig',
            ext: true,
          })),
        },
        200,
        {
          'cache-control': 'public, max-age=300',
        }
      );
    }

    // Skill doc (minimal)
    if (request.method === 'GET' && url.pathname === '/skill.md') {
      const md = `# clawscope (canonical CST control lane)\n\nEndpoints:\n- GET /health\n- GET /v1/did\n- GET /v1/jwks\n- GET /v1/keys/rotation-contract\n- GET /v1/keys/transparency/latest\n- GET /v1/keys/transparency/history (protected)\n- POST /v1/keys/transparency/snapshot (protected)\n- POST /v1/tokens/issue/canonical (admin bootstrap)\n- POST /v1/tokens/issue (admin bootstrap, legacy migration lane)\n- POST /v1/tokens/revoke (protected)\n- GET /v1/revocations/events (protected)\n- GET /v1/revocations/stream (protected)\n- GET /v1/audit/issuance (protected)\n- GET /v1/audit/bundle (protected)\n- GET /v1/reports/revocation-slo (protected)\n- POST /v1/tokens/introspect\n- POST /v1/tokens/introspect/matrix\n\nObservability endpoints:\n- GET /v1/metrics/dashboard (admin)\n- POST /v1/reports/rollups/run (admin)\n- GET /v1/reports/usage (admin)\n- POST /v1/alerts/rules (admin)\n- GET /v1/alerts/events (admin)\n- GET /v1/analytics/cost (admin)\n- GET /v1/traces/:trace_id (admin)\n- GET /v1/reports/sla (admin)\n- GET /v1/missions/aggregate (admin)\n\nProtected auth mode: \`SCOPE_PROTECTED_AUTH_MODE=canonical_cst\` (default) or \`admin_token\`.\nToken format: JWT (JWS compact) signed with Ed25519 (alg=EdDSA).\n`;
      return textResponse(md, 'text/markdown; charset=utf-8', 200, env.SCOPE_VERSION);
    }

    const bypassObservabilityRouter = url.pathname === '/v1/reports/revocation-slo';
    if (!bypassObservabilityRouter) {
      const observabilityResponse = await handleScopeObservabilityRoutes(request, env);
      if (observabilityResponse) return observabilityResponse;
    }

    // Token issuance (CSC-US-014) — Canonical lane
    if (request.method === 'POST' && url.pathname === '/v1/tokens/issue/canonical') {
      const canonicalStartedAtMs = Date.now();
      const adminErr = requireAdmin(request, env);
      if (adminErr) return adminErr;

      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);
      }

      const validated = validateIssueRequest(body, env);
      if (!validated.ok) return validated.res;

      const req = validated.req;
      req.token_lane = 'canonical';
      req.agent_did = req.agent_did ?? req.sub;

      if (req.agent_did !== req.sub) {
        return errorResponse('CANONICAL_AGENT_SUB_MISMATCH', 'agent_did must match sub for canonical lane', 400);
      }

      if (!req.owner_did || !req.controller_did || !req.agent_did) {
        return errorResponse(
          'CANONICAL_CHAIN_REQUIRED',
          'owner_did, controller_did, and agent_did are required for canonical issuance',
          400
        );
      }

      const chainLookup = await fetchControlChainRecord(env, req.controller_did, req.agent_did);
      if (!chainLookup.ok) {
        return jsonResponse(
          {
            error: chainLookup.code,
            message: chainLookup.message,
            details: chainLookup.details ?? null,
          },
          chainLookup.status
        );
      }

      const chain = chainLookup.record;
      if (chain.chain.active !== true || chain.controller.active !== true || chain.agent_binding.active !== true) {
        return errorResponse('CONTROL_CHAIN_INACTIVE', 'Control chain is inactive', 403);
      }

      if (chain.owner_did !== req.owner_did) {
        return errorResponse('CONTROL_CHAIN_OWNER_MISMATCH', 'owner_did does not match registered control chain owner', 403);
      }

      if (chain.chain.controller_did !== req.controller_did || chain.chain.agent_did !== req.agent_did) {
        return errorResponse('CONTROL_CHAIN_CONTEXT_MISMATCH', 'controller/agent pair does not match control chain', 403);
      }

      const sensitivePrefixes = parseSensitiveScopePrefixes(env);
      const sensitiveScopes = collectSensitiveScopes(req.scope, sensitivePrefixes);
      if (sensitiveScopes.length > 0) {
        const allowed = new Set(chain.controller.policy.allowed_sensitive_scopes ?? []);
        const disallowed = sensitiveScopes.filter((scope) => !allowed.has(scope));
        if (disallowed.length > 0) {
          return errorResponse(
            'SENSITIVE_SCOPE_NOT_ALLOWED',
            `Requested sensitive scope(s) are not allowed by control policy: ${disallowed.join(', ')}`,
            403
          );
        }
      }

      if (
        req.control_plane_policy_hash_b64u &&
        req.control_plane_policy_hash_b64u !== chain.controller.policy.policy_hash_b64u
      ) {
        return errorResponse(
          'CONTROL_POLICY_HASH_MISMATCH',
          'control_plane_policy_hash_b64u does not match registered controller policy',
          409
        );
      }

      req.control_plane_policy_hash_b64u = chain.controller.policy.policy_hash_b64u;

      const tier = req.tier ?? env.SCOPE_POLICY_TIER ?? 'default';

      let policy: ResolvedScopePolicy;
      try {
        policy = resolveScopePolicy(env, tier);
      } catch {
        return errorResponse('POLICY_CONFIG_INVALID', 'Token policy configuration is invalid', 503);
      }

      try {
        const { token, token_hash, claims, kid } = await issueToken(req, env, policy.max_ttl_seconds);

        const issuedAt = claims.iat;
        const record: IssuanceRecord = {
          token_hash,
          issued_at: issuedAt,
          issued_at_iso: new Date(issuedAt * 1000).toISOString(),
          sub: claims.sub,
          aud: claims.aud,
          scope: claims.scope,
          iat: claims.iat,
          exp: claims.exp,
          kid,
          policy_version: policy.policy_version,
          policy_tier: policy.tier,
          owner_ref: claims.owner_ref,
          owner_did: claims.owner_did,
          controller_did: claims.controller_did,
          agent_did: claims.agent_did,
          policy_hash_b64u: claims.policy_hash_b64u,
          control_plane_policy_hash_b64u: claims.control_plane_policy_hash_b64u,
          token_scope_hash_b64u: claims.token_scope_hash_b64u,
          payment_account_did: claims.payment_account_did,
          spend_cap: claims.spend_cap,
          mission_id: claims.mission_id,
          delegation_id: claims.delegation_id,
          delegator_did: claims.delegator_did,
          delegate_did: claims.delegate_did,
          delegation_policy_hash_b64u: claims.delegation_policy_hash_b64u,
          delegation_spend_cap_minor: claims.delegation_spend_cap_minor,
          delegation_expires_at: claims.delegation_expires_at,
          token_lane: claims.token_lane,
          jti: claims.jti,
        };

        await persistIssuanceAuditRecord(env, record);

        const responseBody = {
          token,
          token_hash,
          token_lane: 'canonical',
          owner_did: claims.owner_did,
          controller_did: claims.controller_did,
          agent_did: claims.agent_did,
          control_plane_policy_hash_b64u: claims.control_plane_policy_hash_b64u,
          policy_hash_b64u: claims.policy_hash_b64u,
          token_scope_hash_b64u: claims.token_scope_hash_b64u,
          payment_account_did: claims.payment_account_did,
          mission_id: claims.mission_id,
          delegation_id: claims.delegation_id,
          delegator_did: claims.delegator_did,
          delegate_did: claims.delegate_did,
          delegation_policy_hash_b64u: claims.delegation_policy_hash_b64u,
          delegation_spend_cap_minor: claims.delegation_spend_cap_minor,
          delegation_expires_at: claims.delegation_expires_at,
          policy_version: policy.policy_version,
          policy_tier: policy.tier,
          kid,
          iat: claims.iat,
          exp: claims.exp,
          claims,
        };

        const response = jsonResponse(responseBody);
        await emitScopeObservabilityBestEffort(
          env,
          makeScopeEventFromResponse({
            request,
            route: '/v1/tokens/issue/canonical',
            started_at_ms: canonicalStartedAtMs,
            status_code: response.status,
            event_type: 'token_issue',
            token_hash,
            mission_id: claims.mission_id,
            scope_count: claims.scope.length,
            details: {
              token_lane: 'canonical',
              policy_tier: policy.tier,
            },
          })
        );

        return response;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);

        if (msg === 'SCOPE_SIGNING_KEY_NOT_CONFIGURED') {
          return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);
        }
        if (
          msg === 'SCOPE_SIGNING_KEYS_JSON_INVALID' ||
          msg === 'SCOPE_SIGNING_KEYS_DUPLICATE_KID' ||
          msg === 'SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID' ||
          msg === 'SCOPE_VERIFY_PUBLIC_KEYS_DUPLICATE_KID'
        ) {
          return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
        }
        if (msg.startsWith('Invalid Ed25519 key length')) {
          return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
        }
        if (msg === 'TTL_TOO_LONG') {
          return errorResponse('TTL_TOO_LONG', `ttl exceeds max (${policy.max_ttl_seconds}s)`, 400);
        }
        if (msg === 'TTL_EXPIRED') {
          return errorResponse('TTL_EXPIRED', 'exp must be in the future', 400);
        }

        return errorResponse('ISSUE_FAILED', 'Failed to issue token', 500);
      }
    }

    // Token issuance (legacy exchange; migration gate)
    if (request.method === 'POST' && url.pathname === '/v1/tokens/issue') {
      const legacyStartedAtMs = Date.now();
      const adminErr = requireAdmin(request, env);
      if (adminErr) return adminErr;

      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);
      }

      const validated = validateIssueRequest(body, env);
      if (!validated.ok) return validated.res;

      const mode = parseLegacyExchangeMode(env);
      if (mode === 'disabled') {
        const response = errorResponse(
          'LEGACY_EXCHANGE_DISABLED',
          'Legacy token issuance is disabled; use /v1/tokens/issue/canonical',
          403
        );
        await emitScopeObservabilityBestEffort(
          env,
          makeScopeEventFromResponse({
            request,
            route: '/v1/tokens/issue',
            started_at_ms: legacyStartedAtMs,
            status_code: response.status,
            event_type: 'token_issue_denied',
            scope_count: 0,
            details: { reason: 'LEGACY_EXCHANGE_DISABLED' },
          })
        );
        return response;
      }

      const req = validated.req;
      req.token_lane = 'legacy';

      const sensitivePrefixes = parseSensitiveScopePrefixes(env);
      const sensitiveScopes = collectSensitiveScopes(req.scope, sensitivePrefixes);
      if (mode === 'migration' && sensitiveScopes.length > 0) {
        const response = errorResponse(
          'LEGACY_SENSITIVE_SCOPE_FORBIDDEN',
          `Legacy issuance cannot mint sensitive scope(s) during migration: ${sensitiveScopes.join(', ')}`,
          403
        );
        await emitScopeObservabilityBestEffort(
          env,
          makeScopeEventFromResponse({
            request,
            route: '/v1/tokens/issue',
            started_at_ms: legacyStartedAtMs,
            status_code: response.status,
            event_type: 'token_issue_denied',
            scope_count: req.scope.length,
            details: {
              reason: 'LEGACY_SENSITIVE_SCOPE_FORBIDDEN',
              sensitive_scopes: sensitiveScopes,
            },
          })
        );
        return response;
      }

      const tier = req.tier ?? env.SCOPE_POLICY_TIER ?? 'default';

      let policy: ResolvedScopePolicy;
      try {
        policy = resolveScopePolicy(env, tier);
      } catch {
        return errorResponse('POLICY_CONFIG_INVALID', 'Token policy configuration is invalid', 503);
      }

      try {
        const { token, token_hash, claims, kid } = await issueToken(req, env, policy.max_ttl_seconds);

        const issuedAt = claims.iat;
        const record: IssuanceRecord = {
          token_hash,
          issued_at: issuedAt,
          issued_at_iso: new Date(issuedAt * 1000).toISOString(),
          sub: claims.sub,
          aud: claims.aud,
          scope: claims.scope,
          iat: claims.iat,
          exp: claims.exp,
          kid,
          policy_version: policy.policy_version,
          policy_tier: policy.tier,
          owner_ref: claims.owner_ref,
          owner_did: claims.owner_did,
          controller_did: claims.controller_did,
          agent_did: claims.agent_did,
          policy_hash_b64u: claims.policy_hash_b64u,
          control_plane_policy_hash_b64u: claims.control_plane_policy_hash_b64u,
          token_scope_hash_b64u: claims.token_scope_hash_b64u,
          payment_account_did: claims.payment_account_did,
          spend_cap: claims.spend_cap,
          mission_id: claims.mission_id,
          delegation_id: claims.delegation_id,
          delegator_did: claims.delegator_did,
          delegate_did: claims.delegate_did,
          delegation_policy_hash_b64u: claims.delegation_policy_hash_b64u,
          delegation_spend_cap_minor: claims.delegation_spend_cap_minor,
          delegation_expires_at: claims.delegation_expires_at,
          token_lane: claims.token_lane,
          jti: claims.jti,
        };

        await persistIssuanceAuditRecord(env, record);

        const responseBody = {
          token,
          token_hash,
          token_lane: 'legacy',
          legacy_exchange_mode: mode,
          migration_notice:
            mode === 'migration'
              ? 'Legacy exchange is temporary; migrate to /v1/tokens/issue/canonical for sensitive transitions.'
              : null,
          policy_hash_b64u: claims.policy_hash_b64u,
          token_scope_hash_b64u: claims.token_scope_hash_b64u,
          payment_account_did: claims.payment_account_did,
          mission_id: claims.mission_id,
          delegation_id: claims.delegation_id,
          delegator_did: claims.delegator_did,
          delegate_did: claims.delegate_did,
          delegation_policy_hash_b64u: claims.delegation_policy_hash_b64u,
          delegation_spend_cap_minor: claims.delegation_spend_cap_minor,
          delegation_expires_at: claims.delegation_expires_at,
          policy_version: policy.policy_version,
          policy_tier: policy.tier,
          kid,
          iat: claims.iat,
          exp: claims.exp,
          claims,
        };

        const response = jsonResponse(responseBody);
        await emitScopeObservabilityBestEffort(
          env,
          makeScopeEventFromResponse({
            request,
            route: '/v1/tokens/issue',
            started_at_ms: legacyStartedAtMs,
            status_code: response.status,
            event_type: 'token_issue',
            token_hash,
            mission_id: claims.mission_id,
            scope_count: claims.scope.length,
            details: {
              token_lane: 'legacy',
              policy_tier: policy.tier,
              legacy_exchange_mode: mode,
            },
          })
        );

        return response;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);

        if (msg === 'SCOPE_SIGNING_KEY_NOT_CONFIGURED') {
          return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);
        }
        if (
          msg === 'SCOPE_SIGNING_KEYS_JSON_INVALID' ||
          msg === 'SCOPE_SIGNING_KEYS_DUPLICATE_KID' ||
          msg === 'SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID' ||
          msg === 'SCOPE_VERIFY_PUBLIC_KEYS_DUPLICATE_KID'
        ) {
          return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
        }
        if (msg.startsWith('Invalid Ed25519 key length')) {
          return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
        }
        if (msg === 'TTL_TOO_LONG') {
          return errorResponse('TTL_TOO_LONG', `ttl exceeds max (${policy.max_ttl_seconds}s)`, 400);
        }
        if (msg === 'TTL_EXPIRED') {
          return errorResponse('TTL_EXPIRED', 'exp must be in the future', 400);
        }

        return errorResponse('ISSUE_FAILED', 'Failed to issue token', 500);
      }
    }

    // Token revocation (CSC-US-003)
    if (request.method === 'POST' && url.pathname === '/v1/tokens/revoke') {
      const revokeStartedAtMs = Date.now();
      const protectedAccess = await requireProtectedAccess(request, env, {
        requiredScopes: ['control:token:revoke', 'control:token:issue_sensitive'],
        requiredTransitions: ['token.revoke'],
      });
      if (!protectedAccess.ok) return protectedAccess.response;

      const kv = env.SCOPE_REVOCATIONS;
      if (!kv) {
        return errorResponse(
          'REVOCATION_NOT_CONFIGURED',
          'SCOPE_REVOCATIONS KV binding is not configured',
          503
        );
      }

      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);
      }

      if (typeof body !== 'object' || body === null) {
        return errorResponse('INVALID_REQUEST', 'Request body must be a JSON object', 400);
      }

      const b = body as Record<string, unknown>;
      const token = b.token;
      const tokenHashInput = b.token_hash;
      const reason =
        typeof b.reason === 'string' ? b.reason.trim().slice(0, MAX_REVOCATION_REASON_LENGTH) : undefined;

      let token_hash: string;
      if (isNonEmptyString(token)) {
        token_hash = await sha256(token);
      } else if (isNonEmptyString(tokenHashInput)) {
        token_hash = tokenHashInput.trim().toLowerCase();
      } else {
        return errorResponse('INVALID_REQUEST', 'token or token_hash is required', 400);
      }

      if (!/^[0-9a-f]{64}$/.test(token_hash)) {
        return errorResponse('INVALID_TOKEN_HASH', 'token_hash must be a 64-character hex SHA-256', 400);
      }

      const existing = await kv.get(revokedRecordKey(token_hash));
      if (existing) {
        try {
          const rec = JSON.parse(existing) as RevocationRecord;
          return jsonResponse({
            status: 'already_revoked',
            token_hash,
            revoked_at: rec.revoked_at,
            revoked_at_iso: rec.revoked_at_iso,
          });
        } catch {
          return jsonResponse({ status: 'already_revoked', token_hash });
        }
      }

      const revokedAtSec = Math.floor(Date.now() / 1000);
      const record: RevocationRecord = {
        token_hash,
        revoked_at: revokedAtSec,
        revoked_at_iso: new Date(revokedAtSec * 1000).toISOString(),
        reason,
        revoked_by: protectedAccess.context.claims.sub,
      };

      const ttl = parseIntOrDefault(env.SCOPE_REVOCATION_TTL_SECONDS, 60 * 60 * 24 * 30);

      await kv.put(revokedRecordKey(token_hash), JSON.stringify(record), { expirationTtl: ttl });

      const eventKey = revocationEventKey(revokedAtSec, token_hash);
      await kv.put(eventKey, JSON.stringify(record), { expirationTtl: ttl });

      await seedRevocationSloToken(env, token_hash, record.revoked_at, record.revoked_at_iso);

      const responseBody = {
        status: 'revoked',
        token_hash,
        revoked_at: record.revoked_at,
        revoked_at_iso: record.revoked_at_iso,
        event_key: eventKey,
      };

      const response = jsonResponse(responseBody);
      await emitScopeObservabilityBestEffort(
        env,
        makeScopeEventFromResponse({
          request,
          route: '/v1/tokens/revoke',
          started_at_ms: revokeStartedAtMs,
          status_code: response.status,
          event_type: 'token_revoke',
          token_hash,
          scope_count: 0,
          details: {
            reason: reason ?? null,
          },
        })
      );

      return response;
    }

    // Revocation events (CSC-US-003)
    if (request.method === 'GET' && url.pathname === '/v1/revocations/events') {
      const protectedAccess = await requireProtectedAccess(request, env, {
        requiredScopes: ['control:audit:read'],
      });
      if (!protectedAccess.ok) return protectedAccess.response;

      const kv = env.SCOPE_REVOCATIONS;
      if (!kv) {
        return errorResponse(
          'REVOCATION_NOT_CONFIGURED',
          'SCOPE_REVOCATIONS KV binding is not configured',
          503
        );
      }

      const limit = Math.min(
        Math.max(parseIntOrDefault(url.searchParams.get('limit') ?? undefined, 50), 1),
        200
      );

      const cursor = url.searchParams.get('cursor') ?? undefined;

      const list = await kv.list({ prefix: REVOCATION_EVENT_PREFIX, limit, cursor });

      const events: Array<{ key: string; record: unknown }> = [];
      for (const k of list.keys) {
        const raw = await kv.get(k.name);
        if (!raw) continue;

        let record: unknown;
        try {
          record = JSON.parse(raw) as unknown;
        } catch {
          record = raw;
        }

        events.push({ key: k.name, record });
      }

      return jsonResponse({
        events,
        cursor: 'cursor' in list ? list.cursor : null,
        list_complete: list.list_complete,
      });
    }

    // Revocation stream contract (CSC-US-014)
    if (request.method === 'GET' && url.pathname === '/v1/revocations/stream') {
      const protectedAccess = await requireProtectedAccess(request, env, {
        requiredScopes: ['control:audit:read'],
      });
      if (!protectedAccess.ok) return protectedAccess.response;

      const kv = env.SCOPE_REVOCATIONS;
      if (!kv) {
        return errorResponse(
          'REVOCATION_NOT_CONFIGURED',
          'SCOPE_REVOCATIONS KV binding is not configured',
          503
        );
      }

      const limit = Math.min(
        Math.max(parseIntOrDefault(url.searchParams.get('limit') ?? undefined, 50), 1),
        200
      );

      const cursor = url.searchParams.get('cursor') ?? undefined;
      const list = await kv.list({ prefix: REVOCATION_EVENT_PREFIX, limit, cursor });

      const events: Array<{ sequence: number; key: string; record: unknown }> = [];
      for (const [idx, k] of list.keys.entries()) {
        const raw = await kv.get(k.name);
        if (!raw) continue;

        let record: unknown;
        try {
          record = JSON.parse(raw) as unknown;
        } catch {
          record = raw;
        }

        events.push({ sequence: idx + 1, key: k.name, record });
      }

      return jsonResponse({
        stream_version: '1',
        events,
        cursor: 'cursor' in list ? list.cursor : null,
        list_complete: list.list_complete,
      });
    }

    // Key rotation overlap contract (CSC-US-014)
    if (request.method === 'GET' && url.pathname === '/v1/keys/rotation-contract') {
      let keyset: IssuerKeySet | null;
      try {
        keyset = await getIssuerKeySet(env);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'SCOPE_SIGNING_KEY_NOT_CONFIGURED') {
          return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);
        }
        return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
      }

      if (!keyset) {
        return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);
      }

      const overlapSeconds = parseIntOrDefault(env.SCOPE_KEY_ROTATION_OVERLAP_SECONDS, 3600);
      const nowSec = Math.floor(Date.now() / 1000);
      const acceptedKeys = keyset.keys.filter((k) => isKeyAcceptedNow(k, nowSec));
      const expiringKeys = acceptedKeys
        .filter((k) => k.not_after_unix !== undefined)
        .map((k) => ({
          kid: k.kid,
          not_after_unix: k.not_after_unix,
        }));

      const acceptedKids = acceptedKeys.map((k) => k.kid);
      const activeKid = keyset.active.kid;
      const signingKids = keyset.signingKeys.map((k) => k.kid);
      const verifyOnlyKids = acceptedKeys.filter((k) => k.verify_only).map((k) => k.kid);

      return jsonResponse({
        contract_version: '2',
        key_algorithm: 'Ed25519',
        active_kid: activeKid,
        accepted_kids: acceptedKids,
        signing_kids: signingKids,
        verify_only_kids: verifyOnlyKids,
        overlap_seconds: overlapSeconds,
        overlap_window_open: overlapSeconds > 0 && acceptedKids.length > 1,
        expiring_kids: expiringKeys,
        revocation_stream_endpoint: '/v1/revocations/stream',
        jwks_endpoint: '/v1/jwks',
      });
    }

    // Key transparency snapshots (ICP-M6.3)
    if (request.method === 'GET' && url.pathname === '/v1/keys/transparency/latest') {
      try {
        const snapshot = await getOrCreateKeyTransparencySnapshot(env, false);
        return jsonResponse(snapshot);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'SCOPE_SIGNING_KEY_NOT_CONFIGURED') {
          return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);
        }
        if (
          msg === 'SCOPE_SIGNING_KEYS_JSON_INVALID' ||
          msg === 'SCOPE_SIGNING_KEYS_DUPLICATE_KID' ||
          msg === 'SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID' ||
          msg === 'SCOPE_VERIFY_PUBLIC_KEYS_DUPLICATE_KID'
        ) {
          return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
        }
        return errorResponse('KEY_TRANSPARENCY_UNAVAILABLE', 'Failed to generate key transparency snapshot', 503);
      }
    }

    if (request.method === 'GET' && url.pathname === '/v1/keys/transparency/history') {
      const protectedAccess = await requireProtectedAccess(request, env, {
        requiredScopes: ['control:audit:read'],
      });
      if (!protectedAccess.ok) return protectedAccess.response;

      const db = env.SCOPE_OBSERVABILITY_DB;
      if (!db) {
        return errorResponse('OBSERVABILITY_DB_NOT_CONFIGURED', 'SCOPE_OBSERVABILITY_DB is not configured', 503);
      }

      await ensureScopeGovernanceSchema(db);

      const limit = Math.min(
        Math.max(parseIntOrDefault(url.searchParams.get('limit') ?? undefined, 20), 1),
        100
      );

      const rows = await db
        .prepare(
          `SELECT snapshot_json
             FROM scope_key_transparency_snapshots
             ORDER BY generated_at DESC
             LIMIT ?`
        )
        .bind(limit)
        .all();

      const snapshots: KeyTransparencySnapshot[] = [];
      for (const row of rows.results ?? []) {
        const parsed = await parseSnapshotRow(row);
        if (parsed) snapshots.push(parsed);
      }

      return jsonResponse({ snapshots });
    }

    if (request.method === 'POST' && url.pathname === '/v1/keys/transparency/snapshot') {
      const protectedAccess = await requireProtectedAccess(request, env, {
        requiredScopes: ['control:key:rotate', 'control:token:issue_sensitive'],
        requiredTransitions: ['key.rotate'],
      });
      if (!protectedAccess.ok) return protectedAccess.response;

      try {
        const snapshot = await getOrCreateKeyTransparencySnapshot(env, true);
        return jsonResponse({ status: 'snapshot_created', snapshot });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg === 'SCOPE_SIGNING_KEY_NOT_CONFIGURED') {
          return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);
        }
        if (
          msg === 'SCOPE_SIGNING_KEYS_JSON_INVALID' ||
          msg === 'SCOPE_SIGNING_KEYS_DUPLICATE_KID' ||
          msg === 'SCOPE_VERIFY_PUBLIC_KEYS_JSON_INVALID' ||
          msg === 'SCOPE_VERIFY_PUBLIC_KEYS_DUPLICATE_KID'
        ) {
          return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
        }
        return errorResponse('KEY_TRANSPARENCY_UNAVAILABLE', 'Failed to generate key transparency snapshot', 503);
      }
    }

    // Revocation propagation SLO report (ICP-M6.4)
    if (request.method === 'GET' && url.pathname === '/v1/reports/revocation-slo') {
      const protectedAccess = await requireProtectedAccess(request, env, {
        requiredScopes: ['control:audit:read'],
      });
      if (!protectedAccess.ok) return protectedAccess.response;

      const windowHours = Math.min(
        Math.max(parseIntOrDefault(url.searchParams.get('window_hours') ?? undefined, 24), 1),
        24 * 14
      );

      try {
        const report = await buildRevocationSloReport(env, windowHours);
        const shouldPersist = url.searchParams.get('persist') === 'true';
        const maybePersisted = shouldPersist ? await persistRevocationSloReport(env, report) : report;
        return jsonResponse(maybePersisted);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message === 'OBSERVABILITY_DB_NOT_CONFIGURED') {
          return errorResponse('OBSERVABILITY_DB_NOT_CONFIGURED', 'SCOPE_OBSERVABILITY_DB is not configured', 503);
        }
        return errorResponse('REVOCATION_SLO_REPORT_FAILED', 'Failed to build revocation SLO report', 500);
      }
    }

    // Issuance audit events (CSC-US-006)
    if (request.method === 'GET' && url.pathname === '/v1/audit/issuance') {
      const protectedAccess = await requireProtectedAccess(request, env, {
        requiredScopes: ['control:audit:read'],
      });
      if (!protectedAccess.ok) return protectedAccess.response;

      const kv = env.SCOPE_REVOCATIONS;
      if (!kv) {
        return errorResponse(
          'AUDIT_NOT_CONFIGURED',
          'SCOPE_REVOCATIONS KV binding is not configured',
          503
        );
      }

      const limit = Math.min(
        Math.max(parseIntOrDefault(url.searchParams.get('limit') ?? undefined, 50), 1),
        200
      );

      const cursor = url.searchParams.get('cursor') ?? undefined;
      const list = await kv.list({ prefix: ISSUANCE_EVENT_PREFIX, limit, cursor });

      const events: Array<{ key: string; record: unknown }> = [];
      for (const k of list.keys) {
        const raw = await kv.get(k.name);
        if (!raw) continue;

        let record: unknown;
        try {
          record = JSON.parse(raw) as unknown;
        } catch {
          record = raw;
        }

        events.push({ key: k.name, record });
      }

      return jsonResponse({
        events,
        cursor: 'cursor' in list ? list.cursor : null,
        list_complete: list.list_complete,
      });
    }

    // Audit bundle export (CSC-US-006)
    if (request.method === 'GET' && url.pathname === '/v1/audit/bundle') {
      const protectedAccess = await requireProtectedAccess(request, env, {
        requiredScopes: ['control:audit:read'],
      });
      if (!protectedAccess.ok) return protectedAccess.response;

      const kv = env.SCOPE_REVOCATIONS;
      if (!kv) {
        return errorResponse(
          'AUDIT_NOT_CONFIGURED',
          'SCOPE_REVOCATIONS KV binding is not configured',
          503
        );
      }

      const limit = Math.min(
        Math.max(parseIntOrDefault(url.searchParams.get('limit') ?? undefined, 50), 1),
        200
      );

      const cursorIssuance = url.searchParams.get('cursor_issuance') ?? undefined;
      const cursorRevocations = url.searchParams.get('cursor_revocations') ?? undefined;

      const [issuanceList, revocationList] = await Promise.all([
        kv.list({ prefix: ISSUANCE_EVENT_PREFIX, limit, cursor: cursorIssuance }),
        kv.list({ prefix: REVOCATION_EVENT_PREFIX, limit, cursor: cursorRevocations }),
      ]);

      const issuanceEvents: Array<{ key: string; record: unknown }> = [];
      for (const k of issuanceList.keys) {
        const raw = await kv.get(k.name);
        if (!raw) continue;

        let record: unknown;
        try {
          record = JSON.parse(raw) as unknown;
        } catch {
          record = raw;
        }

        issuanceEvents.push({ key: k.name, record });
      }

      const revocationEvents: Array<{ key: string; record: unknown }> = [];
      for (const k of revocationList.keys) {
        const raw = await kv.get(k.name);
        if (!raw) continue;

        let record: unknown;
        try {
          record = JSON.parse(raw) as unknown;
        } catch {
          record = raw;
        }

        revocationEvents.push({ key: k.name, record });
      }

      return jsonResponse({
        generated_at: new Date().toISOString(),
        issuance: {
          events: issuanceEvents,
          cursor: 'cursor' in issuanceList ? issuanceList.cursor : null,
          list_complete: issuanceList.list_complete,
        },
        revocations: {
          events: revocationEvents,
          cursor: 'cursor' in revocationList ? revocationList.cursor : null,
          list_complete: revocationList.list_complete,
        },
      });
    }

    // Token introspection (CSC-US-002)
    if (request.method === 'POST' && url.pathname === '/v1/tokens/introspect') {
      const introspectStartedAtMs = Date.now();
      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);
      }

      if (typeof body !== 'object' || body === null) {
        return errorResponse('INVALID_REQUEST', 'Request body must be a JSON object', 400);
      }

      const token = (body as Record<string, unknown>).token;
      if (!isNonEmptyString(token)) {
        return errorResponse('INVALID_REQUEST', 'token is required', 400);
      }

      const introspection = await getIntrospectionResult(token, env);
      if (!introspection.ok) {
        await emitScopeObservabilityBestEffort(
          env,
          makeScopeEventFromResponse({
            request,
            route: '/v1/tokens/introspect',
            started_at_ms: introspectStartedAtMs,
            status_code: introspection.res.status,
            event_type: 'token_introspect_denied',
            scope_count: 0,
            details: { reason: 'INTROSPECTION_FAILED' },
          })
        );
        return introspection.res;
      }

      const payload = introspection.claims;
      if (introspection.revoked) {
        const revokedBody = {
          active: false,
          revoked: true,
          token_hash: introspection.token_hash,
          sub: payload.sub,
          aud: payload.aud,
          scope: payload.scope,
          owner_ref: payload.owner_ref,
          owner_did: payload.owner_did,
          controller_did: payload.controller_did,
          agent_did: payload.agent_did,
          policy_hash_b64u: payload.policy_hash_b64u,
          control_plane_policy_hash_b64u: payload.control_plane_policy_hash_b64u,
          token_scope_hash_b64u: payload.token_scope_hash_b64u,
          payment_account_did: payload.payment_account_did,
          spend_cap: payload.spend_cap,
          mission_id: payload.mission_id,
          delegation_id: payload.delegation_id,
          delegator_did: payload.delegator_did,
          delegate_did: payload.delegate_did,
          delegation_policy_hash_b64u: payload.delegation_policy_hash_b64u,
          delegation_spend_cap_minor: payload.delegation_spend_cap_minor,
          delegation_expires_at: payload.delegation_expires_at,
          token_lane: payload.token_lane,
          iat: payload.iat,
          exp: payload.exp,
          kid: introspection.kid,
          kid_source: introspection.kid_source,
          revoked_at: introspection.revoked_at,
          revoked_at_iso: introspection.revoked_at_iso,
        };

        await observeRevocationSloToken(env, introspection.token_hash, Math.floor(Date.now() / 1000));

        const response = jsonResponse(revokedBody);
        await emitScopeObservabilityBestEffort(
          env,
          makeScopeEventFromResponse({
            request,
            route: '/v1/tokens/introspect',
            started_at_ms: introspectStartedAtMs,
            status_code: response.status,
            event_type: 'token_introspect',
            token_hash: introspection.token_hash,
            mission_id: payload.mission_id,
            scope_count: Array.isArray(payload.scope) ? payload.scope.length : 0,
            details: {
              active: false,
              revoked: true,
            },
          })
        );

        return response;
      }

      const activeBody = {
        active: true,
        token_hash: introspection.token_hash,
        sub: payload.sub,
        aud: payload.aud,
        scope: payload.scope,
        owner_ref: payload.owner_ref,
        owner_did: payload.owner_did,
        controller_did: payload.controller_did,
        agent_did: payload.agent_did,
        policy_hash_b64u: payload.policy_hash_b64u,
        control_plane_policy_hash_b64u: payload.control_plane_policy_hash_b64u,
        token_scope_hash_b64u: payload.token_scope_hash_b64u,
        payment_account_did: payload.payment_account_did,
        spend_cap: payload.spend_cap,
        mission_id: payload.mission_id,
        delegation_id: payload.delegation_id,
        delegator_did: payload.delegator_did,
        delegate_did: payload.delegate_did,
        delegation_policy_hash_b64u: payload.delegation_policy_hash_b64u,
        delegation_spend_cap_minor: payload.delegation_spend_cap_minor,
        delegation_expires_at: payload.delegation_expires_at,
        token_lane: payload.token_lane,
        iat: payload.iat,
        exp: payload.exp,
        kid: introspection.kid,
        kid_source: introspection.kid_source,
      };

      const response = jsonResponse(activeBody);
      await emitScopeObservabilityBestEffort(
        env,
        makeScopeEventFromResponse({
          request,
          route: '/v1/tokens/introspect',
          started_at_ms: introspectStartedAtMs,
          status_code: response.status,
          event_type: 'token_introspect',
          token_hash: introspection.token_hash,
          mission_id: payload.mission_id,
          scope_count: Array.isArray(payload.scope) ? payload.scope.length : 0,
          details: {
            active: true,
            revoked: false,
          },
        })
      );

      return response;
    }

    // Sensitive-transition introspection matrix (CSC-US-014)
    if (request.method === 'POST' && url.pathname === '/v1/tokens/introspect/matrix') {
      const matrixStartedAtMs = Date.now();
      let body: unknown;
      try {
        body = await request.json();
      } catch {
        return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);
      }

      if (typeof body !== 'object' || body === null) {
        return errorResponse('INVALID_REQUEST', 'Request body must be a JSON object', 400);
      }

      const token = (body as Record<string, unknown>).token;
      const transition =
        typeof (body as Record<string, unknown>).transition === 'string'
          ? ((body as Record<string, unknown>).transition as string).trim()
          : undefined;

      if (!isNonEmptyString(token)) {
        return errorResponse('INVALID_REQUEST', 'token is required', 400);
      }

      const introspection = await getIntrospectionResult(token, env);
      if (!introspection.ok) {
        await emitScopeObservabilityBestEffort(
          env,
          makeScopeEventFromResponse({
            request,
            route: '/v1/tokens/introspect/matrix',
            started_at_ms: matrixStartedAtMs,
            status_code: introspection.res.status,
            event_type: 'token_introspect_denied',
            scope_count: 0,
            details: {
              reason: 'MATRIX_INTROSPECTION_FAILED',
              transition: transition ?? null,
            },
          })
        );
        return introspection.res;
      }

      const payload = introspection.claims;
      const matrix = evaluateTransitionMatrix(payload);

      if (introspection.revoked) {
        const revokedBody = {
          active: false,
          revoked: true,
          token_hash: introspection.token_hash,
          transition: transition ?? null,
          matrix,
          kid: introspection.kid,
          kid_source: introspection.kid_source,
          error: 'TOKEN_REVOKED',
          message: 'Token is revoked and cannot authorize sensitive transitions',
        };

        await observeRevocationSloToken(env, introspection.token_hash, Math.floor(Date.now() / 1000));

        const response = jsonResponse(revokedBody);
        await emitScopeObservabilityBestEffort(
          env,
          makeScopeEventFromResponse({
            request,
            route: '/v1/tokens/introspect/matrix',
            started_at_ms: matrixStartedAtMs,
            status_code: response.status,
            event_type: 'token_matrix',
            token_hash: introspection.token_hash,
            mission_id: payload.mission_id,
            scope_count: Array.isArray(payload.scope) ? payload.scope.length : 0,
            details: {
              active: false,
              revoked: true,
              transition: transition ?? null,
            },
          })
        );

        return response;
      }

      if (transition && !(transition in matrix)) {
        return errorResponse('TRANSITION_UNKNOWN', `Unknown transition '${transition}'`, 400);
      }

      const responseBody = {
        active: true,
        revoked: false,
        token_hash: introspection.token_hash,
        transition: transition ?? null,
        transition_result: transition ? matrix[transition] : null,
        matrix,
        kid: introspection.kid,
        kid_source: introspection.kid_source,
      };

      const response = jsonResponse(responseBody);
      await emitScopeObservabilityBestEffort(
        env,
        makeScopeEventFromResponse({
          request,
          route: '/v1/tokens/introspect/matrix',
          started_at_ms: matrixStartedAtMs,
          status_code: response.status,
          event_type: 'token_matrix',
          token_hash: introspection.token_hash,
          mission_id: payload.mission_id,
          scope_count: Array.isArray(payload.scope) ? payload.scope.length : 0,
          details: {
            active: true,
            revoked: false,
            transition: transition ?? null,
          },
        })
      );

      return response;
    }

    return errorResponse('NOT_FOUND', 'Not found', 404);
  },

  async scheduled(controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    await runScopeObservabilityScheduled(env, controller.cron, controller.scheduledTime);
    await runScopeGovernanceScheduled(env);
  },

  async queue(batch: MessageBatch<any>, env: Env): Promise<void> {
    await processScopeObservabilityQueueBatch(batch as MessageBatch<any>, env);
  },
};
