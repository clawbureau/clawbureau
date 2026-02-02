import {
  base64urlDecode,
  base64urlEncode,
  computeKeyId,
  importEd25519Key,
  sha256,
  signEd25519,
  verifyEd25519,
} from './crypto';

const SCOPE_DID = 'did:web:clawscope.com';

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

  // revocation storage knobs
  SCOPE_REVOCATION_TTL_SECONDS?: string;

  // storage (optional bindings)
  SCOPE_REVOCATIONS?: KVNamespace;

  // secrets
  SCOPE_SIGNING_KEY?: string;
  SCOPE_SIGNING_KEYS_JSON?: string;
  SCOPE_ADMIN_KEY?: string;
}

export interface ScopedTokenClaims {
  token_version: '1';
  sub: string;
  aud: string | string[];
  scope: string[];
  iat: number;
  exp: number;
  owner_ref?: string;
  policy_hash_b64u?: string;
  token_scope_hash_b64u?: string;
  spend_cap?: number;
  mission_id?: string;
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
  spend_cap?: number;
  mission_id?: string;
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
  spend_cap?: number;
  mission_id?: string;
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
}

interface IssuerKeySet {
  active: IssuerKey;
  keys: IssuerKey[];
  byKid: Map<string, IssuerKey>;
}

let cachedKeysetRaw: string | null = null;
let cachedKeyset: IssuerKeySet | null = null;

function parseIntOrDefault(value: string | undefined, d: number): number {
  if (!value) return d;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : d;
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

function getBearerToken(header: string | null): string | null {
  if (!header) return null;
  const trimmed = header.trim();
  if (!trimmed) return null;
  if (trimmed.toLowerCase().startsWith('bearer ')) return trimmed.slice(7).trim();
  return trimmed;
}

function requireAdmin(request: Request, env: Env): Response | null {
  if (!env.SCOPE_ADMIN_KEY || env.SCOPE_ADMIN_KEY.trim().length === 0) {
    return errorResponse('ADMIN_KEY_NOT_CONFIGURED', 'SCOPE_ADMIN_KEY is not configured', 503);
  }

  const token = getBearerToken(request.headers.get('Authorization'));
  if (!token) {
    return errorResponse('UNAUTHORIZED', 'Missing Authorization header', 401);
  }

  if (token !== env.SCOPE_ADMIN_KEY) {
    return errorResponse('UNAUTHORIZED', 'Invalid admin token', 401);
  }

  return null;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
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
  if (typeof b.spend_cap === 'number') req.spend_cap = b.spend_cap;
  if (typeof b.mission_id === 'string') req.mission_id = b.mission_id;

  try {
    const policy = resolveScopePolicy(env, tier);
    const enforced = enforceScopePolicy(req.scope, policy);
    if (!enforced.ok) return { ok: false, res: enforced.res };
  } catch {
    return { ok: false, res: errorResponse('POLICY_CONFIG_INVALID', 'Token policy configuration is invalid', 503) };
  }

  return { ok: true, req };
}

async function getIssuerKeySet(env: Env): Promise<IssuerKeySet | null> {
  const jsonText = env.SCOPE_SIGNING_KEYS_JSON?.trim();
  const cacheKey = jsonText
    ? `json:${jsonText}`
    : env.SCOPE_SIGNING_KEY
      ? `single:${env.SCOPE_SIGNING_KEY}`
      : null;

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
  } else {
    // Single-key mode
    keyStrings = [env.SCOPE_SIGNING_KEY!];
  }

  const keys: IssuerKey[] = [];
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
    };

    if (byKid.has(kid)) {
      throw new Error('SCOPE_SIGNING_KEYS_DUPLICATE_KID');
    }

    keys.push(k);
    byKid.set(kid, k);
  }

  const active = keys[0];
  if (!active) return null;

  const keyset: IssuerKeySet = {
    active,
    keys,
    byKid,
  };

  cachedKeysetRaw = cacheKey;
  cachedKeyset = keyset;

  return keyset;
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

  const claims: ScopedTokenClaims = {
    token_version: '1',
    sub: req.sub,
    aud: req.aud,
    scope: req.scope,
    iat: nowSec,
    exp,
    owner_ref: req.owner_ref,
    spend_cap: req.spend_cap,
    mission_id: req.mission_id,
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
      } catch {
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
      } catch {
        return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
      }

      if (!keyset) return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);

      return jsonResponse(
        {
          keys: keyset.keys.map((k) => ({
            kty: 'OKP',
            crv: 'Ed25519',
            x: k.jwkX,
            kid: k.kid,
            alg: 'EdDSA',
            use: 'sig',
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
      const md = `# clawscope (CST issuer)\n\nEndpoints:\n- GET /health\n- GET /v1/did\n- GET /v1/jwks\n- POST /v1/tokens/issue (admin)\n- POST /v1/tokens/revoke (admin)\n- GET /v1/revocations/events (admin)\n- GET /v1/audit/issuance (admin)\n- GET /v1/audit/bundle (admin)\n- POST /v1/tokens/introspect\n\nToken format: JWT (JWS compact) signed with Ed25519 (alg=EdDSA).\n`;
      return textResponse(md, 'text/markdown; charset=utf-8', 200, env.SCOPE_VERSION);
    }

    // Token issuance (CSC-US-001)
    if (request.method === 'POST' && url.pathname === '/v1/tokens/issue') {
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

      const tier = validated.req.tier ?? env.SCOPE_POLICY_TIER ?? 'default';

      let policy: ResolvedScopePolicy;
      try {
        policy = resolveScopePolicy(env, tier);
      } catch {
        return errorResponse('POLICY_CONFIG_INVALID', 'Token policy configuration is invalid', 503);
      }

      try {
        const { token, token_hash, claims, kid } = await issueToken(
          validated.req,
          env,
          policy.max_ttl_seconds
        );

        // CSC-US-006 — Token audit trail (best-effort; requires KV binding)
        const kv = env.SCOPE_REVOCATIONS;
        if (kv) {
          const ttl = parseIntOrDefault(env.SCOPE_REVOCATION_TTL_SECONDS, 60 * 60 * 24 * 30);
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
            spend_cap: claims.spend_cap,
            mission_id: claims.mission_id,
            jti: claims.jti,
          };

          await kv.put(issuanceRecordKey(token_hash), JSON.stringify(record), { expirationTtl: ttl });
          await kv.put(issuanceEventKey(issuedAt, token_hash), JSON.stringify(record), { expirationTtl: ttl });
        }

        return jsonResponse({
          token,
          token_hash,
          policy_version: policy.policy_version,
          policy_tier: policy.tier,
          kid,
          iat: claims.iat,
          exp: claims.exp,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);

        if (msg === 'SCOPE_SIGNING_KEY_NOT_CONFIGURED') {
          return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);
        }
        if (msg === 'SCOPE_SIGNING_KEYS_JSON_INVALID' || msg === 'SCOPE_SIGNING_KEYS_DUPLICATE_KID') {
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
      const adminErr = requireAdmin(request, env);
      if (adminErr) return adminErr;

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
        revoked_by: 'admin',
      };

      const ttl = parseIntOrDefault(env.SCOPE_REVOCATION_TTL_SECONDS, 60 * 60 * 24 * 30);

      await kv.put(revokedRecordKey(token_hash), JSON.stringify(record), { expirationTtl: ttl });

      const eventKey = revocationEventKey(revokedAtSec, token_hash);
      await kv.put(eventKey, JSON.stringify(record), { expirationTtl: ttl });

      return jsonResponse({
        status: 'revoked',
        token_hash,
        revoked_at: record.revoked_at,
        revoked_at_iso: record.revoked_at_iso,
        event_key: eventKey,
      });
    }

    // Revocation events (CSC-US-003)
    if (request.method === 'GET' && url.pathname === '/v1/revocations/events') {
      const adminErr = requireAdmin(request, env);
      if (adminErr) return adminErr;

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

    // Issuance audit events (CSC-US-006)
    if (request.method === 'GET' && url.pathname === '/v1/audit/issuance') {
      const adminErr = requireAdmin(request, env);
      if (adminErr) return adminErr;

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
      const adminErr = requireAdmin(request, env);
      if (adminErr) return adminErr;

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

      const token_hash = await sha256(token);

      const parts = token.split('.');
      if (parts.length !== 3) {
        return errorResponse('TOKEN_MALFORMED', 'CST token must be a JWT (header.payload.signature)', 401);
      }

      const headerB64u = parts[0]!;
      const payloadB64u = parts[1]!;
      const signatureB64u = parts[2]!;

      let header: unknown;
      try {
        header = decodeJwtJsonSegment(headerB64u);
      } catch {
        return errorResponse('TOKEN_MALFORMED', 'Invalid JWT header encoding', 401);
      }

      if (typeof header !== 'object' || header === null) {
        return errorResponse('TOKEN_MALFORMED', 'Invalid JWT header', 401);
      }

      const h = header as Record<string, unknown>;
      if (h.alg !== 'EdDSA') {
        return errorResponse('TOKEN_UNSUPPORTED_ALG', 'Unsupported token algorithm (expected EdDSA)', 401);
      }

      let payload: unknown;
      try {
        payload = decodeJwtJsonSegment(payloadB64u);
      } catch {
        return errorResponse('TOKEN_MALFORMED', 'Invalid JWT payload encoding', 401);
      }

      if (typeof payload === 'object' && payload !== null) {
        const pv = (payload as Record<string, unknown>).token_version;
        if (pv !== undefined && pv !== '1') {
          return errorResponse('TOKEN_UNKNOWN_VERSION', 'Unknown token_version', 401);
        }
      }

      if (!validateClaimsShape(payload)) {
        return errorResponse(
          'TOKEN_INVALID_CLAIMS',
          'Token claims do not match scoped_token_claims.v1 schema',
          401
        );
      }

      // Validate expiry
      const nowSec = Math.floor(Date.now() / 1000);
      if (payload.exp <= nowSec) {
        return errorResponse('TOKEN_EXPIRED', 'Token has expired', 401);
      }

      // Validate signature
      let keyset: IssuerKeySet | null;
      try {
        keyset = await getIssuerKeySet(env);
      } catch {
        return errorResponse('SIGNING_CONFIG_INVALID', 'Signing key configuration is invalid', 503);
      }

      if (!keyset) {
        return errorResponse('SIGNING_NOT_CONFIGURED', 'SCOPE_SIGNING_KEY is not configured', 503);
      }

      let verifyKey: CryptoKey | null = null;
      if (typeof h.kid === 'string' && h.kid.trim().length > 0) {
        const key = keyset.byKid.get(h.kid.trim());
        if (!key) {
          return errorResponse('TOKEN_UNKNOWN_KID', 'Unknown token kid', 401);
        }
        verifyKey = key.publicKey;
      }

      const signingInput = `${headerB64u}.${payloadB64u}`;
      let sigValid = false;

      try {
        if (verifyKey) {
          sigValid = await verifyEd25519(verifyKey, signatureB64u, signingInput);
        } else {
          for (const k of keyset.keys) {
            if (await verifyEd25519(k.publicKey, signatureB64u, signingInput)) {
              sigValid = true;
              break;
            }
          }
        }
      } catch {
        return errorResponse('TOKEN_SIGNATURE_INVALID', 'Token signature verification failed', 401);
      }

      if (!sigValid) {
        return errorResponse('TOKEN_SIGNATURE_INVALID', 'Token signature verification failed', 401);
      }

      const revocation = await getRevocationRecord(env, token_hash);
      if (revocation) {
        return jsonResponse({
          active: false,
          revoked: true,
          token_hash,
          sub: payload.sub,
          aud: payload.aud,
          scope: payload.scope,
          owner_ref: payload.owner_ref,
          iat: payload.iat,
          exp: payload.exp,
          revoked_at: revocation.revoked_at,
          revoked_at_iso: revocation.revoked_at_iso,
        });
      }

      return jsonResponse({
        active: true,
        token_hash,
        sub: payload.sub,
        aud: payload.aud,
        scope: payload.scope,
        owner_ref: payload.owner_ref,
        iat: payload.iat,
        exp: payload.exp,
      });
    }

    return errorResponse('NOT_FOUND', 'Not found', 404);
  },
};
