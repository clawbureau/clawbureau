export interface Env {
  ENVIRONMENT?: string;
  DELEGATE_VERSION?: string;

  DELEGATE_DB: D1Database;
  DELEGATION_DO: DurableObjectNamespace;
  DELEGATE_EVENTS?: Queue;
  DELEGATE_CACHE?: KVNamespace;

  SCOPE_BASE_URL?: string;
  CLAIM_BASE_URL?: string;
  CONTROLS_BASE_URL?: string;
  LEDGER_BASE_URL?: string;

  DELEGATE_ADMIN_KEY?: string;
  SCOPE_ADMIN_KEY?: string;
  CLAIM_DELEGATE_KEY?: string;
  LEDGER_ADMIN_KEY?: string;

  DELEGATE_SERVICE_DID?: string;
  DELEGATE_SCOPE_OWNER_DID?: string;
  DELEGATE_SCOPE_CONTROLLER_DID?: string;
  DELEGATE_SCOPE_AGENT_DID?: string;
  DELEGATE_SCOPE_TOKEN_TTL_SECONDS?: string;
  DELEGATE_TIMEOUT_MS?: string;
}

type DelegationState = 'pending_approval' | 'approved' | 'revoked' | 'expired';
type SpendAction = 'reserve' | 'consume' | 'release' | 'authorize';

type DelegationQueueMessage = {
  type: 'revoke_token';
  delegation_id: string;
  token_hash: string;
  reason: string;
  actor_did?: string;
};

interface DelegationRecord {
  delegation_id: string;
  delegator_did: string;
  delegate_did: string;
  aud: string[];
  scope: string[];
  ttl_seconds: number;
  spend_cap_minor: string;
  policy_hash_b64u: string | null;
  policy_pin_verified: boolean;
  state: DelegationState;
  reserved_minor: string;
  consumed_minor: string;
  created_by: string | null;
  approved_by: string | null;
  revoked_by: string | null;
  created_at: string;
  approved_at: string | null;
  revoked_at: string | null;
  expires_at: string;
  updated_at: string;
}

interface SpendMutationInput {
  operation: SpendAction;
  delegation_id: string;
  idempotency_key: string;
  amount_minor: string;
  actor_did: string;
  token_hash?: string;
  token_scope_hash_b64u?: string;
  reason?: string;
}

interface SpendMutationResult {
  status: 'applied' | 'already_applied';
  operation: SpendAction;
  delegation_id: string;
  idempotency_key: string;
  amount_minor: string;
  reserved_minor: string;
  consumed_minor: string;
  spend_cap_minor: string;
  ledger_event_id: string | null;
  decided_at: string;
}

class DelegateError extends Error {
  code: string;
  status: number;
  details?: Record<string, unknown>;

  constructor(code: string, message: string, status: number, details?: Record<string, unknown>) {
    super(message);
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

const DID_RE = /^did:[a-z0-9]+:[A-Za-z0-9._%-]+$/;
const SHA256_HEX_RE = /^[a-f0-9]{64}$/;
const SHA256_B64U_RE = /^[A-Za-z0-9_-]{43}$/;
const DELEGATION_ID_RE = /^dlg_[a-f0-9-]+$/;

const REQUIRED_TABLES = [
  'delegations',
  'delegation_tokens',
  'delegation_spend_events',
  'delegation_audit_events',
] as const;

let schemaReady = false;
let scopeServiceTokenCache: { token: string; exp: number } | null = null;

function jsonResponse(payload: unknown, status = 200, version = '0.1.0'): Response {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-clawdelegate-version': version,
    },
  });
}

function textResponse(text: string, status = 200, contentType = 'text/plain; charset=utf-8', version = '0.1.0'): Response {
  return new Response(text, {
    status,
    headers: {
      'content-type': contentType,
      'cache-control': 'no-store',
      'x-clawdelegate-version': version,
    },
  });
}

function errorResponse(code: string, message: string, status: number, version: string, details?: Record<string, unknown>): Response {
  return jsonResponse(
    {
      error: code,
      message,
      ...(details ? { details } : {}),
    },
    status,
    version
  );
}

function toErrorResponse(err: unknown, version: string): Response {
  if (err instanceof DelegateError) {
    return errorResponse(err.code, err.message, err.status, version, err.details);
  }

  const message = err instanceof Error ? err.message : String(err);
  return errorResponse('INTERNAL_ERROR', message, 500, version);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDid(value: unknown): value is string {
  return isNonEmptyString(value) && DID_RE.test(value.trim());
}

function assertDelegationId(value: string): string {
  const normalized = value.trim();
  if (!DELEGATION_ID_RE.test(normalized)) {
    throw new DelegateError('DELEGATION_ID_INVALID', 'delegation id is invalid', 400);
  }
  return normalized;
}

function parseAdminToken(request: Request): string | null {
  const header = request.headers.get('authorization')?.trim();
  if (header) {
    if (header.toLowerCase().startsWith('bearer ')) {
      const token = header.slice(7).trim();
      return token.length > 0 ? token : null;
    }
    return header;
  }

  const xAdmin = request.headers.get('x-admin-key')?.trim();
  return xAdmin && xAdmin.length > 0 ? xAdmin : null;
}

function requireAdmin(request: Request, env: Env, version: string): Response | null {
  const expected = env.DELEGATE_ADMIN_KEY?.trim();
  if (!expected) {
    return errorResponse('ADMIN_KEY_NOT_CONFIGURED', 'DELEGATE_ADMIN_KEY is not configured', 503, version);
  }

  const provided = parseAdminToken(request);
  if (!provided || provided !== expected) {
    return errorResponse('UNAUTHORIZED', 'Missing or invalid admin key', 401, version);
  }

  return null;
}

function parseTimeoutMs(env: Env): number {
  const parsed = Number.parseInt(env.DELEGATE_TIMEOUT_MS ?? '5000', 10);
  if (!Number.isFinite(parsed) || parsed < 500) return 5000;
  return parsed;
}

function normalizeBaseUrl(raw: string, code: string): string {
  const value = raw.trim();
  if (!value) {
    throw new DelegateError(code, `${code.replace(/_/g, '.').toLowerCase()} is not configured`, 503);
  }
  return value.replace(/\/+$/, '');
}

function uniqueSorted(values: string[]): string[] {
  return Array.from(new Set(values.map((v) => v.trim()).filter((v) => v.length > 0))).sort();
}

function normalizeAud(raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    throw new DelegateError('INVALID_REQUEST', 'aud must be an array of strings', 400);
  }

  const out: string[] = [];
  for (const entry of raw) {
    if (!isNonEmptyString(entry)) {
      throw new DelegateError('INVALID_REQUEST', 'aud entries must be non-empty strings', 400);
    }
    const value = entry.trim();
    if (value.length > 256) {
      throw new DelegateError('INVALID_REQUEST', 'aud entries must be <= 256 characters', 400);
    }
    out.push(value);
  }

  if (out.length === 0 || out.length > 16) {
    throw new DelegateError('INVALID_REQUEST', 'aud must contain 1..16 entries', 400);
  }

  return uniqueSorted(out);
}

function normalizeScope(raw: unknown): string[] {
  if (!Array.isArray(raw)) {
    throw new DelegateError('INVALID_REQUEST', 'scope must be an array of strings', 400);
  }

  const out: string[] = [];
  for (const entry of raw) {
    if (!isNonEmptyString(entry)) {
      throw new DelegateError('INVALID_REQUEST', 'scope entries must be non-empty strings', 400);
    }
    const value = entry.trim();
    if (value.length > 128) {
      throw new DelegateError('INVALID_REQUEST', 'scope entries must be <= 128 characters', 400);
    }
    out.push(value);
  }

  if (out.length === 0 || out.length > 64) {
    throw new DelegateError('INVALID_REQUEST', 'scope must contain 1..64 entries', 400);
  }

  return uniqueSorted(out);
}

function parseTtlSeconds(raw: unknown): number {
  if (typeof raw !== 'number' || !Number.isFinite(raw)) {
    throw new DelegateError('INVALID_REQUEST', 'ttl_seconds must be a number', 400);
  }

  const ttl = Math.floor(raw);
  if (ttl < 60 || ttl > 31_536_000) {
    throw new DelegateError('INVALID_REQUEST', 'ttl_seconds must be between 60 and 31536000', 400);
  }

  return ttl;
}

function parseMinorString(raw: unknown, field: string): bigint {
  if (!isNonEmptyString(raw) || !/^[0-9]+$/.test(raw.trim())) {
    throw new DelegateError('INVALID_REQUEST', `${field} must be an integer string`, 400);
  }

  const value = BigInt(raw.trim());
  if (value < 0n) {
    throw new DelegateError('INVALID_REQUEST', `${field} must be >= 0`, 400);
  }

  return value;
}

function parsePositiveMinorString(raw: unknown, field: string): bigint {
  const value = parseMinorString(raw, field);
  if (value <= 0n) {
    throw new DelegateError('INVALID_REQUEST', `${field} must be > 0`, 400);
  }
  return value;
}

function bigintToString(value: bigint): string {
  return value.toString(10);
}

function nowIso(): string {
  return new Date().toISOString();
}

function toEpochSeconds(iso: string): number {
  const ms = Date.parse(iso);
  return Math.floor(ms / 1000);
}

async function parseJsonBody(request: Request): Promise<Record<string, unknown>> {
  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    throw new DelegateError('INVALID_JSON', 'Request body must be valid JSON', 400);
  }

  if (!isRecord(payload)) {
    throw new DelegateError('INVALID_REQUEST', 'Request body must be a JSON object', 400);
  }

  return payload;
}

async function ensureSchema(env: Env): Promise<void> {
  if (schemaReady) return;

  for (const table of REQUIRED_TABLES) {
    const row = await env.DELEGATE_DB
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
      .bind(table)
      .first<{ name: string }>();

    if (!row?.name) {
      throw new DelegateError(
        'SCHEMA_NOT_READY',
        `required table '${table}' is missing; apply migrations before serving traffic`,
        503
      );
    }
  }

  schemaReady = true;
}

function decodeJsonArray(value: unknown, field: string): string[] {
  if (!isNonEmptyString(value)) {
    throw new DelegateError('INTERNAL_ERROR', `stored ${field} is invalid`, 500);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new DelegateError('INTERNAL_ERROR', `stored ${field} is invalid`, 500);
  }

  if (!Array.isArray(parsed) || parsed.some((entry) => typeof entry !== 'string')) {
    throw new DelegateError('INTERNAL_ERROR', `stored ${field} is invalid`, 500);
  }

  return parsed as string[];
}

function toDelegationRecord(row: Record<string, unknown>): DelegationRecord {
  const delegation_id = typeof row.delegation_id === 'string' ? row.delegation_id : null;
  const delegator_did = typeof row.delegator_did === 'string' ? row.delegator_did : null;
  const delegate_did = typeof row.delegate_did === 'string' ? row.delegate_did : null;
  const ttl_seconds = typeof row.ttl_seconds === 'number' ? row.ttl_seconds : Number(row.ttl_seconds);
  const spend_cap_minor = typeof row.spend_cap_minor === 'string' ? row.spend_cap_minor : null;
  const policy_hash_b64u = typeof row.policy_hash_b64u === 'string' ? row.policy_hash_b64u : null;
  const state = typeof row.state === 'string' ? row.state : null;
  const reserved_minor = typeof row.reserved_minor === 'string' ? row.reserved_minor : null;
  const consumed_minor = typeof row.consumed_minor === 'string' ? row.consumed_minor : null;
  const created_at = typeof row.created_at === 'string' ? row.created_at : null;
  const expires_at = typeof row.expires_at === 'string' ? row.expires_at : null;
  const updated_at = typeof row.updated_at === 'string' ? row.updated_at : null;

  if (
    !delegation_id ||
    !delegator_did ||
    !delegate_did ||
    !Number.isFinite(ttl_seconds) ||
    !spend_cap_minor ||
    !state ||
    !reserved_minor ||
    !consumed_minor ||
    !created_at ||
    !expires_at ||
    !updated_at
  ) {
    throw new DelegateError('INTERNAL_ERROR', 'stored delegation row is invalid', 500);
  }

  if (
    state !== 'pending_approval' &&
    state !== 'approved' &&
    state !== 'revoked' &&
    state !== 'expired'
  ) {
    throw new DelegateError('INTERNAL_ERROR', 'stored delegation state is invalid', 500);
  }

  return {
    delegation_id,
    delegator_did,
    delegate_did,
    aud: decodeJsonArray(row.aud_json, 'aud_json'),
    scope: decodeJsonArray(row.scope_json, 'scope_json'),
    ttl_seconds: Math.floor(ttl_seconds),
    spend_cap_minor,
    policy_hash_b64u,
    policy_pin_verified: Number(row.policy_pin_verified ?? 0) === 1,
    state,
    reserved_minor,
    consumed_minor,
    created_by: typeof row.created_by === 'string' ? row.created_by : null,
    approved_by: typeof row.approved_by === 'string' ? row.approved_by : null,
    revoked_by: typeof row.revoked_by === 'string' ? row.revoked_by : null,
    created_at,
    approved_at: typeof row.approved_at === 'string' ? row.approved_at : null,
    revoked_at: typeof row.revoked_at === 'string' ? row.revoked_at : null,
    expires_at,
    updated_at,
  };
}

async function getDelegationById(env: Env, delegationId: string): Promise<DelegationRecord | null> {
  const row = await env.DELEGATE_DB
    .prepare('SELECT * FROM delegations WHERE delegation_id = ?')
    .bind(delegationId)
    .first<Record<string, unknown>>();

  if (!row) return null;
  return toDelegationRecord(row);
}

async function writeAuditEvent(params: {
  env: Env;
  delegation_id: string;
  event_type: string;
  actor_did?: string | null;
  decision: string;
  token_hash?: string | null;
  token_scope_hash_b64u?: string | null;
  details?: Record<string, unknown>;
  created_at?: string;
}): Promise<void> {
  const createdAt = params.created_at ?? nowIso();
  const auditId = `dga_${crypto.randomUUID()}`;

  await params.env.DELEGATE_DB
    .prepare(
      `INSERT INTO delegation_audit_events (
         audit_id,
         delegation_id,
         event_type,
         actor_did,
         decision,
         token_hash,
         token_scope_hash_b64u,
         details_json,
         created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      auditId,
      params.delegation_id,
      params.event_type,
      params.actor_did ?? null,
      params.decision,
      params.token_hash ?? null,
      params.token_scope_hash_b64u ?? null,
      JSON.stringify(params.details ?? {}),
      createdAt
    )
    .run();
}

async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<Response> {
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

async function verifyClaimBootstrap(env: Env, delegatorDid: string, delegateDid: string): Promise<void> {
  const baseUrl = normalizeBaseUrl(env.CLAIM_BASE_URL ?? '', 'CLAIM_BASE_URL_NOT_CONFIGURED');
  const key = env.CLAIM_DELEGATE_KEY?.trim();
  if (!key) {
    throw new DelegateError('CLAIM_DELEGATE_KEY_NOT_CONFIGURED', 'CLAIM_DELEGATE_KEY is required', 503);
  }

  const timeoutMs = parseTimeoutMs(env);
  const response = await fetchWithTimeout(
    `${baseUrl}/v1/delegations/bootstrap`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        authorization: `Bearer ${key}`,
      },
      body: JSON.stringify({
        delegator_did: delegatorDid,
        delegate_did: delegateDid,
      }),
    },
    timeoutMs
  );

  if (response.ok) return;

  const text = await response.text();
  let payload: Record<string, unknown> | null = null;
  try {
    payload = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    payload = null;
  }

  const code = isNonEmptyString(payload?.error) ? payload.error.trim() : 'CLAIM_BINDING_REQUIRED';
  const message = isNonEmptyString(payload?.message)
    ? payload.message.trim()
    : `claim bootstrap verification failed with status ${response.status}`;

  throw new DelegateError(code, message, response.status >= 500 ? 502 : response.status);
}

async function verifyPolicyPin(env: Env, policyHash: string): Promise<void> {
  const baseUrl = normalizeBaseUrl(env.CONTROLS_BASE_URL ?? '', 'CONTROLS_BASE_URL_NOT_CONFIGURED');
  const timeoutMs = parseTimeoutMs(env);
  const response = await fetchWithTimeout(`${baseUrl}/v1/wpc/${encodeURIComponent(policyHash)}`, {
    method: 'GET',
    headers: {
      accept: 'application/json',
    },
  }, timeoutMs);

  if (response.ok) return;

  if (response.status === 404) {
    throw new DelegateError('POLICY_HASH_UNKNOWN', 'policy_hash_b64u does not exist in clawcontrols', 400);
  }

  const text = await response.text();
  let payload: Record<string, unknown> | null = null;
  try {
    payload = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    payload = null;
  }

  const code = isNonEmptyString(payload?.error) ? payload.error.trim() : 'POLICY_PIN_CHECK_FAILED';
  const message = isNonEmptyString(payload?.message)
    ? payload.message.trim()
    : `policy pin verification failed with status ${response.status}`;

  throw new DelegateError(code, message, response.status >= 500 ? 502 : response.status);
}

async function issueDelegatedToken(
  env: Env,
  delegation: DelegationRecord,
  ttlSec: number
): Promise<{ token: string; token_hash: string; token_scope_hash_b64u: string; exp: number }> {
  const baseUrl = normalizeBaseUrl(env.SCOPE_BASE_URL ?? '', 'SCOPE_BASE_URL_NOT_CONFIGURED');
  const adminKey = env.SCOPE_ADMIN_KEY?.trim();
  if (!adminKey) {
    throw new DelegateError('SCOPE_ADMIN_KEY_NOT_CONFIGURED', 'SCOPE_ADMIN_KEY is required', 503);
  }

  const expiresAtSec = toEpochSeconds(delegation.expires_at);
  const nowSec = Math.floor(Date.now() / 1000);
  const remaining = Math.max(1, expiresAtSec - nowSec);
  const effectiveTtl = Math.max(1, Math.min(ttlSec, remaining));

  const spendCapNumber = (() => {
    try {
      const asBigInt = BigInt(delegation.spend_cap_minor);
      const maxSafe = BigInt(Number.MAX_SAFE_INTEGER);
      if (asBigInt > maxSafe) return undefined;
      return Number(asBigInt);
    } catch {
      return undefined;
    }
  })();

  const issueBody: Record<string, unknown> = {
    sub: delegation.delegate_did,
    aud: delegation.aud,
    scope: delegation.scope,
    ttl_sec: effectiveTtl,
    owner_did: delegation.delegator_did,
    controller_did: delegation.delegator_did,
    agent_did: delegation.delegate_did,
    token_lane: 'canonical',
    mission_id: delegation.delegation_id,
    payment_account_did: delegation.delegator_did,
    delegation_id: delegation.delegation_id,
    delegator_did: delegation.delegator_did,
    delegate_did: delegation.delegate_did,
    delegation_spend_cap_minor: delegation.spend_cap_minor,
    delegation_expires_at: expiresAtSec,
  };

  if (delegation.policy_hash_b64u) {
    issueBody.policy_hash_b64u = delegation.policy_hash_b64u;
    issueBody.delegation_policy_hash_b64u = delegation.policy_hash_b64u;
  }

  if (typeof spendCapNumber === 'number' && Number.isFinite(spendCapNumber)) {
    issueBody.spend_cap = spendCapNumber;
  }

  const timeoutMs = parseTimeoutMs(env);
  const response = await fetchWithTimeout(
    `${baseUrl}/v1/tokens/issue/canonical`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        authorization: `Bearer ${adminKey}`,
      },
      body: JSON.stringify(issueBody),
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
    const code = isNonEmptyString(payload?.error) ? payload.error.trim() : 'SCOPE_ISSUE_FAILED';
    const message = isNonEmptyString(payload?.message)
      ? payload.message.trim()
      : `clawscope token issuance failed with status ${response.status}`;
    throw new DelegateError(code, message, response.status >= 500 ? 502 : 400);
  }

  const token = isNonEmptyString(payload.token) ? payload.token.trim() : null;
  const tokenHash = isNonEmptyString(payload.token_hash) ? payload.token_hash.trim().toLowerCase() : null;

  const claims = isRecord(payload.claims) ? payload.claims : null;
  const tokenScopeHash = claims && isNonEmptyString(claims.token_scope_hash_b64u)
    ? claims.token_scope_hash_b64u.trim()
    : null;
  const exp = claims && typeof claims.exp === 'number' && Number.isFinite(claims.exp)
    ? Math.floor(claims.exp)
    : null;

  if (!token || !tokenHash || !SHA256_HEX_RE.test(tokenHash) || !tokenScopeHash || !SHA256_B64U_RE.test(tokenScopeHash) || !exp) {
    throw new DelegateError('SCOPE_ISSUE_FAILED', 'clawscope issuance response is invalid', 502);
  }

  return {
    token,
    token_hash: tokenHash,
    token_scope_hash_b64u: tokenScopeHash,
    exp,
  };
}

async function issueScopeServiceToken(env: Env): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  if (scopeServiceTokenCache && scopeServiceTokenCache.exp > nowSec + 15) {
    return scopeServiceTokenCache.token;
  }

  const baseUrl = normalizeBaseUrl(env.SCOPE_BASE_URL ?? '', 'SCOPE_BASE_URL_NOT_CONFIGURED');
  const adminKey = env.SCOPE_ADMIN_KEY?.trim();
  if (!adminKey) {
    throw new DelegateError('SCOPE_ADMIN_KEY_NOT_CONFIGURED', 'SCOPE_ADMIN_KEY is required', 503);
  }

  const defaultServiceDid = env.DELEGATE_SERVICE_DID?.trim() || 'did:web:clawdelegate.com';
  const ownerDid = env.DELEGATE_SCOPE_OWNER_DID?.trim() || defaultServiceDid;
  const controllerDid = env.DELEGATE_SCOPE_CONTROLLER_DID?.trim() || defaultServiceDid;
  const agentDid = env.DELEGATE_SCOPE_AGENT_DID?.trim() || defaultServiceDid;
  const serviceDid = agentDid;

  const ttl = (() => {
    const parsed = Number.parseInt(env.DELEGATE_SCOPE_TOKEN_TTL_SECONDS ?? '300', 10);
    if (!Number.isFinite(parsed) || parsed < 60) return 300;
    return Math.min(parsed, 900);
  })();

  const host = new URL(baseUrl).hostname;
  const aud = Array.from(new Set([host, 'clawscope.com']));

  const response = await fetchWithTimeout(
    `${baseUrl}/v1/tokens/issue/canonical`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        authorization: `Bearer ${adminKey}`,
      },
      body: JSON.stringify({
        sub: serviceDid,
        aud,
        scope: ['control:token:revoke'],
        ttl_sec: ttl,
        owner_did: ownerDid,
        controller_did: controllerDid,
        agent_did: agentDid,
        token_lane: 'canonical',
        payment_account_did: ownerDid,
      }),
    },
    parseTimeoutMs(env)
  );

  const text = await response.text();
  let payload: Record<string, unknown> | null = null;
  try {
    payload = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    payload = null;
  }

  if (!response.ok || !payload || !isNonEmptyString(payload.token)) {
    const code = isNonEmptyString(payload?.error) ? payload.error.trim() : 'SCOPE_SERVICE_TOKEN_FAILED';
    const message = isNonEmptyString(payload?.message)
      ? payload.message.trim()
      : `failed to issue scope service token (${response.status})`;
    throw new DelegateError(code, message, response.status >= 500 ? 502 : 400);
  }

  const token = payload.token.trim();
  const claims = isRecord(payload.claims) ? payload.claims : null;
  const exp = claims && typeof claims.exp === 'number' && Number.isFinite(claims.exp)
    ? Math.floor(claims.exp)
    : nowSec + ttl;

  scopeServiceTokenCache = { token, exp };
  return token;
}

async function propagateRevocationToScope(env: Env, msg: DelegationQueueMessage): Promise<void> {
  const baseUrl = normalizeBaseUrl(env.SCOPE_BASE_URL ?? '', 'SCOPE_BASE_URL_NOT_CONFIGURED');
  const serviceToken = await issueScopeServiceToken(env);

  const response = await fetchWithTimeout(
    `${baseUrl}/v1/tokens/revoke`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'x-cst': `Bearer ${serviceToken}`,
      },
      body: JSON.stringify({
        token_hash: msg.token_hash,
        reason: msg.reason,
      }),
    },
    parseTimeoutMs(env)
  );

  const text = await response.text();
  let payload: Record<string, unknown> | null = null;
  try {
    payload = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const code = isNonEmptyString(payload?.error) ? payload.error.trim() : 'SCOPE_REVOKE_FAILED';
    const message = isNonEmptyString(payload?.message)
      ? payload.message.trim()
      : `scope revoke failed with status ${response.status}`;
    throw new DelegateError(code, message, response.status >= 500 ? 502 : 400);
  }

  await writeAuditEvent({
    env,
    delegation_id: msg.delegation_id,
    event_type: 'token_revocation_propagated',
    actor_did: msg.actor_did ?? null,
    decision: 'propagated',
    token_hash: msg.token_hash,
    details: {
      scope_status: isNonEmptyString(payload?.status) ? payload.status.trim() : 'ok',
    },
  });
}

function parseSpendAction(path: string): SpendAction | null {
  if (path.endsWith('/spend/reserve')) return 'reserve';
  if (path.endsWith('/spend/consume')) return 'consume';
  if (path.endsWith('/spend/release')) return 'release';
  if (path.endsWith('/spend/authorize')) return 'authorize';
  return null;
}

async function parseSpendMutationRequest(
  request: Request,
  delegationId: string,
  operation: SpendAction
): Promise<SpendMutationInput> {
  const body = await parseJsonBody(request);

  if (!isNonEmptyString(body.idempotency_key)) {
    throw new DelegateError('INVALID_REQUEST', 'idempotency_key is required', 400);
  }

  if (!isDid(body.actor_did)) {
    throw new DelegateError('INVALID_REQUEST', 'actor_did must be a DID', 400);
  }

  const amount = parsePositiveMinorString(body.amount_minor, 'amount_minor');

  const tokenHash = isNonEmptyString(body.token_hash) ? body.token_hash.trim().toLowerCase() : undefined;
  if (tokenHash && !SHA256_HEX_RE.test(tokenHash)) {
    throw new DelegateError('INVALID_REQUEST', 'token_hash must be a lowercase hex sha256', 400);
  }

  const tokenScopeHash = isNonEmptyString(body.token_scope_hash_b64u)
    ? body.token_scope_hash_b64u.trim()
    : undefined;
  if (tokenScopeHash && !SHA256_B64U_RE.test(tokenScopeHash)) {
    throw new DelegateError('INVALID_REQUEST', 'token_scope_hash_b64u must be a SHA-256 base64url hash', 400);
  }

  return {
    operation,
    delegation_id: delegationId,
    idempotency_key: body.idempotency_key.trim(),
    amount_minor: bigintToString(amount),
    actor_did: body.actor_did.trim(),
    token_hash: tokenHash,
    token_scope_hash_b64u: tokenScopeHash,
    reason: isNonEmptyString(body.reason) ? body.reason.trim() : undefined,
  };
}

async function callLedgerSpendHook(params: {
  env: Env;
  operation: 'reserve' | 'consume' | 'release';
  delegation_id: string;
  idempotency_key: string;
  delegator_did: string;
  amount_minor: string;
  actor_did: string;
  token_hash?: string;
}): Promise<string | null> {
  const baseUrl = normalizeBaseUrl(params.env.LEDGER_BASE_URL ?? '', 'LEDGER_BASE_URL_NOT_CONFIGURED');
  const adminKey = params.env.LEDGER_ADMIN_KEY?.trim();
  if (!adminKey) {
    throw new DelegateError('LEDGER_ADMIN_KEY_NOT_CONFIGURED', 'LEDGER_ADMIN_KEY is required for spend mutations', 503);
  }

  const amountMinor = parseMinorString(params.amount_minor, 'amount_minor');

  const amountDollars = (() => {
    const whole = amountMinor / 100n;
    const cents = amountMinor % 100n;
    return `${whole.toString()}.${cents.toString().padStart(2, '0')}`;
  })();

  const idempotencyKey = `${params.delegation_id}:${params.idempotency_key}:${params.operation}`;

  const response = await fetchWithTimeout(
    `${baseUrl}/v1/transfers`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        authorization: `Bearer ${adminKey}`,
      },
      body: JSON.stringify({
        idempotency_key: idempotencyKey,
        currency: 'USD',
        from: {
          account: params.delegator_did,
          bucket: params.operation === 'release' ? 'H' : 'A',
        },
        to: {
          account: params.delegator_did,
          bucket: params.operation === 'release' ? 'A' : 'H',
        },
        amount_minor: params.amount_minor,
        amount: amountDollars,
        metadata: {
          source: 'clawdelegate',
          delegation_id: params.delegation_id,
          operation: params.operation,
          actor_did: params.actor_did,
          token_hash: params.token_hash ?? null,
        },
      }),
    },
    parseTimeoutMs(params.env)
  );

  const text = await response.text();
  let payload: Record<string, unknown> | null = null;
  try {
    payload = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const code = isNonEmptyString(payload?.code)
      ? payload.code.trim()
      : isNonEmptyString(payload?.error)
        ? payload.error.trim().toUpperCase().replace(/[^A-Z0-9_]+/g, '_')
        : 'LEDGER_SPEND_FAILED';

    const message = isNonEmptyString(payload?.error)
      ? payload.error.trim()
      : isNonEmptyString(payload?.message)
        ? payload.message.trim()
        : `ledger spend hook failed with status ${response.status}`;

    throw new DelegateError(code, message, response.status >= 500 ? 502 : 400);
  }

  return isNonEmptyString(payload?.event_id) ? payload.event_id.trim() : null;
}

async function runSpendMutation(env: Env, input: SpendMutationInput): Promise<SpendMutationResult> {
  const delegation = await getDelegationById(env, input.delegation_id);
  if (!delegation) {
    throw new DelegateError('DELEGATION_NOT_FOUND', 'delegation does not exist', 404);
  }

  const now = nowIso();
  if (delegation.state === 'revoked') {
    throw new DelegateError('DELEGATION_REVOKED', 'delegation is revoked', 409);
  }

  if (delegation.state === 'pending_approval') {
    throw new DelegateError('DELEGATION_NOT_APPROVED', 'delegation must be approved before spend', 409);
  }

  if (toEpochSeconds(delegation.expires_at) <= Math.floor(Date.now() / 1000)) {
    await env.DELEGATE_DB
      .prepare('UPDATE delegations SET state = ?, updated_at = ? WHERE delegation_id = ? AND state != ?')
      .bind('expired', now, delegation.delegation_id, 'revoked')
      .run();

    throw new DelegateError('DELEGATION_EXPIRED', 'delegation has expired', 409);
  }

  const existing = await env.DELEGATE_DB
    .prepare(
      'SELECT action, result_json FROM delegation_spend_events WHERE delegation_id = ? AND idempotency_key = ? LIMIT 1'
    )
    .bind(delegation.delegation_id, input.idempotency_key)
    .first<Record<string, unknown>>();

  if (existing) {
    const existingAction = typeof existing.action === 'string' ? existing.action : null;
    if (existingAction && existingAction !== input.operation) {
      throw new DelegateError(
        'IDEMPOTENCY_KEY_REUSED',
        'idempotency_key is already used for a different spend action',
        409
      );
    }

    let previous: SpendMutationResult | null = null;
    try {
      previous = isNonEmptyString(existing.result_json)
        ? (JSON.parse(existing.result_json) as SpendMutationResult)
        : null;
    } catch {
      previous = null;
    }

    if (!previous) {
      throw new DelegateError('INTERNAL_ERROR', 'stored spend result is invalid', 500);
    }

    return {
      ...previous,
      status: 'already_applied',
    };
  }

  const amount = BigInt(input.amount_minor);
  const reserved = BigInt(delegation.reserved_minor);
  const consumed = BigInt(delegation.consumed_minor);
  const cap = BigInt(delegation.spend_cap_minor);

  let nextReserved = reserved;
  let nextConsumed = consumed;
  let ledgerEventId: string | null = null;

  if (input.operation === 'reserve') {
    if (consumed + reserved + amount > cap) {
      throw new DelegateError('DELEGATION_SPEND_CAP_EXCEEDED', 'delegation spend cap exceeded', 402, {
        spend_cap_minor: delegation.spend_cap_minor,
        reserved_minor: delegation.reserved_minor,
        consumed_minor: delegation.consumed_minor,
        attempted_minor: input.amount_minor,
      });
    }

    ledgerEventId = await callLedgerSpendHook({
      env,
      operation: 'reserve',
      delegation_id: delegation.delegation_id,
      idempotency_key: `${input.idempotency_key}:reserve`,
      delegator_did: delegation.delegator_did,
      amount_minor: input.amount_minor,
      actor_did: input.actor_did,
      token_hash: input.token_hash,
    });

    nextReserved = reserved + amount;
  } else if (input.operation === 'consume') {
    if (reserved < amount) {
      throw new DelegateError('DELEGATION_RESERVE_INSUFFICIENT', 'reserved budget is insufficient to consume amount', 409, {
        reserved_minor: delegation.reserved_minor,
        attempted_minor: input.amount_minor,
      });
    }

    ledgerEventId = await callLedgerSpendHook({
      env,
      operation: 'consume',
      delegation_id: delegation.delegation_id,
      idempotency_key: `${input.idempotency_key}:consume`,
      delegator_did: delegation.delegator_did,
      amount_minor: input.amount_minor,
      actor_did: input.actor_did,
      token_hash: input.token_hash,
    });

    nextReserved = reserved - amount;
    nextConsumed = consumed + amount;
  } else if (input.operation === 'release') {
    if (reserved < amount) {
      throw new DelegateError('DELEGATION_RESERVE_INSUFFICIENT', 'reserved budget is insufficient to release amount', 409, {
        reserved_minor: delegation.reserved_minor,
        attempted_minor: input.amount_minor,
      });
    }

    ledgerEventId = await callLedgerSpendHook({
      env,
      operation: 'release',
      delegation_id: delegation.delegation_id,
      idempotency_key: `${input.idempotency_key}:release`,
      delegator_did: delegation.delegator_did,
      amount_minor: input.amount_minor,
      actor_did: input.actor_did,
      token_hash: input.token_hash,
    });

    nextReserved = reserved - amount;
  } else if (input.operation === 'authorize') {
    if (consumed + reserved + amount > cap) {
      throw new DelegateError('DELEGATION_SPEND_CAP_EXCEEDED', 'delegation spend cap exceeded', 402, {
        spend_cap_minor: delegation.spend_cap_minor,
        reserved_minor: delegation.reserved_minor,
        consumed_minor: delegation.consumed_minor,
        attempted_minor: input.amount_minor,
      });
    }

    // Reserve then consume to preserve deterministic reserve/consume ledger trail.
    await callLedgerSpendHook({
      env,
      operation: 'reserve',
      delegation_id: delegation.delegation_id,
      idempotency_key: `${input.idempotency_key}:reserve`,
      delegator_did: delegation.delegator_did,
      amount_minor: input.amount_minor,
      actor_did: input.actor_did,
      token_hash: input.token_hash,
    });

    ledgerEventId = await callLedgerSpendHook({
      env,
      operation: 'consume',
      delegation_id: delegation.delegation_id,
      idempotency_key: `${input.idempotency_key}:consume`,
      delegator_did: delegation.delegator_did,
      amount_minor: input.amount_minor,
      actor_did: input.actor_did,
      token_hash: input.token_hash,
    });

    nextConsumed = consumed + amount;
  }

  const decidedAt = nowIso();
  const result: SpendMutationResult = {
    status: 'applied',
    operation: input.operation,
    delegation_id: input.delegation_id,
    idempotency_key: input.idempotency_key,
    amount_minor: input.amount_minor,
    reserved_minor: bigintToString(nextReserved),
    consumed_minor: bigintToString(nextConsumed),
    spend_cap_minor: delegation.spend_cap_minor,
    ledger_event_id: ledgerEventId,
    decided_at: decidedAt,
  };

  const spendEventId = `dgs_${crypto.randomUUID()}`;

  await env.DELEGATE_DB.batch([
    env.DELEGATE_DB
      .prepare('UPDATE delegations SET reserved_minor = ?, consumed_minor = ?, updated_at = ? WHERE delegation_id = ?')
      .bind(result.reserved_minor, result.consumed_minor, decidedAt, delegation.delegation_id),
    env.DELEGATE_DB
      .prepare(
        `INSERT INTO delegation_spend_events (
           spend_event_id,
           delegation_id,
           idempotency_key,
           action,
           amount_minor,
           status,
           actor_did,
           token_hash,
           token_scope_hash_b64u,
           ledger_event_id,
           result_json,
           created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        spendEventId,
        delegation.delegation_id,
        input.idempotency_key,
        input.operation,
        input.amount_minor,
        'applied',
        input.actor_did,
        input.token_hash ?? null,
        input.token_scope_hash_b64u ?? null,
        ledgerEventId,
        JSON.stringify(result),
        decidedAt
      ),
  ]);

  await writeAuditEvent({
    env,
    delegation_id: delegation.delegation_id,
    event_type: `spend_${input.operation}`,
    actor_did: input.actor_did,
    decision: 'applied',
    token_hash: input.token_hash,
    token_scope_hash_b64u: input.token_scope_hash_b64u,
    details: {
      amount_minor: input.amount_minor,
      idempotency_key: input.idempotency_key,
      ledger_event_id: ledgerEventId,
      result,
    },
    created_at: decidedAt,
  });

  return result;
}

async function invokeSpendDo(env: Env, input: SpendMutationInput): Promise<SpendMutationResult> {
  const id = env.DELEGATION_DO.idFromName(input.delegation_id);
  const stub = env.DELEGATION_DO.get(id);

  const response = await stub.fetch('https://delegation-do.internal/spend', {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify(input),
  });

  const text = await response.text();
  let payload: Record<string, unknown> | null = null;
  try {
    payload = text ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    payload = null;
  }

  if (!response.ok || !payload) {
    const code = isNonEmptyString(payload?.error) ? payload.error.trim() : 'SPEND_COORDINATION_FAILED';
    const message = isNonEmptyString(payload?.message)
      ? payload.message.trim()
      : `spend coordination failed with status ${response.status}`;
    throw new DelegateError(code, message, response.status >= 500 ? 502 : response.status);
  }

  if (!isRecord(payload.result)) {
    throw new DelegateError('SPEND_COORDINATION_FAILED', 'spend coordinator response is invalid', 502);
  }

  return payload.result as unknown as SpendMutationResult;
}

async function listAuditRows(
  env: Env,
  delegationId: string,
  limit: number
): Promise<Array<Record<string, unknown>>> {
  const result = await env.DELEGATE_DB
    .prepare(
      `SELECT audit_id, delegation_id, event_type, actor_did, decision, token_hash, token_scope_hash_b64u, details_json, created_at
         FROM delegation_audit_events
        WHERE delegation_id = ?
        ORDER BY created_at DESC, audit_id DESC
        LIMIT ?`
    )
    .bind(delegationId, limit)
    .all<Record<string, unknown>>();

  return result.results ?? [];
}

function parseLimit(value: string | null, fallback: number, max: number): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function sha256B64u(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return base64urlEncode(new Uint8Array(digest));
}

function canonicalAuditEvent(row: Record<string, unknown>): Record<string, unknown> {
  let details: unknown = {};
  try {
    details = isNonEmptyString(row.details_json) ? JSON.parse(row.details_json) : {};
  } catch {
    details = {};
  }

  return {
    schema_version: '1',
    audit_id: row.audit_id,
    delegation_id: row.delegation_id,
    event_type: row.event_type,
    actor_did: row.actor_did,
    decision: row.decision,
    token_hash: row.token_hash,
    token_scope_hash_b64u: row.token_scope_hash_b64u,
    details,
    created_at: row.created_at,
  };
}

export const __test = {
  normalizeAud,
  normalizeScope,
  parseTtlSeconds,
  parseMinorString,
  parsePositiveMinorString,
};

export class DelegationDurableObject {
  private state: DurableObjectState;
  private env: Env;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method !== 'POST') {
      return jsonResponse({ error: 'METHOD_NOT_ALLOWED', message: 'POST required' }, 405, this.env.DELEGATE_VERSION ?? '0.1.0');
    }

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: 'INVALID_JSON', message: 'Request body must be valid JSON' }, 400, this.env.DELEGATE_VERSION ?? '0.1.0');
    }

    if (!isRecord(body)) {
      return jsonResponse({ error: 'INVALID_REQUEST', message: 'Request body must be a JSON object' }, 400, this.env.DELEGATE_VERSION ?? '0.1.0');
    }

    try {
      await ensureSchema(this.env);

      const operation = body.operation;
      const delegationId = body.delegation_id;
      const idempotencyKey = body.idempotency_key;
      const amountMinor = body.amount_minor;
      const actorDid = body.actor_did;

      if (
        operation !== 'reserve' &&
        operation !== 'consume' &&
        operation !== 'release' &&
        operation !== 'authorize'
      ) {
        throw new DelegateError('INVALID_REQUEST', 'operation must be reserve|consume|release|authorize', 400);
      }

      if (!isNonEmptyString(delegationId) || !DELEGATION_ID_RE.test(delegationId.trim())) {
        throw new DelegateError('INVALID_REQUEST', 'delegation_id is invalid', 400);
      }

      if (!isNonEmptyString(idempotencyKey)) {
        throw new DelegateError('INVALID_REQUEST', 'idempotency_key is required', 400);
      }

      const amount = parsePositiveMinorString(amountMinor, 'amount_minor');

      if (!isDid(actorDid)) {
        throw new DelegateError('INVALID_REQUEST', 'actor_did must be a DID', 400);
      }

      const tokenHash = isNonEmptyString(body.token_hash) ? body.token_hash.trim().toLowerCase() : undefined;
      if (tokenHash && !SHA256_HEX_RE.test(tokenHash)) {
        throw new DelegateError('INVALID_REQUEST', 'token_hash must be a lowercase hex sha256', 400);
      }

      const tokenScopeHash = isNonEmptyString(body.token_scope_hash_b64u)
        ? body.token_scope_hash_b64u.trim()
        : undefined;
      if (tokenScopeHash && !SHA256_B64U_RE.test(tokenScopeHash)) {
        throw new DelegateError('INVALID_REQUEST', 'token_scope_hash_b64u must be a SHA-256 base64url hash', 400);
      }

      const result = await this.state.blockConcurrencyWhile(() =>
        runSpendMutation(this.env, {
          operation,
          delegation_id: delegationId.trim(),
          idempotency_key: idempotencyKey.trim(),
          amount_minor: bigintToString(amount),
          actor_did: actorDid.trim(),
          token_hash: tokenHash,
          token_scope_hash_b64u: tokenScopeHash,
          reason: isNonEmptyString(body.reason) ? body.reason.trim() : undefined,
        })
      );

      return jsonResponse({ result }, 200, this.env.DELEGATE_VERSION ?? '0.1.0');
    } catch (err) {
      if (err instanceof DelegateError) {
        return jsonResponse(
          {
            error: err.code,
            message: err.message,
            ...(err.details ? { details: err.details } : {}),
          },
          err.status,
          this.env.DELEGATE_VERSION ?? '0.1.0'
        );
      }

      const message = err instanceof Error ? err.message : String(err);
      return jsonResponse({ error: 'INTERNAL_ERROR', message }, 500, this.env.DELEGATE_VERSION ?? '0.1.0');
    }
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const version = env.DELEGATE_VERSION ?? '0.1.0';

    try {
      await ensureSchema(env);
    } catch (err) {
      return toErrorResponse(err, version);
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    if (method === 'GET' && path === '/health') {
      return jsonResponse(
        {
          status: 'ok',
          service: 'clawdelegate',
          version,
          environment: env.ENVIRONMENT ?? 'unknown',
        },
        200,
        version
      );
    }

    if (method === 'GET' && path === '/docs') {
      const md = `# clawdelegate\n\nEndpoints:\n- POST /v1/delegations\n- GET /v1/delegations/:id\n- GET /v1/delegations\n- POST /v1/delegations/:id/approve\n- POST /v1/delegations/:id/tokens/issue\n- POST /v1/delegations/:id/revoke\n- POST /v1/delegations/:id/spend/reserve\n- POST /v1/delegations/:id/spend/consume\n- POST /v1/delegations/:id/spend/release\n- POST /v1/delegations/:id/spend/authorize\n- GET /v1/delegations/:id/audit\n- GET /v1/delegations/:id/audit/export\n\nCloudflare stack:\n- D1 authoritative state\n- Durable Object spend serialization\n- Queue-based revocation fanout\n`;
      return textResponse(md, 200, 'text/markdown; charset=utf-8', version);
    }

    if (method === 'GET' && path === '/skill.md') {
      return textResponse(
        '# clawdelegate\n\nDelegation control plane for delegated CST issuance, spend governance, and revocation fanout.',
        200,
        'text/markdown; charset=utf-8',
        version
      );
    }

    if (!path.startsWith('/v1/')) {
      return errorResponse('NOT_FOUND', 'Not found', 404, version);
    }

    const adminErr = requireAdmin(request, env, version);
    if (adminErr) return adminErr;

    try {
      if (method === 'POST' && path === '/v1/delegations') {
        const body = await parseJsonBody(request);

        if (!isNonEmptyString(body.idempotency_key)) {
          throw new DelegateError('INVALID_REQUEST', 'idempotency_key is required', 400);
        }

        if (!isDid(body.delegator_did)) {
          throw new DelegateError('INVALID_REQUEST', 'delegator_did must be a DID', 400);
        }

        if (!isDid(body.delegate_did)) {
          throw new DelegateError('INVALID_REQUEST', 'delegate_did must be a DID', 400);
        }

        const delegatorDid = body.delegator_did.trim();
        const delegateDid = body.delegate_did.trim();

        if (delegatorDid === delegateDid) {
          throw new DelegateError('INVALID_REQUEST', 'delegator_did and delegate_did must differ', 400);
        }

        const aud = normalizeAud(body.aud);
        const scope = normalizeScope(body.scope);
        const ttl = parseTtlSeconds(body.ttl_seconds);
        const spendCapMinor = parseMinorString(body.spend_cap_minor, 'spend_cap_minor');

        const policyHash = isNonEmptyString(body.policy_hash_b64u) ? body.policy_hash_b64u.trim() : null;
        if (policyHash && !SHA256_B64U_RE.test(policyHash)) {
          throw new DelegateError('INVALID_REQUEST', 'policy_hash_b64u must be a SHA-256 base64url hash', 400);
        }

        const idempotencyKey = body.idempotency_key.trim();

        const existing = await env.DELEGATE_DB
          .prepare('SELECT * FROM delegations WHERE idempotency_key = ? LIMIT 1')
          .bind(idempotencyKey)
          .first<Record<string, unknown>>();

        if (existing) {
          const record = toDelegationRecord(existing);
          return jsonResponse({ schema_version: '1', delegation: record, status: 'already_exists' }, 200, version);
        }

        await verifyClaimBootstrap(env, delegatorDid, delegateDid);

        if (policyHash) {
          await verifyPolicyPin(env, policyHash);
        }

        const createdAt = nowIso();
        const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
        const delegationId = `dlg_${crypto.randomUUID()}`;
        const createdBy = isDid(body.created_by) ? body.created_by.trim() : delegatorDid;

        await env.DELEGATE_DB
          .prepare(
            `INSERT INTO delegations (
               delegation_id,
               idempotency_key,
               delegator_did,
               delegate_did,
               aud_json,
               scope_json,
               ttl_seconds,
               spend_cap_minor,
               policy_hash_b64u,
               policy_pin_verified,
               state,
               reserved_minor,
               consumed_minor,
               created_by,
               created_at,
               expires_at,
               updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '0', '0', ?, ?, ?, ?)`
          )
          .bind(
            delegationId,
            idempotencyKey,
            delegatorDid,
            delegateDid,
            JSON.stringify(aud),
            JSON.stringify(scope),
            ttl,
            bigintToString(spendCapMinor),
            policyHash,
            policyHash ? 1 : 0,
            'pending_approval',
            createdBy,
            createdAt,
            expiresAt,
            createdAt
          )
          .run();

        await writeAuditEvent({
          env,
          delegation_id: delegationId,
          event_type: 'delegation_created',
          actor_did: createdBy,
          decision: 'created',
          details: {
            idempotency_key: idempotencyKey,
            delegator_did: delegatorDid,
            delegate_did: delegateDid,
            aud,
            scope,
            ttl_seconds: ttl,
            spend_cap_minor: bigintToString(spendCapMinor),
            policy_hash_b64u: policyHash,
          },
          created_at: createdAt,
        });

        const created = await getDelegationById(env, delegationId);
        if (!created) {
          throw new DelegateError('INTERNAL_ERROR', 'failed to load created delegation', 500);
        }

        return jsonResponse({ schema_version: '1', delegation: created, status: 'created' }, 201, version);
      }

      if (method === 'GET' && path === '/v1/delegations') {
        const stateRaw = url.searchParams.get('state');
        const state = stateRaw && ['pending_approval', 'approved', 'revoked', 'expired'].includes(stateRaw)
          ? stateRaw
          : null;

        const limit = parseLimit(url.searchParams.get('limit'), 50, 200);
        const cursor = url.searchParams.get('cursor');

        let sql = 'SELECT * FROM delegations';
        const binds: Array<string | number> = [];

        if (state) {
          sql += ' WHERE state = ?';
          binds.push(state);
        }

        if (cursor) {
          const [cursorCreatedAt, cursorId] = cursor.split('|');
          if (!cursorCreatedAt || !cursorId) {
            throw new DelegateError('INVALID_REQUEST', 'cursor is invalid', 400);
          }

          sql += state
            ? ' AND (created_at < ? OR (created_at = ? AND delegation_id < ?))'
            : ' WHERE (created_at < ? OR (created_at = ? AND delegation_id < ?))';
          binds.push(cursorCreatedAt, cursorCreatedAt, cursorId);
        }

        sql += ' ORDER BY created_at DESC, delegation_id DESC LIMIT ?';
        binds.push(limit);

        const rows = await env.DELEGATE_DB.prepare(sql).bind(...binds).all<Record<string, unknown>>();
        const records = (rows.results ?? []).map(toDelegationRecord);

        const nextCursor = records.length === limit
          ? `${records[records.length - 1]!.created_at}|${records[records.length - 1]!.delegation_id}`
          : null;

        return jsonResponse(
          {
            schema_version: '1',
            delegations: records,
            cursor: nextCursor,
          },
          200,
          version
        );
      }

      const delegationMatch = path.match(/^\/v1\/delegations\/(dlg_[a-f0-9-]+)$/);
      if (method === 'GET' && delegationMatch) {
        const delegationId = assertDelegationId(delegationMatch[1]!);
        const delegation = await getDelegationById(env, delegationId);
        if (!delegation) {
          throw new DelegateError('DELEGATION_NOT_FOUND', 'delegation does not exist', 404);
        }

        return jsonResponse({ schema_version: '1', delegation }, 200, version);
      }

      const approveMatch = path.match(/^\/v1\/delegations\/(dlg_[a-f0-9-]+)\/approve$/);
      if (method === 'POST' && approveMatch) {
        const delegationId = assertDelegationId(approveMatch[1]!);
        const delegation = await getDelegationById(env, delegationId);
        if (!delegation) {
          throw new DelegateError('DELEGATION_NOT_FOUND', 'delegation does not exist', 404);
        }

        if (delegation.state === 'revoked') {
          throw new DelegateError('DELEGATION_REVOKED', 'delegation is revoked', 409);
        }

        if (delegation.state === 'expired' || toEpochSeconds(delegation.expires_at) <= Math.floor(Date.now() / 1000)) {
          await env.DELEGATE_DB
            .prepare('UPDATE delegations SET state = ?, updated_at = ? WHERE delegation_id = ?')
            .bind('expired', nowIso(), delegationId)
            .run();
          throw new DelegateError('DELEGATION_EXPIRED', 'delegation has expired', 409);
        }

        if (delegation.state === 'approved') {
          return jsonResponse({ schema_version: '1', delegation, status: 'already_approved' }, 200, version);
        }

        const body = await parseJsonBody(request).catch(() => ({} as Record<string, unknown>));
        const approvedBy = isDid(body.approved_by) ? body.approved_by.trim() : delegation.delegator_did;
        const approvedAt = nowIso();

        await env.DELEGATE_DB
          .prepare('UPDATE delegations SET state = ?, approved_by = ?, approved_at = ?, updated_at = ? WHERE delegation_id = ?')
          .bind('approved', approvedBy, approvedAt, approvedAt, delegationId)
          .run();

        await writeAuditEvent({
          env,
          delegation_id: delegationId,
          event_type: 'delegation_approved',
          actor_did: approvedBy,
          decision: 'approved',
          details: {
            approved_at: approvedAt,
          },
          created_at: approvedAt,
        });

        const updated = await getDelegationById(env, delegationId);
        if (!updated) {
          throw new DelegateError('INTERNAL_ERROR', 'failed to load approved delegation', 500);
        }

        return jsonResponse({ schema_version: '1', delegation: updated, status: 'approved' }, 200, version);
      }

      const issueMatch = path.match(/^\/v1\/delegations\/(dlg_[a-f0-9-]+)\/tokens\/issue$/);
      if (method === 'POST' && issueMatch) {
        const delegationId = assertDelegationId(issueMatch[1]!);
        const delegation = await getDelegationById(env, delegationId);
        if (!delegation) {
          throw new DelegateError('DELEGATION_NOT_FOUND', 'delegation does not exist', 404);
        }

        if (delegation.state !== 'approved') {
          throw new DelegateError('DELEGATION_NOT_APPROVED', 'delegation must be approved before token issuance', 409);
        }

        if (toEpochSeconds(delegation.expires_at) <= Math.floor(Date.now() / 1000)) {
          await env.DELEGATE_DB
            .prepare('UPDATE delegations SET state = ?, updated_at = ? WHERE delegation_id = ?')
            .bind('expired', nowIso(), delegationId)
            .run();

          throw new DelegateError('DELEGATION_EXPIRED', 'delegation has expired', 409);
        }

        const body = await parseJsonBody(request);
        const requestedTtl = typeof body.ttl_seconds === 'number' && Number.isFinite(body.ttl_seconds)
          ? Math.floor(body.ttl_seconds)
          : delegation.ttl_seconds;

        if (requestedTtl <= 0) {
          throw new DelegateError('INVALID_REQUEST', 'ttl_seconds must be > 0', 400);
        }

        const issuedBy = isDid(body.issued_by) ? body.issued_by.trim() : delegation.delegator_did;
        const issued = await issueDelegatedToken(env, delegation, requestedTtl);
        const issuedAt = nowIso();

        await env.DELEGATE_DB
          .prepare(
            `INSERT INTO delegation_tokens (
               token_hash,
               delegation_id,
               token_scope_hash_b64u,
               issued_at,
               expires_at
             ) VALUES (?, ?, ?, ?, ?)`
          )
          .bind(
            issued.token_hash,
            delegation.delegation_id,
            issued.token_scope_hash_b64u,
            issuedAt,
            new Date(issued.exp * 1000).toISOString()
          )
          .run();

        await writeAuditEvent({
          env,
          delegation_id: delegation.delegation_id,
          event_type: 'delegated_cst_issued',
          actor_did: issuedBy,
          decision: 'issued',
          token_hash: issued.token_hash,
          token_scope_hash_b64u: issued.token_scope_hash_b64u,
          details: {
            issued_at: issuedAt,
            expires_at: new Date(issued.exp * 1000).toISOString(),
          },
          created_at: issuedAt,
        });

        return jsonResponse(
          {
            schema_version: '1',
            delegation_id: delegation.delegation_id,
            token: issued.token,
            token_hash: issued.token_hash,
            token_scope_hash_b64u: issued.token_scope_hash_b64u,
            exp: issued.exp,
          },
          201,
          version
        );
      }

      const revokeMatch = path.match(/^\/v1\/delegations\/(dlg_[a-f0-9-]+)\/revoke$/);
      if (method === 'POST' && revokeMatch) {
        const delegationId = assertDelegationId(revokeMatch[1]!);
        const delegation = await getDelegationById(env, delegationId);
        if (!delegation) {
          throw new DelegateError('DELEGATION_NOT_FOUND', 'delegation does not exist', 404);
        }

        const body = await parseJsonBody(request).catch(() => ({} as Record<string, unknown>));
        const revokedBy = isDid(body.revoked_by) ? body.revoked_by.trim() : delegation.delegator_did;
        const reason = isNonEmptyString(body.reason) ? body.reason.trim().slice(0, 256) : 'delegation_revoked';
        const revokedAt = nowIso();

        if (delegation.state === 'revoked') {
          return jsonResponse({ schema_version: '1', delegation, status: 'already_revoked' }, 200, version);
        }

        await env.DELEGATE_DB
          .prepare('UPDATE delegations SET state = ?, revoked_by = ?, revoked_at = ?, updated_at = ? WHERE delegation_id = ?')
          .bind('revoked', revokedBy, revokedAt, revokedAt, delegationId)
          .run();

        const tokenRows = await env.DELEGATE_DB
          .prepare('SELECT token_hash FROM delegation_tokens WHERE delegation_id = ? AND revoked_at IS NULL')
          .bind(delegationId)
          .all<Record<string, unknown>>();

        const tokenHashes = (tokenRows.results ?? [])
          .map((row) => (typeof row.token_hash === 'string' ? row.token_hash.trim().toLowerCase() : null))
          .filter((value): value is string => !!value && SHA256_HEX_RE.test(value));

        await env.DELEGATE_DB
          .prepare('UPDATE delegation_tokens SET revoked_at = ?, revocation_reason = ? WHERE delegation_id = ? AND revoked_at IS NULL')
          .bind(revokedAt, reason, delegationId)
          .run();

        if (tokenHashes.length > 0) {
          if (env.DELEGATE_EVENTS) {
            for (const tokenHash of tokenHashes) {
              await env.DELEGATE_EVENTS.send({
                type: 'revoke_token',
                delegation_id: delegationId,
                token_hash: tokenHash,
                reason,
                actor_did: revokedBy,
              } satisfies DelegationQueueMessage, { contentType: 'json' });
            }
          } else {
            for (const tokenHash of tokenHashes) {
              await propagateRevocationToScope(env, {
                type: 'revoke_token',
                delegation_id: delegationId,
                token_hash: tokenHash,
                reason,
                actor_did: revokedBy,
              });
            }
          }
        }

        await writeAuditEvent({
          env,
          delegation_id: delegationId,
          event_type: 'delegation_revoked',
          actor_did: revokedBy,
          decision: 'revoked',
          details: {
            revoked_at: revokedAt,
            reason,
            token_count: tokenHashes.length,
          },
          created_at: revokedAt,
        });

        const updated = await getDelegationById(env, delegationId);
        if (!updated) {
          throw new DelegateError('INTERNAL_ERROR', 'failed to load revoked delegation', 500);
        }

        return jsonResponse(
          {
            schema_version: '1',
            delegation: updated,
            status: 'revoked',
            revoke_fanout: {
              queued: tokenHashes.length,
              queue_enabled: !!env.DELEGATE_EVENTS,
            },
          },
          200,
          version
        );
      }

      const spendMatch = path.match(/^\/v1\/delegations\/(dlg_[a-f0-9-]+)\/spend\/(reserve|consume|release|authorize)$/);
      if (method === 'POST' && spendMatch) {
        const delegationId = assertDelegationId(spendMatch[1]!);
        const operation = parseSpendAction(path);
        if (!operation) {
          throw new DelegateError('NOT_FOUND', 'Not found', 404);
        }

        const input = await parseSpendMutationRequest(request, delegationId, operation);
        const result = await invokeSpendDo(env, input);

        return jsonResponse({ schema_version: '1', result }, 200, version);
      }

      const auditMatch = path.match(/^\/v1\/delegations\/(dlg_[a-f0-9-]+)\/audit$/);
      if (method === 'GET' && auditMatch) {
        const delegationId = assertDelegationId(auditMatch[1]!);
        const delegation = await getDelegationById(env, delegationId);
        if (!delegation) {
          throw new DelegateError('DELEGATION_NOT_FOUND', 'delegation does not exist', 404);
        }

        const limit = parseLimit(url.searchParams.get('limit'), 200, 500);
        const rows = await listAuditRows(env, delegationId, limit);
        const events = rows.map(canonicalAuditEvent);

        return jsonResponse({ schema_version: '1', delegation_id: delegationId, events }, 200, version);
      }

      const auditExportMatch = path.match(/^\/v1\/delegations\/(dlg_[a-f0-9-]+)\/audit\/export$/);
      if (method === 'GET' && auditExportMatch) {
        const delegationId = assertDelegationId(auditExportMatch[1]!);
        const delegation = await getDelegationById(env, delegationId);
        if (!delegation) {
          throw new DelegateError('DELEGATION_NOT_FOUND', 'delegation does not exist', 404);
        }

        const limit = parseLimit(url.searchParams.get('limit'), 500, 2000);
        const rows = await listAuditRows(env, delegationId, limit);
        const events = rows.map(canonicalAuditEvent);
        const jsonl = events.map((event) => JSON.stringify(event)).join('\n');
        const digest = await sha256B64u(jsonl);

        return new Response(`${jsonl}${jsonl.length > 0 ? '\n' : ''}`, {
          status: 200,
          headers: {
            'content-type': 'application/x-ndjson; charset=utf-8',
            'cache-control': 'no-store',
            'x-clawdelegate-version': version,
            'x-audit-sha256-b64u': digest,
            'x-audit-record-count': String(events.length),
          },
        });
      }

      return errorResponse('NOT_FOUND', 'Not found', 404, version);
    } catch (err) {
      return toErrorResponse(err, version);
    }
  },

  async queue(batch: MessageBatch<DelegationQueueMessage>, env: Env): Promise<void> {
    const version = env.DELEGATE_VERSION ?? '0.1.0';

    for (const message of batch.messages) {
      try {
        const body = message.body;
        if (!body || body.type !== 'revoke_token') {
          message.ack();
          continue;
        }

        if (!DELEGATION_ID_RE.test(body.delegation_id) || !SHA256_HEX_RE.test(body.token_hash)) {
          message.ack();
          continue;
        }

        await ensureSchema(env);
        await propagateRevocationToScope(env, body);
        message.ack();
      } catch (err) {
        const response = toErrorResponse(err, version);
        const details = await response.text();
        console.error(`[clawdelegate] queue revoke propagation failed: ${details}`);
        message.retry();
      }
    }
  },
};
