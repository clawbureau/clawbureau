import {
  didKeyToEd25519PublicKeyBytes,
  importEd25519PublicKeyFromBytes,
  verifyEd25519,
} from './crypto';

type SupportedPlatform = 'github' | 'x' | 'moltbook';

type AuditEventType =
  | 'platform_claim.registered'
  | 'primary_did.updated'
  | 'owner_attestation.registered'
  | 'scope_token.exchanged'
  | 'org_roster.manifest_registered';

interface ScopeExchangeChallengeRecord {
  challenge_id: string;
  owner_did: string;
  message: string;
  nonce: string;
  aud: string[];
  scope: string[];
  ttl_sec: number;
  exp: number;
  owner_attestation_id?: string;
  mission_id?: string;
  controller_did?: string;
  agent_did?: string;
}

interface PlatformClaimRecord {
  claim_id: string;
  owner_did: string;
  platform: SupportedPlatform;
  handle: string;
  proof_url: string;
  verification_ref?: string;
  created_at: number;
  updated_at: number;
}

interface OwnerAttestationRecord {
  attestation_id: string;
  owner_did: string;
  owner_provider: string;
  provider_ref?: string;
  verification_level: string;
  proof_url?: string;
  expires_at?: number;
  envelope_json?: string;
  created_at: number;
  updated_at: number;
}

interface RosterMember {
  member_did: string;
  team_role: string;
}

interface ClaimM5Env {
  CLAIM_VERSION: string;
  CLAIM_STORE?: KVNamespace;
  CLAIM_CACHE?: KVNamespace;
  CLAIM_DB?: D1Database;
  CLAIM_AUDIT_EXPORTS?: R2Bucket;

  CLAIM_SCOPE_BASE_URL?: string;
  CLAIM_SCOPE_ADMIN_KEY?: string;
  CLAIM_SCOPE_TIMEOUT_MS?: string;
  CLAIM_SCOPE_EXCHANGE_TTL_SECONDS?: string;

  CLAWVERIFY_BASE_URL?: string;
  CLAWVERIFY_TIMEOUT_MS?: string;

  CLAIM_CLAWLOGS_BASE_URL?: string;
  CLAIM_CLAWLOGS_ADMIN_KEY?: string;
  CLAIM_CLAWLOGS_MODE?: string; // required|best_effort|disabled
}

const BINDING_PREFIX = 'binding:';
const LEGACY_BINDING_EVENTS_PREFIX = 'events:bindings:';
const SCOPE_EXCHANGE_CHALLENGE_PREFIX = 'scope-exchange:challenge:';
const SCOPE_EXCHANGE_USED_PREFIX = 'scope-exchange:used:';

const MAX_SCOPE_ITEMS = 64;
const MAX_SCOPE_ITEM_LENGTH = 128;
const MAX_AUD_ITEMS = 16;
const MAX_AUD_ITEM_LENGTH = 256;
const MAX_TEAM_MEMBERS = 500;
const MAX_TEAM_ROLE_LENGTH = 64;
const MAX_HANDLE_LENGTH = 128;
const MAX_PROVIDER_LENGTH = 64;
const MAX_VERIFICATION_LEVEL_LENGTH = 64;

const DEFAULT_SCOPE_EXCHANGE_TTL_SECONDS = 300;

function jsonResponse(body: unknown, status = 200, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('content-type', 'application/json; charset=utf-8');
  return new Response(JSON.stringify(body, null, 2), { status, headers });
}

function errorResponse(code: string, message: string, status = 400): Response {
  return jsonResponse({ error: code, message }, status);
}

function parseIntOrDefault(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const n = Number.parseInt(value, 10);
  return Number.isFinite(n) ? n : fallback;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  const out = new Uint8Array(digest);
  return Array.from(out)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256B64u(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return toBase64Url(new Uint8Array(digest));
}

function randomNonce(size = 16): string {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

function randomId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID()}`;
}

function challengeKey(challengeId: string): string {
  return `${SCOPE_EXCHANGE_CHALLENGE_PREFIX}${challengeId}`;
}

function usedChallengeKey(challengeId: string): string {
  return `${SCOPE_EXCHANGE_USED_PREFIX}${challengeId}`;
}

function bindingKey(did: string): string {
  return `${BINDING_PREFIX}${did}`;
}

async function readJsonBody(request: Request): Promise<Record<string, unknown> | null> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return null;
  }

  if (!body || typeof body !== 'object') return null;
  return body as Record<string, unknown>;
}

function normalizeScopes(input: unknown): string[] | null {
  if (!Array.isArray(input)) return null;
  if (input.length === 0 || input.length > MAX_SCOPE_ITEMS) return null;

  const out: string[] = [];
  for (const raw of input) {
    if (typeof raw !== 'string') return null;
    const scope = raw.trim();
    if (!scope || scope.length > MAX_SCOPE_ITEM_LENGTH) return null;
    out.push(scope);
  }

  return Array.from(new Set(out)).sort();
}

function normalizeAudience(input: unknown): string[] | null {
  if (typeof input === 'string') {
    const aud = input.trim();
    if (!aud || aud.length > MAX_AUD_ITEM_LENGTH) return null;
    return [aud];
  }

  if (!Array.isArray(input) || input.length === 0 || input.length > MAX_AUD_ITEMS) return null;

  const out: string[] = [];
  for (const raw of input) {
    if (typeof raw !== 'string') return null;
    const aud = raw.trim();
    if (!aud || aud.length > MAX_AUD_ITEM_LENGTH) return null;
    out.push(aud);
  }

  return Array.from(new Set(out)).sort();
}

function parseIsoToEpochSeconds(iso: string | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  return Math.floor(t / 1000);
}

function parseAttestationExpiresAt(input: unknown): number | null {
  if (input === undefined || input === null) return null;
  if (typeof input === 'number' && Number.isFinite(input) && input > 0) return Math.floor(input);
  if (typeof input === 'string' && input.trim().length > 0) {
    const asInt = Number.parseInt(input.trim(), 10);
    if (Number.isFinite(asInt) && asInt > 0) return Math.floor(asInt);
    return parseIsoToEpochSeconds(input.trim());
  }
  return null;
}

function canonicalStringify(value: unknown): string {
  if (value === null) return 'null';

  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Non-finite number in canonicalStringify');
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';

  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalStringify(v)).join(',')}]`;
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalStringify(obj[k])}`).join(',')}}`;
  }

  throw new Error(`Unsupported canonicalStringify type: ${typeof value}`);
}

async function verifyDidSignature(did: string, message: string, signatureB64u: string): Promise<boolean> {
  try {
    const pub = didKeyToEd25519PublicKeyBytes(did);
    const key = await importEd25519PublicKeyFromBytes(pub);
    return await verifyEd25519(key, signatureB64u, message);
  } catch {
    return false;
  }
}

async function getActiveBinding(kv: KVNamespace, did: string): Promise<boolean> {
  const raw = await kv.get(bindingKey(did));
  if (!raw) return false;

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return parsed.active === true;
  } catch {
    return false;
  }
}

let schemaInitialized = false;

async function ensureClaimIdentitySchema(db: D1Database): Promise<void> {
  if (schemaInitialized) return;

  await db.batch([
    db.prepare(`
      CREATE TABLE IF NOT EXISTS platform_claims (
        claim_id TEXT PRIMARY KEY,
        owner_did TEXT NOT NULL,
        platform TEXT NOT NULL,
        handle TEXT NOT NULL,
        proof_url TEXT NOT NULL,
        verification_ref TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        active INTEGER NOT NULL DEFAULT 1
      )
    `),
    db.prepare(
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_platform_claim_owner_platform_handle ON platform_claims(owner_did, platform, handle)`
    ),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_platform_claim_owner ON platform_claims(owner_did, updated_at DESC)`
    ),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS account_primary_dids (
        account_id TEXT PRIMARY KEY,
        primary_did TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      )
    `),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS owner_attestations (
        attestation_id TEXT PRIMARY KEY,
        owner_did TEXT NOT NULL,
        owner_provider TEXT NOT NULL,
        provider_ref TEXT,
        verification_level TEXT NOT NULL,
        proof_url TEXT,
        expires_at INTEGER,
        envelope_json TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        active INTEGER NOT NULL DEFAULT 1
      )
    `),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_owner_attestations_owner ON owner_attestations(owner_did, updated_at DESC)`
    ),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_owner_attestations_provider_ref ON owner_attestations(owner_provider, provider_ref)`
    ),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS org_roster_manifests (
        manifest_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        owner_did TEXT NOT NULL,
        manifest_hash_b64u TEXT NOT NULL,
        manifest_version TEXT NOT NULL,
        member_count INTEGER NOT NULL,
        issued_at INTEGER NOT NULL,
        signature_b64u TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL
      )
    `),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_org_roster_manifests_org ON org_roster_manifests(org_id, created_at DESC)`
    ),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS org_roster_members (
        manifest_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        member_did TEXT NOT NULL,
        team_role TEXT NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (manifest_id, member_did)
      )
    `),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_org_roster_members_org ON org_roster_members(org_id, member_did)`
    ),
    db.prepare(`
      CREATE TABLE IF NOT EXISTS binding_audit_events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL,
        actor_did TEXT NOT NULL,
        subject_did TEXT,
        occurred_at INTEGER NOT NULL,
        details_json TEXT NOT NULL
      )
    `),
    db.prepare(
      `CREATE INDEX IF NOT EXISTS idx_binding_audit_events_occurred ON binding_audit_events(occurred_at DESC)`
    ),
  ]);

  schemaInitialized = true;
}

async function appendAuditEvent(
  env: ClaimM5Env,
  eventType: AuditEventType,
  actorDid: string,
  subjectDid: string | null,
  details: Record<string, unknown>
): Promise<void> {
  if (!env.CLAIM_DB) return;

  await ensureClaimIdentitySchema(env.CLAIM_DB);

  const nowSec = Math.floor(Date.now() / 1000);
  await env.CLAIM_DB.prepare(
    `
      INSERT INTO binding_audit_events (
        event_id,
        event_type,
        actor_did,
        subject_did,
        occurred_at,
        details_json
      ) VALUES (?, ?, ?, ?, ?, ?)
    `
  )
    .bind(
      randomId('audit'),
      eventType,
      actorDid,
      subjectDid,
      nowSec,
      JSON.stringify(details)
    )
    .run();
}

async function fetchJsonWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number
): Promise<{ ok: boolean; status: number; json: any | null; error?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);

  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    const text = await res.text();

    let json: any = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = { raw: text };
    }

    return { ok: res.ok, status: res.status, json };
  } catch (err) {
    return {
      ok: false,
      status: 503,
      json: null,
      error: err instanceof Error ? err.message : String(err),
    };
  } finally {
    clearTimeout(timer);
  }
}

async function verifyMessageEnvelopeWithClawverify(
  env: ClaimM5Env,
  envelope: unknown
): Promise<{ ok: true; signerDid: string | null } | { ok: false; code: string; message: string; status: number }> {
  const baseUrl = env.CLAWVERIFY_BASE_URL?.trim();
  if (!baseUrl) {
    return {
      ok: false,
      code: 'VERIFIER_NOT_CONFIGURED',
      message: 'CLAWVERIFY_BASE_URL is not configured',
      status: 503,
    };
  }

  const timeoutMs = parseIntOrDefault(env.CLAWVERIFY_TIMEOUT_MS, 5000);
  const res = await fetchJsonWithTimeout(
    `${baseUrl.replace(/\/$/, '')}/v1/verify/message`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ envelope }),
    },
    timeoutMs
  );

  if (!res.ok) {
    const code = isNonEmptyString(res.json?.error?.code)
      ? String(res.json.error.code)
      : 'PLATFORM_CLAIM_VERIFICATION_FAILED';
    const message = isNonEmptyString(res.json?.error?.message)
      ? String(res.json.error.message)
      : isNonEmptyString(res.json?.result?.reason)
        ? String(res.json.result.reason)
        : 'clawverify rejected platform claim envelope';

    return { ok: false, code, message, status: res.status >= 400 ? res.status : 422 };
  }

  const signerDid = isNonEmptyString(res.json?.signer_did) ? String(res.json.signer_did) : null;
  return { ok: true, signerDid };
}

async function appendTokenIssuanceToClawlogs(
  env: ClaimM5Env,
  payload: {
    token_hash: string;
    policy_version?: string;
    owner_did: string;
    audience: string[];
    scope: string[];
    issued_at: number;
  }
): Promise<{ ok: true; leaf_hash_b64u: string; status: 'written' | 'skipped' } | { ok: false; code: string; message: string }> {
  const mode = (env.CLAIM_CLAWLOGS_MODE?.trim().toLowerCase() || 'best_effort') as
    | 'required'
    | 'best_effort'
    | 'disabled';

  if (mode === 'disabled') {
    return { ok: true, leaf_hash_b64u: '', status: 'skipped' };
  }

  const baseUrl = env.CLAIM_CLAWLOGS_BASE_URL?.trim();
  const adminKey = env.CLAIM_CLAWLOGS_ADMIN_KEY?.trim();
  if (!baseUrl || !adminKey) {
    if (mode === 'required') {
      return {
        ok: false,
        code: 'CLAWLOGS_NOT_CONFIGURED',
        message: 'CLAIM_CLAWLOGS_BASE_URL and CLAIM_CLAWLOGS_ADMIN_KEY are required in required mode',
      };
    }
    return { ok: true, leaf_hash_b64u: '', status: 'skipped' };
  }

  const leafPayload = canonicalStringify({
    token_hash: payload.token_hash,
    policy_version: payload.policy_version ?? null,
    owner_did: payload.owner_did,
    audience: payload.audience,
    scope: payload.scope,
    issued_at: payload.issued_at,
  });
  const leafHash = await sha256B64u(leafPayload);

  const timeoutMs = parseIntOrDefault(env.CLAIM_SCOPE_TIMEOUT_MS, 5000);
  const appendRes = await fetchJsonWithTimeout(
    `${baseUrl.replace(/\/$/, '')}/v1/logs/identity-scope-exchange/append`,
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ leaf_hash_b64u: leafHash }),
    },
    timeoutMs
  );

  if (!appendRes.ok) {
    if (mode === 'required') {
      return {
        ok: false,
        code: 'CLAWLOGS_APPEND_FAILED',
        message: isNonEmptyString(appendRes.json?.error?.message)
          ? String(appendRes.json.error.message)
          : 'Failed to append scope token issuance leaf to clawlogs',
      };
    }

    return { ok: true, leaf_hash_b64u: leafHash, status: 'skipped' };
  }

  return { ok: true, leaf_hash_b64u: leafHash, status: 'written' };
}

async function issueScopeTokenFromChallenge(
  env: ClaimM5Env,
  challenge: ScopeExchangeChallengeRecord,
  ownerDid: string,
  scopeAdminKeyOverride?: string
): Promise<{ ok: true; response: any } | { ok: false; code: string; message: string; status: number }> {
  const baseUrl = env.CLAIM_SCOPE_BASE_URL?.trim();
  const adminKey =
    (scopeAdminKeyOverride && scopeAdminKeyOverride.trim().length > 0
      ? scopeAdminKeyOverride.trim()
      : undefined) ?? env.CLAIM_SCOPE_ADMIN_KEY?.trim();

  if (!baseUrl || !adminKey) {
    return {
      ok: false,
      code: 'SCOPE_DEPENDENCY_NOT_CONFIGURED',
      message:
        'CLAIM_SCOPE_BASE_URL and CLAIM_SCOPE_ADMIN_KEY (or x-scope-admin-key header override) are required for scope exchange',
      status: 503,
    };
  }

  const useCanonical =
    isNonEmptyString(challenge.controller_did) && isNonEmptyString(challenge.agent_did);

  const endpoint = useCanonical ? '/v1/tokens/issue/canonical' : '/v1/tokens/issue';
  const requestBody: Record<string, unknown> = {
    sub: useCanonical ? challenge.agent_did : ownerDid,
    aud: challenge.aud,
    scope: challenge.scope,
    ttl_sec: challenge.ttl_sec,
    owner_ref: challenge.owner_attestation_id,
    mission_id: challenge.mission_id,
  };

  if (useCanonical) {
    requestBody.owner_did = ownerDid;
    requestBody.controller_did = challenge.controller_did;
    requestBody.agent_did = challenge.agent_did;
  }

  const timeoutMs = parseIntOrDefault(env.CLAIM_SCOPE_TIMEOUT_MS, 5000);
  const result = await fetchJsonWithTimeout(
    `${baseUrl.replace(/\/$/, '')}${endpoint}`,
    {
      method: 'POST',
      headers: {
        authorization: `Bearer ${adminKey}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    },
    timeoutMs
  );

  if (!result.ok) {
    const code = isNonEmptyString(result.json?.error)
      ? String(result.json.error)
      : 'SCOPE_ISSUE_FAILED';
    const message = isNonEmptyString(result.json?.message)
      ? String(result.json.message)
      : result.error ?? 'clawscope token issuance failed';

    return {
      ok: false,
      code,
      message,
      status: result.status >= 400 ? result.status : 502,
    };
  }

  return { ok: true, response: result.json };
}

function parsePlatform(input: unknown): SupportedPlatform | null {
  if (typeof input !== 'string') return null;
  const p = input.trim().toLowerCase();
  if (p === 'github' || p === 'x' || p === 'moltbook') return p;
  return null;
}

function parseRosterMembers(input: unknown): RosterMember[] | null {
  if (!Array.isArray(input) || input.length === 0 || input.length > MAX_TEAM_MEMBERS) return null;

  const out: RosterMember[] = [];
  for (const raw of input) {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const did = typeof obj.member_did === 'string' ? obj.member_did.trim() : '';
    const role = typeof obj.team_role === 'string' ? obj.team_role.trim() : '';
    if (!did || !role || role.length > MAX_TEAM_ROLE_LENGTH) return null;
    out.push({ member_did: did, team_role: role });
  }

  const sorted = out.sort((a, b) => a.member_did.localeCompare(b.member_did));
  return sorted;
}

function toCsv(rows: Array<Record<string, unknown>>, columns: string[]): string {
  const escape = (value: unknown): string => {
    if (value === null || value === undefined) return '';
    const s = String(value);
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };

  const header = columns.join(',');
  const body = rows
    .map((row) => columns.map((c) => escape(row[c])).join(','))
    .join('\n');

  return `${header}\n${body}`;
}

export async function handleClaimM5Routes(request: Request, env: ClaimM5Env): Promise<Response | null> {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  // ---- CCL-US-004 platform claims ----
  if (method === 'POST' && url.pathname === '/v1/platform-claims/register') {
    if (!env.CLAIM_DB) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB is not configured', 503);
    }
    if (!env.CLAIM_STORE) {
      return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE is not configured', 503);
    }

    const body = await readJsonBody(request);
    if (!body) return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);

    const ownerDid = typeof body.owner_did === 'string' ? body.owner_did.trim() : '';
    const platform = parsePlatform(body.platform);
    const handle = typeof body.handle === 'string' ? body.handle.trim() : '';
    const proofUrl = typeof body.proof_url === 'string' ? body.proof_url.trim() : '';
    const verificationEnvelope = body.verification_envelope;

    if (!ownerDid) return errorResponse('INVALID_REQUEST', 'owner_did is required', 400);
    if (!platform) {
      return errorResponse('PLATFORM_UNSUPPORTED', 'platform must be one of github, x, moltbook', 400);
    }
    if (!handle || handle.length > MAX_HANDLE_LENGTH) {
      return errorResponse('INVALID_HANDLE', `handle is required (max ${MAX_HANDLE_LENGTH} chars)`, 400);
    }
    if (!proofUrl || !/^https:\/\//i.test(proofUrl)) {
      return errorResponse('INVALID_PROOF_URL', 'proof_url must be an https URL', 400);
    }

    const ownerBinding = await getActiveBinding(env.CLAIM_STORE, ownerDid);
    if (!ownerBinding) {
      return errorResponse('OWNER_BINDING_REQUIRED', 'owner_did must be an active binding', 403);
    }

    if (!verificationEnvelope || typeof verificationEnvelope !== 'object') {
      return errorResponse(
        'VERIFICATION_ENVELOPE_REQUIRED',
        'verification_envelope is required and must be an object',
        400
      );
    }

    const verify = await verifyMessageEnvelopeWithClawverify(env, verificationEnvelope);
    if (!verify.ok) {
      return errorResponse(verify.code, verify.message, verify.status);
    }

    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const nowSec = Math.floor(Date.now() / 1000);
    const claimId = await sha256Hex(`${ownerDid}:${platform}:${handle.toLowerCase()}`);
    const verificationRef = await sha256B64u(canonicalStringify(verificationEnvelope));

    await env.CLAIM_DB.prepare(
      `
      INSERT INTO platform_claims (
        claim_id,
        owner_did,
        platform,
        handle,
        proof_url,
        verification_ref,
        created_at,
        updated_at,
        active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
      ON CONFLICT(claim_id) DO UPDATE SET
        proof_url = excluded.proof_url,
        verification_ref = excluded.verification_ref,
        updated_at = excluded.updated_at,
        active = 1
      `
    )
      .bind(claimId, ownerDid, platform, handle, proofUrl, verificationRef, nowSec, nowSec)
      .run();

    await appendAuditEvent(env, 'platform_claim.registered', ownerDid, ownerDid, {
      claim_id: claimId,
      platform,
      handle,
      verification_ref: verificationRef,
      verifier_signer_did: verify.signerDid,
    });

    if (env.CLAIM_CACHE) {
      await env.CLAIM_CACHE.delete(`profile:${ownerDid}`);
    }

    return jsonResponse({
      status: 'registered',
      claim: {
        claim_id: claimId,
        owner_did: ownerDid,
        platform,
        handle,
        proof_url: proofUrl,
        verification_ref: verificationRef,
        verifier_signer_did: verify.signerDid,
      },
    });
  }

  const getPlatformClaimsMatch = /^\/v1\/platform-claims\/([^/]+)$/.exec(url.pathname);
  if (method === 'GET' && getPlatformClaimsMatch) {
    if (!env.CLAIM_DB) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB is not configured', 503);
    }

    const ownerDid = decodeURIComponent(getPlatformClaimsMatch[1] ?? '').trim();
    if (!ownerDid) return errorResponse('INVALID_REQUEST', 'owner_did path segment is required', 400);

    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const rows = await env.CLAIM_DB.prepare(
      `
      SELECT
        claim_id,
        owner_did,
        platform,
        handle,
        proof_url,
        verification_ref,
        created_at,
        updated_at
      FROM platform_claims
      WHERE owner_did = ? AND active = 1
      ORDER BY updated_at DESC
      `
    )
      .bind(ownerDid)
      .all();

    return jsonResponse({
      status: 'ok',
      owner_did: ownerDid,
      claims: rows.results ?? [],
    });
  }

  // ---- CCL-US-005 primary DID selection ----
  const setPrimaryDidMatch = /^\/v1\/accounts\/([^/]+)\/primary-did$/.exec(url.pathname);
  if (method === 'POST' && setPrimaryDidMatch) {
    if (!env.CLAIM_DB || !env.CLAIM_STORE) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB and CLAIM_STORE are required', 503);
    }

    const accountId = decodeURIComponent(setPrimaryDidMatch[1] ?? '').trim();
    if (!accountId) return errorResponse('INVALID_REQUEST', 'account_id is required', 400);

    const body = await readJsonBody(request);
    if (!body) return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);

    const primaryDid = typeof body.primary_did === 'string' ? body.primary_did.trim() : '';
    const actorDid = typeof body.actor_did === 'string' ? body.actor_did.trim() : primaryDid;

    if (!primaryDid) return errorResponse('INVALID_REQUEST', 'primary_did is required', 400);

    const activeBinding = await getActiveBinding(env.CLAIM_STORE, primaryDid);
    if (!activeBinding) {
      return errorResponse('PRIMARY_DID_BINDING_REQUIRED', 'primary_did must be an active binding', 403);
    }

    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const nowSec = Math.floor(Date.now() / 1000);
    await env.CLAIM_DB.prepare(
      `
      INSERT INTO account_primary_dids (account_id, primary_did, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(account_id) DO UPDATE SET
        primary_did = excluded.primary_did,
        updated_at = excluded.updated_at
      `
    )
      .bind(accountId, primaryDid, nowSec)
      .run();

    await appendAuditEvent(env, 'primary_did.updated', actorDid, primaryDid, {
      account_id: accountId,
      primary_did: primaryDid,
    });

    if (env.CLAIM_CACHE) {
      await env.CLAIM_CACHE.delete(`account-profile:${accountId}`);
    }

    return jsonResponse({
      status: 'updated',
      account_id: accountId,
      primary_did: primaryDid,
      updated_at: nowSec,
    });
  }

  const getProfileMatch = /^\/v1\/accounts\/([^/]+)\/profile$/.exec(url.pathname);
  if (method === 'GET' && getProfileMatch) {
    if (!env.CLAIM_DB) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB is not configured', 503);
    }

    const accountId = decodeURIComponent(getProfileMatch[1] ?? '').trim();
    if (!accountId) return errorResponse('INVALID_REQUEST', 'account_id is required', 400);

    const cacheKey = `account-profile:${accountId}`;
    if (env.CLAIM_CACHE) {
      const cached = await env.CLAIM_CACHE.get(cacheKey);
      if (cached) {
        try {
          return jsonResponse(JSON.parse(cached), 200, { 'x-cache': 'hit' });
        } catch {
          // fallthrough to rebuild
        }
      }
    }

    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const profile = await env.CLAIM_DB.prepare(
      `SELECT account_id, primary_did, updated_at FROM account_primary_dids WHERE account_id = ?`
    )
      .bind(accountId)
      .first<Record<string, unknown>>();

    if (!profile) {
      return errorResponse('ACCOUNT_PROFILE_NOT_FOUND', 'No primary DID configured for account', 404);
    }

    const claimsRows = await env.CLAIM_DB.prepare(
      `
      SELECT claim_id, platform, handle, proof_url, verification_ref, updated_at
      FROM platform_claims
      WHERE owner_did = ? AND active = 1
      ORDER BY updated_at DESC
      `
    )
      .bind(String(profile.primary_did))
      .all();

    const body = {
      status: 'ok',
      account_id: accountId,
      primary_did: profile.primary_did,
      updated_at: profile.updated_at,
      platform_claims: claimsRows.results ?? [],
    };

    if (env.CLAIM_CACHE) {
      await env.CLAIM_CACHE.put(cacheKey, JSON.stringify(body), { expirationTtl: 120 });
    }

    return jsonResponse(body, 200, { 'x-cache': 'miss' });
  }

  // ---- CCL-US-006 binding audit trail ----
  if (method === 'GET' && url.pathname === '/v1/bindings/audit') {
    if (!env.CLAIM_DB) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB is not configured', 503);
    }
    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const limit = Math.min(Math.max(parseIntOrDefault(url.searchParams.get('limit') ?? undefined, 100), 1), 500);
    const cursor = parseIntOrDefault(url.searchParams.get('cursor') ?? undefined, Number.MAX_SAFE_INTEGER);

    const rows = await env.CLAIM_DB.prepare(
      `
      SELECT sequence, event_id, event_type, actor_did, subject_did, occurred_at, details_json
      FROM binding_audit_events
      WHERE sequence < ?
      ORDER BY sequence DESC
      LIMIT ?
      `
    )
      .bind(cursor, limit)
      .all<Record<string, unknown>>();

    const events = (rows.results ?? []).map((row) => {
      const detailsRaw = row.details_json;
      let details: unknown = null;
      if (typeof detailsRaw === 'string') {
        try {
          details = JSON.parse(detailsRaw);
        } catch {
          details = detailsRaw;
        }
      }

      const sequence =
        typeof row.sequence === 'number'
          ? row.sequence
          : Number.parseInt(String(row.sequence ?? '0'), 10);

      return {
        sequence,
        event_id: typeof row.event_id === 'string' ? row.event_id : null,
        event_type: typeof row.event_type === 'string' ? row.event_type : null,
        actor_did: typeof row.actor_did === 'string' ? row.actor_did : null,
        subject_did: typeof row.subject_did === 'string' ? row.subject_did : null,
        occurred_at:
          typeof row.occurred_at === 'number'
            ? row.occurred_at
            : Number.parseInt(String(row.occurred_at ?? '0'), 10),
        details,
      };
    });

    const nextCursor = events.length > 0 ? (events[events.length - 1]?.sequence ?? null) : null;

    const legacyEvents: Array<{ key: string; record: unknown }> = [];
    if (env.CLAIM_STORE) {
      const legacyList = await env.CLAIM_STORE.list({ prefix: LEGACY_BINDING_EVENTS_PREFIX, limit: Math.min(limit, 200) });
      for (const key of legacyList.keys) {
        const raw = await env.CLAIM_STORE.get(key.name);
        if (!raw) continue;
        try {
          legacyEvents.push({ key: key.name, record: JSON.parse(raw) });
        } catch {
          legacyEvents.push({ key: key.name, record: raw });
        }
      }
    }

    return jsonResponse({
      status: 'ok',
      events,
      cursor: nextCursor,
      legacy_binding_events: legacyEvents,
    });
  }

  if (method === 'GET' && url.pathname === '/v1/bindings/audit/export') {
    if (!env.CLAIM_DB) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB is not configured', 503);
    }
    if (!env.CLAIM_AUDIT_EXPORTS) {
      return errorResponse('AUDIT_EXPORT_NOT_CONFIGURED', 'CLAIM_AUDIT_EXPORTS bucket is not configured', 503);
    }

    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const format = (url.searchParams.get('format') ?? 'csv').trim().toLowerCase();
    if (format !== 'csv' && format !== 'jsonl') {
      return errorResponse('INVALID_EXPORT_FORMAT', 'format must be csv or jsonl', 400);
    }

    const maxRows = Math.min(
      Math.max(parseIntOrDefault(url.searchParams.get('limit') ?? undefined, 5000), 1),
      20000
    );

    const rows = await env.CLAIM_DB.prepare(
      `
      SELECT sequence, event_id, event_type, actor_did, subject_did, occurred_at, details_json
      FROM binding_audit_events
      ORDER BY sequence DESC
      LIMIT ?
      `
    )
      .bind(maxRows)
      .all<Record<string, unknown>>();

    const exportRows = (rows.results ?? []).map((row) => ({
      sequence: row.sequence,
      event_id: row.event_id,
      event_type: row.event_type,
      actor_did: row.actor_did,
      subject_did: row.subject_did,
      occurred_at: row.occurred_at,
      details_json: row.details_json,
    }));

    const content =
      format === 'jsonl'
        ? exportRows.map((row) => JSON.stringify(row)).join('\n')
        : toCsv(exportRows, [
            'sequence',
            'event_id',
            'event_type',
            'actor_did',
            'subject_did',
            'occurred_at',
            'details_json',
          ]);

    const now = new Date();
    const timestamp = now.toISOString().replace(/[:.]/g, '-');
    const key = `binding-audit/${timestamp}.${format}`;
    await env.CLAIM_AUDIT_EXPORTS.put(key, content, {
      httpMetadata: {
        contentType: format === 'jsonl' ? 'application/x-ndjson' : 'text/csv',
      },
    });

    const exportHash = await sha256Hex(content);

    return jsonResponse({
      status: 'exported',
      key,
      format,
      rows: exportRows.length,
      sha256: exportHash,
    });
  }

  // ---- CCL-US-007 owner attestation registry ----
  if (method === 'POST' && url.pathname === '/v1/owner-attestations/register') {
    if (!env.CLAIM_DB || !env.CLAIM_STORE) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB and CLAIM_STORE are required', 503);
    }

    const body = await readJsonBody(request);
    if (!body) return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);

    const ownerDid = typeof body.owner_did === 'string' ? body.owner_did.trim() : '';
    const attestationId = typeof body.attestation_id === 'string' ? body.attestation_id.trim() : '';
    const ownerProvider = typeof body.owner_provider === 'string' ? body.owner_provider.trim().toLowerCase() : '';
    const providerRef = typeof body.provider_ref === 'string' ? body.provider_ref.trim() : undefined;
    const verificationLevel =
      typeof body.verification_level === 'string' ? body.verification_level.trim() : '';
    const proofUrl = typeof body.proof_url === 'string' ? body.proof_url.trim() : undefined;
    const expiresAt = parseAttestationExpiresAt(body.expires_at);
    const envelope = body.attestation_envelope;

    if (!ownerDid) return errorResponse('INVALID_REQUEST', 'owner_did is required', 400);
    if (!attestationId) return errorResponse('INVALID_REQUEST', 'attestation_id is required', 400);
    if (!ownerProvider || ownerProvider.length > MAX_PROVIDER_LENGTH) {
      return errorResponse('INVALID_OWNER_PROVIDER', 'owner_provider is required', 400);
    }
    if (ownerProvider !== 'worldid' && ownerProvider !== 'onemolt' && ownerProvider !== 'oauth' && ownerProvider !== 'other') {
      return errorResponse('INVALID_OWNER_PROVIDER', 'owner_provider must be one of worldid, onemolt, oauth, other', 400);
    }
    if (!verificationLevel || verificationLevel.length > MAX_VERIFICATION_LEVEL_LENGTH) {
      return errorResponse(
        'INVALID_VERIFICATION_LEVEL',
        `verification_level is required (max ${MAX_VERIFICATION_LEVEL_LENGTH} chars)`,
        400
      );
    }
    if (proofUrl && !/^https:\/\//i.test(proofUrl)) {
      return errorResponse('INVALID_PROOF_URL', 'proof_url must be an https URL when provided', 400);
    }

    const ownerBinding = await getActiveBinding(env.CLAIM_STORE, ownerDid);
    if (!ownerBinding) {
      return errorResponse('OWNER_BINDING_REQUIRED', 'owner_did must be an active binding', 403);
    }

    if (!envelope || typeof envelope !== 'object') {
      return errorResponse(
        'ATTESTATION_ENVELOPE_REQUIRED',
        'attestation_envelope is required and must be an object',
        400
      );
    }

    const baseUrl = env.CLAWVERIFY_BASE_URL?.trim();
    if (!baseUrl) {
      return errorResponse('VERIFIER_NOT_CONFIGURED', 'CLAWVERIFY_BASE_URL is not configured', 503);
    }

    const verifyTimeout = parseIntOrDefault(env.CLAWVERIFY_TIMEOUT_MS, 5000);
    const verifyRes = await fetchJsonWithTimeout(
      `${baseUrl.replace(/\/$/, '')}/v1/verify/owner-attestation`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ envelope }),
      },
      verifyTimeout
    );

    if (!verifyRes.ok) {
      const code = isNonEmptyString(verifyRes.json?.error?.code)
        ? String(verifyRes.json.error.code)
        : 'OWNER_ATTESTATION_INVALID';
      const message = isNonEmptyString(verifyRes.json?.error?.message)
        ? String(verifyRes.json.error.message)
        : isNonEmptyString(verifyRes.json?.result?.reason)
          ? String(verifyRes.json.result.reason)
          : 'owner attestation verification failed';
      return errorResponse(code, message, verifyRes.status >= 400 ? verifyRes.status : 422);
    }

    if (isNonEmptyString(verifyRes.json?.subject_did) && verifyRes.json.subject_did !== ownerDid) {
      return errorResponse(
        'OWNER_ATTESTATION_SUBJECT_MISMATCH',
        'subject_did in attestation envelope must match owner_did',
        409
      );
    }

    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const nowSec = Math.floor(Date.now() / 1000);
    const envelopeJson = JSON.stringify(envelope);

    await env.CLAIM_DB.prepare(
      `
      INSERT INTO owner_attestations (
        attestation_id,
        owner_did,
        owner_provider,
        provider_ref,
        verification_level,
        proof_url,
        expires_at,
        envelope_json,
        created_at,
        updated_at,
        active
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
      ON CONFLICT(attestation_id) DO UPDATE SET
        owner_did = excluded.owner_did,
        owner_provider = excluded.owner_provider,
        provider_ref = excluded.provider_ref,
        verification_level = excluded.verification_level,
        proof_url = excluded.proof_url,
        expires_at = excluded.expires_at,
        envelope_json = excluded.envelope_json,
        updated_at = excluded.updated_at,
        active = 1
      `
    )
      .bind(
        attestationId,
        ownerDid,
        ownerProvider,
        providerRef ?? null,
        verificationLevel,
        proofUrl ?? null,
        expiresAt,
        envelopeJson,
        nowSec,
        nowSec
      )
      .run();

    await appendAuditEvent(env, 'owner_attestation.registered', ownerDid, ownerDid, {
      attestation_id: attestationId,
      owner_provider: ownerProvider,
      provider_ref: providerRef ?? null,
      verification_level: verificationLevel,
      expires_at: expiresAt,
      verifier_status: verifyRes.json?.owner_status ?? null,
    });

    return jsonResponse({
      status: 'registered',
      attestation: {
        attestation_id: attestationId,
        owner_did: ownerDid,
        owner_provider: ownerProvider,
        provider_ref: providerRef ?? null,
        verification_level: verificationLevel,
        expires_at: expiresAt,
        verifier_owner_status: verifyRes.json?.owner_status ?? null,
      },
    });
  }

  const getOwnerAttestationMatch = /^\/v1\/owner-attestations\/([^/]+)$/.exec(url.pathname);
  if (
    method === 'GET' &&
    getOwnerAttestationMatch &&
    decodeURIComponent(getOwnerAttestationMatch[1] ?? '').trim().toLowerCase() !== 'lookup'
  ) {
    if (!env.CLAIM_DB) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB is not configured', 503);
    }

    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const ownerDid = decodeURIComponent(getOwnerAttestationMatch[1] ?? '').trim();
    if (!ownerDid) return errorResponse('INVALID_REQUEST', 'owner_did path segment is required', 400);

    const rows = await env.CLAIM_DB.prepare(
      `
      SELECT
        attestation_id,
        owner_did,
        owner_provider,
        provider_ref,
        verification_level,
        proof_url,
        expires_at,
        created_at,
        updated_at,
        active
      FROM owner_attestations
      WHERE owner_did = ? AND active = 1
      ORDER BY updated_at DESC
      `
    )
      .bind(ownerDid)
      .all();

    return jsonResponse({
      status: 'ok',
      owner_did: ownerDid,
      attestations: rows.results ?? [],
    });
  }

  if (method === 'GET' && url.pathname === '/v1/owner-attestations/lookup') {
    if (!env.CLAIM_DB) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB is not configured', 503);
    }

    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const ownerProvider = (url.searchParams.get('owner_provider') ?? '').trim().toLowerCase();
    const providerRef = (url.searchParams.get('provider_ref') ?? '').trim();

    if (!ownerProvider || !providerRef) {
      return errorResponse('INVALID_REQUEST', 'owner_provider and provider_ref query params are required', 400);
    }

    const rows = await env.CLAIM_DB.prepare(
      `
      SELECT
        attestation_id,
        owner_did,
        owner_provider,
        provider_ref,
        verification_level,
        proof_url,
        expires_at,
        created_at,
        updated_at
      FROM owner_attestations
      WHERE owner_provider = ? AND provider_ref = ? AND active = 1
      ORDER BY updated_at DESC
      `
    )
      .bind(ownerProvider, providerRef)
      .all();

    return jsonResponse({
      status: 'ok',
      owner_provider: ownerProvider,
      provider_ref: providerRef,
      attestations: rows.results ?? [],
    });
  }

  // ---- CCL-US-008 challenge -> scoped token exchange ----
  if (method === 'POST' && url.pathname === '/v1/scoped-tokens/challenges') {
    if (!env.CLAIM_STORE) {
      return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE is not configured', 503);
    }

    const body = await readJsonBody(request);
    if (!body) return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);

    const ownerDid = typeof body.owner_did === 'string' ? body.owner_did.trim() : '';
    const aud = normalizeAudience(body.aud);
    const scope = normalizeScopes(body.scope);
    const ttlSec = Math.min(
      Math.max(
        typeof body.ttl_sec === 'number' ? Math.floor(body.ttl_sec) : DEFAULT_SCOPE_EXCHANGE_TTL_SECONDS,
        30
      ),
      3600
    );

    const ownerAttestationId =
      typeof body.owner_attestation_id === 'string' ? body.owner_attestation_id.trim() : undefined;
    const missionId = typeof body.mission_id === 'string' ? body.mission_id.trim() : undefined;
    const controllerDid = typeof body.controller_did === 'string' ? body.controller_did.trim() : undefined;
    const agentDid = typeof body.agent_did === 'string' ? body.agent_did.trim() : undefined;

    if (!ownerDid) return errorResponse('INVALID_REQUEST', 'owner_did is required', 400);
    if (!aud) return errorResponse('INVALID_REQUEST', 'aud must be a non-empty string or array of strings', 400);
    if (!scope) return errorResponse('INVALID_REQUEST', 'scope must be a non-empty array of strings', 400);

    const ownerBinding = await getActiveBinding(env.CLAIM_STORE, ownerDid);
    if (!ownerBinding) {
      return errorResponse('OWNER_BINDING_REQUIRED', 'owner_did must be an active binding', 403);
    }

    if (!!controllerDid !== !!agentDid) {
      return errorResponse(
        'INVALID_CANONICAL_CONTEXT',
        'controller_did and agent_did must be provided together for canonical exchange',
        400
      );
    }

    if (ownerAttestationId) {
      if (!env.CLAIM_DB) {
        return errorResponse(
          'IDENTITY_REGISTRY_NOT_CONFIGURED',
          'CLAIM_DB is required when owner_attestation_id is provided',
          503
        );
      }

      await ensureClaimIdentitySchema(env.CLAIM_DB);
      const attestation = await env.CLAIM_DB.prepare(
        `
        SELECT attestation_id, owner_did, expires_at, active
        FROM owner_attestations
        WHERE attestation_id = ?
        `
      )
        .bind(ownerAttestationId)
        .first<Record<string, unknown>>();

      if (!attestation || attestation.active !== 1) {
        return errorResponse('OWNER_ATTESTATION_NOT_FOUND', 'owner_attestation_id is not active', 404);
      }

      if (attestation.owner_did !== ownerDid) {
        return errorResponse(
          'OWNER_ATTESTATION_OWNER_MISMATCH',
          'owner_attestation_id does not belong to owner_did',
          409
        );
      }

      if (
        typeof attestation.expires_at === 'number' &&
        Number.isFinite(attestation.expires_at) &&
        Math.floor(attestation.expires_at) < Math.floor(Date.now() / 1000)
      ) {
        return errorResponse('OWNER_ATTESTATION_EXPIRED', 'owner_attestation_id is expired', 409);
      }
    }

    const challengeId = randomId('scope_chl');
    const nonce = randomNonce(16);
    const nowSec = Math.floor(Date.now() / 1000);
    const exp = nowSec + ttlSec;

    const messagePayload = {
      challenge_version: '1',
      challenge_id: challengeId,
      owner_did: ownerDid,
      aud,
      scope,
      ttl_sec: ttlSec,
      owner_attestation_id: ownerAttestationId ?? null,
      mission_id: missionId ?? null,
      controller_did: controllerDid ?? null,
      agent_did: agentDid ?? null,
      nonce,
      exp,
    };

    const message = `clawclaim:scope_exchange:v1:${canonicalStringify(messagePayload)}`;

    const record: ScopeExchangeChallengeRecord = {
      challenge_id: challengeId,
      owner_did: ownerDid,
      message,
      nonce,
      aud,
      scope,
      ttl_sec: ttlSec,
      exp,
      owner_attestation_id: ownerAttestationId,
      mission_id: missionId,
      controller_did: controllerDid,
      agent_did: agentDid,
    };

    const ttlForStorage = Math.max(
      ttlSec,
      parseIntOrDefault(env.CLAIM_SCOPE_EXCHANGE_TTL_SECONDS, DEFAULT_SCOPE_EXCHANGE_TTL_SECONDS)
    );

    await env.CLAIM_STORE.put(challengeKey(challengeId), JSON.stringify(record), {
      expirationTtl: ttlForStorage,
    });

    return jsonResponse({
      challenge_id: challengeId,
      owner_did: ownerDid,
      message,
      expires_at: exp,
      ttl_sec: ttlSec,
    });
  }

  if (method === 'POST' && url.pathname === '/v1/scoped-tokens/exchange') {
    if (!env.CLAIM_STORE) {
      return errorResponse('STORE_NOT_CONFIGURED', 'CLAIM_STORE is not configured', 503);
    }

    const body = await readJsonBody(request);
    if (!body) return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);

    const ownerDid = typeof body.owner_did === 'string' ? body.owner_did.trim() : '';
    const challengeId = typeof body.challenge_id === 'string' ? body.challenge_id.trim() : '';
    const signatureB64u = typeof body.signature_b64u === 'string' ? body.signature_b64u.trim() : '';

    if (!ownerDid || !challengeId || !signatureB64u) {
      return errorResponse(
        'INVALID_REQUEST',
        'owner_did, challenge_id, and signature_b64u are required',
        400
      );
    }

    const used = await env.CLAIM_STORE.get(usedChallengeKey(challengeId));
    if (used) {
      return errorResponse('TOKEN_EXCHANGE_CHALLENGE_USED', 'challenge_id has already been used', 409);
    }

    const rawChallenge = await env.CLAIM_STORE.get(challengeKey(challengeId));
    if (!rawChallenge) {
      return errorResponse('TOKEN_EXCHANGE_CHALLENGE_NOT_FOUND', 'challenge_id not found or expired', 404);
    }

    let challenge: ScopeExchangeChallengeRecord;
    try {
      challenge = JSON.parse(rawChallenge) as ScopeExchangeChallengeRecord;
    } catch {
      return errorResponse('TOKEN_EXCHANGE_CHALLENGE_INVALID', 'Stored challenge is malformed', 409);
    }

    if (challenge.owner_did !== ownerDid) {
      return errorResponse('TOKEN_EXCHANGE_OWNER_MISMATCH', 'owner_did does not match challenge owner', 403);
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (challenge.exp < nowSec) {
      return errorResponse('TOKEN_EXCHANGE_CHALLENGE_EXPIRED', 'challenge has expired', 409);
    }

    const validSig = await verifyDidSignature(ownerDid, challenge.message, signatureB64u);
    if (!validSig) {
      return errorResponse('TOKEN_EXCHANGE_SIGNATURE_INVALID', 'signature_b64u is invalid', 401);
    }

    await env.CLAIM_STORE.put(usedChallengeKey(challengeId), '1', { expirationTtl: 3600 });
    await env.CLAIM_STORE.delete(challengeKey(challengeId));

    const scopeAdminKeyOverride = request.headers.get('x-scope-admin-key') ?? undefined;
    const issued = await issueScopeTokenFromChallenge(
      env,
      challenge,
      ownerDid,
      scopeAdminKeyOverride
    );
    if (!issued.ok) {
      return errorResponse(issued.code, issued.message, issued.status);
    }

    const tokenHash = isNonEmptyString(issued.response?.token_hash)
      ? String(issued.response.token_hash)
      : '';

    if (!tokenHash) {
      return errorResponse('SCOPE_RESPONSE_INVALID', 'clawscope response missing token_hash', 502);
    }

    const clawlogsResult = await appendTokenIssuanceToClawlogs(env, {
      token_hash: tokenHash,
      policy_version: isNonEmptyString(issued.response?.policy_version)
        ? String(issued.response.policy_version)
        : undefined,
      owner_did: ownerDid,
      audience: challenge.aud,
      scope: challenge.scope,
      issued_at: Math.floor(Date.now() / 1000),
    });

    if (!clawlogsResult.ok) {
      return errorResponse(clawlogsResult.code, clawlogsResult.message, 503);
    }

    await appendAuditEvent(env, 'scope_token.exchanged', ownerDid, ownerDid, {
      challenge_id: challengeId,
      token_hash: tokenHash,
      policy_version: issued.response?.policy_version ?? null,
      token_lane: issued.response?.token_lane ?? null,
      clawlogs_leaf_hash_b64u: clawlogsResult.leaf_hash_b64u || null,
      clawlogs_status: clawlogsResult.status,
      owner_attestation_id: challenge.owner_attestation_id ?? null,
      mission_id: challenge.mission_id ?? null,
    });

    return jsonResponse({
      status: 'issued',
      owner_did: ownerDid,
      token: issued.response?.token,
      token_hash: tokenHash,
      policy_version: issued.response?.policy_version ?? null,
      token_lane: issued.response?.token_lane ?? null,
      kid: issued.response?.kid ?? null,
      iat: issued.response?.iat ?? null,
      exp: issued.response?.exp ?? null,
      clawlogs_leaf_hash_b64u: clawlogsResult.leaf_hash_b64u || null,
      clawlogs_status: clawlogsResult.status,
    });
  }

  // ---- CCL-US-009 org/team roster claims ----
  const rosterManifestMatch = /^\/v1\/orgs\/([^/]+)\/roster-manifests$/.exec(url.pathname);
  if (method === 'POST' && rosterManifestMatch) {
    if (!env.CLAIM_DB || !env.CLAIM_STORE) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB and CLAIM_STORE are required', 503);
    }

    const orgId = decodeURIComponent(rosterManifestMatch[1] ?? '').trim();
    if (!orgId) return errorResponse('INVALID_REQUEST', 'org_id path segment is required', 400);

    const body = await readJsonBody(request);
    if (!body) return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400);

    const ownerDid = typeof body.owner_did === 'string' ? body.owner_did.trim() : '';
    const signatureB64u = typeof body.signature_b64u === 'string' ? body.signature_b64u.trim() : '';
    const issuedAt =
      typeof body.issued_at === 'number' && Number.isFinite(body.issued_at)
        ? Math.floor(body.issued_at)
        : Math.floor(Date.now() / 1000);
    const members = parseRosterMembers(body.members);

    if (!ownerDid) return errorResponse('INVALID_REQUEST', 'owner_did is required', 400);
    if (!members) {
      return errorResponse(
        'INVALID_ROSTER_MEMBERS',
        'members must be a non-empty array of { member_did, team_role }',
        400
      );
    }
    if (!signatureB64u) {
      return errorResponse('INVALID_REQUEST', 'signature_b64u is required', 400);
    }

    const ownerBinding = await getActiveBinding(env.CLAIM_STORE, ownerDid);
    if (!ownerBinding) {
      return errorResponse('OWNER_BINDING_REQUIRED', 'owner_did must be an active binding', 403);
    }

    for (const member of members) {
      const memberBinding = await getActiveBinding(env.CLAIM_STORE, member.member_did);
      if (!memberBinding) {
        return errorResponse(
          'ROSTER_MEMBER_BINDING_REQUIRED',
          `member_did must be an active binding: ${member.member_did}`,
          403
        );
      }
    }

    const canonicalPayload = {
      manifest_version: '1',
      org_id: orgId,
      owner_did: ownerDid,
      issued_at: issuedAt,
      members,
    };

    const manifestHash = await sha256B64u(canonicalStringify(canonicalPayload));
    const signingMessage = `clawclaim:org_roster_manifest:v1:${manifestHash}`;
    const validSig = await verifyDidSignature(ownerDid, signingMessage, signatureB64u);
    if (!validSig) {
      return errorResponse('ROSTER_MANIFEST_SIGNATURE_INVALID', 'signature_b64u does not verify', 401);
    }

    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const nowSec = Math.floor(Date.now() / 1000);
    const manifestId = await sha256Hex(`${orgId}:${ownerDid}:${manifestHash}`);

    await env.CLAIM_DB.batch([
      env.CLAIM_DB.prepare(`UPDATE org_roster_manifests SET active = 0 WHERE org_id = ?`).bind(orgId),
      env.CLAIM_DB.prepare(`
        INSERT INTO org_roster_manifests (
          manifest_id,
          org_id,
          owner_did,
          manifest_hash_b64u,
          manifest_version,
          member_count,
          issued_at,
          signature_b64u,
          active,
          created_at
        ) VALUES (?, ?, ?, ?, '1', ?, ?, ?, 1, ?)
      `).bind(manifestId, orgId, ownerDid, manifestHash, members.length, issuedAt, signatureB64u, nowSec),
    ]);

    for (const member of members) {
      await env.CLAIM_DB.prepare(
        `
        INSERT INTO org_roster_members (
          manifest_id,
          org_id,
          member_did,
          team_role,
          active,
          created_at
        ) VALUES (?, ?, ?, ?, 1, ?)
        `
      )
        .bind(manifestId, orgId, member.member_did, member.team_role, nowSec)
        .run();
    }

    await appendAuditEvent(env, 'org_roster.manifest_registered', ownerDid, ownerDid, {
      org_id: orgId,
      manifest_id: manifestId,
      manifest_hash_b64u: manifestHash,
      member_count: members.length,
    });

    return jsonResponse({
      status: 'registered',
      org_id: orgId,
      manifest_id: manifestId,
      manifest_hash_b64u: manifestHash,
      member_count: members.length,
      issued_at: issuedAt,
    });
  }

  const getRosterLatestMatch = /^\/v1\/orgs\/([^/]+)\/roster\/latest$/.exec(url.pathname);
  if (method === 'GET' && getRosterLatestMatch) {
    if (!env.CLAIM_DB) {
      return errorResponse('IDENTITY_REGISTRY_NOT_CONFIGURED', 'CLAIM_DB is not configured', 503);
    }

    await ensureClaimIdentitySchema(env.CLAIM_DB);

    const orgId = decodeURIComponent(getRosterLatestMatch[1] ?? '').trim();
    if (!orgId) return errorResponse('INVALID_REQUEST', 'org_id path segment is required', 400);

    const manifest = await env.CLAIM_DB.prepare(
      `
      SELECT manifest_id, org_id, owner_did, manifest_hash_b64u, manifest_version,
             member_count, issued_at, signature_b64u, created_at
      FROM org_roster_manifests
      WHERE org_id = ? AND active = 1
      ORDER BY created_at DESC
      LIMIT 1
      `
    )
      .bind(orgId)
      .first<Record<string, unknown>>();

    if (!manifest) {
      return errorResponse('ROSTER_NOT_FOUND', 'No active roster manifest found for org_id', 404);
    }

    const members = await env.CLAIM_DB.prepare(
      `
      SELECT member_did, team_role, created_at
      FROM org_roster_members
      WHERE org_id = ? AND manifest_id = ? AND active = 1
      ORDER BY member_did ASC
      `
    )
      .bind(orgId, String(manifest.manifest_id))
      .all();

    return jsonResponse({
      status: 'ok',
      org_id: orgId,
      manifest,
      members: members.results ?? [],
    });
  }

  return null;
}
