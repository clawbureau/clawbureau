import {
  type ClosureEventInput,
  computeClosureScoreDelta,
  computePenaltyScoreDelta,
  deriveTier,
  isDidString,
  isDisputePenalty,
  type PenaltyType,
  selectReviewersDeterministic,
  type SelectReviewersRequest,
  type ReviewerInfo,
} from './core';

interface Env {
  REP_DB?: D1Database;
  REP_EVENTS?: Queue;
  REP_CACHE?: KVNamespace;
  REP_VERSION?: string;
  REP_ADMIN_KEY?: string;
  REP_INGEST_KEY?: string;
  REP_DECAY_DAILY_RATE?: string;
  REP_REVIEWER_CACHE_TTL_SECONDS?: string;
}

type IngestBody = {
  schema_version: '1';
  source_event_id: string;
  did: string;
  event_type: 'closure';
  value_usd: number;
  closure_type: ClosureEventInput['closure_type'];
  proof_tier: ClosureEventInput['proof_tier'];
  owner_verified: boolean;
  owner_attestation_ref?: string;
  occurred_at: string;
  metadata?: Record<string, unknown>;
};

type PenaltyBody = {
  schema_version: '1';
  source_event_id: string;
  did: string;
  penalty_type: PenaltyType;
  severity: number;
  reason?: string;
  occurred_at: string;
  metadata?: Record<string, unknown>;
};

type DecayBody = {
  schema_version?: '1';
  run_day?: string;
};

let schemaReady: Promise<void> | null = null;

const PENALTY_TYPES: ReadonlySet<string> = new Set([
  'dispute_upheld_against_reviewer',
  'dispute_upheld_against_worker',
  'fraud_confirmed',
  'spam_review',
  'policy_violation',
]);

const PROOF_TIERS: ReadonlySet<string> = new Set([
  'unknown',
  'self',
  'gateway',
  'sandbox',
  'tee',
  'witnessed_web',
]);

const CLOSURE_TYPES: ReadonlySet<string> = new Set([
  'auto_approve',
  'quorum_approve',
  'manual_approve',
  'dispute_resolved',
]);

const ISSUES = {
  invalidRequest: 'INVALID_REQUEST',
  unauthorized: 'UNAUTHORIZED',
  dependencyNotConfigured: 'DEPENDENCY_NOT_CONFIGURED',
  notFound: 'NOT_FOUND',
  queueError: 'QUEUE_SEND_FAILED',
  dbWriteFailed: 'DB_WRITE_FAILED',
} as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function parseNumber(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return value;
}

function nowIso(): string {
  return new Date().toISOString();
}

function jsonResponse(payload: unknown, status = 200, version = '0.1.0'): Response {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-clawrep-version': version,
    },
  });
}

function textResponse(payload: string, status = 200, version = '0.1.0'): Response {
  return new Response(payload, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'x-clawrep-version': version,
    },
  });
}

function errorResponse(
  error: string,
  message: string,
  status: number,
  version: string,
  details?: Record<string, unknown>
): Response {
  return jsonResponse(
    {
      error,
      message,
      ...(details ? { details } : {}),
    },
    status,
    version
  );
}

function parseBearerToken(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.toLowerCase().startsWith('bearer ')) {
    const token = trimmed.slice(7).trim();
    return token.length > 0 ? token : null;
  }
  return trimmed;
}

function readAuthToken(request: Request): string | null {
  const auth = parseBearerToken(request.headers.get('authorization'));
  if (auth) return auth;
  return parseBearerToken(request.headers.get('x-admin-key'));
}

function requireAdmin(request: Request, env: Env, version: string): Response | null {
  const configured = env.REP_ADMIN_KEY?.trim();
  if (!configured) {
    return errorResponse(
      ISSUES.dependencyNotConfigured,
      'REP_ADMIN_KEY is required for admin endpoints',
      503,
      version
    );
  }
  const provided = readAuthToken(request);
  if (!provided) {
    return errorResponse(ISSUES.unauthorized, 'Missing Authorization header', 401, version);
  }
  if (provided !== configured) {
    return errorResponse(ISSUES.unauthorized, 'Invalid admin token', 401, version);
  }
  return null;
}

function requireIngestAuth(request: Request, env: Env, version: string): Response | null {
  const configured = env.REP_INGEST_KEY?.trim();
  if (!configured) {
    return errorResponse(
      ISSUES.dependencyNotConfigured,
      'REP_INGEST_KEY is required for ingest endpoint',
      503,
      version
    );
  }

  const provided =
    parseBearerToken(request.headers.get('authorization')) ??
    parseBearerToken(request.headers.get('x-rep-ingest-key'));

  if (!provided) {
    return errorResponse(ISSUES.unauthorized, 'Missing ingest authorization header', 401, version);
  }
  if (provided !== configured) {
    return errorResponse(ISSUES.unauthorized, 'Invalid ingest token', 401, version);
  }
  return null;
}

function parseIsoOrNow(value: unknown): string {
  if (!isNonEmptyString(value)) return nowIso();
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return nowIso();
  return parsed.toISOString();
}

function parseRunDay(value: unknown): string {
  if (!isNonEmptyString(value)) {
    return nowIso().slice(0, 10);
  }
  const trimmed = value.trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
    return nowIso().slice(0, 10);
  }
  return trimmed;
}

function parseBoolean(value: unknown, fallback = false): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
  }
  return fallback;
}

function parseDecayRate(env: Env): number {
  const raw = env.REP_DECAY_DAILY_RATE?.trim();
  if (!raw) return 0.02;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 0.5) return 0.02;
  return parsed;
}

function parseReviewerCacheTtl(env: Env): number {
  const raw = env.REP_REVIEWER_CACHE_TTL_SECONDS?.trim();
  if (!raw) return 120;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 3600) return 120;
  return Math.floor(parsed);
}

async function parseRequestJson(request: Request): Promise<unknown> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function ensureSchema(db: D1Database): Promise<void> {
  if (!schemaReady) {
    schemaReady = (async () => {
      const requiredTables = ['rep_profiles', 'rep_events', 'rep_audit_events', 'decay_runs'];
      for (const tableName of requiredTables) {
        const row = await db
          .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`)
          .bind(tableName)
          .first<{ name: string }>();
        if (!row?.name) {
          throw new Error(`REP_SCHEMA_NOT_READY:${tableName}`);
        }
      }
    })();
  }

  await schemaReady;
}

async function appendAudit(
  db: D1Database,
  eventKind: string,
  did: string | null,
  sourceEventId: string | null,
  details?: Record<string, unknown>
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO rep_audit_events (event_kind, did, source_event_id, details_json, created_at)
       VALUES (?, ?, ?, ?, ?)`
    )
    .bind(eventKind, did, sourceEventId, details ? JSON.stringify(details) : null, nowIso())
    .run();
}

async function upsertProfileFromEvent(
  db: D1Database,
  eventRow: {
    did: string;
    event_type: string;
    score_delta: number;
    owner_verified: number | null;
    owner_attestation_ref: string | null;
    occurred_at: string;
    penalty_type: string | null;
  }
): Promise<void> {
  const existing = await db.prepare('SELECT * FROM rep_profiles WHERE did = ?').bind(eventRow.did).first();
  const now = nowIso();
  const ownerVerified = eventRow.owner_verified === 1;
  const isDispute =
    eventRow.penalty_type === 'dispute_upheld_against_reviewer' ||
    eventRow.penalty_type === 'dispute_upheld_against_worker';

  if (!existing) {
    const initialScore = Math.max(0, Number(eventRow.score_delta));
    await db
      .prepare(
        `INSERT INTO rep_profiles (
          did, reputation_score, events_count, penalties_count, dispute_penalties_count,
          is_owner_verified, owner_attestation_ref, last_event_at, last_decay_at, updated_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        eventRow.did,
        initialScore,
        1,
        eventRow.event_type === 'penalty' ? 1 : 0,
        isDispute ? 1 : 0,
        ownerVerified ? 1 : 0,
        eventRow.owner_attestation_ref,
        eventRow.occurred_at,
        eventRow.event_type === 'decay' ? now : null,
        now,
        now
      )
      .run();
    return;
  }

  const currentScore = Number(existing.reputation_score ?? 0);
  const nextScore = Math.max(0, currentScore + Number(eventRow.score_delta));
  const currentEvents = Number(existing.events_count ?? 0);
  const currentPenalties = Number(existing.penalties_count ?? 0);
  const currentDisputePenalties = Number(existing.dispute_penalties_count ?? 0);
  const currentOwnerVerified = Number(existing.is_owner_verified ?? 0) === 1;

  await db
    .prepare(
      `UPDATE rep_profiles
       SET reputation_score = ?,
           events_count = ?,
           penalties_count = ?,
           dispute_penalties_count = ?,
           is_owner_verified = ?,
           owner_attestation_ref = COALESCE(?, owner_attestation_ref),
           last_event_at = ?,
           last_decay_at = ?,
           updated_at = ?
       WHERE did = ?`
    )
    .bind(
      nextScore,
      currentEvents + 1,
      currentPenalties + (eventRow.event_type === 'penalty' ? 1 : 0),
      currentDisputePenalties + (isDispute ? 1 : 0),
      currentOwnerVerified || ownerVerified ? 1 : 0,
      eventRow.owner_attestation_ref,
      eventRow.occurred_at,
      eventRow.event_type === 'decay' ? now : existing.last_decay_at,
      now,
      eventRow.did
    )
    .run();
}

async function processEventBySourceId(
  db: D1Database,
  sourceEventId: string,
  trigger: 'queue' | 'manual' | 'decay'
): Promise<{ processed: boolean; reason?: string }> {
  const row = await db
    .prepare(
      `SELECT source_event_id, did, event_type, status, score_delta, owner_verified,
              owner_attestation_ref, occurred_at, penalty_type
       FROM rep_events
       WHERE source_event_id = ?`
    )
    .bind(sourceEventId)
    .first<{
      source_event_id: string;
      did: string;
      event_type: string;
      status: string;
      score_delta: number;
      owner_verified: number | null;
      owner_attestation_ref: string | null;
      occurred_at: string;
      penalty_type: string | null;
    }>();

  if (!row) {
    return { processed: false, reason: 'event_not_found' };
  }

  if (row.status === 'processed') {
    return { processed: false, reason: 'already_processed' };
  }

  const claim = await db
    .prepare(
      `UPDATE rep_events
       SET status = 'processing', error_code = NULL, error_message = NULL
       WHERE source_event_id = ? AND status IN ('pending', 'failed')`
    )
    .bind(sourceEventId)
    .run();

  if (Number(claim.meta.changes ?? 0) === 0) {
    return { processed: false, reason: 'processing_claim_failed' };
  }

  try {
    await upsertProfileFromEvent(db, row);

    await db
      .prepare(
        `UPDATE rep_events
         SET status = 'processed', processed_at = ?, error_code = NULL, error_message = NULL
         WHERE source_event_id = ?`
      )
      .bind(nowIso(), sourceEventId)
      .run();

    await appendAudit(db, 'event.processed', row.did, sourceEventId, { trigger, score_delta: row.score_delta });
    return { processed: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await db
      .prepare(
        `UPDATE rep_events
         SET status = 'failed', error_code = 'PROCESSING_FAILED', error_message = ?
         WHERE source_event_id = ?`
      )
      .bind(message.slice(0, 500), sourceEventId)
      .run();
    await appendAudit(db, 'event.processing_failed', row.did, sourceEventId, {
      trigger,
      error: message.slice(0, 500),
    });
    throw error;
  }
}

async function enqueueEvent(env: Env, sourceEventId: string): Promise<void> {
  if (!env.REP_EVENTS) {
    throw new Error('REP_EVENTS queue is not configured');
  }
  await env.REP_EVENTS.send({ source_event_id: sourceEventId });
}

function parseIngestBody(body: unknown): { ok: true; value: IngestBody } | { ok: false; message: string; field?: string } {
  if (!isRecord(body)) {
    return { ok: false, message: 'Body must be a JSON object' };
  }

  if (body.schema_version !== '1') {
    return { ok: false, message: 'schema_version must be "1"', field: 'schema_version' };
  }

  if (body.event_type !== 'closure') {
    return { ok: false, message: 'event_type must be "closure"', field: 'event_type' };
  }

  if (!isNonEmptyString(body.source_event_id)) {
    return { ok: false, message: 'source_event_id is required', field: 'source_event_id' };
  }

  if (!isDidString(body.did)) {
    return { ok: false, message: 'did must be a valid DID string', field: 'did' };
  }

  const valueUsd = parseNumber(body.value_usd);
  if (valueUsd === null || valueUsd < 0 || valueUsd > 1_000_000) {
    return {
      ok: false,
      message: 'value_usd must be a finite number between 0 and 1000000',
      field: 'value_usd',
    };
  }

  if (!isNonEmptyString(body.closure_type) || !CLOSURE_TYPES.has(body.closure_type)) {
    return {
      ok: false,
      message: 'closure_type must be one of auto_approve|quorum_approve|manual_approve|dispute_resolved',
      field: 'closure_type',
    };
  }

  if (!isNonEmptyString(body.proof_tier) || !PROOF_TIERS.has(body.proof_tier)) {
    return {
      ok: false,
      message: 'proof_tier must be one of unknown|self|gateway|sandbox|tee|witnessed_web',
      field: 'proof_tier',
    };
  }

  if (body.owner_attestation_ref !== undefined && body.owner_attestation_ref !== null && !isNonEmptyString(body.owner_attestation_ref)) {
    return { ok: false, message: 'owner_attestation_ref must be a non-empty string', field: 'owner_attestation_ref' };
  }

  if (body.metadata !== undefined && body.metadata !== null && !isRecord(body.metadata)) {
    return { ok: false, message: 'metadata must be a JSON object', field: 'metadata' };
  }

  return {
    ok: true,
    value: {
      schema_version: '1',
      source_event_id: body.source_event_id.trim(),
      did: body.did.trim(),
      event_type: 'closure',
      value_usd: valueUsd,
      closure_type: body.closure_type as ClosureEventInput['closure_type'],
      proof_tier: body.proof_tier as ClosureEventInput['proof_tier'],
      owner_verified: parseBoolean(body.owner_verified, false),
      owner_attestation_ref: isNonEmptyString(body.owner_attestation_ref) ? body.owner_attestation_ref.trim() : undefined,
      occurred_at: parseIsoOrNow(body.occurred_at),
      metadata: body.metadata as Record<string, unknown> | undefined,
    },
  };
}

function parsePenaltyBody(body: unknown): { ok: true; value: PenaltyBody } | { ok: false; message: string; field?: string } {
  if (!isRecord(body)) {
    return { ok: false, message: 'Body must be a JSON object' };
  }

  if (body.schema_version !== '1') {
    return { ok: false, message: 'schema_version must be "1"', field: 'schema_version' };
  }

  if (!isNonEmptyString(body.source_event_id)) {
    return { ok: false, message: 'source_event_id is required', field: 'source_event_id' };
  }

  if (!isDidString(body.did)) {
    return { ok: false, message: 'did must be a valid DID string', field: 'did' };
  }

  if (!isNonEmptyString(body.penalty_type) || !PENALTY_TYPES.has(body.penalty_type)) {
    return {
      ok: false,
      message:
        'penalty_type must be one of dispute_upheld_against_reviewer|dispute_upheld_against_worker|fraud_confirmed|spam_review|policy_violation',
      field: 'penalty_type',
    };
  }

  const severityRaw = body.severity === undefined ? 1 : parseNumber(body.severity);
  if (severityRaw === null || severityRaw < 1 || severityRaw > 5) {
    return { ok: false, message: 'severity must be a finite number between 1 and 5', field: 'severity' };
  }

  if (body.reason !== undefined && body.reason !== null && !isNonEmptyString(body.reason)) {
    return { ok: false, message: 'reason must be a non-empty string', field: 'reason' };
  }

  if (body.metadata !== undefined && body.metadata !== null && !isRecord(body.metadata)) {
    return { ok: false, message: 'metadata must be a JSON object', field: 'metadata' };
  }

  return {
    ok: true,
    value: {
      schema_version: '1',
      source_event_id: body.source_event_id.trim(),
      did: body.did.trim(),
      penalty_type: body.penalty_type as PenaltyType,
      severity: Math.floor(severityRaw),
      reason: isNonEmptyString(body.reason) ? body.reason.trim() : undefined,
      occurred_at: parseIsoOrNow(body.occurred_at),
      metadata: body.metadata as Record<string, unknown> | undefined,
    },
  };
}

function parseSelectReviewersBody(
  body: unknown
): { ok: true; value: SelectReviewersRequest } | { ok: false; message: string; field?: string } {
  if (!isRecord(body)) {
    return { ok: false, message: 'Body must be a JSON object' };
  }

  if (!isNonEmptyString(body.bounty_id)) {
    return { ok: false, message: 'bounty_id is required', field: 'bounty_id' };
  }

  const difficulty = parseNumber(body.difficulty_scalar);
  if (difficulty === null || difficulty < 0.1 || difficulty > 10) {
    return {
      ok: false,
      message: 'difficulty_scalar must be a finite number between 0.1 and 10',
      field: 'difficulty_scalar',
    };
  }

  const quorumSize = parseNumber(body.quorum_size);
  if (quorumSize === null || !Number.isInteger(quorumSize) || quorumSize < 1 || quorumSize > 10) {
    return {
      ok: false,
      message: 'quorum_size must be an integer between 1 and 10',
      field: 'quorum_size',
    };
  }

  if (body.min_reputation_score !== undefined && body.min_reputation_score !== null) {
    const minRep = parseNumber(body.min_reputation_score);
    if (minRep === null || minRep < 0) {
      return {
        ok: false,
        message: 'min_reputation_score must be a finite number >= 0',
        field: 'min_reputation_score',
      };
    }
  }

  if (body.exclude_dids !== undefined && body.exclude_dids !== null) {
    if (!Array.isArray(body.exclude_dids) || body.exclude_dids.some((item) => !isDidString(item))) {
      return {
        ok: false,
        message: 'exclude_dids must be an array of DID strings',
        field: 'exclude_dids',
      };
    }
  }

  if (body.submission_proof_tier !== undefined && body.submission_proof_tier !== null) {
    if (!isNonEmptyString(body.submission_proof_tier) || !PROOF_TIERS.has(body.submission_proof_tier)) {
      return {
        ok: false,
        message: 'submission_proof_tier must be one of unknown|self|gateway|sandbox|tee|witnessed_web',
        field: 'submission_proof_tier',
      };
    }
  }

  return {
    ok: true,
    value: {
      bounty_id: body.bounty_id.trim(),
      difficulty_scalar: difficulty,
      quorum_size: quorumSize,
      min_reputation_score:
        body.min_reputation_score === undefined || body.min_reputation_score === null
          ? undefined
          : Number(body.min_reputation_score),
      require_owner_verified: parseBoolean(body.require_owner_verified, false),
      exclude_dids: Array.isArray(body.exclude_dids) ? (body.exclude_dids as string[]).map((did) => did.trim()) : undefined,
      submission_proof_tier: isNonEmptyString(body.submission_proof_tier)
        ? (body.submission_proof_tier as SelectReviewersRequest['submission_proof_tier'])
        : undefined,
    },
  };
}

async function hashRequestKey(input: string): Promise<string> {
  const encoded = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  const bytes = new Uint8Array(digest);

  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function runDecay(
  env: Env,
  runDay: string,
  triggeredBy: 'admin' | 'cron'
): Promise<{ already_applied: boolean; run_day: string; affected_profiles: number; total_delta: number }> {
  const db = env.REP_DB;
  if (!db) {
    throw new Error('REP_DB is not configured');
  }
  if (!env.REP_EVENTS) {
    throw new Error('REP_EVENTS queue is not configured');
  }

  const now = nowIso();
  const insertRun = await db
    .prepare(
      `INSERT INTO decay_runs (run_day, triggered_by, affected_profiles, total_delta, executed_at)
       VALUES (?, ?, 0, 0, ?)
       ON CONFLICT(run_day) DO NOTHING`
    )
    .bind(runDay, triggeredBy, now)
    .run();

  if (Number(insertRun.meta.changes ?? 0) === 0) {
    return {
      already_applied: true,
      run_day: runDay,
      affected_profiles: 0,
      total_delta: 0,
    };
  }

  const decayRate = parseDecayRate(env);
  const profiles = await db
    .prepare(
      `SELECT did, reputation_score
       FROM rep_profiles
       WHERE reputation_score > 0`
    )
    .all<{ did: string; reputation_score: number }>();

  let affectedProfiles = 0;
  let totalDelta = 0;

  const rows = (profiles.results ?? []) as Array<{ did: string; reputation_score: number }>;
  for (const profile of rows) {
    const score = Number(profile.reputation_score ?? 0);
    const decayAmount = Math.round(score * decayRate * 1_000_000) / 1_000_000;
    if (decayAmount <= 0) continue;

    const sourceEventId = `decay:${runDay}:${profile.did}`;

    const insertEvent = await db
      .prepare(
        `INSERT OR IGNORE INTO rep_events (
          source_event_id, did, event_type, status, score_delta,
          occurred_at, ingested_at
        ) VALUES (?, ?, 'decay', 'pending', ?, ?, ?)`
      )
      .bind(sourceEventId, profile.did, -decayAmount, `${runDay}T00:00:00.000Z`, now)
      .run();

    if (Number(insertEvent.meta.changes ?? 0) === 0) continue;

    await enqueueEvent(env, sourceEventId);
    await processEventBySourceId(db, sourceEventId, 'decay');

    affectedProfiles += 1;
    totalDelta += decayAmount;
  }

  await db
    .prepare('UPDATE decay_runs SET affected_profiles = ?, total_delta = ?, executed_at = ? WHERE run_day = ?')
    .bind(affectedProfiles, totalDelta, nowIso(), runDay)
    .run();

  await appendAudit(db, 'decay.run', null, null, {
    run_day: runDay,
    triggered_by: triggeredBy,
    affected_profiles: affectedProfiles,
    total_delta: totalDelta,
  });

  return {
    already_applied: false,
    run_day: runDay,
    affected_profiles: affectedProfiles,
    total_delta: totalDelta,
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const version = env.REP_VERSION ?? '0.1.0';
    const url = new URL(request.url);
    const method = request.method.toUpperCase();

    if (url.pathname === '/health') {
      return jsonResponse(
        {
          ok: true,
          service: 'clawrep',
          version,
          now: nowIso(),
        },
        200,
        version
      );
    }

    if (url.pathname === '/docs') {
      return textResponse(
        [
          'clawrep (reputation service)',
          '',
          'Endpoints:',
          '- POST /v1/events/ingest (auth: ingest key)',
          '- GET /v1/rep/:did',
          '- GET /v1/tiers/:did',
          '- POST /v1/reviewers/select',
          '- GET /v1/reviewers/:did',
          '- POST /v1/penalties/apply (auth: admin key)',
          '- POST /v1/decay/run (auth: admin key)',
          '- GET /v1/audit/events (auth: admin key)',
        ].join('\n'),
        200,
        version
      );
    }

    if (url.pathname === '/skill.md') {
      const md = `---
name: clawrep
version: "1"
metadata: {"owner":"clawbureau","service":"clawrep","auth":"ingest/admin bearer"}
---

# clawrep

Canonical reputation service for deterministic scoring, tiers, reviewer selection, penalties, and decay.`;
      return textResponse(md, 200, version);
    }

    if (!env.REP_DB) {
      return errorResponse(ISSUES.dependencyNotConfigured, 'REP_DB is not configured', 503, version);
    }

    try {
      await ensureSchema(env.REP_DB);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return errorResponse(
        ISSUES.dependencyNotConfigured,
        `Reputation schema is not ready (apply D1 migrations): ${message}`,
        503,
        version
      );
    }

    if (method === 'POST' && url.pathname === '/v1/events/ingest') {
      const authErr = requireIngestAuth(request, env, version);
      if (authErr) return authErr;

      const body = await parseRequestJson(request);
      const parsed = parseIngestBody(body);
      if (!parsed.ok) {
        return errorResponse(ISSUES.invalidRequest, parsed.message, 400, version, parsed.field ? { field: parsed.field } : undefined);
      }

      const input = parsed.value;
      const scoring = computeClosureScoreDelta(input);
      const ingestedAt = nowIso();

      try {
        const insert = await env.REP_DB.prepare(
          `INSERT INTO rep_events (
            source_event_id, did, event_type, status, score_delta,
            closure_type, proof_tier, owner_verified, owner_attestation_ref,
            value_usd, concave_value, weight_closure, weight_proof, weight_owner,
            occurred_at, ingested_at, metadata_json
          ) VALUES (?, ?, 'closure', 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            input.source_event_id,
            input.did,
            scoring.score_delta,
            input.closure_type,
            input.proof_tier,
            input.owner_verified ? 1 : 0,
            input.owner_attestation_ref ?? null,
            input.value_usd,
            scoring.concave_value,
            scoring.weight_closure,
            scoring.weight_proof,
            scoring.weight_owner,
            input.occurred_at,
            ingestedAt,
            input.metadata ? JSON.stringify(input.metadata) : null
          )
          .run();

        if (Number(insert.meta.changes ?? 0) !== 1) {
          return errorResponse(ISSUES.dbWriteFailed, 'Event ingest did not persist', 500, version);
        }

        await appendAudit(env.REP_DB, 'event.ingested', input.did, input.source_event_id, {
          event_type: 'closure',
          score_delta: scoring.score_delta,
        });

        try {
          await enqueueEvent(env, input.source_event_id);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          await env.REP_DB.prepare(
            `UPDATE rep_events
             SET status = 'failed', error_code = ?, error_message = ?
             WHERE source_event_id = ?`
          )
            .bind(ISSUES.queueError, message.slice(0, 500), input.source_event_id)
            .run();
          await appendAudit(env.REP_DB, 'event.enqueue_failed', input.did, input.source_event_id, {
            error: message.slice(0, 500),
          });
          return errorResponse(
            ISSUES.dependencyNotConfigured,
            'REP_EVENTS queue is required for ingest',
            503,
            version
          );
        }

        const processResult = await processEventBySourceId(env.REP_DB, input.source_event_id, 'manual');

        return jsonResponse(
          {
            status: 'accepted',
            duplicate: false,
            source_event_id: input.source_event_id,
            did: input.did,
            score_delta: scoring.score_delta,
            process_result: processResult,
          },
          202,
          version
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.toLowerCase().includes('unique') || message.toLowerCase().includes('constraint')) {
          const existing = await env.REP_DB.prepare(
            `SELECT source_event_id, did, status, score_delta, event_type, occurred_at
             FROM rep_events
             WHERE source_event_id = ?`
          )
            .bind(input.source_event_id)
            .first<{
              source_event_id: string;
              did: string;
              status: string;
              score_delta: number;
              event_type: string;
              occurred_at: string;
            }>();

          await appendAudit(env.REP_DB, 'event.duplicate', input.did, input.source_event_id, {
            event_type: 'closure',
          });

          return jsonResponse(
            {
              status: 'duplicate',
              duplicate: true,
              source_event_id: input.source_event_id,
              event: existing,
            },
            200,
            version
          );
        }

        return errorResponse(ISSUES.dbWriteFailed, `Failed to ingest event: ${message}`, 500, version);
      }
    }

    if (method === 'POST' && url.pathname === '/v1/penalties/apply') {
      const authErr = requireAdmin(request, env, version);
      if (authErr) return authErr;

      const body = await parseRequestJson(request);
      const parsed = parsePenaltyBody(body);
      if (!parsed.ok) {
        return errorResponse(ISSUES.invalidRequest, parsed.message, 400, version, parsed.field ? { field: parsed.field } : undefined);
      }
      const input = parsed.value;
      const delta = computePenaltyScoreDelta(input.penalty_type, input.severity);

      try {
        await env.REP_DB.prepare(
          `INSERT INTO rep_events (
            source_event_id, did, event_type, status, score_delta,
            penalty_type, severity, occurred_at, ingested_at, metadata_json
          ) VALUES (?, ?, 'penalty', 'pending', ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            input.source_event_id,
            input.did,
            delta,
            input.penalty_type,
            input.severity,
            input.occurred_at,
            nowIso(),
            JSON.stringify({
              ...(input.metadata ?? {}),
              ...(input.reason ? { reason: input.reason } : {}),
            })
          )
          .run();

        await appendAudit(env.REP_DB, 'penalty.applied', input.did, input.source_event_id, {
          penalty_type: input.penalty_type,
          severity: input.severity,
          score_delta: delta,
        });

        await enqueueEvent(env, input.source_event_id);
        const processResult = await processEventBySourceId(env.REP_DB, input.source_event_id, 'manual');

        return jsonResponse(
          {
            status: 'accepted',
            duplicate: false,
            source_event_id: input.source_event_id,
            did: input.did,
            penalty_type: input.penalty_type,
            severity: input.severity,
            score_delta: delta,
            deterministic_dispute_penalty: isDisputePenalty(input.penalty_type),
            process_result: processResult,
          },
          202,
          version
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.toLowerCase().includes('unique') || message.toLowerCase().includes('constraint')) {
          const existing = await env.REP_DB.prepare(
            `SELECT source_event_id, did, status, score_delta, penalty_type, severity, occurred_at
             FROM rep_events
             WHERE source_event_id = ?`
          )
            .bind(input.source_event_id)
            .first();

          await appendAudit(env.REP_DB, 'penalty.duplicate', input.did, input.source_event_id);

          return jsonResponse(
            {
              status: 'duplicate',
              duplicate: true,
              source_event_id: input.source_event_id,
              event: existing,
            },
            200,
            version
          );
        }

        return errorResponse(ISSUES.dbWriteFailed, `Failed to apply penalty: ${message}`, 500, version);
      }
    }

    if (method === 'POST' && url.pathname === '/v1/decay/run') {
      const authErr = requireAdmin(request, env, version);
      if (authErr) return authErr;

      const body = (await parseRequestJson(request)) as DecayBody | null;
      if (body !== null && body !== undefined && !isRecord(body)) {
        return errorResponse(ISSUES.invalidRequest, 'Body must be a JSON object', 400, version);
      }

      const runDay = parseRunDay(body?.run_day);

      try {
        const result = await runDecay(env, runDay, 'admin');
        return jsonResponse(
          {
            status: result.already_applied ? 'already_applied' : 'applied',
            ...result,
            decay_rate: parseDecayRate(env),
          },
          200,
          version
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return errorResponse(ISSUES.dependencyNotConfigured, message, 503, version);
      }
    }

    if (method === 'GET' && url.pathname.startsWith('/v1/rep/')) {
      const did = decodeURIComponent(url.pathname.slice('/v1/rep/'.length));
      if (!isDidString(did)) {
        return errorResponse(ISSUES.invalidRequest, 'did path parameter must be a DID', 400, version, { field: 'did' });
      }

      const profile = await env.REP_DB.prepare('SELECT * FROM rep_profiles WHERE did = ?').bind(did).first<{
        did: string;
        reputation_score: number;
        events_count: number;
        penalties_count: number;
        dispute_penalties_count: number;
        is_owner_verified: number;
        owner_attestation_ref: string | null;
        last_event_at: string | null;
        last_decay_at: string | null;
        updated_at: string;
        created_at: string;
      }>();

      if (!profile) {
        return errorResponse(ISSUES.notFound, 'Reputation profile not found', 404, version);
      }

      const tier = deriveTier({
        reputation_score: Number(profile.reputation_score ?? 0),
        events_count: Number(profile.events_count ?? 0),
        dispute_penalties_count: Number(profile.dispute_penalties_count ?? 0),
      });

      return jsonResponse(
        {
          did: profile.did,
          reputation_score: Number(profile.reputation_score ?? 0),
          events_count: Number(profile.events_count ?? 0),
          penalties_count: Number(profile.penalties_count ?? 0),
          dispute_penalties_count: Number(profile.dispute_penalties_count ?? 0),
          is_owner_verified: Number(profile.is_owner_verified ?? 0) === 1,
          owner_attestation_ref: profile.owner_attestation_ref ?? null,
          tier,
          last_event_at: profile.last_event_at,
          last_decay_at: profile.last_decay_at,
          updated_at: profile.updated_at,
          created_at: profile.created_at,
        },
        200,
        version
      );
    }

    if (method === 'GET' && url.pathname.startsWith('/v1/tiers/')) {
      const did = decodeURIComponent(url.pathname.slice('/v1/tiers/'.length));
      if (!isDidString(did)) {
        return errorResponse(ISSUES.invalidRequest, 'did path parameter must be a DID', 400, version, { field: 'did' });
      }

      const profile = await env.REP_DB.prepare(
        'SELECT did, reputation_score, events_count, dispute_penalties_count FROM rep_profiles WHERE did = ?'
      )
        .bind(did)
        .first<{
          did: string;
          reputation_score: number;
          events_count: number;
          dispute_penalties_count: number;
        }>();

      if (!profile) {
        return errorResponse(ISSUES.notFound, 'Reputation profile not found', 404, version);
      }

      const tier = deriveTier({
        reputation_score: Number(profile.reputation_score ?? 0),
        events_count: Number(profile.events_count ?? 0),
        dispute_penalties_count: Number(profile.dispute_penalties_count ?? 0),
      });

      return jsonResponse(
        {
          did: profile.did,
          reputation_score: Number(profile.reputation_score ?? 0),
          ...tier,
          evaluated_at: nowIso(),
        },
        200,
        version
      );
    }

    if (method === 'GET' && url.pathname.startsWith('/v1/reviewers/')) {
      const did = decodeURIComponent(url.pathname.slice('/v1/reviewers/'.length));
      if (!isDidString(did)) {
        return errorResponse(ISSUES.invalidRequest, 'reviewer DID is invalid', 400, version, { field: 'reviewer_did' });
      }

      const reviewer = await env.REP_DB.prepare(
        `SELECT did, reputation_score, is_owner_verified, owner_attestation_ref
         FROM rep_profiles
         WHERE did = ?`
      )
        .bind(did)
        .first<{
          did: string;
          reputation_score: number;
          is_owner_verified: number;
          owner_attestation_ref: string | null;
        }>();

      if (!reviewer) {
        return errorResponse(ISSUES.notFound, 'Reviewer not found', 404, version);
      }

      return jsonResponse(
        {
          reviewer_did: reviewer.did,
          reputation_score: Number(reviewer.reputation_score ?? 0),
          is_owner_verified: Number(reviewer.is_owner_verified ?? 0) === 1,
          owner_attestation_ref: reviewer.owner_attestation_ref ?? undefined,
        },
        200,
        version
      );
    }

    if (method === 'POST' && url.pathname === '/v1/reviewers/select') {
      const body = await parseRequestJson(request);
      const parsed = parseSelectReviewersBody(body);
      if (!parsed.ok) {
        return errorResponse(ISSUES.invalidRequest, parsed.message, 400, version, parsed.field ? { field: parsed.field } : undefined);
      }
      const input = parsed.value;
      const selectedAt = nowIso();

      let cacheKey: string | null = null;
      if (env.REP_CACHE) {
        cacheKey = `reviewer-select:${await hashRequestKey(JSON.stringify(input))}`;
        const cached = await env.REP_CACHE.get(cacheKey);
        if (cached) {
          return jsonResponse(JSON.parse(cached), 200, version);
        }
      }

      const candidatesRows = await env.REP_DB.prepare(
        `SELECT did, reputation_score, is_owner_verified, owner_attestation_ref
         FROM rep_profiles
         WHERE reputation_score >= 0
         ORDER BY did ASC`
      ).all<{
        did: string;
        reputation_score: number;
        is_owner_verified: number;
        owner_attestation_ref: string | null;
      }>();

      const candidates: ReviewerInfo[] = (candidatesRows.results ?? []).map((row) => ({
        reviewer_did: row.did,
        reputation_score: Number(row.reputation_score ?? 0),
        is_owner_verified: Number(row.is_owner_verified ?? 0) === 1,
        owner_attestation_ref: row.owner_attestation_ref ?? undefined,
      }));

      const selected = selectReviewersDeterministic(input, candidates);
      if (selected.length < input.quorum_size) {
        return errorResponse(
          ISSUES.invalidRequest,
          'Insufficient eligible reviewers for requested quorum size',
          409,
          version,
          {
            requested_quorum_size: input.quorum_size,
            available_reviewers: selected.length,
          }
        );
      }

      const response = {
        bounty_id: input.bounty_id,
        reviewers: selected,
        selected_at: selectedAt,
      };

      if (env.REP_CACHE && cacheKey) {
        await env.REP_CACHE.put(cacheKey, JSON.stringify(response), {
          expirationTtl: parseReviewerCacheTtl(env),
        });
      }

      await appendAudit(env.REP_DB, 'reviewers.selected', null, null, {
        bounty_id: input.bounty_id,
        quorum_size: input.quorum_size,
        selected_reviewers: selected.map((item) => item.reviewer_did),
      });

      return jsonResponse(response, 200, version);
    }

    if (method === 'GET' && url.pathname === '/v1/audit/events') {
      const authErr = requireAdmin(request, env, version);
      if (authErr) return authErr;

      const limitRaw = Number(url.searchParams.get('limit') ?? '100');
      const limit = Number.isFinite(limitRaw) ? Math.min(500, Math.max(1, Math.floor(limitRaw))) : 100;
      const cursorRaw = url.searchParams.get('cursor');
      const cursor = cursorRaw && /^\d+$/.test(cursorRaw) ? Number(cursorRaw) : null;

      const rows = cursor
        ? await env.REP_DB.prepare(
            `SELECT audit_id, event_kind, did, source_event_id, details_json, created_at
             FROM rep_audit_events
             WHERE audit_id < ?
             ORDER BY audit_id DESC
             LIMIT ?`
          )
            .bind(cursor, limit)
            .all<{
              audit_id: number;
              event_kind: string;
              did: string | null;
              source_event_id: string | null;
              details_json: string | null;
              created_at: string;
            }>()
        : await env.REP_DB.prepare(
            `SELECT audit_id, event_kind, did, source_event_id, details_json, created_at
             FROM rep_audit_events
             ORDER BY audit_id DESC
             LIMIT ?`
          )
            .bind(limit)
            .all<{
              audit_id: number;
              event_kind: string;
              did: string | null;
              source_event_id: string | null;
              details_json: string | null;
              created_at: string;
            }>();

      const events = (rows.results ?? []).map((row) => ({
        audit_id: row.audit_id,
        event_kind: row.event_kind,
        did: row.did,
        source_event_id: row.source_event_id,
        details: row.details_json ? JSON.parse(row.details_json) : null,
        created_at: row.created_at,
      }));

      return jsonResponse(
        {
          events,
          next_cursor: events.length === limit ? String(events[events.length - 1]?.audit_id ?? '') : null,
        },
        200,
        version
      );
    }

    return errorResponse(ISSUES.notFound, 'Not found', 404, version);
  },

  async queue(batch: MessageBatch<unknown>, env: Env, _ctx: ExecutionContext): Promise<void> {
    if (!env.REP_DB) return;
    try {
      await ensureSchema(env.REP_DB);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[clawrep] queue schema check failed: ${message}`);
      return;
    }

    for (const message of batch.messages) {
      try {
        const body = message.body;
        const sourceEventId =
          isRecord(body) && isNonEmptyString(body.source_event_id)
            ? body.source_event_id
            : isNonEmptyString(body)
              ? body
              : null;

        if (!sourceEventId) {
          await appendAudit(env.REP_DB, 'event.queue_invalid_message', null, null, {
            body_type: typeof body,
          });
          message.ack();
          continue;
        }

        await processEventBySourceId(env.REP_DB, sourceEventId, 'queue');
        message.ack();
      } catch (error) {
        const messageText = error instanceof Error ? error.message : String(error);
        console.error(`[clawrep] queue processing failed: ${messageText}`);
        message.retry();
      }
    }
  },

  async scheduled(event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    if (!env.REP_DB) return;
    try {
      await ensureSchema(env.REP_DB);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[clawrep] scheduled schema check failed: ${message}`);
      return;
    }

    const runDay = new Date(event.scheduledTime).toISOString().slice(0, 10);
    try {
      await runDecay(env, runDay, 'cron');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[clawrep] scheduled decay failed: ${message}`);
      await appendAudit(env.REP_DB, 'decay.cron_failed', null, null, {
        run_day: runDay,
        error: message.slice(0, 500),
      });
    }
  },
};
