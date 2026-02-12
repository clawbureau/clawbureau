import {
  type ClosureEventInput,
  computeClosureScoreDelta,
  computePenaltyScoreDelta,
  computeRecoveryScoreDelta,
  deriveTier,
  isDidString,
  isDisputePenalty,
  type PenaltyType,
  type RecoveryType,
  selectReviewersDeterministicWithSignals,
  type SelectReviewersRequest,
  type ReviewerInfo,
  type ReviewerSelectionSignals,
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
  REP_REVIEWER_HISTORY_DAYS?: string;
  REP_REVIEWER_COOLDOWN_HOURS?: string;
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

type RecoveryKind = RecoveryType;

type IngestLoopEnvelope = {
  schema_version: '1';
  source_event_id: string;
  source_service: string;
  kind: 'closure' | 'penalty' | 'recovery';
  did: string;
  occurred_at?: string;
  closure?: {
    value_usd: number;
    closure_type: ClosureEventInput['closure_type'];
    proof_tier: ClosureEventInput['proof_tier'];
    owner_verified?: boolean;
    owner_attestation_ref?: string;
  };
  penalty?: {
    penalty_type: PenaltyType;
    severity?: number;
    reason?: string;
  };
  recovery?: {
    recovery_type: RecoveryKind;
    severity?: number;
    reason?: string;
  };
  metadata?: Record<string, unknown>;
};

type QueueMessageEnvelope =
  | {
      source_event_id: string;
    }
  | IngestLoopEnvelope;

type DriftRecomputeBody = {
  did?: string;
  limit?: number;
  apply_repair?: boolean;
};

type QueueReplayBody = {
  source_event_id?: string;
  limit?: number;
};

let schemaReady: Promise<void> | null = null;

const PENALTY_TYPES: ReadonlySet<string> = new Set([
  'dispute_upheld_against_reviewer',
  'dispute_upheld_against_worker',
  'fraud_confirmed',
  'spam_review',
  'policy_violation',
]);

const RECOVERY_TYPES: ReadonlySet<string> = new Set(['appeal_upheld_for_reviewer', 'appeal_upheld_for_worker']);

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
  loopEnvelopeInvalid: 'LOOP_ENVELOPE_INVALID',
  queueReplayFailed: 'QUEUE_REPLAY_FAILED',
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

function parseReviewerHistoryDays(env: Env): number {
  const raw = env.REP_REVIEWER_HISTORY_DAYS?.trim();
  if (!raw) return 30;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 1 || parsed > 120) return 30;
  return Math.floor(parsed);
}

function parseReviewerCooldownHours(env: Env): number {
  const raw = env.REP_REVIEWER_COOLDOWN_HOURS?.trim();
  if (!raw) return 12;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 240) return 12;
  return Math.floor(parsed);
}

function percentile(values: number[], pct: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.floor((pct / 100) * (sorted.length - 1))));
  return sorted[idx] ?? 0;
}

function pairKey(a: string, b: string): string {
  return a <= b ? `${a}::${b}` : `${b}::${a}`;
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
      const requiredTables = ['rep_profiles', 'rep_events', 'rep_audit_events', 'decay_runs', 'rep_drift_reports'];
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

function parseIngestLoopEnvelope(
  body: unknown
): { ok: true; value: IngestLoopEnvelope } | { ok: false; message: string; field?: string } {
  if (!isRecord(body)) {
    return { ok: false, message: 'Body must be a JSON object' };
  }

  if (body.schema_version !== '1') {
    return { ok: false, message: 'schema_version must be "1"', field: 'schema_version' };
  }

  if (!isNonEmptyString(body.source_event_id)) {
    return { ok: false, message: 'source_event_id is required', field: 'source_event_id' };
  }

  if (!isNonEmptyString(body.source_service)) {
    return { ok: false, message: 'source_service is required', field: 'source_service' };
  }

  if (!isDidString(body.did)) {
    return { ok: false, message: 'did must be a valid DID string', field: 'did' };
  }

  if (!isNonEmptyString(body.kind) || !['closure', 'penalty', 'recovery'].includes(body.kind)) {
    return { ok: false, message: 'kind must be closure|penalty|recovery', field: 'kind' };
  }

  const kind = body.kind as IngestLoopEnvelope['kind'];

  if (kind === 'closure') {
    if (!isRecord(body.closure)) {
      return { ok: false, message: 'closure payload is required', field: 'closure' };
    }

    const valueUsd = parseNumber(body.closure.value_usd);
    if (valueUsd === null || valueUsd < 0 || valueUsd > 1_000_000) {
      return {
        ok: false,
        message: 'closure.value_usd must be a finite number between 0 and 1000000',
        field: 'closure.value_usd',
      };
    }

    if (!isNonEmptyString(body.closure.closure_type) || !CLOSURE_TYPES.has(body.closure.closure_type)) {
      return {
        ok: false,
        message: 'closure.closure_type must be one of auto_approve|quorum_approve|manual_approve|dispute_resolved',
        field: 'closure.closure_type',
      };
    }

    if (!isNonEmptyString(body.closure.proof_tier) || !PROOF_TIERS.has(body.closure.proof_tier)) {
      return {
        ok: false,
        message: 'closure.proof_tier must be one of unknown|self|gateway|sandbox|tee|witnessed_web',
        field: 'closure.proof_tier',
      };
    }
  }

  if (kind === 'penalty') {
    if (!isRecord(body.penalty)) {
      return { ok: false, message: 'penalty payload is required', field: 'penalty' };
    }

    if (!isNonEmptyString(body.penalty.penalty_type) || !PENALTY_TYPES.has(body.penalty.penalty_type)) {
      return {
        ok: false,
        message:
          'penalty.penalty_type must be one of dispute_upheld_against_reviewer|dispute_upheld_against_worker|fraud_confirmed|spam_review|policy_violation',
        field: 'penalty.penalty_type',
      };
    }

    const severity = body.penalty.severity === undefined ? 1 : parseNumber(body.penalty.severity);
    if (severity === null || severity < 1 || severity > 5) {
      return { ok: false, message: 'penalty.severity must be a finite number between 1 and 5', field: 'penalty.severity' };
    }
  }

  if (kind === 'recovery') {
    if (!isRecord(body.recovery)) {
      return { ok: false, message: 'recovery payload is required', field: 'recovery' };
    }

    if (!isNonEmptyString(body.recovery.recovery_type) || !RECOVERY_TYPES.has(body.recovery.recovery_type)) {
      return {
        ok: false,
        message: 'recovery.recovery_type must be one of appeal_upheld_for_reviewer|appeal_upheld_for_worker',
        field: 'recovery.recovery_type',
      };
    }

    const severity = body.recovery.severity === undefined ? 1 : parseNumber(body.recovery.severity);
    if (severity === null || severity < 1 || severity > 5) {
      return { ok: false, message: 'recovery.severity must be a finite number between 1 and 5', field: 'recovery.severity' };
    }
  }

  if (body.metadata !== undefined && body.metadata !== null && !isRecord(body.metadata)) {
    return { ok: false, message: 'metadata must be a JSON object', field: 'metadata' };
  }

  const normalized: IngestLoopEnvelope = {
    schema_version: '1',
    source_event_id: body.source_event_id.trim(),
    source_service: body.source_service.trim(),
    kind,
    did: body.did.trim(),
    occurred_at: parseIsoOrNow(body.occurred_at),
    metadata: body.metadata as Record<string, unknown> | undefined,
  };

  if (kind === 'closure') {
    const closure = body.closure as Record<string, unknown>;
    normalized.closure = {
      value_usd: Number(closure.value_usd),
      closure_type: closure.closure_type as ClosureEventInput['closure_type'],
      proof_tier: closure.proof_tier as ClosureEventInput['proof_tier'],
      owner_verified: parseBoolean(closure.owner_verified, false),
      owner_attestation_ref: isNonEmptyString(closure.owner_attestation_ref) ? closure.owner_attestation_ref.trim() : undefined,
    };
  }

  if (kind === 'penalty') {
    const penalty = body.penalty as Record<string, unknown>;
    normalized.penalty = {
      penalty_type: penalty.penalty_type as PenaltyType,
      severity: Math.floor(Number(penalty.severity ?? 1)),
      reason: isNonEmptyString(penalty.reason) ? penalty.reason.trim() : undefined,
    };
  }

  if (kind === 'recovery') {
    const recovery = body.recovery as Record<string, unknown>;
    normalized.recovery = {
      recovery_type: recovery.recovery_type as RecoveryKind,
      severity: Math.floor(Number(recovery.severity ?? 1)),
      reason: isNonEmptyString(recovery.reason) ? recovery.reason.trim() : undefined,
    };
  }

  return { ok: true, value: normalized };
}

function parseQueueEnvelope(body: unknown): { ok: true; value: QueueMessageEnvelope } | { ok: false; message: string } {
  if (isRecord(body) && isNonEmptyString(body.source_event_id) && !('schema_version' in body) && !('kind' in body)) {
    return { ok: true, value: { source_event_id: body.source_event_id.trim() } };
  }

  const parsed = parseIngestLoopEnvelope(body);
  if (parsed.ok) return { ok: true, value: parsed.value };

  if (isNonEmptyString(body)) {
    return { ok: true, value: { source_event_id: body.trim() } };
  }

  return { ok: false, message: parsed.message };
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

  if (body.requester_did !== undefined && body.requester_did !== null && !isDidString(body.requester_did)) {
    return {
      ok: false,
      message: 'requester_did must be a DID string',
      field: 'requester_did',
    };
  }

  if (body.worker_did !== undefined && body.worker_did !== null && !isDidString(body.worker_did)) {
    return {
      ok: false,
      message: 'worker_did must be a DID string',
      field: 'worker_did',
    };
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
      requester_did: isDidString(body.requester_did) ? body.requester_did.trim() : undefined,
      worker_did: isDidString(body.worker_did) ? body.worker_did.trim() : undefined,
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

function parseAuditDetails(detailsJson: string | null): Record<string, unknown> | null {
  if (!detailsJson) return null;
  try {
    const parsed = JSON.parse(detailsJson);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function safeDateMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : null;
}

async function processLoopEnvelope(
  db: D1Database,
  envelope: IngestLoopEnvelope
): Promise<{ duplicate: boolean; source_event_id: string; did: string; kind: string; score_delta: number }> {
  const ingestedAt = nowIso();
  const occurredAt = envelope.occurred_at ?? nowIso();

  if (envelope.kind === 'closure') {
    const closure = envelope.closure!;
    const scoring = computeClosureScoreDelta({
      value_usd: closure.value_usd,
      closure_type: closure.closure_type,
      proof_tier: closure.proof_tier,
      owner_verified: closure.owner_verified ?? false,
    });

    try {
      await db
        .prepare(
          `INSERT INTO rep_events (
            source_event_id, source_service, did, event_type, status, score_delta,
            closure_type, proof_tier, owner_verified, owner_attestation_ref,
            value_usd, concave_value, weight_closure, weight_proof, weight_owner,
            occurred_at, ingested_at, metadata_json
          ) VALUES (?, ?, ?, 'closure', 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          envelope.source_event_id,
          envelope.source_service,
          envelope.did,
          scoring.score_delta,
          closure.closure_type,
          closure.proof_tier,
          closure.owner_verified ? 1 : 0,
          closure.owner_attestation_ref ?? null,
          closure.value_usd,
          scoring.concave_value,
          scoring.weight_closure,
          scoring.weight_proof,
          scoring.weight_owner,
          occurredAt,
          ingestedAt,
          JSON.stringify({
            source_service: envelope.source_service,
            kind: envelope.kind,
            ...(envelope.metadata ?? {}),
          })
        )
        .run();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.toLowerCase().includes('unique') || message.toLowerCase().includes('constraint')) {
        return {
          duplicate: true,
          source_event_id: envelope.source_event_id,
          did: envelope.did,
          kind: envelope.kind,
          score_delta: scoring.score_delta,
        };
      }
      throw error;
    }

    await appendAudit(db, 'loop.closure.ingested', envelope.did, envelope.source_event_id, {
      source_service: envelope.source_service,
      score_delta: scoring.score_delta,
    });

    return {
      duplicate: false,
      source_event_id: envelope.source_event_id,
      did: envelope.did,
      kind: envelope.kind,
      score_delta: scoring.score_delta,
    };
  }

  if (envelope.kind === 'penalty') {
    const penalty = envelope.penalty!;
    const scoreDelta = computePenaltyScoreDelta(penalty.penalty_type, penalty.severity ?? 1);

    try {
      await db
        .prepare(
          `INSERT INTO rep_events (
            source_event_id, source_service, did, event_type, status, score_delta,
            penalty_type, severity, occurred_at, ingested_at, metadata_json
          ) VALUES (?, ?, ?, 'penalty', 'pending', ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          envelope.source_event_id,
          envelope.source_service,
          envelope.did,
          scoreDelta,
          penalty.penalty_type,
          Math.floor(penalty.severity ?? 1),
          occurredAt,
          ingestedAt,
          JSON.stringify({
            source_service: envelope.source_service,
            reason: penalty.reason ?? null,
            kind: envelope.kind,
            ...(envelope.metadata ?? {}),
          })
        )
        .run();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.toLowerCase().includes('unique') || message.toLowerCase().includes('constraint')) {
        return {
          duplicate: true,
          source_event_id: envelope.source_event_id,
          did: envelope.did,
          kind: envelope.kind,
          score_delta: scoreDelta,
        };
      }
      throw error;
    }

    await appendAudit(db, 'loop.penalty.ingested', envelope.did, envelope.source_event_id, {
      source_service: envelope.source_service,
      penalty_type: penalty.penalty_type,
      severity: penalty.severity ?? 1,
      score_delta: scoreDelta,
    });

    return {
      duplicate: false,
      source_event_id: envelope.source_event_id,
      did: envelope.did,
      kind: envelope.kind,
      score_delta: scoreDelta,
    };
  }

  if (envelope.kind === 'recovery') {
    const recovery = envelope.recovery!;
    const scoreDelta = computeRecoveryScoreDelta(recovery.recovery_type, recovery.severity ?? 1);

    try {
      await db
        .prepare(
          `INSERT INTO rep_events (
            source_event_id, source_service, did, event_type, status, score_delta,
            occurred_at, ingested_at, metadata_json, severity
          ) VALUES (?, ?, ?, 'recovery', 'pending', ?, ?, ?, ?, ?)`
        )
        .bind(
          envelope.source_event_id,
          envelope.source_service,
          envelope.did,
          scoreDelta,
          occurredAt,
          ingestedAt,
          JSON.stringify({
            source_service: envelope.source_service,
            recovery_type: recovery.recovery_type,
            reason: recovery.reason ?? null,
            kind: envelope.kind,
            ...(envelope.metadata ?? {}),
          }),
          Math.floor(recovery.severity ?? 1)
        )
        .run();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.toLowerCase().includes('unique') || message.toLowerCase().includes('constraint')) {
        return {
          duplicate: true,
          source_event_id: envelope.source_event_id,
          did: envelope.did,
          kind: envelope.kind,
          score_delta: scoreDelta,
        };
      }
      throw error;
    }

    await appendAudit(db, 'loop.recovery.ingested', envelope.did, envelope.source_event_id, {
      source_service: envelope.source_service,
      recovery_type: recovery.recovery_type,
      severity: recovery.severity ?? 1,
      score_delta: scoreDelta,
    });

    return {
      duplicate: false,
      source_event_id: envelope.source_event_id,
      did: envelope.did,
      kind: envelope.kind,
      score_delta: scoreDelta,
    };
  }

  throw new Error('INVALID_LOOP_KIND');
}

async function buildReviewerSignals(
  db: D1Database,
  env: Env,
  request: SelectReviewersRequest
): Promise<ReviewerSelectionSignals> {
  const historyDays = parseReviewerHistoryDays(env);
  const cooldownHours = parseReviewerCooldownHours(env);
  const now = Date.now();
  const historyCutoffIso = new Date(now - historyDays * 24 * 60 * 60 * 1000).toISOString();
  const cooldownCutoffMs = now - cooldownHours * 60 * 60 * 1000;

  const rows = await db
    .prepare(
      `SELECT details_json, created_at
       FROM rep_audit_events
       WHERE event_kind = 'reviewers.selected'
         AND created_at >= ?
       ORDER BY audit_id DESC
       LIMIT 500`
    )
    .bind(historyCutoffIso)
    .all<{ details_json: string | null; created_at: string }>();

  const recentSelectionCounts: Record<string, number> = {};
  const pairSelectionCounts: Record<string, number> = {};
  const cooldownBlocked = new Set<string>();

  for (const row of rows.results ?? []) {
    const details = parseAuditDetails(row.details_json);
    if (!details) continue;
    const selectedReviewers = Array.isArray(details.selected_reviewers)
      ? details.selected_reviewers.filter((item): item is string => typeof item === 'string' && item.trim().length > 0).map((item) => item.trim())
      : [];

    if (selectedReviewers.length === 0) continue;

    for (const did of selectedReviewers) {
      recentSelectionCounts[did] = (recentSelectionCounts[did] ?? 0) + 1;
      const createdAtMs = safeDateMs(row.created_at);
      if (createdAtMs !== null && createdAtMs >= cooldownCutoffMs) {
        cooldownBlocked.add(did);
      }
    }

    for (let i = 0; i < selectedReviewers.length; i += 1) {
      const left = selectedReviewers[i];
      if (!left) continue;
      for (let j = i + 1; j < selectedReviewers.length; j += 1) {
        const right = selectedReviewers[j];
        if (!right) continue;
        const key = pairKey(left, right);
        pairSelectionCounts[key] = (pairSelectionCounts[key] ?? 0) + 1;
      }
    }
  }

  return {
    requester_did: request.requester_did,
    worker_did: request.worker_did,
    recent_selection_counts: recentSelectionCounts,
    pair_selection_counts: pairSelectionCounts,
    cooldown_blocked: cooldownBlocked,
    cooldown_hours: cooldownHours,
    history_window_days: historyDays,
  };
}

async function buildDriftReport(
  db: D1Database,
  body: DriftRecomputeBody
): Promise<{
  generated_at: string;
  scope: 'single' | 'all';
  total_profiles_checked: number;
  mismatches: Array<Record<string, unknown>>;
  error_buckets: Record<string, number>;
  repaired: number;
}> {
  const scopeDid = isDidString(body.did) ? body.did.trim() : null;
  const limit = Number.isFinite(Number(body.limit)) ? Math.max(1, Math.min(500, Math.floor(Number(body.limit)))) : 200;
  const applyRepair = Boolean(body.apply_repair);

  const didRows = scopeDid
    ? [{ did: scopeDid }]
    : (
        await db
          .prepare(
            `SELECT did FROM rep_profiles
             UNION
             SELECT did FROM rep_events`
          )
          .all<{ did: string }>()
      ).results ?? [];

  const errorBuckets: {
    PROFILE_MISSING: number;
    SCORE_MISMATCH: number;
    EVENTS_COUNT_MISMATCH: number;
    PENALTIES_COUNT_MISMATCH: number;
    DISPUTE_COUNT_MISMATCH: number;
    OWNER_VERIFIED_MISMATCH: number;
  } = {
    PROFILE_MISSING: 0,
    SCORE_MISMATCH: 0,
    EVENTS_COUNT_MISMATCH: 0,
    PENALTIES_COUNT_MISMATCH: 0,
    DISPUTE_COUNT_MISMATCH: 0,
    OWNER_VERIFIED_MISMATCH: 0,
  };

  const mismatches: Array<Record<string, unknown>> = [];
  let repaired = 0;

  for (const row of didRows) {
    const did = row.did;
    if (!isDidString(did)) continue;

    const profile = await db
      .prepare(
        `SELECT did, reputation_score, events_count, penalties_count, dispute_penalties_count, is_owner_verified, owner_attestation_ref
         FROM rep_profiles
         WHERE did = ?`
      )
      .bind(did)
      .first<{
        did: string;
        reputation_score: number;
        events_count: number;
        penalties_count: number;
        dispute_penalties_count: number;
        is_owner_verified: number;
        owner_attestation_ref: string | null;
      }>();

    const aggregate = await db
      .prepare(
        `SELECT
           COALESCE(SUM(score_delta), 0) AS score,
           COUNT(*) AS events_count,
           SUM(CASE WHEN event_type = 'penalty' THEN 1 ELSE 0 END) AS penalties_count,
           SUM(CASE WHEN penalty_type IN ('dispute_upheld_against_reviewer','dispute_upheld_against_worker') THEN 1 ELSE 0 END) AS dispute_penalties_count,
           MAX(COALESCE(owner_verified, 0)) AS owner_verified
         FROM rep_events
         WHERE did = ? AND status = 'processed'`
      )
      .bind(did)
      .first<{
        score: number;
        events_count: number;
        penalties_count: number;
        dispute_penalties_count: number;
        owner_verified: number;
      }>();

    const expected = {
      reputation_score: Number(aggregate?.score ?? 0),
      events_count: Number(aggregate?.events_count ?? 0),
      penalties_count: Number(aggregate?.penalties_count ?? 0),
      dispute_penalties_count: Number(aggregate?.dispute_penalties_count ?? 0),
      is_owner_verified: Number(aggregate?.owner_verified ?? 0) === 1,
    };

    if (!profile) {
      errorBuckets.PROFILE_MISSING += 1;
      if (mismatches.length < limit) {
        mismatches.push({ did, bucket: 'PROFILE_MISSING', expected });
      }

      if (applyRepair && expected.events_count > 0) {
        const now = nowIso();
        await db
          .prepare(
            `INSERT INTO rep_profiles (
              did, reputation_score, events_count, penalties_count, dispute_penalties_count,
              is_owner_verified, owner_attestation_ref, last_event_at, last_decay_at, updated_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)`
          )
          .bind(
            did,
            expected.reputation_score,
            expected.events_count,
            expected.penalties_count,
            expected.dispute_penalties_count,
            expected.is_owner_verified ? 1 : 0,
            now,
            now
          )
          .run();
        repaired += 1;
      }
      continue;
    }

    const profileChecks = [
      {
        bucket: 'SCORE_MISMATCH',
        ok: Math.abs(Number(profile.reputation_score ?? 0) - expected.reputation_score) < 0.000001,
        current: Number(profile.reputation_score ?? 0),
        expected: expected.reputation_score,
      },
      {
        bucket: 'EVENTS_COUNT_MISMATCH',
        ok: Number(profile.events_count ?? 0) === expected.events_count,
        current: Number(profile.events_count ?? 0),
        expected: expected.events_count,
      },
      {
        bucket: 'PENALTIES_COUNT_MISMATCH',
        ok: Number(profile.penalties_count ?? 0) === expected.penalties_count,
        current: Number(profile.penalties_count ?? 0),
        expected: expected.penalties_count,
      },
      {
        bucket: 'DISPUTE_COUNT_MISMATCH',
        ok: Number(profile.dispute_penalties_count ?? 0) === expected.dispute_penalties_count,
        current: Number(profile.dispute_penalties_count ?? 0),
        expected: expected.dispute_penalties_count,
      },
      {
        bucket: 'OWNER_VERIFIED_MISMATCH',
        ok: (Number(profile.is_owner_verified ?? 0) === 1) === expected.is_owner_verified,
        current: Number(profile.is_owner_verified ?? 0) === 1,
        expected: expected.is_owner_verified,
      },
    ] as const;

    const failedChecks = profileChecks.filter((check) => !check.ok);
    if (failedChecks.length === 0) continue;

    for (const failed of failedChecks) {
      errorBuckets[failed.bucket] = (errorBuckets[failed.bucket] ?? 0) + 1;
      if (mismatches.length < limit) {
        mismatches.push({
          did,
          bucket: failed.bucket,
          current: failed.current,
          expected: failed.expected,
        });
      }
    }

    if (applyRepair) {
      await db
        .prepare(
          `UPDATE rep_profiles
           SET reputation_score = ?,
               events_count = ?,
               penalties_count = ?,
               dispute_penalties_count = ?,
               is_owner_verified = ?,
               updated_at = ?
           WHERE did = ?`
        )
        .bind(
          expected.reputation_score,
          expected.events_count,
          expected.penalties_count,
          expected.dispute_penalties_count,
          expected.is_owner_verified ? 1 : 0,
          nowIso(),
          did
        )
        .run();
      repaired += 1;
    }
  }

  return {
    generated_at: nowIso(),
    scope: scopeDid ? 'single' : 'all',
    total_profiles_checked: didRows.length,
    mismatches,
    error_buckets: errorBuckets,
    repaired,
  };
}

async function persistDriftReport(
  db: D1Database,
  report: {
    generated_at: string;
    scope: 'single' | 'all';
    total_profiles_checked: number;
    mismatches: Array<Record<string, unknown>>;
    error_buckets: Record<string, number>;
    repaired: number;
  }
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO rep_drift_reports (
        scope,
        total_profiles_checked,
        mismatch_count,
        repaired_count,
        report_json,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?)`
    )
    .bind(
      report.scope,
      report.total_profiles_checked,
      report.mismatches.length,
      report.repaired,
      JSON.stringify(report),
      report.generated_at
    )
    .run();
}

async function buildIngestSlo(
  db: D1Database,
  windowHours: number
): Promise<Record<string, unknown>> {
  const boundedWindow = Math.max(1, Math.min(168, Math.floor(windowHours)));
  const cutoffIso = new Date(Date.now() - boundedWindow * 60 * 60 * 1000).toISOString();

  const rows = await db
    .prepare(
      `SELECT source_event_id, status, ingested_at, processed_at, error_code
       FROM rep_events
       WHERE ingested_at >= ?`
    )
    .bind(cutoffIso)
    .all<{
      source_event_id: string;
      status: string;
      ingested_at: string;
      processed_at: string | null;
      error_code: string | null;
    }>();

  const latenciesSeconds: number[] = [];
  let processed = 0;
  let failed = 0;
  let pending = 0;
  const errorBuckets: Record<string, number> = {};

  for (const row of rows.results ?? []) {
    if (row.status === 'processed') {
      processed += 1;
      const ingestedMs = safeDateMs(row.ingested_at);
      const processedMs = safeDateMs(row.processed_at);
      if (ingestedMs !== null && processedMs !== null && processedMs >= ingestedMs) {
        latenciesSeconds.push((processedMs - ingestedMs) / 1000);
      }
    } else if (row.status === 'failed') {
      failed += 1;
      const code = row.error_code ?? 'UNKNOWN_ERROR';
      errorBuckets[code] = (errorBuckets[code] ?? 0) + 1;
    } else {
      pending += 1;
    }
  }

  const total = processed + failed + pending;
  const successRate = total === 0 ? 1 : processed / total;

  return {
    window_hours: boundedWindow,
    total_events: total,
    processed,
    failed,
    pending,
    success_rate: successRate,
    latency_seconds: {
      p50: percentile(latenciesSeconds, 50),
      p95: percentile(latenciesSeconds, 95),
      max: latenciesSeconds.length ? Math.max(...latenciesSeconds) : 0,
    },
    error_buckets: errorBuckets,
  };
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
          '- POST /v1/events/ingest-loop (auth: ingest key)',
          '- GET /v1/rep/:did',
          '- GET /v1/tiers/:did',
          '- POST /v1/reviewers/select',
          '- GET /v1/reviewers/:did',
          '- POST /v1/penalties/apply (auth: admin key)',
          '- POST /v1/decay/run (auth: admin key)',
          '- GET /v1/audit/events (auth: admin key)',
          '- GET /v1/ops/queue/status (auth: admin key)',
          '- POST /v1/ops/queue/replay (auth: admin key)',
          '- GET /v1/ops/slo/ingest (auth: admin key)',
          '- POST /v1/ops/drift/recompute (auth: admin key)',
          '- GET /v1/ops/drift/latest (auth: admin key)',
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

    if (method === 'POST' && url.pathname === '/v1/events/ingest-loop') {
      const authErr = requireIngestAuth(request, env, version);
      if (authErr) return authErr;

      const body = await parseRequestJson(request);
      const parsed = parseIngestLoopEnvelope(body);
      if (!parsed.ok) {
        return errorResponse(
          ISSUES.loopEnvelopeInvalid,
          parsed.message,
          400,
          version,
          parsed.field ? { field: parsed.field } : undefined
        );
      }

      const envelope = parsed.value;

      const existing = await env.REP_DB.prepare(
        `SELECT source_event_id, status, score_delta, event_type, occurred_at
         FROM rep_events
         WHERE source_event_id = ?`
      )
        .bind(envelope.source_event_id)
        .first<{ source_event_id: string; status: string; score_delta: number; event_type: string; occurred_at: string }>();

      if (existing) {
        await appendAudit(env.REP_DB, 'loop.event.duplicate_precheck', envelope.did, envelope.source_event_id, {
          source_service: envelope.source_service,
          kind: envelope.kind,
        });

        return jsonResponse(
          {
            status: 'duplicate',
            duplicate: true,
            source_event_id: envelope.source_event_id,
            event: existing,
          },
          200,
          version
        );
      }

      if (!env.REP_EVENTS) {
        return errorResponse(ISSUES.dependencyNotConfigured, 'REP_EVENTS queue is not configured', 503, version);
      }

      try {
        await env.REP_EVENTS.send(envelope, { contentType: 'json' });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        await appendAudit(env.REP_DB, 'loop.event.enqueue_failed', envelope.did, envelope.source_event_id, {
          source_service: envelope.source_service,
          kind: envelope.kind,
          error: message.slice(0, 500),
        });
        return errorResponse(ISSUES.queueError, `Failed to enqueue ingest-loop event: ${message}`, 503, version);
      }

      await appendAudit(env.REP_DB, 'loop.event.enqueued', envelope.did, envelope.source_event_id, {
        source_service: envelope.source_service,
        kind: envelope.kind,
      });

      return jsonResponse(
        {
          status: 'accepted',
          duplicate: false,
          source_event_id: envelope.source_event_id,
          kind: envelope.kind,
          did: envelope.did,
          source_service: envelope.source_service,
        },
        202,
        version
      );
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

      const signals = await buildReviewerSignals(env.REP_DB, env, input);
      const selection = selectReviewersDeterministicWithSignals(input, candidates, signals);
      const selected = selection.reviewers;

      if (selected.length < input.quorum_size) {
        return errorResponse(
          ISSUES.invalidRequest,
          'Insufficient eligible reviewers for requested quorum size',
          409,
          version,
          {
            requested_quorum_size: input.quorum_size,
            available_reviewers: selected.length,
            exclusion_buckets: selection.metadata.exclusion_buckets,
          }
        );
      }

      const response = {
        bounty_id: input.bounty_id,
        reviewers: selected,
        selected_at: selectedAt,
        selection_metadata: selection.metadata,
      };

      if (env.REP_CACHE && cacheKey) {
        await env.REP_CACHE.put(cacheKey, JSON.stringify(response), {
          expirationTtl: parseReviewerCacheTtl(env),
        });
      }

      await appendAudit(env.REP_DB, 'reviewers.selected', null, null, {
        bounty_id: input.bounty_id,
        quorum_size: input.quorum_size,
        requester_did: input.requester_did ?? null,
        worker_did: input.worker_did ?? null,
        selected_reviewers: selected.map((item) => item.reviewer_did),
        selection_metadata: selection.metadata,
      });

      return jsonResponse(response, 200, version);
    }

    if (method === 'GET' && url.pathname === '/v1/ops/queue/status') {
      const authErr = requireAdmin(request, env, version);
      if (authErr) return authErr;

      const eventCountsRows = await env.REP_DB.prepare(
        `SELECT status, COUNT(*) AS count
         FROM rep_events
         GROUP BY status`
      ).all<{ status: string; count: number }>();

      const counts = {
        pending: 0,
        processing: 0,
        processed: 0,
        failed: 0,
      };
      for (const row of eventCountsRows.results ?? []) {
        if (row.status in counts) {
          counts[row.status as keyof typeof counts] = Number(row.count ?? 0);
        }
      }

      const windowStart = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const recentOpsRows = await env.REP_DB.prepare(
        `SELECT event_kind, COUNT(*) AS count
         FROM rep_audit_events
         WHERE event_kind IN ('queue.ingest_failed', 'queue.replay', 'queue.loop_invalid')
           AND created_at >= ?
         GROUP BY event_kind`
      )
        .bind(windowStart)
        .all<{ event_kind: string; count: number }>();

      const recentOps: Record<string, number> = {
        queue_ingest_failed: 0,
        queue_replay: 0,
        queue_loop_invalid: 0,
      };
      for (const row of recentOpsRows.results ?? []) {
        if (row.event_kind === 'queue.ingest_failed') recentOps.queue_ingest_failed = Number(row.count ?? 0);
        if (row.event_kind === 'queue.replay') recentOps.queue_replay = Number(row.count ?? 0);
        if (row.event_kind === 'queue.loop_invalid') recentOps.queue_loop_invalid = Number(row.count ?? 0);
      }

      return jsonResponse(
        {
          queue_depth: counts.pending + counts.processing + counts.failed,
          event_status_counts: counts,
          recent_24h: recentOps,
        },
        200,
        version
      );
    }

    if (method === 'POST' && url.pathname === '/v1/ops/queue/replay') {
      const authErr = requireAdmin(request, env, version);
      if (authErr) return authErr;

      if (!env.REP_EVENTS) {
        return errorResponse(ISSUES.dependencyNotConfigured, 'REP_EVENTS queue is not configured', 503, version);
      }

      const body = (await parseRequestJson(request)) as QueueReplayBody | null;
      const requestedSourceEventId = isNonEmptyString(body?.source_event_id) ? body!.source_event_id.trim() : null;
      const limit = Number.isFinite(Number(body?.limit)) ? Math.max(1, Math.min(100, Math.floor(Number(body?.limit)))) : 25;

      const rows = await env.REP_DB.prepare(
        `SELECT audit_id, source_event_id, details_json
         FROM rep_audit_events
         WHERE event_kind = 'queue.ingest_failed'
         ORDER BY audit_id DESC
         LIMIT 500`
      ).all<{ audit_id: number; source_event_id: string | null; details_json: string | null }>();

      const replayCandidates = new Map<string, QueueMessageEnvelope>();

      for (const row of rows.results ?? []) {
        const sourceEventId = row.source_event_id?.trim() ?? null;
        if (!sourceEventId) continue;
        if (requestedSourceEventId && sourceEventId !== requestedSourceEventId) continue;
        if (replayCandidates.has(sourceEventId)) continue;

        const details = parseAuditDetails(row.details_json);
        const envelopeRaw = details && isRecord(details.envelope) ? details.envelope : null;
        if (envelopeRaw) {
          const parsedEnvelope = parseQueueEnvelope(envelopeRaw);
          if (parsedEnvelope.ok) {
            replayCandidates.set(sourceEventId, parsedEnvelope.value);
            continue;
          }
        }

        replayCandidates.set(sourceEventId, { source_event_id: sourceEventId });
      }

      const replayed: string[] = [];
      const failures: Array<{ source_event_id: string; error: string }> = [];

      for (const [sourceEventId, envelope] of Array.from(replayCandidates.entries()).slice(0, limit)) {
        try {
          await env.REP_EVENTS.send(envelope, { contentType: 'json' });
          replayed.push(sourceEventId);
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          failures.push({ source_event_id: sourceEventId, error: message.slice(0, 240) });
        }
      }

      await appendAudit(env.REP_DB, 'queue.replay', null, requestedSourceEventId, {
        requested_source_event_id: requestedSourceEventId,
        requested_limit: limit,
        replayed,
        failures,
      });

      const status = failures.length > 0 && replayed.length === 0 ? 500 : 200;
      return jsonResponse(
        {
          status: failures.length === 0 ? 'ok' : replayed.length > 0 ? 'partial' : 'failed',
          replayed_count: replayed.length,
          failure_count: failures.length,
          replayed,
          failures,
        },
        status,
        version
      );
    }

    if (method === 'GET' && url.pathname === '/v1/ops/slo/ingest') {
      const authErr = requireAdmin(request, env, version);
      if (authErr) return authErr;

      const windowHoursRaw = Number(url.searchParams.get('window_hours') ?? '24');
      const report = await buildIngestSlo(env.REP_DB, Number.isFinite(windowHoursRaw) ? windowHoursRaw : 24);
      return jsonResponse(report, 200, version);
    }

    if (method === 'POST' && url.pathname === '/v1/ops/drift/recompute') {
      const authErr = requireAdmin(request, env, version);
      if (authErr) return authErr;

      const bodyRaw = (await parseRequestJson(request)) as DriftRecomputeBody | null;
      if (bodyRaw !== null && bodyRaw !== undefined && !isRecord(bodyRaw)) {
        return errorResponse(ISSUES.invalidRequest, 'Body must be a JSON object', 400, version);
      }

      const report = await buildDriftReport(env.REP_DB, bodyRaw ?? {});
      await persistDriftReport(env.REP_DB, report);
      await appendAudit(env.REP_DB, 'drift.report', isDidString(bodyRaw?.did) ? bodyRaw!.did : null, null, report);
      return jsonResponse(report, 200, version);
    }

    if (method === 'GET' && url.pathname === '/v1/ops/drift/latest') {
      const authErr = requireAdmin(request, env, version);
      if (authErr) return authErr;

      const row = await env.REP_DB.prepare(
        `SELECT report_json, created_at
         FROM rep_drift_reports
         ORDER BY report_id DESC
         LIMIT 1`
      ).first<{ report_json: string; created_at: string }>();

      if (!row) {
        return errorResponse(ISSUES.notFound, 'No drift report available', 404, version);
      }

      let parsed: Record<string, unknown> | null = null;
      try {
        const json = JSON.parse(row.report_json);
        parsed = isRecord(json) ? json : null;
      } catch {
        parsed = null;
      }

      return jsonResponse(
        {
          report: parsed,
          created_at: row.created_at,
        },
        200,
        version
      );
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
      const body = message.body;
      const parsedEnvelope = parseQueueEnvelope(body);

      if (!parsedEnvelope.ok) {
        await appendAudit(env.REP_DB, 'queue.loop_invalid', null, null, {
          body_type: typeof body,
          error: parsedEnvelope.message,
        });
        message.ack();
        continue;
      }

      const envelope = parsedEnvelope.value;
      const sourceEventId = envelope.source_event_id;

      try {
        if ('schema_version' in envelope && envelope.schema_version === '1') {
          const ingest = await processLoopEnvelope(env.REP_DB, envelope);
          if (!ingest.duplicate) {
            await processEventBySourceId(env.REP_DB, sourceEventId, 'queue');
          }

          await appendAudit(env.REP_DB, 'queue.ingest_processed', envelope.did, sourceEventId, {
            source_service: envelope.source_service,
            kind: envelope.kind,
            duplicate: ingest.duplicate,
          });
        } else {
          await processEventBySourceId(env.REP_DB, sourceEventId, 'queue');
        }

        message.ack();
      } catch (error) {
        const messageText = error instanceof Error ? error.message : String(error);
        console.error(`[clawrep] queue processing failed: ${messageText}`);

        await appendAudit(env.REP_DB, 'queue.ingest_failed', null, sourceEventId, {
          attempts: message.attempts,
          error: messageText.slice(0, 500),
          envelope,
        });

        const permanent =
          messageText.includes('INVALID_LOOP_KIND') ||
          messageText.includes('LOOP_ENVELOPE_INVALID') ||
          messageText.includes('INVALID_REQUEST');

        if (permanent) {
          message.ack();
        } else {
          message.retry({ delaySeconds: 30 });
        }
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
      const driftReport = await buildDriftReport(env.REP_DB, { limit: 100, apply_repair: false });
      await persistDriftReport(env.REP_DB, driftReport);
      await appendAudit(env.REP_DB, 'drift.report', null, null, {
        ...driftReport,
        trigger: 'cron',
        run_day: runDay,
      });
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
