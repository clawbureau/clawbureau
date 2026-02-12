interface Env {
  ENVIRONMENT?: string;
  CLAWTRIALS_VERSION?: string;
  CLAWREP_BASE_URL?: string;
  CLAWREP_INGEST_KEY?: string;
  REP_EVENTS?: Queue;

  TRIALS_DB: D1Database;
  TRIALS_ADMIN_KEY?: string;
  TRIALS_JUDGE_POOL?: string;

  ESCROW_BASE_URL?: string;
  TRIALS_ESCROW_KEY?: string;
}

interface HarnessRunRequest {
  schema_version: '1';
  test_harness_id: string;
  submission_id: string;
  bounty_id: string;
  output: Record<string, unknown>;
  proof_bundle_hash: string;
  timeout_ms?: number;
}

interface HarnessRunResponse {
  schema_version: '1';
  test_harness_id: string;
  submission_id: string;
  bounty_id: string;
  passed: boolean;
  total_tests: number;
  passed_tests: number;
  failed_tests: number;
  execution_time_ms: number;
  completed_at: string;
  error?: string;
  test_results: Array<Record<string, unknown>>;
}

interface HarnessDefinition {
  id: string;
  description: string;
  evaluate: (request: HarnessRunRequest) => {
    passed: boolean;
    test_results: Array<Record<string, unknown>>;
    error?: string;
  };
}

type CaseStatus = 'open' | 'appealed' | 'decided';
type DecisionOutcome = 'worker_award' | 'requester_refund';

interface TrialEvidenceBundle {
  proof_bundle_hash_b64u: string;
  receipt_refs: string[];
  artifact_refs: string[];
}

interface TrialDecision {
  idempotency_key: string;
  outcome: DecisionOutcome;
  decided_by: string;
  rationale: string | null;
  decided_at: string;
  round: number;
  reaffirmed: boolean;
}

interface TrialAppeal {
  idempotency_key: string;
  appealed_by: string;
  reason: string;
  appealed_at: string;
}

interface EscrowDecisionResolution {
  escrow_id: string;
  status: 'released' | 'cancelled';
  resolution: {
    case_id: string;
    decision: DecisionOutcome;
    decided_by: string;
    resolved_at: string;
  };
  ledger_refs: {
    worker_transfer?: string | null;
    refund_transfer?: string | null;
    fee_transfers: string[];
    referral_transfers: string[];
  };
}

interface TrialCaseRecord {
  case_id: string;
  create_idempotency_key: string;
  source_system: string;
  source_ref: string;
  submission_id: string;
  escrow_id: string;
  requester_did: string;
  worker_did: string;
  opened_by: string;
  reason: string | null;
  status: CaseStatus;
  decision_round: number;
  judge_did: string;
  judge_assignment_hash_b64u: string;
  evidence: TrialEvidenceBundle;
  decision: TrialDecision | null;
  appeal: TrialAppeal | null;
  resolution: EscrowDecisionResolution | null;
  resolved_outcome: DecisionOutcome | null;
  decision_idempotency_key: string | null;
  appeal_idempotency_key: string | null;
  opened_at: string;
  decided_at: string | null;
  appealed_at: string | null;
  resolved_at: string | null;
  updated_at: string;
}

class TrialsError extends Error {
  code: string;
  status: number;
  details?: Record<string, unknown>;

  constructor(message: string, code: string, status: number, details?: Record<string, unknown>) {
    super(message);
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isDidString(value: unknown): value is string {
  return isNonEmptyString(value) && value.trim().startsWith('did:');
}

type ClawrepLoopEnvelope = {
  schema_version: '1';
  source_event_id: string;
  source_service: 'clawtrials';
  kind: 'penalty' | 'recovery';
  did: string;
  occurred_at: string;
  penalty?: {
    penalty_type:
      | 'dispute_upheld_against_reviewer'
      | 'dispute_upheld_against_worker'
      | 'fraud_confirmed'
      | 'spam_review'
      | 'policy_violation';
    severity?: number;
    reason?: string;
  };
  recovery?: {
    recovery_type: 'appeal_upheld_for_reviewer' | 'appeal_upheld_for_worker';
    severity?: number;
    reason?: string;
  };
  metadata?: Record<string, unknown>;
};

function resolveClawrepBaseUrl(env: Env): string {
  const base = env.CLAWREP_BASE_URL?.trim();
  if (base && base.length > 0) return base;
  return 'https://clawrep.com';
}

async function emitTrialOutcomeToClawrep(env: Env, envelope: ClawrepLoopEnvelope): Promise<void> {
  try {
    if (env.REP_EVENTS) {
      await env.REP_EVENTS.send(envelope, { contentType: 'json' });
      return;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[clawtrials] clawrep queue send failed source_event_id=${envelope.source_event_id}: ${message}`);
  }

  if (!env.CLAWREP_INGEST_KEY || env.CLAWREP_INGEST_KEY.trim().length === 0) return;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(`${resolveClawrepBaseUrl(env)}/v1/events/ingest-loop`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        authorization: `Bearer ${env.CLAWREP_INGEST_KEY}`,
      },
      body: JSON.stringify(envelope),
      signal: controller.signal,
    });

    if (!response.ok && response.status !== 409) {
      const text = await response.text();
      console.error(
        `[clawtrials] clawrep ingest-loop failed status=${response.status} source_event_id=${envelope.source_event_id} body=${text.slice(0, 240)}`
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[clawtrials] clawrep ingest-loop error source_event_id=${envelope.source_event_id}: ${message}`);
  } finally {
    clearTimeout(timeout);
  }
}

function d1String(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function d1Number(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
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
      'x-clawtrials-version': version,
    },
  });
}

function textResponse(text: string, status = 200, version = '0.1.0'): Response {
  return new Response(text, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'x-clawtrials-version': version,
    },
  });
}

function errorResponse(
  code: string,
  message: string,
  status: number,
  version: string,
  details?: Record<string, unknown>
): Response {
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

function fromError(err: unknown, version: string): Response {
  if (err instanceof TrialsError) {
    return errorResponse(err.code, err.message, err.status, version, err.details);
  }

  const message = err instanceof Error ? err.message : String(err);
  return errorResponse('INTERNAL_ERROR', message, 500, version);
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

function parseAdminToken(request: Request): string | null {
  const auth = parseBearerToken(request.headers.get('authorization'));
  if (auth) return auth;

  const header = request.headers.get('x-admin-key');
  if (!header || header.trim().length === 0) return null;
  return header.trim();
}

function requireAdmin(request: Request, env: Env, version: string): Response | null {
  const key = env.TRIALS_ADMIN_KEY?.trim();
  if (!key) {
    return errorResponse('ADMIN_KEY_NOT_CONFIGURED', 'TRIALS_ADMIN_KEY is not configured', 503, version);
  }

  const token = parseAdminToken(request);
  if (!token) {
    return errorResponse('UNAUTHORIZED', 'Missing admin token', 401, version);
  }

  if (token !== key) {
    return errorResponse('UNAUTHORIZED', 'Invalid admin token', 401, version);
  }

  return null;
}

async function parseJsonBody(request: Request): Promise<unknown | null> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function parseIdempotencyKey(input: unknown, fieldName: string): string {
  if (!isNonEmptyString(input)) {
    throw new TrialsError(`${fieldName} is required`, 'INVALID_REQUEST', 400, { field: fieldName });
  }

  const value = input.trim();
  if (value.length > 200) {
    throw new TrialsError(`${fieldName} is too long`, 'INVALID_REQUEST', 400, { field: fieldName, max: 200 });
  }

  return value;
}

function parseDid(input: unknown, fieldName: string): string {
  if (!isNonEmptyString(input) || !input.trim().startsWith('did:')) {
    throw new TrialsError(`${fieldName} must be a DID string`, 'INVALID_REQUEST', 400, { field: fieldName });
  }

  return input.trim();
}

function parseCaseStatus(value: unknown): CaseStatus | null {
  if (value === 'open' || value === 'appealed' || value === 'decided') return value;
  return null;
}

function parseDecisionOutcome(value: unknown): DecisionOutcome | null {
  if (value === 'worker_award' || value === 'requester_refund') return value;
  return null;
}

function parseStringArray(input: unknown, fieldName: string, requireNonEmpty = true): string[] {
  if (!Array.isArray(input)) {
    throw new TrialsError(`${fieldName} must be an array`, 'INVALID_REQUEST', 400, { field: fieldName });
  }

  const out: string[] = [];
  for (const entry of input) {
    if (!isNonEmptyString(entry)) {
      throw new TrialsError(`${fieldName} entries must be non-empty strings`, 'INVALID_REQUEST', 400, { field: fieldName });
    }
    out.push(entry.trim());
  }

  if (requireNonEmpty && out.length === 0) {
    throw new TrialsError(`${fieldName} must be non-empty`, 'INVALID_REQUEST', 400, { field: fieldName });
  }

  return out;
}

function normalizeEvidence(input: unknown): TrialEvidenceBundle {
  if (!isRecord(input)) {
    throw new TrialsError('evidence must be an object', 'INVALID_REQUEST', 400, { field: 'evidence' });
  }

  const proof = input.proof_bundle_hash_b64u;
  if (!isNonEmptyString(proof)) {
    throw new TrialsError('proof_bundle_hash_b64u is required', 'INVALID_REQUEST', 400, {
      field: 'evidence.proof_bundle_hash_b64u',
    });
  }

  return {
    proof_bundle_hash_b64u: proof.trim(),
    receipt_refs: parseStringArray(input.receipt_refs, 'evidence.receipt_refs', true),
    artifact_refs: parseStringArray(input.artifact_refs, 'evidence.artifact_refs', true),
  };
}

function resolveEscrowBaseUrl(env: Env): string {
  const configured = env.ESCROW_BASE_URL?.trim();
  if (configured) return configured.replace(/\/$/, '');
  return 'https://clawescrow.com';
}

function base64ToUrlSafe(base64: string): string {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64FromUrlSafe(base64url: string): string {
  const normalized = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  return normalized + padding;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function b64uEncodeUtf8(value: string): string {
  const bytes = new TextEncoder().encode(value);
  return base64ToUrlSafe(bytesToBase64(bytes));
}

function b64uDecodeUtf8(value: string): string | null {
  try {
    const bytes = base64ToBytes(base64FromUrlSafe(value));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

function b64uFromBytes(bytes: Uint8Array): string {
  return base64ToUrlSafe(bytesToBase64(bytes));
}

function encodeCursor(openedAt: string, caseId: string): string {
  return b64uEncodeUtf8(`${openedAt}::${caseId}`);
}

function decodeCursor(cursor: string | null): { opened_at: string; case_id: string } | null {
  if (!cursor) return null;
  const decoded = b64uDecodeUtf8(cursor.trim());
  if (!decoded) return null;

  const [openedAt, caseId] = decoded.split('::');
  if (!openedAt || !caseId) return null;
  if (!caseId.startsWith('trc_')) return null;

  const parsedDate = new Date(openedAt);
  if (!Number.isFinite(parsedDate.getTime())) return null;

  return {
    opened_at: parsedDate.toISOString(),
    case_id: caseId,
  };
}

function parseJudgePool(raw: string | undefined): string[] {
  if (!raw || raw.trim().length === 0) return [];
  const out = new Set<string>();

  for (const item of raw.split(',')) {
    const did = item.trim();
    if (!did) continue;
    if (!did.startsWith('did:')) {
      throw new TrialsError('TRIALS_JUDGE_POOL contains invalid DID', 'JUDGE_POOL_INVALID', 503, {
        judge_entry: did,
      });
    }
    out.add(did);
  }

  return Array.from(out);
}

async function deterministicJudgeIndex(seed: string, size: number): Promise<{ index: number; hash_b64u: string }> {
  if (size <= 0) {
    throw new TrialsError('judge pool is empty', 'JUDGE_POOL_EMPTY', 503);
  }

  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(seed));
  const bytes = new Uint8Array(digest);

  let acc = 0n;
  for (let i = 0; i < 8; i += 1) {
    acc = (acc << 8n) + BigInt(bytes[i] ?? 0);
  }

  const index = Number(acc % BigInt(size));
  return {
    index,
    hash_b64u: b64uFromBytes(bytes),
  };
}

function parseTrialDecision(input: unknown): TrialDecision | null {
  if (!isRecord(input)) return null;

  const idempotencyKey = d1String(input.idempotency_key);
  const outcome = parseDecisionOutcome(input.outcome);
  const decidedBy = d1String(input.decided_by);
  const rationaleRaw = input.rationale;
  const decidedAt = d1String(input.decided_at);
  const round = d1Number(input.round);
  const reaffirmed = input.reaffirmed;

  if (!idempotencyKey || !outcome || !decidedBy || !decidedAt || round === null || !Number.isInteger(round)) {
    return null;
  }

  if (rationaleRaw !== null && rationaleRaw !== undefined && !isNonEmptyString(rationaleRaw)) {
    return null;
  }

  if (typeof reaffirmed !== 'boolean') return null;

  return {
    idempotency_key: idempotencyKey,
    outcome,
    decided_by: decidedBy,
    rationale: isNonEmptyString(rationaleRaw) ? rationaleRaw.trim() : null,
    decided_at: decidedAt,
    round,
    reaffirmed,
  };
}

function parseTrialAppeal(input: unknown): TrialAppeal | null {
  if (!isRecord(input)) return null;

  const idempotencyKey = d1String(input.idempotency_key);
  const appealedBy = d1String(input.appealed_by);
  const reason = d1String(input.reason);
  const appealedAt = d1String(input.appealed_at);

  if (!idempotencyKey || !appealedBy || !reason || !appealedAt) return null;

  return {
    idempotency_key: idempotencyKey,
    appealed_by: appealedBy,
    reason,
    appealed_at: appealedAt,
  };
}

function parseEscrowResolution(input: unknown): EscrowDecisionResolution | null {
  if (!isRecord(input)) return null;

  const escrowId = d1String(input.escrow_id);
  const statusRaw = input.status;
  const status = statusRaw === 'released' || statusRaw === 'cancelled' ? statusRaw : null;

  const resolutionRaw = input.resolution;
  if (!isRecord(resolutionRaw)) return null;

  const caseId = d1String(resolutionRaw.case_id);
  const decision = parseDecisionOutcome(resolutionRaw.decision);
  const decidedBy = d1String(resolutionRaw.decided_by);
  const resolvedAt = d1String(resolutionRaw.resolved_at);

  const ledgerRefsRaw = input.ledger_refs;
  if (!isRecord(ledgerRefsRaw)) return null;

  const workerTransfer = isNonEmptyString(ledgerRefsRaw.worker_transfer) ? ledgerRefsRaw.worker_transfer.trim() : null;
  const refundTransfer = isNonEmptyString(ledgerRefsRaw.refund_transfer) ? ledgerRefsRaw.refund_transfer.trim() : null;

  const feeTransfers = Array.isArray(ledgerRefsRaw.fee_transfers)
    ? ledgerRefsRaw.fee_transfers.filter((entry): entry is string => typeof entry === 'string').map((entry) => entry.trim())
    : [];

  const referralTransfers = Array.isArray(ledgerRefsRaw.referral_transfers)
    ? ledgerRefsRaw.referral_transfers.filter((entry): entry is string => typeof entry === 'string').map((entry) => entry.trim())
    : [];

  if (!escrowId || !status || !caseId || !decision || !decidedBy || !resolvedAt) return null;

  return {
    escrow_id: escrowId,
    status,
    resolution: {
      case_id: caseId,
      decision,
      decided_by: decidedBy,
      resolved_at: resolvedAt,
    },
    ledger_refs: {
      worker_transfer: workerTransfer,
      refund_transfer: refundTransfer,
      fee_transfers: feeTransfers,
      referral_transfers: referralTransfers,
    },
  };
}

function parseCaseRow(row: Record<string, unknown>): TrialCaseRecord | null {
  const caseId = d1String(row.case_id);
  const createKey = d1String(row.create_idempotency_key);
  const sourceSystem = d1String(row.source_system);
  const sourceRef = d1String(row.source_ref);
  const submissionId = d1String(row.submission_id);
  const escrowId = d1String(row.escrow_id);
  const requesterDid = d1String(row.requester_did);
  const workerDid = d1String(row.worker_did);
  const openedBy = d1String(row.opened_by);
  const reason = d1String(row.reason);
  const status = parseCaseStatus(d1String(row.status));
  const decisionRound = d1Number(row.decision_round);
  const judgeDid = d1String(row.judge_did);
  const assignmentHash = d1String(row.judge_assignment_hash_b64u);

  const evidenceJson = d1String(row.evidence_json);
  const decisionJson = d1String(row.decision_json);
  const appealJson = d1String(row.appeal_json);
  const resolutionJson = d1String(row.resolution_json);

  const resolvedOutcome = parseDecisionOutcome(d1String(row.resolved_outcome));
  const decisionIdempotency = d1String(row.decision_idempotency_key);
  const appealIdempotency = d1String(row.appeal_idempotency_key);

  const openedAt = d1String(row.opened_at);
  const decidedAt = d1String(row.decided_at);
  const appealedAt = d1String(row.appealed_at);
  const resolvedAt = d1String(row.resolved_at);
  const updatedAt = d1String(row.updated_at);

  if (
    !caseId ||
    !createKey ||
    !sourceSystem ||
    !sourceRef ||
    !submissionId ||
    !escrowId ||
    !requesterDid ||
    !workerDid ||
    !openedBy ||
    !status ||
    decisionRound === null ||
    !Number.isInteger(decisionRound) ||
    !judgeDid ||
    !assignmentHash ||
    !evidenceJson ||
    !openedAt ||
    !updatedAt
  ) {
    return null;
  }

  let evidence: TrialEvidenceBundle;
  try {
    evidence = normalizeEvidence(JSON.parse(evidenceJson));
  } catch {
    return null;
  }

  const decision = decisionJson ? parseTrialDecision(safeJsonParse(decisionJson)) : null;
  const appeal = appealJson ? parseTrialAppeal(safeJsonParse(appealJson)) : null;
  const resolution = resolutionJson ? parseEscrowResolution(safeJsonParse(resolutionJson)) : null;

  return {
    case_id: caseId,
    create_idempotency_key: createKey,
    source_system: sourceSystem,
    source_ref: sourceRef,
    submission_id: submissionId,
    escrow_id: escrowId,
    requester_did: requesterDid,
    worker_did: workerDid,
    opened_by: openedBy,
    reason: reason ?? null,
    status,
    decision_round: decisionRound,
    judge_did: judgeDid,
    judge_assignment_hash_b64u: assignmentHash,
    evidence,
    decision,
    appeal,
    resolution,
    resolved_outcome: resolvedOutcome,
    decision_idempotency_key: decisionIdempotency,
    appeal_idempotency_key: appealIdempotency,
    opened_at: openedAt,
    decided_at: decidedAt,
    appealed_at: appealedAt,
    resolved_at: resolvedAt,
    updated_at: updatedAt,
  };
}

function safeJsonParse(input: string): unknown {
  try {
    return JSON.parse(input);
  } catch {
    return null;
  }
}

function caseResponsePayload(record: TrialCaseRecord): Record<string, unknown> {
  return {
    case_id: record.case_id,
    status: record.status,
    decision_round: record.decision_round,
    source: {
      system: record.source_system,
      ref: record.source_ref,
      submission_id: record.submission_id,
    },
    escrow_id: record.escrow_id,
    parties: {
      requester_did: record.requester_did,
      worker_did: record.worker_did,
      opened_by: record.opened_by,
    },
    judge: {
      judge_did: record.judge_did,
      assignment_hash_b64u: record.judge_assignment_hash_b64u,
    },
    reason: record.reason,
    evidence: record.evidence,
    decision: record.decision,
    appeal: record.appeal,
    resolution: record.resolution,
    resolved_outcome: record.resolved_outcome,
    timestamps: {
      opened_at: record.opened_at,
      decided_at: record.decided_at,
      appealed_at: record.appealed_at,
      resolved_at: record.resolved_at,
      updated_at: record.updated_at,
    },
  };
}

async function getCaseById(db: D1Database, caseId: string): Promise<TrialCaseRecord | null> {
  const row = await db.prepare('SELECT * FROM trial_cases WHERE case_id = ?').bind(caseId).first();
  if (!row || !isRecord(row)) return null;
  return parseCaseRow(row);
}

async function getCaseByCreateKey(db: D1Database, createKey: string): Promise<TrialCaseRecord | null> {
  const row = await db
    .prepare('SELECT * FROM trial_cases WHERE create_idempotency_key = ?')
    .bind(createKey)
    .first();

  if (!row || !isRecord(row)) return null;
  return parseCaseRow(row);
}

async function listCases(
  db: D1Database,
  params: {
    status?: CaseStatus;
    escrow_id?: string;
    requester_did?: string;
    worker_did?: string;
    judge_did?: string;
    source_system?: string;
    source_ref?: string;
    limit: number;
    cursor?: { opened_at: string; case_id: string };
  }
): Promise<{ cases: TrialCaseRecord[]; next_cursor?: string }> {
  const where: string[] = [];
  const binds: unknown[] = [];

  if (params.status) {
    where.push('status = ?');
    binds.push(params.status);
  }

  if (params.escrow_id) {
    where.push('escrow_id = ?');
    binds.push(params.escrow_id);
  }

  if (params.requester_did) {
    where.push('requester_did = ?');
    binds.push(params.requester_did);
  }

  if (params.worker_did) {
    where.push('worker_did = ?');
    binds.push(params.worker_did);
  }

  if (params.judge_did) {
    where.push('judge_did = ?');
    binds.push(params.judge_did);
  }

  if (params.source_system) {
    where.push('source_system = ?');
    binds.push(params.source_system);
  }

  if (params.source_ref) {
    where.push('source_ref = ?');
    binds.push(params.source_ref);
  }

  if (params.cursor) {
    where.push('(opened_at > ? OR (opened_at = ? AND case_id > ?))');
    binds.push(params.cursor.opened_at, params.cursor.opened_at, params.cursor.case_id);
  }

  const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

  const rows = await db
    .prepare(
      `SELECT *
         FROM trial_cases
         ${whereClause}
         ORDER BY opened_at ASC, case_id ASC
         LIMIT ?`
    )
    .bind(...binds, params.limit + 1)
    .all<Record<string, unknown>>();

  const parsed: TrialCaseRecord[] = [];
  for (const row of rows.results ?? []) {
    if (!isRecord(row)) continue;
    const parsedRow = parseCaseRow(row);
    if (parsedRow) parsed.push(parsedRow);
  }

  let nextCursor: string | undefined;
  if (parsed.length > params.limit) {
    const tail = parsed[params.limit - 1];
    if (tail) {
      nextCursor = encodeCursor(tail.opened_at, tail.case_id);
    }
  }

  return {
    cases: parsed.slice(0, params.limit),
    next_cursor: nextCursor,
  };
}

async function createCase(
  db: D1Database,
  params: {
    create_idempotency_key: string;
    source_system: string;
    source_ref: string;
    submission_id: string;
    escrow_id: string;
    requester_did: string;
    worker_did: string;
    opened_by: string;
    reason: string | null;
    evidence: TrialEvidenceBundle;
    judge_did: string;
    judge_assignment_hash_b64u: string;
  }
): Promise<{ case_record: TrialCaseRecord; idempotent_replay: boolean }> {
  const existing = await getCaseByCreateKey(db, params.create_idempotency_key);
  if (existing) {
    return {
      case_record: existing,
      idempotent_replay: true,
    };
  }

  const caseId = `trc_${crypto.randomUUID()}`;
  const openedAt = nowIso();

  await db
    .prepare(
      `INSERT INTO trial_cases (
          case_id,
          create_idempotency_key,
          source_system,
          source_ref,
          submission_id,
          escrow_id,
          requester_did,
          worker_did,
          opened_by,
          reason,
          status,
          decision_round,
          judge_did,
          judge_assignment_hash_b64u,
          evidence_json,
          decision_json,
          appeal_json,
          resolution_json,
          resolved_outcome,
          decision_idempotency_key,
          appeal_idempotency_key,
          opened_at,
          decided_at,
          appealed_at,
          resolved_at,
          updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 0, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, ?, NULL, NULL, NULL, ?)`
    )
    .bind(
      caseId,
      params.create_idempotency_key,
      params.source_system,
      params.source_ref,
      params.submission_id,
      params.escrow_id,
      params.requester_did,
      params.worker_did,
      params.opened_by,
      params.reason,
      params.judge_did,
      params.judge_assignment_hash_b64u,
      JSON.stringify(params.evidence),
      openedAt,
      openedAt
    )
    .run();

  const created = await getCaseById(db, caseId);
  if (!created) {
    throw new TrialsError('Failed to load created case', 'DB_WRITE_FAILED', 500, {
      case_id: caseId,
    });
  }

  return {
    case_record: created,
    idempotent_replay: false,
  };
}

async function resolveEscrowDecision(
  env: Env,
  params: {
    escrow_id: string;
    case_id: string;
    decision: DecisionOutcome;
    decided_by: string;
    rationale: string | null;
    idempotency_key: string;
  }
): Promise<EscrowDecisionResolution> {
  const key = env.TRIALS_ESCROW_KEY?.trim();
  if (!key) {
    throw new TrialsError('TRIALS_ESCROW_KEY is not configured', 'ESCROW_KEY_NOT_CONFIGURED', 503);
  }

  const url = `${resolveEscrowBaseUrl(env)}/v1/escrows/${encodeURIComponent(params.escrow_id)}/resolve`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${key}`,
        'content-type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify({
        idempotency_key: params.idempotency_key,
        case_id: params.case_id,
        decision: params.decision,
        decided_by: params.decided_by,
        reason: params.rationale ?? undefined,
      }),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new TrialsError('Escrow resolve request failed', 'ESCROW_REQUEST_FAILED', 503, {
      message,
      url,
    });
  }

  const text = await response.text();
  let parsed: unknown = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }

  if (!response.ok) {
    const details = isRecord(parsed) ? parsed : { raw: text };
    const code = isNonEmptyString(details.error) ? details.error.trim() : 'ESCROW_DECISION_FAILED';
    const message = isNonEmptyString(details.message) ? details.message.trim() : 'Escrow decision enforcement failed';
    throw new TrialsError(message, code, response.status, {
      escrow_id: params.escrow_id,
      case_id: params.case_id,
    });
  }

  const resolution = parseEscrowResolution(parsed);
  if (!resolution) {
    throw new TrialsError('Escrow returned invalid resolution payload', 'ESCROW_INVALID_RESPONSE', 502, {
      escrow_id: params.escrow_id,
      case_id: params.case_id,
    });
  }

  return resolution;
}

async function computeDisputeMetrics(
  db: D1Database,
  params: { from: string; to: string }
): Promise<Record<string, unknown>> {
  const rows = await db
    .prepare(
      `SELECT status, resolved_outcome, opened_at, resolved_at
         FROM trial_cases
        WHERE opened_at >= ?
          AND opened_at < ?
        ORDER BY opened_at DESC
        LIMIT 10000`
    )
    .bind(params.from, params.to)
    .all<Record<string, unknown>>();

  let total = 0;
  let open = 0;
  let appealed = 0;
  let decided = 0;

  let workerAward = 0;
  let requesterRefund = 0;

  const resolutionDurations: number[] = [];

  for (const row of rows.results ?? []) {
    if (!isRecord(row)) continue;

    const status = parseCaseStatus(d1String(row.status));
    if (!status) continue;

    total += 1;

    if (status === 'open') open += 1;
    if (status === 'appealed') appealed += 1;
    if (status === 'decided') decided += 1;

    const outcome = parseDecisionOutcome(d1String(row.resolved_outcome));
    if (outcome === 'worker_award') workerAward += 1;
    if (outcome === 'requester_refund') requesterRefund += 1;

    const openedAt = d1String(row.opened_at);
    const resolvedAt = d1String(row.resolved_at);
    if (!openedAt || !resolvedAt) continue;

    const openedMs = Date.parse(openedAt);
    const resolvedMs = Date.parse(resolvedAt);
    if (!Number.isFinite(openedMs) || !Number.isFinite(resolvedMs) || resolvedMs < openedMs) continue;

    resolutionDurations.push(resolvedMs - openedMs);
  }

  resolutionDurations.sort((a, b) => a - b);
  const avgResolutionMs =
    resolutionDurations.length > 0
      ? Math.round(resolutionDurations.reduce((sum, item) => sum + item, 0) / resolutionDurations.length)
      : 0;

  const p95ResolutionMs =
    resolutionDurations.length > 0
      ? resolutionDurations[Math.max(0, Math.ceil(resolutionDurations.length * 0.95) - 1)]
      : 0;

  return {
    window: {
      from: params.from,
      to: params.to,
    },
    totals: {
      total_cases: total,
      open_cases: open,
      appealed_cases: appealed,
      decided_cases: decided,
    },
    outcomes: {
      worker_award: workerAward,
      requester_refund: requesterRefund,
    },
    resolution_time: {
      samples: resolutionDurations.length,
      avg_ms: avgResolutionMs,
      p95_ms: p95ResolutionMs,
    },
  };
}

function monthStartIso(date = new Date()): string {
  const y = date.getUTCFullYear();
  const m = date.getUTCMonth();
  return new Date(Date.UTC(y, m, 1, 0, 0, 0, 0)).toISOString();
}

function addDaysIso(input: string, days: number): string {
  const base = new Date(input);
  return new Date(base.getTime() + days * 24 * 60 * 60 * 1000).toISOString();
}

async function handleCreateCase(request: Request, env: Env, version: string): Promise<Response> {
  if (!env.TRIALS_DB) {
    return errorResponse('TRIALS_DB_NOT_CONFIGURED', 'TRIALS_DB binding is missing', 503, version);
  }

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Body must be a JSON object', 400, version);
  }

  try {
    const createIdempotencyKey = parseIdempotencyKey(body.idempotency_key, 'idempotency_key');

    const sourceSystem = isNonEmptyString(body.source_system) ? body.source_system.trim() : '';
    const sourceRef = isNonEmptyString(body.source_ref) ? body.source_ref.trim() : '';
    const submissionId = isNonEmptyString(body.submission_id) ? body.submission_id.trim() : '';

    if (!sourceSystem) {
      throw new TrialsError('source_system is required', 'INVALID_REQUEST', 400, { field: 'source_system' });
    }

    if (!sourceRef) {
      throw new TrialsError('source_ref is required', 'INVALID_REQUEST', 400, { field: 'source_ref' });
    }

    if (!submissionId) {
      throw new TrialsError('submission_id is required', 'INVALID_REQUEST', 400, { field: 'submission_id' });
    }

    const escrowId = isNonEmptyString(body.escrow_id) ? body.escrow_id.trim() : '';
    if (!escrowId.startsWith('esc_')) {
      throw new TrialsError('escrow_id must be an escrow id', 'INVALID_REQUEST', 400, {
        field: 'escrow_id',
      });
    }

    const requesterDid = parseDid(body.requester_did, 'requester_did');
    const workerDid = parseDid(body.worker_did, 'worker_did');
    const openedBy = parseDid(body.opened_by, 'opened_by');

    const reasonRaw = body.reason;
    if (reasonRaw !== undefined && reasonRaw !== null && !isNonEmptyString(reasonRaw)) {
      throw new TrialsError('reason must be a non-empty string', 'INVALID_REQUEST', 400, {
        field: 'reason',
      });
    }

    const reason = isNonEmptyString(reasonRaw) ? reasonRaw.trim() : null;
    const evidence = normalizeEvidence(body.evidence);

    const judges = parseJudgePool(env.TRIALS_JUDGE_POOL);
    if (judges.length === 0) {
      throw new TrialsError('TRIALS_JUDGE_POOL is empty', 'JUDGE_POOL_EMPTY', 503);
    }

    const seed = `${sourceSystem}|${sourceRef}|${submissionId}|${escrowId}|${evidence.proof_bundle_hash_b64u}`;
    const judgeAssignment = await deterministicJudgeIndex(seed, judges.length);

    const created = await createCase(env.TRIALS_DB, {
      create_idempotency_key: createIdempotencyKey,
      source_system: sourceSystem,
      source_ref: sourceRef,
      submission_id: submissionId,
      escrow_id: escrowId,
      requester_did: requesterDid,
      worker_did: workerDid,
      opened_by: openedBy,
      reason,
      evidence,
      judge_did: judges[judgeAssignment.index] as string,
      judge_assignment_hash_b64u: judgeAssignment.hash_b64u,
    });

    return jsonResponse(
      {
        status: created.idempotent_replay ? 'idempotent_replay' : 'created',
        case: caseResponsePayload(created.case_record),
      },
      created.idempotent_replay ? 200 : 201,
      version
    );
  } catch (err) {
    return fromError(err, version);
  }
}

async function handleGetCase(caseId: string, env: Env, version: string): Promise<Response> {
  if (!env.TRIALS_DB) {
    return errorResponse('TRIALS_DB_NOT_CONFIGURED', 'TRIALS_DB binding is missing', 503, version);
  }

  const record = await getCaseById(env.TRIALS_DB, caseId);
  if (!record) {
    return errorResponse('NOT_FOUND', 'Case not found', 404, version, { case_id: caseId });
  }

  return jsonResponse({ case: caseResponsePayload(record) }, 200, version);
}

async function handleListCases(url: URL, env: Env, version: string): Promise<Response> {
  if (!env.TRIALS_DB) {
    return errorResponse('TRIALS_DB_NOT_CONFIGURED', 'TRIALS_DB binding is missing', 503, version);
  }

  const statusRaw = url.searchParams.get('status');
  const status = parseCaseStatus(statusRaw);
  if (statusRaw && !status) {
    return errorResponse('INVALID_REQUEST', 'status must be open|appealed|decided', 400, version);
  }

  const escrowId = url.searchParams.get('escrow_id')?.trim() ?? undefined;
  if (escrowId && !escrowId.startsWith('esc_')) {
    return errorResponse('INVALID_REQUEST', 'escrow_id must be an escrow id', 400, version);
  }

  const requesterDid = url.searchParams.get('requester_did')?.trim() ?? undefined;
  if (requesterDid && !requesterDid.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'requester_did must be a DID string', 400, version);
  }

  const workerDid = url.searchParams.get('worker_did')?.trim() ?? undefined;
  if (workerDid && !workerDid.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID string', 400, version);
  }

  const judgeDid = url.searchParams.get('judge_did')?.trim() ?? undefined;
  if (judgeDid && !judgeDid.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'judge_did must be a DID string', 400, version);
  }

  const sourceSystem = url.searchParams.get('source_system')?.trim() ?? undefined;
  const sourceRef = url.searchParams.get('source_ref')?.trim() ?? undefined;

  const limitRaw = url.searchParams.get('limit') ?? '50';
  const limit = Number.parseInt(limitRaw, 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > 200) {
    return errorResponse('INVALID_REQUEST', 'limit must be between 1 and 200', 400, version);
  }

  const cursorRaw = url.searchParams.get('cursor');
  const cursor = decodeCursor(cursorRaw);
  if (cursorRaw && !cursor) {
    return errorResponse('INVALID_REQUEST', 'cursor is invalid', 400, version);
  }

  const result = await listCases(env.TRIALS_DB, {
    status: status ?? undefined,
    escrow_id: escrowId,
    requester_did: requesterDid,
    worker_did: workerDid,
    judge_did: judgeDid,
    source_system: sourceSystem,
    source_ref: sourceRef,
    limit,
    cursor: cursor ?? undefined,
  });

  return jsonResponse(
    {
      cases: result.cases.map((record) => caseResponsePayload(record)),
      next_cursor: result.next_cursor ?? null,
    },
    200,
    version
  );
}

async function handleDecideCase(caseId: string, request: Request, env: Env, version: string): Promise<Response> {
  if (!env.TRIALS_DB) {
    return errorResponse('TRIALS_DB_NOT_CONFIGURED', 'TRIALS_DB binding is missing', 503, version);
  }

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Body must be a JSON object', 400, version);
  }

  try {
    const decisionIdempotencyKey = parseIdempotencyKey(body.idempotency_key, 'idempotency_key');
    const outcome = parseDecisionOutcome(body.outcome);
    if (!outcome) {
      throw new TrialsError('outcome must be worker_award|requester_refund', 'INVALID_REQUEST', 400, {
        field: 'outcome',
      });
    }

    const decidedBy = parseDid(body.decided_by, 'decided_by');

    const rationaleRaw = body.rationale;
    if (rationaleRaw !== undefined && rationaleRaw !== null && !isNonEmptyString(rationaleRaw)) {
      throw new TrialsError('rationale must be a non-empty string when provided', 'INVALID_REQUEST', 400, {
        field: 'rationale',
      });
    }
    const rationale = isNonEmptyString(rationaleRaw) ? rationaleRaw.trim() : null;

    const existing = await getCaseById(env.TRIALS_DB, caseId);
    if (!existing) {
      throw new TrialsError('Case not found', 'NOT_FOUND', 404, { case_id: caseId });
    }

    if (existing.status === 'decided') {
      if (existing.decision_idempotency_key === decisionIdempotencyKey) {
        return jsonResponse({ status: 'idempotent_replay', case: caseResponsePayload(existing) }, 200, version);
      }

      throw new TrialsError('Case is already decided', 'CASE_ALREADY_DECIDED', 409, {
        case_id: caseId,
      });
    }

    const now = nowIso();
    const nextRound = existing.decision_round + 1;

    let resolutionPayload = existing.resolution;
    let reaffirmed = false;

    if (existing.status === 'appealed') {
      const resolvedOutcome = existing.resolved_outcome;
      if (!resolvedOutcome) {
        throw new TrialsError('Appealed case is missing resolved outcome', 'INVALID_STATE', 409, {
          case_id: caseId,
        });
      }

      if (resolvedOutcome !== outcome) {
        throw new TrialsError(
          'Appeal cannot change already-settled payout outcome',
          'OUTCOME_CHANGE_FORBIDDEN',
          409,
          {
            case_id: caseId,
            resolved_outcome: resolvedOutcome,
            requested_outcome: outcome,
          }
        );
      }

      reaffirmed = true;
    } else {
      resolutionPayload = await resolveEscrowDecision(env, {
        escrow_id: existing.escrow_id,
        case_id: existing.case_id,
        decision: outcome,
        decided_by: decidedBy,
        rationale,
        idempotency_key: `trial:decision:${existing.case_id}:${decisionIdempotencyKey}`,
      });
    }

    const decision: TrialDecision = {
      idempotency_key: decisionIdempotencyKey,
      outcome,
      decided_by: decidedBy,
      rationale,
      decided_at: now,
      round: nextRound,
      reaffirmed,
    };

    const updateResult = await env.TRIALS_DB
      .prepare(
        `UPDATE trial_cases
            SET status = 'decided',
                decision_round = ?,
                decision_idempotency_key = ?,
                decision_json = ?,
                resolved_outcome = COALESCE(resolved_outcome, ?),
                resolution_json = COALESCE(resolution_json, ?),
                decided_at = ?,
                resolved_at = COALESCE(resolved_at, ?),
                updated_at = ?
          WHERE case_id = ?
            AND status = ?`
      )
      .bind(
        nextRound,
        decisionIdempotencyKey,
        JSON.stringify(decision),
        outcome,
        resolutionPayload ? JSON.stringify(resolutionPayload) : null,
        now,
        resolutionPayload?.resolution.resolved_at ?? now,
        now,
        existing.case_id,
        existing.status
      )
      .run();

    if (!updateResult.success || !updateResult.meta || updateResult.meta.changes === 0) {
      const refreshed = await getCaseById(env.TRIALS_DB, caseId);
      if (!refreshed) {
        throw new TrialsError('Case not found after update attempt', 'NOT_FOUND', 404, {
          case_id: caseId,
        });
      }

      if (refreshed.status === 'decided' && refreshed.decision_idempotency_key === decisionIdempotencyKey) {
        return jsonResponse({ status: 'idempotent_replay', case: caseResponsePayload(refreshed) }, 200, version);
      }

      throw new TrialsError('Case decision update conflicted', 'STATE_TRANSITION_CONFLICT', 409, {
        case_id: caseId,
      });
    }

    const decided = await getCaseById(env.TRIALS_DB, caseId);
    if (!decided) {
      throw new TrialsError('Case missing after decision update', 'DB_WRITE_FAILED', 500, {
        case_id: caseId,
      });
    }

    return jsonResponse(
      {
        status: reaffirmed ? 'appeal_decision_reaffirmed' : 'decided',
        case: caseResponsePayload(decided),
      },
      200,
      version
    );
  } catch (err) {
    return fromError(err, version);
  }
}

async function handleAppealCase(caseId: string, request: Request, env: Env, version: string): Promise<Response> {
  if (!env.TRIALS_DB) {
    return errorResponse('TRIALS_DB_NOT_CONFIGURED', 'TRIALS_DB binding is missing', 503, version);
  }

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    return errorResponse('INVALID_REQUEST', 'Body must be a JSON object', 400, version);
  }

  try {
    const appealIdempotencyKey = parseIdempotencyKey(body.idempotency_key, 'idempotency_key');
    const appealedBy = parseDid(body.appealed_by, 'appealed_by');

    const reasonRaw = body.reason;
    if (!isNonEmptyString(reasonRaw)) {
      throw new TrialsError('reason is required', 'INVALID_REQUEST', 400, {
        field: 'reason',
      });
    }

    const reason = reasonRaw.trim();

    const existing = await getCaseById(env.TRIALS_DB, caseId);
    if (!existing) {
      throw new TrialsError('Case not found', 'NOT_FOUND', 404, { case_id: caseId });
    }

    if (existing.status === 'appealed') {
      if (existing.appeal_idempotency_key === appealIdempotencyKey) {
        return jsonResponse({ status: 'idempotent_replay', case: caseResponsePayload(existing) }, 200, version);
      }

      throw new TrialsError('Case is already appealed', 'CASE_ALREADY_APPEALED', 409, {
        case_id: caseId,
      });
    }

    if (existing.status !== 'decided') {
      throw new TrialsError('Appeal requires decided case', 'INVALID_STATUS', 409, {
        case_id: caseId,
        status: existing.status,
      });
    }

    const appeal: TrialAppeal = {
      idempotency_key: appealIdempotencyKey,
      appealed_by: appealedBy,
      reason,
      appealed_at: nowIso(),
    };

    const update = await env.TRIALS_DB
      .prepare(
        `UPDATE trial_cases
            SET status = 'appealed',
                appeal_idempotency_key = COALESCE(appeal_idempotency_key, ?),
                appeal_json = COALESCE(appeal_json, ?),
                appealed_at = COALESCE(appealed_at, ?),
                decision_idempotency_key = NULL,
                updated_at = ?
          WHERE case_id = ?
            AND status = 'decided'`
      )
      .bind(
        appeal.idempotency_key,
        JSON.stringify(appeal),
        appeal.appealed_at,
        appeal.appealed_at,
        existing.case_id
      )
      .run();

    if (!update.success || !update.meta || update.meta.changes === 0) {
      const refreshed = await getCaseById(env.TRIALS_DB, caseId);
      if (!refreshed) {
        throw new TrialsError('Case not found after appeal update', 'NOT_FOUND', 404, {
          case_id: caseId,
        });
      }

      if (refreshed.status === 'appealed' && refreshed.appeal_idempotency_key === appealIdempotencyKey) {
        return jsonResponse({ status: 'idempotent_replay', case: caseResponsePayload(refreshed) }, 200, version);
      }

      throw new TrialsError('Appeal transition conflicted', 'STATE_TRANSITION_CONFLICT', 409, {
        case_id: caseId,
      });
    }

    const appealed = await getCaseById(env.TRIALS_DB, caseId);
    if (!appealed) {
      throw new TrialsError('Case missing after appeal update', 'DB_WRITE_FAILED', 500, {
        case_id: caseId,
      });
    }

    return jsonResponse({ status: 'appealed', case: caseResponsePayload(appealed) }, 200, version);
  } catch (err) {
    return fromError(err, version);
  }
}

async function handleDisputeMetrics(url: URL, env: Env, version: string): Promise<Response> {
  if (!env.TRIALS_DB) {
    return errorResponse('TRIALS_DB_NOT_CONFIGURED', 'TRIALS_DB binding is missing', 503, version);
  }

  const fromRaw = url.searchParams.get('from');
  const toRaw = url.searchParams.get('to');

  const from = fromRaw?.trim() || monthStartIso();
  const to = toRaw?.trim() || addDaysIso(from, 31);

  const fromDate = new Date(from);
  const toDate = new Date(to);

  if (!Number.isFinite(fromDate.getTime()) || !Number.isFinite(toDate.getTime()) || toDate <= fromDate) {
    return errorResponse('INVALID_REQUEST', 'from/to must be valid ISO datetimes with to > from', 400, version);
  }

  const metrics = await computeDisputeMetrics(env.TRIALS_DB, {
    from: fromDate.toISOString(),
    to: toDate.toISOString(),
  });

  return jsonResponse(
    {
      report: 'dispute_metrics',
      generated_at: nowIso(),
      ...metrics,
    },
    200,
    version
  );
}

function deterministicInt(seed: string, min: number, max: number): number {
  let acc = 0;
  for (let i = 0; i < seed.length; i += 1) {
    acc = (acc + seed.charCodeAt(i) * (i + 17)) % 1_000_000_007;
  }
  const span = Math.max(1, max - min + 1);
  return min + (acc % span);
}

function summarizeOutput(output: Record<string, unknown>): string {
  const raw = output.result_summary;
  if (!isNonEmptyString(raw)) return '';
  return raw.trim().toLowerCase();
}

const HARNESSES: HarnessDefinition[] = [
  {
    id: 'th_smoke_pass_v1',
    description: 'Always passes with deterministic smoke assertions',
    evaluate: (request) => ({
      passed: true,
      test_results: [
        {
          name: 'proof_bundle_hash_present',
          status: 'passed',
          details: { proof_bundle_hash: request.proof_bundle_hash },
        },
        {
          name: 'submission_id_format',
          status: request.submission_id.startsWith('sub_') ? 'passed' : 'failed',
        },
        {
          name: 'output_payload_present',
          status: Object.keys(request.output).length > 0 ? 'passed' : 'failed',
        },
      ],
    }),
  },
  {
    id: 'th_smoke_fail_v1',
    description: 'Always fails with deterministic rejection for negative-path testing',
    evaluate: () => ({
      passed: false,
      test_results: [
        {
          name: 'intentional_failure',
          status: 'failed',
          reason: 'Harness configured for deterministic fail-path tests',
        },
      ],
    }),
  },
  {
    id: 'th_policy_summary_v1',
    description: 'Pass/fail derived deterministically from output.result_summary markers',
    evaluate: (request) => {
      const summary = summarizeOutput(request.output);

      if (summary.includes('[force_harness_error]')) {
        return {
          passed: false,
          error: 'HARNESS_RULE_ERROR:force_harness_error',
          test_results: [
            {
              name: 'policy_summary_markers',
              status: 'failed',
              reason: 'force_harness_error marker present',
            },
          ],
        };
      }

      if (summary.includes('[force_fail]')) {
        return {
          passed: false,
          test_results: [
            {
              name: 'policy_summary_markers',
              status: 'failed',
              reason: 'force_fail marker present',
            },
          ],
        };
      }

      if (summary.length === 0) {
        return {
          passed: false,
          test_results: [
            {
              name: 'summary_required',
              status: 'failed',
              reason: 'result_summary must be non-empty',
            },
          ],
        };
      }

      return {
        passed: true,
        test_results: [
          {
            name: 'summary_required',
            status: 'passed',
          },
          {
            name: 'summary_marker_guard',
            status: 'passed',
          },
        ],
      };
    },
  },
];

const HARNESS_MAP = new Map(HARNESSES.map((h) => [h.id, h]));

function validateHarnessRunRequest(body: unknown): { ok: true; request: HarnessRunRequest } | { ok: false; response: Response } {
  if (!isRecord(body)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'Body must be a JSON object' }, 400),
    };
  }

  const schemaVersion = body.schema_version;
  const testHarnessId = body.test_harness_id;
  const submissionId = body.submission_id;
  const bountyId = body.bounty_id;
  const output = body.output;
  const proofBundleHash = body.proof_bundle_hash;
  const timeoutMs = body.timeout_ms;

  if (schemaVersion !== '1') {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'schema_version must be "1"' }, 400),
    };
  }

  if (!isNonEmptyString(testHarnessId)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'test_harness_id is required' }, 400),
    };
  }

  if (!isNonEmptyString(submissionId)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'submission_id is required' }, 400),
    };
  }

  if (!isNonEmptyString(bountyId)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'bounty_id is required' }, 400),
    };
  }

  if (!isRecord(output)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'output must be an object' }, 400),
    };
  }

  if (!isNonEmptyString(proofBundleHash)) {
    return {
      ok: false,
      response: jsonResponse({ error: 'INVALID_REQUEST', message: 'proof_bundle_hash is required' }, 400),
    };
  }

  if (timeoutMs !== undefined && timeoutMs !== null) {
    if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 300_000) {
      return {
        ok: false,
        response: jsonResponse(
          { error: 'INVALID_REQUEST', message: 'timeout_ms must be a number between 1 and 300000' },
          400
        ),
      };
    }
  }

  return {
    ok: true,
    request: {
      schema_version: '1',
      test_harness_id: testHarnessId.trim(),
      submission_id: submissionId.trim(),
      bounty_id: bountyId.trim(),
      output,
      proof_bundle_hash: proofBundleHash.trim(),
      timeout_ms: typeof timeoutMs === 'number' ? timeoutMs : undefined,
    },
  };
}

function buildHarnessResponse(
  request: HarnessRunRequest,
  result: { passed: boolean; test_results: Array<Record<string, unknown>>; error?: string }
): HarnessRunResponse {
  const normalized = result.test_results.map((row, index) => {
    const base = isRecord(row) ? row : {};
    const statusRaw = base.status;
    const status =
      isNonEmptyString(statusRaw) && (statusRaw === 'passed' || statusRaw === 'failed')
        ? statusRaw
        : result.passed
          ? 'passed'
          : 'failed';
    return {
      test_id: `test_${index + 1}`,
      ...base,
      status,
    };
  });

  const failedCount = normalized.filter((row) => row.status === 'failed').length;
  const passedCount = normalized.length - failedCount;
  const executionTime = deterministicInt(`${request.submission_id}:${request.proof_bundle_hash}`, 80, 320);

  return {
    schema_version: '1',
    test_harness_id: request.test_harness_id,
    submission_id: request.submission_id,
    bounty_id: request.bounty_id,
    passed: result.error ? false : result.passed,
    total_tests: normalized.length,
    passed_tests: passedCount,
    failed_tests: failedCount,
    execution_time_ms: executionTime,
    completed_at: new Date().toISOString(),
    ...(result.error ? { error: result.error } : {}),
    test_results: normalized,
  };
}

function docsPage(origin: string): string {
  const harnessRows = HARNESSES.map((h) => `<li><code>${h.id}</code> — ${h.description}</li>`).join('');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawtrials API</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system; max-width: 920px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
      code, pre { background: #f4f4f5; border-radius: 6px; padding: 0.2rem 0.35rem; }
      pre { overflow-x: auto; padding: 0.75rem; }
    </style>
  </head>
  <body>
    <h1>clawtrials</h1>
    <p>Deterministic arbitration + legacy harness lane.</p>

    <h2>Public</h2>
    <ul>
      <li><code>GET ${origin}/health</code></li>
      <li><code>GET ${origin}/v1/harness/catalog</code></li>
      <li><code>POST ${origin}/v1/harness/run</code></li>
    </ul>

    <h2>Admin (Bearer TRIALS_ADMIN_KEY)</h2>
    <ul>
      <li><code>POST ${origin}/v1/trials/cases</code></li>
      <li><code>GET ${origin}/v1/trials/cases</code></li>
      <li><code>GET ${origin}/v1/trials/cases/{case_id}</code></li>
      <li><code>POST ${origin}/v1/trials/cases/{case_id}/decision</code></li>
      <li><code>POST ${origin}/v1/trials/cases/{case_id}/appeal</code></li>
      <li><code>GET ${origin}/v1/trials/reports/disputes</code></li>
    </ul>

    <h2>Harness IDs</h2>
    <ul>${harnessRows}</ul>

    <h2>Create case example</h2>
    <pre>curl -sS -X POST "${origin}/v1/trials/cases" \
  -H "authorization: Bearer &lt;TRIALS_ADMIN_KEY&gt;" \
  -H "content-type: application/json" \
  --data '{
    "idempotency_key":"trial:create:abc",
    "source_system":"clawbounties",
    "source_ref":"bty_123",
    "submission_id":"sub_123",
    "escrow_id":"esc_123",
    "requester_did":"did:key:zRequester",
    "worker_did":"did:key:zWorker",
    "opened_by":"did:key:zRequester",
    "reason":"Requester disputes submission",
    "evidence":{
      "proof_bundle_hash_b64u":"abc123",
      "receipt_refs":["receipt:gateway:1"],
      "artifact_refs":["artifact:submission:sub_123"]
    }
  }'</pre>
  </body>
</html>`;
}

export const __internals = {
  parseJudgePool,
  deterministicJudgeIndex,
  encodeCursor,
  decodeCursor,
  normalizeEvidence,
  parseDecisionOutcome,
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();
    const version = env.CLAWTRIALS_VERSION?.trim() || '0.2.0';

    if (method === 'GET' || method === 'HEAD') {
      if (path === '/' || path === '/docs') {
        return new Response(docsPage(url.origin), {
          status: 200,
          headers: {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
            'x-clawtrials-version': version,
          },
        });
      }

      if (path === '/health') {
        const judgePoolCount = (() => {
          try {
            return parseJudgePool(env.TRIALS_JUDGE_POOL).length;
          } catch {
            return 0;
          }
        })();

        return jsonResponse(
          {
            status: 'ok',
            service: 'clawtrials',
            version,
            environment: env.ENVIRONMENT ?? 'unknown',
            harness_count: HARNESSES.length,
            judge_pool_size: judgePoolCount,
          },
          200,
          version
        );
      }

      if (path === '/v1/harness/catalog') {
        return jsonResponse(
          {
            schema_version: '1',
            harnesses: HARNESSES.map((h) => ({ id: h.id, description: h.description })),
          },
          200,
          version
        );
      }
    }

    if (path === '/v1/harness/run' && method === 'POST') {
      const parsedBody = await parseJsonBody(request);
      const validated = validateHarnessRunRequest(parsedBody);
      if (!validated.ok) return validated.response;

      const runRequest = validated.request;
      const harness = HARNESS_MAP.get(runRequest.test_harness_id);
      if (!harness) {
        const response = buildHarnessResponse(runRequest, {
          passed: false,
          error: `HARNESS_NOT_FOUND:${runRequest.test_harness_id}`,
          test_results: [],
        });
        return jsonResponse(response, 200, version);
      }

      try {
        const result = harness.evaluate(runRequest);
        const response = buildHarnessResponse(runRequest, result);

        const workerDid = isRecord(runRequest.output) ? runRequest.output.worker_did : null;
        if (isDidString(workerDid)) {
          const sourceEventId = `clawtrials:harness:${runRequest.submission_id}:${runRequest.test_harness_id}:${response.passed ? 'pass' : 'fail'}`;
          if (response.passed) {
            await emitTrialOutcomeToClawrep(env, {
              schema_version: '1',
              source_event_id: sourceEventId,
              source_service: 'clawtrials',
              kind: 'recovery',
              did: workerDid.trim(),
              occurred_at: response.completed_at,
              recovery: {
                recovery_type: 'appeal_upheld_for_worker',
                severity: 1,
                reason: 'Trial harness passed',
              },
              metadata: {
                bounty_id: runRequest.bounty_id,
                submission_id: runRequest.submission_id,
                test_harness_id: runRequest.test_harness_id,
                total_tests: response.total_tests,
                failed_tests: response.failed_tests,
              },
            });
          } else {
            await emitTrialOutcomeToClawrep(env, {
              schema_version: '1',
              source_event_id: sourceEventId,
              source_service: 'clawtrials',
              kind: 'penalty',
              did: workerDid.trim(),
              occurred_at: response.completed_at,
              penalty: {
                penalty_type: 'policy_violation',
                severity: 1,
                reason: 'Trial harness failed',
              },
              metadata: {
                bounty_id: runRequest.bounty_id,
                submission_id: runRequest.submission_id,
                test_harness_id: runRequest.test_harness_id,
                total_tests: response.total_tests,
                failed_tests: response.failed_tests,
              },
            });
          }
        }

        return jsonResponse(response, 200, version);
      } catch (err) {
        const reason = err instanceof Error ? err.message : 'Unknown error';
        const response = buildHarnessResponse(runRequest, {
          passed: false,
          error: `HARNESS_EXECUTION_FAILED:${reason}`,
          test_results: [],
        });

        const workerDid = isRecord(runRequest.output) ? runRequest.output.worker_did : null;
        if (isDidString(workerDid)) {
          await emitTrialOutcomeToClawrep(env, {
            schema_version: '1',
            source_event_id: `clawtrials:harness:${runRequest.submission_id}:${runRequest.test_harness_id}:error`,
            source_service: 'clawtrials',
            kind: 'penalty',
            did: workerDid.trim(),
            occurred_at: response.completed_at,
            penalty: {
              penalty_type: 'policy_violation',
              severity: 1,
              reason: 'Trial harness execution failed',
            },
            metadata: {
              bounty_id: runRequest.bounty_id,
              submission_id: runRequest.submission_id,
              test_harness_id: runRequest.test_harness_id,
            },
          });
        }

        return jsonResponse(response, 200, version);
      }
    }

    if (path.startsWith('/v1/trials/')) {
      const adminErr = requireAdmin(request, env, version);
      if (adminErr) return adminErr;

      if (path === '/v1/trials/cases' && method === 'POST') {
        return handleCreateCase(request, env, version);
      }

      if (path === '/v1/trials/cases' && method === 'GET') {
        return handleListCases(url, env, version);
      }

      const caseMatch = path.match(/^\/v1\/trials\/cases\/(trc_[a-f0-9-]+)$/);
      if (caseMatch && method === 'GET') {
        return handleGetCase(caseMatch[1], env, version);
      }

      const decisionMatch = path.match(/^\/v1\/trials\/cases\/(trc_[a-f0-9-]+)\/decision$/);
      if (decisionMatch && method === 'POST') {
        return handleDecideCase(decisionMatch[1], request, env, version);
      }

      const appealMatch = path.match(/^\/v1\/trials\/cases\/(trc_[a-f0-9-]+)\/appeal$/);
      if (appealMatch && method === 'POST') {
        return handleAppealCase(appealMatch[1], request, env, version);
      }

      if (path === '/v1/trials/reports/disputes' && method === 'GET') {
        return handleDisputeMetrics(url, env, version);
      }
    }

    if (path === '/robots.txt') {
      return textResponse('User-agent: *\nAllow: /\n', 200, version);
    }

    return errorResponse('NOT_FOUND', 'Not found', 404, version, { path, method });
  },
};
