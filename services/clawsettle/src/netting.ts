import { ClawSettleError } from './stripe';
import { LedgerPayoutClient } from './payouts';
import type {
  Env,
  NettingEntryRecord,
  NettingEntryStatus,
  NettingReportRow,
  NettingRunExecuteRequest,
  NettingRunExecuteResponse,
  NettingRunRecord,
  NettingRunReport,
  NettingRunStatus,
  NettingRunStatusResponse,
} from './types';

const DEFAULT_NETTING_SOURCE_DOMAIN = 'clawsettle.payouts';
const DEFAULT_NETTING_TARGET_DOMAIN = 'clawsettle.netting';
const DEFAULT_NETTING_LIMIT = 100;
const MAX_NETTING_LIMIT = 500;

interface NettingCandidatePayout {
  payout_id: string;
  connect_account_id: string;
  currency: string;
  amount_minor: string;
  finalized_at: string;
}

interface LedgerClientLike {
  findEventByIdempotencyKey(idempotencyKey: string): Promise<{ id: string; idempotencyKey: string } | null>;
  transferV1(input: {
    idempotencyKey: string;
    currency: 'USD';
    from: { account: string; bucket: 'A' | 'H' | 'B' | 'F' | 'P' };
    to: { account: string; bucket: 'A' | 'H' | 'B' | 'F' | 'P' };
    amountMinor: string;
    metadata?: Record<string, unknown>;
  }): Promise<{ event_id: string; status: 'applied' }>;
}

interface NettingRepositoryLike {
  findRunById(id: string): Promise<NettingRunRecord | null>;
  findRunByIdempotencyKey(idempotencyKey: string): Promise<NettingRunRecord | null>;
  createRun(run: NettingRunRecord): Promise<void>;
  transitionRunStatusIfCurrent(params: {
    runId: string;
    from: NettingRunStatus;
    to: NettingRunStatus;
    updatedAt: string;
  }): Promise<boolean>;
  setRunSummary(params: {
    runId: string;
    candidateCount: number;
    totalAmountMinor: string;
    updatedAt: string;
  }): Promise<void>;
  completeRun(params: {
    runId: string;
    status: NettingRunStatus;
    appliedCount: number;
    failedCount: number;
    reportHash: string;
    updatedAt: string;
    completedAt: string;
    lastErrorCode?: string;
    lastErrorMessage?: string;
  }): Promise<void>;
  setRunError(params: {
    runId: string;
    code: string;
    message: string;
    updatedAt: string;
  }): Promise<void>;
  listEntriesByRun(runId: string): Promise<NettingEntryRecord[]>;
  createEntry(entry: NettingEntryRecord): Promise<void>;
  deleteEntryById(entryId: string): Promise<void>;
  createEntryPayoutMappings(params: {
    runId: string;
    entryId: string;
    payouts: Array<{ payoutId: string; amountMinor: string }>;
    createdAt: string;
  }): Promise<void>;
  transitionEntryStatusIfCurrent(params: {
    entryId: string;
    from: NettingEntryStatus;
    to: NettingEntryStatus;
    updatedAt: string;
  }): Promise<boolean>;
  markEntryApplied(params: {
    entryId: string;
    ledgerEventId: string;
    updatedAt: string;
    appliedAt: string;
  }): Promise<boolean>;
  markEntryFailed(params: {
    entryId: string;
    code: string;
    message: string;
    updatedAt: string;
  }): Promise<boolean>;
  listEligiblePaidPayoutCandidates(params: {
    currency: string;
    selectionBefore: string;
    limit: number;
  }): Promise<NettingCandidatePayout[]>;
}

interface NettingServiceDeps {
  repository?: NettingRepositoryLike;
  ledgerClient?: LedgerClientLike;
  now?: () => string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isSqliteUniqueConstraintError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return message.includes('UNIQUE constraint failed');
}

function parsePositiveIntegerEnv(value: string | undefined, fallback: number, field: string): number {
  if (!value || value.trim().length === 0) {
    return fallback;
  }

  const parsed = Number.parseInt(value.trim(), 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new ClawSettleError('Invalid numeric environment configuration', 'DEPENDENCY_NOT_CONFIGURED', 503, {
      field,
    });
  }

  return parsed;
}

function parsePositiveLimit(value: unknown, fallback: number): number {
  if (typeof value === 'undefined' || value === null) {
    return fallback;
  }

  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new ClawSettleError('limit must be a positive integer', 'INVALID_REQUEST', 400, {
      field: 'limit',
    });
  }

  const parsed = Math.floor(value);
  if (parsed <= 0) {
    throw new ClawSettleError('limit must be a positive integer', 'INVALID_REQUEST', 400, {
      field: 'limit',
    });
  }

  return Math.min(parsed, MAX_NETTING_LIMIT);
}

function parseNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ClawSettleError(`Missing required field: ${field}`, 'INVALID_REQUEST', 400, {
      field,
    });
  }

  return value.trim();
}

function parseCurrency(value: unknown): string {
  const raw = parseNonEmptyString(value, 'currency').toUpperCase();
  if (raw !== 'USD') {
    throw new ClawSettleError('Only USD netting is supported', 'UNSUPPORTED_CURRENCY', 400, {
      currency: raw,
    });
  }

  return raw;
}

function parsePositiveMinorAmount(value: string): bigint {
  if (!/^[0-9]+$/.test(value)) {
    throw new ClawSettleError('amount_minor must be a positive integer string', 'INVALID_REQUEST', 400, {
      field: 'amount_minor',
    });
  }

  const amount = BigInt(value);
  if (amount <= 0n) {
    throw new ClawSettleError('amount_minor must be greater than zero', 'INVALID_REQUEST', 400, {
      field: 'amount_minor',
    });
  }

  return amount;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function stableStringify(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('Non-finite number is not allowed in canonical payloads');
      }
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((x) => stableStringify(x)).join(',')}]`;
      }

      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const parts: string[] = [];

      for (const key of keys) {
        const entry = obj[key];
        if (typeof entry === 'undefined') {
          continue;
        }
        parts.push(`${JSON.stringify(key)}:${stableStringify(entry)}`);
      }

      return `{${parts.join(',')}}`;
    }
    case 'undefined':
      return 'null';
    default:
      throw new Error(`Unsupported type in stable stringify: ${typeof value}`);
  }
}

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return toHex(new Uint8Array(digest));
}

function parseJsonStringArray(value: unknown): string[] {
  if (typeof value !== 'string') {
    return [];
  }

  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) {
      return [];
    }

    return parsed.filter((item): item is string => typeof item === 'string');
  } catch {
    return [];
  }
}

function safeErrorMessage(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err ?? 'Unknown error');
  return message.length > 500 ? message.slice(0, 500) : message;
}

function parseRunStatus(value: unknown): NettingRunStatus {
  switch (value) {
    case 'created':
    case 'running':
    case 'applied':
    case 'failed':
      return value;
    default:
      throw new Error(`Invalid netting run status: ${String(value)}`);
  }
}

function parseEntryStatus(value: unknown): NettingEntryStatus {
  switch (value) {
    case 'pending':
    case 'applying':
    case 'applied':
    case 'failed':
      return value;
    default:
      throw new Error(`Invalid netting entry status: ${String(value)}`);
  }
}

function parseRunRow(row: Record<string, unknown>): NettingRunRecord {
  return {
    id: String(row.id),
    idempotency_key: String(row.idempotency_key),
    request_hash: String(row.request_hash),
    currency: String(row.currency),
    selection_before: String(row.selection_before),
    source_clearing_domain: String(row.source_clearing_domain),
    target_clearing_domain: String(row.target_clearing_domain),
    status: parseRunStatus(row.status),
    candidate_count: Number(row.candidate_count ?? 0),
    applied_count: Number(row.applied_count ?? 0),
    failed_count: Number(row.failed_count ?? 0),
    total_amount_minor: String(row.total_amount_minor ?? '0'),
    last_error_code: typeof row.last_error_code === 'string' ? row.last_error_code : undefined,
    last_error_message:
      typeof row.last_error_message === 'string' ? row.last_error_message : undefined,
    report_hash: typeof row.report_hash === 'string' ? row.report_hash : undefined,
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
    completed_at: typeof row.completed_at === 'string' ? row.completed_at : undefined,
  };
}

function parseEntryRow(row: Record<string, unknown>): NettingEntryRecord {
  return {
    id: String(row.id),
    run_id: String(row.run_id),
    entry_key: String(row.entry_key),
    connect_account_id: String(row.connect_account_id),
    currency: String(row.currency),
    amount_minor: String(row.amount_minor),
    payout_count: Number(row.payout_count ?? 0),
    payout_ids: parseJsonStringArray(row.payout_ids_json),
    idempotency_key: String(row.idempotency_key),
    status: parseEntryStatus(row.status),
    ledger_event_id: typeof row.ledger_event_id === 'string' ? row.ledger_event_id : undefined,
    last_error_code:
      typeof row.last_error_code === 'string' ? row.last_error_code : undefined,
    last_error_message:
      typeof row.last_error_message === 'string' ? row.last_error_message : undefined,
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
    applied_at: typeof row.applied_at === 'string' ? row.applied_at : undefined,
  };
}

function parseCandidateRow(row: Record<string, unknown>): NettingCandidatePayout {
  return {
    payout_id: String(row.id),
    connect_account_id: String(row.connect_account_id),
    currency: String(row.currency),
    amount_minor: String(row.amount_minor),
    finalized_at: String(row.finalized_at),
  };
}

export class NettingRepository implements NettingRepositoryLike {
  constructor(private readonly db: D1Database) {}

  async findRunById(id: string): Promise<NettingRunRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT
           id,
           idempotency_key,
           request_hash,
           currency,
           selection_before,
           source_clearing_domain,
           target_clearing_domain,
           status,
           candidate_count,
           applied_count,
           failed_count,
           total_amount_minor,
           last_error_code,
           last_error_message,
           report_hash,
           created_at,
           updated_at,
           completed_at
         FROM netting_runs
         WHERE id = ?
         LIMIT 1`
      )
      .bind(id)
      .first();

    return row ? parseRunRow(row) : null;
  }

  async findRunByIdempotencyKey(idempotencyKey: string): Promise<NettingRunRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT
           id,
           idempotency_key,
           request_hash,
           currency,
           selection_before,
           source_clearing_domain,
           target_clearing_domain,
           status,
           candidate_count,
           applied_count,
           failed_count,
           total_amount_minor,
           last_error_code,
           last_error_message,
           report_hash,
           created_at,
           updated_at,
           completed_at
         FROM netting_runs
         WHERE idempotency_key = ?
         LIMIT 1`
      )
      .bind(idempotencyKey)
      .first();

    return row ? parseRunRow(row) : null;
  }

  async createRun(run: NettingRunRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO netting_runs (
           id,
           idempotency_key,
           request_hash,
           currency,
           selection_before,
           source_clearing_domain,
           target_clearing_domain,
           status,
           candidate_count,
           applied_count,
           failed_count,
           total_amount_minor,
           last_error_code,
           last_error_message,
           report_hash,
           created_at,
           updated_at,
           completed_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        run.id,
        run.idempotency_key,
        run.request_hash,
        run.currency,
        run.selection_before,
        run.source_clearing_domain,
        run.target_clearing_domain,
        run.status,
        run.candidate_count,
        run.applied_count,
        run.failed_count,
        run.total_amount_minor,
        run.last_error_code ?? null,
        run.last_error_message ?? null,
        run.report_hash ?? null,
        run.created_at,
        run.updated_at,
        run.completed_at ?? null
      )
      .run();
  }

  async transitionRunStatusIfCurrent(params: {
    runId: string;
    from: NettingRunStatus;
    to: NettingRunStatus;
    updatedAt: string;
  }): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE netting_runs
         SET status = ?,
             updated_at = ?
         WHERE id = ?
           AND status = ?`
      )
      .bind(params.to, params.updatedAt, params.runId, params.from)
      .run();

    const changes = Number((result.meta as { changes?: number } | undefined)?.changes ?? 0);
    return changes > 0;
  }

  async setRunSummary(params: {
    runId: string;
    candidateCount: number;
    totalAmountMinor: string;
    updatedAt: string;
  }): Promise<void> {
    await this.db
      .prepare(
        `UPDATE netting_runs
         SET candidate_count = ?,
             total_amount_minor = ?,
             updated_at = ?
         WHERE id = ?`
      )
      .bind(params.candidateCount, params.totalAmountMinor, params.updatedAt, params.runId)
      .run();
  }

  async completeRun(params: {
    runId: string;
    status: NettingRunStatus;
    appliedCount: number;
    failedCount: number;
    reportHash: string;
    updatedAt: string;
    completedAt: string;
    lastErrorCode?: string;
    lastErrorMessage?: string;
  }): Promise<void> {
    await this.db
      .prepare(
        `UPDATE netting_runs
         SET status = ?,
             applied_count = ?,
             failed_count = ?,
             report_hash = ?,
             updated_at = ?,
             completed_at = ?,
             last_error_code = ?,
             last_error_message = ?
         WHERE id = ?`
      )
      .bind(
        params.status,
        params.appliedCount,
        params.failedCount,
        params.reportHash,
        params.updatedAt,
        params.completedAt,
        params.status === 'applied' ? null : params.lastErrorCode ?? 'NETTING_RUN_FAILED',
        params.status === 'applied' ? null : params.lastErrorMessage ?? 'One or more netting entries failed',
        params.runId
      )
      .run();
  }

  async setRunError(params: {
    runId: string;
    code: string;
    message: string;
    updatedAt: string;
  }): Promise<void> {
    await this.db
      .prepare(
        `UPDATE netting_runs
         SET status = 'failed',
             last_error_code = ?,
             last_error_message = ?,
             updated_at = ?
         WHERE id = ?`
      )
      .bind(params.code, params.message, params.updatedAt, params.runId)
      .run();
  }

  async listEntriesByRun(runId: string): Promise<NettingEntryRecord[]> {
    const result = await this.db
      .prepare(
        `SELECT
           id,
           run_id,
           entry_key,
           connect_account_id,
           currency,
           amount_minor,
           payout_count,
           payout_ids_json,
           idempotency_key,
           status,
           ledger_event_id,
           last_error_code,
           last_error_message,
           created_at,
           updated_at,
           applied_at
         FROM netting_entries
         WHERE run_id = ?
         ORDER BY created_at ASC, id ASC`
      )
      .bind(runId)
      .all();

    const rows = Array.isArray(result.results) ? result.results : [];
    return rows.map((row) => parseEntryRow(row));
  }

  async createEntry(entry: NettingEntryRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO netting_entries (
           id,
           run_id,
           entry_key,
           connect_account_id,
           currency,
           amount_minor,
           payout_count,
           payout_ids_json,
           idempotency_key,
           status,
           ledger_event_id,
           last_error_code,
           last_error_message,
           created_at,
           updated_at,
           applied_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        entry.id,
        entry.run_id,
        entry.entry_key,
        entry.connect_account_id,
        entry.currency,
        entry.amount_minor,
        entry.payout_count,
        JSON.stringify(entry.payout_ids),
        entry.idempotency_key,
        entry.status,
        entry.ledger_event_id ?? null,
        entry.last_error_code ?? null,
        entry.last_error_message ?? null,
        entry.created_at,
        entry.updated_at,
        entry.applied_at ?? null
      )
      .run();
  }

  async deleteEntryById(entryId: string): Promise<void> {
    await this.db
      .prepare(`DELETE FROM netting_entries WHERE id = ?`)
      .bind(entryId)
      .run();
  }

  async createEntryPayoutMappings(params: {
    runId: string;
    entryId: string;
    payouts: Array<{ payoutId: string; amountMinor: string }>;
    createdAt: string;
  }): Promise<void> {
    if (params.payouts.length === 0) {
      return;
    }

    const placeholders = params.payouts.map(() => '(?, ?, ?, ?, ?)').join(', ');
    const args: Array<string> = [];

    for (const payout of params.payouts) {
      args.push(params.runId, params.entryId, payout.payoutId, payout.amountMinor, params.createdAt);
    }

    await this.db
      .prepare(
        `INSERT INTO netting_entry_payouts (
           run_id,
           entry_id,
           payout_id,
           amount_minor,
           created_at
         ) VALUES ${placeholders}`
      )
      .bind(...args)
      .run();
  }

  async transitionEntryStatusIfCurrent(params: {
    entryId: string;
    from: NettingEntryStatus;
    to: NettingEntryStatus;
    updatedAt: string;
  }): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE netting_entries
         SET status = ?,
             updated_at = ?
         WHERE id = ?
           AND status = ?`
      )
      .bind(params.to, params.updatedAt, params.entryId, params.from)
      .run();

    const changes = Number((result.meta as { changes?: number } | undefined)?.changes ?? 0);
    return changes > 0;
  }

  async markEntryApplied(params: {
    entryId: string;
    ledgerEventId: string;
    updatedAt: string;
    appliedAt: string;
  }): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE netting_entries
         SET status = 'applied',
             ledger_event_id = COALESCE(ledger_event_id, ?),
             applied_at = COALESCE(applied_at, ?),
             updated_at = ?,
             last_error_code = NULL,
             last_error_message = NULL
         WHERE id = ?
           AND status = 'applying'`
      )
      .bind(params.ledgerEventId, params.appliedAt, params.updatedAt, params.entryId)
      .run();

    const changes = Number((result.meta as { changes?: number } | undefined)?.changes ?? 0);
    return changes > 0;
  }

  async markEntryFailed(params: {
    entryId: string;
    code: string;
    message: string;
    updatedAt: string;
  }): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE netting_entries
         SET status = 'failed',
             last_error_code = ?,
             last_error_message = ?,
             updated_at = ?
         WHERE id = ?
           AND status = 'applying'`
      )
      .bind(params.code, params.message, params.updatedAt, params.entryId)
      .run();

    const changes = Number((result.meta as { changes?: number } | undefined)?.changes ?? 0);
    return changes > 0;
  }

  async listEligiblePaidPayoutCandidates(params: {
    currency: string;
    selectionBefore: string;
    limit: number;
  }): Promise<NettingCandidatePayout[]> {
    const result = await this.db
      .prepare(
        `SELECT
           p.id,
           p.connect_account_id,
           p.currency,
           p.amount_minor,
           p.finalized_at
         FROM payouts p
         LEFT JOIN netting_entry_payouts nep
           ON nep.payout_id = p.id
         WHERE p.status = 'paid'
           AND p.currency = ?
           AND p.finalized_at IS NOT NULL
           AND p.finalized_at <= ?
           AND nep.payout_id IS NULL
         ORDER BY p.finalized_at ASC, p.id ASC
         LIMIT ?`
      )
      .bind(params.currency, params.selectionBefore, params.limit)
      .all();

    const rows = Array.isArray(result.results) ? result.results : [];
    return rows.map((row) => parseCandidateRow(row));
  }
}

interface NormalizedRunRequest {
  currency: string;
  limit: number;
  sourceClearingDomain: string;
  targetClearingDomain: string;
}

interface PreparedNettingEntry {
  id: string;
  entry_key: string;
  connect_account_id: string;
  currency: string;
  amount_minor: string;
  payout_ids: string[];
  idempotency_key: string;
}

export class NettingService {
  private readonly repository: NettingRepositoryLike;
  private readonly ledgerClient?: LedgerClientLike;
  private readonly now: () => string;
  private readonly defaultLimit: number;
  private readonly sourceDomain: string;
  private readonly targetDomain: string;

  constructor(private readonly env: Env, deps: NettingServiceDeps = {}) {
    this.repository = deps.repository ?? new NettingRepository(env.DB);
    this.ledgerClient = deps.ledgerClient;
    this.now = deps.now ?? (() => new Date().toISOString());

    this.defaultLimit = parsePositiveIntegerEnv(
      env.NETTING_RUN_DEFAULT_LIMIT,
      DEFAULT_NETTING_LIMIT,
      'env.NETTING_RUN_DEFAULT_LIMIT'
    );

    const sourceConfigured = env.NETTING_SOURCE_CLEARING_DOMAIN?.trim();
    const payoutConfigured = env.PAYOUTS_CLEARING_DOMAIN?.trim();
    this.sourceDomain =
      sourceConfigured && sourceConfigured.length > 0
        ? sourceConfigured
        : payoutConfigured && payoutConfigured.length > 0
          ? payoutConfigured
          : DEFAULT_NETTING_SOURCE_DOMAIN;

    const targetConfigured = env.NETTING_TARGET_CLEARING_DOMAIN?.trim();
    this.targetDomain =
      targetConfigured && targetConfigured.length > 0
        ? targetConfigured
        : DEFAULT_NETTING_TARGET_DOMAIN;
  }

  private getLedgerClient(): LedgerClientLike {
    if (this.ledgerClient) {
      return this.ledgerClient;
    }

    const baseUrl = this.env.LEDGER_BASE_URL?.trim();
    if (!baseUrl) {
      throw new ClawSettleError('Ledger base URL not configured', 'DEPENDENCY_NOT_CONFIGURED', 503, {
        field: 'env.LEDGER_BASE_URL',
      });
    }

    const adminKey = this.env.LEDGER_ADMIN_KEY?.trim();
    if (!adminKey) {
      throw new ClawSettleError('Ledger admin key not configured', 'DEPENDENCY_NOT_CONFIGURED', 503, {
        field: 'env.LEDGER_ADMIN_KEY',
      });
    }

    return new LedgerPayoutClient(baseUrl, adminKey);
  }

  private normalizeRunRequest(raw: unknown): NormalizedRunRequest {
    if (raw !== undefined && raw !== null && !isRecord(raw)) {
      throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
    }

    const body = isRecord(raw) ? raw : {};

    const currency = body.currency === undefined ? 'USD' : parseCurrency(body.currency);
    const limit = parsePositiveLimit(body.limit, this.defaultLimit);

    const sourceDomain =
      body.source_clearing_domain === undefined
        ? this.sourceDomain
        : parseNonEmptyString(body.source_clearing_domain, 'source_clearing_domain');

    const targetDomain =
      body.target_clearing_domain === undefined
        ? this.targetDomain
        : parseNonEmptyString(body.target_clearing_domain, 'target_clearing_domain');

    if (sourceDomain === targetDomain) {
      throw new ClawSettleError(
        'source_clearing_domain and target_clearing_domain must differ',
        'INVALID_REQUEST',
        400,
        {
          source_clearing_domain: sourceDomain,
          target_clearing_domain: targetDomain,
        }
      );
    }

    return {
      currency,
      limit,
      sourceClearingDomain: sourceDomain,
      targetClearingDomain: targetDomain,
    };
  }

  private async buildRunRequestHash(input: NormalizedRunRequest): Promise<string> {
    return sha256Hex(
      stableStringify({
        currency: input.currency,
        limit: input.limit,
        source_clearing_domain: input.sourceClearingDomain,
        target_clearing_domain: input.targetClearingDomain,
      })
    );
  }

  private async buildDeterministicId(prefix: string, source: string, length = 28): Promise<string> {
    const hash = await sha256Hex(`${prefix}:${source}`);
    return `${prefix}_${hash.slice(0, length)}`;
  }

  private async ensureIdempotencyCompatible(existing: NettingRunRecord, requestHash: string): Promise<void> {
    if (existing.request_hash !== requestHash) {
      throw new ClawSettleError('Idempotency key reused with different netting payload', 'IDEMPOTENCY_KEY_REUSED', 409, {
        run_id: existing.id,
      });
    }
  }

  private prepareEntries(candidates: NettingCandidatePayout[], runId: string): PreparedNettingEntry[] {
    const grouped = new Map<
      string,
      {
        connect_account_id: string;
        currency: string;
        payout_ids: string[];
        amount_minor_total: bigint;
      }
    >();

    for (const candidate of candidates) {
      const key = `${candidate.connect_account_id}::${candidate.currency}`;
      const amount = parsePositiveMinorAmount(candidate.amount_minor);

      const existing = grouped.get(key);
      if (existing) {
        existing.payout_ids.push(candidate.payout_id);
        existing.amount_minor_total += amount;
        continue;
      }

      grouped.set(key, {
        connect_account_id: candidate.connect_account_id,
        currency: candidate.currency,
        payout_ids: [candidate.payout_id],
        amount_minor_total: amount,
      });
    }

    const entries = Array.from(grouped.values())
      .sort((a, b) => {
        const byConnect = a.connect_account_id.localeCompare(b.connect_account_id);
        if (byConnect !== 0) return byConnect;
        return a.currency.localeCompare(b.currency);
      })
      .map((group) => {
        const payoutIds = [...group.payout_ids];
        const canonicalKey = stableStringify({
          connect_account_id: group.connect_account_id,
          currency: group.currency,
          payout_ids: payoutIds,
        });

        return {
          entry_key: canonicalKey,
          connect_account_id: group.connect_account_id,
          currency: group.currency,
          payout_ids: payoutIds,
          amount_minor: group.amount_minor_total.toString(),
        };
      });

    return entries.map((entry) => {
      const hashSource = stableStringify({
        run_id: runId,
        connect_account_id: entry.connect_account_id,
        currency: entry.currency,
        payout_ids: entry.payout_ids,
      });

      // Deterministic IDs derived from canonical entry payload.
      // Hashing done synchronously by precomputed key in create flow.
      return {
        id: '',
        entry_key: hashSource,
        connect_account_id: entry.connect_account_id,
        currency: entry.currency,
        amount_minor: entry.amount_minor,
        payout_ids: entry.payout_ids,
        idempotency_key: '',
      };
    });
  }

  private async finalizePreparedEntries(entries: PreparedNettingEntry[]): Promise<PreparedNettingEntry[]> {
    const out: PreparedNettingEntry[] = [];

    for (const entry of entries) {
      const hash = await sha256Hex(entry.entry_key);
      const entryId = `nte_${hash.slice(0, 28)}`;
      out.push({
        ...entry,
        id: entryId,
        idempotency_key: `netting:entry:${entryId}`,
      });
    }

    return out;
  }

  private async buildReportHash(run: NettingRunRecord, rows: NettingReportRow[]): Promise<string> {
    return sha256Hex(
      stableStringify({
        run_id: run.id,
        summary: {
          status: run.status,
          currency: run.currency,
          source_clearing_domain: run.source_clearing_domain,
          target_clearing_domain: run.target_clearing_domain,
          candidate_count: run.candidate_count,
          applied_count: run.applied_count,
          failed_count: run.failed_count,
          total_amount_minor: run.total_amount_minor,
        },
        entries: rows,
      })
    );
  }

  private toReportRows(entries: NettingEntryRecord[]): NettingReportRow[] {
    return [...entries]
      .sort((a, b) => a.id.localeCompare(b.id))
      .map((entry) => ({
        entry_id: entry.id,
        connect_account_id: entry.connect_account_id,
        payout_count: entry.payout_count,
        amount_minor: entry.amount_minor,
        status: entry.status,
        ledger_event_id: entry.ledger_event_id,
        last_error_code: entry.last_error_code,
        last_error_message: entry.last_error_message,
        payout_ids: [...entry.payout_ids],
      }));
  }

  private async persistRunEntries(params: {
    run: NettingRunRecord;
    entries: PreparedNettingEntry[];
    candidates: NettingCandidatePayout[];
  }): Promise<void> {
    const nowIso = this.now();

    const amountByPayout = new Map<string, string>();
    for (const candidate of params.candidates) {
      amountByPayout.set(candidate.payout_id, candidate.amount_minor);
    }

    for (const entry of params.entries) {
      const entryRecord: NettingEntryRecord = {
        id: entry.id,
        run_id: params.run.id,
        entry_key: entry.entry_key,
        connect_account_id: entry.connect_account_id,
        currency: entry.currency,
        amount_minor: entry.amount_minor,
        payout_count: entry.payout_ids.length,
        payout_ids: [...entry.payout_ids],
        idempotency_key: entry.idempotency_key,
        status: 'pending',
        created_at: nowIso,
        updated_at: nowIso,
      };

      try {
        await this.repository.createEntry(entryRecord);
      } catch (err) {
        if (!isSqliteUniqueConstraintError(err)) {
          throw err;
        }

        throw new ClawSettleError(
          'Duplicate netting entry conflict',
          'DUPLICATE_CONFLICT',
          409,
          {
            entry_id: entryRecord.id,
          }
        );
      }

      try {
        await this.repository.createEntryPayoutMappings({
          runId: params.run.id,
          entryId: entryRecord.id,
          payouts: entryRecord.payout_ids.map((payoutId) => ({
            payoutId,
            amountMinor: amountByPayout.get(payoutId) ?? '0',
          })),
          createdAt: nowIso,
        });
      } catch (err) {
        await this.repository.deleteEntryById(entryRecord.id);

        if (!isSqliteUniqueConstraintError(err)) {
          throw err;
        }

        throw new ClawSettleError(
          'Concurrent netting overlap detected',
          'DUPLICATE_CONFLICT',
          409,
          {
            run_id: params.run.id,
            entry_id: entryRecord.id,
          }
        );
      }
    }
  }

  private async createRunIfMissing(params: {
    idempotencyKey: string;
    requestHash: string;
    normalized: NormalizedRunRequest;
  }): Promise<NettingRunRecord> {
    const existing = await this.repository.findRunByIdempotencyKey(params.idempotencyKey);
    if (existing) {
      await this.ensureIdempotencyCompatible(existing, params.requestHash);
      return existing;
    }

    const runId = await this.buildDeterministicId('nrun', params.idempotencyKey, 28);
    const nowIso = this.now();

    const run: NettingRunRecord = {
      id: runId,
      idempotency_key: params.idempotencyKey,
      request_hash: params.requestHash,
      currency: params.normalized.currency,
      selection_before: nowIso,
      source_clearing_domain: params.normalized.sourceClearingDomain,
      target_clearing_domain: params.normalized.targetClearingDomain,
      status: 'created',
      candidate_count: 0,
      applied_count: 0,
      failed_count: 0,
      total_amount_minor: '0',
      created_at: nowIso,
      updated_at: nowIso,
    };

    try {
      await this.repository.createRun(run);
    } catch (err) {
      if (!isSqliteUniqueConstraintError(err)) {
        throw err;
      }

      const raced = await this.repository.findRunByIdempotencyKey(params.idempotencyKey);
      if (!raced) {
        throw err;
      }

      await this.ensureIdempotencyCompatible(raced, params.requestHash);
      return raced;
    }

    const candidates = await this.repository.listEligiblePaidPayoutCandidates({
      currency: params.normalized.currency,
      selectionBefore: run.selection_before,
      limit: params.normalized.limit,
    });

    const prepared = await this.finalizePreparedEntries(this.prepareEntries(candidates, run.id));

    let totalAmount = 0n;
    for (const entry of prepared) {
      totalAmount += parsePositiveMinorAmount(entry.amount_minor);
    }

    try {
      await this.persistRunEntries({
        run,
        entries: prepared,
        candidates,
      });
    } catch (err) {
      const code = err instanceof ClawSettleError ? err.code : 'INTERNAL_ERROR';
      const message = safeErrorMessage(err);
      await this.repository.setRunError({
        runId: run.id,
        code,
        message,
        updatedAt: this.now(),
      });
      throw err;
    }

    await this.repository.setRunSummary({
      runId: run.id,
      candidateCount: candidates.length,
      totalAmountMinor: totalAmount.toString(),
      updatedAt: this.now(),
    });

    const refreshed = await this.repository.findRunById(run.id);
    if (!refreshed) {
      throw new ClawSettleError('Netting run not found after create', 'INTERNAL_ERROR', 500, {
        run_id: run.id,
      });
    }

    return refreshed;
  }

  private async executeRunById(runId: string): Promise<NettingRunStatusResponse> {
    const run = await this.repository.findRunById(runId);
    if (!run) {
      throw new ClawSettleError('Netting run not found', 'NOT_FOUND', 404, {
        run_id: runId,
      });
    }

    if (run.status === 'applied') {
      return this.getRun(runId);
    }

    if (run.status === 'running') {
      throw new ClawSettleError('Netting run already executing', 'DUPLICATE_CONFLICT', 409, {
        run_id: runId,
      });
    }

    if (run.status !== 'created' && run.status !== 'failed') {
      throw new ClawSettleError('Invalid netting run status transition', 'INVALID_STATUS_TRANSITION', 409, {
        run_id: runId,
        from_status: run.status,
        to_status: 'running',
      });
    }

    const claimed = await this.repository.transitionRunStatusIfCurrent({
      runId,
      from: run.status,
      to: 'running',
      updatedAt: this.now(),
    });

    if (!claimed) {
      throw new ClawSettleError('Netting run status collision', 'DUPLICATE_CONFLICT', 409, {
        run_id: runId,
      });
    }

    let entries = await this.repository.listEntriesByRun(runId);

    for (const entry of entries) {
      if (entry.status === 'applied') {
        continue;
      }

      if (entry.status === 'applying') {
        throw new ClawSettleError('Concurrent netting entry execution detected', 'DUPLICATE_CONFLICT', 409, {
          run_id: runId,
          entry_id: entry.id,
        });
      }

      if (entry.status !== 'pending' && entry.status !== 'failed') {
        throw new ClawSettleError('Invalid netting entry status transition', 'INVALID_STATUS_TRANSITION', 409, {
          run_id: runId,
          entry_id: entry.id,
          from_status: entry.status,
          to_status: 'applying',
        });
      }

      const entryClaimed = await this.repository.transitionEntryStatusIfCurrent({
        entryId: entry.id,
        from: entry.status,
        to: 'applying',
        updatedAt: this.now(),
      });

      if (!entryClaimed) {
        throw new ClawSettleError('Netting entry status collision', 'DUPLICATE_CONFLICT', 409, {
          run_id: runId,
          entry_id: entry.id,
        });
      }

      try {
        const existingEvent = await this.getLedgerClient().findEventByIdempotencyKey(entry.idempotency_key);

        if (existingEvent) {
          await this.repository.markEntryApplied({
            entryId: entry.id,
            ledgerEventId: existingEvent.id,
            updatedAt: this.now(),
            appliedAt: this.now(),
          });
          continue;
        }

        const transfer = await this.getLedgerClient().transferV1({
          idempotencyKey: entry.idempotency_key,
          currency: 'USD',
          from: {
            account: `clearing:${run.source_clearing_domain}`,
            bucket: 'A',
          },
          to: {
            account: `clearing:${run.target_clearing_domain}`,
            bucket: 'A',
          },
          amountMinor: entry.amount_minor,
          metadata: {
            netting_run_id: run.id,
            netting_entry_id: entry.id,
            connect_account_id: entry.connect_account_id,
            payout_count: entry.payout_count,
            payout_ids: entry.payout_ids,
          },
        });

        await this.repository.markEntryApplied({
          entryId: entry.id,
          ledgerEventId: transfer.event_id,
          updatedAt: this.now(),
          appliedAt: this.now(),
        });
      } catch (err) {
        const code = err instanceof ClawSettleError ? err.code : 'LEDGER_INGEST_FAILED';

        const detailStatus =
          err instanceof ClawSettleError && typeof err.details?.status === 'number'
            ? err.details.status
            : err instanceof ClawSettleError && typeof err.details?.ledger_status === 'number'
              ? err.details.ledger_status
              : undefined;

        const detailCode =
          err instanceof ClawSettleError && typeof err.details?.ledger_code === 'string'
            ? err.details.ledger_code
            : undefined;

        const message = safeErrorMessage(
          detailStatus !== undefined
            ? `${safeErrorMessage(err)} (status=${detailStatus}${detailCode ? ` code=${detailCode}` : ''})`
            : err
        );

        await this.repository.markEntryFailed({
          entryId: entry.id,
          code,
          message,
          updatedAt: this.now(),
        });
      }
    }

    entries = await this.repository.listEntriesByRun(runId);
    const appliedCount = entries.filter((entry) => entry.status === 'applied').length;
    const failedCount = entries.filter((entry) => entry.status === 'failed').length;

    const post = await this.repository.findRunById(runId);
    if (!post) {
      throw new ClawSettleError('Netting run missing after execute', 'INTERNAL_ERROR', 500, {
        run_id: runId,
      });
    }

    const finalStatus: NettingRunStatus = failedCount > 0 ? 'failed' : 'applied';
    const reportRows = this.toReportRows(entries);
    const reportHash = await this.buildReportHash(
      {
        ...post,
        status: finalStatus,
        applied_count: appliedCount,
        failed_count: failedCount,
      },
      reportRows
    );

    const firstFailed = entries.find((entry) => entry.status === 'failed');

    await this.repository.completeRun({
      runId,
      status: finalStatus,
      appliedCount,
      failedCount,
      reportHash,
      updatedAt: this.now(),
      completedAt: this.now(),
      lastErrorCode: firstFailed?.last_error_code,
      lastErrorMessage: firstFailed?.last_error_message,
    });

    return this.getRun(runId);
  }

  async createAndExecuteRun(
    raw: unknown,
    idempotencyKey: string
  ): Promise<NettingRunExecuteResponse> {
    if (typeof idempotencyKey !== 'string' || idempotencyKey.trim().length === 0) {
      throw new ClawSettleError('Missing idempotency key', 'INVALID_REQUEST', 400, {
        field: 'idempotency_key',
      });
    }

    const normalized = this.normalizeRunRequest(raw);
    const requestHash = await this.buildRunRequestHash(normalized);

    const existing = await this.repository.findRunByIdempotencyKey(idempotencyKey.trim());
    if (existing) {
      await this.ensureIdempotencyCompatible(existing, requestHash);
      const resumed = await this.executeRunById(existing.id);
      return {
        ok: true,
        deduped: existing.status === 'applied' && resumed.run.status === 'applied',
        run: resumed.run,
        entries: resumed.entries,
      };
    }

    const run = await this.createRunIfMissing({
      idempotencyKey: idempotencyKey.trim(),
      requestHash,
      normalized,
    });

    const executed = await this.executeRunById(run.id);
    return {
      ok: true,
      deduped: false,
      run: executed.run,
      entries: executed.entries,
    };
  }

  async getRun(runId: string): Promise<NettingRunStatusResponse> {
    const run = await this.repository.findRunById(runId);
    if (!run) {
      throw new ClawSettleError('Netting run not found', 'NOT_FOUND', 404, {
        run_id: runId,
      });
    }

    const entries = await this.repository.listEntriesByRun(runId);

    return {
      ok: true,
      run,
      entries,
    };
  }

  async buildRunReport(runId: string): Promise<NettingRunReport> {
    const status = await this.getRun(runId);

    const rows = this.toReportRows(status.entries);
    const artifactSha = await this.buildReportHash(status.run, rows);

    if (status.run.report_hash && status.run.report_hash !== artifactSha) {
      throw new ClawSettleError('Netting report hash mismatch', 'INTERNAL_ERROR', 500, {
        run_id: runId,
      });
    }

    return {
      run_id: status.run.id,
      generated_at: this.now(),
      summary: {
        status: status.run.status,
        currency: status.run.currency,
        source_clearing_domain: status.run.source_clearing_domain,
        target_clearing_domain: status.run.target_clearing_domain,
        candidate_count: status.run.candidate_count,
        applied_count: status.run.applied_count,
        failed_count: status.run.failed_count,
        total_amount_minor: status.run.total_amount_minor,
      },
      entries: rows,
      artifact_sha256: artifactSha,
    };
  }

  toRunReportCsv(report: NettingRunReport): string {
    const header = [
      'entry_id',
      'connect_account_id',
      'payout_count',
      'amount_minor',
      'status',
      'ledger_event_id',
      'last_error_code',
      'last_error_message',
      'payout_ids',
    ];

    const escape = (value: unknown): string => {
      const raw = value === undefined || value === null ? '' : String(value);
      if (!raw.includes(',') && !raw.includes('"') && !raw.includes('\n')) {
        return raw;
      }
      return `"${raw.replace(/"/g, '""')}"`;
    };

    const lines = [header.join(',')];

    for (const row of report.entries) {
      lines.push(
        [
          row.entry_id,
          row.connect_account_id,
          row.payout_count,
          row.amount_minor,
          row.status,
          row.ledger_event_id,
          row.last_error_code,
          row.last_error_message,
          row.payout_ids.join('|'),
        ]
          .map((value) => escape(value))
          .join(',')
      );
    }

    return lines.join('\n');
  }
}

export function parseNettingRequestBody(body: unknown): NettingRunExecuteRequest {
  if (body === undefined || body === null) {
    return {};
  }

  if (!isRecord(body)) {
    throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
  }

  const out: NettingRunExecuteRequest = {};

  if (body.currency !== undefined) {
    out.currency = parseCurrency(body.currency);
  }

  if (body.limit !== undefined) {
    if (typeof body.limit !== 'number' || !Number.isFinite(body.limit)) {
      throw new ClawSettleError('limit must be a positive integer', 'INVALID_REQUEST', 400, {
        field: 'limit',
      });
    }
    out.limit = Math.floor(body.limit);
  }

  if (body.source_clearing_domain !== undefined) {
    out.source_clearing_domain = parseNonEmptyString(
      body.source_clearing_domain,
      'source_clearing_domain'
    );
  }

  if (body.target_clearing_domain !== undefined) {
    out.target_clearing_domain = parseNonEmptyString(
      body.target_clearing_domain,
      'target_clearing_domain'
    );
  }

  return out;
}
