import { ClawSettleError } from './stripe';
import type {
  DailyPayoutReconciliationReport,
  DailyPayoutReconciliationRow,
  Env,
  PayoutConnectAccount,
  PayoutConnectOnboardRequest,
  PayoutCreateRequest,
  PayoutCreateResponse,
  PayoutLifecycleHookInput,
  PayoutRecord,
  PayoutRetryResponse,
  PayoutStatus,
} from './types';

const DEFAULT_PAYOUTS_CLEARING_DOMAIN = 'clawsettle.payouts';
const DEFAULT_STUCK_MINUTES = 60;
const DEFAULT_RECON_LIMIT = 2000;

interface LedgerAccountSnapshot {
  id: string;
  did: string;
  balances: {
    available: string;
    held: string;
  };
}

interface LedgerV1TransferResponse {
  event_id: string;
  status: 'applied';
}

interface LedgerEventSnapshot {
  id: string;
  idempotencyKey: string;
}

interface LedgerClientLike {
  getAccountById(accountId: string): Promise<LedgerAccountSnapshot>;
  findEventByIdempotencyKey(idempotencyKey: string): Promise<LedgerEventSnapshot | null>;
  transferV1(input: {
    idempotencyKey: string;
    currency: 'USD';
    from: { account: string; bucket: 'A' | 'H' | 'B' | 'F' | 'P' };
    to: { account: string; bucket: 'A' | 'H' | 'B' | 'F' | 'P' };
    amountMinor: string;
    metadata?: Record<string, unknown>;
  }): Promise<LedgerV1TransferResponse>;
}

interface PayoutRepositoryLike {
  findConnectAccountByAccountId(accountId: string): Promise<PayoutConnectAccount | null>;
  upsertConnectAccount(record: PayoutConnectAccount): Promise<void>;
  findById(id: string): Promise<PayoutRecord | null>;
  findByIdempotencyKey(idempotencyKey: string): Promise<PayoutRecord | null>;
  findByExternalPayoutId(externalPayoutId: string): Promise<PayoutRecord | null>;
  create(record: PayoutRecord): Promise<void>;
  setLockEventIfMissing(payoutId: string, lockEventId: string, updatedAt: string): Promise<void>;
  markSubmittedIfInitiated(params: {
    payoutId: string;
    externalPayoutId: string;
    updatedAt: string;
    submittedAt: string;
  }): Promise<boolean>;
  updateStatusIfCurrent(params: {
    payoutId: string;
    fromStatus: PayoutStatus;
    toStatus: PayoutStatus;
    updatedAt: string;
    finalizedAt?: string;
    failedAt?: string;
    clearErrors?: boolean;
  }): Promise<boolean>;
  setFinalizeEventIfMissing(payoutId: string, eventId: string, updatedAt: string): Promise<void>;
  setRollbackEventIfMissing(payoutId: string, eventId: string, updatedAt: string): Promise<void>;
  setLifecycleError(payoutId: string, code: string, message: string, updatedAt: string): Promise<void>;
  appendAuditEvent(params: {
    payoutId: string;
    eventType: string;
    eventIdempotencyKey?: string;
    details: Record<string, unknown>;
    createdAt: string;
  }): Promise<void>;
  listAuditEvents(payoutId: string): Promise<Array<Record<string, unknown>>>;
  listStuck(params: {
    statuses: PayoutStatus[];
    beforeOrAtIso: string;
    limit: number;
  }): Promise<PayoutRecord[]>;
  listFailed(limit: number): Promise<PayoutRecord[]>;
  listByCreatedRange(params: {
    startIso: string;
    endIso: string;
    limit: number;
  }): Promise<PayoutRecord[]>;
}

interface PayoutServiceDeps {
  repository?: PayoutRepositoryLike;
  ledgerClient?: LedgerClientLike;
  now?: () => string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
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

function parseJsonObject(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }

  try {
    const parsed = JSON.parse(value);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
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

function safeErrorMessage(err: unknown): string {
  const text = err instanceof Error ? err.message : String(err ?? 'Unknown error');
  return text.length > 500 ? text.slice(0, 500) : text;
}

function parsePayoutStatus(value: unknown): PayoutStatus {
  switch (value) {
    case 'initiated':
    case 'submitted':
    case 'finalizing_paid':
    case 'finalizing_failed':
    case 'paid':
    case 'failed':
      return value;
    default:
      throw new Error(`Invalid payout status row: ${String(value)}`);
  }
}

function parseConnectAccountRow(row: Record<string, unknown>): PayoutConnectAccount {
  return {
    account_id: String(row.account_id),
    provider: 'stripe',
    connect_account_id: String(row.connect_account_id),
    onboarding_status:
      row.onboarding_status === 'pending' || row.onboarding_status === 'active'
        ? row.onboarding_status
        : 'active',
    onboarding_url: typeof row.onboarding_url === 'string' ? row.onboarding_url : undefined,
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
  };
}

function parsePayoutRow(row: Record<string, unknown>): PayoutRecord {
  return {
    id: String(row.id),
    idempotency_key: String(row.idempotency_key),
    request_hash: String(row.request_hash),
    provider: 'stripe',
    account_id: String(row.account_id),
    account_did: String(row.account_did),
    connect_account_id: String(row.connect_account_id),
    external_payout_id:
      typeof row.external_payout_id === 'string' ? row.external_payout_id : undefined,
    amount_minor: String(row.amount_minor),
    currency: String(row.currency),
    status: parsePayoutStatus(row.status),
    lock_idempotency_key: String(row.lock_idempotency_key),
    lock_event_id: typeof row.lock_event_id === 'string' ? row.lock_event_id : undefined,
    finalize_idempotency_key: String(row.finalize_idempotency_key),
    finalize_event_id: typeof row.finalize_event_id === 'string' ? row.finalize_event_id : undefined,
    rollback_idempotency_key: String(row.rollback_idempotency_key),
    rollback_event_id: typeof row.rollback_event_id === 'string' ? row.rollback_event_id : undefined,
    last_error_code: typeof row.last_error_code === 'string' ? row.last_error_code : undefined,
    last_error_message:
      typeof row.last_error_message === 'string' ? row.last_error_message : undefined,
    metadata: parseJsonObject(row.metadata_json),
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
    submitted_at: typeof row.submitted_at === 'string' ? row.submitted_at : undefined,
    finalized_at: typeof row.finalized_at === 'string' ? row.finalized_at : undefined,
    failed_at: typeof row.failed_at === 'string' ? row.failed_at : undefined,
  };
}

function parseIsoDateOnly(value: string): string {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new ClawSettleError('date must be YYYY-MM-DD', 'INVALID_REQUEST', 400, {
      field: 'date',
    });
  }

  return value;
}

function parsePositiveLimit(value: string | null, fallback: number, field: string, max = 200): number {
  if (!value || value.trim().length === 0) {
    return fallback;
  }

  const parsed = Number.parseInt(value.trim(), 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new ClawSettleError('Invalid numeric query parameter', 'INVALID_REQUEST', 400, {
      field,
    });
  }

  return Math.min(max, parsed);
}

function parseStuckMinutes(value: string | null, fallback: number): number {
  if (!value || value.trim().length === 0) {
    return fallback;
  }

  const parsed = Number.parseInt(value.trim(), 10);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new ClawSettleError('older_than_minutes must be a non-negative integer', 'INVALID_REQUEST', 400, {
      field: 'older_than_minutes',
    });
  }

  return Math.min(parsed, 24 * 60 * 30);
}

export class LedgerPayoutClient implements LedgerClientLike {
  constructor(
    private readonly ledgerBaseUrl: string,
    private readonly ledgerAdminKey: string
  ) {}

  private authHeaders(): HeadersInit {
    return {
      authorization: `Bearer ${this.ledgerAdminKey}`,
      'x-admin-key': this.ledgerAdminKey,
      'content-type': 'application/json; charset=utf-8',
    };
  }

  private async parseResponse(response: Response): Promise<{ json: Record<string, unknown> | null; text: string }> {
    const text = await response.text();

    let json: Record<string, unknown> | null = null;
    try {
      const parsed = JSON.parse(text);
      json = isRecord(parsed) ? parsed : null;
    } catch {
      json = null;
    }

    return { json, text };
  }

  async getAccountById(accountId: string): Promise<LedgerAccountSnapshot> {
    const response = await fetch(
      `${this.ledgerBaseUrl.replace(/\/$/, '')}/accounts/id/${encodeURIComponent(accountId)}`,
      {
        method: 'GET',
        headers: this.authHeaders(),
      }
    );

    const payload = await this.parseResponse(response);

    if (response.status === 404) {
      throw new ClawSettleError('Account not found', 'NOT_FOUND', 404, {
        account_id: accountId,
      });
    }

    if (response.status < 200 || response.status >= 300) {
      throw new ClawSettleError('Ledger account lookup failed', 'LEDGER_INGEST_FAILED', 502, {
        account_id: accountId,
        ledger_status: response.status,
      });
    }

    const id = payload.json?.id;
    const did = payload.json?.did;
    const balances = payload.json?.balances;

    if (!isNonEmptyString(id) || !isNonEmptyString(did) || !isRecord(balances)) {
      throw new ClawSettleError('Ledger account response malformed', 'LEDGER_INGEST_FAILED', 502, {
        account_id: accountId,
      });
    }

    const available = balances.available;
    const held = balances.held;

    if (!isNonEmptyString(available) || !isNonEmptyString(held)) {
      throw new ClawSettleError('Ledger account balances malformed', 'LEDGER_INGEST_FAILED', 502, {
        account_id: accountId,
      });
    }

    return {
      id,
      did,
      balances: {
        available,
        held,
      },
    };
  }

  async findEventByIdempotencyKey(idempotencyKey: string): Promise<LedgerEventSnapshot | null> {
    const response = await fetch(
      `${this.ledgerBaseUrl.replace(/\/$/, '')}/events/idempotency/${encodeURIComponent(idempotencyKey)}`,
      {
        method: 'GET',
        headers: this.authHeaders(),
      }
    );

    if (response.status === 404) {
      return null;
    }

    const payload = await this.parseResponse(response);

    if (response.status < 200 || response.status >= 300) {
      throw new ClawSettleError('Ledger event lookup failed', 'LEDGER_INGEST_FAILED', 502, {
        idempotency_key: idempotencyKey,
        ledger_status: response.status,
      });
    }

    const id = payload.json?.id;
    const idem = payload.json?.idempotencyKey;

    if (!isNonEmptyString(id) || !isNonEmptyString(idem)) {
      throw new ClawSettleError('Ledger event response malformed', 'LEDGER_INGEST_FAILED', 502, {
        idempotency_key: idempotencyKey,
      });
    }

    return {
      id,
      idempotencyKey: idem,
    };
  }

  async transferV1(input: {
    idempotencyKey: string;
    currency: 'USD';
    from: { account: string; bucket: 'A' | 'H' | 'B' | 'F' | 'P' };
    to: { account: string; bucket: 'A' | 'H' | 'B' | 'F' | 'P' };
    amountMinor: string;
    metadata?: Record<string, unknown>;
  }): Promise<LedgerV1TransferResponse> {
    const response = await fetch(
      `${this.ledgerBaseUrl.replace(/\/$/, '')}/v1/transfers`,
      {
        method: 'POST',
        headers: this.authHeaders(),
        body: JSON.stringify({
          idempotency_key: input.idempotencyKey,
          currency: input.currency,
          from: input.from,
          to: input.to,
          amount_minor: input.amountMinor,
          metadata: input.metadata,
        }),
      }
    );

    const payload = await this.parseResponse(response);

    if (response.status === 400 && payload.json?.code === 'INSUFFICIENT_FUNDS') {
      throw new ClawSettleError('Insufficient funds', 'INSUFFICIENT_FUNDS', 400, {
        idempotency_key: input.idempotencyKey,
      });
    }

    if (response.status < 200 || response.status >= 300) {
      throw new ClawSettleError('Ledger transfer failed', 'LEDGER_INGEST_FAILED', 502, {
        idempotency_key: input.idempotencyKey,
        ledger_status: response.status,
        ledger_code: payload.json?.code,
      });
    }

    const eventId = payload.json?.event_id;
    if (!isNonEmptyString(eventId)) {
      throw new ClawSettleError('Ledger transfer response malformed', 'LEDGER_INGEST_FAILED', 502, {
        idempotency_key: input.idempotencyKey,
      });
    }

    return {
      event_id: eventId,
      status: 'applied',
    };
  }
}

export class PayoutRepository implements PayoutRepositoryLike {
  constructor(private readonly db: D1Database) {}

  async findConnectAccountByAccountId(accountId: string): Promise<PayoutConnectAccount | null> {
    const row = await this.db
      .prepare(
        `SELECT
           account_id,
           provider,
           connect_account_id,
           onboarding_status,
           onboarding_url,
           created_at,
           updated_at
         FROM payout_connect_accounts
         WHERE account_id = ?
         LIMIT 1`
      )
      .bind(accountId)
      .first();

    return row ? parseConnectAccountRow(row) : null;
  }

  async upsertConnectAccount(record: PayoutConnectAccount): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO payout_connect_accounts (
           account_id,
           provider,
           connect_account_id,
           onboarding_status,
           onboarding_url,
           created_at,
           updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(account_id) DO UPDATE SET
           connect_account_id = excluded.connect_account_id,
           onboarding_status = excluded.onboarding_status,
           onboarding_url = excluded.onboarding_url,
           updated_at = excluded.updated_at`
      )
      .bind(
        record.account_id,
        record.provider,
        record.connect_account_id,
        record.onboarding_status,
        record.onboarding_url ?? null,
        record.created_at,
        record.updated_at
      )
      .run();
  }

  async findById(id: string): Promise<PayoutRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT
           id,
           idempotency_key,
           request_hash,
           provider,
           account_id,
           account_did,
           connect_account_id,
           external_payout_id,
           amount_minor,
           currency,
           status,
           lock_idempotency_key,
           lock_event_id,
           finalize_idempotency_key,
           finalize_event_id,
           rollback_idempotency_key,
           rollback_event_id,
           last_error_code,
           last_error_message,
           metadata_json,
           created_at,
           updated_at,
           submitted_at,
           finalized_at,
           failed_at
         FROM payouts
         WHERE id = ?
         LIMIT 1`
      )
      .bind(id)
      .first();

    return row ? parsePayoutRow(row) : null;
  }

  async findByIdempotencyKey(idempotencyKey: string): Promise<PayoutRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT
           id,
           idempotency_key,
           request_hash,
           provider,
           account_id,
           account_did,
           connect_account_id,
           external_payout_id,
           amount_minor,
           currency,
           status,
           lock_idempotency_key,
           lock_event_id,
           finalize_idempotency_key,
           finalize_event_id,
           rollback_idempotency_key,
           rollback_event_id,
           last_error_code,
           last_error_message,
           metadata_json,
           created_at,
           updated_at,
           submitted_at,
           finalized_at,
           failed_at
         FROM payouts
         WHERE idempotency_key = ?
         LIMIT 1`
      )
      .bind(idempotencyKey)
      .first();

    return row ? parsePayoutRow(row) : null;
  }

  async findByExternalPayoutId(externalPayoutId: string): Promise<PayoutRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT
           id,
           idempotency_key,
           request_hash,
           provider,
           account_id,
           account_did,
           connect_account_id,
           external_payout_id,
           amount_minor,
           currency,
           status,
           lock_idempotency_key,
           lock_event_id,
           finalize_idempotency_key,
           finalize_event_id,
           rollback_idempotency_key,
           rollback_event_id,
           last_error_code,
           last_error_message,
           metadata_json,
           created_at,
           updated_at,
           submitted_at,
           finalized_at,
           failed_at
         FROM payouts
         WHERE external_payout_id = ?
         LIMIT 1`
      )
      .bind(externalPayoutId)
      .first();

    return row ? parsePayoutRow(row) : null;
  }

  async create(record: PayoutRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO payouts (
           id,
           idempotency_key,
           request_hash,
           provider,
           account_id,
           account_did,
           connect_account_id,
           external_payout_id,
           amount_minor,
           currency,
           status,
           lock_idempotency_key,
           lock_event_id,
           finalize_idempotency_key,
           finalize_event_id,
           rollback_idempotency_key,
           rollback_event_id,
           last_error_code,
           last_error_message,
           metadata_json,
           created_at,
           updated_at,
           submitted_at,
           finalized_at,
           failed_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        record.id,
        record.idempotency_key,
        record.request_hash,
        record.provider,
        record.account_id,
        record.account_did,
        record.connect_account_id,
        record.external_payout_id ?? null,
        record.amount_minor,
        record.currency,
        record.status,
        record.lock_idempotency_key,
        record.lock_event_id ?? null,
        record.finalize_idempotency_key,
        record.finalize_event_id ?? null,
        record.rollback_idempotency_key,
        record.rollback_event_id ?? null,
        record.last_error_code ?? null,
        record.last_error_message ?? null,
        record.metadata ? JSON.stringify(record.metadata) : null,
        record.created_at,
        record.updated_at,
        record.submitted_at ?? null,
        record.finalized_at ?? null,
        record.failed_at ?? null
      )
      .run();
  }

  async setLockEventIfMissing(payoutId: string, lockEventId: string, updatedAt: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE payouts
         SET lock_event_id = COALESCE(lock_event_id, ?),
             updated_at = ?
         WHERE id = ?`
      )
      .bind(lockEventId, updatedAt, payoutId)
      .run();
  }

  async markSubmittedIfInitiated(params: {
    payoutId: string;
    externalPayoutId: string;
    updatedAt: string;
    submittedAt: string;
  }): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE payouts
         SET status = 'submitted',
             external_payout_id = COALESCE(external_payout_id, ?),
             submitted_at = COALESCE(submitted_at, ?),
             updated_at = ?,
             last_error_code = NULL,
             last_error_message = NULL
         WHERE id = ?
           AND status = 'initiated'`
      )
      .bind(
        params.externalPayoutId,
        params.submittedAt,
        params.updatedAt,
        params.payoutId
      )
      .run();

    const changes = Number((result.meta as { changes?: number } | undefined)?.changes ?? 0);
    return changes > 0;
  }

  async updateStatusIfCurrent(params: {
    payoutId: string;
    fromStatus: PayoutStatus;
    toStatus: PayoutStatus;
    updatedAt: string;
    finalizedAt?: string;
    failedAt?: string;
    clearErrors?: boolean;
  }): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE payouts
         SET status = ?,
             updated_at = ?,
             finalized_at = COALESCE(?, finalized_at),
             failed_at = COALESCE(?, failed_at),
             last_error_code = CASE WHEN ? = 1 THEN NULL ELSE last_error_code END,
             last_error_message = CASE WHEN ? = 1 THEN NULL ELSE last_error_message END
         WHERE id = ?
           AND status = ?`
      )
      .bind(
        params.toStatus,
        params.updatedAt,
        params.finalizedAt ?? null,
        params.failedAt ?? null,
        params.clearErrors ? 1 : 0,
        params.clearErrors ? 1 : 0,
        params.payoutId,
        params.fromStatus
      )
      .run();

    const changes = Number((result.meta as { changes?: number } | undefined)?.changes ?? 0);
    return changes > 0;
  }

  async setFinalizeEventIfMissing(payoutId: string, eventId: string, updatedAt: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE payouts
         SET finalize_event_id = COALESCE(finalize_event_id, ?),
             updated_at = ?
         WHERE id = ?`
      )
      .bind(eventId, updatedAt, payoutId)
      .run();
  }

  async setRollbackEventIfMissing(payoutId: string, eventId: string, updatedAt: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE payouts
         SET rollback_event_id = COALESCE(rollback_event_id, ?),
             updated_at = ?
         WHERE id = ?`
      )
      .bind(eventId, updatedAt, payoutId)
      .run();
  }

  async setLifecycleError(payoutId: string, code: string, message: string, updatedAt: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE payouts
         SET last_error_code = ?,
             last_error_message = ?,
             updated_at = ?
         WHERE id = ?`
      )
      .bind(code, message, updatedAt, payoutId)
      .run();
  }

  async appendAuditEvent(params: {
    payoutId: string;
    eventType: string;
    eventIdempotencyKey?: string;
    details: Record<string, unknown>;
    createdAt: string;
  }): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO payout_audit_events (
           payout_id,
           event_type,
           event_idempotency_key,
           details_json,
           created_at
         ) VALUES (?, ?, ?, ?, ?)`
      )
      .bind(
        params.payoutId,
        params.eventType,
        params.eventIdempotencyKey ?? null,
        JSON.stringify(params.details),
        params.createdAt
      )
      .run();
  }

  async listAuditEvents(payoutId: string): Promise<Array<Record<string, unknown>>> {
    const result = await this.db
      .prepare(
        `SELECT id, payout_id, event_type, event_idempotency_key, details_json, created_at
         FROM payout_audit_events
         WHERE payout_id = ?
         ORDER BY id ASC`
      )
      .bind(payoutId)
      .all();

    const rows = Array.isArray(result.results) ? result.results : [];

    return rows.map((row) => ({
      id: row.id,
      payout_id: row.payout_id,
      event_type: row.event_type,
      event_idempotency_key: row.event_idempotency_key,
      details: parseJsonObject(row.details_json) ?? {},
      created_at: row.created_at,
    }));
  }

  async listStuck(params: {
    statuses: PayoutStatus[];
    beforeOrAtIso: string;
    limit: number;
  }): Promise<PayoutRecord[]> {
    if (params.statuses.length === 0) {
      return [];
    }

    const placeholders = params.statuses.map(() => '?').join(',');
    const statement = this.db.prepare(
      `SELECT
         id,
         idempotency_key,
         request_hash,
         provider,
         account_id,
         account_did,
         connect_account_id,
         external_payout_id,
         amount_minor,
         currency,
         status,
         lock_idempotency_key,
         lock_event_id,
         finalize_idempotency_key,
         finalize_event_id,
         rollback_idempotency_key,
         rollback_event_id,
         last_error_code,
         last_error_message,
         metadata_json,
         created_at,
         updated_at,
         submitted_at,
         finalized_at,
         failed_at
       FROM payouts
       WHERE status IN (${placeholders})
         AND updated_at <= ?
       ORDER BY updated_at ASC, id ASC
       LIMIT ?`
    );

    const bound = statement.bind(...params.statuses, params.beforeOrAtIso, params.limit);
    const result = await bound.all();
    const rows = Array.isArray(result.results) ? result.results : [];
    return rows.map((row) => parsePayoutRow(row));
  }

  async listFailed(limit: number): Promise<PayoutRecord[]> {
    const result = await this.db
      .prepare(
        `SELECT
           id,
           idempotency_key,
           request_hash,
           provider,
           account_id,
           account_did,
           connect_account_id,
           external_payout_id,
           amount_minor,
           currency,
           status,
           lock_idempotency_key,
           lock_event_id,
           finalize_idempotency_key,
           finalize_event_id,
           rollback_idempotency_key,
           rollback_event_id,
           last_error_code,
           last_error_message,
           metadata_json,
           created_at,
           updated_at,
           submitted_at,
           finalized_at,
           failed_at
         FROM payouts
         WHERE status = 'failed'
         ORDER BY failed_at DESC, id DESC
         LIMIT ?`
      )
      .bind(limit)
      .all();

    const rows = Array.isArray(result.results) ? result.results : [];
    return rows.map((row) => parsePayoutRow(row));
  }

  async listByCreatedRange(params: {
    startIso: string;
    endIso: string;
    limit: number;
  }): Promise<PayoutRecord[]> {
    const result = await this.db
      .prepare(
        `SELECT
           id,
           idempotency_key,
           request_hash,
           provider,
           account_id,
           account_did,
           connect_account_id,
           external_payout_id,
           amount_minor,
           currency,
           status,
           lock_idempotency_key,
           lock_event_id,
           finalize_idempotency_key,
           finalize_event_id,
           rollback_idempotency_key,
           rollback_event_id,
           last_error_code,
           last_error_message,
           metadata_json,
           created_at,
           updated_at,
           submitted_at,
           finalized_at,
           failed_at
         FROM payouts
         WHERE created_at >= ?
           AND created_at < ?
         ORDER BY created_at ASC, id ASC
         LIMIT ?`
      )
      .bind(params.startIso, params.endIso, params.limit)
      .all();

    const rows = Array.isArray(result.results) ? result.results : [];
    return rows.map((row) => parsePayoutRow(row));
  }
}

export class PayoutService {
  private readonly repository: PayoutRepositoryLike;
  private readonly ledgerClient?: LedgerClientLike;
  private readonly now: () => string;
  private readonly stuckMinutesDefault: number;
  private readonly clearingDomain: string;

  constructor(private readonly env: Env, deps: PayoutServiceDeps = {}) {
    this.repository = deps.repository ?? new PayoutRepository(env.DB);
    this.ledgerClient = deps.ledgerClient;
    this.now = deps.now ?? (() => new Date().toISOString());

    this.stuckMinutesDefault = parsePositiveIntegerEnv(
      env.PAYOUT_STUCK_MINUTES_DEFAULT,
      DEFAULT_STUCK_MINUTES,
      'env.PAYOUT_STUCK_MINUTES_DEFAULT'
    );

    const configuredDomain = env.PAYOUTS_CLEARING_DOMAIN?.trim();
    this.clearingDomain = configuredDomain && configuredDomain.length > 0
      ? configuredDomain
      : DEFAULT_PAYOUTS_CLEARING_DOMAIN;
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

  private async deriveDeterministicId(prefix: string, source: string, length = 24): Promise<string> {
    const hash = await sha256Hex(`${prefix}:${source}`);
    return `${prefix}_${hash.slice(0, length)}`;
  }

  private buildOnboardingUrl(connectAccountId: string, request: PayoutConnectOnboardRequest): string {
    const base = this.env.STRIPE_CONNECT_ONBOARD_BASE_URL?.trim() || 'https://dashboard.stripe.com/connect/accounts';
    const url = new URL(`${base.replace(/\/$/, '')}/${encodeURIComponent(connectAccountId)}`);

    if (isNonEmptyString(request.refresh_url)) {
      url.searchParams.set('refresh_url', request.refresh_url.trim());
    }

    if (isNonEmptyString(request.return_url)) {
      url.searchParams.set('return_url', request.return_url.trim());
    }

    url.searchParams.set('account_id', request.account_id.trim());

    return url.toString();
  }

  private normalizePayoutCreateRequest(input: unknown): PayoutCreateRequest {
    if (!isRecord(input)) {
      throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
    }

    const accountId = input.account_id;
    const amountMinor = input.amount_minor;
    const currency = input.currency;

    if (!isNonEmptyString(accountId)) {
      throw new ClawSettleError('Missing required field: account_id', 'INVALID_REQUEST', 400, {
        field: 'account_id',
      });
    }

    if (!isNonEmptyString(amountMinor)) {
      throw new ClawSettleError('Missing required field: amount_minor', 'INVALID_REQUEST', 400, {
        field: 'amount_minor',
      });
    }

    if (!isNonEmptyString(currency)) {
      throw new ClawSettleError('Missing required field: currency', 'INVALID_REQUEST', 400, {
        field: 'currency',
      });
    }

    const normalizedCurrency = currency.trim().toUpperCase();
    if (normalizedCurrency !== 'USD') {
      throw new ClawSettleError('Only USD payouts are supported', 'UNSUPPORTED_CURRENCY', 400, {
        currency: normalizedCurrency,
      });
    }

    const metadata = input.metadata;
    if (metadata !== undefined && !isRecord(metadata)) {
      throw new ClawSettleError('metadata must be an object', 'INVALID_REQUEST', 400, {
        field: 'metadata',
      });
    }

    parsePositiveMinorAmount(amountMinor.trim());

    return {
      account_id: accountId.trim(),
      amount_minor: amountMinor.trim(),
      currency: normalizedCurrency,
      metadata: metadata ? { ...metadata } : undefined,
    };
  }

  private normalizeConnectOnboardRequest(input: unknown): PayoutConnectOnboardRequest {
    if (!isRecord(input)) {
      throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
    }

    if (!isNonEmptyString(input.account_id)) {
      throw new ClawSettleError('Missing required field: account_id', 'INVALID_REQUEST', 400, {
        field: 'account_id',
      });
    }

    const request: PayoutConnectOnboardRequest = {
      account_id: input.account_id.trim(),
      refresh_url: isNonEmptyString(input.refresh_url) ? input.refresh_url.trim() : undefined,
      return_url: isNonEmptyString(input.return_url) ? input.return_url.trim() : undefined,
    };

    return request;
  }

  private async computePayoutRequestHash(params: {
    accountId: string;
    amountMinor: string;
    currency: string;
    connectAccountId: string;
    metadata?: Record<string, unknown>;
  }): Promise<string> {
    const canonical = stableStringify({
      account_id: params.accountId,
      amount_minor: params.amountMinor,
      currency: params.currency,
      connect_account_id: params.connectAccountId,
      metadata: params.metadata ?? {},
    });

    return sha256Hex(canonical);
  }

  private async ensureIdempotencyReuseCompatible(existing: PayoutRecord, requestHash: string): Promise<void> {
    if (existing.request_hash !== requestHash) {
      throw new ClawSettleError(
        'Idempotency key reused with different payout payload',
        'IDEMPOTENCY_KEY_REUSED',
        409,
        {
          payout_id: existing.id,
        }
      );
    }
  }

  private async ensureLockApplied(payout: PayoutRecord): Promise<PayoutRecord> {
    if (isNonEmptyString(payout.lock_event_id)) {
      return payout;
    }

    const amount = parsePositiveMinorAmount(payout.amount_minor);
    const ledger = this.getLedgerClient();
    const account = await ledger.getAccountById(payout.account_id);

    if (!/^[0-9]+$/.test(account.balances.available)) {
      throw new ClawSettleError('Ledger account balances malformed', 'LEDGER_INGEST_FAILED', 502, {
        account_id: payout.account_id,
      });
    }

    const availableBig = BigInt(account.balances.available);

    if (availableBig < amount) {
      const existingLock = await ledger.findEventByIdempotencyKey(payout.lock_idempotency_key);
      if (!existingLock) {
        throw new ClawSettleError('Insufficient funds', 'INSUFFICIENT_FUNDS', 400, {
          account_id: payout.account_id,
          amount_minor: payout.amount_minor,
          available_minor: account.balances.available,
        });
      }

      await this.repository.setLockEventIfMissing(payout.id, existingLock.id, this.now());
      const refreshed = await this.repository.findById(payout.id);
      if (!refreshed) {
        throw new ClawSettleError('Payout disappeared after lock recovery', 'INTERNAL_ERROR', 500, {
          payout_id: payout.id,
        });
      }

      return refreshed;
    }

    const transfer = await ledger.transferV1({
      idempotencyKey: payout.lock_idempotency_key,
      currency: 'USD',
      from: {
        account: payout.account_did,
        bucket: 'A',
      },
      to: {
        account: payout.account_did,
        bucket: 'H',
      },
      amountMinor: payout.amount_minor,
      metadata: {
        payout_id: payout.id,
        stage: 'lock',
      },
    });

    const nowIso = this.now();
    await this.repository.setLockEventIfMissing(payout.id, transfer.event_id, nowIso);

    await this.repository.appendAuditEvent({
      payoutId: payout.id,
      eventType: 'payout.lock.applied',
      eventIdempotencyKey: payout.lock_idempotency_key,
      details: {
        lock_event_id: transfer.event_id,
      },
      createdAt: nowIso,
    });

    const refreshed = await this.repository.findById(payout.id);
    if (!refreshed) {
      throw new ClawSettleError('Payout not found after lock apply', 'INTERNAL_ERROR', 500, {
        payout_id: payout.id,
      });
    }

    return refreshed;
  }

  private async submitExternalPayout(payout: PayoutRecord): Promise<string> {
    return this.deriveDeterministicId('po', `${payout.id}:${payout.connect_account_id}`);
  }

  private async ensureSubmitted(payout: PayoutRecord): Promise<PayoutRecord> {
    if (payout.status !== 'initiated') {
      return payout;
    }

    const externalPayoutId = await this.submitExternalPayout(payout);
    const nowIso = this.now();
    const marked = await this.repository.markSubmittedIfInitiated({
      payoutId: payout.id,
      externalPayoutId,
      submittedAt: nowIso,
      updatedAt: nowIso,
    });

    if (marked) {
      await this.repository.appendAuditEvent({
        payoutId: payout.id,
        eventType: 'payout.submitted',
        eventIdempotencyKey: payout.idempotency_key,
        details: {
          external_payout_id: externalPayoutId,
          connect_account_id: payout.connect_account_id,
        },
        createdAt: nowIso,
      });
    }

    const refreshed = await this.repository.findById(payout.id);
    if (!refreshed) {
      throw new ClawSettleError('Payout not found after provider submit', 'INTERNAL_ERROR', 500, {
        payout_id: payout.id,
      });
    }

    return refreshed;
  }

  private async buildInitialPayoutRecord(params: {
    payoutId: string;
    idempotencyKey: string;
    requestHash: string;
    accountId: string;
    accountDid: string;
    connectAccountId: string;
    amountMinor: string;
    currency: string;
    metadata?: Record<string, unknown>;
  }): Promise<PayoutRecord> {
    const nowIso = this.now();
    return {
      id: params.payoutId,
      idempotency_key: params.idempotencyKey,
      request_hash: params.requestHash,
      provider: 'stripe',
      account_id: params.accountId,
      account_did: params.accountDid,
      connect_account_id: params.connectAccountId,
      amount_minor: params.amountMinor,
      currency: params.currency,
      status: 'initiated',
      lock_idempotency_key: `payout:lock:${params.payoutId}`,
      finalize_idempotency_key: `payout:finalize:${params.payoutId}`,
      rollback_idempotency_key: `payout:rollback:${params.payoutId}`,
      metadata: params.metadata,
      created_at: nowIso,
      updated_at: nowIso,
    };
  }

  private async ensureLifecycleClaimed(payoutId: string, from: PayoutStatus, to: PayoutStatus): Promise<PayoutRecord> {
    const nowIso = this.now();
    const claimed = await this.repository.updateStatusIfCurrent({
      payoutId,
      fromStatus: from,
      toStatus: to,
      updatedAt: nowIso,
    });

    if (claimed) {
      const refreshed = await this.repository.findById(payoutId);
      if (!refreshed) {
        throw new ClawSettleError('Payout missing after lifecycle claim', 'INTERNAL_ERROR', 500, {
          payout_id: payoutId,
        });
      }

      await this.repository.appendAuditEvent({
        payoutId,
        eventType: `payout.status.${to}`,
        details: {
          from_status: from,
          to_status: to,
        },
        createdAt: nowIso,
      });

      return refreshed;
    }

    const current = await this.repository.findById(payoutId);
    if (!current) {
      throw new ClawSettleError('Payout not found', 'NOT_FOUND', 404, {
        payout_id: payoutId,
      });
    }

    return current;
  }

  private async finalizeAsPaid(payoutId: string, lifecycleSource: string): Promise<PayoutRecord> {
    let payout = await this.repository.findById(payoutId);
    if (!payout) {
      throw new ClawSettleError('Payout not found', 'NOT_FOUND', 404, {
        payout_id: payoutId,
      });
    }

    if (payout.status === 'paid') {
      return payout;
    }

    if (payout.status === 'failed' || payout.status === 'finalizing_failed') {
      throw new ClawSettleError('Invalid payout status transition', 'INVALID_STATUS_TRANSITION', 409, {
        payout_id: payout.id,
        from_status: payout.status,
        to_status: 'paid',
      });
    }

    if (payout.status === 'submitted') {
      payout = await this.ensureLifecycleClaimed(payout.id, 'submitted', 'finalizing_paid');
    }

    if (payout.status !== 'finalizing_paid' && payout.status !== 'paid') {
      throw new ClawSettleError('Invalid payout status transition', 'INVALID_STATUS_TRANSITION', 409, {
        payout_id: payout.id,
        from_status: payout.status,
        to_status: 'paid',
      });
    }

    if (!payout.finalize_event_id) {
      try {
        const transfer = await this.getLedgerClient().transferV1({
          idempotencyKey: payout.finalize_idempotency_key,
          currency: 'USD',
          from: {
            account: payout.account_did,
            bucket: 'H',
          },
          to: {
            account: `clearing:${this.clearingDomain}`,
            bucket: 'A',
          },
          amountMinor: payout.amount_minor,
          metadata: {
            payout_id: payout.id,
            stage: 'finalize_paid',
            source: lifecycleSource,
          },
        });

        await this.repository.setFinalizeEventIfMissing(payout.id, transfer.event_id, this.now());

        await this.repository.appendAuditEvent({
          payoutId: payout.id,
          eventType: 'payout.finalize.applied',
          eventIdempotencyKey: payout.finalize_idempotency_key,
          details: {
            event_id: transfer.event_id,
            source: lifecycleSource,
          },
          createdAt: this.now(),
        });
      } catch (err) {
        const code = err instanceof ClawSettleError ? err.code : 'LEDGER_INGEST_FAILED';
        const message = safeErrorMessage(err);
        await this.repository.setLifecycleError(payout.id, code, message, this.now());
        throw err;
      }
    }

    const finalizedAt = this.now();
    const marked = await this.repository.updateStatusIfCurrent({
      payoutId: payout.id,
      fromStatus: 'finalizing_paid',
      toStatus: 'paid',
      updatedAt: finalizedAt,
      finalizedAt,
      clearErrors: true,
    });

    if (!marked) {
      const current = await this.repository.findById(payout.id);
      if (!current) {
        throw new ClawSettleError('Payout not found', 'NOT_FOUND', 404, {
          payout_id: payout.id,
        });
      }

      if (current.status === 'paid') {
        return current;
      }

      throw new ClawSettleError('Invalid payout status transition', 'INVALID_STATUS_TRANSITION', 409, {
        payout_id: payout.id,
        from_status: current.status,
        to_status: 'paid',
      });
    }

    await this.repository.appendAuditEvent({
      payoutId: payout.id,
      eventType: 'payout.status.paid',
      details: {
        source: lifecycleSource,
      },
      createdAt: finalizedAt,
    });

    const refreshed = await this.repository.findById(payout.id);
    if (!refreshed) {
      throw new ClawSettleError('Payout not found after paid finalize', 'INTERNAL_ERROR', 500, {
        payout_id: payout.id,
      });
    }

    return refreshed;
  }

  private async finalizeAsFailed(payoutId: string, lifecycleSource: string): Promise<PayoutRecord> {
    let payout = await this.repository.findById(payoutId);
    if (!payout) {
      throw new ClawSettleError('Payout not found', 'NOT_FOUND', 404, {
        payout_id: payoutId,
      });
    }

    if (payout.status === 'failed') {
      return payout;
    }

    if (payout.status === 'paid' || payout.status === 'finalizing_paid') {
      throw new ClawSettleError('Invalid payout status transition', 'INVALID_STATUS_TRANSITION', 409, {
        payout_id: payout.id,
        from_status: payout.status,
        to_status: 'failed',
      });
    }

    if (payout.status === 'submitted') {
      payout = await this.ensureLifecycleClaimed(payout.id, 'submitted', 'finalizing_failed');
    }

    if (payout.status !== 'finalizing_failed' && payout.status !== 'failed') {
      throw new ClawSettleError('Invalid payout status transition', 'INVALID_STATUS_TRANSITION', 409, {
        payout_id: payout.id,
        from_status: payout.status,
        to_status: 'failed',
      });
    }

    if (!payout.rollback_event_id) {
      try {
        const transfer = await this.getLedgerClient().transferV1({
          idempotencyKey: payout.rollback_idempotency_key,
          currency: 'USD',
          from: {
            account: payout.account_did,
            bucket: 'H',
          },
          to: {
            account: payout.account_did,
            bucket: 'A',
          },
          amountMinor: payout.amount_minor,
          metadata: {
            payout_id: payout.id,
            stage: 'rollback_failed',
            source: lifecycleSource,
          },
        });

        await this.repository.setRollbackEventIfMissing(payout.id, transfer.event_id, this.now());

        await this.repository.appendAuditEvent({
          payoutId: payout.id,
          eventType: 'payout.rollback.applied',
          eventIdempotencyKey: payout.rollback_idempotency_key,
          details: {
            event_id: transfer.event_id,
            source: lifecycleSource,
          },
          createdAt: this.now(),
        });
      } catch (err) {
        const code = err instanceof ClawSettleError ? err.code : 'LEDGER_INGEST_FAILED';
        const message = safeErrorMessage(err);
        await this.repository.setLifecycleError(payout.id, code, message, this.now());
        throw err;
      }
    }

    const failedAt = this.now();
    const marked = await this.repository.updateStatusIfCurrent({
      payoutId: payout.id,
      fromStatus: 'finalizing_failed',
      toStatus: 'failed',
      updatedAt: failedAt,
      failedAt,
      clearErrors: true,
    });

    if (!marked) {
      const current = await this.repository.findById(payout.id);
      if (!current) {
        throw new ClawSettleError('Payout not found', 'NOT_FOUND', 404, {
          payout_id: payout.id,
        });
      }

      if (current.status === 'failed') {
        return current;
      }

      throw new ClawSettleError('Invalid payout status transition', 'INVALID_STATUS_TRANSITION', 409, {
        payout_id: payout.id,
        from_status: current.status,
        to_status: 'failed',
      });
    }

    await this.repository.appendAuditEvent({
      payoutId: payout.id,
      eventType: 'payout.status.failed',
      details: {
        source: lifecycleSource,
      },
      createdAt: failedAt,
    });

    const refreshed = await this.repository.findById(payout.id);
    if (!refreshed) {
      throw new ClawSettleError('Payout not found after failed rollback', 'INTERNAL_ERROR', 500, {
        payout_id: payout.id,
      });
    }

    return refreshed;
  }

  async onboardConnectAccount(rawInput: unknown): Promise<{
    ok: true;
    deduped: boolean;
    account: PayoutConnectAccount;
  }> {
    const input = this.normalizeConnectOnboardRequest(rawInput);

    await this.getLedgerClient().getAccountById(input.account_id);

    const existing = await this.repository.findConnectAccountByAccountId(input.account_id);
    if (existing) {
      return {
        ok: true,
        deduped: true,
        account: existing,
      };
    }

    const connectAccountId = await this.deriveDeterministicId('acct', input.account_id, 24);
    const nowIso = this.now();
    const record: PayoutConnectAccount = {
      account_id: input.account_id,
      provider: 'stripe',
      connect_account_id: connectAccountId,
      onboarding_status: 'active',
      onboarding_url: this.buildOnboardingUrl(connectAccountId, input),
      created_at: nowIso,
      updated_at: nowIso,
    };

    await this.repository.upsertConnectAccount(record);

    return {
      ok: true,
      deduped: false,
      account: record,
    };
  }

  async createPayout(rawInput: unknown, idempotencyKey: string): Promise<PayoutCreateResponse> {
    if (!isNonEmptyString(idempotencyKey)) {
      throw new ClawSettleError('Missing idempotency key', 'INVALID_REQUEST', 400, {
        field: 'idempotency_key',
      });
    }

    const input = this.normalizePayoutCreateRequest(rawInput);

    const connectAccount = await this.repository.findConnectAccountByAccountId(input.account_id);
    if (!connectAccount) {
      throw new ClawSettleError(
        'Payout destination not configured for account',
        'PAYOUT_DESTINATION_NOT_CONFIGURED',
        422,
        {
          account_id: input.account_id,
        }
      );
    }

    const account = await this.getLedgerClient().getAccountById(input.account_id);
    const requestHash = await this.computePayoutRequestHash({
      accountId: input.account_id,
      amountMinor: input.amount_minor,
      currency: input.currency,
      connectAccountId: connectAccount.connect_account_id,
      metadata: input.metadata,
    });

    let payout = await this.repository.findByIdempotencyKey(idempotencyKey.trim());
    if (payout) {
      await this.ensureIdempotencyReuseCompatible(payout, requestHash);
    }

    if (!payout) {
      const payoutId = await this.deriveDeterministicId('pout', idempotencyKey.trim(), 28);
      const record = await this.buildInitialPayoutRecord({
        payoutId,
        idempotencyKey: idempotencyKey.trim(),
        requestHash,
        accountId: input.account_id,
        accountDid: account.did,
        connectAccountId: connectAccount.connect_account_id,
        amountMinor: input.amount_minor,
        currency: input.currency,
        metadata: input.metadata,
      });

      try {
        await this.repository.create(record);
        payout = record;
      } catch (err) {
        if (!isSqliteUniqueConstraintError(err)) {
          throw err;
        }

        const raced = await this.repository.findByIdempotencyKey(idempotencyKey.trim());
        if (!raced) {
          throw err;
        }

        await this.ensureIdempotencyReuseCompatible(raced, requestHash);
        payout = raced;
      }
    }

    if (!payout) {
      throw new ClawSettleError('Failed to create payout', 'INTERNAL_ERROR', 500);
    }

    if (payout.status !== 'initiated') {
      return {
        ok: true,
        deduped: true,
        payout,
      };
    }

    let current = await this.ensureLockApplied(payout);
    current = await this.ensureSubmitted(current);

    return {
      ok: true,
      deduped: false,
      payout: current,
    };
  }

  async getPayoutById(payoutId: string): Promise<{ ok: true; payout: PayoutRecord; audit_events: Array<Record<string, unknown>> }> {
    const payout = await this.repository.findById(payoutId);
    if (!payout) {
      throw new ClawSettleError('Payout not found', 'NOT_FOUND', 404, {
        payout_id: payoutId,
      });
    }

    const auditEvents = await this.repository.listAuditEvents(payoutId);

    return {
      ok: true,
      payout,
      audit_events: auditEvents,
    };
  }

  async applyStripeLifecycle(input: PayoutLifecycleHookInput): Promise<void> {
    const payload = input.payload;
    if (payload.direction !== 'payout') {
      return;
    }

    const payout = await this.repository.findByExternalPayoutId(payload.external_payment_id);
    if (!payout) {
      return;
    }

    const source = `${input.event_type}:${input.event_id}`;

    if (payload.status === 'confirmed') {
      await this.finalizeAsPaid(payout.id, source);
      return;
    }

    if (payload.status === 'failed') {
      await this.finalizeAsFailed(payout.id, source);
    }
  }

  async retryPayout(payoutId: string): Promise<PayoutRetryResponse> {
    const payout = await this.repository.findById(payoutId);
    if (!payout) {
      throw new ClawSettleError('Payout not found', 'NOT_FOUND', 404, {
        payout_id: payoutId,
      });
    }

    const previous = payout.status;

    if (payout.status === 'initiated') {
      const locked = await this.ensureLockApplied(payout);
      const submitted = await this.ensureSubmitted(locked);
      return {
        ok: true,
        payout_id: payout.id,
        previous_status: previous,
        status: submitted.status,
        retried: true,
      };
    }

    if (payout.status === 'finalizing_paid') {
      const finalized = await this.finalizeAsPaid(payout.id, 'ops:retry');
      return {
        ok: true,
        payout_id: payout.id,
        previous_status: previous,
        status: finalized.status,
        retried: true,
      };
    }

    if (payout.status === 'finalizing_failed') {
      const finalized = await this.finalizeAsFailed(payout.id, 'ops:retry');
      return {
        ok: true,
        payout_id: payout.id,
        previous_status: previous,
        status: finalized.status,
        retried: true,
      };
    }

    return {
      ok: true,
      payout_id: payout.id,
      previous_status: previous,
      status: payout.status,
      retried: false,
    };
  }

  async listStuckPayouts(query: { olderThanMinutes?: string | null; limit?: string | null }): Promise<{
    ok: true;
    older_than_minutes: number;
    payouts: PayoutRecord[];
  }> {
    const olderThanMinutes = parseStuckMinutes(query.olderThanMinutes ?? null, this.stuckMinutesDefault);
    const limit = parsePositiveLimit(query.limit ?? null, 100, 'limit', 500);

    const nowMs = Date.parse(this.now());
    const baseNowMs = Number.isFinite(nowMs) ? nowMs : Date.now();
    const cutoff = new Date(baseNowMs - olderThanMinutes * 60_000).toISOString();

    const payouts = await this.repository.listStuck({
      statuses: ['initiated', 'submitted', 'finalizing_paid', 'finalizing_failed'],
      beforeOrAtIso: cutoff,
      limit,
    });

    return {
      ok: true,
      older_than_minutes: olderThanMinutes,
      payouts,
    };
  }

  async listFailedPayouts(query: { limit?: string | null }): Promise<{
    ok: true;
    payouts: PayoutRecord[];
  }> {
    const limit = parsePositiveLimit(query.limit ?? null, 100, 'limit', 500);
    const payouts = await this.repository.listFailed(limit);

    return {
      ok: true,
      payouts,
    };
  }

  private async computeArtifactHash(reportBody: {
    date: string;
    totals: DailyPayoutReconciliationReport['totals'];
    rows: DailyPayoutReconciliationRow[];
  }): Promise<string> {
    return sha256Hex(stableStringify(reportBody));
  }

  async buildDailyReconciliationReport(inputDate: string): Promise<DailyPayoutReconciliationReport> {
    const date = parseIsoDateOnly(inputDate);
    const startIso = `${date}T00:00:00.000Z`;
    const startMs = Date.parse(startIso);
    if (!Number.isFinite(startMs)) {
      throw new ClawSettleError('Invalid date', 'INVALID_REQUEST', 400, {
        field: 'date',
      });
    }

    const endIso = new Date(startMs + 24 * 60 * 60 * 1000).toISOString();

    const payouts = await this.repository.listByCreatedRange({
      startIso,
      endIso,
      limit: DEFAULT_RECON_LIMIT,
    });

    const rows: DailyPayoutReconciliationRow[] = payouts.map((payout) => ({
      payout_id: payout.id,
      account_id: payout.account_id,
      external_payout_id: payout.external_payout_id,
      amount_minor: payout.amount_minor,
      currency: payout.currency,
      status: payout.status,
      created_at: payout.created_at,
      submitted_at: payout.submitted_at,
      finalized_at: payout.finalized_at,
      failed_at: payout.failed_at,
      lock_event_id: payout.lock_event_id,
      finalize_event_id: payout.finalize_event_id,
      rollback_event_id: payout.rollback_event_id,
    }));

    const amountByStatus: Record<string, bigint> = {};
    let amountTotal = 0n;

    for (const row of rows) {
      const amount = BigInt(row.amount_minor);
      amountTotal += amount;
      amountByStatus[row.status] = (amountByStatus[row.status] ?? 0n) + amount;
    }

    const totals = {
      payout_count: rows.length,
      amount_minor_total: amountTotal.toString(),
      amount_minor_by_status: Object.keys(amountByStatus)
        .sort()
        .reduce<Record<string, string>>((acc, key) => {
          acc[key] = amountByStatus[key]?.toString() ?? '0';
          return acc;
        }, {}),
    };

    const generatedAt = this.now();
    const artifactSha = await this.computeArtifactHash({
      date,
      totals,
      rows,
    });

    return {
      date,
      generated_at: generatedAt,
      totals,
      rows,
      artifact_sha256: artifactSha,
    };
  }

  toDailyReconciliationCsv(report: DailyPayoutReconciliationReport): string {
    const header = [
      'payout_id',
      'account_id',
      'external_payout_id',
      'amount_minor',
      'currency',
      'status',
      'created_at',
      'submitted_at',
      'finalized_at',
      'failed_at',
      'lock_event_id',
      'finalize_event_id',
      'rollback_event_id',
    ];

    const escape = (value: unknown): string => {
      const raw = value === undefined || value === null ? '' : String(value);
      if (!raw.includes(',') && !raw.includes('"') && !raw.includes('\n')) {
        return raw;
      }
      return `"${raw.replace(/"/g, '""')}"`;
    };

    const lines = [header.join(',')];

    for (const row of report.rows) {
      lines.push(
        [
          row.payout_id,
          row.account_id,
          row.external_payout_id,
          row.amount_minor,
          row.currency,
          row.status,
          row.created_at,
          row.submitted_at,
          row.finalized_at,
          row.failed_at,
          row.lock_event_id,
          row.finalize_event_id,
          row.rollback_event_id,
        ]
          .map((value) => escape(value))
          .join(',')
      );
    }

    return lines.join('\n');
  }
}

export function extractIdempotencyKey(request: Request): string | null {
  const candidate =
    request.headers.get('idempotency-key') ??
    request.headers.get('Idempotency-Key') ??
    request.headers.get('x-idempotency-key') ??
    request.headers.get('X-Idempotency-Key');

  if (!candidate || candidate.trim().length === 0) {
    return null;
  }

  return candidate.trim();
}

export async function parseJsonRequestBody(request: Request): Promise<unknown> {
  const raw = await request.text();
  if (raw.trim().length === 0) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
  }
}
