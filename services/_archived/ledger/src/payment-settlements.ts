/**
 * Machine-payment settlement ingestion for ClawLedger
 *
 * Provider-agnostic settlement layer:
 * - idempotent ingest
 * - fail-closed status transitions
 * - deterministic settlement lookups/pagination
 * - exactly-once side effects under natural-key ingest races
 */

import { AccountRepository, InsufficientFundsError } from './accounts';
import { EventRepository, computeEventHash } from './events';
import type {
  AccountId,
  Env,
  EventType,
  LedgerEvent,
  MachinePaymentSettlement,
  PaymentSettlementDirection,
  PaymentSettlementIngestRequest,
  PaymentSettlementIngestResponse,
  PaymentSettlementListQuery,
  PaymentSettlementListResponse,
  PaymentSettlementStatus,
} from './types';

const PAYMENT_SETTLEMENT_DIRECTIONS: readonly PaymentSettlementDirection[] = [
  'payin',
  'refund',
  'payout',
] as const;

const PAYMENT_SETTLEMENT_STATUSES: readonly PaymentSettlementStatus[] = [
  'pending',
  'confirmed',
  'failed',
  'reversed',
] as const;

const MAX_LIST_LIMIT = 200;
const MAX_SETTLEMENT_RACE_RETRIES = 6;

interface NormalizedSettlementInput {
  provider: string;
  external_payment_id: string;
  direction: PaymentSettlementDirection;
  status: PaymentSettlementStatus;
  account_id: string;
  amount_minor: string;
  amount_minor_bigint: bigint;
  currency: string;
  network?: string;
  rail?: string;
  metadata?: Record<string, unknown>;
  provider_created_at?: string;
  provider_updated_at?: string;
  settled_at?: string;
}

interface SettlementStatusUpdate {
  status: PaymentSettlementStatus;
  network?: string;
  rail?: string;
  metadata?: Record<string, unknown>;
  provider_created_at?: string;
  provider_updated_at?: string;
  settled_at?: string;
  updated_at: string;
}

export interface PaymentSettlementIngestionRecord {
  idempotency_key: string;
  request_hash: string;
  settlement_id: string;
  response_json: string;
  created_at: string;
}

export interface PaymentSettlementRepositoryLike {
  findById(id: string): Promise<MachinePaymentSettlement | null>;

  findByNaturalKey(
    provider: string,
    externalPaymentId: string,
    direction: PaymentSettlementDirection
  ): Promise<MachinePaymentSettlement | null>;

  findByProviderExternal(
    provider: string,
    externalPaymentId: string,
    direction?: PaymentSettlementDirection
  ): Promise<MachinePaymentSettlement[]>;

  createSettlement(settlement: MachinePaymentSettlement): Promise<void>;

  updateStatusIfCurrent(
    settlementId: string,
    fromStatus: PaymentSettlementStatus,
    update: SettlementStatusUpdate
  ): Promise<boolean>;

  updateLatestEventId(
    settlementId: string,
    latestEventId: string,
    updatedAt: string
  ): Promise<void>;

  deleteByIdIfStatusAndNoEvent(
    settlementId: string,
    status: PaymentSettlementStatus
  ): Promise<boolean>;

  listSettlements(query: PaymentSettlementListQuery): Promise<PaymentSettlementListResponse>;

  findIngestionByIdempotencyKey(
    idempotencyKey: string
  ): Promise<PaymentSettlementIngestionRecord | null>;

  createIngestion(record: PaymentSettlementIngestionRecord): Promise<void>;
}

interface PaymentAccountRepositoryLike {
  findById(id: AccountId): Promise<{ id: string } | null>;
  creditAvailable(id: AccountId, amount: bigint): Promise<unknown>;
  debitAvailable(id: AccountId, amount: bigint): Promise<unknown>;
}

interface PaymentEventRepositoryLike {
  findById(id: string): Promise<LedgerEvent | null>;
  getLastEventHash(): Promise<string>;
  create(
    idempotencyKey: string,
    eventType: EventType,
    accountId: string,
    amount: bigint,
    bucket: 'available',
    previousHash: string,
    eventHash: string,
    toAccountId?: string,
    metadata?: Record<string, unknown>,
    createdAt?: string
  ): Promise<LedgerEvent>;
}

export interface PaymentSettlementServiceDeps {
  settlementRepository?: PaymentSettlementRepositoryLike;
  accountRepository?: PaymentAccountRepositoryLike;
  eventRepository?: PaymentEventRepositoryLike;
  now?: () => string;
}

interface CursorParts {
  created_at: string;
  id: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
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

function isSqliteUniqueConstraintError(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return message.includes('UNIQUE constraint failed');
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
      throw new Error(`Unsupported payload type for stable stringify: ${typeof value}`);
  }
}

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return toHex(new Uint8Array(digest));
}

function generateSettlementId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).slice(2, 10);
  return `set_${timestamp}_${random}`;
}

function parseCursorParts(cursor: string | undefined): CursorParts | null {
  if (!cursor) {
    return null;
  }

  const parts = cursor.split('::');
  if (parts.length !== 2) {
    return null;
  }

  const created_at = parts[0]?.trim();
  const id = parts[1]?.trim();

  if (!created_at || !id) {
    return null;
  }

  return { created_at, id };
}

function getD1Changes(result: unknown): number {
  if (!isRecord(result)) {
    return 0;
  }

  const meta = result.meta;
  if (!isRecord(meta)) {
    return 0;
  }

  const changes = meta.changes;
  return typeof changes === 'number' ? changes : 0;
}

export function encodeSettlementCursor(createdAt: string, id: string): string {
  return `${createdAt}::${id}`;
}

export function decodeSettlementCursor(cursor: string | undefined): CursorParts | null {
  return parseCursorParts(cursor);
}

export function isValidPaymentSettlementDirection(
  value: string
): value is PaymentSettlementDirection {
  return PAYMENT_SETTLEMENT_DIRECTIONS.includes(value as PaymentSettlementDirection);
}

export function isValidPaymentSettlementStatus(
  value: string
): value is PaymentSettlementStatus {
  return PAYMENT_SETTLEMENT_STATUSES.includes(value as PaymentSettlementStatus);
}

export function isValidPaymentStatusTransition(
  fromStatus: PaymentSettlementStatus,
  toStatus: PaymentSettlementStatus
): boolean {
  if (fromStatus === toStatus) {
    return true;
  }

  switch (fromStatus) {
    case 'pending':
      return toStatus === 'confirmed' || toStatus === 'failed' || toStatus === 'reversed';
    case 'confirmed':
      return toStatus === 'reversed';
    case 'failed':
    case 'reversed':
      return false;
  }
}

function parsePositiveAmountMinor(value: string): bigint {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error('amount_minor must be a positive integer string');
  }

  const amount = BigInt(value);
  if (amount <= 0n) {
    throw new Error('amount_minor must be greater than zero');
  }

  return amount;
}

function parseSettlementRow(row: Record<string, unknown>): MachinePaymentSettlement {
  return {
    id: String(row.id),
    provider: String(row.provider),
    external_payment_id: String(row.external_payment_id),
    direction: String(row.direction) as PaymentSettlementDirection,
    status: String(row.status) as PaymentSettlementStatus,
    account_id: String(row.account_id),
    amount_minor: String(row.amount_minor),
    currency: String(row.currency),
    network: row.network ? String(row.network) : undefined,
    rail: row.rail ? String(row.rail) : undefined,
    metadata: parseJsonObject(row.metadata),
    provider_created_at: row.provider_created_at ? String(row.provider_created_at) : undefined,
    provider_updated_at: row.provider_updated_at ? String(row.provider_updated_at) : undefined,
    settled_at: row.settled_at ? String(row.settled_at) : undefined,
    latest_event_id: row.latest_event_id ? String(row.latest_event_id) : undefined,
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
  };
}

function parseIngestionRow(
  row: Record<string, unknown>
): PaymentSettlementIngestionRecord {
  return {
    idempotency_key: String(row.idempotency_key),
    request_hash: String(row.request_hash),
    settlement_id: String(row.settlement_id),
    response_json: String(row.response_json),
    created_at: String(row.created_at),
  };
}

export function resolveSettlementEventType(
  direction: PaymentSettlementDirection,
  status: PaymentSettlementStatus
): EventType | null {
  if (direction === 'payin' && status === 'confirmed') {
    return 'payin_settle';
  }

  if ((direction === 'payin' && status === 'reversed') ||
      (direction === 'refund' && status === 'confirmed')) {
    return 'payin_reverse';
  }

  if (direction === 'payout' && status === 'confirmed') {
    return 'payout_settle';
  }

  return null;
}

export class PaymentSettlementError extends Error {
  constructor(
    message: string,
    public code: string,
    public status = 400,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'PaymentSettlementError';
  }
}

export class PaymentSettlementRepository implements PaymentSettlementRepositoryLike {
  constructor(private db: D1Database) {}

  async findById(id: string): Promise<MachinePaymentSettlement | null> {
    const result = await this.db
      .prepare(
        `SELECT id, provider, external_payment_id, direction, status, account_id,
                amount_minor, currency, network, rail, metadata,
                provider_created_at, provider_updated_at, settled_at,
                latest_event_id, created_at, updated_at
         FROM payment_settlements
         WHERE id = ?
         LIMIT 1`
      )
      .bind(id)
      .first();

    if (!result) {
      return null;
    }

    return parseSettlementRow(result);
  }

  async findByNaturalKey(
    provider: string,
    externalPaymentId: string,
    direction: PaymentSettlementDirection
  ): Promise<MachinePaymentSettlement | null> {
    const result = await this.db
      .prepare(
        `SELECT id, provider, external_payment_id, direction, status, account_id,
                amount_minor, currency, network, rail, metadata,
                provider_created_at, provider_updated_at, settled_at,
                latest_event_id, created_at, updated_at
         FROM payment_settlements
         WHERE provider = ? AND external_payment_id = ? AND direction = ?
         LIMIT 1`
      )
      .bind(provider, externalPaymentId, direction)
      .first();

    if (!result) {
      return null;
    }

    return parseSettlementRow(result);
  }

  async findByProviderExternal(
    provider: string,
    externalPaymentId: string,
    direction?: PaymentSettlementDirection
  ): Promise<MachinePaymentSettlement[]> {
    const bindings: (string | number)[] = [provider, externalPaymentId];

    const whereDirection = direction ? 'AND direction = ?' : '';
    if (direction) {
      bindings.push(direction);
    }

    const results = await this.db
      .prepare(
        `SELECT id, provider, external_payment_id, direction, status, account_id,
                amount_minor, currency, network, rail, metadata,
                provider_created_at, provider_updated_at, settled_at,
                latest_event_id, created_at, updated_at
         FROM payment_settlements
         WHERE provider = ? AND external_payment_id = ? ${whereDirection}
         ORDER BY created_at DESC, id DESC`
      )
      .bind(...bindings)
      .all();

    return (results.results || []).map((row) =>
      parseSettlementRow(row as Record<string, unknown>)
    );
  }

  async createSettlement(settlement: MachinePaymentSettlement): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO payment_settlements (
          id, provider, external_payment_id, direction, status, account_id,
          amount_minor, currency, network, rail, metadata,
          provider_created_at, provider_updated_at, settled_at,
          latest_event_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        settlement.id,
        settlement.provider,
        settlement.external_payment_id,
        settlement.direction,
        settlement.status,
        settlement.account_id,
        settlement.amount_minor,
        settlement.currency,
        settlement.network ?? null,
        settlement.rail ?? null,
        settlement.metadata ? JSON.stringify(settlement.metadata) : null,
        settlement.provider_created_at ?? null,
        settlement.provider_updated_at ?? null,
        settlement.settled_at ?? null,
        settlement.latest_event_id ?? null,
        settlement.created_at,
        settlement.updated_at
      )
      .run();
  }

  async updateStatusIfCurrent(
    settlementId: string,
    fromStatus: PaymentSettlementStatus,
    update: SettlementStatusUpdate
  ): Promise<boolean> {
    const result = await this.db
      .prepare(
        `UPDATE payment_settlements
         SET status = ?,
             network = ?,
             rail = ?,
             metadata = ?,
             provider_created_at = ?,
             provider_updated_at = ?,
             settled_at = ?,
             updated_at = ?
         WHERE id = ? AND status = ?`
      )
      .bind(
        update.status,
        update.network ?? null,
        update.rail ?? null,
        update.metadata ? JSON.stringify(update.metadata) : null,
        update.provider_created_at ?? null,
        update.provider_updated_at ?? null,
        update.settled_at ?? null,
        update.updated_at,
        settlementId,
        fromStatus
      )
      .run();

    return getD1Changes(result) === 1;
  }

  async updateLatestEventId(
    settlementId: string,
    latestEventId: string,
    updatedAt: string
  ): Promise<void> {
    await this.db
      .prepare(
        `UPDATE payment_settlements
         SET latest_event_id = ?, updated_at = ?
         WHERE id = ?`
      )
      .bind(latestEventId, updatedAt, settlementId)
      .run();
  }

  async deleteByIdIfStatusAndNoEvent(
    settlementId: string,
    status: PaymentSettlementStatus
  ): Promise<boolean> {
    const result = await this.db
      .prepare(
        `DELETE FROM payment_settlements
         WHERE id = ? AND status = ? AND latest_event_id IS NULL`
      )
      .bind(settlementId, status)
      .run();

    return getD1Changes(result) === 1;
  }

  async listSettlements(query: PaymentSettlementListQuery): Promise<PaymentSettlementListResponse> {
    const where: string[] = [];
    const bindings: (string | number)[] = [];

    if (query.account_id) {
      where.push('account_id = ?');
      bindings.push(query.account_id);
    }

    if (query.status) {
      where.push('status = ?');
      bindings.push(query.status);
    }

    if (query.provider) {
      where.push('provider = ?');
      bindings.push(query.provider);
    }

    if (query.direction) {
      where.push('direction = ?');
      bindings.push(query.direction);
    }

    const cursor = decodeSettlementCursor(query.cursor);
    if (query.cursor && !cursor) {
      throw new PaymentSettlementError('Invalid cursor', 'INVALID_CURSOR', 400);
    }

    if (cursor) {
      where.push('(created_at < ? OR (created_at = ? AND id < ?))');
      bindings.push(cursor.created_at, cursor.created_at, cursor.id);
    }

    const limit = Math.min(
      Math.max(Number.isFinite(query.limit) ? Number(query.limit) : 50, 1),
      MAX_LIST_LIMIT
    );

    bindings.push(limit + 1);

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    const results = await this.db
      .prepare(
        `SELECT id, provider, external_payment_id, direction, status, account_id,
                amount_minor, currency, network, rail, metadata,
                provider_created_at, provider_updated_at, settled_at,
                latest_event_id, created_at, updated_at
         FROM payment_settlements
         ${whereClause}
         ORDER BY created_at DESC, id DESC
         LIMIT ?`
      )
      .bind(...bindings)
      .all();

    const rows = (results.results || []).map((row) =>
      parseSettlementRow(row as Record<string, unknown>)
    );

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;
    const last = page.at(-1);

    return {
      settlements: page,
      next_cursor: hasMore && last ? encodeSettlementCursor(last.created_at, last.id) : undefined,
    };
  }

  async findIngestionByIdempotencyKey(
    idempotencyKey: string
  ): Promise<PaymentSettlementIngestionRecord | null> {
    const result = await this.db
      .prepare(
        `SELECT idempotency_key, request_hash, settlement_id, response_json, created_at
         FROM payment_settlement_ingestions
         WHERE idempotency_key = ?
         LIMIT 1`
      )
      .bind(idempotencyKey)
      .first();

    if (!result) {
      return null;
    }

    return parseIngestionRow(result);
  }

  async createIngestion(record: PaymentSettlementIngestionRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO payment_settlement_ingestions (
          idempotency_key, request_hash, settlement_id, response_json, created_at
        ) VALUES (?, ?, ?, ?, ?)`
      )
      .bind(
        record.idempotency_key,
        record.request_hash,
        record.settlement_id,
        record.response_json,
        record.created_at
      )
      .run();
  }
}

export class PaymentSettlementService {
  private settlementRepository: PaymentSettlementRepositoryLike;
  private accountRepository: PaymentAccountRepositoryLike;
  private eventRepository: PaymentEventRepositoryLike;
  private now: () => string;

  constructor(env: Env, deps: PaymentSettlementServiceDeps = {}) {
    this.settlementRepository = deps.settlementRepository ?? new PaymentSettlementRepository(env.DB);
    this.accountRepository = deps.accountRepository ?? new AccountRepository(env.DB);
    this.eventRepository = deps.eventRepository ?? new EventRepository(env.DB);
    this.now = deps.now ?? (() => new Date().toISOString());
  }

  private async buildRequestHash(input: NormalizedSettlementInput): Promise<string> {
    const canonical = {
      provider: input.provider,
      external_payment_id: input.external_payment_id,
      direction: input.direction,
      status: input.status,
      account_id: input.account_id,
      amount_minor: input.amount_minor,
      currency: input.currency,
      network: input.network,
      rail: input.rail,
      metadata: input.metadata,
      provider_created_at: input.provider_created_at,
      provider_updated_at: input.provider_updated_at,
      settled_at: input.settled_at,
    };

    return sha256Hex(stableStringify(canonical));
  }

  private normalizeIngestRequest(
    request: PaymentSettlementIngestRequest
  ): NormalizedSettlementInput {
    if (!isNonEmptyString(request.provider)) {
      throw new PaymentSettlementError('provider is required', 'INVALID_REQUEST', 400);
    }

    if (!isNonEmptyString(request.external_payment_id)) {
      throw new PaymentSettlementError(
        'external_payment_id is required',
        'INVALID_REQUEST',
        400
      );
    }

    if (!isNonEmptyString(request.direction) || !isValidPaymentSettlementDirection(request.direction)) {
      throw new PaymentSettlementError(
        'direction must be one of: payin|refund|payout',
        'INVALID_REQUEST',
        400
      );
    }

    if (!isNonEmptyString(request.status) || !isValidPaymentSettlementStatus(request.status)) {
      throw new PaymentSettlementError(
        'status must be one of: pending|confirmed|failed|reversed',
        'INVALID_REQUEST',
        400
      );
    }

    if (!isNonEmptyString(request.account_id)) {
      throw new PaymentSettlementError('account_id is required', 'INVALID_REQUEST', 400);
    }

    if (!isNonEmptyString(request.amount_minor)) {
      throw new PaymentSettlementError('amount_minor is required', 'INVALID_REQUEST', 400);
    }

    let amount_minor_bigint: bigint;
    try {
      amount_minor_bigint = parsePositiveAmountMinor(request.amount_minor.trim());
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Invalid amount_minor';
      throw new PaymentSettlementError(message, 'INVALID_REQUEST', 400);
    }

    if (!isNonEmptyString(request.currency)) {
      throw new PaymentSettlementError('currency is required', 'INVALID_REQUEST', 400);
    }

    const currency = request.currency.trim().toUpperCase();
    if (!/^[A-Z]{3}$/.test(currency)) {
      throw new PaymentSettlementError(
        'currency must be a 3-letter ISO code',
        'INVALID_REQUEST',
        400
      );
    }

    if (request.metadata !== undefined && !isRecord(request.metadata)) {
      throw new PaymentSettlementError('metadata must be an object', 'INVALID_REQUEST', 400);
    }

    return {
      provider: request.provider.trim(),
      external_payment_id: request.external_payment_id.trim(),
      direction: request.direction,
      status: request.status,
      account_id: request.account_id.trim(),
      amount_minor: request.amount_minor.trim(),
      amount_minor_bigint,
      currency,
      network: isNonEmptyString(request.network) ? request.network.trim() : undefined,
      rail: isNonEmptyString(request.rail) ? request.rail.trim() : undefined,
      metadata: request.metadata,
      provider_created_at: isNonEmptyString(request.provider_created_at)
        ? request.provider_created_at.trim()
        : undefined,
      provider_updated_at: isNonEmptyString(request.provider_updated_at)
        ? request.provider_updated_at.trim()
        : undefined,
      settled_at: isNonEmptyString(request.settled_at) ? request.settled_at.trim() : undefined,
    };
  }

  private parseCachedResponse(
    ingestion: PaymentSettlementIngestionRecord,
    idempotencyKey: string
  ): PaymentSettlementIngestResponse {
    try {
      const parsed = JSON.parse(ingestion.response_json);
      if (!isRecord(parsed) || !isRecord(parsed.idempotency)) {
        throw new Error('Invalid cached response shape');
      }

      const parsedResponse = parsed as unknown as PaymentSettlementIngestResponse;

      return {
        ...parsedResponse,
        idempotency: {
          ...parsedResponse.idempotency,
          key: idempotencyKey,
          replayed: true,
        },
      };
    } catch {
      throw new PaymentSettlementError(
        'Corrupt idempotency replay record',
        'INTERNAL_ERROR',
        500
      );
    }
  }

  private buildCreateSettlement(
    input: NormalizedSettlementInput,
    now: string
  ): MachinePaymentSettlement {
    return {
      id: generateSettlementId(),
      provider: input.provider,
      external_payment_id: input.external_payment_id,
      direction: input.direction,
      status: input.status,
      account_id: input.account_id,
      amount_minor: input.amount_minor,
      currency: input.currency,
      network: input.network,
      rail: input.rail,
      metadata: input.metadata,
      provider_created_at: input.provider_created_at,
      provider_updated_at: input.provider_updated_at,
      settled_at:
        input.settled_at ??
        (input.status === 'confirmed' || input.status === 'reversed' ? now : undefined),
      latest_event_id: undefined,
      created_at: now,
      updated_at: now,
    };
  }

  private assertImmutableSettlementFields(
    existing: MachinePaymentSettlement,
    input: NormalizedSettlementInput
  ): void {
    if (
      existing.account_id !== input.account_id ||
      existing.amount_minor !== input.amount_minor ||
      existing.currency !== input.currency
    ) {
      throw new PaymentSettlementError(
        'Natural-key duplicate conflicts with immutable settlement fields',
        'DUPLICATE_CONFLICT',
        409,
        {
          provider: input.provider,
          external_payment_id: input.external_payment_id,
          direction: input.direction,
        }
      );
    }
  }

  private buildStatusUpdate(
    previous: MachinePaymentSettlement,
    input: NormalizedSettlementInput,
    status: PaymentSettlementStatus,
    now: string
  ): SettlementStatusUpdate {
    return {
      status,
      network: input.network ?? previous.network,
      rail: input.rail ?? previous.rail,
      metadata: input.metadata ?? previous.metadata,
      provider_created_at: input.provider_created_at ?? previous.provider_created_at,
      provider_updated_at: input.provider_updated_at ?? previous.provider_updated_at,
      settled_at:
        input.settled_at ??
        previous.settled_at ??
        (status === 'confirmed' || status === 'reversed' ? now : undefined),
      updated_at: now,
    };
  }

  private applyStatusUpdate(
    previous: MachinePaymentSettlement,
    update: SettlementStatusUpdate
  ): MachinePaymentSettlement {
    return {
      ...previous,
      status: update.status,
      network: update.network,
      rail: update.rail,
      metadata: update.metadata,
      provider_created_at: update.provider_created_at,
      provider_updated_at: update.provider_updated_at,
      settled_at: update.settled_at,
      updated_at: update.updated_at,
    };
  }

  private buildRollbackUpdate(
    previous: MachinePaymentSettlement,
    now: string
  ): SettlementStatusUpdate {
    return {
      status: previous.status,
      network: previous.network,
      rail: previous.rail,
      metadata: previous.metadata,
      provider_created_at: previous.provider_created_at,
      provider_updated_at: previous.provider_updated_at,
      settled_at: previous.settled_at,
      updated_at: now,
    };
  }

  private async createSettlementEvent(
    settlementId: string,
    input: NormalizedSettlementInput,
    eventType: EventType,
    now: string
  ): Promise<LedgerEvent> {
    if (eventType === 'payin_settle') {
      await this.accountRepository.creditAvailable(
        input.account_id,
        input.amount_minor_bigint
      );
    }

    if (eventType === 'payin_reverse') {
      try {
        await this.accountRepository.debitAvailable(
          input.account_id,
          input.amount_minor_bigint
        );
      } catch (err) {
        if (err instanceof InsufficientFundsError) {
          throw new PaymentSettlementError(
            'Insufficient funds for payin reversal/refund settlement',
            'INSUFFICIENT_FUNDS',
            422,
            {
              account_id: err.accountId,
              bucket: err.bucket,
              requested: err.requested.toString(),
              available: err.available.toString(),
            }
          );
        }
        throw err;
      }
    }

    // payout_settle intentionally does not mutate balances here to avoid double-debit behavior.

    const previousHash = await this.eventRepository.getLastEventHash();
    const eventIdempotencyKey = `payment_settlement:${settlementId}:${eventType}`;

    const eventHash = await computeEventHash(
      previousHash,
      eventType,
      input.account_id,
      undefined,
      input.amount_minor_bigint,
      'available',
      eventIdempotencyKey,
      now
    );

    const metadata: Record<string, unknown> = {
      payment_settlement: {
        settlement_id: settlementId,
        provider: input.provider,
        external_payment_id: input.external_payment_id,
        direction: input.direction,
        status: input.status,
        network: input.network,
        rail: input.rail,
      },
      provider_metadata: input.metadata,
    };

    return this.eventRepository.create(
      eventIdempotencyKey,
      eventType,
      input.account_id,
      input.amount_minor_bigint,
      'available',
      previousHash,
      eventHash,
      undefined,
      metadata,
      now
    );
  }

  private async persistIngestionRecord(
    idempotencyKey: string,
    requestHash: string,
    settlementId: string,
    response: PaymentSettlementIngestResponse,
    now: string
  ): Promise<PaymentSettlementIngestResponse> {
    const ingestionRecord: PaymentSettlementIngestionRecord = {
      idempotency_key: idempotencyKey,
      request_hash: requestHash,
      settlement_id: settlementId,
      response_json: JSON.stringify(response),
      created_at: now,
    };

    try {
      await this.settlementRepository.createIngestion(ingestionRecord);
    } catch (err) {
      if (!isSqliteUniqueConstraintError(err)) {
        throw err;
      }

      const raced = await this.settlementRepository.findIngestionByIdempotencyKey(
        idempotencyKey
      );

      if (!raced) {
        throw err;
      }

      if (raced.request_hash !== requestHash) {
        throw new PaymentSettlementError(
          'Idempotency key already used with a different payload',
          'IDEMPOTENCY_KEY_REUSED',
          409
        );
      }

      return this.parseCachedResponse(raced, idempotencyKey);
    }

    return response;
  }

  async ingest(
    request: PaymentSettlementIngestRequest,
    idempotencyKey: string
  ): Promise<PaymentSettlementIngestResponse> {
    if (!isNonEmptyString(idempotencyKey)) {
      throw new PaymentSettlementError(
        'Idempotency-Key header is required',
        'MISSING_IDEMPOTENCY_KEY',
        400
      );
    }

    const normalized = this.normalizeIngestRequest(request);
    const requestHash = await this.buildRequestHash(normalized);

    const replay = await this.settlementRepository.findIngestionByIdempotencyKey(
      idempotencyKey
    );

    if (replay) {
      if (replay.request_hash !== requestHash) {
        throw new PaymentSettlementError(
          'Idempotency key already used with a different payload',
          'IDEMPOTENCY_KEY_REUSED',
          409
        );
      }

      return this.parseCachedResponse(replay, idempotencyKey);
    }

    const account = await this.accountRepository.findById(normalized.account_id);
    if (!account) {
      throw new PaymentSettlementError('account_id not found', 'NOT_FOUND', 404, {
        field: 'account_id',
      });
    }

    for (let attempt = 0; attempt < MAX_SETTLEMENT_RACE_RETRIES; attempt += 1) {
      const now = this.now();
      let claimedCreate = false;

      let settlement = await this.settlementRepository.findByNaturalKey(
        normalized.provider,
        normalized.external_payment_id,
        normalized.direction
      );

      if (!settlement) {
        const candidate = this.buildCreateSettlement(normalized, now);

        try {
          await this.settlementRepository.createSettlement(candidate);
          settlement = candidate;
          claimedCreate = true;
        } catch (err) {
          if (isSqliteUniqueConstraintError(err)) {
            // Lost the natural-key create race. Re-read in next attempt.
            continue;
          }
          throw err;
        }
      }

      this.assertImmutableSettlementFields(settlement, normalized);

      const previousSnapshot = settlement;
      let transitioned = false;

      if (!claimedCreate && settlement.status !== normalized.status) {
        if (!isValidPaymentStatusTransition(settlement.status, normalized.status)) {
          throw new PaymentSettlementError(
            `Invalid status transition: ${settlement.status} -> ${normalized.status}`,
            'INVALID_STATUS_TRANSITION',
            409,
            {
              from: settlement.status,
              to: normalized.status,
            }
          );
        }

        const statusUpdate = this.buildStatusUpdate(
          settlement,
          normalized,
          normalized.status,
          now
        );

        const claimedTransition = await this.settlementRepository.updateStatusIfCurrent(
          settlement.id,
          settlement.status,
          statusUpdate
        );

        if (!claimedTransition) {
          // Lost race to another transition writer. Retry with fresh state.
          continue;
        }

        settlement = this.applyStatusUpdate(settlement, statusUpdate);
        transitioned = true;
      }

      const deduped = !claimedCreate && !transitioned;

      const eventType =
        claimedCreate || transitioned
          ? resolveSettlementEventType(normalized.direction, normalized.status)
          : null;

      let createdEvent: LedgerEvent | null = null;

      if (eventType) {
        try {
          createdEvent = await this.createSettlementEvent(
            settlement.id,
            normalized,
            eventType,
            this.now()
          );

          await this.settlementRepository.updateLatestEventId(
            settlement.id,
            createdEvent.id,
            this.now()
          );
        } catch (err) {
          if (err instanceof PaymentSettlementError && err.code === 'INSUFFICIENT_FUNDS') {
            if (claimedCreate) {
              try {
                await this.settlementRepository.deleteByIdIfStatusAndNoEvent(
                  settlement.id,
                  settlement.status
                );
              } catch {
                // best effort rollback
              }
            } else if (transitioned) {
              const rollbackUpdate = this.buildRollbackUpdate(previousSnapshot, this.now());
              try {
                await this.settlementRepository.updateStatusIfCurrent(
                  settlement.id,
                  settlement.status,
                  rollbackUpdate
                );
              } catch {
                // best effort rollback
              }
            }
          }

          throw err;
        }
      }

      const persisted =
        (await this.settlementRepository.findById(settlement.id)) ??
        {
          ...settlement,
          latest_event_id: createdEvent?.id ?? settlement.latest_event_id,
          updated_at: this.now(),
        };

      const response: PaymentSettlementIngestResponse = {
        settlement: persisted,
        idempotency: {
          key: idempotencyKey,
          replayed: false,
          deduped,
        },
        event: createdEvent
          ? {
              id: createdEvent.id,
              event_type: createdEvent.eventType,
              event_hash: createdEvent.eventHash,
              created_at: createdEvent.createdAt,
            }
          : undefined,
      };

      return this.persistIngestionRecord(
        idempotencyKey,
        requestHash,
        persisted.id,
        response,
        now
      );
    }

    throw new PaymentSettlementError(
      'Settlement ingest contention exceeded retry budget',
      'CONCURRENT_INGESTION_CONFLICT',
      409
    );
  }

  async getByProviderExternal(
    provider: string,
    externalPaymentId: string,
    direction?: PaymentSettlementDirection
  ): Promise<MachinePaymentSettlement[]> {
    if (!isNonEmptyString(provider)) {
      throw new PaymentSettlementError('provider is required', 'INVALID_REQUEST', 400);
    }

    if (!isNonEmptyString(externalPaymentId)) {
      throw new PaymentSettlementError(
        'external_payment_id is required',
        'INVALID_REQUEST',
        400
      );
    }

    if (direction && !isValidPaymentSettlementDirection(direction)) {
      throw new PaymentSettlementError(
        'direction must be one of: payin|refund|payout',
        'INVALID_REQUEST',
        400
      );
    }

    return this.settlementRepository.findByProviderExternal(
      provider.trim(),
      externalPaymentId.trim(),
      direction
    );
  }

  async list(query: PaymentSettlementListQuery): Promise<PaymentSettlementListResponse> {
    if (query.status && !isValidPaymentSettlementStatus(query.status)) {
      throw new PaymentSettlementError(
        'status must be one of: pending|confirmed|failed|reversed',
        'INVALID_REQUEST',
        400
      );
    }

    if (query.direction && !isValidPaymentSettlementDirection(query.direction)) {
      throw new PaymentSettlementError(
        'direction must be one of: payin|refund|payout',
        'INVALID_REQUEST',
        400
      );
    }

    if (query.cursor && !decodeSettlementCursor(query.cursor)) {
      throw new PaymentSettlementError('Invalid cursor', 'INVALID_CURSOR', 400);
    }

    const normalizedLimit =
      query.limit === undefined
        ? 50
        : Math.min(Math.max(Number(query.limit), 1), MAX_LIST_LIMIT);

    return this.settlementRepository.listSettlements({
      ...query,
      provider: query.provider?.trim(),
      account_id: query.account_id?.trim(),
      limit: normalizedLimit,
    });
  }
}
