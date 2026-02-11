import type {
  Env,
  PaymentSettlementIngestPayload,
  RetryForwardingResponse,
  StripeEvent,
  StripeWebhookOutboxRecord,
  StripeWebhookRecord,
  StripeWebhookResponse,
} from './types';

const DEFAULT_STRIPE_TOLERANCE_SECONDS = 300;
const DEFAULT_RETRY_BATCH_LIMIT = 25;
const DEFAULT_RETRY_BASE_SECONDS = 15;
const DEFAULT_RETRY_MAX_SECONDS = 300;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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

function safeEqualText(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return out === 0;
}

function parseBooleanFlag(value: string | undefined): boolean {
  if (!value) {
    return false;
  }

  const normalized = value.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'y';
}

function parsePositiveIntegerEnv(
  value: string | undefined,
  fallback: number,
  field: string
): number {
  if (!value || value.trim().length === 0) {
    return fallback;
  }

  const parsed = Number.parseInt(value.trim(), 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new ClawSettleError(
      'Invalid numeric environment configuration',
      'DEPENDENCY_NOT_CONFIGURED',
      503,
      { field }
    );
  }

  return parsed;
}

function toOutboxBoolean(value: unknown): boolean {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'number') {
    return value !== 0;
  }

  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return normalized === '1' || normalized === 'true' || normalized === 'yes';
  }

  return false;
}

function computeRetryDelaySeconds(
  attempts: number,
  baseSeconds: number,
  maxSeconds: number
): number {
  const boundedAttempts = Math.max(1, attempts);
  const delay = baseSeconds * Math.pow(2, boundedAttempts - 1);
  return Math.min(maxSeconds, Math.max(baseSeconds, Math.floor(delay)));
}

function truncateErrorMessage(value: unknown): string {
  const text = value instanceof Error ? value.message : String(value ?? 'Unknown ledger failure');
  return text.length > 500 ? text.slice(0, 500) : text;
}

type SettleEnvironment = 'staging' | 'production';

function resolveSettleEnvironment(env: Env): SettleEnvironment {
  const raw = env.SETTLE_ENV?.trim().toLowerCase();

  if (!raw || raw === 'production' || raw === 'prod' || raw === 'live') {
    return 'production';
  }

  if (raw === 'staging' || raw === 'stage') {
    return 'staging';
  }

  throw new ClawSettleError(
    'Invalid settle environment configuration',
    'DEPENDENCY_NOT_CONFIGURED',
    503,
    { field: 'env.SETTLE_ENV' }
  );
}

function parseMinorAmount(value: unknown, field: string): string {
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) {
      throw new ClawSettleError(
        `${field} must be a non-negative integer`,
        'INVALID_EVENT_PAYLOAD',
        422,
        { field }
      );
    }
    return String(value);
  }

  if (typeof value === 'string') {
    if (!/^[0-9]+$/.test(value)) {
      throw new ClawSettleError(
        `${field} must be a non-negative integer`,
        'INVALID_EVENT_PAYLOAD',
        422,
        { field }
      );
    }
    return value;
  }

  throw new ClawSettleError(
    `${field} must be a non-negative integer`,
    'INVALID_EVENT_PAYLOAD',
    422,
    { field }
  );
}

function requireString(
  obj: Record<string, unknown>,
  field: string,
  path: string
): string {
  const value = obj[field];
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ClawSettleError(
      `Missing required field: ${path}`,
      'INVALID_EVENT_PAYLOAD',
      422,
      { field: path }
    );
  }

  return value.trim();
}

function getOptionalString(
  obj: Record<string, unknown>,
  field: string
): string | undefined {
  const value = obj[field];
  if (typeof value !== 'string') {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function unixSecondsToIso(value: unknown): string | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return undefined;
  }

  if (value <= 0) {
    return undefined;
  }

  return new Date(Math.floor(value) * 1000).toISOString();
}

function extractAccountId(object: Record<string, unknown>): string {
  const metadata = object.metadata;
  if (!isRecord(metadata)) {
    throw new ClawSettleError(
      'Missing required field: data.object.metadata.account_id',
      'INVALID_EVENT_PAYLOAD',
      422,
      { field: 'data.object.metadata.account_id' }
    );
  }

  const accountId = metadata.account_id;
  if (typeof accountId !== 'string' || accountId.trim().length === 0) {
    throw new ClawSettleError(
      'Missing required field: data.object.metadata.account_id',
      'INVALID_EVENT_PAYLOAD',
      422,
      { field: 'data.object.metadata.account_id' }
    );
  }

  return accountId.trim();
}

function deriveRail(object: Record<string, unknown>): string | undefined {
  const methodTypes = object.payment_method_types;
  if (Array.isArray(methodTypes) && methodTypes.length > 0) {
    const first = methodTypes[0];
    if (typeof first === 'string' && first.trim().length > 0) {
      return first.trim();
    }
  }

  const method = getOptionalString(object, 'method');
  if (method) {
    return method;
  }

  return undefined;
}

interface ParsedStripeSignature {
  timestamp: number;
  v1Signatures: string[];
}

interface ForwardAttemptResult {
  ok: boolean;
  eventId: string;
  eventType: string;
  idempotencyKey: string;
  ledgerStatus?: number;
  settlementId?: string;
  retryScheduled?: boolean;
  nextRetryAt?: string;
}

export class ClawSettleError extends Error {
  constructor(
    message: string,
    public code: string,
    public status = 400,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'ClawSettleError';
  }
}

export interface StripeWebhookRepositoryLike {
  findByEventId(eventId: string): Promise<StripeWebhookRecord | null>;
  create(record: StripeWebhookRecord): Promise<void>;
}

export interface StripeWebhookOutboxRepositoryLike {
  findByEventId(eventId: string): Promise<StripeWebhookOutboxRecord | null>;
  create(record: StripeWebhookOutboxRecord): Promise<void>;
  incrementAttempt(eventId: string, attemptedAt: string, updatedAt: string): Promise<void>;
  markForwarded(params: {
    eventId: string;
    settlementId?: string;
    ledgerStatus?: number;
    forwardedAt: string;
    updatedAt: string;
  }): Promise<void>;
  markFailed(params: {
    eventId: string;
    ledgerStatus?: number;
    nextRetryAt: string;
    errorCode: string;
    errorMessage: string;
    updatedAt: string;
  }): Promise<void>;
  listRetryable(nowIso: string, limit: number): Promise<StripeWebhookOutboxRecord[]>;
}

export interface LedgerSettlementClientLike {
  ingest(
    payload: PaymentSettlementIngestPayload,
    idempotencyKey: string
  ): Promise<{ status: number; json: Record<string, unknown> | null; text: string }>;
}

export function parseStripeSignatureHeader(header: string): ParsedStripeSignature {
  const entries = header
    .split(',')
    .map((chunk) => chunk.trim())
    .filter(Boolean);

  let timestamp: number | null = null;
  const v1Signatures: string[] = [];

  for (const entry of entries) {
    const [k, ...rest] = entry.split('=');
    if (!k || rest.length === 0) {
      continue;
    }

    const value = rest.join('=').trim();
    if (!value) {
      continue;
    }

    if (k === 't') {
      const parsed = Number.parseInt(value, 10);
      if (Number.isFinite(parsed)) {
        timestamp = parsed;
      }
      continue;
    }

    if (k === 'v1') {
      v1Signatures.push(value.toLowerCase());
    }
  }

  if (!timestamp || v1Signatures.length === 0) {
    throw new ClawSettleError(
      'Invalid Stripe-Signature header',
      'SIGNATURE_INVALID',
      401
    );
  }

  return { timestamp, v1Signatures };
}

export async function computeStripeV1Signature(
  secret: string,
  timestamp: number,
  rawBody: string
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false,
    ['sign']
  );

  const payload = `${timestamp}.${rawBody}`;
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return toHex(new Uint8Array(sig));
}

export async function verifyStripeSignature(params: {
  secret: string;
  signatureHeader: string;
  rawBody: string;
  nowMs?: number;
  toleranceSeconds?: number;
}): Promise<{ timestamp: number }> {
  const { timestamp, v1Signatures } = parseStripeSignatureHeader(params.signatureHeader);

  const nowMs = params.nowMs ?? Date.now();
  const toleranceSeconds = params.toleranceSeconds ?? DEFAULT_STRIPE_TOLERANCE_SECONDS;

  const ageSeconds = Math.abs(nowMs - timestamp * 1000) / 1000;
  if (ageSeconds > toleranceSeconds) {
    throw new ClawSettleError(
      'Stripe signature timestamp outside tolerance window',
      'SIGNATURE_INVALID',
      401,
      {
        tolerance_seconds: toleranceSeconds,
      }
    );
  }

  const expected = await computeStripeV1Signature(params.secret, timestamp, params.rawBody);

  const matched = v1Signatures.some((candidate) =>
    safeEqualText(candidate.toLowerCase(), expected)
  );

  if (!matched) {
    throw new ClawSettleError('Stripe signature mismatch', 'SIGNATURE_INVALID', 401);
  }

  return { timestamp };
}

export function parseStripeEvent(rawBody: string): StripeEvent {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody);
  } catch {
    throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
  }

  if (!isRecord(parsed)) {
    throw new ClawSettleError('Invalid Stripe event payload', 'INVALID_REQUEST', 400);
  }

  const id = parsed.id;
  const type = parsed.type;
  const data = parsed.data;

  if (typeof id !== 'string' || id.trim().length === 0) {
    throw new ClawSettleError('Missing Stripe event id', 'INVALID_REQUEST', 400);
  }

  if (typeof type !== 'string' || type.trim().length === 0) {
    throw new ClawSettleError('Missing Stripe event type', 'INVALID_REQUEST', 400);
  }

  if (!isRecord(data) || !isRecord(data.object)) {
    throw new ClawSettleError('Missing Stripe event data.object', 'INVALID_REQUEST', 400);
  }

  return {
    id: id.trim(),
    type: type.trim(),
    created: typeof parsed.created === 'number' ? parsed.created : undefined,
    livemode: typeof parsed.livemode === 'boolean' ? parsed.livemode : undefined,
    data: {
      object: data.object,
    },
  };
}

export function mapStripeEventToSettlementIngest(
  event: StripeEvent
): PaymentSettlementIngestPayload | null {
  const object = event.data.object;

  if (event.type === 'payment_intent.succeeded') {
    const externalPaymentId = requireString(object, 'id', 'data.object.id');
    const amountMinor = parseMinorAmount(
      object.amount_received ?? object.amount,
      'data.object.amount_received'
    );
    const currency = requireString(object, 'currency', 'data.object.currency').toUpperCase();
    const accountId = extractAccountId(object);

    return {
      provider: 'stripe',
      external_payment_id: externalPaymentId,
      direction: 'payin',
      status: 'confirmed',
      account_id: accountId,
      amount_minor: amountMinor,
      currency,
      network: 'stripe',
      rail: deriveRail(object),
      provider_created_at: unixSecondsToIso(object.created),
      provider_updated_at: unixSecondsToIso(event.created),
      settled_at: unixSecondsToIso(event.created),
      metadata: {
        stripe_event_id: event.id,
        stripe_event_type: event.type,
        stripe_object_id: externalPaymentId,
      },
    };
  }

  if (event.type === 'payment_intent.payment_failed' || event.type === 'payment_intent.canceled') {
    const externalPaymentId = requireString(object, 'id', 'data.object.id');
    const amountMinor = parseMinorAmount(object.amount, 'data.object.amount');
    const currency = requireString(object, 'currency', 'data.object.currency').toUpperCase();
    const accountId = extractAccountId(object);

    return {
      provider: 'stripe',
      external_payment_id: externalPaymentId,
      direction: 'payin',
      status: 'failed',
      account_id: accountId,
      amount_minor: amountMinor,
      currency,
      network: 'stripe',
      rail: deriveRail(object),
      provider_created_at: unixSecondsToIso(object.created),
      provider_updated_at: unixSecondsToIso(event.created),
      metadata: {
        stripe_event_id: event.id,
        stripe_event_type: event.type,
        stripe_object_id: externalPaymentId,
      },
    };
  }

  if (event.type === 'charge.refunded') {
    const externalPaymentId = requireString(object, 'id', 'data.object.id');
    const amountMinor = parseMinorAmount(
      object.amount_refunded ?? object.amount,
      'data.object.amount_refunded'
    );
    const currency = requireString(object, 'currency', 'data.object.currency').toUpperCase();
    const accountId = extractAccountId(object);

    return {
      provider: 'stripe',
      external_payment_id: externalPaymentId,
      direction: 'refund',
      status: 'confirmed',
      account_id: accountId,
      amount_minor: amountMinor,
      currency,
      network: 'stripe',
      rail: deriveRail(object),
      provider_created_at: unixSecondsToIso(object.created),
      provider_updated_at: unixSecondsToIso(event.created),
      settled_at: unixSecondsToIso(event.created),
      metadata: {
        stripe_event_id: event.id,
        stripe_event_type: event.type,
        stripe_object_id: externalPaymentId,
      },
    };
  }

  if (event.type === 'payout.paid' || event.type === 'payout.failed') {
    const externalPaymentId = requireString(object, 'id', 'data.object.id');
    const amountMinor = parseMinorAmount(object.amount, 'data.object.amount');
    const currency = requireString(object, 'currency', 'data.object.currency').toUpperCase();
    const accountId = extractAccountId(object);

    return {
      provider: 'stripe',
      external_payment_id: externalPaymentId,
      direction: 'payout',
      status: event.type === 'payout.paid' ? 'confirmed' : 'failed',
      account_id: accountId,
      amount_minor: amountMinor,
      currency,
      network: 'stripe',
      rail: deriveRail(object),
      provider_created_at: unixSecondsToIso(object.created),
      provider_updated_at: unixSecondsToIso(event.created),
      settled_at: event.type === 'payout.paid' ? unixSecondsToIso(event.created) : undefined,
      metadata: {
        stripe_event_id: event.id,
        stripe_event_type: event.type,
        stripe_object_id: externalPaymentId,
      },
    };
  }

  return null;
}

function parseWebhookRecord(row: Record<string, unknown>): StripeWebhookRecord {
  return {
    event_id: String(row.event_id),
    event_type: String(row.event_type),
    idempotency_key: String(row.idempotency_key),
    settlement_id: typeof row.settlement_id === 'string' ? row.settlement_id : undefined,
    response_json: String(row.response_json),
    processed_at: String(row.processed_at),
  };
}

function parseOutboxRecord(row: Record<string, unknown>): StripeWebhookOutboxRecord {
  return {
    event_id: String(row.event_id),
    event_type: String(row.event_type),
    idempotency_key: String(row.idempotency_key),
    livemode: toOutboxBoolean(row.livemode),
    settlement_payload_json: String(row.settlement_payload_json),
    status:
      row.status === 'pending' || row.status === 'failed' || row.status === 'forwarded'
        ? row.status
        : 'pending',
    attempts: Number.isFinite(Number(row.attempts)) ? Number(row.attempts) : 0,
    next_retry_at: typeof row.next_retry_at === 'string' ? row.next_retry_at : undefined,
    last_attempted_at:
      typeof row.last_attempted_at === 'string' ? row.last_attempted_at : undefined,
    last_error_code: typeof row.last_error_code === 'string' ? row.last_error_code : undefined,
    last_error_message:
      typeof row.last_error_message === 'string' ? row.last_error_message : undefined,
    ledger_status:
      Number.isFinite(Number(row.ledger_status)) && row.ledger_status !== null
        ? Number(row.ledger_status)
        : undefined,
    settlement_id: typeof row.settlement_id === 'string' ? row.settlement_id : undefined,
    created_at: String(row.created_at),
    updated_at: String(row.updated_at),
    forwarded_at: typeof row.forwarded_at === 'string' ? row.forwarded_at : undefined,
  };
}

export class StripeWebhookRepository implements StripeWebhookRepositoryLike {
  constructor(private db: D1Database) {}

  async findByEventId(eventId: string): Promise<StripeWebhookRecord | null> {
    const result = await this.db
      .prepare(
        `SELECT event_id, event_type, idempotency_key, settlement_id, response_json, processed_at
         FROM stripe_webhook_events
         WHERE event_id = ?
         LIMIT 1`
      )
      .bind(eventId)
      .first();

    if (!result) {
      return null;
    }

    return parseWebhookRecord(result);
  }

  async create(record: StripeWebhookRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO stripe_webhook_events (
          event_id, event_type, idempotency_key, settlement_id, response_json, processed_at
        ) VALUES (?, ?, ?, ?, ?, ?)`
      )
      .bind(
        record.event_id,
        record.event_type,
        record.idempotency_key,
        record.settlement_id ?? null,
        record.response_json,
        record.processed_at
      )
      .run();
  }
}

export class StripeWebhookOutboxRepository implements StripeWebhookOutboxRepositoryLike {
  constructor(private db: D1Database) {}

  async findByEventId(eventId: string): Promise<StripeWebhookOutboxRecord | null> {
    const result = await this.db
      .prepare(
        `SELECT
          event_id,
          event_type,
          idempotency_key,
          livemode,
          settlement_payload_json,
          status,
          attempts,
          next_retry_at,
          last_attempted_at,
          last_error_code,
          last_error_message,
          ledger_status,
          settlement_id,
          created_at,
          updated_at,
          forwarded_at
         FROM stripe_webhook_outbox
         WHERE event_id = ?
         LIMIT 1`
      )
      .bind(eventId)
      .first();

    if (!result) {
      return null;
    }

    return parseOutboxRecord(result);
  }

  async create(record: StripeWebhookOutboxRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO stripe_webhook_outbox (
          event_id,
          event_type,
          idempotency_key,
          livemode,
          settlement_payload_json,
          status,
          attempts,
          next_retry_at,
          last_attempted_at,
          last_error_code,
          last_error_message,
          ledger_status,
          settlement_id,
          created_at,
          updated_at,
          forwarded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        record.event_id,
        record.event_type,
        record.idempotency_key,
        record.livemode ? 1 : 0,
        record.settlement_payload_json,
        record.status,
        record.attempts,
        record.next_retry_at ?? null,
        record.last_attempted_at ?? null,
        record.last_error_code ?? null,
        record.last_error_message ?? null,
        record.ledger_status ?? null,
        record.settlement_id ?? null,
        record.created_at,
        record.updated_at,
        record.forwarded_at ?? null
      )
      .run();
  }

  async incrementAttempt(eventId: string, attemptedAt: string, updatedAt: string): Promise<void> {
    await this.db
      .prepare(
        `UPDATE stripe_webhook_outbox
         SET attempts = attempts + 1,
             last_attempted_at = ?,
             updated_at = ?
         WHERE event_id = ?
           AND status != 'forwarded'`
      )
      .bind(attemptedAt, updatedAt, eventId)
      .run();
  }

  async markForwarded(params: {
    eventId: string;
    settlementId?: string;
    ledgerStatus?: number;
    forwardedAt: string;
    updatedAt: string;
  }): Promise<void> {
    await this.db
      .prepare(
        `UPDATE stripe_webhook_outbox
         SET status = 'forwarded',
             settlement_id = ?,
             ledger_status = ?,
             forwarded_at = ?,
             next_retry_at = NULL,
             last_error_code = NULL,
             last_error_message = NULL,
             updated_at = ?
         WHERE event_id = ?
           AND status != 'forwarded'`
      )
      .bind(
        params.settlementId ?? null,
        params.ledgerStatus ?? null,
        params.forwardedAt,
        params.updatedAt,
        params.eventId
      )
      .run();
  }

  async markFailed(params: {
    eventId: string;
    ledgerStatus?: number;
    nextRetryAt: string;
    errorCode: string;
    errorMessage: string;
    updatedAt: string;
  }): Promise<void> {
    await this.db
      .prepare(
        `UPDATE stripe_webhook_outbox
         SET status = 'failed',
             ledger_status = ?,
             next_retry_at = ?,
             last_error_code = ?,
             last_error_message = ?,
             updated_at = ?
         WHERE event_id = ?
           AND status != 'forwarded'`
      )
      .bind(
        params.ledgerStatus ?? null,
        params.nextRetryAt,
        params.errorCode,
        params.errorMessage,
        params.updatedAt,
        params.eventId
      )
      .run();
  }

  async listRetryable(nowIso: string, limit: number): Promise<StripeWebhookOutboxRecord[]> {
    const result = await this.db
      .prepare(
        `SELECT
          event_id,
          event_type,
          idempotency_key,
          livemode,
          settlement_payload_json,
          status,
          attempts,
          next_retry_at,
          last_attempted_at,
          last_error_code,
          last_error_message,
          ledger_status,
          settlement_id,
          created_at,
          updated_at,
          forwarded_at
         FROM stripe_webhook_outbox
         WHERE status IN ('pending', 'failed')
           AND (next_retry_at IS NULL OR next_retry_at <= ?)
         ORDER BY created_at ASC
         LIMIT ?`
      )
      .bind(nowIso, limit)
      .all();

    const rows = Array.isArray(result.results) ? result.results : [];
    return rows.map((row) => parseOutboxRecord(row));
  }
}

export class LedgerSettlementClient implements LedgerSettlementClientLike {
  constructor(
    private ledgerBaseUrl: string,
    private ledgerAdminKey: string
  ) {}

  async ingest(
    payload: PaymentSettlementIngestPayload,
    idempotencyKey: string
  ): Promise<{ status: number; json: Record<string, unknown> | null; text: string }> {
    const response = await fetch(
      `${this.ledgerBaseUrl.replace(/\/$/, '')}/v1/payments/settlements/ingest`,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json; charset=utf-8',
          authorization: `Bearer ${this.ledgerAdminKey}`,
          'idempotency-key': idempotencyKey,
        },
        body: JSON.stringify(payload),
      }
    );

    const text = await response.text();
    let json: Record<string, unknown> | null = null;

    try {
      const parsed = JSON.parse(text);
      json = isRecord(parsed) ? parsed : null;
    } catch {
      json = null;
    }

    return {
      status: response.status,
      json,
      text,
    };
  }
}

interface StripeWebhookServiceDeps {
  repository?: StripeWebhookRepositoryLike;
  outboxRepository?: StripeWebhookOutboxRepositoryLike;
  ledgerClient?: LedgerSettlementClientLike;
  now?: () => string;
  nowMs?: () => number;
}

export class StripeWebhookService {
  private readonly repository: StripeWebhookRepositoryLike;
  private readonly outboxRepository: StripeWebhookOutboxRepositoryLike;
  private readonly ledgerClient?: LedgerSettlementClientLike;
  private readonly now: () => string;
  private readonly nowMs: () => number;
  private readonly retryBatchLimit: number;
  private readonly retryBaseSeconds: number;
  private readonly retryMaxSeconds: number;

  constructor(private env: Env, deps: StripeWebhookServiceDeps = {}) {
    this.repository = deps.repository ?? new StripeWebhookRepository(env.DB);
    this.outboxRepository = deps.outboxRepository ?? new StripeWebhookOutboxRepository(env.DB);
    this.ledgerClient = deps.ledgerClient;
    this.now = deps.now ?? (() => new Date().toISOString());
    this.nowMs = deps.nowMs ?? (() => Date.now());

    this.retryBatchLimit = parsePositiveIntegerEnv(
      env.FORWARDING_RETRY_BATCH_LIMIT,
      DEFAULT_RETRY_BATCH_LIMIT,
      'env.FORWARDING_RETRY_BATCH_LIMIT'
    );
    this.retryBaseSeconds = parsePositiveIntegerEnv(
      env.FORWARDING_RETRY_BASE_SECONDS,
      DEFAULT_RETRY_BASE_SECONDS,
      'env.FORWARDING_RETRY_BASE_SECONDS'
    );
    this.retryMaxSeconds = parsePositiveIntegerEnv(
      env.FORWARDING_RETRY_MAX_SECONDS,
      DEFAULT_RETRY_MAX_SECONDS,
      'env.FORWARDING_RETRY_MAX_SECONDS'
    );
  }

  private requireSigningSecret(): string {
    const secret = this.env.STRIPE_WEBHOOK_SIGNING_SECRET;
    if (!secret || secret.trim().length === 0) {
      throw new ClawSettleError(
        'Stripe webhook signing secret not configured',
        'DEPENDENCY_NOT_CONFIGURED',
        503,
        { field: 'env.STRIPE_WEBHOOK_SIGNING_SECRET' }
      );
    }

    return secret.trim();
  }

  private getLedgerClient(): LedgerSettlementClientLike {
    if (this.ledgerClient) {
      return this.ledgerClient;
    }

    const baseUrl = this.env.LEDGER_BASE_URL?.trim();
    if (!baseUrl) {
      throw new ClawSettleError(
        'Ledger base URL not configured',
        'DEPENDENCY_NOT_CONFIGURED',
        503,
        { field: 'env.LEDGER_BASE_URL' }
      );
    }

    const adminKey = this.env.LEDGER_ADMIN_KEY?.trim();
    if (!adminKey) {
      throw new ClawSettleError(
        'Ledger admin key not configured',
        'DEPENDENCY_NOT_CONFIGURED',
        503,
        { field: 'env.LEDGER_ADMIN_KEY' }
      );
    }

    return new LedgerSettlementClient(baseUrl, adminKey);
  }

  private parseCachedResponse(
    record: StripeWebhookRecord,
    deduped: boolean
  ): StripeWebhookResponse {
    try {
      const parsed = JSON.parse(record.response_json);
      if (!isRecord(parsed)) {
        throw new Error('Invalid cached response');
      }

      return {
        ok: true,
        deduped,
        event_id: String(parsed.event_id ?? record.event_id),
        event_type: String(parsed.event_type ?? record.event_type),
        idempotency_key: String(parsed.idempotency_key ?? record.idempotency_key),
        forwarded_to_ledger: Boolean(parsed.forwarded_to_ledger),
        ledger_status:
          typeof parsed.ledger_status === 'number' ? parsed.ledger_status : undefined,
        settlement_id:
          typeof parsed.settlement_id === 'string'
            ? parsed.settlement_id
            : record.settlement_id,
        retry_scheduled:
          typeof parsed.retry_scheduled === 'boolean' ? parsed.retry_scheduled : undefined,
        next_retry_at:
          typeof parsed.next_retry_at === 'string' ? parsed.next_retry_at : undefined,
      };
    } catch {
      throw new ClawSettleError(
        'Corrupt webhook dedupe record',
        'INTERNAL_ERROR',
        500
      );
    }
  }

  private enforceEventLivemode(event: StripeEvent): void {
    const settleEnv = resolveSettleEnvironment(this.env);

    if (typeof event.livemode !== 'boolean') {
      throw new ClawSettleError(
        'Stripe event livemode does not match environment policy',
        'LIVEMODE_MISMATCH',
        422,
        {
          settle_env: settleEnv,
          expected_livemode: settleEnv === 'staging' ? false : true,
          event_livemode: null,
          reason: 'missing_livemode',
        }
      );
    }

    if (settleEnv === 'staging') {
      if (event.livemode !== false) {
        throw new ClawSettleError(
          'Stripe event livemode does not match environment policy',
          'LIVEMODE_MISMATCH',
          422,
          {
            settle_env: settleEnv,
            expected_livemode: false,
            event_livemode: event.livemode,
          }
        );
      }
      return;
    }

    const allowTestInProd = parseBooleanFlag(this.env.STRIPE_ALLOW_TESTMODE_EVENTS_IN_PROD);
    if (!allowTestInProd && event.livemode === false) {
      throw new ClawSettleError(
        'Stripe event livemode does not match environment policy',
        'LIVEMODE_MISMATCH',
        422,
        {
          settle_env: settleEnv,
          expected_livemode: true,
          event_livemode: event.livemode,
          allow_testmode_in_prod: false,
        }
      );
    }
  }

  private async persistAndReturn(
    record: StripeWebhookRecord,
    response: StripeWebhookResponse
  ): Promise<StripeWebhookResponse> {
    try {
      await this.repository.create(record);
      return response;
    } catch (err) {
      if (!isSqliteUniqueConstraintError(err)) {
        throw err;
      }

      const raced = await this.repository.findByEventId(record.event_id);
      if (!raced) {
        throw err;
      }

      return this.parseCachedResponse(raced, true);
    }
  }

  private parseSettlementPayloadJson(raw: string): PaymentSettlementIngestPayload {
    try {
      const parsed = JSON.parse(raw);
      if (!isRecord(parsed)) {
        throw new Error('invalid payload');
      }
      return parsed as unknown as PaymentSettlementIngestPayload;
    } catch {
      throw new ClawSettleError(
        'Corrupt settlement outbox payload',
        'INTERNAL_ERROR',
        500
      );
    }
  }

  private async ensureOutboxRecord(
    event: StripeEvent,
    idempotencyKey: string,
    settlementPayload: PaymentSettlementIngestPayload
  ): Promise<StripeWebhookOutboxRecord> {
    const existing = await this.outboxRepository.findByEventId(event.id);
    if (existing) {
      return existing;
    }

    const nowIso = this.now();
    const candidate: StripeWebhookOutboxRecord = {
      event_id: event.id,
      event_type: event.type,
      idempotency_key: idempotencyKey,
      livemode: Boolean(event.livemode),
      settlement_payload_json: JSON.stringify(settlementPayload),
      status: 'pending',
      attempts: 0,
      created_at: nowIso,
      updated_at: nowIso,
    };

    try {
      await this.outboxRepository.create(candidate);
      return candidate;
    } catch (err) {
      if (!isSqliteUniqueConstraintError(err)) {
        throw err;
      }

      const raced = await this.outboxRepository.findByEventId(event.id);
      if (!raced) {
        throw err;
      }
      return raced;
    }
  }

  private buildForwardedResponse(params: {
    eventId: string;
    eventType: string;
    idempotencyKey: string;
    settlementId?: string;
    ledgerStatus?: number;
    deduped: boolean;
  }): StripeWebhookResponse {
    return {
      ok: true,
      deduped: params.deduped,
      event_id: params.eventId,
      event_type: params.eventType,
      idempotency_key: params.idempotencyKey,
      forwarded_to_ledger: true,
      ledger_status: params.ledgerStatus,
      settlement_id: params.settlementId,
    };
  }

  private async forwardOutboxEvent(eventId: string): Promise<ForwardAttemptResult> {
    const existing = await this.outboxRepository.findByEventId(eventId);
    if (!existing) {
      throw new ClawSettleError(
        'Missing outbox event record',
        'INTERNAL_ERROR',
        500,
        { event_id: eventId }
      );
    }

    if (existing.status === 'forwarded') {
      return {
        ok: true,
        eventId: existing.event_id,
        eventType: existing.event_type,
        idempotencyKey: existing.idempotency_key,
        ledgerStatus: existing.ledger_status,
        settlementId: existing.settlement_id,
      };
    }

    const attemptTime = this.now();
    await this.outboxRepository.incrementAttempt(existing.event_id, attemptTime, attemptTime);

    const current = await this.outboxRepository.findByEventId(existing.event_id);
    if (!current) {
      throw new ClawSettleError(
        'Outbox event disappeared during forwarding',
        'INTERNAL_ERROR',
        500,
        { event_id: existing.event_id }
      );
    }

    if (current.status === 'forwarded') {
      return {
        ok: true,
        eventId: current.event_id,
        eventType: current.event_type,
        idempotencyKey: current.idempotency_key,
        ledgerStatus: current.ledger_status,
        settlementId: current.settlement_id,
      };
    }

    const payload = this.parseSettlementPayloadJson(current.settlement_payload_json);

    let ledgerStatus: number | undefined;
    let settlementId: string | undefined;
    let ingestErrorMessage: string | undefined;

    try {
      const ledger = await this.getLedgerClient().ingest(payload, current.idempotency_key);
      ledgerStatus = ledger.status;

      if (ledger.status >= 200 && ledger.status < 300) {
        settlementId =
          isRecord(ledger.json?.settlement) &&
          typeof ledger.json?.settlement?.id === 'string'
            ? String(ledger.json?.settlement?.id)
            : undefined;

        const doneAt = this.now();
        await this.outboxRepository.markForwarded({
          eventId: current.event_id,
          settlementId,
          ledgerStatus,
          forwardedAt: doneAt,
          updatedAt: doneAt,
        });

        return {
          ok: true,
          eventId: current.event_id,
          eventType: current.event_type,
          idempotencyKey: current.idempotency_key,
          ledgerStatus,
          settlementId,
        };
      }

      ingestErrorMessage = `Ledger HTTP ${ledger.status}`;
    } catch (err) {
      ingestErrorMessage = truncateErrorMessage(err);
    }

    const attempts = Math.max(1, current.attempts);
    const retryDelaySeconds = computeRetryDelaySeconds(
      attempts,
      this.retryBaseSeconds,
      this.retryMaxSeconds
    );
    const nextRetryAt = new Date(this.nowMs() + retryDelaySeconds * 1000).toISOString();

    await this.outboxRepository.markFailed({
      eventId: current.event_id,
      ledgerStatus,
      nextRetryAt,
      errorCode: 'LEDGER_INGEST_FAILED',
      errorMessage: ingestErrorMessage ?? 'Ledger settlement ingest failed',
      updatedAt: this.now(),
    });

    return {
      ok: false,
      eventId: current.event_id,
      eventType: current.event_type,
      idempotencyKey: current.idempotency_key,
      ledgerStatus,
      retryScheduled: true,
      nextRetryAt,
    };
  }

  private async persistForwardedWebhookRecord(params: {
    eventId: string;
    eventType: string;
    idempotencyKey: string;
    settlementId?: string;
    ledgerStatus?: number;
  }): Promise<void> {
    const existing = await this.repository.findByEventId(params.eventId);
    if (existing) {
      return;
    }

    const response = this.buildForwardedResponse({
      eventId: params.eventId,
      eventType: params.eventType,
      idempotencyKey: params.idempotencyKey,
      settlementId: params.settlementId,
      ledgerStatus: params.ledgerStatus,
      deduped: false,
    });

    const record: StripeWebhookRecord = {
      event_id: params.eventId,
      event_type: params.eventType,
      idempotency_key: params.idempotencyKey,
      settlement_id: params.settlementId,
      response_json: JSON.stringify(response),
      processed_at: this.now(),
    };

    await this.persistAndReturn(record, response);
  }

  private resolveRetryLimit(limit?: number): number {
    if (typeof limit !== 'number' || !Number.isFinite(limit)) {
      return this.retryBatchLimit;
    }

    const parsed = Math.floor(limit);
    if (parsed <= 0) {
      throw new ClawSettleError('Invalid retry limit', 'INVALID_REQUEST', 400, {
        field: 'limit',
      });
    }

    return Math.min(parsed, 200);
  }

  async processWebhook(
    rawBody: string,
    signatureHeader: string | null
  ): Promise<StripeWebhookResponse> {
    const signingSecret = this.requireSigningSecret();

    if (!signatureHeader || signatureHeader.trim().length === 0) {
      throw new ClawSettleError(
        'Missing Stripe-Signature header',
        'SIGNATURE_INVALID',
        401
      );
    }

    await verifyStripeSignature({
      secret: signingSecret,
      signatureHeader: signatureHeader.trim(),
      rawBody,
      nowMs: this.nowMs(),
    });

    const event = parseStripeEvent(rawBody);
    this.enforceEventLivemode(event);

    const existing = await this.repository.findByEventId(event.id);
    if (existing) {
      return this.parseCachedResponse(existing, true);
    }

    const idempotencyKey = `stripe:event:${event.id}`;
    const settlementPayload = mapStripeEventToSettlementIngest(event);

    if (!settlementPayload) {
      const ignoredResponse: StripeWebhookResponse = {
        ok: true,
        deduped: false,
        event_id: event.id,
        event_type: event.type,
        idempotency_key: idempotencyKey,
        forwarded_to_ledger: false,
      };

      const record: StripeWebhookRecord = {
        event_id: event.id,
        event_type: event.type,
        idempotency_key: idempotencyKey,
        settlement_id: undefined,
        response_json: JSON.stringify(ignoredResponse),
        processed_at: this.now(),
      };

      return this.persistAndReturn(record, ignoredResponse);
    }

    await this.ensureOutboxRecord(event, idempotencyKey, settlementPayload);

    const forwardAttempt = await this.forwardOutboxEvent(event.id);

    if (!forwardAttempt.ok) {
      throw new ClawSettleError(
        'Ledger settlement ingest failed',
        'LEDGER_INGEST_FAILED',
        502,
        {
          event_id: event.id,
          ledger_status: forwardAttempt.ledgerStatus,
          retry_scheduled: true,
          next_retry_at: forwardAttempt.nextRetryAt,
        }
      );
    }

    const response = this.buildForwardedResponse({
      eventId: forwardAttempt.eventId,
      eventType: forwardAttempt.eventType,
      idempotencyKey: forwardAttempt.idempotencyKey,
      ledgerStatus: forwardAttempt.ledgerStatus,
      settlementId: forwardAttempt.settlementId,
      deduped: false,
    });

    const record: StripeWebhookRecord = {
      event_id: forwardAttempt.eventId,
      event_type: forwardAttempt.eventType,
      idempotency_key: forwardAttempt.idempotencyKey,
      settlement_id: forwardAttempt.settlementId,
      response_json: JSON.stringify(response),
      processed_at: this.now(),
    };

    return this.persistAndReturn(record, response);
  }

  async retryFailedForwarding(
    limit?: number,
    force = false,
    eventId?: string
  ): Promise<RetryForwardingResponse> {
    const retryLimit = this.resolveRetryLimit(limit);
    const nowIso = this.now();

    let candidates: StripeWebhookOutboxRecord[];

    if (typeof eventId === 'string' && eventId.trim().length > 0) {
      const event = await this.outboxRepository.findByEventId(eventId.trim());
      if (!event || event.status === 'forwarded') {
        return {
          ok: true,
          attempted: 0,
          forwarded: 0,
          failed: 0,
        };
      }

      if (
        !force &&
        event.next_retry_at &&
        Number.isFinite(Date.parse(event.next_retry_at)) &&
        Date.parse(event.next_retry_at) > Date.parse(nowIso)
      ) {
        return {
          ok: true,
          attempted: 0,
          forwarded: 0,
          failed: 0,
        };
      }

      candidates = [event];
    } else {
      const dueIso = force ? '9999-12-31T23:59:59.999Z' : nowIso;
      candidates = await this.outboxRepository.listRetryable(dueIso, retryLimit);
    }

    let attempted = 0;
    let forwarded = 0;
    let failed = 0;

    for (const candidate of candidates) {
      attempted += 1;

      const result = await this.forwardOutboxEvent(candidate.event_id);
      if (result.ok) {
        forwarded += 1;
        await this.persistForwardedWebhookRecord({
          eventId: result.eventId,
          eventType: result.eventType,
          idempotencyKey: result.idempotencyKey,
          settlementId: result.settlementId,
          ledgerStatus: result.ledgerStatus,
        });
      } else {
        failed += 1;
      }
    }

    return {
      ok: true,
      attempted,
      forwarded,
      failed,
    };
  }
}
