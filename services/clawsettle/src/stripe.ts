import type {
  Env,
  PaymentSettlementIngestPayload,
  StripeEvent,
  StripeWebhookRecord,
  StripeWebhookResponse,
} from './types';

const DEFAULT_STRIPE_TOLERANCE_SECONDS = 300;

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
  ledgerClient?: LedgerSettlementClientLike;
  now?: () => string;
  nowMs?: () => number;
}

export class StripeWebhookService {
  private readonly repository: StripeWebhookRepositoryLike;
  private readonly ledgerClient?: LedgerSettlementClientLike;
  private readonly now: () => string;
  private readonly nowMs: () => number;

  constructor(private env: Env, deps: StripeWebhookServiceDeps = {}) {
    this.repository = deps.repository ?? new StripeWebhookRepository(env.DB);
    this.ledgerClient = deps.ledgerClient;
    this.now = deps.now ?? (() => new Date().toISOString());
    this.nowMs = deps.nowMs ?? (() => Date.now());
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

    const ledgerClient = this.getLedgerClient();
    const ledger = await ledgerClient.ingest(settlementPayload, idempotencyKey);

    if (ledger.status < 200 || ledger.status >= 300) {
      throw new ClawSettleError(
        'Ledger settlement ingest failed',
        'LEDGER_INGEST_FAILED',
        502,
        {
          ledger_status: ledger.status,
        }
      );
    }

    const settlementId =
      isRecord(ledger.json?.settlement) &&
      typeof ledger.json?.settlement?.id === 'string'
        ? String(ledger.json?.settlement?.id)
        : undefined;

    const response: StripeWebhookResponse = {
      ok: true,
      deduped: false,
      event_id: event.id,
      event_type: event.type,
      idempotency_key: idempotencyKey,
      forwarded_to_ledger: true,
      ledger_status: ledger.status,
      settlement_id: settlementId,
    };

    const record: StripeWebhookRecord = {
      event_id: event.id,
      event_type: event.type,
      idempotency_key: idempotencyKey,
      settlement_id: settlementId,
      response_json: JSON.stringify(response),
      processed_at: this.now(),
    };

    return this.persistAndReturn(record, response);
  }
}
