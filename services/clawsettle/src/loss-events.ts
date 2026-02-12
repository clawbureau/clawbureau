import { ClawSettleError } from './stripe';
import type { Env } from './types';

type LossSeverity = 'low' | 'medium' | 'high' | 'critical';
type LossEventStatus = 'recorded' | 'processing' | 'partially_forwarded' | 'forwarded' | 'failed';
type LossOutboxStatus = 'pending' | 'forwarded' | 'failed';
type LossTargetService = 'ledger' | 'escrow' | 'clawinsure' | 'clawincome' | 'clawbounties';

const LOSS_TARGETS: readonly LossTargetService[] = [
  'ledger',
  'escrow',
  'clawinsure',
  'clawincome',
  'clawbounties',
] as const;

type LossOutboxOperation = 'apply' | 'resolve';

interface LossEventRecord {
  id: string;
  idempotency_key: string;
  request_hash: string;
  source_service: string;
  source_event_id: string;
  account_did: string;
  account_id: string | null;
  currency: 'USD';
  amount_minor: string;
  reason_code: string;
  severity: LossSeverity;
  occurred_at: string;
  metadata_json: string | null;
  status: LossEventStatus;
  target_count: number;
  forwarded_count: number;
  failed_count: number;
  created_at: string;
  updated_at: string;
  last_forwarded_at: string | null;
}

interface LossEventOutboxRecord {
  id: string;
  loss_event_id: string;
  target_service: LossTargetService;
  target_url: string;
  status: LossOutboxStatus;
  attempts: number;
  last_http_status: number | null;
  last_error_code: string | null;
  last_error_message: string | null;
  next_retry_at: string | null;
  forwarded_at: string | null;
  created_at: string;
  updated_at: string;
}

interface LossEventResolutionRecord {
  id: string;
  loss_event_id: string;
  idempotency_key: string;
  request_hash: string;
  reason: string | null;
  status: LossEventStatus;
  target_count: number;
  forwarded_count: number;
  failed_count: number;
  created_at: string;
  updated_at: string;
  last_forwarded_at: string | null;
  resolved_at: string | null;
}

interface LossEventResolutionOutboxRecord {
  id: string;
  loss_event_id: string;
  target_service: LossTargetService;
  target_url: string;
  status: LossOutboxStatus;
  attempts: number;
  last_http_status: number | null;
  last_error_code: string | null;
  last_error_message: string | null;
  next_retry_at: string | null;
  forwarded_at: string | null;
  created_at: string;
  updated_at: string;
}

interface LossEventQueueMessage {
  loss_event_id: string;
  trigger: 'create' | 'resolve' | 'retry' | 'cron';
  queued_at: string;
}

interface LossEventEnvelope {
  source_service?: string;
  source_event_id?: string;
  source?: {
    service?: string;
    external_event_id?: string;
    provider?: string;
    external_payment_id?: string;
  };
  kind?: string;
  account_did: string;
  account_id?: string;
  amount_minor: string;
  currency: string;
  reason_code?: string;
  severity?: LossSeverity;
  risk?: {
    score?: number;
  };
  evidence?: Record<string, unknown>;
  occurred_at?: string;
  metadata?: Record<string, unknown>;
  targets?: LossTargetService[];
}

interface LossTargetConfig {
  service: LossTargetService;
  url: string;
  auth_token: string;
}

interface LossEventView {
  loss_event_id: string;
  source_service: string;
  source_event_id: string;
  account_did: string;
  account_id: string | null;
  amount_minor: string;
  currency: 'USD';
  reason_code: string;
  severity: LossSeverity;
  occurred_at: string;
  metadata: Record<string, unknown> | null;
  status: LossEventStatus;
  target_count: number;
  forwarded_count: number;
  failed_count: number;
  created_at: string;
  updated_at: string;
  last_forwarded_at: string | null;
}

interface LossEventResolutionView {
  resolution_id: string;
  loss_event_id: string;
  reason: string | null;
  status: LossEventStatus;
  target_count: number;
  forwarded_count: number;
  failed_count: number;
  created_at: string;
  updated_at: string;
  last_forwarded_at: string | null;
  resolved_at: string | null;
}

interface LossOutboxView {
  outbox_id: string;
  loss_event_id: string;
  target_service: LossTargetService;
  target_url: string;
  status: LossOutboxStatus;
  attempts: number;
  last_http_status: number | null;
  last_error_code: string | null;
  last_error_message: string | null;
  next_retry_at: string | null;
  forwarded_at: string | null;
  created_at: string;
  updated_at: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

function encodeCursor(createdAt: string, id: string): string {
  const payload = `${createdAt}::${id}`;
  return btoa(payload).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeCursor(value: string | null): { created_at: string; id: string } | null {
  if (!value || value.trim().length === 0) {
    return null;
  }

  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
    const decoded = atob(padded);
    const sep = decoded.lastIndexOf('::');
    if (sep <= 0 || sep === decoded.length - 2) {
      return null;
    }

    return {
      created_at: decoded.slice(0, sep),
      id: decoded.slice(sep + 2),
    };
  } catch {
    return null;
  }
}

function parsePositiveMinor(value: unknown, field: string): string {
  if (typeof value !== 'string' || !/^\d+$/.test(value.trim())) {
    throw new ClawSettleError(`${field} must be a positive integer string`, 'INVALID_REQUEST', 400, {
      field,
    });
  }

  const normalized = value.trim().replace(/^0+(?=\d)/, '');
  const asBigInt = BigInt(normalized);
  if (asBigInt <= 0n) {
    throw new ClawSettleError(`${field} must be greater than zero`, 'INVALID_REQUEST', 400, {
      field,
    });
  }

  return asBigInt.toString();
}

function parseRequiredString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ClawSettleError(`Missing required field: ${field}`, 'INVALID_REQUEST', 400, {
      field,
    });
  }

  return value.trim();
}

function parseOptionalString(value: unknown, field: string): string | null {
  if (value === null || value === undefined) {
    return null;
  }

  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ClawSettleError(`${field} must be a non-empty string`, 'INVALID_REQUEST', 400, {
      field,
    });
  }

  return value.trim();
}

function parseSeverity(value: unknown): LossSeverity {
  if (value === null || value === undefined) {
    return 'high';
  }

  if (value === 'low' || value === 'medium' || value === 'high' || value === 'critical') {
    return value;
  }

  throw new ClawSettleError('severity must be one of low|medium|high|critical', 'INVALID_REQUEST', 400, {
    field: 'severity',
  });
}

function parseOccurredAt(value: unknown): string {
  if (value === null || value === undefined) {
    return nowIso();
  }

  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new ClawSettleError('occurred_at must be a valid ISO timestamp', 'INVALID_REQUEST', 400, {
      field: 'occurred_at',
    });
  }

  const date = new Date(value.trim());
  if (!Number.isFinite(date.getTime())) {
    throw new ClawSettleError('occurred_at must be a valid ISO timestamp', 'INVALID_REQUEST', 400, {
      field: 'occurred_at',
    });
  }

  return date.toISOString();
}

function parseMetadata(value: unknown): Record<string, unknown> | null {
  if (value === null || value === undefined) {
    return null;
  }

  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new ClawSettleError('metadata must be an object', 'INVALID_REQUEST', 400, {
      field: 'metadata',
    });
  }

  return value as Record<string, unknown>;
}

function parseTargets(value: unknown): LossTargetService[] | null {
  if (value === null || value === undefined) {
    return null;
  }

  if (!Array.isArray(value)) {
    throw new ClawSettleError('targets must be an array', 'INVALID_REQUEST', 400, {
      field: 'targets',
    });
  }

  const parsed = value.map((entry) => {
    if (!LOSS_TARGETS.includes(entry as LossTargetService)) {
      throw new ClawSettleError(
        `targets entries must be one of ${LOSS_TARGETS.join('|')}`,
        'INVALID_REQUEST',
        400,
        { field: 'targets' }
      );
    }

    return entry as LossTargetService;
  });

  return parsed.length > 0 ? parsed : null;
}

function parseLossEventPayload(input: unknown): {
  source_service: string;
  source_event_id: string;
  account_did: string;
  account_id: string | null;
  amount_minor: string;
  currency: 'USD';
  reason_code: string;
  severity: LossSeverity;
  occurred_at: string;
  metadata: Record<string, unknown> | null;
  requested_targets: LossTargetService[] | null;
} {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
  }

  const payload = input as LossEventEnvelope;

  const sourceService =
    payload.source && typeof payload.source.service === 'string' && payload.source.service.trim().length > 0
      ? payload.source.service.trim()
      : parseRequiredString(payload.source_service, 'source_service');

  const sourceEventId =
    payload.source && typeof payload.source.external_event_id === 'string' && payload.source.external_event_id.trim().length > 0
      ? payload.source.external_event_id.trim()
      : parseRequiredString(payload.source_event_id, 'source_event_id');

  const accountDid = parseRequiredString(payload.account_did, 'account_did');
  if (!/^did:[a-z0-9]+:[A-Za-z0-9._:-]+$/.test(accountDid)) {
    throw new ClawSettleError('account_did must be a DID string', 'INVALID_REQUEST', 400, {
      field: 'account_did',
    });
  }

  const accountId = parseOptionalString(payload.account_id, 'account_id');
  const amountMinor = parsePositiveMinor(payload.amount_minor, 'amount_minor');

  const reasonCode =
    typeof payload.reason_code === 'string' && payload.reason_code.trim().length > 0
      ? payload.reason_code.trim()
      : typeof payload.kind === 'string' && payload.kind.trim().length > 0
        ? payload.kind.trim()
        : parseRequiredString(payload.reason_code, 'reason_code');

  const severity =
    payload.severity !== undefined
      ? parseSeverity(payload.severity)
      : payload.risk && typeof payload.risk.score === 'number'
        ? payload.risk.score >= 85
          ? 'critical'
          : payload.risk.score >= 65
            ? 'high'
            : payload.risk.score >= 35
              ? 'medium'
              : 'low'
        : 'high';

  const occurredAt = parseOccurredAt(payload.occurred_at);

  const metadata = {
    ...(parseMetadata(payload.metadata) ?? {}),
    ...(payload.source && typeof payload.source.provider === 'string'
      ? { provider: payload.source.provider.trim() }
      : {}),
    ...(payload.source && typeof payload.source.external_payment_id === 'string'
      ? { external_payment_id: payload.source.external_payment_id.trim() }
      : {}),
    ...(typeof payload.kind === 'string' && payload.kind.trim().length > 0
      ? { kind: payload.kind.trim() }
      : {}),
    ...(payload.evidence && typeof payload.evidence === 'object' && !Array.isArray(payload.evidence)
      ? { evidence: payload.evidence }
      : {}),
  };

  const requestedTargets = parseTargets(payload.targets);

  if (payload.currency !== 'USD') {
    throw new ClawSettleError('Only USD loss events are supported', 'UNSUPPORTED_CURRENCY', 400, {
      field: 'currency',
      value: payload.currency,
    });
  }

  return {
    source_service: sourceService,
    source_event_id: sourceEventId,
    account_did: accountDid,
    account_id: accountId,
    amount_minor: amountMinor,
    currency: 'USD',
    reason_code: reasonCode,
    severity,
    occurred_at: occurredAt,
    metadata,
    requested_targets: requestedTargets,
  };
}

function stableStringify(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('Non-finite number is not allowed in canonical payloads');
      }
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
      }

      const entries = Object.entries(value as Record<string, unknown>)
        .filter(([, entry]) => entry !== undefined)
        .sort(([a], [b]) => a.localeCompare(b));

      const parts: string[] = [];
      for (const [key, entry] of entries) {
        parts.push(`${JSON.stringify(key)}:${stableStringify(entry)}`);
      }

      return `{${parts.join(',')}}`;
    }
    default:
      throw new Error(`Unsupported type in stable stringify: ${typeof value}`);
  }
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return toHex(new Uint8Array(digest));
}

async function deriveDeterministicId(prefix: string, source: string): Promise<string> {
  const hash = await sha256Hex(`${prefix}:${source}`);
  return `${prefix}_${hash.slice(0, 24)}`;
}

function parseJsonObject<T>(value: string | null): T | null {
  if (!value || value.trim().length === 0) {
    return null;
  }

  try {
    const parsed = JSON.parse(value) as unknown;
    if (typeof parsed !== 'object' || parsed === null) {
      return null;
    }
    return parsed as T;
  } catch {
    return null;
  }
}

function normalizeEvent(row: LossEventRecord): LossEventView {
  return {
    loss_event_id: row.id,
    source_service: row.source_service,
    source_event_id: row.source_event_id,
    account_did: row.account_did,
    account_id: row.account_id,
    amount_minor: row.amount_minor,
    currency: row.currency,
    reason_code: row.reason_code,
    severity: row.severity,
    occurred_at: row.occurred_at,
    metadata: parseJsonObject<Record<string, unknown>>(row.metadata_json),
    status: row.status,
    target_count: row.target_count,
    forwarded_count: row.forwarded_count,
    failed_count: row.failed_count,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_forwarded_at: row.last_forwarded_at,
  };
}

function normalizeOutbox(row: LossEventOutboxRecord): LossOutboxView {
  return {
    outbox_id: row.id,
    loss_event_id: row.loss_event_id,
    target_service: row.target_service,
    target_url: row.target_url,
    status: row.status,
    attempts: row.attempts,
    last_http_status: row.last_http_status,
    last_error_code: row.last_error_code,
    last_error_message: row.last_error_message,
    next_retry_at: row.next_retry_at,
    forwarded_at: row.forwarded_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function normalizeResolution(row: LossEventResolutionRecord): LossEventResolutionView {
  return {
    resolution_id: row.id,
    loss_event_id: row.loss_event_id,
    reason: row.reason,
    status: row.status,
    target_count: row.target_count,
    forwarded_count: row.forwarded_count,
    failed_count: row.failed_count,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_forwarded_at: row.last_forwarded_at,
    resolved_at: row.resolved_at,
  };
}

function normalizeResolutionOutbox(row: LossEventResolutionOutboxRecord): LossOutboxView {
  return {
    outbox_id: row.id,
    loss_event_id: row.loss_event_id,
    target_service: row.target_service,
    target_url: row.target_url,
    status: row.status,
    attempts: row.attempts,
    last_http_status: row.last_http_status,
    last_error_code: row.last_error_code,
    last_error_message: row.last_error_message,
    next_retry_at: row.next_retry_at,
    forwarded_at: row.forwarded_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function parseRecord<T>(row: Record<string, unknown> | null, parser: (row: Record<string, unknown>) => T | null): T | null {
  if (!row) return null;
  return parser(row);
}

function asString(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return value.toString();
  return null;
}

function asNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim().length > 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function parseLossEventRecord(row: Record<string, unknown>): LossEventRecord | null {
  const id = asString(row.id);
  const idempotency_key = asString(row.idempotency_key);
  const request_hash = asString(row.request_hash);
  const source_service = asString(row.source_service);
  const source_event_id = asString(row.source_event_id);
  const account_did = asString(row.account_did);
  const account_id = asString(row.account_id);
  const currency = asString(row.currency);
  const amount_minor = asString(row.amount_minor);
  const reason_code = asString(row.reason_code);
  const severityRaw = asString(row.severity);
  const occurred_at = asString(row.occurred_at);
  const metadata_json = asString(row.metadata_json);
  const statusRaw = asString(row.status);
  const target_count = asNumber(row.target_count);
  const forwarded_count = asNumber(row.forwarded_count);
  const failed_count = asNumber(row.failed_count);
  const created_at = asString(row.created_at);
  const updated_at = asString(row.updated_at);
  const last_forwarded_at = asString(row.last_forwarded_at);

  if (
    !id ||
    !idempotency_key ||
    !request_hash ||
    !source_service ||
    !source_event_id ||
    !account_did ||
    !currency ||
    !amount_minor ||
    !reason_code ||
    !severityRaw ||
    !occurred_at ||
    !statusRaw ||
    target_count === null ||
    forwarded_count === null ||
    failed_count === null ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  if (currency !== 'USD') return null;
  if (severityRaw !== 'low' && severityRaw !== 'medium' && severityRaw !== 'high' && severityRaw !== 'critical') {
    return null;
  }

  if (
    statusRaw !== 'recorded' &&
    statusRaw !== 'processing' &&
    statusRaw !== 'partially_forwarded' &&
    statusRaw !== 'forwarded' &&
    statusRaw !== 'failed'
  ) {
    return null;
  }

  return {
    id,
    idempotency_key,
    request_hash,
    source_service,
    source_event_id,
    account_did,
    account_id,
    currency: 'USD',
    amount_minor,
    reason_code,
    severity: severityRaw,
    occurred_at,
    metadata_json,
    status: statusRaw,
    target_count,
    forwarded_count,
    failed_count,
    created_at,
    updated_at,
    last_forwarded_at,
  };
}

function parseLossOutboxRecord(row: Record<string, unknown>): LossEventOutboxRecord | null {
  const id = asString(row.id);
  const loss_event_id = asString(row.loss_event_id);
  const target_service_raw = asString(row.target_service);
  const target_url = asString(row.target_url);
  const status_raw = asString(row.status);
  const attempts = asNumber(row.attempts);
  const last_http_status = asNumber(row.last_http_status);
  const last_error_code = asString(row.last_error_code);
  const last_error_message = asString(row.last_error_message);
  const next_retry_at = asString(row.next_retry_at);
  const forwarded_at = asString(row.forwarded_at);
  const created_at = asString(row.created_at);
  const updated_at = asString(row.updated_at);

  if (!id || !loss_event_id || !target_service_raw || !target_url || !status_raw || attempts === null || !created_at || !updated_at) {
    return null;
  }

  if (!LOSS_TARGETS.includes(target_service_raw as LossTargetService)) {
    return null;
  }

  if (status_raw !== 'pending' && status_raw !== 'forwarded' && status_raw !== 'failed') {
    return null;
  }

  return {
    id,
    loss_event_id,
    target_service: target_service_raw as LossTargetService,
    target_url,
    status: status_raw,
    attempts,
    last_http_status,
    last_error_code,
    last_error_message,
    next_retry_at,
    forwarded_at,
    created_at,
    updated_at,
  };
}

function parseLossResolutionRecord(row: Record<string, unknown>): LossEventResolutionRecord | null {
  const id = asString(row.id);
  const loss_event_id = asString(row.loss_event_id);
  const idempotency_key = asString(row.idempotency_key);
  const request_hash = asString(row.request_hash);
  const reason = asString(row.reason);
  const statusRaw = asString(row.status);
  const target_count = asNumber(row.target_count);
  const forwarded_count = asNumber(row.forwarded_count);
  const failed_count = asNumber(row.failed_count);
  const created_at = asString(row.created_at);
  const updated_at = asString(row.updated_at);
  const last_forwarded_at = asString(row.last_forwarded_at);
  const resolved_at = asString(row.resolved_at);

  if (
    !id ||
    !loss_event_id ||
    !idempotency_key ||
    !request_hash ||
    !statusRaw ||
    target_count === null ||
    forwarded_count === null ||
    failed_count === null ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  if (
    statusRaw !== 'recorded' &&
    statusRaw !== 'processing' &&
    statusRaw !== 'partially_forwarded' &&
    statusRaw !== 'forwarded' &&
    statusRaw !== 'failed'
  ) {
    return null;
  }

  return {
    id,
    loss_event_id,
    idempotency_key,
    request_hash,
    reason,
    status: statusRaw,
    target_count,
    forwarded_count,
    failed_count,
    created_at,
    updated_at,
    last_forwarded_at,
    resolved_at,
  };
}

function parseLossResolutionOutboxRecord(row: Record<string, unknown>): LossEventResolutionOutboxRecord | null {
  const id = asString(row.id);
  const loss_event_id = asString(row.loss_event_id);
  const target_service_raw = asString(row.target_service);
  const target_url = asString(row.target_url);
  const status_raw = asString(row.status);
  const attempts = asNumber(row.attempts);
  const last_http_status = asNumber(row.last_http_status);
  const last_error_code = asString(row.last_error_code);
  const last_error_message = asString(row.last_error_message);
  const next_retry_at = asString(row.next_retry_at);
  const forwarded_at = asString(row.forwarded_at);
  const created_at = asString(row.created_at);
  const updated_at = asString(row.updated_at);

  if (!id || !loss_event_id || !target_service_raw || !target_url || !status_raw || attempts === null || !created_at || !updated_at) {
    return null;
  }

  if (!LOSS_TARGETS.includes(target_service_raw as LossTargetService)) {
    return null;
  }

  if (status_raw !== 'pending' && status_raw !== 'forwarded' && status_raw !== 'failed') {
    return null;
  }

  return {
    id,
    loss_event_id,
    target_service: target_service_raw as LossTargetService,
    target_url,
    status: status_raw,
    attempts,
    last_http_status,
    last_error_code,
    last_error_message,
    next_retry_at,
    forwarded_at,
    created_at,
    updated_at,
  };
}

function getBearerToken(request: Request): string | null {
  const authorization = request.headers.get('authorization') ?? request.headers.get('Authorization');
  if (!authorization) return null;
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (typeof value !== 'string') return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === '1' || normalized === 'true' || normalized === 'yes') return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no') return false;
  return fallback;
}

function parseIntegerEnv(value: string | undefined, fallback: number, field: string): number {
  if (!value || value.trim().length === 0) return fallback;
  const parsed = Number.parseInt(value.trim(), 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new ClawSettleError('Invalid numeric environment configuration', 'DEPENDENCY_NOT_CONFIGURED', 503, {
      field,
      value,
    });
  }

  return parsed;
}

function parseQueryLimit(value: string | null, fallback: number, max = 200): number {
  if (!value || value.trim().length === 0) return fallback;
  const parsed = Number.parseInt(value.trim(), 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new ClawSettleError('limit must be a positive integer', 'INVALID_REQUEST', 400, {
      field: 'limit',
      value,
    });
  }

  return Math.min(parsed, max);
}

function parseOutboxOperation(value: string | null): LossOutboxOperation {
  if (!value || value.trim().length === 0) {
    return 'apply';
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === 'apply' || normalized === 'resolve') {
    return normalized;
  }

  throw new ClawSettleError('operation must be apply|resolve', 'INVALID_REQUEST', 400, {
    field: 'operation',
    value,
  });
}

function parseLossResolutionPayload(input: unknown): { reason: string | null } {
  if (input === null || input === undefined) {
    return { reason: null };
  }

  if (typeof input !== 'object' || Array.isArray(input)) {
    throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
  }

  const payload = input as Record<string, unknown>;
  const reasonRaw = payload.reason;

  if (reasonRaw === undefined || reasonRaw === null) {
    return { reason: null };
  }

  if (typeof reasonRaw !== 'string' || reasonRaw.trim().length === 0) {
    throw new ClawSettleError('reason must be a non-empty string', 'INVALID_REQUEST', 400, {
      field: 'reason',
    });
  }

  return { reason: reasonRaw.trim() };
}

function resolveTargetConfigs(
  env: Env,
  payload: {
    account_did: string;
    account_id: string | null;
    reason_code: string;
    metadata: Record<string, unknown> | null;
    requested_targets: LossTargetService[] | null;
  }
): LossTargetConfig[] {
  const requested = payload.requested_targets
    ? payload.requested_targets
    : [
        'ledger',
        'clawinsure',
        'clawincome',
        ...(typeof payload.metadata?.escrow_id === 'string' ? (['escrow'] as const) : []),
        ...(typeof payload.metadata?.bounty_id === 'string' ? (['clawbounties'] as const) : []),
      ];

  const unique = Array.from(new Set(requested));

  const configs: LossTargetConfig[] = [];

  for (const target of unique) {
    if (target === 'ledger') {
      const baseUrl = env.LEDGER_BASE_URL?.trim();
      const token = (env.LEDGER_RISK_KEY ?? env.LEDGER_ADMIN_KEY)?.trim();
      if (!baseUrl) {
        throw new ClawSettleError('Ledger base URL not configured for loss events', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'LEDGER_BASE_URL',
        });
      }
      if (!token) {
        throw new ClawSettleError('Ledger risk key not configured for loss events', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'LEDGER_RISK_KEY',
        });
      }
      configs.push({
        service: 'ledger',
        url: `${baseUrl.replace(/\/$/, '')}/v1/risk/holds/apply`,
        auth_token: token,
      });
      continue;
    }

    if (target === 'escrow') {
      const escrowId = typeof payload.metadata?.escrow_id === 'string' ? payload.metadata.escrow_id.trim() : null;
      if (!escrowId) {
        throw new ClawSettleError('escrow target requires metadata.escrow_id', 'INVALID_REQUEST', 400, {
          field: 'metadata.escrow_id',
        });
      }
      const baseUrl = env.ESCROW_BASE_URL?.trim();
      const token = env.ESCROW_RISK_KEY?.trim();
      if (!baseUrl) {
        throw new ClawSettleError('Escrow base URL not configured for loss events', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'ESCROW_BASE_URL',
        });
      }
      if (!token) {
        throw new ClawSettleError('Escrow risk key not configured for loss events', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'ESCROW_RISK_KEY',
        });
      }
      configs.push({
        service: 'escrow',
        url: `${baseUrl.replace(/\/$/, '')}/v1/escrows/${encodeURIComponent(escrowId)}/risk-hold`,
        auth_token: token,
      });
      continue;
    }

    if (target === 'clawinsure') {
      const baseUrl = env.CLAWINSURE_BASE_URL?.trim();
      const token = env.INSURE_RISK_KEY?.trim();
      if (!baseUrl) {
        throw new ClawSettleError('Clawinsure base URL not configured for loss events', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'CLAWINSURE_BASE_URL',
        });
      }
      if (!token) {
        throw new ClawSettleError('INSURE_RISK_KEY not configured for loss events', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'INSURE_RISK_KEY',
        });
      }
      configs.push({
        service: 'clawinsure',
        url: `${baseUrl.replace(/\/$/, '')}/v1/claims/auto`,
        auth_token: token,
      });
      continue;
    }

    if (target === 'clawincome') {
      const baseUrl = env.CLAWINCOME_BASE_URL?.trim();
      const token = env.INCOME_RISK_KEY?.trim();
      if (!baseUrl) {
        throw new ClawSettleError('Clawincome base URL not configured for loss events', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'CLAWINCOME_BASE_URL',
        });
      }
      if (!token) {
        throw new ClawSettleError('INCOME_RISK_KEY not configured for loss events', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'INCOME_RISK_KEY',
        });
      }
      configs.push({
        service: 'clawincome',
        url: `${baseUrl.replace(/\/$/, '')}/v1/risk/adjustments`,
        auth_token: token,
      });
      continue;
    }

    if (target === 'clawbounties') {
      const bountyId = typeof payload.metadata?.bounty_id === 'string' ? payload.metadata.bounty_id.trim() : null;
      if (!bountyId) {
        throw new ClawSettleError('clawbounties target requires metadata.bounty_id', 'INVALID_REQUEST', 400, {
          field: 'metadata.bounty_id',
        });
      }

      const baseUrl = env.CLAWBOUNTIES_BASE_URL?.trim();
      const token = env.BOUNTIES_RISK_KEY?.trim();
      if (!baseUrl) {
        throw new ClawSettleError('Clawbounties base URL not configured for loss events', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'CLAWBOUNTIES_BASE_URL',
        });
      }
      if (!token) {
        throw new ClawSettleError('BOUNTIES_RISK_KEY not configured for loss events', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'BOUNTIES_RISK_KEY',
        });
      }
      configs.push({
        service: 'clawbounties',
        url: `${baseUrl.replace(/\/$/, '')}/v1/risk/loss-events`,
        auth_token: token,
      });
      continue;
    }
  }

  if (configs.length === 0) {
    throw new ClawSettleError('No valid loss-event targets resolved', 'INVALID_REQUEST', 400);
  }

  return configs;
}

function resolveResolutionTargetConfigs(
  env: Env,
  params: {
    event: LossEventRecord;
    apply_outbox: LossEventOutboxRecord[];
  }
): LossTargetConfig[] {
  const hasEscrow = params.apply_outbox.some((row) => row.target_service === 'escrow');
  const hasBounties = params.apply_outbox.some((row) => row.target_service === 'clawbounties');

  const targets: LossTargetService[] = [
    'ledger',
    ...(hasEscrow ? (['escrow'] as const) : []),
    ...(hasBounties ? (['clawbounties'] as const) : []),
  ];

  const configs: LossTargetConfig[] = [];

  for (const target of targets) {
    if (target === 'ledger') {
      const baseUrl = env.LEDGER_BASE_URL?.trim();
      const token = (env.LEDGER_RISK_KEY ?? env.LEDGER_ADMIN_KEY)?.trim();
      if (!baseUrl) {
        throw new ClawSettleError('Ledger base URL not configured for loss-event resolution', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'LEDGER_BASE_URL',
        });
      }
      if (!token) {
        throw new ClawSettleError('Ledger risk key not configured for loss-event resolution', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'LEDGER_RISK_KEY',
        });
      }

      configs.push({
        service: 'ledger',
        url: `${baseUrl.replace(/\/$/, '')}/v1/risk/holds/release-by-source`,
        auth_token: token,
      });
      continue;
    }

    if (target === 'escrow') {
      const token = env.ESCROW_RISK_KEY?.trim();
      if (!token) {
        throw new ClawSettleError('ESCROW_RISK_KEY not configured for loss-event resolution', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'ESCROW_RISK_KEY',
        });
      }

      const escrowOutbox = params.apply_outbox.find((row) => row.target_service === 'escrow') ?? null;
      if (!escrowOutbox) {
        throw new ClawSettleError('Escrow outbox entry not found for loss-event resolution', 'INTERNAL_ERROR', 500, {
          loss_event_id: params.event.id,
        });
      }

      configs.push({
        service: 'escrow',
        url: escrowOutbox.target_url,
        auth_token: token,
      });
      continue;
    }

    if (target === 'clawbounties') {
      const baseUrl = env.CLAWBOUNTIES_BASE_URL?.trim();
      const token = env.BOUNTIES_RISK_KEY?.trim();
      if (!baseUrl) {
        throw new ClawSettleError('Clawbounties base URL not configured for loss-event resolution', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'CLAWBOUNTIES_BASE_URL',
        });
      }
      if (!token) {
        throw new ClawSettleError('BOUNTIES_RISK_KEY not configured for loss-event resolution', 'DEPENDENCY_NOT_CONFIGURED', 503, {
          field: 'BOUNTIES_RISK_KEY',
        });
      }

      configs.push({
        service: 'clawbounties',
        url: `${baseUrl.replace(/\/$/, '')}/v1/risk/loss-events/clear`,
        auth_token: token,
      });
      continue;
    }
  }

  return configs;
}

function buildTargetRequestBody(
  target: LossTargetService,
  event: LossEventRecord,
  targetIdempotencyKey: string
): Record<string, unknown> {
  const metadata = parseJsonObject<Record<string, unknown>>(event.metadata_json);

  if (target === 'ledger') {
    const accountRef = event.account_did ?? event.account_id;

    return {
      idempotency_key: targetIdempotencyKey,
      source_loss_event_id: event.id,
      account: accountRef,
      amount_minor: event.amount_minor,
      currency: event.currency,
      reason: event.reason_code,
      metadata: {
        source_service: event.source_service,
        source_event_id: event.source_event_id,
        severity: event.severity,
        account_did: event.account_did,
        ...(metadata ? { upstream: metadata } : {}),
      },
    };
  }

  if (target === 'escrow') {
    return {
      idempotency_key: targetIdempotencyKey,
      action: 'apply',
      source_loss_event_id: event.id,
      reason: event.reason_code,
      metadata: {
        source_service: event.source_service,
        source_event_id: event.source_event_id,
        severity: event.severity,
        amount_minor: event.amount_minor,
        account_id: event.account_id,
        account_did: event.account_did,
        ...(metadata ? { upstream: metadata } : {}),
      },
    };
  }

  if (target === 'clawincome') {
    return {
      idempotency_key: targetIdempotencyKey,
      source_loss_event_id: event.id,
      source_service: event.source_service,
      source_event_id: event.source_event_id,
      account_id: event.account_id ?? event.account_did,
      account_did: event.account_did,
      direction: 'debit',
      amount_minor: event.amount_minor,
      currency: event.currency,
      reason_code: event.reason_code,
      severity: event.severity,
      occurred_at: event.occurred_at,
      metadata: metadata ?? null,
    };
  }

  if (target === 'clawbounties') {
    const bountyId = typeof metadata?.bounty_id === 'string' ? metadata.bounty_id.trim() : null;

    return {
      idempotency_key: targetIdempotencyKey,
      source_loss_event_id: event.id,
      source_service: event.source_service,
      source_event_id: event.source_event_id,
      bounty_id: bountyId,
      account_did: event.account_did,
      amount_minor: event.amount_minor,
      currency: event.currency,
      reason_code: event.reason_code,
      severity: event.severity,
      metadata: metadata ?? null,
    };
  }

  return {
    idempotency_key: targetIdempotencyKey,
    source_loss_event_id: event.id,
    source_service: event.source_service,
    source_event_id: event.source_event_id,
    account_id: event.account_id ?? event.account_did,
    account_did: event.account_did,
    amount_minor: event.amount_minor,
    currency: event.currency,
    reason_code: event.reason_code,
    severity: event.severity,
    occurred_at: event.occurred_at,
    metadata: metadata ?? null,
  };
}

function classifyForwardFailure(status: number | null, errorCode: string): {
  permanent: boolean;
} {
  if (errorCode === 'DEPENDENCY_NOT_CONFIGURED') {
    return { permanent: false };
  }

  if (status === null) {
    return { permanent: false };
  }

  if (status >= 500 || status === 429) {
    return { permanent: false };
  }

  if (status === 409) {
    // Treat idempotency conflicts as success at caller boundary.
    return { permanent: true };
  }

  return { permanent: status >= 400 && status < 500 };
}

function computeNextRetryAt(attempts: number, now: string): string {
  const baseSeconds = Math.min(15 * Math.max(1, attempts), 300);
  const when = new Date(now);
  when.setUTCSeconds(when.getUTCSeconds() + baseSeconds);
  return when.toISOString();
}

async function readLossEventById(db: D1Database, lossEventId: string): Promise<LossEventRecord | null> {
  const row = await db.prepare('SELECT * FROM loss_events WHERE id = ?').bind(lossEventId).first<Record<string, unknown>>();
  return parseRecord(row, parseLossEventRecord);
}

async function readLossEventByIdempotencyKey(db: D1Database, idempotencyKey: string): Promise<LossEventRecord | null> {
  const row = await db
    .prepare('SELECT * FROM loss_events WHERE idempotency_key = ?')
    .bind(idempotencyKey)
    .first<Record<string, unknown>>();
  return parseRecord(row, parseLossEventRecord);
}

async function readLossOutboxByEventId(db: D1Database, lossEventId: string): Promise<LossEventOutboxRecord[]> {
  const rows = await db
    .prepare('SELECT * FROM loss_event_outbox WHERE loss_event_id = ? ORDER BY created_at ASC, id ASC')
    .bind(lossEventId)
    .all<Record<string, unknown>>();

  return (rows.results ?? [])
    .map((row) => parseLossOutboxRecord(row))
    .filter((row): row is LossEventOutboxRecord => Boolean(row));
}

async function readLossResolutionByIdempotencyKey(db: D1Database, idempotencyKey: string): Promise<LossEventResolutionRecord | null> {
  const row = await db
    .prepare('SELECT * FROM loss_event_resolutions WHERE idempotency_key = ?')
    .bind(idempotencyKey)
    .first<Record<string, unknown>>();

  return parseRecord(row, parseLossResolutionRecord);
}

async function readLossResolutionByEventId(db: D1Database, lossEventId: string): Promise<LossEventResolutionRecord | null> {
  const row = await db
    .prepare('SELECT * FROM loss_event_resolutions WHERE loss_event_id = ?')
    .bind(lossEventId)
    .first<Record<string, unknown>>();

  return parseRecord(row, parseLossResolutionRecord);
}

async function readResolutionOutboxByEventId(db: D1Database, lossEventId: string): Promise<LossEventResolutionOutboxRecord[]> {
  const rows = await db
    .prepare('SELECT * FROM loss_event_resolution_outbox WHERE loss_event_id = ? ORDER BY created_at ASC, id ASC')
    .bind(lossEventId)
    .all<Record<string, unknown>>();

  return (rows.results ?? [])
    .map((row) => parseLossResolutionOutboxRecord(row))
    .filter((row): row is LossEventResolutionOutboxRecord => Boolean(row));
}

async function recomputeLossEventStatus(db: D1Database, lossEventId: string, at: string): Promise<void> {
  const summaryRow = await db
    .prepare(
      `SELECT
        COUNT(1) AS target_count,
        SUM(CASE WHEN status = 'forwarded' THEN 1 ELSE 0 END) AS forwarded_count,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_count
       FROM loss_event_outbox
       WHERE loss_event_id = ?`
    )
    .bind(lossEventId)
    .first<Record<string, unknown>>();

  if (!summaryRow) {
    return;
  }

  const targetCount = asNumber(summaryRow.target_count) ?? 0;
  const forwardedCount = asNumber(summaryRow.forwarded_count) ?? 0;
  const failedCount = asNumber(summaryRow.failed_count) ?? 0;
  const pendingCount = asNumber(summaryRow.pending_count) ?? 0;

  let status: LossEventStatus = 'recorded';
  if (targetCount > 0 && forwardedCount === targetCount) {
    status = 'forwarded';
  } else if (failedCount > 0 && forwardedCount > 0) {
    status = 'partially_forwarded';
  } else if (failedCount > 0 && pendingCount === 0 && forwardedCount === 0) {
    status = 'failed';
  } else if (forwardedCount > 0) {
    status = 'partially_forwarded';
  } else if (pendingCount < targetCount) {
    status = 'processing';
  }

  await db
    .prepare(
      `UPDATE loss_events
       SET status = ?,
           target_count = ?,
           forwarded_count = ?,
           failed_count = ?,
           updated_at = ?,
           last_forwarded_at = CASE WHEN ? > 0 THEN ? ELSE last_forwarded_at END
       WHERE id = ?`
    )
    .bind(status, targetCount, forwardedCount, failedCount, at, forwardedCount, at, lossEventId)
    .run();
}

async function markOutboxForwarded(db: D1Database, outbox: LossEventOutboxRecord, now: string, httpStatus: number): Promise<void> {
  await db
    .prepare(
      `UPDATE loss_event_outbox
       SET status = 'forwarded',
           attempts = ?,
           last_http_status = ?,
           last_error_code = NULL,
           last_error_message = NULL,
           next_retry_at = NULL,
           forwarded_at = ?,
           updated_at = ?
       WHERE id = ?`
    )
    .bind(outbox.attempts + 1, httpStatus, now, now, outbox.id)
    .run();

  await recomputeLossEventStatus(db, outbox.loss_event_id, now);
}

async function markOutboxFailed(
  db: D1Database,
  outbox: LossEventOutboxRecord,
  now: string,
  params: {
    http_status: number | null;
    error_code: string;
    error_message: string;
    next_retry_at: string | null;
    permanent: boolean;
  }
): Promise<void> {
  await db
    .prepare(
      `UPDATE loss_event_outbox
       SET status = 'failed',
           attempts = ?,
           last_http_status = ?,
           last_error_code = ?,
           last_error_message = ?,
           next_retry_at = ?,
           updated_at = ?
       WHERE id = ?`
    )
    .bind(
      outbox.attempts + 1,
      params.http_status,
      params.error_code,
      params.error_message.slice(0, 1000),
      params.permanent ? null : params.next_retry_at,
      now,
      outbox.id
    )
    .run();

  await recomputeLossEventStatus(db, outbox.loss_event_id, now);
}

async function recomputeLossResolutionStatus(db: D1Database, lossEventId: string, at: string): Promise<void> {
  const summaryRow = await db
    .prepare(
      `SELECT
        COUNT(1) AS target_count,
        SUM(CASE WHEN status = 'forwarded' THEN 1 ELSE 0 END) AS forwarded_count,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_count
       FROM loss_event_resolution_outbox
       WHERE loss_event_id = ?`
    )
    .bind(lossEventId)
    .first<Record<string, unknown>>();

  if (!summaryRow) {
    return;
  }

  const targetCount = asNumber(summaryRow.target_count) ?? 0;
  const forwardedCount = asNumber(summaryRow.forwarded_count) ?? 0;
  const failedCount = asNumber(summaryRow.failed_count) ?? 0;
  const pendingCount = asNumber(summaryRow.pending_count) ?? 0;

  let status: LossEventStatus = 'recorded';
  if (targetCount > 0 && forwardedCount === targetCount) {
    status = 'forwarded';
  } else if (failedCount > 0 && forwardedCount > 0) {
    status = 'partially_forwarded';
  } else if (failedCount > 0 && pendingCount === 0 && forwardedCount === 0) {
    status = 'failed';
  } else if (forwardedCount > 0) {
    status = 'partially_forwarded';
  } else if (pendingCount < targetCount) {
    status = 'processing';
  }

  await db
    .prepare(
      `UPDATE loss_event_resolutions
       SET status = ?,
           target_count = ?,
           forwarded_count = ?,
           failed_count = ?,
           updated_at = ?,
           last_forwarded_at = CASE WHEN ? > 0 THEN ? ELSE last_forwarded_at END,
           resolved_at = CASE WHEN ? = 'forwarded' THEN COALESCE(resolved_at, ?) ELSE resolved_at END
       WHERE loss_event_id = ?`
    )
    .bind(
      status,
      targetCount,
      forwardedCount,
      failedCount,
      at,
      forwardedCount,
      at,
      status,
      at,
      lossEventId
    )
    .run();
}

async function markResolutionOutboxForwarded(
  db: D1Database,
  outbox: LossEventResolutionOutboxRecord,
  now: string,
  httpStatus: number
): Promise<void> {
  await db
    .prepare(
      `UPDATE loss_event_resolution_outbox
       SET status = 'forwarded',
           attempts = ?,
           last_http_status = ?,
           last_error_code = NULL,
           last_error_message = NULL,
           next_retry_at = NULL,
           forwarded_at = ?,
           updated_at = ?
       WHERE id = ?`
    )
    .bind(outbox.attempts + 1, httpStatus, now, now, outbox.id)
    .run();

  await recomputeLossResolutionStatus(db, outbox.loss_event_id, now);
}

async function markResolutionOutboxFailed(
  db: D1Database,
  outbox: LossEventResolutionOutboxRecord,
  now: string,
  params: {
    http_status: number | null;
    error_code: string;
    error_message: string;
    next_retry_at: string | null;
    permanent: boolean;
  }
): Promise<void> {
  await db
    .prepare(
      `UPDATE loss_event_resolution_outbox
       SET status = 'failed',
           attempts = ?,
           last_http_status = ?,
           last_error_code = ?,
           last_error_message = ?,
           next_retry_at = ?,
           updated_at = ?
       WHERE id = ?`
    )
    .bind(
      outbox.attempts + 1,
      params.http_status,
      params.error_code,
      params.error_message.slice(0, 1000),
      params.permanent ? null : params.next_retry_at,
      now,
      outbox.id
    )
    .run();

  await recomputeLossResolutionStatus(db, outbox.loss_event_id, now);
}

async function fetchRetryableResolutionOutbox(
  db: D1Database,
  params: {
    now: string;
    limit: number;
    loss_event_id?: string;
  }
): Promise<Array<{ outbox: LossEventResolutionOutboxRecord; event: LossEventRecord; resolution: LossEventResolutionRecord }>> {
  const where: string[] = [
    "o.status IN ('pending','failed')",
    '(o.next_retry_at IS NULL OR o.next_retry_at <= ?)',
  ];
  const binds: unknown[] = [params.now];

  if (params.loss_event_id) {
    where.push('o.loss_event_id = ?');
    binds.push(params.loss_event_id);
  }

  binds.push(params.limit);

  const query = `SELECT
    o.id AS outbox_id,
    o.loss_event_id AS outbox_loss_event_id,
    o.target_service,
    o.target_url,
    o.status AS outbox_status,
    o.attempts,
    o.last_http_status,
    o.last_error_code,
    o.last_error_message,
    o.next_retry_at,
    o.forwarded_at,
    o.created_at AS outbox_created_at,
    o.updated_at AS outbox_updated_at,
    r.id AS resolution_id,
    r.idempotency_key AS resolution_idempotency_key,
    r.request_hash AS resolution_request_hash,
    r.reason AS resolution_reason,
    r.status AS resolution_status,
    r.target_count AS resolution_target_count,
    r.forwarded_count AS resolution_forwarded_count,
    r.failed_count AS resolution_failed_count,
    r.created_at AS resolution_created_at,
    r.updated_at AS resolution_updated_at,
    r.last_forwarded_at AS resolution_last_forwarded_at,
    r.resolved_at AS resolution_resolved_at,
    e.*
  FROM loss_event_resolution_outbox o
  JOIN loss_event_resolutions r ON r.loss_event_id = o.loss_event_id
  JOIN loss_events e ON e.id = o.loss_event_id
  WHERE ${where.join(' AND ')}
  ORDER BY o.created_at ASC, o.id ASC
  LIMIT ?`;

  const rows = await db.prepare(query).bind(...binds).all<Record<string, unknown>>();
  const results: Array<{ outbox: LossEventResolutionOutboxRecord; event: LossEventRecord; resolution: LossEventResolutionRecord }> = [];

  for (const row of rows.results ?? []) {
    const outbox = parseLossResolutionOutboxRecord({
      id: row.outbox_id,
      loss_event_id: row.outbox_loss_event_id,
      target_service: row.target_service,
      target_url: row.target_url,
      status: row.outbox_status,
      attempts: row.attempts,
      last_http_status: row.last_http_status,
      last_error_code: row.last_error_code,
      last_error_message: row.last_error_message,
      next_retry_at: row.next_retry_at,
      forwarded_at: row.forwarded_at,
      created_at: row.outbox_created_at,
      updated_at: row.outbox_updated_at,
    });

    const resolution = parseLossResolutionRecord({
      id: row.resolution_id,
      loss_event_id: row.outbox_loss_event_id,
      idempotency_key: row.resolution_idempotency_key,
      request_hash: row.resolution_request_hash,
      reason: row.resolution_reason,
      status: row.resolution_status,
      target_count: row.resolution_target_count,
      forwarded_count: row.resolution_forwarded_count,
      failed_count: row.resolution_failed_count,
      created_at: row.resolution_created_at,
      updated_at: row.resolution_updated_at,
      last_forwarded_at: row.resolution_last_forwarded_at,
      resolved_at: row.resolution_resolved_at,
    });

    const event = parseLossEventRecord({
      id: row.id,
      idempotency_key: row.idempotency_key,
      request_hash: row.request_hash,
      source_service: row.source_service,
      source_event_id: row.source_event_id,
      account_id: row.account_id,
      account_did: row.account_did,
      currency: row.currency,
      amount_minor: row.amount_minor,
      reason_code: row.reason_code,
      severity: row.severity,
      occurred_at: row.occurred_at,
      metadata_json: row.metadata_json,
      status: row.status,
      target_count: row.target_count,
      forwarded_count: row.forwarded_count,
      failed_count: row.failed_count,
      created_at: row.created_at,
      updated_at: row.updated_at,
      last_forwarded_at: row.last_forwarded_at,
    });

    if (outbox && resolution && event) {
      results.push({ outbox, resolution, event });
    }
  }

  return results;
}

async function fetchRetryableOutbox(
  db: D1Database,
  params: {
    now: string;
    limit: number;
    loss_event_id?: string;
  }
): Promise<Array<{ outbox: LossEventOutboxRecord; event: LossEventRecord }>> {
  const where: string[] = [
    "o.status IN ('pending','failed')",
    '(o.next_retry_at IS NULL OR o.next_retry_at <= ?)',
  ];
  const binds: unknown[] = [params.now];

  if (params.loss_event_id) {
    where.push('o.loss_event_id = ?');
    binds.push(params.loss_event_id);
  }

  binds.push(params.limit);

  const query = `SELECT
    o.id AS outbox_id,
    o.loss_event_id AS outbox_loss_event_id,
    o.target_service,
    o.target_url,
    o.status AS outbox_status,
    o.attempts,
    o.last_http_status,
    o.last_error_code,
    o.last_error_message,
    o.next_retry_at,
    o.forwarded_at,
    o.created_at AS outbox_created_at,
    o.updated_at AS outbox_updated_at,
    e.*
  FROM loss_event_outbox o
  JOIN loss_events e ON e.id = o.loss_event_id
  WHERE ${where.join(' AND ')}
  ORDER BY o.created_at ASC, o.id ASC
  LIMIT ?`;

  const rows = await db.prepare(query).bind(...binds).all<Record<string, unknown>>();
  const results: Array<{ outbox: LossEventOutboxRecord; event: LossEventRecord }> = [];

  for (const row of rows.results ?? []) {
    const outbox = parseLossOutboxRecord({
      id: row.outbox_id,
      loss_event_id: row.outbox_loss_event_id,
      target_service: row.target_service,
      target_url: row.target_url,
      status: row.outbox_status,
      attempts: row.attempts,
      last_http_status: row.last_http_status,
      last_error_code: row.last_error_code,
      last_error_message: row.last_error_message,
      next_retry_at: row.next_retry_at,
      forwarded_at: row.forwarded_at,
      created_at: row.outbox_created_at,
      updated_at: row.outbox_updated_at,
    });

    const event = parseLossEventRecord({
      id: row.id,
      idempotency_key: row.idempotency_key,
      request_hash: row.request_hash,
      source_service: row.source_service,
      source_event_id: row.source_event_id,
      account_id: row.account_id,
      account_did: row.account_did,
      currency: row.currency,
      amount_minor: row.amount_minor,
      reason_code: row.reason_code,
      severity: row.severity,
      occurred_at: row.occurred_at,
      metadata_json: row.metadata_json,
      status: row.status,
      target_count: row.target_count,
      forwarded_count: row.forwarded_count,
      failed_count: row.failed_count,
      created_at: row.created_at,
      updated_at: row.updated_at,
      last_forwarded_at: row.last_forwarded_at,
    });

    if (outbox && event) {
      results.push({ outbox, event });
    }
  }

  return results;
}

async function forwardOutboxEntry(
  env: Env,
  outbox: LossEventOutboxRecord,
  event: LossEventRecord
): Promise<{ ok: boolean; http_status: number | null; error_code?: string; error_message?: string }> {
  const metadata = parseJsonObject<Record<string, unknown>>(event.metadata_json);

  const tokenByService: Record<LossTargetService, string | null> = {
    ledger: (env.LEDGER_RISK_KEY ?? env.LEDGER_ADMIN_KEY)?.trim() || null,
    escrow: env.ESCROW_RISK_KEY?.trim() || null,
    clawinsure: env.INSURE_RISK_KEY?.trim() || null,
    clawincome: env.INCOME_RISK_KEY?.trim() || null,
    clawbounties: env.BOUNTIES_RISK_KEY?.trim() || null,
  };

  const token = tokenByService[outbox.target_service];
  if (!token) {
    return {
      ok: false,
      http_status: null,
      error_code: 'DEPENDENCY_NOT_CONFIGURED',
      error_message: `${outbox.target_service} auth token is not configured`,
    };
  }

  if (outbox.target_service === 'escrow') {
    const escrowId = typeof metadata?.escrow_id === 'string' ? metadata.escrow_id.trim() : null;
    if (!escrowId) {
      return {
        ok: false,
        http_status: 400,
        error_code: 'INVALID_REQUEST',
        error_message: 'metadata.escrow_id missing for escrow risk hold',
      };
    }
  }

  if (outbox.target_service === 'clawbounties') {
    const bountyId = typeof metadata?.bounty_id === 'string' ? metadata.bounty_id.trim() : null;
    if (!bountyId) {
      return {
        ok: false,
        http_status: 400,
        error_code: 'INVALID_REQUEST',
        error_message: 'metadata.bounty_id missing for clawbounties fanout',
      };
    }
  }

  const targetIdempotencyKey = `loss-event:${event.id}:${outbox.target_service}`;
  const body = buildTargetRequestBody(outbox.target_service, event, targetIdempotencyKey);

  let response: Response;
  try {
    response = await fetch(outbox.target_url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        authorization: `Bearer ${token}`,
        'idempotency-key': targetIdempotencyKey,
      },
      body: JSON.stringify(body),
    });
  } catch (error) {
    return {
      ok: false,
      http_status: null,
      error_code: 'FETCH_FAILED',
      error_message: error instanceof Error ? error.message : String(error),
    };
  }

  const text = await response.text();
  let parsed: Record<string, unknown> | null = null;
  try {
    parsed = text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    parsed = null;
  }

  if (response.status === 409) {
    return { ok: true, http_status: response.status };
  }

  if (!response.ok) {
    const errorCode = typeof parsed?.code === 'string' ? parsed.code : 'UPSTREAM_ERROR';
    const errorMessage = typeof parsed?.error === 'string'
      ? parsed.error
      : typeof parsed?.message === 'string'
        ? parsed.message
        : text.slice(0, 500);

    return {
      ok: false,
      http_status: response.status,
      error_code: errorCode,
      error_message: errorMessage || `HTTP ${response.status}`,
    };
  }

  return { ok: true, http_status: response.status };
}

function buildResolutionTargetRequestBody(
  target: LossTargetService,
  event: LossEventRecord,
  resolution: LossEventResolutionRecord,
  targetIdempotencyKey: string
): Record<string, unknown> {
  const metadata = parseJsonObject<Record<string, unknown>>(event.metadata_json);

  if (target === 'ledger') {
    return {
      idempotency_key: targetIdempotencyKey,
      source_loss_event_id: event.id,
      reason: resolution.reason ?? `loss_event_resolved:${event.reason_code}`,
    };
  }

  if (target === 'escrow') {
    return {
      idempotency_key: targetIdempotencyKey,
      action: 'release',
      source_loss_event_id: event.id,
      reason: resolution.reason ?? `loss_event_resolved:${event.reason_code}`,
    };
  }

  if (target === 'clawbounties') {
    const bountyId = typeof metadata?.bounty_id === 'string' ? metadata.bounty_id.trim() : null;

    return {
      idempotency_key: targetIdempotencyKey,
      source_loss_event_id: event.id,
      bounty_id: bountyId,
      reason: resolution.reason ?? `loss_event_resolved:${event.reason_code}`,
      metadata: metadata ?? null,
    };
  }

  throw new ClawSettleError('Unsupported resolution target', 'INVALID_REQUEST', 400, {
    target,
  });
}

async function forwardResolutionOutboxEntry(
  env: Env,
  outbox: LossEventResolutionOutboxRecord,
  event: LossEventRecord,
  resolution: LossEventResolutionRecord
): Promise<{ ok: boolean; http_status: number | null; error_code?: string; error_message?: string }> {
  const metadata = parseJsonObject<Record<string, unknown>>(event.metadata_json);

  const tokenByService: Record<LossTargetService, string | null> = {
    ledger: (env.LEDGER_RISK_KEY ?? env.LEDGER_ADMIN_KEY)?.trim() || null,
    escrow: env.ESCROW_RISK_KEY?.trim() || null,
    clawinsure: env.INSURE_RISK_KEY?.trim() || null,
    clawincome: env.INCOME_RISK_KEY?.trim() || null,
    clawbounties: env.BOUNTIES_RISK_KEY?.trim() || null,
  };

  const token = tokenByService[outbox.target_service];
  if (!token) {
    return {
      ok: false,
      http_status: null,
      error_code: 'DEPENDENCY_NOT_CONFIGURED',
      error_message: `${outbox.target_service} auth token is not configured`,
    };
  }

  if (outbox.target_service === 'escrow') {
    const escrowId = typeof metadata?.escrow_id === 'string' ? metadata.escrow_id.trim() : null;
    if (!escrowId) {
      return {
        ok: false,
        http_status: 400,
        error_code: 'INVALID_REQUEST',
        error_message: 'metadata.escrow_id missing for escrow risk hold release',
      };
    }
  }

  if (outbox.target_service === 'clawbounties') {
    const bountyId = typeof metadata?.bounty_id === 'string' ? metadata.bounty_id.trim() : null;
    if (!bountyId) {
      return {
        ok: false,
        http_status: 400,
        error_code: 'INVALID_REQUEST',
        error_message: 'metadata.bounty_id missing for clawbounties risk clear',
      };
    }
  }

  if (outbox.target_service !== 'ledger' && outbox.target_service !== 'escrow' && outbox.target_service !== 'clawbounties') {
    return {
      ok: false,
      http_status: 400,
      error_code: 'INVALID_REQUEST',
      error_message: `Unsupported resolution target: ${outbox.target_service}`,
    };
  }

  const targetIdempotencyKey = `loss-event:resolve:${event.id}:${outbox.target_service}`;
  const body = buildResolutionTargetRequestBody(outbox.target_service, event, resolution, targetIdempotencyKey);

  let response: Response;
  try {
    response = await fetch(outbox.target_url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        authorization: `Bearer ${token}`,
        'idempotency-key': targetIdempotencyKey,
      },
      body: JSON.stringify(body),
    });
  } catch (error) {
    return {
      ok: false,
      http_status: null,
      error_code: 'FETCH_FAILED',
      error_message: error instanceof Error ? error.message : String(error),
    };
  }

  const text = await response.text();
  let parsed: Record<string, unknown> | null = null;
  try {
    parsed = text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : null;
  } catch {
    parsed = null;
  }

  if (response.status === 409) {
    return { ok: true, http_status: response.status };
  }

  if (!response.ok) {
    const errorCode =
      typeof parsed?.code === 'string'
        ? parsed.code
        : typeof parsed?.error === 'string'
          ? parsed.error
          : 'UPSTREAM_ERROR';

    const errorMessage =
      typeof parsed?.message === 'string'
        ? parsed.message
        : typeof parsed?.code === 'string' && typeof parsed?.error === 'string'
          ? parsed.error
          : text.slice(0, 500) || `HTTP ${response.status}`;

    return {
      ok: false,
      http_status: response.status,
      error_code: errorCode,
      error_message: errorMessage,
    };
  }

  return { ok: true, http_status: response.status };
}

export class LossEventService {
  constructor(private readonly env: Env) {}

  async createLossEvent(payloadInput: unknown, idempotencyKey: string): Promise<{
    ok: true;
    deduped: boolean;
    event: LossEventView;
    outbox: LossOutboxView[];
  }> {
    const payload = parseLossEventPayload(payloadInput);

    const canonicalRequest = {
      source_service: payload.source_service,
      source_event_id: payload.source_event_id,
      account_id: payload.account_id,
      account_did: payload.account_did,
      amount_minor: payload.amount_minor,
      currency: payload.currency,
      reason_code: payload.reason_code,
      severity: payload.severity,
      occurred_at: payload.occurred_at,
      metadata: payload.metadata,
      targets: payload.requested_targets,
    };
    const requestHash = await sha256Hex(stableStringify(canonicalRequest));

    const existing = await readLossEventByIdempotencyKey(this.env.DB, idempotencyKey);
    if (existing) {
      if (existing.request_hash !== requestHash) {
        throw new ClawSettleError(
          'Idempotency key replay with mismatched payload',
          'IDEMPOTENCY_CONFLICT',
          409,
          {
            idempotency_key: idempotencyKey,
            existing_loss_event_id: existing.id,
          }
        );
      }

      const outboxExisting = await readLossOutboxByEventId(this.env.DB, existing.id);
      return {
        ok: true,
        deduped: true,
        event: normalizeEvent(existing),
        outbox: outboxExisting.map((row) => normalizeOutbox(row)),
      };
    }

    const configs = resolveTargetConfigs(this.env, {
      account_did: payload.account_did,
      account_id: payload.account_id,
      reason_code: payload.reason_code,
      metadata: payload.metadata,
      requested_targets: payload.requested_targets,
    });

    const now = nowIso();
    const eventId = await deriveDeterministicId(
      'lse',
      stableStringify({
        source_service: payload.source_service,
        source_event_id: payload.source_event_id,
        idempotency_key: idempotencyKey,
      })
    );

    const eventInsert = this.env.DB.prepare(
      `INSERT INTO loss_events (
        id,
        idempotency_key,
        request_hash,
        source_service,
        source_event_id,
        account_did,
        account_id,
        currency,
        amount_minor,
        reason_code,
        severity,
        occurred_at,
        metadata_json,
        status,
        target_count,
        forwarded_count,
        failed_count,
        created_at,
        updated_at,
        last_forwarded_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'recorded', ?, 0, 0, ?, ?, NULL)`
    ).bind(
      eventId,
      idempotencyKey,
      requestHash,
      payload.source_service,
      payload.source_event_id,
      payload.account_did,
      payload.account_id,
      payload.currency,
      payload.amount_minor,
      payload.reason_code,
      payload.severity,
      payload.occurred_at,
      payload.metadata ? JSON.stringify(payload.metadata) : null,
      configs.length,
      now,
      now
    );

    const outboxStatements: D1PreparedStatement[] = [];
    for (const config of configs) {
      const outboxId = await deriveDeterministicId('lso', `${eventId}:${config.service}`);
      outboxStatements.push(
        this.env.DB.prepare(
          `INSERT INTO loss_event_outbox (
            id,
            loss_event_id,
            target_service,
            target_url,
            status,
            attempts,
            last_http_status,
            last_error_code,
            last_error_message,
            next_retry_at,
            forwarded_at,
            created_at,
            updated_at
          ) VALUES (?, ?, ?, ?, 'pending', 0, NULL, NULL, NULL, NULL, NULL, ?, ?)`
        ).bind(outboxId, eventId, config.service, config.url, now, now)
      );
    }

    try {
      await this.env.DB.batch([eventInsert, ...outboxStatements]);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      if (message.includes('UNIQUE constraint failed: loss_events.idempotency_key')) {
        const deduped = await readLossEventByIdempotencyKey(this.env.DB, idempotencyKey);
        if (!deduped) {
          throw new ClawSettleError('Failed to create loss event', 'INTERNAL_ERROR', 500);
        }
        if (deduped.request_hash !== requestHash) {
          throw new ClawSettleError(
            'Idempotency key replay with mismatched payload',
            'IDEMPOTENCY_CONFLICT',
            409,
            {
              idempotency_key: idempotencyKey,
              existing_loss_event_id: deduped.id,
            }
          );
        }
        const outboxDeduped = await readLossOutboxByEventId(this.env.DB, deduped.id);
        return {
          ok: true,
          deduped: true,
          event: normalizeEvent(deduped),
          outbox: outboxDeduped.map((row) => normalizeOutbox(row)),
        };
      }

      throw new ClawSettleError('Failed to persist loss event', 'INTERNAL_ERROR', 500, {
        message,
      });
    }

    const event = await readLossEventById(this.env.DB, eventId);
    if (!event) {
      throw new ClawSettleError('Failed to reload loss event', 'INTERNAL_ERROR', 500);
    }

    const outbox = await readLossOutboxByEventId(this.env.DB, eventId);

    await this.enqueueLossEvent({
      loss_event_id: event.id,
      trigger: 'create',
      queued_at: now,
    });

    return {
      ok: true,
      deduped: false,
      event: normalizeEvent(event),
      outbox: outbox.map((row) => normalizeOutbox(row)),
    };
  }

  async resolveLossEvent(
    lossEventId: string,
    payloadInput: unknown,
    idempotencyKey: string
  ): Promise<{ ok: true; deduped: boolean; event: LossEventView; resolution: LossEventResolutionView; outbox: LossOutboxView[] }> {
    const event = await readLossEventById(this.env.DB, lossEventId);
    if (!event) {
      throw new ClawSettleError('Loss event not found', 'NOT_FOUND', 404, {
        loss_event_id: lossEventId,
      });
    }

    if (event.status !== 'forwarded') {
      throw new ClawSettleError('Loss event must be forwarded before resolve', 'LOSS_EVENT_NOT_READY', 409, {
        loss_event_id: lossEventId,
        status: event.status,
      });
    }

    const payload = parseLossResolutionPayload(payloadInput);

    const applyOutbox = await readLossOutboxByEventId(this.env.DB, lossEventId);

    const targetServices: LossTargetService[] = [
      'ledger',
      ...(applyOutbox.some((row) => row.target_service === 'escrow') ? (['escrow'] as const) : []),
      ...(applyOutbox.some((row) => row.target_service === 'clawbounties') ? (['clawbounties'] as const) : []),
    ];

    const canonicalRequest = {
      loss_event_id: event.id,
      reason: payload.reason,
      targets: targetServices,
    };
    const requestHash = await sha256Hex(stableStringify(canonicalRequest));

    const existing = await readLossResolutionByIdempotencyKey(this.env.DB, idempotencyKey);
    if (existing) {
      if (existing.loss_event_id !== event.id || existing.request_hash !== requestHash) {
        throw new ClawSettleError('Idempotency key replay with mismatched payload', 'IDEMPOTENCY_CONFLICT', 409, {
          idempotency_key: idempotencyKey,
          existing_resolution_id: existing.id,
          existing_loss_event_id: existing.loss_event_id,
        });
      }

      const outboxExisting = await readResolutionOutboxByEventId(this.env.DB, existing.loss_event_id);

      return {
        ok: true,
        deduped: true,
        event: normalizeEvent(event),
        resolution: normalizeResolution(existing),
        outbox: outboxExisting.map((row) => normalizeResolutionOutbox(row)),
      };
    }

    const existingByEvent = await readLossResolutionByEventId(this.env.DB, event.id);
    if (existingByEvent) {
      throw new ClawSettleError('Loss event resolution already exists', 'IDEMPOTENCY_CONFLICT', 409, {
        loss_event_id: event.id,
        existing_resolution_id: existingByEvent.id,
        existing_idempotency_key: existingByEvent.idempotency_key,
      });
    }

    const configs = resolveResolutionTargetConfigs(this.env, {
      event,
      apply_outbox: applyOutbox,
    });

    const now = nowIso();
    const resolutionId = await deriveDeterministicId(
      'lsr',
      stableStringify({
        loss_event_id: event.id,
        idempotency_key: idempotencyKey,
      })
    );

    const resolutionInsert = this.env.DB.prepare(
      `INSERT INTO loss_event_resolutions (
        id,
        loss_event_id,
        idempotency_key,
        request_hash,
        reason,
        status,
        target_count,
        forwarded_count,
        failed_count,
        created_at,
        updated_at,
        last_forwarded_at,
        resolved_at
      ) VALUES (?, ?, ?, ?, ?, 'recorded', ?, 0, 0, ?, ?, NULL, NULL)`
    ).bind(resolutionId, event.id, idempotencyKey, requestHash, payload.reason, configs.length, now, now);

    const outboxStatements: D1PreparedStatement[] = [];
    for (const config of configs) {
      const outboxId = await deriveDeterministicId('lro', `${event.id}:${config.service}`);
      outboxStatements.push(
        this.env.DB.prepare(
          `INSERT INTO loss_event_resolution_outbox (
            id,
            loss_event_id,
            target_service,
            target_url,
            status,
            attempts,
            last_http_status,
            last_error_code,
            last_error_message,
            next_retry_at,
            forwarded_at,
            created_at,
            updated_at
          ) VALUES (?, ?, ?, ?, 'pending', 0, NULL, NULL, NULL, NULL, NULL, ?, ?)`
        ).bind(outboxId, event.id, config.service, config.url, now, now)
      );
    }

    try {
      await this.env.DB.batch([resolutionInsert, ...outboxStatements]);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);

      if (message.includes('UNIQUE constraint failed: loss_event_resolutions.idempotency_key')) {
        const deduped = await readLossResolutionByIdempotencyKey(this.env.DB, idempotencyKey);
        if (!deduped) {
          throw new ClawSettleError('Failed to create loss-event resolution', 'INTERNAL_ERROR', 500);
        }

        if (deduped.request_hash !== requestHash || deduped.loss_event_id !== event.id) {
          throw new ClawSettleError('Idempotency key replay with mismatched payload', 'IDEMPOTENCY_CONFLICT', 409, {
            idempotency_key: idempotencyKey,
            existing_resolution_id: deduped.id,
            existing_loss_event_id: deduped.loss_event_id,
          });
        }

        const outboxDeduped = await readResolutionOutboxByEventId(this.env.DB, deduped.loss_event_id);
        return {
          ok: true,
          deduped: true,
          event: normalizeEvent(event),
          resolution: normalizeResolution(deduped),
          outbox: outboxDeduped.map((row) => normalizeResolutionOutbox(row)),
        };
      }

      if (message.includes('UNIQUE constraint failed: loss_event_resolutions.loss_event_id')) {
        const deduped = await readLossResolutionByEventId(this.env.DB, event.id);
        if (!deduped) {
          throw new ClawSettleError('Failed to create loss-event resolution', 'INTERNAL_ERROR', 500);
        }

        if (deduped.idempotency_key === idempotencyKey && deduped.request_hash === requestHash) {
          const outboxDeduped = await readResolutionOutboxByEventId(this.env.DB, deduped.loss_event_id);
          return {
            ok: true,
            deduped: true,
            event: normalizeEvent(event),
            resolution: normalizeResolution(deduped),
            outbox: outboxDeduped.map((row) => normalizeResolutionOutbox(row)),
          };
        }

        throw new ClawSettleError('Loss event resolution already exists', 'IDEMPOTENCY_CONFLICT', 409, {
          loss_event_id: event.id,
          existing_resolution_id: deduped.id,
          existing_idempotency_key: deduped.idempotency_key,
        });
      }

      throw new ClawSettleError('Failed to persist loss-event resolution', 'INTERNAL_ERROR', 500, {
        message,
      });
    }

    const resolution = await readLossResolutionByEventId(this.env.DB, lossEventId);
    if (!resolution) {
      throw new ClawSettleError('Failed to reload loss-event resolution', 'INTERNAL_ERROR', 500);
    }

    const outbox = await readResolutionOutboxByEventId(this.env.DB, lossEventId);

    await this.enqueueLossEvent({
      loss_event_id: event.id,
      trigger: 'resolve',
      queued_at: now,
    });

    return {
      ok: true,
      deduped: false,
      event: normalizeEvent(event),
      resolution: normalizeResolution(resolution),
      outbox: outbox.map((row) => normalizeResolutionOutbox(row)),
    };
  }

  async enqueueLossEvent(message: LossEventQueueMessage): Promise<void> {
    if (!this.env.LOSS_EVENTS) {
      return;
    }

    try {
      await this.env.LOSS_EVENTS.send(message);
    } catch (error) {
      const messageText = error instanceof Error ? error.message : String(error);
      console.error('[clawsettle] failed to enqueue loss event', messageText);
    }
  }

  async getLossEvent(lossEventId: string): Promise<{ ok: true; event: LossEventView; outbox: LossOutboxView[] }> {
    const event = await readLossEventById(this.env.DB, lossEventId);
    if (!event) {
      throw new ClawSettleError('Loss event not found', 'NOT_FOUND', 404, {
        loss_event_id: lossEventId,
      });
    }

    const outbox = await readLossOutboxByEventId(this.env.DB, lossEventId);

    return {
      ok: true,
      event: normalizeEvent(event),
      outbox: outbox.map((row) => normalizeOutbox(row)),
    };
  }

  async listLossEvents(url: URL): Promise<{
    ok: true;
    events: LossEventView[];
    next_cursor: string | null;
  }> {
    const limit = parseQueryLimit(url.searchParams.get('limit'), 50);
    const cursor = decodeCursor(url.searchParams.get('cursor'));

    if (url.searchParams.get('cursor') && !cursor) {
      throw new ClawSettleError('Invalid cursor', 'INVALID_CURSOR', 400, {
        field: 'cursor',
      });
    }

    const status = url.searchParams.get('status')?.trim() || null;
    if (
      status &&
      status !== 'recorded' &&
      status !== 'processing' &&
      status !== 'partially_forwarded' &&
      status !== 'forwarded' &&
      status !== 'failed'
    ) {
      throw new ClawSettleError(
        'status must be one of recorded|processing|partially_forwarded|forwarded|failed',
        'INVALID_REQUEST',
        400,
        { field: 'status' }
      );
    }

    const accountId = url.searchParams.get('account_id')?.trim() || null;
    const sourceService = url.searchParams.get('source_service')?.trim() || null;

    const where: string[] = [];
    const binds: unknown[] = [];

    if (status) {
      where.push('status = ?');
      binds.push(status);
    }

    if (accountId) {
      where.push('account_id = ?');
      binds.push(accountId);
    }

    if (sourceService) {
      where.push('source_service = ?');
      binds.push(sourceService);
    }

    if (cursor) {
      where.push('(created_at < ? OR (created_at = ? AND id < ?))');
      binds.push(cursor.created_at, cursor.created_at, cursor.id);
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    const rows = await this.env.DB
      .prepare(
        `SELECT *
         FROM loss_events
         ${whereSql}
         ORDER BY created_at DESC, id DESC
         LIMIT ?`
      )
      .bind(...binds, limit + 1)
      .all<Record<string, unknown>>();

    const parsed = (rows.results ?? [])
      .map((row) => parseLossEventRecord(row))
      .filter((row): row is LossEventRecord => Boolean(row));

    const hasMore = parsed.length > limit;
    const page = hasMore ? parsed.slice(0, limit) : parsed;
    const next = hasMore ? page[page.length - 1] : null;

    return {
      ok: true,
      events: page.map((row) => normalizeEvent(row)),
      next_cursor: next ? encodeCursor(next.created_at, next.id) : null,
    };
  }

  async listOutbox(url: URL): Promise<{ ok: true; outbox: LossOutboxView[]; next_cursor: string | null }> {
    const operation = parseOutboxOperation(url.searchParams.get('operation'));
    const limit = parseQueryLimit(url.searchParams.get('limit'), 50);
    const cursor = decodeCursor(url.searchParams.get('cursor'));

    if (url.searchParams.get('cursor') && !cursor) {
      throw new ClawSettleError('Invalid cursor', 'INVALID_CURSOR', 400, {
        field: 'cursor',
      });
    }

    const status = url.searchParams.get('status')?.trim() || null;
    if (status && status !== 'pending' && status !== 'forwarded' && status !== 'failed') {
      throw new ClawSettleError('status must be one of pending|forwarded|failed', 'INVALID_REQUEST', 400, {
        field: 'status',
      });
    }

    const target = url.searchParams.get('target_service')?.trim() || null;
    if (target && !LOSS_TARGETS.includes(target as LossTargetService)) {
      throw new ClawSettleError(
        `target_service must be one of ${LOSS_TARGETS.join('|')}`,
        'INVALID_REQUEST',
        400,
        { field: 'target_service' }
      );
    }

    const lossEventId = url.searchParams.get('loss_event_id')?.trim() || null;

    const where: string[] = [];
    const binds: unknown[] = [];

    if (status) {
      where.push('status = ?');
      binds.push(status);
    }

    if (target) {
      where.push('target_service = ?');
      binds.push(target);
    }

    if (lossEventId) {
      where.push('loss_event_id = ?');
      binds.push(lossEventId);
    }

    if (cursor) {
      where.push('(created_at < ? OR (created_at = ? AND id < ?))');
      binds.push(cursor.created_at, cursor.created_at, cursor.id);
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
    const outboxTable = operation === 'resolve' ? 'loss_event_resolution_outbox' : 'loss_event_outbox';

    const rows = await this.env.DB
      .prepare(
        `SELECT *
         FROM ${outboxTable}
         ${whereSql}
         ORDER BY created_at DESC, id DESC
         LIMIT ?`
      )
      .bind(...binds, limit + 1)
      .all<Record<string, unknown>>();

    if (operation === 'resolve') {
      const parsed = (rows.results ?? [])
        .map((row) => parseLossResolutionOutboxRecord(row))
        .filter((row): row is LossEventResolutionOutboxRecord => Boolean(row));

      const hasMore = parsed.length > limit;
      const page = hasMore ? parsed.slice(0, limit) : parsed;
      const next = hasMore ? page[page.length - 1] : null;

      return {
        ok: true,
        outbox: page.map((row) => normalizeResolutionOutbox(row)),
        next_cursor: next ? encodeCursor(next.created_at, next.id) : null,
      };
    }

    const parsed = (rows.results ?? [])
      .map((row) => parseLossOutboxRecord(row))
      .filter((row): row is LossEventOutboxRecord => Boolean(row));

    const hasMore = parsed.length > limit;
    const page = hasMore ? parsed.slice(0, limit) : parsed;
    const next = hasMore ? page[page.length - 1] : null;

    return {
      ok: true,
      outbox: page.map((row) => normalizeOutbox(row)),
      next_cursor: next ? encodeCursor(next.created_at, next.id) : null,
    };
  }

  async retryForwarding(params: { operation?: LossOutboxOperation; limit?: number; loss_event_id?: string }): Promise<{
    ok: true;
    attempted: number;
    forwarded: number;
    failed: number;
  }> {
    const operation: LossOutboxOperation = params.operation ?? 'apply';
    const limit = params.limit && Number.isInteger(params.limit) && params.limit > 0 ? params.limit : 25;
    const now = nowIso();

    if (operation === 'resolve') {
      const candidates = await fetchRetryableResolutionOutbox(this.env.DB, {
        now,
        limit,
        loss_event_id: params.loss_event_id,
      });

      let attempted = 0;
      let forwarded = 0;
      let failed = 0;

      for (const candidate of candidates) {
        attempted += 1;
        const resT0 = Date.now();
        const result = await forwardResolutionOutboxEntry(this.env, candidate.outbox, candidate.event, candidate.resolution);
        const at = nowIso();
        const resMs = Date.now() - resT0;

        // ECON-OPS-002: Log resolve delivery
        try {
          const { logWebhookDelivery } = await import('./ops-intelligence.js');
          await logWebhookDelivery(this.env.DB, {
            event_type: `loss:resolve:${candidate.outbox.target_service}`,
            source: 'loss_resolve',
            received_at: at,
            processing_ms: resMs,
            status: result.ok ? 'success' : 'failed',
            error_code: result.ok ? undefined : (result.error_code ?? 'UPSTREAM_ERROR'),
            idempotency_key: `loss-resolve:${candidate.event.id}:${candidate.outbox.target_service}`,
          });
        } catch { /* best-effort */ }

        if (result.ok) {
          await markResolutionOutboxForwarded(this.env.DB, candidate.outbox, at, result.http_status ?? 200);
          forwarded += 1;
          continue;
        }

        const errorCode = result.error_code ?? 'UPSTREAM_ERROR';
        const errorMessage = result.error_message ?? 'Unknown error';
        const classification = classifyForwardFailure(result.http_status, errorCode);

        await markResolutionOutboxFailed(this.env.DB, candidate.outbox, at, {
          http_status: result.http_status,
          error_code: errorCode,
          error_message: errorMessage,
          next_retry_at: classification.permanent ? null : computeNextRetryAt(candidate.outbox.attempts + 1, at),
          permanent: classification.permanent,
        });

        failed += 1;
      }

      return {
        ok: true,
        attempted,
        forwarded,
        failed,
      };
    }

    const candidates = await fetchRetryableOutbox(this.env.DB, {
      now,
      limit,
      loss_event_id: params.loss_event_id,
    });

    let attempted = 0;
    let forwarded = 0;
    let failed = 0;

    for (const candidate of candidates) {
      attempted += 1;
      const fwdT0 = Date.now();
      const result = await forwardOutboxEntry(this.env, candidate.outbox, candidate.event);
      const at = nowIso();
      const fwdMs = Date.now() - fwdT0;

      // ECON-OPS-002: Log delivery for SLA tracking (best-effort)
      const fwdSource = operation === 'apply' ? 'loss_apply' as const : 'loss_resolve' as const;
      try {
        const { logWebhookDelivery } = await import('./ops-intelligence.js');
        await logWebhookDelivery(this.env.DB, {
          event_type: `loss:${operation}:${candidate.outbox.target_service}`,
          source: fwdSource,
          received_at: at,
          processing_ms: fwdMs,
          status: result.ok ? 'success' : 'failed',
          error_code: result.ok ? undefined : (result.error_code ?? 'UPSTREAM_ERROR'),
          idempotency_key: `loss-event:${candidate.event.id}:${candidate.outbox.target_service}`,
        });
      } catch { /* best-effort */ }

      if (result.ok) {
        await markOutboxForwarded(this.env.DB, candidate.outbox, at, result.http_status ?? 200);
        forwarded += 1;
        continue;
      }

      const errorCode = result.error_code ?? 'UPSTREAM_ERROR';
      const errorMessage = result.error_message ?? 'Unknown error';
      const classification = classifyForwardFailure(result.http_status, errorCode);

      await markOutboxFailed(this.env.DB, candidate.outbox, at, {
        http_status: result.http_status,
        error_code: errorCode,
        error_message: errorMessage,
        next_retry_at: classification.permanent ? null : computeNextRetryAt(candidate.outbox.attempts + 1, at),
        permanent: classification.permanent,
      });

      failed += 1;
    }

    return {
      ok: true,
      attempted,
      forwarded,
      failed,
    };
  }

  async processQueueMessage(payload: unknown): Promise<void> {
    if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
      throw new ClawSettleError('Queue payload must be an object', 'INVALID_REQUEST', 400);
    }

    const msg = payload as Partial<LossEventQueueMessage>;
    const lossEventId = parseRequiredString(msg.loss_event_id, 'loss_event_id');

    await this.retryForwarding({
      operation: 'apply',
      limit: 25,
      loss_event_id: lossEventId,
    });

    await this.retryForwarding({
      operation: 'resolve',
      limit: 25,
      loss_event_id: lossEventId,
    });
  }

  static readOnlyAllowed(path: string): boolean {
    return (
      path === '/v1/loss-events' ||
      path === '/v1/loss-events/outbox' ||
      /^\/v1\/loss-events\/[^/]+$/.test(path)
    );
  }

  static parseRetryBody(input: unknown): { operation?: LossOutboxOperation; limit?: number; loss_event_id?: string } {
    if (input === null || input === undefined) {
      return {};
    }

    if (typeof input !== 'object' || Array.isArray(input)) {
      throw new ClawSettleError('Invalid JSON payload', 'INVALID_REQUEST', 400);
    }

    const payload = input as Record<string, unknown>;

    let operation: LossOutboxOperation | undefined;
    if (payload.operation !== undefined && payload.operation !== null) {
      if (typeof payload.operation !== 'string') {
        throw new ClawSettleError('operation must be apply|resolve', 'INVALID_REQUEST', 400, {
          field: 'operation',
        });
      }

      operation = parseOutboxOperation(payload.operation);
    }

    let limit: number | undefined;
    if (payload.limit !== undefined) {
      if (typeof payload.limit !== 'number' || !Number.isInteger(payload.limit) || payload.limit <= 0) {
        throw new ClawSettleError('limit must be a positive integer', 'INVALID_REQUEST', 400, {
          field: 'limit',
        });
      }
      limit = payload.limit;
    }

    let lossEventId: string | undefined;
    if (payload.loss_event_id !== undefined && payload.loss_event_id !== null) {
      if (typeof payload.loss_event_id !== 'string' || payload.loss_event_id.trim().length === 0) {
        throw new ClawSettleError('loss_event_id must be a non-empty string', 'INVALID_REQUEST', 400, {
          field: 'loss_event_id',
        });
      }
      lossEventId = payload.loss_event_id.trim();
    }

    return {
      ...(operation ? { operation } : {}),
      ...(limit ? { limit } : {}),
      ...(lossEventId ? { loss_event_id: lossEventId } : {}),
    };
  }
}

export function isLossEventReadRequest(method: string, path: string): boolean {
  return method === 'GET' && LossEventService.readOnlyAllowed(path);
}

export function assertLossEventAuth(request: Request, env: Env, method: string, path: string): void {
  const adminKey = env.SETTLE_ADMIN_KEY?.trim();
  const readToken = env.SETTLE_LOSS_READ_TOKEN?.trim();

  const allowReadToken = isLossEventReadRequest(method, path);

  if (!adminKey && !(allowReadToken && readToken)) {
    throw new ClawSettleError('Settlement admin key not configured', 'DEPENDENCY_NOT_CONFIGURED', 503, {
      field: 'SETTLE_ADMIN_KEY',
    });
  }

  const token = getBearerToken(request) ?? request.headers.get('x-admin-key')?.trim() ?? null;
  const adminAuthorized = Boolean(adminKey) && token === adminKey;
  const readAuthorized = Boolean(readToken) && allowReadToken && token === readToken;

  if (!adminAuthorized && !readAuthorized) {
    throw new ClawSettleError('Unauthorized', 'UNAUTHORIZED', 401);
  }
}

export function resolveLossEventRetryLimit(env: Env): number {
  return parseIntegerEnv(env.LOSS_FORWARD_RETRY_BATCH_LIMIT, 25, 'LOSS_FORWARD_RETRY_BATCH_LIMIT');
}

export function shouldInlineLossEventForwarding(env: Env): boolean {
  const forceInline = parseBooleanEnv(env.LOSS_EVENTS_FORCE_INLINE, false);
  return forceInline || !env.LOSS_EVENTS;
}
