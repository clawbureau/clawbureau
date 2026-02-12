export interface Env {
  INCOME_VERSION: string;
  INCOME_DB: D1Database;

  INCOME_ADMIN_KEY?: string;
  INCOME_RISK_KEY?: string;
  INCOME_SCOPE_REQUIRED?: string;

  CLAWSCOPE_BASE_URL?: string;

  LEDGER_BASE_URL?: string;
  LEDGER_ADMIN_KEY?: string;

  ESCROW_BASE_URL?: string;
  ESCROW_ADMIN_KEY?: string;

  CUTS_BASE_URL?: string;
  CUTS_ADMIN_KEY?: string;

  SETTLE_BASE_URL?: string;
  SETTLE_ADMIN_KEY?: string;
}

type ReportType =
  | 'monthly_statement_json'
  | 'monthly_statement_csv'
  | 'invoices_json'
  | 'tax_lots_json';

interface ReportSnapshotRow {
  snapshot_id: string;
  report_type: ReportType;
  did: string;
  period_key: string;
  payload_json: string;
  csv_body: string | null;
  payload_hash_b64u: string;
  source_refs_json: string | null;
  created_at: string;
}

interface RiskAdjustmentRow {
  adjustment_id: string;
  idempotency_key: string;
  source_loss_event_id: string;
  source_service: string;
  source_event_id: string | null;
  account_id: string;
  account_did: string | null;
  direction: 'debit' | 'credit';
  amount_minor: string;
  currency: 'USD';
  reason_code: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  occurred_at: string;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
}

interface ViewerContext {
  is_admin: boolean;
  actor_did: string | null;
  scope: string[];
  token_lane?: string;
}

interface IntrospectionResponse {
  active: boolean;
  revoked?: boolean;
  sub?: string;
  scope?: string[];
  token_lane?: string;
}

interface LedgerAccountResponse {
  id: string;
  did: string;
}

interface LedgerBalancesResponse {
  did: string;
  currency: 'USD';
  buckets: {
    A: string;
    H: string;
    B: string;
    F: string;
    P: string;
  };
  as_of: string;
}

interface EscrowFeeSplit {
  kind: 'platform' | 'referral';
  account: string;
  bucket: 'A' | 'F';
  amount_minor: string;
  referrer_did?: string;
  referral_code?: string;
}

interface EscrowFeeItem {
  kind: string;
  payer: 'buyer' | 'worker';
  amount_minor: string;
  rate_bps: number;
  min_fee_minor: string;
  floor_applied: boolean;
  splits?: EscrowFeeSplit[];
}

interface EscrowFinanceRecord {
  escrow_id: string;
  status: 'released';
  buyer_did: string;
  worker_did: string | null;
  amount_minor: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  fee_quote: {
    policy_id: string;
    policy_version: string;
    policy_hash_b64u: string;
    buyer_total_minor: string;
    worker_net_minor: string;
    fees: EscrowFeeItem[];
  };
  timestamps: {
    released_at: string;
    created_at: string;
    updated_at: string;
  };
  ledger_refs: {
    hold_transfer: string;
    worker_transfer: string | null;
    fee_transfers: string[];
    referral_transfers: string[];
  };
}

interface EscrowListResponse {
  escrows: EscrowFinanceRecord[];
  next_cursor?: string;
}

interface CutsApplyEvent {
  apply_id: string;
  settlement_ref: string | null;
  month: string;
  policy: {
    id: string;
    version: string;
    hash_b64u: string;
  };
  fee_summary: {
    principal_minor: string;
    buyer_total_minor: string;
    worker_net_minor: string;
    total_fee_minor: string;
    platform_fee_minor: string;
    referral_payout_minor: string;
    platform_retained_minor: string;
  };
  transfer_plan: {
    transfers: Array<{
      transfer_index: number;
      fee_index: number;
      fee_kind: string;
      payer: 'buyer' | 'worker';
      split_kind: 'platform' | 'referral';
      to_account: string;
      to_bucket: 'A' | 'F';
      amount_minor: string;
      referrer_did?: string;
      referral_code?: string;
    }>;
  };
  ledger_refs: {
    fee_transfers: string[];
    referral_transfers: string[];
  };
  finalized_at: string | null;
  snapshot_hash_b64u: string;
  created_at: string;
}

interface CutsApplyEventsResponse {
  events: CutsApplyEvent[];
  next_cursor?: string;
}

interface SettlePayoutRecord {
  id: string;
  account_did: string;
  account_id: string;
  external_payout_id?: string;
  amount_minor: string;
  currency: string;
  status: string;
  created_at: string;
  submitted_at?: string;
  finalized_at?: string;
  failed_at?: string;
}

interface SettlePayoutListResponse {
  payouts: SettlePayoutRecord[];
  next_cursor?: string;
}

interface LedgerSettlementRecord {
  id: string;
  provider: string;
  external_payment_id: string;
  direction: 'payin' | 'refund' | 'payout';
  status: 'pending' | 'confirmed' | 'failed' | 'reversed';
  account_id: string;
  amount_minor: string;
  currency: string;
  settled_at?: string;
  created_at: string;
  updated_at: string;
}

interface LedgerSettlementListResponse {
  settlements: LedgerSettlementRecord[];
  next_cursor?: string;
}

interface ReportSourceRefs {
  escrow_count: number;
  cuts_apply_count: number;
  payout_count: number;
  payout_settlement_count: number;
}

interface FinancialContext {
  did: string;
  month: string;
  start_iso: string;
  end_iso: string;
  ledger_account_id: string;
  escrows: EscrowFinanceRecord[];
  cuts_apply_by_escrow: Map<string, CutsApplyEvent>;
  payouts: SettlePayoutRecord[];
  payout_settlements: LedgerSettlementRecord[];
  balances: LedgerBalancesResponse;
}

interface StatementLineItem {
  occurred_at: string;
  type: 'escrow_income' | 'escrow_spend' | 'payout';
  ref_id: string;
  direction: 'in' | 'out';
  amount_minor: string;
  currency: 'USD';
  details: Record<string, unknown>;
}

interface StatementPayload {
  did: string;
  month: string;
  currency: 'USD';
  generated_at: string;
  totals: {
    gross_earned_minor: string;
    worker_fees_minor: string;
    net_earned_minor: string;
    buyer_spend_minor: string;
    buyer_fees_minor: string;
    payouts_minor: string;
    ending_balance_minor: string;
  };
  counts: {
    released_as_worker: number;
    released_as_buyer: number;
    payouts: number;
  };
  line_items: StatementLineItem[];
  source_refs: ReportSourceRefs;
}

interface InvoiceItem {
  invoice_id: string;
  escrow_id: string;
  released_at: string;
  buyer_did: string;
  worker_did: string | null;
  reward_minor: string;
  buyer_fee_minor: string;
  total_minor: string;
  currency: 'USD';
  policy: {
    id: string;
    version: string;
    hash_b64u: string;
  };
  finance_ref: {
    cuts_apply_id: string;
    cuts_snapshot_hash_b64u: string;
  };
  tax: {
    jurisdiction: string | null;
    vat_number: string | null;
  };
}

interface InvoicesPayload {
  did: string;
  month: string;
  currency: 'USD';
  generated_at: string;
  totals: {
    invoice_count: number;
    gross_reward_minor: string;
    buyer_fee_minor: string;
    total_minor: string;
  };
  invoices: InvoiceItem[];
  source_refs: ReportSourceRefs;
}

interface TaxLotItem {
  lot_id: string;
  occurred_at: string;
  category: 'income' | 'expense' | 'payout';
  source: 'escrow' | 'payout';
  source_ref: string;
  amount_minor: string;
  currency: 'USD';
  jurisdiction: string | null;
  notes?: string;
}

interface TaxLotsPayload {
  did: string;
  year: string;
  currency: 'USD';
  generated_at: string;
  totals: {
    income_minor: string;
    expense_minor: string;
    payout_minor: string;
    lot_count: number;
  };
  tax_lots: TaxLotItem[];
  source_refs: ReportSourceRefs;
}

interface IncomeTimelineItem {
  occurred_at: string;
  item_id: string;
  type: 'escrow_income' | 'escrow_spend' | 'payout';
  direction: 'in' | 'out';
  amount_minor: string;
  currency: 'USD';
  metadata: Record<string, unknown>;
}

class IncomeError extends Error {
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

function jsonResponse(body: unknown, status = 200, version = '0.1.0'): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-clawincome-version': version,
    },
  });
}

function textResponse(body: string, contentType: string, status = 200, version = '0.1.0', headers?: Record<string, string>): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'x-clawincome-version': version,
      ...(headers ?? {}),
    },
  });
}

function errorResponse(err: IncomeError, version = '0.1.0'): Response {
  return jsonResponse(
    {
      error: err.code,
      message: err.message,
      details: err.details,
    },
    err.status,
    version
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function parseIsoTimestamp(value: string, field: string): string {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new IncomeError(`${field} must be a valid ISO timestamp`, 'INVALID_REQUEST', 400, { field });
  }
  return date.toISOString();
}

function parseMonth(value: string | null): string {
  if (!value || !/^\d{4}-\d{2}$/.test(value.trim())) {
    throw new IncomeError('month must be YYYY-MM', 'INVALID_REQUEST', 400, { field: 'month' });
  }
  return value.trim();
}

function parseYear(value: string | null): string {
  if (!value || !/^\d{4}$/.test(value.trim())) {
    throw new IncomeError('year must be YYYY', 'INVALID_REQUEST', 400, { field: 'year' });
  }
  return value.trim();
}

function monthRange(month: string): { startIso: string; endIso: string } {
  const [yearRaw, monthRaw] = month.split('-');
  const year = Number(yearRaw);
  const monthIndex = Number(monthRaw) - 1;
  const start = new Date(Date.UTC(year, monthIndex, 1, 0, 0, 0, 0));
  const end = new Date(Date.UTC(year, monthIndex + 1, 1, 0, 0, 0, 0));
  return { startIso: start.toISOString(), endIso: end.toISOString() };
}

function yearRange(year: string): { startIso: string; endIso: string } {
  const y = Number(year);
  const start = new Date(Date.UTC(y, 0, 1, 0, 0, 0, 0));
  const end = new Date(Date.UTC(y + 1, 0, 1, 0, 0, 0, 0));
  return { startIso: start.toISOString(), endIso: end.toISOString() };
}

function nowIso(): string {
  return new Date().toISOString();
}

async function parseJsonBody(request: Request): Promise<unknown | null> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function parsePositiveMinor(value: string, field: string): bigint {
  if (!/^[0-9]+$/.test(value)) {
    throw new IncomeError(`${field} must be a positive integer string`, 'INVALID_RESPONSE', 502, { field, value });
  }

  const parsed = BigInt(value);
  if (parsed <= 0n) {
    throw new IncomeError(`${field} must be positive`, 'INVALID_RESPONSE', 502, { field, value });
  }

  return parsed;
}

function parseNonNegativeMinor(value: string, field: string): bigint {
  if (!/^[0-9]+$/.test(value)) {
    throw new IncomeError(`${field} must be a non-negative integer string`, 'INVALID_RESPONSE', 502, { field, value });
  }

  const parsed = BigInt(value);
  if (parsed < 0n) {
    throw new IncomeError(`${field} must be non-negative`, 'INVALID_RESPONSE', 502, { field, value });
  }

  return parsed;
}

function sumMinor(values: string[], field: string): bigint {
  return values.reduce((acc, value) => acc + parseNonNegativeMinor(value, field), 0n);
}

function parseBearerToken(request: Request): string | null {
  const authorization = request.headers.get('authorization') ?? request.headers.get('Authorization');
  if (!authorization) return null;

  const trimmed = authorization.trim();
  if (trimmed.length === 0) return null;

  if (trimmed.toLowerCase().startsWith('bearer ')) {
    return trimmed.slice(7).trim();
  }

  return trimmed;
}

function parseAdminHeader(request: Request): string | null {
  const header = request.headers.get('x-admin-key') ?? request.headers.get('X-Admin-Key');
  if (!header) return null;
  const trimmed = header.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function base64urlEncode(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(input: string): Uint8Array {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function sha256B64uUtf8(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return base64urlEncode(new Uint8Array(digest));
}

function stableStringify(value: unknown): string {
  if (value === null) return 'null';

  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  }

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new Error('Non-finite number in stableStringify');
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'bigint':
      return JSON.stringify(value.toString());
    case 'object': {
      const object = value as Record<string, unknown>;
      const keys = Object.keys(object).sort();
      return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(object[key])}`).join(',')}}`;
    }
    default:
      return 'null';
  }
}

function encodeCursorIndex(index: number): string {
  return base64urlEncode(new TextEncoder().encode(JSON.stringify({ i: index })));
}

function decodeCursorIndex(cursor: string | null): number | null {
  if (!cursor) return null;
  try {
    const bytes = base64urlDecode(cursor);
    const decoded = JSON.parse(new TextDecoder().decode(bytes)) as { i?: unknown };
    if (typeof decoded.i === 'number' && Number.isInteger(decoded.i) && decoded.i >= 0) {
      return decoded.i;
    }
    return null;
  } catch {
    return null;
  }
}

function parseLimit(url: URL, defaultValue = 50, maxValue = 200): number {
  const raw = url.searchParams.get('limit');
  if (!raw) return defaultValue;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new IncomeError('limit must be a positive integer', 'INVALID_REQUEST', 400, { field: 'limit' });
  }
  return Math.min(parsed, maxValue);
}

async function ensureAccessAudit(
  db: D1Database,
  params: {
    endpoint: string;
    requested_did: string;
    actor_did: string | null;
    is_admin: boolean;
    outcome: 'allowed' | 'denied';
    details?: Record<string, unknown>;
  }
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO access_audit_events (
        audit_id,
        endpoint,
        requested_did,
        actor_did,
        is_admin,
        outcome,
        created_at,
        details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      `ina_${crypto.randomUUID()}`,
      params.endpoint,
      params.requested_did,
      params.actor_did,
      params.is_admin ? 1 : 0,
      params.outcome,
      nowIso(),
      params.details ? JSON.stringify(params.details) : null
    )
    .run();
}

function getBaseUrl(value: string | undefined, envField: string): string {
  if (!value || value.trim().length === 0) {
    throw new IncomeError(`${envField} is not configured`, 'DEPENDENCY_NOT_CONFIGURED', 503, {
      field: envField,
    });
  }
  return value.trim();
}

function getRequiredSecret(value: string | undefined, envField: string): string {
  if (!value || value.trim().length === 0) {
    throw new IncomeError(`${envField} is not configured`, 'DEPENDENCY_NOT_CONFIGURED', 503, {
      field: envField,
    });
  }
  return value.trim();
}

async function introspectToken(token: string, env: Env): Promise<IntrospectionResponse> {
  const baseUrl = getBaseUrl(env.CLAWSCOPE_BASE_URL, 'CLAWSCOPE_BASE_URL');

  const response = await fetch(`${baseUrl}/v1/tokens/introspect`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({ token }),
  });

  const text = await response.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    throw new IncomeError('token introspection failed', 'AUTH_INTROSPECTION_FAILED', 502, {
      status: response.status,
      raw: isRecord(json) ? json : text,
    });
  }

  if (!isRecord(json) || typeof json.active !== 'boolean') {
    throw new IncomeError('invalid token introspection response', 'AUTH_INTROSPECTION_INVALID', 502);
  }

  const scope = Array.isArray(json.scope)
    ? json.scope.filter((entry): entry is string => typeof entry === 'string')
    : [];

  return {
    active: json.active,
    revoked: json.revoked === true,
    sub: isNonEmptyString(json.sub) ? json.sub.trim() : undefined,
    scope,
    token_lane: isNonEmptyString(json.token_lane) ? json.token_lane.trim() : undefined,
  };
}

async function authorize(
  request: Request,
  requestedDid: string,
  endpoint: string,
  env: Env
): Promise<ViewerContext> {
  const adminKey = env.INCOME_ADMIN_KEY?.trim() || null;
  const adminCandidate = parseAdminHeader(request) ?? parseBearerToken(request);

  if (adminKey && adminCandidate === adminKey) {
    return {
      is_admin: true,
      actor_did: null,
      scope: [],
    };
  }

  const bearer = parseBearerToken(request);
  if (!bearer) {
    throw new IncomeError('Missing authentication token', 'UNAUTHORIZED', 401, {
      endpoint,
    });
  }

  const introspection = await introspectToken(bearer, env);
  if (!introspection.active || introspection.revoked) {
    throw new IncomeError('Token is inactive', 'UNAUTHORIZED', 401, {
      endpoint,
    });
  }

  if (!isNonEmptyString(introspection.sub)) {
    throw new IncomeError('Token subject is missing', 'UNAUTHORIZED', 401, {
      endpoint,
    });
  }

  const requiredScope = (env.INCOME_SCOPE_REQUIRED?.trim() || 'clawincome:read');
  const scopeSet = new Set(introspection.scope ?? []);
  if (!scopeSet.has(requiredScope)) {
    throw new IncomeError('Missing required scope', 'SCOPE_REQUIRED', 403, {
      required_scope: requiredScope,
      endpoint,
    });
  }

  const actorDid = introspection.sub.trim();
  if (actorDid !== requestedDid) {
    throw new IncomeError('Requested DID does not match token subject', 'FORBIDDEN', 403, {
      requested_did: requestedDid,
      actor_did: actorDid,
    });
  }

  return {
    is_admin: false,
    actor_did: actorDid,
    scope: introspection.scope ?? [],
    token_lane: introspection.token_lane,
  };
}

async function fetchJson(url: string, init: RequestInit, dependency: string): Promise<Record<string, unknown>> {
  let response: Response;
  try {
    response = await fetch(url, init);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new IncomeError(`${dependency} request failed`, 'DEPENDENCY_REQUEST_FAILED', 503, {
      dependency,
      message,
      url,
    });
  }

  const text = await response.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    throw new IncomeError(`${dependency} returned non-OK response`, 'DEPENDENCY_RESPONSE_FAILED', 502, {
      dependency,
      status: response.status,
      url,
      body: isRecord(json) ? json : text,
    });
  }

  if (!isRecord(json)) {
    throw new IncomeError(`${dependency} returned invalid JSON`, 'DEPENDENCY_RESPONSE_INVALID', 502, {
      dependency,
      url,
      body: text,
    });
  }

  return json;
}

function requireRiskService(request: Request, env: Env): void {
  const configured = env.INCOME_RISK_KEY?.trim();
  if (!configured) {
    throw new IncomeError('INCOME_RISK_KEY is not configured', 'ADMIN_KEY_NOT_CONFIGURED', 503, {
      field: 'INCOME_RISK_KEY',
    });
  }

  const candidate = parseAdminHeader(request) ?? parseBearerToken(request);
  if (!candidate) {
    throw new IncomeError('Missing risk token', 'UNAUTHORIZED', 401);
  }

  if (candidate !== configured) {
    throw new IncomeError('Invalid risk token', 'UNAUTHORIZED', 401);
  }
}

function parseRiskAdjustmentPayload(input: unknown): {
  idempotency_key: string;
  source_loss_event_id: string;
  source_service: string;
  source_event_id: string | null;
  account_id: string;
  account_did: string | null;
  direction: 'debit' | 'credit';
  amount_minor: string;
  currency: 'USD';
  reason_code: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  occurred_at: string;
  metadata: Record<string, unknown> | null;
} {
  if (!isRecord(input)) {
    throw new IncomeError('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  if (!isNonEmptyString(input.idempotency_key)) {
    throw new IncomeError('idempotency_key is required', 'INVALID_REQUEST', 400, { field: 'idempotency_key' });
  }

  if (!isNonEmptyString(input.source_loss_event_id)) {
    throw new IncomeError('source_loss_event_id is required', 'INVALID_REQUEST', 400, { field: 'source_loss_event_id' });
  }

  const currency = isNonEmptyString(input.currency) ? input.currency.trim() : 'USD';
  if (currency !== 'USD') {
    throw new IncomeError('Only USD adjustments are supported', 'UNSUPPORTED_CURRENCY', 400, {
      field: 'currency',
      value: currency,
    });
  }

  if (!isNonEmptyString(input.account_id)) {
    throw new IncomeError('account_id is required', 'INVALID_REQUEST', 400, { field: 'account_id' });
  }

  const directionRaw = isNonEmptyString(input.direction) ? input.direction.trim() : null;
  if (directionRaw !== 'debit' && directionRaw !== 'credit') {
    throw new IncomeError('direction must be debit|credit', 'INVALID_REQUEST', 400, { field: 'direction' });
  }

  if (!isNonEmptyString(input.amount_minor) || !/^[0-9]+$/.test(input.amount_minor.trim())) {
    throw new IncomeError('amount_minor must be a non-negative integer string', 'INVALID_REQUEST', 400, { field: 'amount_minor' });
  }
  const amountMinor = BigInt(input.amount_minor.trim());
  if (amountMinor <= 0n) {
    throw new IncomeError('amount_minor must be greater than zero', 'INVALID_REQUEST', 400, { field: 'amount_minor' });
  }

  if (!isNonEmptyString(input.reason_code)) {
    throw new IncomeError('reason_code is required', 'INVALID_REQUEST', 400, { field: 'reason_code' });
  }

  const severityRaw = isNonEmptyString(input.severity) ? input.severity.trim() : 'high';
  if (severityRaw !== 'low' && severityRaw !== 'medium' && severityRaw !== 'high' && severityRaw !== 'critical') {
    throw new IncomeError('severity must be low|medium|high|critical', 'INVALID_REQUEST', 400, { field: 'severity' });
  }

  const occurredAtRaw = isNonEmptyString(input.occurred_at) ? input.occurred_at.trim() : nowIso();
  const occurredAtDate = new Date(occurredAtRaw);
  if (!Number.isFinite(occurredAtDate.getTime())) {
    throw new IncomeError('occurred_at must be an ISO timestamp', 'INVALID_REQUEST', 400, { field: 'occurred_at' });
  }

  const metadata = isRecord(input.metadata) ? (input.metadata as Record<string, unknown>) : null;

  return {
    idempotency_key: input.idempotency_key.trim(),
    source_loss_event_id: input.source_loss_event_id.trim(),
    source_service: isNonEmptyString(input.source_service) ? input.source_service.trim() : 'unknown',
    source_event_id: isNonEmptyString(input.source_event_id) ? input.source_event_id.trim() : null,
    account_id: input.account_id.trim(),
    account_did: isNonEmptyString(input.account_did) ? input.account_did.trim() : null,
    direction: directionRaw,
    amount_minor: amountMinor.toString(),
    currency: 'USD',
    reason_code: input.reason_code.trim(),
    severity: severityRaw,
    occurred_at: occurredAtDate.toISOString(),
    metadata,
  };
}

function parseRiskAdjustmentRow(row: unknown): RiskAdjustmentRow | null {
  if (!isRecord(row)) return null;

  const adjustment_id = isNonEmptyString(row.adjustment_id) ? row.adjustment_id.trim() : null;
  const idempotency_key = isNonEmptyString(row.idempotency_key) ? row.idempotency_key.trim() : null;
  const source_loss_event_id = isNonEmptyString(row.source_loss_event_id) ? row.source_loss_event_id.trim() : null;
  const source_service = isNonEmptyString(row.source_service) ? row.source_service.trim() : null;
  const account_id = isNonEmptyString(row.account_id) ? row.account_id.trim() : null;
  const amount_minor = isNonEmptyString(row.amount_minor) ? row.amount_minor.trim() : null;
  const currency = isNonEmptyString(row.currency) ? row.currency.trim() : null;
  const reason_code = isNonEmptyString(row.reason_code) ? row.reason_code.trim() : null;
  const severity = isNonEmptyString(row.severity) ? row.severity.trim() : null;
  const direction = isNonEmptyString(row.direction) ? row.direction.trim() : null;
  const occurred_at = isNonEmptyString(row.occurred_at) ? row.occurred_at.trim() : null;
  const created_at = isNonEmptyString(row.created_at) ? row.created_at.trim() : null;
  const updated_at = isNonEmptyString(row.updated_at) ? row.updated_at.trim() : null;

  if (!adjustment_id || !idempotency_key || !source_loss_event_id || !source_service || !account_id || !amount_minor || !currency || !reason_code || !severity || !direction || !occurred_at || !created_at || !updated_at) {
    return null;
  }

  if (currency !== 'USD') return null;
  if (direction !== 'debit' && direction !== 'credit') return null;
  if (severity !== 'low' && severity !== 'medium' && severity !== 'high' && severity !== 'critical') return null;

  return {
    adjustment_id,
    idempotency_key,
    source_loss_event_id,
    source_service,
    source_event_id: isNonEmptyString(row.source_event_id) ? row.source_event_id.trim() : null,
    account_id,
    account_did: isNonEmptyString(row.account_did) ? row.account_did.trim() : null,
    direction,
    amount_minor,
    currency: 'USD',
    reason_code,
    severity,
    occurred_at,
    metadata_json: isNonEmptyString(row.metadata_json) ? row.metadata_json.trim() : null,
    created_at,
    updated_at,
  };
}

async function getRiskAdjustmentByIdempotencyKey(db: D1Database, key: string): Promise<RiskAdjustmentRow | null> {
  const row = await db.prepare('SELECT * FROM risk_adjustments WHERE idempotency_key = ?').bind(key).first();
  return parseRiskAdjustmentRow(row);
}

async function getRiskAdjustmentById(db: D1Database, adjustmentId: string): Promise<RiskAdjustmentRow | null> {
  const row = await db.prepare('SELECT * FROM risk_adjustments WHERE adjustment_id = ?').bind(adjustmentId).first();
  return parseRiskAdjustmentRow(row);
}

async function insertRiskAdjustment(db: D1Database, record: RiskAdjustmentRow): Promise<void> {
  await db
    .prepare(
      `INSERT INTO risk_adjustments (
        adjustment_id,
        idempotency_key,
        source_loss_event_id,
        source_service,
        source_event_id,
        account_id,
        account_did,
        direction,
        amount_minor,
        currency,
        reason_code,
        severity,
        occurred_at,
        metadata_json,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      record.adjustment_id,
      record.idempotency_key,
      record.source_loss_event_id,
      record.source_service,
      record.source_event_id,
      record.account_id,
      record.account_did,
      record.direction,
      record.amount_minor,
      record.currency,
      record.reason_code,
      record.severity,
      record.occurred_at,
      record.metadata_json,
      record.created_at,
      record.updated_at
    )
    .run();
}

async function handleRiskAdjustment(request: Request, env: Env, version: string): Promise<Response> {
  requireRiskService(request, env);

  const body = await parseJsonBody(request);
  const payload = parseRiskAdjustmentPayload(body);

  const existing = await getRiskAdjustmentByIdempotencyKey(env.INCOME_DB, payload.idempotency_key);
  if (existing) {
    const existingHash = await sha256B64uUtf8(
      stableStringify({
        source_loss_event_id: existing.source_loss_event_id,
        source_service: existing.source_service,
        source_event_id: existing.source_event_id,
        account_id: existing.account_id,
        account_did: existing.account_did,
        direction: existing.direction,
        amount_minor: existing.amount_minor,
        currency: existing.currency,
        reason_code: existing.reason_code,
        severity: existing.severity,
        occurred_at: existing.occurred_at,
        metadata: existing.metadata_json ? JSON.parse(existing.metadata_json) : null,
      })
    );

    const newHash = await sha256B64uUtf8(
      stableStringify({
        source_loss_event_id: payload.source_loss_event_id,
        source_service: payload.source_service,
        source_event_id: payload.source_event_id,
        account_id: payload.account_id,
        account_did: payload.account_did,
        direction: payload.direction,
        amount_minor: payload.amount_minor,
        currency: payload.currency,
        reason_code: payload.reason_code,
        severity: payload.severity,
        occurred_at: payload.occurred_at,
        metadata: payload.metadata,
      })
    );

    if (existingHash !== newHash) {
      throw new IncomeError('Idempotency key replay with mismatched payload', 'IDEMPOTENCY_CONFLICT', 409, {
        idempotency_key: payload.idempotency_key,
        adjustment_id: existing.adjustment_id,
      });
    }

    return jsonResponse({ ok: true, adjustment: existing, replay: true }, 200, version);
  }

  const record: RiskAdjustmentRow = {
    adjustment_id: `rad_${crypto.randomUUID()}`,
    idempotency_key: payload.idempotency_key,
    source_loss_event_id: payload.source_loss_event_id,
    source_service: payload.source_service,
    source_event_id: payload.source_event_id,
    account_id: payload.account_id,
    account_did: payload.account_did,
    direction: payload.direction,
    amount_minor: payload.amount_minor,
    currency: 'USD',
    reason_code: payload.reason_code,
    severity: payload.severity,
    occurred_at: payload.occurred_at,
    metadata_json: payload.metadata ? JSON.stringify(payload.metadata) : null,
    created_at: nowIso(),
    updated_at: nowIso(),
  };

  await insertRiskAdjustment(env.INCOME_DB, record);

  const saved = await getRiskAdjustmentById(env.INCOME_DB, record.adjustment_id);
  if (!saved) {
    throw new IncomeError('Risk adjustment persistence failed', 'DB_WRITE_FAILED', 500);
  }

  return jsonResponse({ ok: true, adjustment: saved, replay: false }, 201, version);
}

async function ledgerGetAccountByDid(did: string, env: Env): Promise<LedgerAccountResponse> {
  const baseUrl = getBaseUrl(env.LEDGER_BASE_URL, 'LEDGER_BASE_URL');
  const adminKey = getRequiredSecret(env.LEDGER_ADMIN_KEY, 'LEDGER_ADMIN_KEY');

  const data = await fetchJson(
    `${baseUrl}/accounts/${did}`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${adminKey}`,
      },
    },
    'ledger'
  );

  const id = data.id;
  const didValue = data.did;

  if (!isNonEmptyString(id) || !isNonEmptyString(didValue)) {
    throw new IncomeError('ledger account response is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502, {
      dependency: 'ledger',
      route: '/accounts/:did',
    });
  }

  return {
    id: id.trim(),
    did: didValue.trim(),
  };
}

async function ledgerGetBalances(did: string, env: Env): Promise<LedgerBalancesResponse> {
  const baseUrl = getBaseUrl(env.LEDGER_BASE_URL, 'LEDGER_BASE_URL');
  const adminKey = getRequiredSecret(env.LEDGER_ADMIN_KEY, 'LEDGER_ADMIN_KEY');

  const data = await fetchJson(
    `${baseUrl}/v1/balances?did=${encodeURIComponent(did)}`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${adminKey}`,
      },
    },
    'ledger'
  );

  if (!isRecord(data.buckets)) {
    throw new IncomeError('ledger balances response is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
  }

  const buckets = data.buckets;

  for (const key of ['A', 'H', 'B', 'F', 'P']) {
    if (!isNonEmptyString(buckets[key])) {
      throw new IncomeError('ledger balances response is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502, {
        missing_bucket: key,
      });
    }
  }

  const bucketA = buckets['A'] as string;
  const bucketH = buckets['H'] as string;
  const bucketB = buckets['B'] as string;
  const bucketF = buckets['F'] as string;
  const bucketP = buckets['P'] as string;

  return {
    did,
    currency: 'USD',
    buckets: {
      A: bucketA.trim(),
      H: bucketH.trim(),
      B: bucketB.trim(),
      F: bucketF.trim(),
      P: bucketP.trim(),
    },
    as_of: isNonEmptyString(data.as_of) ? data.as_of.trim() : nowIso(),
  };
}

async function ledgerListPayoutSettlements(
  accountId: string,
  startIso: string,
  endIso: string,
  env: Env
): Promise<LedgerSettlementRecord[]> {
  const baseUrl = getBaseUrl(env.LEDGER_BASE_URL, 'LEDGER_BASE_URL');
  const adminKey = getRequiredSecret(env.LEDGER_ADMIN_KEY, 'LEDGER_ADMIN_KEY');

  const out: LedgerSettlementRecord[] = [];
  let cursor: string | null = null;

  for (let page = 0; page < 40; page++) {
    const url = new URL(`${baseUrl}/v1/payments/settlements`);
    url.searchParams.set('account_id', accountId);
    url.searchParams.set('direction', 'payout');
    url.searchParams.set('limit', '100');
    if (cursor) {
      url.searchParams.set('cursor', cursor);
    }

    const data = await fetchJson(
      url.toString(),
      {
        method: 'GET',
        headers: {
          authorization: `Bearer ${adminKey}`,
        },
      },
      'ledger'
    );

    const settlementsRaw = data.settlements;
    if (!Array.isArray(settlementsRaw)) {
      throw new IncomeError('ledger settlements response is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
    }

    for (const settlementRaw of settlementsRaw) {
      if (!isRecord(settlementRaw)) {
        throw new IncomeError('ledger settlement item is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
      }

      const id = settlementRaw.id;
      const provider = settlementRaw.provider;
      const external_payment_id = settlementRaw.external_payment_id;
      const direction = settlementRaw.direction;
      const status = settlementRaw.status;
      const account_id = settlementRaw.account_id;
      const amount_minor = settlementRaw.amount_minor;
      const currency = settlementRaw.currency;
      const created_at = settlementRaw.created_at;
      const updated_at = settlementRaw.updated_at;

      if (
        !isNonEmptyString(id) ||
        !isNonEmptyString(provider) ||
        !isNonEmptyString(external_payment_id) ||
        direction !== 'payout' ||
        (status !== 'pending' && status !== 'confirmed' && status !== 'failed' && status !== 'reversed') ||
        !isNonEmptyString(account_id) ||
        !isNonEmptyString(amount_minor) ||
        !isNonEmptyString(currency) ||
        !isNonEmptyString(created_at) ||
        !isNonEmptyString(updated_at)
      ) {
        throw new IncomeError('ledger settlement item is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
      }

      const occurredAt = isNonEmptyString(settlementRaw.settled_at)
        ? settlementRaw.settled_at.trim()
        : created_at.trim();

      if (occurredAt >= startIso && occurredAt < endIso) {
        out.push({
          id: id.trim(),
          provider: provider.trim(),
          external_payment_id: external_payment_id.trim(),
          direction: 'payout',
          status,
          account_id: account_id.trim(),
          amount_minor: amount_minor.trim(),
          currency: currency.trim(),
          settled_at: isNonEmptyString(settlementRaw.settled_at) ? settlementRaw.settled_at.trim() : undefined,
          created_at: created_at.trim(),
          updated_at: updated_at.trim(),
        });
      }
    }

    cursor = isNonEmptyString(data.next_cursor) ? data.next_cursor.trim() : null;
    if (!cursor) break;
  }

  return out;
}

async function escrowListReleasedByDid(
  did: string,
  startIso: string,
  endIso: string,
  env: Env
): Promise<EscrowFinanceRecord[]> {
  const baseUrl = getBaseUrl(env.ESCROW_BASE_URL, 'ESCROW_BASE_URL');
  const adminKey = getRequiredSecret(env.ESCROW_ADMIN_KEY, 'ESCROW_ADMIN_KEY');

  const out: EscrowFinanceRecord[] = [];
  let cursor: string | null = null;

  for (let page = 0; page < 40; page++) {
    const url = new URL(`${baseUrl}/v1/escrows`);
    url.searchParams.set('did', did);
    url.searchParams.set('status', 'released');
    url.searchParams.set('from', startIso);
    url.searchParams.set('to', endIso);
    url.searchParams.set('limit', '100');
    if (cursor) {
      url.searchParams.set('cursor', cursor);
    }

    const dataRaw = await fetchJson(
      url.toString(),
      {
        method: 'GET',
        headers: {
          authorization: `Bearer ${adminKey}`,
        },
      },
      'escrow'
    );

    const escrowsRaw = dataRaw.escrows;
    if (!Array.isArray(escrowsRaw)) {
      throw new IncomeError('escrow list response is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
    }

    for (const escrowRaw of escrowsRaw) {
      if (!isRecord(escrowRaw)) {
        throw new IncomeError('escrow list item is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
      }

      const escrow_id = escrowRaw.escrow_id;
      const status = escrowRaw.status;
      const buyer_did = escrowRaw.buyer_did;
      const worker_did = escrowRaw.worker_did;
      const amount_minor = escrowRaw.amount_minor;
      const buyer_total_minor = escrowRaw.buyer_total_minor;
      const worker_net_minor = escrowRaw.worker_net_minor;
      const fee_quote = escrowRaw.fee_quote;
      const timestamps = escrowRaw.timestamps;
      const ledger_refs = escrowRaw.ledger_refs;

      if (
        !isNonEmptyString(escrow_id) ||
        status !== 'released' ||
        !isNonEmptyString(buyer_did) ||
        (worker_did !== null && worker_did !== undefined && !isNonEmptyString(worker_did)) ||
        !isNonEmptyString(amount_minor) ||
        !isNonEmptyString(buyer_total_minor) ||
        !isNonEmptyString(worker_net_minor) ||
        !isRecord(fee_quote) ||
        !isRecord(timestamps) ||
        !isRecord(ledger_refs)
      ) {
        throw new IncomeError('escrow list item is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
      }

      const released_at = timestamps.released_at;
      const created_at = timestamps.created_at;
      const updated_at = timestamps.updated_at;
      if (!isNonEmptyString(released_at) || !isNonEmptyString(created_at) || !isNonEmptyString(updated_at)) {
        throw new IncomeError('escrow list item timestamps are invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
      }

      if (
        !isNonEmptyString(fee_quote.policy_id) ||
        !isNonEmptyString(fee_quote.policy_version) ||
        !isNonEmptyString(fee_quote.policy_hash_b64u) ||
        !isNonEmptyString(fee_quote.buyer_total_minor) ||
        !isNonEmptyString(fee_quote.worker_net_minor) ||
        !Array.isArray(fee_quote.fees)
      ) {
        throw new IncomeError('escrow fee_quote is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
      }

      const fees: EscrowFeeItem[] = fee_quote.fees.map((feeRaw) => {
        if (!isRecord(feeRaw)) {
          throw new IncomeError('escrow fee item invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
        }

        if (
          !isNonEmptyString(feeRaw.kind) ||
          (feeRaw.payer !== 'buyer' && feeRaw.payer !== 'worker') ||
          !isNonEmptyString(feeRaw.amount_minor) ||
          typeof feeRaw.rate_bps !== 'number' ||
          !isNonEmptyString(feeRaw.min_fee_minor) ||
          typeof feeRaw.floor_applied !== 'boolean'
        ) {
          throw new IncomeError('escrow fee item invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
        }

        let splits: EscrowFeeSplit[] | undefined;
        if (feeRaw.splits !== undefined) {
          if (!Array.isArray(feeRaw.splits)) {
            throw new IncomeError('escrow fee split invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
          }

          splits = feeRaw.splits.map((splitRaw) => {
            if (!isRecord(splitRaw)) {
              throw new IncomeError('escrow fee split invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
            }
            if (
              (splitRaw.kind !== 'platform' && splitRaw.kind !== 'referral') ||
              !isNonEmptyString(splitRaw.account) ||
              (splitRaw.bucket !== 'A' && splitRaw.bucket !== 'F') ||
              !isNonEmptyString(splitRaw.amount_minor)
            ) {
              throw new IncomeError('escrow fee split invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
            }

            return {
              kind: splitRaw.kind,
              account: splitRaw.account.trim(),
              bucket: splitRaw.bucket,
              amount_minor: splitRaw.amount_minor.trim(),
              referrer_did: isNonEmptyString(splitRaw.referrer_did) ? splitRaw.referrer_did.trim() : undefined,
              referral_code: isNonEmptyString(splitRaw.referral_code) ? splitRaw.referral_code.trim() : undefined,
            };
          });
        }

        return {
          kind: feeRaw.kind.trim(),
          payer: feeRaw.payer,
          amount_minor: feeRaw.amount_minor.trim(),
          rate_bps: feeRaw.rate_bps,
          min_fee_minor: feeRaw.min_fee_minor.trim(),
          floor_applied: feeRaw.floor_applied,
          splits,
        };
      });

      const feeTransfers = Array.isArray(ledger_refs.fee_transfers)
        ? ledger_refs.fee_transfers.filter((value): value is string => typeof value === 'string').map((value) => value.trim())
        : [];

      const referralTransfers = Array.isArray(ledger_refs.referral_transfers)
        ? ledger_refs.referral_transfers.filter((value): value is string => typeof value === 'string').map((value) => value.trim())
        : [];

      out.push({
        escrow_id: escrow_id.trim(),
        status: 'released',
        buyer_did: buyer_did.trim(),
        worker_did: isNonEmptyString(worker_did) ? worker_did.trim() : null,
        amount_minor: amount_minor.trim(),
        buyer_total_minor: buyer_total_minor.trim(),
        worker_net_minor: worker_net_minor.trim(),
        fee_quote: {
          policy_id: fee_quote.policy_id.trim(),
          policy_version: fee_quote.policy_version.trim(),
          policy_hash_b64u: fee_quote.policy_hash_b64u.trim(),
          buyer_total_minor: fee_quote.buyer_total_minor.trim(),
          worker_net_minor: fee_quote.worker_net_minor.trim(),
          fees,
        },
        timestamps: {
          released_at: released_at.trim(),
          created_at: created_at.trim(),
          updated_at: updated_at.trim(),
        },
        ledger_refs: {
          hold_transfer: isNonEmptyString(ledger_refs.hold_transfer) ? ledger_refs.hold_transfer.trim() : '',
          worker_transfer: isNonEmptyString(ledger_refs.worker_transfer) ? ledger_refs.worker_transfer.trim() : null,
          fee_transfers: feeTransfers,
          referral_transfers: referralTransfers,
        },
      });
    }

    cursor = isNonEmptyString(dataRaw.next_cursor) ? dataRaw.next_cursor.trim() : null;
    if (!cursor) break;
  }

  return out;
}

async function cutsGetApplyEventForEscrow(escrowId: string, env: Env): Promise<CutsApplyEvent> {
  const baseUrl = getBaseUrl(env.CUTS_BASE_URL, 'CUTS_BASE_URL');
  const adminKey = getRequiredSecret(env.CUTS_ADMIN_KEY, 'CUTS_ADMIN_KEY');

  const dataRaw = await fetchJson(
    `${baseUrl}/v1/fees/apply/events?settlement_ref=${encodeURIComponent(escrowId)}&limit=2`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${adminKey}`,
      },
    },
    'clawcuts'
  );

  const eventsRaw = dataRaw.events;
  if (!Array.isArray(eventsRaw) || eventsRaw.length !== 1) {
    throw new IncomeError('Expected exactly one clawcuts apply event for escrow', 'FINANCE_REF_MISMATCH', 502, {
      escrow_id: escrowId,
      event_count: Array.isArray(eventsRaw) ? eventsRaw.length : null,
    });
  }

  const raw = eventsRaw[0];
  if (!isRecord(raw)) {
    throw new IncomeError('clawcuts apply event is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
  }

  if (
    !isNonEmptyString(raw.apply_id) ||
    !isNonEmptyString(raw.month) ||
    !isRecord(raw.policy) ||
    !isRecord(raw.fee_summary) ||
    !isRecord(raw.transfer_plan) ||
    !isRecord(raw.ledger_refs) ||
    !isNonEmptyString(raw.snapshot_hash_b64u) ||
    !isNonEmptyString(raw.created_at)
  ) {
    throw new IncomeError('clawcuts apply event is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
  }

  const policy = raw.policy;
  if (!isNonEmptyString(policy.id) || !isNonEmptyString(policy.version) || !isNonEmptyString(policy.hash_b64u)) {
    throw new IncomeError('clawcuts policy block is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
  }

  const feeSummary = raw.fee_summary;
  for (const field of [
    'principal_minor',
    'buyer_total_minor',
    'worker_net_minor',
    'total_fee_minor',
    'platform_fee_minor',
    'referral_payout_minor',
    'platform_retained_minor',
  ]) {
    if (!isNonEmptyString(feeSummary[field])) {
      throw new IncomeError('clawcuts fee summary is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502, { field });
    }
  }

  const transferPlan = raw.transfer_plan;
  if (!Array.isArray(transferPlan.transfers)) {
    throw new IncomeError('clawcuts transfer plan is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
  }

  const transfers = transferPlan.transfers.map((transferRaw) => {
    if (!isRecord(transferRaw)) {
      throw new IncomeError('clawcuts transfer item is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
    }
    if (
      typeof transferRaw.transfer_index !== 'number' ||
      typeof transferRaw.fee_index !== 'number' ||
      !isNonEmptyString(transferRaw.fee_kind) ||
      (transferRaw.payer !== 'buyer' && transferRaw.payer !== 'worker') ||
      (transferRaw.split_kind !== 'platform' && transferRaw.split_kind !== 'referral') ||
      !isNonEmptyString(transferRaw.to_account) ||
      (transferRaw.to_bucket !== 'A' && transferRaw.to_bucket !== 'F') ||
      !isNonEmptyString(transferRaw.amount_minor)
    ) {
      throw new IncomeError('clawcuts transfer item is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
    }

    const payer: 'buyer' | 'worker' = transferRaw.payer;
    const split_kind: 'platform' | 'referral' = transferRaw.split_kind;
    const to_bucket: 'A' | 'F' = transferRaw.to_bucket;

    return {
      transfer_index: transferRaw.transfer_index,
      fee_index: transferRaw.fee_index,
      fee_kind: transferRaw.fee_kind.trim(),
      payer,
      split_kind,
      to_account: transferRaw.to_account.trim(),
      to_bucket,
      amount_minor: transferRaw.amount_minor.trim(),
      referrer_did: isNonEmptyString(transferRaw.referrer_did) ? transferRaw.referrer_did.trim() : undefined,
      referral_code: isNonEmptyString(transferRaw.referral_code) ? transferRaw.referral_code.trim() : undefined,
    };
  });

  const ledgerRefs = raw.ledger_refs;
  const feeTransfers = Array.isArray(ledgerRefs.fee_transfers)
    ? ledgerRefs.fee_transfers.filter((entry): entry is string => typeof entry === 'string').map((entry) => entry.trim())
    : [];
  const referralTransfers = Array.isArray(ledgerRefs.referral_transfers)
    ? ledgerRefs.referral_transfers.filter((entry): entry is string => typeof entry === 'string').map((entry) => entry.trim())
    : [];

  const principalMinor = (feeSummary.principal_minor as string).trim();
  const buyerTotalMinor = (feeSummary.buyer_total_minor as string).trim();
  const workerNetMinor = (feeSummary.worker_net_minor as string).trim();
  const totalFeeMinor = (feeSummary.total_fee_minor as string).trim();
  const platformFeeMinor = (feeSummary.platform_fee_minor as string).trim();
  const referralPayoutMinor = (feeSummary.referral_payout_minor as string).trim();
  const platformRetainedMinor = (feeSummary.platform_retained_minor as string).trim();

  return {
    apply_id: raw.apply_id.trim(),
    settlement_ref: isNonEmptyString(raw.settlement_ref) ? raw.settlement_ref.trim() : null,
    month: raw.month.trim(),
    policy: {
      id: policy.id.trim(),
      version: policy.version.trim(),
      hash_b64u: policy.hash_b64u.trim(),
    },
    fee_summary: {
      principal_minor: principalMinor,
      buyer_total_minor: buyerTotalMinor,
      worker_net_minor: workerNetMinor,
      total_fee_minor: totalFeeMinor,
      platform_fee_minor: platformFeeMinor,
      referral_payout_minor: referralPayoutMinor,
      platform_retained_minor: platformRetainedMinor,
    },
    transfer_plan: { transfers },
    ledger_refs: {
      fee_transfers: feeTransfers,
      referral_transfers: referralTransfers,
    },
    finalized_at: isNonEmptyString(raw.finalized_at) ? raw.finalized_at.trim() : null,
    snapshot_hash_b64u: raw.snapshot_hash_b64u.trim(),
    created_at: raw.created_at.trim(),
  };
}

async function settleListPayoutsForDid(
  did: string,
  startIso: string,
  endIso: string,
  env: Env
): Promise<SettlePayoutRecord[]> {
  const baseUrl = getBaseUrl(env.SETTLE_BASE_URL, 'SETTLE_BASE_URL');
  const adminKey = getRequiredSecret(env.SETTLE_ADMIN_KEY, 'SETTLE_ADMIN_KEY');

  const out: SettlePayoutRecord[] = [];
  let cursor: string | null = null;

  for (let page = 0; page < 40; page++) {
    const url = new URL(`${baseUrl}/v1/payouts`);
    url.searchParams.set('account_did', did);
    url.searchParams.set('from', startIso);
    url.searchParams.set('to', endIso);
    url.searchParams.set('limit', '100');
    if (cursor) {
      url.searchParams.set('cursor', cursor);
    }

    const dataRaw = await fetchJson(
      url.toString(),
      {
        method: 'GET',
        headers: {
          authorization: `Bearer ${adminKey}`,
        },
      },
      'clawsettle'
    );

    const payoutsRaw = dataRaw.payouts;
    if (!Array.isArray(payoutsRaw)) {
      throw new IncomeError('clawsettle payout list is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
    }

    for (const payoutRaw of payoutsRaw) {
      if (!isRecord(payoutRaw)) {
        throw new IncomeError('clawsettle payout row is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
      }

      if (
        !isNonEmptyString(payoutRaw.id) ||
        !isNonEmptyString(payoutRaw.account_did) ||
        !isNonEmptyString(payoutRaw.account_id) ||
        !isNonEmptyString(payoutRaw.amount_minor) ||
        !isNonEmptyString(payoutRaw.currency) ||
        !isNonEmptyString(payoutRaw.status) ||
        !isNonEmptyString(payoutRaw.created_at)
      ) {
        throw new IncomeError('clawsettle payout row is invalid', 'DEPENDENCY_RESPONSE_INVALID', 502);
      }

      out.push({
        id: payoutRaw.id.trim(),
        account_did: payoutRaw.account_did.trim(),
        account_id: payoutRaw.account_id.trim(),
        external_payout_id: isNonEmptyString(payoutRaw.external_payout_id)
          ? payoutRaw.external_payout_id.trim()
          : undefined,
        amount_minor: payoutRaw.amount_minor.trim(),
        currency: payoutRaw.currency.trim(),
        status: payoutRaw.status.trim(),
        created_at: payoutRaw.created_at.trim(),
        submitted_at: isNonEmptyString(payoutRaw.submitted_at) ? payoutRaw.submitted_at.trim() : undefined,
        finalized_at: isNonEmptyString(payoutRaw.finalized_at) ? payoutRaw.finalized_at.trim() : undefined,
        failed_at: isNonEmptyString(payoutRaw.failed_at) ? payoutRaw.failed_at.trim() : undefined,
      });
    }

    cursor = isNonEmptyString(dataRaw.next_cursor) ? dataRaw.next_cursor.trim() : null;
    if (!cursor) break;
  }

  return out;
}

function validateEscrowFinanceRefs(escrow: EscrowFinanceRecord, apply: CutsApplyEvent): void {
  if (apply.settlement_ref !== escrow.escrow_id) {
    throw new IncomeError('clawcuts apply settlement_ref mismatch', 'FINANCE_REF_MISMATCH', 502, {
      escrow_id: escrow.escrow_id,
      apply_id: apply.apply_id,
      settlement_ref: apply.settlement_ref,
    });
  }

  if (apply.policy.id !== escrow.fee_quote.policy_id) {
    throw new IncomeError('Policy id mismatch between escrow and clawcuts apply', 'FINANCE_REF_MISMATCH', 502, {
      escrow_id: escrow.escrow_id,
      apply_policy_id: apply.policy.id,
      escrow_policy_id: escrow.fee_quote.policy_id,
    });
  }

  if (apply.policy.version !== escrow.fee_quote.policy_version) {
    throw new IncomeError('Policy version mismatch between escrow and clawcuts apply', 'FINANCE_REF_MISMATCH', 502, {
      escrow_id: escrow.escrow_id,
      apply_policy_version: apply.policy.version,
      escrow_policy_version: escrow.fee_quote.policy_version,
    });
  }

  if (apply.policy.hash_b64u !== escrow.fee_quote.policy_hash_b64u) {
    throw new IncomeError('Policy hash mismatch between escrow and clawcuts apply', 'FINANCE_REF_MISMATCH', 502, {
      escrow_id: escrow.escrow_id,
      apply_policy_hash_b64u: apply.policy.hash_b64u,
      escrow_policy_hash_b64u: escrow.fee_quote.policy_hash_b64u,
    });
  }

  const applyBuyer = parsePositiveMinor(apply.fee_summary.buyer_total_minor, 'apply.fee_summary.buyer_total_minor');
  const applyWorker = parseNonNegativeMinor(apply.fee_summary.worker_net_minor, 'apply.fee_summary.worker_net_minor');
  const escrowBuyer = parsePositiveMinor(escrow.buyer_total_minor, 'escrow.buyer_total_minor');
  const escrowWorker = parseNonNegativeMinor(escrow.worker_net_minor, 'escrow.worker_net_minor');

  if (applyBuyer !== escrowBuyer || applyWorker !== escrowWorker) {
    throw new IncomeError('Escrow totals mismatch clawcuts apply summary', 'FINANCE_REF_MISMATCH', 502, {
      escrow_id: escrow.escrow_id,
      apply_buyer_total_minor: applyBuyer.toString(),
      escrow_buyer_total_minor: escrowBuyer.toString(),
      apply_worker_net_minor: applyWorker.toString(),
      escrow_worker_net_minor: escrowWorker.toString(),
    });
  }

  if (!apply.finalized_at) {
    throw new IncomeError('clawcuts apply event is not finalized', 'FINANCE_REF_MISMATCH', 502, {
      escrow_id: escrow.escrow_id,
      apply_id: apply.apply_id,
    });
  }
}

function buildPayoutSettlementMap(settlements: LedgerSettlementRecord[]): Map<string, LedgerSettlementRecord> {
  const map = new Map<string, LedgerSettlementRecord>();
  for (const settlement of settlements) {
    map.set(settlement.external_payment_id, settlement);
  }
  return map;
}

function validatePayoutRefs(payouts: SettlePayoutRecord[], settlements: LedgerSettlementRecord[], did: string): void {
  const settlementByExternalId = buildPayoutSettlementMap(settlements);

  for (const payout of payouts) {
    if (payout.account_did !== did) {
      throw new IncomeError('clawsettle payout account_did mismatch', 'FINANCE_REF_MISMATCH', 502, {
        did,
        payout_id: payout.id,
        payout_account_did: payout.account_did,
      });
    }

    if (!payout.external_payout_id) {
      continue;
    }

    const isTerminal = payout.status === 'paid' || payout.status === 'failed';
    if (!isTerminal) continue;

    const settlement = settlementByExternalId.get(payout.external_payout_id);
    if (!settlement) {
      throw new IncomeError('Missing ledger settlement for payout', 'FINANCE_REF_MISMATCH', 502, {
        payout_id: payout.id,
        external_payout_id: payout.external_payout_id,
      });
    }

    const expectedStatus = payout.status === 'paid' ? 'confirmed' : 'failed';
    if (settlement.status !== expectedStatus) {
      throw new IncomeError('Payout settlement status mismatch', 'FINANCE_REF_MISMATCH', 502, {
        payout_id: payout.id,
        payout_status: payout.status,
        settlement_id: settlement.id,
        settlement_status: settlement.status,
      });
    }
  }
}

async function buildFinancialContext(
  did: string,
  month: string,
  startIso: string,
  endIso: string,
  env: Env
): Promise<FinancialContext> {
  const account = await ledgerGetAccountByDid(did, env);
  const escrows = await escrowListReleasedByDid(did, startIso, endIso, env);

  const cutsApplyEvents = await Promise.all(
    escrows.map((escrow) => cutsGetApplyEventForEscrow(escrow.escrow_id, env))
  );

  const cutsApplyByEscrow = new Map<string, CutsApplyEvent>();
  for (let i = 0; i < escrows.length; i++) {
    const escrow = escrows[i];
    const apply = cutsApplyEvents[i];
    if (!escrow || !apply) continue;

    validateEscrowFinanceRefs(escrow, apply);
    cutsApplyByEscrow.set(escrow.escrow_id, apply);
  }

  const payouts = await settleListPayoutsForDid(did, startIso, endIso, env);
  const payoutSettlements = await ledgerListPayoutSettlements(account.id, startIso, endIso, env);
  validatePayoutRefs(payouts, payoutSettlements, did);

  const balances = await ledgerGetBalances(did, env);

  return {
    did,
    month,
    start_iso: startIso,
    end_iso: endIso,
    ledger_account_id: account.id,
    escrows,
    cuts_apply_by_escrow: cutsApplyByEscrow,
    payouts,
    payout_settlements: payoutSettlements,
    balances,
  };
}

function compareByTimestampAndId(a: { occurred_at: string; ref_id: string }, b: { occurred_at: string; ref_id: string }): number {
  if (a.occurred_at < b.occurred_at) return -1;
  if (a.occurred_at > b.occurred_at) return 1;
  return a.ref_id.localeCompare(b.ref_id);
}

function buildStatementPayload(context: FinancialContext): StatementPayload {
  let grossEarned = 0n;
  let workerFees = 0n;
  let netEarned = 0n;
  let buyerSpend = 0n;
  let buyerFees = 0n;
  let payoutsTotal = 0n;

  let releasedAsWorker = 0;
  let releasedAsBuyer = 0;

  const lineItems: StatementLineItem[] = [];

  for (const escrow of context.escrows) {
    const principal = parsePositiveMinor(escrow.amount_minor, 'escrow.amount_minor');
    const buyerTotal = parsePositiveMinor(escrow.buyer_total_minor, 'escrow.buyer_total_minor');
    const workerNet = parseNonNegativeMinor(escrow.worker_net_minor, 'escrow.worker_net_minor');

    const workerFeeMinor = principal - workerNet;
    const buyerFeeMinor = buyerTotal - principal;

    if (escrow.worker_did === context.did) {
      releasedAsWorker += 1;
      grossEarned += principal;
      workerFees += workerFeeMinor;
      netEarned += workerNet;

      lineItems.push({
        occurred_at: escrow.timestamps.released_at,
        type: 'escrow_income',
        ref_id: escrow.escrow_id,
        direction: 'in',
        amount_minor: workerNet.toString(),
        currency: 'USD',
        details: {
          principal_minor: principal.toString(),
          worker_fee_minor: workerFeeMinor.toString(),
          policy_id: escrow.fee_quote.policy_id,
          policy_version: escrow.fee_quote.policy_version,
          policy_hash_b64u: escrow.fee_quote.policy_hash_b64u,
        },
      });
    }

    if (escrow.buyer_did === context.did) {
      releasedAsBuyer += 1;
      buyerSpend += buyerTotal;
      buyerFees += buyerFeeMinor;

      lineItems.push({
        occurred_at: escrow.timestamps.released_at,
        type: 'escrow_spend',
        ref_id: escrow.escrow_id,
        direction: 'out',
        amount_minor: buyerTotal.toString(),
        currency: 'USD',
        details: {
          principal_minor: principal.toString(),
          buyer_fee_minor: buyerFeeMinor.toString(),
          policy_id: escrow.fee_quote.policy_id,
          policy_version: escrow.fee_quote.policy_version,
          policy_hash_b64u: escrow.fee_quote.policy_hash_b64u,
        },
      });
    }
  }

  for (const payout of context.payouts) {
    if (payout.status !== 'paid') continue;

    const amount = parsePositiveMinor(payout.amount_minor, 'payout.amount_minor');
    payoutsTotal += amount;

    const occurredAt = payout.finalized_at ?? payout.created_at;

    lineItems.push({
      occurred_at: occurredAt,
      type: 'payout',
      ref_id: payout.id,
      direction: 'out',
      amount_minor: amount.toString(),
      currency: 'USD',
      details: {
        external_payout_id: payout.external_payout_id ?? null,
        account_id: payout.account_id,
      },
    });
  }

  lineItems.sort(compareByTimestampAndId);

  const endingBalanceMinor = parseNonNegativeMinor(context.balances.buckets.A, 'balances.A').toString();

  return {
    did: context.did,
    month: context.month,
    currency: 'USD',
    generated_at: nowIso(),
    totals: {
      gross_earned_minor: grossEarned.toString(),
      worker_fees_minor: workerFees.toString(),
      net_earned_minor: netEarned.toString(),
      buyer_spend_minor: buyerSpend.toString(),
      buyer_fees_minor: buyerFees.toString(),
      payouts_minor: payoutsTotal.toString(),
      ending_balance_minor: endingBalanceMinor,
    },
    counts: {
      released_as_worker: releasedAsWorker,
      released_as_buyer: releasedAsBuyer,
      payouts: context.payouts.filter((entry) => entry.status === 'paid').length,
    },
    line_items: lineItems,
    source_refs: {
      escrow_count: context.escrows.length,
      cuts_apply_count: context.cuts_apply_by_escrow.size,
      payout_count: context.payouts.length,
      payout_settlement_count: context.payout_settlements.length,
    },
  };
}

function statementToCsv(payload: StatementPayload): string {
  const header = ['occurred_at', 'type', 'ref_id', 'direction', 'amount_minor', 'currency', 'details_json'];
  const rows = payload.line_items.map((item) => {
    const details = JSON.stringify(item.details);
    return [
      item.occurred_at,
      item.type,
      item.ref_id,
      item.direction,
      item.amount_minor,
      item.currency,
      details,
    ];
  });

  const csv = [header.join(',')]
    .concat(rows.map((row) => row.map((cell) => escapeCsv(cell)).join(',')))
    .join('\n');

  return `${csv}\n`;
}

function escapeCsv(value: string): string {
  if (/[",\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

async function buildInvoicesPayload(context: FinancialContext): Promise<InvoicesPayload> {
  const invoices: InvoiceItem[] = [];

  for (const escrow of context.escrows) {
    if (escrow.buyer_did !== context.did) continue;

    const apply = context.cuts_apply_by_escrow.get(escrow.escrow_id);
    if (!apply) {
      throw new IncomeError('Missing clawcuts apply event for escrow invoice', 'FINANCE_REF_MISMATCH', 502, {
        escrow_id: escrow.escrow_id,
      });
    }

    const rewardMinor = parsePositiveMinor(escrow.amount_minor, 'escrow.amount_minor');
    const totalMinor = parsePositiveMinor(escrow.buyer_total_minor, 'escrow.buyer_total_minor');
    const buyerFeeMinor = totalMinor - rewardMinor;

    const invoiceHash = await sha256B64uUtf8(`${context.did}:${context.month}:${escrow.escrow_id}`);

    invoices.push({
      invoice_id: `inv_${invoiceHash.slice(0, 20)}`,
      escrow_id: escrow.escrow_id,
      released_at: escrow.timestamps.released_at,
      buyer_did: escrow.buyer_did,
      worker_did: escrow.worker_did,
      reward_minor: rewardMinor.toString(),
      buyer_fee_minor: buyerFeeMinor.toString(),
      total_minor: totalMinor.toString(),
      currency: 'USD',
      policy: {
        id: escrow.fee_quote.policy_id,
        version: escrow.fee_quote.policy_version,
        hash_b64u: escrow.fee_quote.policy_hash_b64u,
      },
      finance_ref: {
        cuts_apply_id: apply.apply_id,
        cuts_snapshot_hash_b64u: apply.snapshot_hash_b64u,
      },
      tax: {
        jurisdiction: null,
        vat_number: null,
      },
    });
  }

  invoices.sort((a, b) => {
    if (a.released_at < b.released_at) return -1;
    if (a.released_at > b.released_at) return 1;
    return a.invoice_id.localeCompare(b.invoice_id);
  });

  const grossReward = sumMinor(invoices.map((invoice) => invoice.reward_minor), 'invoice.reward_minor');
  const buyerFee = sumMinor(invoices.map((invoice) => invoice.buyer_fee_minor), 'invoice.buyer_fee_minor');
  const total = sumMinor(invoices.map((invoice) => invoice.total_minor), 'invoice.total_minor');

  return {
    did: context.did,
    month: context.month,
    currency: 'USD',
    generated_at: nowIso(),
    totals: {
      invoice_count: invoices.length,
      gross_reward_minor: grossReward.toString(),
      buyer_fee_minor: buyerFee.toString(),
      total_minor: total.toString(),
    },
    invoices,
    source_refs: {
      escrow_count: context.escrows.length,
      cuts_apply_count: context.cuts_apply_by_escrow.size,
      payout_count: context.payouts.length,
      payout_settlement_count: context.payout_settlements.length,
    },
  };
}

async function buildTaxLotsPayload(
  did: string,
  year: string,
  env: Env
): Promise<TaxLotsPayload> {
  const { startIso, endIso } = yearRange(year);
  const context = await buildFinancialContext(did, `${year}-01`, startIso, endIso, env);

  const lots: TaxLotItem[] = [];

  for (const escrow of context.escrows) {
    const principal = parsePositiveMinor(escrow.amount_minor, 'escrow.amount_minor');
    const buyerTotal = parsePositiveMinor(escrow.buyer_total_minor, 'escrow.buyer_total_minor');
    const workerNet = parseNonNegativeMinor(escrow.worker_net_minor, 'escrow.worker_net_minor');

    if (escrow.worker_did === did) {
      const lotHash = await sha256B64uUtf8(`income:${did}:${escrow.escrow_id}`);
      lots.push({
        lot_id: `lot_${lotHash.slice(0, 20)}`,
        occurred_at: escrow.timestamps.released_at,
        category: 'income',
        source: 'escrow',
        source_ref: escrow.escrow_id,
        amount_minor: workerNet.toString(),
        currency: 'USD',
        jurisdiction: null,
      });
    }

    if (escrow.buyer_did === did) {
      const lotHash = await sha256B64uUtf8(`expense:${did}:${escrow.escrow_id}`);
      lots.push({
        lot_id: `lot_${lotHash.slice(0, 20)}`,
        occurred_at: escrow.timestamps.released_at,
        category: 'expense',
        source: 'escrow',
        source_ref: escrow.escrow_id,
        amount_minor: buyerTotal.toString(),
        currency: 'USD',
        jurisdiction: null,
        notes: `reward_minor=${principal.toString()}`,
      });
    }
  }

  for (const payout of context.payouts) {
    if (payout.status !== 'paid') continue;

    const payoutAmount = parsePositiveMinor(payout.amount_minor, 'payout.amount_minor');
    const lotHash = await sha256B64uUtf8(`payout:${did}:${payout.id}`);

    lots.push({
      lot_id: `lot_${lotHash.slice(0, 20)}`,
      occurred_at: payout.finalized_at ?? payout.created_at,
      category: 'payout',
      source: 'payout',
      source_ref: payout.id,
      amount_minor: payoutAmount.toString(),
      currency: 'USD',
      jurisdiction: null,
      notes: payout.external_payout_id ? `external_payout_id=${payout.external_payout_id}` : undefined,
    });
  }

  lots.sort((a, b) => {
    if (a.occurred_at < b.occurred_at) return -1;
    if (a.occurred_at > b.occurred_at) return 1;
    return a.lot_id.localeCompare(b.lot_id);
  });

  const incomeMinor = sumMinor(
    lots.filter((lot) => lot.category === 'income').map((lot) => lot.amount_minor),
    'tax_lot.income'
  );

  const expenseMinor = sumMinor(
    lots.filter((lot) => lot.category === 'expense').map((lot) => lot.amount_minor),
    'tax_lot.expense'
  );

  const payoutMinor = sumMinor(
    lots.filter((lot) => lot.category === 'payout').map((lot) => lot.amount_minor),
    'tax_lot.payout'
  );

  return {
    did,
    year,
    currency: 'USD',
    generated_at: nowIso(),
    totals: {
      income_minor: incomeMinor.toString(),
      expense_minor: expenseMinor.toString(),
      payout_minor: payoutMinor.toString(),
      lot_count: lots.length,
    },
    tax_lots: lots,
    source_refs: {
      escrow_count: context.escrows.length,
      cuts_apply_count: context.cuts_apply_by_escrow.size,
      payout_count: context.payouts.length,
      payout_settlement_count: context.payout_settlements.length,
    },
  };
}

function buildIncomeTimelineEntries(context: FinancialContext): IncomeTimelineItem[] {
  const entries: IncomeTimelineItem[] = [];

  for (const escrow of context.escrows) {
    const principal = parsePositiveMinor(escrow.amount_minor, 'escrow.amount_minor');
    const buyerTotal = parsePositiveMinor(escrow.buyer_total_minor, 'escrow.buyer_total_minor');
    const workerNet = parseNonNegativeMinor(escrow.worker_net_minor, 'escrow.worker_net_minor');

    if (escrow.worker_did === context.did) {
      entries.push({
        occurred_at: escrow.timestamps.released_at,
        item_id: `escrow_income:${escrow.escrow_id}`,
        type: 'escrow_income',
        direction: 'in',
        amount_minor: workerNet.toString(),
        currency: 'USD',
        metadata: {
          escrow_id: escrow.escrow_id,
          principal_minor: principal.toString(),
          policy_id: escrow.fee_quote.policy_id,
          policy_version: escrow.fee_quote.policy_version,
          policy_hash_b64u: escrow.fee_quote.policy_hash_b64u,
        },
      });
    }

    if (escrow.buyer_did === context.did) {
      entries.push({
        occurred_at: escrow.timestamps.released_at,
        item_id: `escrow_spend:${escrow.escrow_id}`,
        type: 'escrow_spend',
        direction: 'out',
        amount_minor: buyerTotal.toString(),
        currency: 'USD',
        metadata: {
          escrow_id: escrow.escrow_id,
          principal_minor: principal.toString(),
          policy_id: escrow.fee_quote.policy_id,
          policy_version: escrow.fee_quote.policy_version,
          policy_hash_b64u: escrow.fee_quote.policy_hash_b64u,
        },
      });
    }
  }

  for (const payout of context.payouts) {
    if (payout.status !== 'paid') continue;

    entries.push({
      occurred_at: payout.finalized_at ?? payout.created_at,
      item_id: `payout:${payout.id}`,
      type: 'payout',
      direction: 'out',
      amount_minor: parsePositiveMinor(payout.amount_minor, 'payout.amount_minor').toString(),
      currency: 'USD',
      metadata: {
        payout_id: payout.id,
        external_payout_id: payout.external_payout_id ?? null,
        account_id: payout.account_id,
      },
    });
  }

  entries.sort((a, b) => {
    if (a.occurred_at < b.occurred_at) return -1;
    if (a.occurred_at > b.occurred_at) return 1;
    return a.item_id.localeCompare(b.item_id);
  });

  return entries;
}

function parseSnapshotRow(row: unknown): ReportSnapshotRow | null {
  if (!isRecord(row)) return null;

  const snapshot_id = row.snapshot_id;
  const report_type = row.report_type;
  const did = row.did;
  const period_key = row.period_key;
  const payload_json = row.payload_json;
  const csv_body = row.csv_body;
  const payload_hash_b64u = row.payload_hash_b64u;
  const source_refs_json = row.source_refs_json;
  const created_at = row.created_at;

  if (
    !isNonEmptyString(snapshot_id) ||
    !isNonEmptyString(report_type) ||
    !isNonEmptyString(did) ||
    !isNonEmptyString(period_key) ||
    !isNonEmptyString(payload_json) ||
    !isNonEmptyString(payload_hash_b64u) ||
    !isNonEmptyString(created_at)
  ) {
    return null;
  }

  if (
    report_type !== 'monthly_statement_json' &&
    report_type !== 'monthly_statement_csv' &&
    report_type !== 'invoices_json' &&
    report_type !== 'tax_lots_json'
  ) {
    return null;
  }

  return {
    snapshot_id: snapshot_id.trim(),
    report_type,
    did: did.trim(),
    period_key: period_key.trim(),
    payload_json: payload_json.trim(),
    csv_body: isNonEmptyString(csv_body) ? csv_body : null,
    payload_hash_b64u: payload_hash_b64u.trim(),
    source_refs_json: isNonEmptyString(source_refs_json) ? source_refs_json : null,
    created_at: created_at.trim(),
  };
}

async function getReportSnapshot(
  db: D1Database,
  reportType: ReportType,
  did: string,
  periodKey: string
): Promise<ReportSnapshotRow | null> {
  const row = await db
    .prepare(
      `SELECT snapshot_id, report_type, did, period_key, payload_json, csv_body, payload_hash_b64u, source_refs_json, created_at
       FROM report_snapshots
       WHERE report_type = ? AND did = ? AND period_key = ?`
    )
    .bind(reportType, did, periodKey)
    .first();

  return parseSnapshotRow(row);
}

async function insertReportSnapshot(
  db: D1Database,
  params: {
    reportType: ReportType;
    did: string;
    periodKey: string;
    payloadJson: string;
    csvBody: string | null;
    payloadHashB64u: string;
    sourceRefsJson: string | null;
  }
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO report_snapshots (
        snapshot_id,
        report_type,
        did,
        period_key,
        payload_json,
        csv_body,
        payload_hash_b64u,
        source_refs_json,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      `irs_${crypto.randomUUID()}`,
      params.reportType,
      params.did,
      params.periodKey,
      params.payloadJson,
      params.csvBody,
      params.payloadHashB64u,
      params.sourceRefsJson,
      nowIso()
    )
    .run();
}

async function getOrCreateReportSnapshot<T>(
  env: Env,
  reportType: ReportType,
  did: string,
  periodKey: string,
  build: () => Promise<{ payload: T; csvBody?: string; hashSource: string; sourceRefs?: ReportSourceRefs }>
): Promise<{
  snapshot: ReportSnapshotRow;
  payload: T;
}> {
  const existing = await getReportSnapshot(env.INCOME_DB, reportType, did, periodKey);
  if (existing) {
    let payload: unknown;
    try {
      payload = JSON.parse(existing.payload_json);
    } catch {
      throw new IncomeError('Stored snapshot payload is invalid JSON', 'DB_CORRUPT', 500, {
        snapshot_id: existing.snapshot_id,
      });
    }

    return {
      snapshot: existing,
      payload: payload as T,
    };
  }

  const built = await build();
  const payloadJson = JSON.stringify(built.payload);
  const payloadHashB64u = await sha256B64uUtf8(built.hashSource);

  try {
    await insertReportSnapshot(env.INCOME_DB, {
      reportType,
      did,
      periodKey,
      payloadJson,
      csvBody: built.csvBody ?? null,
      payloadHashB64u,
      sourceRefsJson: built.sourceRefs ? JSON.stringify(built.sourceRefs) : null,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (!message.includes('UNIQUE')) {
      throw new IncomeError('Failed to insert report snapshot', 'DB_WRITE_FAILED', 500, {
        report_type: reportType,
        did,
        period_key: periodKey,
      });
    }
  }

  const reloaded = await getReportSnapshot(env.INCOME_DB, reportType, did, periodKey);
  if (!reloaded) {
    throw new IncomeError('Failed to load report snapshot', 'DB_READ_FAILED', 500, {
      report_type: reportType,
      did,
      period_key: periodKey,
    });
  }

  let payload: unknown;
  try {
    payload = JSON.parse(reloaded.payload_json);
  } catch {
    throw new IncomeError('Stored snapshot payload is invalid JSON', 'DB_CORRUPT', 500, {
      snapshot_id: reloaded.snapshot_id,
    });
  }

  return {
    snapshot: reloaded,
    payload: payload as T,
  };
}

function buildMonthlyStatementResponse(payload: StatementPayload, snapshot: ReportSnapshotRow) {
  return {
    ...payload,
    snapshot: {
      id: snapshot.snapshot_id,
      report_type: snapshot.report_type,
      did: snapshot.did,
      period_key: snapshot.period_key,
      hash_b64u: snapshot.payload_hash_b64u,
      created_at: snapshot.created_at,
    },
  };
}

function buildInvoicesResponse(payload: InvoicesPayload, snapshot: ReportSnapshotRow) {
  return {
    ...payload,
    snapshot: {
      id: snapshot.snapshot_id,
      report_type: snapshot.report_type,
      did: snapshot.did,
      period_key: snapshot.period_key,
      hash_b64u: snapshot.payload_hash_b64u,
      created_at: snapshot.created_at,
    },
  };
}

function buildTaxLotsResponse(payload: TaxLotsPayload, snapshot: ReportSnapshotRow) {
  return {
    ...payload,
    snapshot: {
      id: snapshot.snapshot_id,
      report_type: snapshot.report_type,
      did: snapshot.did,
      period_key: snapshot.period_key,
      hash_b64u: snapshot.payload_hash_b64u,
      created_at: snapshot.created_at,
    },
  };
}

async function handleMonthlyStatementJson(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const did = url.searchParams.get('did');
  const monthRaw = url.searchParams.get('month');

  if (!isNonEmptyString(did)) {
    throw new IncomeError('did query parameter is required', 'INVALID_REQUEST', 400, { field: 'did' });
  }

  const normalizedDid = did.trim();
  const month = parseMonth(monthRaw);

  let viewer: ViewerContext;
  try {
    viewer = await authorize(request, normalizedDid, '/v1/statements/monthly', env);
  } catch (err) {
    if (err instanceof IncomeError) {
      await ensureAccessAudit(env.INCOME_DB, {
        endpoint: '/v1/statements/monthly',
        requested_did: normalizedDid,
        actor_did: null,
        is_admin: false,
        outcome: 'denied',
        details: {
          code: err.code,
          reason: err.message,
        },
      });
      throw err;
    }
    throw err;
  }

  await ensureAccessAudit(env.INCOME_DB, {
    endpoint: '/v1/statements/monthly',
    requested_did: normalizedDid,
    actor_did: viewer.actor_did,
    is_admin: viewer.is_admin,
    outcome: 'allowed',
  });

  const { startIso, endIso } = monthRange(month);

  const snapshotResult = await getOrCreateReportSnapshot<StatementPayload>(
    env,
    'monthly_statement_json',
    normalizedDid,
    month,
    async () => {
      const context = await buildFinancialContext(normalizedDid, month, startIso, endIso, env);
      const payload = buildStatementPayload(context);
      return {
        payload,
        hashSource: stableStringify(payload),
        sourceRefs: payload.source_refs,
      };
    }
  );

  return jsonResponse(buildMonthlyStatementResponse(snapshotResult.payload, snapshotResult.snapshot), 200, env.INCOME_VERSION);
}

async function handleMonthlyStatementCsv(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const did = url.searchParams.get('did');
  const monthRaw = url.searchParams.get('month');

  if (!isNonEmptyString(did)) {
    throw new IncomeError('did query parameter is required', 'INVALID_REQUEST', 400, { field: 'did' });
  }

  const normalizedDid = did.trim();
  const month = parseMonth(monthRaw);

  let viewer: ViewerContext;
  try {
    viewer = await authorize(request, normalizedDid, '/v1/statements/monthly.csv', env);
  } catch (err) {
    if (err instanceof IncomeError) {
      await ensureAccessAudit(env.INCOME_DB, {
        endpoint: '/v1/statements/monthly.csv',
        requested_did: normalizedDid,
        actor_did: null,
        is_admin: false,
        outcome: 'denied',
        details: {
          code: err.code,
          reason: err.message,
        },
      });
      throw err;
    }
    throw err;
  }

  await ensureAccessAudit(env.INCOME_DB, {
    endpoint: '/v1/statements/monthly.csv',
    requested_did: normalizedDid,
    actor_did: viewer.actor_did,
    is_admin: viewer.is_admin,
    outcome: 'allowed',
  });

  // Ensure JSON snapshot exists first so CSV and JSON stay finance-identical.
  const { startIso, endIso } = monthRange(month);
  const statementSnapshot = await getOrCreateReportSnapshot<StatementPayload>(
    env,
    'monthly_statement_json',
    normalizedDid,
    month,
    async () => {
      const context = await buildFinancialContext(normalizedDid, month, startIso, endIso, env);
      const payload = buildStatementPayload(context);
      return {
        payload,
        hashSource: stableStringify(payload),
        sourceRefs: payload.source_refs,
      };
    }
  );

  const csvSnapshot = await getOrCreateReportSnapshot<{ did: string; month: string }>(
    env,
    'monthly_statement_csv',
    normalizedDid,
    month,
    async () => {
      const csv = statementToCsv(statementSnapshot.payload);
      return {
        payload: {
          did: normalizedDid,
          month,
        },
        csvBody: csv,
        hashSource: csv,
        sourceRefs: statementSnapshot.payload.source_refs,
      };
    }
  );

  const csvBody = csvSnapshot.snapshot.csv_body;
  if (!csvBody) {
    throw new IncomeError('CSV snapshot is missing csv_body', 'DB_CORRUPT', 500, {
      snapshot_id: csvSnapshot.snapshot.snapshot_id,
    });
  }

  return textResponse(csvBody, 'text/csv; charset=utf-8', 200, env.INCOME_VERSION, {
    'x-clawincome-snapshot-id': csvSnapshot.snapshot.snapshot_id,
    'x-clawincome-snapshot-hash': csvSnapshot.snapshot.payload_hash_b64u,
    'x-clawincome-source-snapshot-id': statementSnapshot.snapshot.snapshot_id,
    'x-clawincome-source-snapshot-hash': statementSnapshot.snapshot.payload_hash_b64u,
  });
}

async function handleInvoices(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const did = url.searchParams.get('did');
  const monthRaw = url.searchParams.get('month');

  if (!isNonEmptyString(did)) {
    throw new IncomeError('did query parameter is required', 'INVALID_REQUEST', 400, { field: 'did' });
  }

  const normalizedDid = did.trim();
  const month = parseMonth(monthRaw);

  let viewer: ViewerContext;
  try {
    viewer = await authorize(request, normalizedDid, '/v1/invoices', env);
  } catch (err) {
    if (err instanceof IncomeError) {
      await ensureAccessAudit(env.INCOME_DB, {
        endpoint: '/v1/invoices',
        requested_did: normalizedDid,
        actor_did: null,
        is_admin: false,
        outcome: 'denied',
        details: {
          code: err.code,
          reason: err.message,
        },
      });
      throw err;
    }
    throw err;
  }

  await ensureAccessAudit(env.INCOME_DB, {
    endpoint: '/v1/invoices',
    requested_did: normalizedDid,
    actor_did: viewer.actor_did,
    is_admin: viewer.is_admin,
    outcome: 'allowed',
  });

  const { startIso, endIso } = monthRange(month);

  const snapshotResult = await getOrCreateReportSnapshot<InvoicesPayload>(
    env,
    'invoices_json',
    normalizedDid,
    month,
    async () => {
      const context = await buildFinancialContext(normalizedDid, month, startIso, endIso, env);
      const payload = await buildInvoicesPayload(context);
      return {
        payload,
        hashSource: stableStringify(payload),
        sourceRefs: payload.source_refs,
      };
    }
  );

  return jsonResponse(buildInvoicesResponse(snapshotResult.payload, snapshotResult.snapshot), 200, env.INCOME_VERSION);
}

async function handleTaxLots(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const did = url.searchParams.get('did');
  const yearRaw = url.searchParams.get('year');

  if (!isNonEmptyString(did)) {
    throw new IncomeError('did query parameter is required', 'INVALID_REQUEST', 400, { field: 'did' });
  }

  const normalizedDid = did.trim();
  const year = parseYear(yearRaw);

  let viewer: ViewerContext;
  try {
    viewer = await authorize(request, normalizedDid, '/v1/tax-lots', env);
  } catch (err) {
    if (err instanceof IncomeError) {
      await ensureAccessAudit(env.INCOME_DB, {
        endpoint: '/v1/tax-lots',
        requested_did: normalizedDid,
        actor_did: null,
        is_admin: false,
        outcome: 'denied',
        details: {
          code: err.code,
          reason: err.message,
        },
      });
      throw err;
    }
    throw err;
  }

  await ensureAccessAudit(env.INCOME_DB, {
    endpoint: '/v1/tax-lots',
    requested_did: normalizedDid,
    actor_did: viewer.actor_did,
    is_admin: viewer.is_admin,
    outcome: 'allowed',
  });

  const snapshotResult = await getOrCreateReportSnapshot<TaxLotsPayload>(
    env,
    'tax_lots_json',
    normalizedDid,
    year,
    async () => {
      const payload = await buildTaxLotsPayload(normalizedDid, year, env);
      return {
        payload,
        hashSource: stableStringify(payload),
        sourceRefs: payload.source_refs,
      };
    }
  );

  return jsonResponse(buildTaxLotsResponse(snapshotResult.payload, snapshotResult.snapshot), 200, env.INCOME_VERSION);
}

async function handleIncomeTimeline(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const did = url.searchParams.get('did');
  const fromRaw = url.searchParams.get('from');
  const toRaw = url.searchParams.get('to');

  if (!isNonEmptyString(did)) {
    throw new IncomeError('did query parameter is required', 'INVALID_REQUEST', 400, { field: 'did' });
  }
  if (!isNonEmptyString(fromRaw)) {
    throw new IncomeError('from query parameter is required', 'INVALID_REQUEST', 400, { field: 'from' });
  }
  if (!isNonEmptyString(toRaw)) {
    throw new IncomeError('to query parameter is required', 'INVALID_REQUEST', 400, { field: 'to' });
  }

  const normalizedDid = did.trim();
  const fromIso = parseIsoTimestamp(fromRaw.trim(), 'from');
  const toIso = parseIsoTimestamp(toRaw.trim(), 'to');

  if (fromIso >= toIso) {
    throw new IncomeError('from must be strictly before to', 'INVALID_REQUEST', 400, {
      from: fromIso,
      to: toIso,
    });
  }

  const limit = parseLimit(url, 50, 200);
  const cursorRaw = url.searchParams.get('cursor');
  const cursorIndex = decodeCursorIndex(cursorRaw);
  if (cursorRaw && cursorIndex === null) {
    throw new IncomeError('cursor is invalid', 'INVALID_CURSOR', 400, { cursor: cursorRaw });
  }

  let viewer: ViewerContext;
  try {
    viewer = await authorize(request, normalizedDid, '/v1/income', env);
  } catch (err) {
    if (err instanceof IncomeError) {
      await ensureAccessAudit(env.INCOME_DB, {
        endpoint: '/v1/income',
        requested_did: normalizedDid,
        actor_did: null,
        is_admin: false,
        outcome: 'denied',
        details: {
          code: err.code,
          reason: err.message,
        },
      });
      throw err;
    }
    throw err;
  }

  await ensureAccessAudit(env.INCOME_DB, {
    endpoint: '/v1/income',
    requested_did: normalizedDid,
    actor_did: viewer.actor_did,
    is_admin: viewer.is_admin,
    outcome: 'allowed',
  });

  const monthLabel = `${fromIso.slice(0, 7)}..${toIso.slice(0, 7)}`;
  const context = await buildFinancialContext(normalizedDid, monthLabel, fromIso, toIso, env);
  const entries = buildIncomeTimelineEntries(context);

  const startIndex = cursorIndex === null ? 0 : cursorIndex + 1;
  const page = entries.slice(startIndex, startIndex + limit);
  const nextCursor = startIndex + page.length < entries.length ? encodeCursorIndex(startIndex + page.length - 1) : undefined;

  return jsonResponse(
    {
      did: normalizedDid,
      from: fromIso,
      to: toIso,
      currency: 'USD',
      items: page,
      page_info: {
        limit,
        returned: page.length,
        next_cursor: nextCursor,
      },
      source_refs: {
        escrow_count: context.escrows.length,
        cuts_apply_count: context.cuts_apply_by_escrow.size,
        payout_count: context.payouts.length,
        payout_settlement_count: context.payout_settlements.length,
      },
    },
    200,
    env.INCOME_VERSION
  );
}

function renderLanding(origin: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawincome</title>
  </head>
  <body>
    <main style="max-width: 900px; margin: 2rem auto; font-family: system-ui, sans-serif; line-height: 1.5;">
      <h1>clawincome</h1>
      <p>Income statements, invoices, and finance reporting APIs.</p>
      <ul>
        <li><code>GET /health</code></li>
        <li><code>GET /v1/statements/monthly?did=...&amp;month=YYYY-MM</code></li>
        <li><code>GET /v1/statements/monthly.csv?did=...&amp;month=YYYY-MM</code></li>
        <li><code>GET /v1/invoices?did=...&amp;month=YYYY-MM</code></li>
        <li><code>GET /v1/tax-lots?did=...&amp;year=YYYY</code></li>
        <li><code>GET /v1/income?did=...&amp;from=ISO&amp;to=ISO&amp;cursor=...</code></li>
        <li><code>POST /v1/risk/adjustments</code> (risk service key)</li>
      </ul>
      <p><a href="${origin}/skill.md">skill.md</a></p>
    </main>
  </body>
</html>`;
}

function renderSkill(origin: string): string {
  const metadata = {
    name: 'clawincome',
    version: '1',
    description: 'Income statements, invoices, tax lots, and timeline APIs.',
    endpoints: [
      { method: 'GET', path: '/health' },
      { method: 'GET', path: '/v1/statements/monthly' },
      { method: 'GET', path: '/v1/statements/monthly.csv' },
      { method: 'GET', path: '/v1/invoices' },
      { method: 'GET', path: '/v1/tax-lots' },
      { method: 'GET', path: '/v1/income' },
      { method: 'POST', path: '/v1/risk/adjustments' },
    ],
  };

  return `---\nmetadata: '${JSON.stringify(metadata)}'\n---\n\n# clawincome\n\nEndpoints:\n- GET /health\n- GET /v1/statements/monthly\n- GET /v1/statements/monthly.csv\n- GET /v1/invoices\n- GET /v1/tax-lots\n- GET /v1/income\n- POST /v1/risk/adjustments (risk service key)\n\nExample:\n\n\`\`\`bash\ncurl -sS \\\n  -H 'authorization: Bearer <token>' \\\n  "${origin}/v1/statements/monthly?did=did:key:z...&month=2026-02"\n\`\`\`\n`;
}

async function router(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();

  const version = env.INCOME_VERSION?.trim() || '0.1.0';

  if (method === 'GET' && path === '/health') {
    return jsonResponse({ status: 'ok', service: 'clawincome', version }, 200, version);
  }

  if (method === 'GET' && path === '/') {
    return textResponse(renderLanding(url.origin), 'text/html; charset=utf-8', 200, version);
  }

  if (method === 'GET' && path === '/skill.md') {
    return textResponse(renderSkill(url.origin), 'text/markdown; charset=utf-8', 200, version);
  }

  if (method === 'GET' && path === '/v1/statements/monthly') {
    return handleMonthlyStatementJson(request, env);
  }

  if (method === 'GET' && path === '/v1/statements/monthly.csv') {
    return handleMonthlyStatementCsv(request, env);
  }

  if (method === 'GET' && path === '/v1/invoices') {
    return handleInvoices(request, env);
  }

  if (method === 'GET' && path === '/v1/tax-lots') {
    return handleTaxLots(request, env);
  }

  if (method === 'GET' && path === '/v1/income') {
    return handleIncomeTimeline(request, env);
  }

  if (method === 'POST' && path === '/v1/risk/adjustments') {
    return handleRiskAdjustment(request, env, version);
  }

  throw new IncomeError('Not found', 'NOT_FOUND', 404);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await router(request, env);
    } catch (err) {
      if (err instanceof IncomeError) {
        return errorResponse(err, env.INCOME_VERSION);
      }

      const message = err instanceof Error ? err.message : String(err);
      return errorResponse(
        new IncomeError(message || 'Internal error', 'INTERNAL_ERROR', 500),
        env.INCOME_VERSION
      );
    }
  },
};

export const __internals = {
  stableStringify,
  encodeCursorIndex,
  decodeCursorIndex,
  monthRange,
  yearRange,
};
