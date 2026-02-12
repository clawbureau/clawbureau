/**
 * clawescrow.com worker
 *
 * - Public discovery endpoints (landing/docs/skill/robots/sitemap/security/health)
 * - Admin-gated escrow API (Agent Economy MVP)
 */

export interface Env {
  ESCROW_VERSION: string;

  /** Admin key required for all non-public endpoints. Set via `wrangler secret put`. */
  ESCROW_ADMIN_KEY?: string;

  /** Used to call clawledger. Set via `wrangler secret put`. */
  LEDGER_ADMIN_KEY?: string;

  /** Used to call clawcuts fee-apply control plane. Set via `wrangler secret put`. */
  CLAWCUTS_APPLY_KEY?: string;

  /** Defaults to https://clawledger.com (set in wrangler vars). */
  LEDGER_BASE_URL?: string;

  /** Defaults to https://clawcuts.com (set in wrangler vars). */
  CLAWCUTS_BASE_URL?: string;

  /** Defaults to https://clawrep.com (set in wrangler vars). */
  CLAWREP_BASE_URL?: string;

  /** Ingest key used for clawrep loop endpoint. */
  CLAWREP_INGEST_KEY?: string;

  /** Clearing account domain for fee pool transfers (defaults to clawcuts). */
  FEE_CLEARING_DOMAIN?: string;

  /** D1 database binding */
  ESCROW_DB: D1Database;

  /** Optional direct queue producer binding to clawrep events. */
  REP_EVENTS?: Queue;
}

type EscrowStatus = 'held' | 'released' | 'frozen' | 'cancelled';

type FeePayer = 'buyer' | 'worker';
type FeeSplitKind = 'platform' | 'referral';
type LedgerBucket = 'A' | 'H' | 'B' | 'F' | 'P';

interface FeeSplit {
  kind: FeeSplitKind;
  account: string;
  bucket: 'A' | 'F';
  amount_minor: string;
  referrer_did?: string;
  referral_code?: string;
}

interface FeeItem {
  kind: string;
  payer: FeePayer;
  amount_minor: string;
  rate_bps: number;
  min_fee_minor: string;
  floor_applied: boolean;
  base_amount_minor?: string;
  discount_bps_applied?: number;
  discount_minor?: string;
  splits?: FeeSplit[];
}

interface FeeQuoteSnapshot {
  policy_id: string;
  policy_version: string;
  policy_hash_b64u: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  fees: FeeItem[];
}

interface CreateEscrowResponseBody {
  escrow_id: string;
  status: 'held';
  held_amount_minor: string;
  dispute_window_ends_at: string;
  ledger_refs: {
    hold_transfer: string;
  };
}

interface AssignEscrowResponseBody {
  escrow_id: string;
  status: EscrowStatus;
  worker_did: string;
}

interface ReleaseEscrowResponseBody {
  escrow_id: string;
  status: 'released';
  ledger_refs: {
    worker_transfer: string;
    fee_transfers: string[];
    referral_transfers: string[];
  };
}

interface DisputeEscrowResponseBody {
  escrow_id: string;
  status: 'frozen';
  dispute_window_ends_at: string;
}

interface EscrowRecord {
  escrow_id: string;
  create_idempotency_key: string;
  buyer_did: string;
  worker_did: string | null;
  currency: 'USD';
  amount_minor: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  fee_quote: FeeQuoteSnapshot;
  metadata: Record<string, unknown> | null;
  status: EscrowStatus;
  created_at: string;
  updated_at: string;
  held_at: string;
  released_at: string | null;
  dispute_window_seconds: number;
  dispute_window_ends_at: string;
  ledger_hold_event_id: string;
  ledger_worker_event_id: string | null;
  ledger_fee_event_ids: string[];
  ledger_referral_event_ids: string[];
  assign_idempotency_key: string | null;
  release_idempotency_key: string | null;
  dispute_idempotency_key: string | null;
  verification: Record<string, unknown> | null;
  dispute: Record<string, unknown> | null;
}

function jsonResponse(body: unknown, status = 200, version?: string): Response {
  const headers = new Headers();
  headers.set('content-type', 'application/json; charset=utf-8');
  if (version) headers.set('X-Escrow-Version', version);
  return new Response(JSON.stringify(body, null, 2), { status, headers });
}

function textResponse(body: string, contentType: string, status = 200, version?: string): Response {
  const headers = new Headers();
  headers.set('content-type', contentType);
  headers.set('cache-control', 'public, max-age=300');
  if (version) headers.set('X-Escrow-Version', version);
  return new Response(body, { status, headers });
}

function htmlResponse(body: string, status = 200, version?: string): Response {
  return textResponse(body, 'text/html; charset=utf-8', status, version);
}

function errorResponse(code: string, message: string, status = 400, details?: Record<string, unknown>, version?: string): Response {
  return jsonResponse({ error: code, message, details }, status, version);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function parsePositiveMinor(input: unknown): bigint | null {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  if (!/^[0-9]+$/.test(s)) return null;
  try {
    const n = BigInt(s);
    if (n <= 0n) return null;
    return n;
  } catch {
    return null;
  }
}

function parseNonNegativeMinor(input: unknown): bigint | null {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  if (!/^[0-9]+$/.test(s)) return null;
  try {
    const n = BigInt(s);
    if (n < 0n) return null;
    return n;
  } catch {
    return null;
  }
}

function nowIso(): string {
  return new Date().toISOString();
}

function addSeconds(iso: string, seconds: number): string {
  const base = new Date(iso);
  return new Date(base.getTime() + seconds * 1000).toISOString();
}

function getBearerToken(header: string | null): string | null {
  if (!header) return null;
  const trimmed = header.trim();
  if (!trimmed) return null;
  if (trimmed.toLowerCase().startsWith('bearer ')) return trimmed.slice(7).trim();
  return trimmed;
}

function getAdminToken(request: Request): string | null {
  const bearer = getBearerToken(request.headers.get('authorization'));
  if (bearer) return bearer;
  const headerKey = request.headers.get('x-admin-key');
  if (headerKey && headerKey.trim().length > 0) return headerKey.trim();
  return null;
}

function requireAdmin(request: Request, env: Env, version: string): Response | null {
  if (!env.ESCROW_ADMIN_KEY || env.ESCROW_ADMIN_KEY.trim().length === 0) {
    return errorResponse('ADMIN_KEY_NOT_CONFIGURED', 'ESCROW_ADMIN_KEY is not configured', 503, undefined, version);
  }

  const token = getAdminToken(request);
  if (!token) {
    return errorResponse('UNAUTHORIZED', 'Missing admin token', 401, undefined, version);
  }

  if (token !== env.ESCROW_ADMIN_KEY) {
    return errorResponse('UNAUTHORIZED', 'Invalid admin token', 401, undefined, version);
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

function safeJsonParse<T>(input: string | null): T | null {
  if (!input) return null;
  try {
    return JSON.parse(input) as T;
  } catch {
    return null;
  }
}

function resolveLedgerBaseUrl(env: Env): string {
  const base = env.LEDGER_BASE_URL?.trim();
  if (base && base.length > 0) return base;
  return 'https://clawledger.com';
}

function resolveClawcutsBaseUrl(env: Env): string {
  const base = env.CLAWCUTS_BASE_URL?.trim();
  if (base && base.length > 0) return base;
  return 'https://clawcuts.com';
}

function resolveClawrepBaseUrl(env: Env): string {
  const base = env.CLAWREP_BASE_URL?.trim();
  if (base && base.length > 0) return base;
  return 'https://clawrep.com';
}

type ClawrepLoopEnvelope = {
  schema_version: '1';
  source_event_id: string;
  source_service: 'escrow';
  kind: 'closure' | 'penalty';
  did: string;
  occurred_at: string;
  closure?: {
    value_usd: number;
    closure_type: 'auto_approve' | 'quorum_approve' | 'manual_approve' | 'dispute_resolved';
    proof_tier: 'unknown' | 'self' | 'gateway' | 'sandbox' | 'tee' | 'witnessed_web';
    owner_verified?: boolean;
  };
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
  metadata?: Record<string, unknown>;
};

function minorToUsd(minor: string): number {
  const parsed = parseNonNegativeMinor(minor);
  if (parsed === null) return 0;
  const major = Number(parsed / 100n);
  const cents = Number(parsed % 100n);
  return major + cents / 100;
}

async function emitEscrowOutcomeToClawrep(env: Env, envelope: ClawrepLoopEnvelope): Promise<void> {
  try {
    if (env.REP_EVENTS) {
      await env.REP_EVENTS.send(envelope, { contentType: 'json' });
      return;
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[clawescrow] clawrep queue send failed source_event_id=${envelope.source_event_id}: ${message}`);
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
        `[clawescrow] clawrep ingest-loop failed status=${response.status} source_event_id=${envelope.source_event_id} body=${text.slice(0, 240)}`
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[clawescrow] clawrep ingest-loop error source_event_id=${envelope.source_event_id}: ${message}`);
  } finally {
    clearTimeout(timeout);
  }
}

interface CutsApplyTransfer {
  transfer_index: number;
  fee_index: number;
  fee_kind: string;
  payer: FeePayer;
  split_kind: FeeSplitKind;
  to_account: string;
  to_bucket: 'A' | 'F';
  amount_minor: string;
  referrer_did?: string;
  referral_code?: string;
}

interface CutsApplyResponse {
  apply_id: string;
  idempotency_key: string;
  fee_summary: {
    total_fee_minor: string;
    referral_payout_minor: string;
    platform_retained_minor: string;
    buyer_total_minor: string;
    worker_net_minor: string;
  };
  transfer_plan: {
    transfers: CutsApplyTransfer[];
  };
}

async function clawcutsApplyFees(
  env: Env,
  params: {
    idempotency_key: string;
    product: string;
    settlement_ref: string;
    occurred_at: string;
    snapshot: FeeQuoteSnapshot;
    context: Record<string, unknown>;
  }
): Promise<CutsApplyResponse> {
  if (!env.CLAWCUTS_APPLY_KEY || env.CLAWCUTS_APPLY_KEY.trim().length === 0) {
    throw new Error('CLAWCUTS_APPLY_KEY_NOT_CONFIGURED');
  }

  const url = `${resolveClawcutsBaseUrl(env)}/v1/fees/apply`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${env.CLAWCUTS_APPLY_KEY.trim()}`,
    },
    body: JSON.stringify({
      idempotency_key: params.idempotency_key,
      product: params.product,
      currency: 'USD',
      settlement_ref: params.settlement_ref,
      occurred_at: params.occurred_at,
      snapshot: params.snapshot,
      context: params.context,
    }),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`CUTS_APPLY_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isRecord(json.fee_summary) || !isRecord(json.transfer_plan)) {
    throw new Error('CUTS_APPLY_INVALID_RESPONSE');
  }

  if (!isNonEmptyString(json.apply_id) || !isNonEmptyString(json.idempotency_key)) {
    throw new Error('CUTS_APPLY_INVALID_RESPONSE');
  }

  const summary = json.fee_summary;
  if (
    !isNonEmptyString(summary.total_fee_minor) ||
    !isNonEmptyString(summary.referral_payout_minor) ||
    !isNonEmptyString(summary.platform_retained_minor) ||
    !isNonEmptyString(summary.buyer_total_minor) ||
    !isNonEmptyString(summary.worker_net_minor)
  ) {
    throw new Error('CUTS_APPLY_INVALID_RESPONSE');
  }

  const transferPlan = json.transfer_plan;
  if (!Array.isArray(transferPlan.transfers)) {
    throw new Error('CUTS_APPLY_INVALID_RESPONSE');
  }

  const transfers: CutsApplyTransfer[] = [];
  for (const transferRaw of transferPlan.transfers) {
    if (!isRecord(transferRaw)) throw new Error('CUTS_APPLY_INVALID_RESPONSE');
    if (typeof transferRaw.transfer_index !== 'number' || !Number.isInteger(transferRaw.transfer_index) || transferRaw.transfer_index < 0) {
      throw new Error('CUTS_APPLY_INVALID_RESPONSE');
    }
    if (typeof transferRaw.fee_index !== 'number' || !Number.isInteger(transferRaw.fee_index) || transferRaw.fee_index < 0) {
      throw new Error('CUTS_APPLY_INVALID_RESPONSE');
    }
    if (!isNonEmptyString(transferRaw.fee_kind)) throw new Error('CUTS_APPLY_INVALID_RESPONSE');
    if (transferRaw.payer !== 'buyer' && transferRaw.payer !== 'worker') throw new Error('CUTS_APPLY_INVALID_RESPONSE');
    if (transferRaw.split_kind !== 'platform' && transferRaw.split_kind !== 'referral') throw new Error('CUTS_APPLY_INVALID_RESPONSE');
    if (!isNonEmptyString(transferRaw.to_account)) throw new Error('CUTS_APPLY_INVALID_RESPONSE');
    if (transferRaw.to_bucket !== 'A' && transferRaw.to_bucket !== 'F') throw new Error('CUTS_APPLY_INVALID_RESPONSE');
    if (!isNonEmptyString(transferRaw.amount_minor) || parseNonNegativeMinor(transferRaw.amount_minor.trim()) === null) {
      throw new Error('CUTS_APPLY_INVALID_RESPONSE');
    }

    const normalized: CutsApplyTransfer = {
      transfer_index: transferRaw.transfer_index,
      fee_index: transferRaw.fee_index,
      fee_kind: transferRaw.fee_kind.trim(),
      payer: transferRaw.payer,
      split_kind: transferRaw.split_kind,
      to_account: transferRaw.to_account.trim(),
      to_bucket: transferRaw.to_bucket,
      amount_minor: transferRaw.amount_minor.trim(),
    };

    if (isNonEmptyString(transferRaw.referrer_did)) {
      normalized.referrer_did = transferRaw.referrer_did.trim();
    }

    if (isNonEmptyString(transferRaw.referral_code)) {
      normalized.referral_code = transferRaw.referral_code.trim();
    }

    transfers.push(normalized);
  }

  return {
    apply_id: json.apply_id.trim(),
    idempotency_key: json.idempotency_key.trim(),
    fee_summary: {
      total_fee_minor: summary.total_fee_minor.trim(),
      referral_payout_minor: summary.referral_payout_minor.trim(),
      platform_retained_minor: summary.platform_retained_minor.trim(),
      buyer_total_minor: summary.buyer_total_minor.trim(),
      worker_net_minor: summary.worker_net_minor.trim(),
    },
    transfer_plan: {
      transfers,
    },
  };
}

async function clawcutsFinalizeFeeApply(
  env: Env,
  params: {
    idempotency_key: string;
    ledger_fee_event_ids: string[];
    ledger_referral_event_ids: string[];
  }
): Promise<void> {
  if (!env.CLAWCUTS_APPLY_KEY || env.CLAWCUTS_APPLY_KEY.trim().length === 0) {
    throw new Error('CLAWCUTS_APPLY_KEY_NOT_CONFIGURED');
  }

  const url = `${resolveClawcutsBaseUrl(env)}/v1/fees/apply/finalize`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${env.CLAWCUTS_APPLY_KEY.trim()}`,
    },
    body: JSON.stringify({
      idempotency_key: params.idempotency_key,
      ledger_fee_event_ids: params.ledger_fee_event_ids,
      ledger_referral_event_ids: params.ledger_referral_event_ids,
    }),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`CUTS_FINALIZE_FAILED:${response.status}:${JSON.stringify(details)}`);
  }
}

async function ledgerV1Transfer(
  env: Env,
  params: {
    idempotency_key: string;
    from: { account: string; bucket: LedgerBucket };
    to: { account: string; bucket: LedgerBucket };
    amount_minor: string;
    metadata?: Record<string, unknown>;
  }
): Promise<{ event_id: string }> {
  if (!env.LEDGER_ADMIN_KEY || env.LEDGER_ADMIN_KEY.trim().length === 0) {
    throw new Error('LEDGER_ADMIN_KEY_NOT_CONFIGURED');
  }

  const url = `${resolveLedgerBaseUrl(env)}/v1/transfers`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-admin-key': env.LEDGER_ADMIN_KEY,
    },
    body: JSON.stringify({
      idempotency_key: params.idempotency_key,
      currency: 'USD',
      from: params.from,
      to: params.to,
      amount_minor: params.amount_minor,
      metadata: params.metadata,
    }),
  });

  const text = await response.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const details = isRecord(json) ? json : { raw: text };
    throw new Error(`LEDGER_TRANSFER_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isNonEmptyString(json.event_id)) {
    throw new Error('LEDGER_TRANSFER_INVALID_RESPONSE');
  }

  return { event_id: json.event_id };
}

function d1String(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return value.toString();
  return null;
}

function d1Number(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number') return value;
  if (typeof value === 'string' && value.trim().length > 0) {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }
  return null;
}

function parseEscrowRow(row: Record<string, unknown>): EscrowRecord | null {
  const escrow_id = d1String(row.escrow_id);
  const create_idempotency_key = d1String(row.create_idempotency_key);
  const buyer_did = d1String(row.buyer_did);
  const currency = d1String(row.currency);
  const amount_minor = d1String(row.amount_minor);
  const buyer_total_minor = d1String(row.buyer_total_minor);
  const worker_net_minor = d1String(row.worker_net_minor);
  const status = d1String(row.status);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);
  const held_at = d1String(row.held_at);
  const dispute_window_ends_at = d1String(row.dispute_window_ends_at);
  const dispute_window_seconds = d1Number(row.dispute_window_seconds);
  const ledger_hold_event_id = d1String(row.ledger_hold_event_id);

  if (
    !escrow_id ||
    !create_idempotency_key ||
    !buyer_did ||
    currency !== 'USD' ||
    !amount_minor ||
    !buyer_total_minor ||
    !worker_net_minor ||
    !status ||
    !created_at ||
    !updated_at ||
    !held_at ||
    dispute_window_seconds === null ||
    !dispute_window_ends_at ||
    !ledger_hold_event_id
  ) {
    return null;
  }

  const fee_quote = safeJsonParse<FeeQuoteSnapshot>(d1String(row.fee_quote_json));
  if (!fee_quote) return null;

  const metadata = safeJsonParse<Record<string, unknown>>(d1String(row.metadata_json));
  const ledger_fee_event_ids = safeJsonParse<string[]>(d1String(row.ledger_fee_event_ids_json)) ?? [];
  const ledger_referral_event_ids = safeJsonParse<string[]>(d1String(row.ledger_referral_event_ids_json)) ?? [];
  const verification = safeJsonParse<Record<string, unknown>>(d1String(row.verification_json));
  const dispute = safeJsonParse<Record<string, unknown>>(d1String(row.dispute_json));

  const statusTyped = status as EscrowStatus;
  if (statusTyped !== 'held' && statusTyped !== 'released' && statusTyped !== 'frozen' && statusTyped !== 'cancelled') {
    return null;
  }

  return {
    escrow_id,
    create_idempotency_key,
    buyer_did,
    worker_did: d1String(row.worker_did),
    currency: 'USD',
    amount_minor,
    buyer_total_minor,
    worker_net_minor,
    fee_quote,
    metadata,
    status: statusTyped,
    created_at,
    updated_at,
    held_at,
    released_at: d1String(row.released_at),
    dispute_window_seconds,
    dispute_window_ends_at,
    ledger_hold_event_id,
    ledger_worker_event_id: d1String(row.ledger_worker_event_id),
    ledger_fee_event_ids,
    ledger_referral_event_ids,
    assign_idempotency_key: d1String(row.assign_idempotency_key),
    release_idempotency_key: d1String(row.release_idempotency_key),
    dispute_idempotency_key: d1String(row.dispute_idempotency_key),
    verification,
    dispute,
  };
}

async function getEscrowById(db: D1Database, escrowId: string): Promise<EscrowRecord | null> {
  const row = await db.prepare('SELECT * FROM escrows WHERE escrow_id = ?').bind(escrowId).first();
  if (!row) return null;
  if (!isRecord(row)) return null;
  return parseEscrowRow(row);
}

async function getEscrowByCreateIdempotencyKey(db: D1Database, key: string): Promise<EscrowRecord | null> {
  const row = await db.prepare('SELECT * FROM escrows WHERE create_idempotency_key = ?').bind(key).first();
  if (!row) return null;
  if (!isRecord(row)) return null;
  return parseEscrowRow(row);
}

function base64urlEncode(input: string): string {
  return btoa(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(input: string): string | null {
  try {
    const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
    return atob(padded);
  } catch {
    return null;
  }
}

function encodeEscrowCursor(releasedAt: string, escrowId: string): string {
  return base64urlEncode(`${releasedAt}::${escrowId}`);
}

function decodeEscrowCursor(cursor: string | null): { released_at: string; escrow_id: string } | null {
  if (!cursor || cursor.trim().length === 0) return null;

  const decoded = base64urlDecode(cursor.trim());
  if (!decoded) return null;

  const [releasedAt, escrowId] = decoded.split('::');
  if (!releasedAt || !escrowId) return null;

  const releasedAtIso = new Date(releasedAt);
  if (!Number.isFinite(releasedAtIso.getTime())) return null;
  if (!escrowId.startsWith('esc_')) return null;

  return {
    released_at: releasedAtIso.toISOString(),
    escrow_id: escrowId,
  };
}

async function listEscrows(
  db: D1Database,
  params: {
    did?: string;
    buyer_did?: string;
    worker_did?: string;
    status?: EscrowStatus;
    from?: string;
    to?: string;
    cursor?: { released_at: string; escrow_id: string };
    limit: number;
  }
): Promise<{ escrows: EscrowRecord[]; next_cursor?: string }> {
  const where: string[] = [];
  const binds: Array<string | number | null> = [];

  if (params.did) {
    where.push('(buyer_did = ? OR worker_did = ?)');
    binds.push(params.did, params.did);
  }

  if (params.buyer_did) {
    where.push('buyer_did = ?');
    binds.push(params.buyer_did);
  }

  if (params.worker_did) {
    where.push('worker_did = ?');
    binds.push(params.worker_did);
  }

  if (params.status) {
    where.push('status = ?');
    binds.push(params.status);
  }

  if (params.from) {
    where.push('released_at IS NOT NULL');
    where.push('released_at >= ?');
    binds.push(params.from);
  }

  if (params.to) {
    where.push('released_at IS NOT NULL');
    where.push('released_at < ?');
    binds.push(params.to);
  }

  if (params.cursor) {
    where.push('released_at IS NOT NULL');
    where.push('(released_at > ? OR (released_at = ? AND escrow_id > ?))');
    binds.push(params.cursor.released_at, params.cursor.released_at, params.cursor.escrow_id);
  }

  const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

  const result = await db
    .prepare(
      `SELECT *
       FROM escrows
       ${whereSql}
       ORDER BY COALESCE(released_at, created_at) ASC, escrow_id ASC
       LIMIT ?`
    )
    .bind(...binds, params.limit + 1)
    .all();

  const rows = Array.isArray(result.results) ? result.results : [];
  const parsed: EscrowRecord[] = [];
  for (const row of rows) {
    if (!isRecord(row)) continue;
    const escrow = parseEscrowRow(row);
    if (escrow) parsed.push(escrow);
  }

  const hasMore = parsed.length > params.limit;
  const page = hasMore ? parsed.slice(0, params.limit) : parsed;

  let nextCursor: string | undefined;
  if (hasMore) {
    const last = page[page.length - 1];
    if (last && last.released_at) {
      nextCursor = encodeEscrowCursor(last.released_at, last.escrow_id);
    }
  }

  return {
    escrows: page,
    ...(nextCursor ? { next_cursor: nextCursor } : {}),
  };
}

async function insertEscrow(db: D1Database, record: EscrowRecord): Promise<void> {
  await db
    .prepare(
      `INSERT INTO escrows (
        escrow_id,
        create_idempotency_key,
        buyer_did,
        worker_did,
        currency,
        amount_minor,
        buyer_total_minor,
        worker_net_minor,
        fee_quote_json,
        metadata_json,
        status,
        created_at,
        updated_at,
        held_at,
        released_at,
        dispute_window_seconds,
        dispute_window_ends_at,
        ledger_hold_event_id,
        ledger_worker_event_id,
        ledger_fee_event_ids_json,
        ledger_referral_event_ids_json,
        assign_idempotency_key,
        release_idempotency_key,
        dispute_idempotency_key,
        verification_json,
        dispute_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      record.escrow_id,
      record.create_idempotency_key,
      record.buyer_did,
      record.worker_did,
      record.currency,
      record.amount_minor,
      record.buyer_total_minor,
      record.worker_net_minor,
      JSON.stringify(record.fee_quote),
      record.metadata ? JSON.stringify(record.metadata) : null,
      record.status,
      record.created_at,
      record.updated_at,
      record.held_at,
      record.released_at,
      record.dispute_window_seconds,
      record.dispute_window_ends_at,
      record.ledger_hold_event_id,
      record.ledger_worker_event_id,
      JSON.stringify(record.ledger_fee_event_ids),
      JSON.stringify(record.ledger_referral_event_ids),
      record.assign_idempotency_key,
      record.release_idempotency_key,
      record.dispute_idempotency_key,
      record.verification ? JSON.stringify(record.verification) : null,
      record.dispute ? JSON.stringify(record.dispute) : null
    )
    .run();
}

async function updateEscrowAssign(db: D1Database, escrowId: string, workerDid: string, idempotencyKey: string, now: string): Promise<void> {
  await db
    .prepare(
      `UPDATE escrows
       SET worker_did = ?, assign_idempotency_key = ?, updated_at = ?
       WHERE escrow_id = ?`
    )
    .bind(workerDid, idempotencyKey, now, escrowId)
    .run();
}

async function tryLockRelease(db: D1Database, escrowId: string, idempotencyKey: string, now: string): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE escrows
       SET release_idempotency_key = ?, updated_at = ?
       WHERE escrow_id = ? AND status = 'held' AND release_idempotency_key IS NULL`
    )
    .bind(idempotencyKey, now, escrowId)
    .run();

  return (result.meta.changes ?? 0) > 0;
}

async function updateEscrowReleased(
  db: D1Database,
  escrowId: string,
  releasedAt: string,
  workerEventId: string,
  feeEventIds: string[],
  referralEventIds: string[],
  verification: Record<string, unknown> | null
): Promise<void> {
  await db
    .prepare(
      `UPDATE escrows
       SET status = 'released', released_at = ?, updated_at = ?, ledger_worker_event_id = ?, ledger_fee_event_ids_json = ?, ledger_referral_event_ids_json = ?, verification_json = ?
       WHERE escrow_id = ?`
    )
    .bind(
      releasedAt,
      releasedAt,
      workerEventId,
      JSON.stringify(feeEventIds),
      JSON.stringify(referralEventIds),
      verification ? JSON.stringify(verification) : null,
      escrowId
    )
    .run();
}

async function tryLockDispute(db: D1Database, escrowId: string, idempotencyKey: string, now: string): Promise<boolean> {
  const result = await db
    .prepare(
      `UPDATE escrows
       SET dispute_idempotency_key = ?, updated_at = ?
       WHERE escrow_id = ? AND status = 'held' AND dispute_idempotency_key IS NULL`
    )
    .bind(idempotencyKey, now, escrowId)
    .run();

  return (result.meta.changes ?? 0) > 0;
}

async function updateEscrowDisputed(
  db: D1Database,
  escrowId: string,
  now: string,
  dispute: Record<string, unknown>
): Promise<void> {
  await db
    .prepare(
      `UPDATE escrows
       SET status = 'frozen', dispute_json = ?, updated_at = ?
       WHERE escrow_id = ?`
    )
    .bind(JSON.stringify(dispute), now, escrowId)
    .run();
}

function landingPage(origin: string, version: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>clawescrow.com — Escrow</title>
</head>
<body>
  <main style="max-width: 780px; margin: 40px auto; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; line-height: 1.5; padding: 0 16px;">
    <h1>clawescrow.com</h1>
    <p>Escrow holds/releases for agent work (Agent Economy MVP).</p>

    <h2>Developer</h2>
    <ul>
      <li><a href="${origin}/docs">Docs</a></li>
      <li><a href="${origin}/skill.md">OpenClaw Skill</a></li>
      <li><a href="${origin}/health">Health</a></li>
    </ul>

    <p><small>Version: ${version}</small></p>

    <h2>Security</h2>
    <ul>
      <li><a href="${origin}/.well-known/security.txt">security.txt</a></li>
    </ul>
  </main>
</body>
</html>`;
}

function docsPage(origin: string): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>clawescrow.com — Docs</title>
</head>
<body>
  <main style="max-width: 900px; margin: 40px auto; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; line-height: 1.5; padding: 0 16px;">
    <h1>clawescrow.com — Docs</h1>
    <p><a href="${origin}/">← Home</a></p>

    <h2>Purpose</h2>
    <p>
      clawescrow holds buyer funds (A→H) and releases them (H→A) based on marketplace flows.
      It is typically used by <code>clawbounties</code>.
    </p>

    <h2>Public endpoints</h2>
    <ul>
      <li><code>GET /</code></li>
      <li><code>GET /docs</code></li>
      <li><code>GET /skill.md</code></li>
      <li><code>GET /health</code></li>
      <li><code>GET /robots.txt</code></li>
      <li><code>GET /sitemap.xml</code></li>
      <li><code>GET /.well-known/security.txt</code></li>
    </ul>

    <h2>Escrow API (admin)</h2>
    <p>
      All <code>/v1/*</code> endpoints require <code>Authorization: Bearer &lt;ESCROW_ADMIN_KEY&gt;</code>.
    </p>
    <ul>
      <li><code>POST /v1/escrows</code> — create escrow hold (calls clawledger /v1/transfers A→H)</li>
      <li><code>GET /v1/escrows</code> — list/filter escrows (admin, cursor pagination)</li>
      <li><code>POST /v1/escrows/{escrow_id}/assign</code> — set worker DID</li>
      <li><code>POST /v1/escrows/{escrow_id}/release</code> — release to worker + fee pool (calls clawledger /v1/transfers)</li>
      <li><code>POST /v1/escrows/{escrow_id}/dispute</code> — freeze within dispute window</li>
      <li><code>GET /v1/escrows/{escrow_id}</code> — fetch escrow record</li>
    </ul>

    <p style="margin-top: 32px; opacity: 0.8;">© Claw Bureau</p>
  </main>
</body>
</html>`;
}

function skillMarkdown(origin: string, version: string): string {
  // OpenClaw requirement: frontmatter metadata must be a single-line JSON object string.
  const metadata = JSON.stringify({
    schema_version: '1',
    id: 'clawescrow',
    name: 'clawescrow.com',
    version,
    base_url: origin,
    endpoints: {
      docs: `${origin}/docs`,
      health: `${origin}/health`,
    },
    capabilities: ['escrow_hold', 'escrow_release', 'disputes', 'status'],
  });

  return `---
name: clawescrow
metadata: '${metadata}'
---

# clawescrow

Escrow holds/releases for agent work.

## Base URL

- ${origin}

## Links

- Docs: ${origin}/docs
- security.txt: ${origin}/.well-known/security.txt
`;
}

function robotsTxt(origin: string): string {
  return `User-agent: *
Allow: /
Sitemap: ${origin}/sitemap.xml
`;
}

function sitemapXml(origin: string): string {
  const urls = [
    `${origin}/`,
    `${origin}/docs`,
    `${origin}/skill.md`,
    `${origin}/health`,
    `${origin}/.well-known/security.txt`,
  ];

  const urlset = urls.map((u) => `  <url><loc>${u}</loc></url>`).join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urlset}
</urlset>
`;
}

function securityTxt(origin: string): string {
  // Minimal, RFC 9116-ish.
  return `Contact: mailto:security@clawbureau.org
Preferred-Languages: en
Canonical: ${origin}/.well-known/security.txt
`;
}

function sumFeesMinor(fees: FeeItem[]): bigint {
  return fees.reduce((acc, fee) => {
    const n = parseNonNegativeMinor(fee.amount_minor);
    if (n === null) return acc;
    return acc + n;
  }, 0n);
}

function validateFeeQuoteSnapshot(snapshot: unknown): FeeQuoteSnapshot | null {
  if (!isRecord(snapshot)) return null;

  const policy_id = snapshot.policy_id;
  const policy_version = snapshot.policy_version;
  const policy_hash_b64u = snapshot.policy_hash_b64u;
  const buyer_total_minor = snapshot.buyer_total_minor;
  const worker_net_minor = snapshot.worker_net_minor;
  const fees = snapshot.fees;

  if (!isNonEmptyString(policy_id)) return null;
  if (!isNonEmptyString(policy_version)) return null;
  if (!isNonEmptyString(policy_hash_b64u)) return null;
  if (parsePositiveMinor(buyer_total_minor) === null) return null;
  if (parseNonNegativeMinor(worker_net_minor) === null) return null;
  if (!Array.isArray(fees)) return null;

  const parsedFees: FeeItem[] = [];
  for (const item of fees) {
    if (!isRecord(item)) return null;
    const kind = item.kind;
    const payer = item.payer;
    const amount_minor = item.amount_minor;
    const rate_bps = item.rate_bps;
    const min_fee_minor = item.min_fee_minor;
    const floor_applied = item.floor_applied;

    if (!isNonEmptyString(kind)) return null;
    if (payer !== 'buyer' && payer !== 'worker') return null;

    if (typeof amount_minor !== 'string') return null;
    const amount_minor_trimmed = amount_minor.trim();
    const amountMinorParsed = parseNonNegativeMinor(amount_minor_trimmed);
    if (amountMinorParsed === null) return null;

    if (typeof rate_bps !== 'number' || !Number.isFinite(rate_bps)) return null;

    if (typeof min_fee_minor !== 'string') return null;
    const min_fee_minor_trimmed = min_fee_minor.trim();
    if (parseNonNegativeMinor(min_fee_minor_trimmed) === null) return null;

    if (typeof floor_applied !== 'boolean') return null;

    const normalized: FeeItem = {
      kind: kind.trim(),
      payer,
      amount_minor: amount_minor_trimmed,
      rate_bps,
      min_fee_minor: min_fee_minor_trimmed,
      floor_applied,
    };

    if (isNonEmptyString(item.base_amount_minor)) {
      const baseAmount = item.base_amount_minor.trim();
      if (parseNonNegativeMinor(baseAmount) === null) return null;
      normalized.base_amount_minor = baseAmount;
    }

    if (item.discount_bps_applied !== undefined) {
      if (typeof item.discount_bps_applied !== 'number' || !Number.isInteger(item.discount_bps_applied)) return null;
      if (item.discount_bps_applied < 0 || item.discount_bps_applied > 10_000) return null;
      normalized.discount_bps_applied = item.discount_bps_applied;
    }

    if (item.discount_minor !== undefined) {
      if (!isNonEmptyString(item.discount_minor)) return null;
      const discountMinor = item.discount_minor.trim();
      if (parseNonNegativeMinor(discountMinor) === null) return null;
      normalized.discount_minor = discountMinor;
    }

    if (item.splits !== undefined) {
      if (!Array.isArray(item.splits)) return null;
      const splits: FeeSplit[] = [];
      let splitTotal = 0n;

      for (const splitRaw of item.splits) {
        if (!isRecord(splitRaw)) return null;
        const splitKind = splitRaw.kind;
        const account = splitRaw.account;
        const bucket = splitRaw.bucket;
        const splitAmountRaw = splitRaw.amount_minor;

        if (splitKind !== 'platform' && splitKind !== 'referral') return null;
        if (!isNonEmptyString(account)) return null;
        if (bucket !== 'A' && bucket !== 'F') return null;
        if (splitKind === 'platform' && bucket !== 'F') return null;
        if (splitKind === 'referral' && bucket !== 'A') return null;

        if (!isNonEmptyString(splitAmountRaw)) return null;
        const splitAmount = splitAmountRaw.trim();
        const splitAmountMinor = parseNonNegativeMinor(splitAmount);
        if (splitAmountMinor === null) return null;

        const referrer_did = isNonEmptyString(splitRaw.referrer_did) ? splitRaw.referrer_did.trim() : undefined;
        const referral_code = isNonEmptyString(splitRaw.referral_code) ? splitRaw.referral_code.trim() : undefined;

        if (splitKind === 'referral') {
          if (!referrer_did || !referrer_did.startsWith('did:')) return null;
        }

        splitTotal += splitAmountMinor;

        const split: FeeSplit = {
          kind: splitKind,
          account: account.trim(),
          bucket,
          amount_minor: splitAmount,
        };

        if (referrer_did) split.referrer_did = referrer_did;
        if (referral_code) split.referral_code = referral_code;

        splits.push(split);
      }

      if (splits.length > 0) {
        if (splitTotal !== amountMinorParsed) return null;
        normalized.splits = splits;
      }
    }

    parsedFees.push(normalized);
  }

  return {
    policy_id: policy_id.trim(),
    policy_version: policy_version.trim(),
    policy_hash_b64u: policy_hash_b64u.trim(),
    buyer_total_minor: (buyer_total_minor as string).trim(),
    worker_net_minor: (worker_net_minor as string).trim(),
    fees: parsedFees,
  };
}

async function handleCreateEscrow(request: Request, env: Env, version: string): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotency_key = bodyRaw.idempotency_key;
  const buyer_did = bodyRaw.buyer_did;
  const worker_did = bodyRaw.worker_did;
  const currency = bodyRaw.currency;
  const amount_minor = bodyRaw.amount_minor;
  const fee_quote = validateFeeQuoteSnapshot(bodyRaw.fee_quote);
  const dispute_window_seconds = bodyRaw.dispute_window_seconds;
  const metadata = bodyRaw.metadata;

  if (!isNonEmptyString(idempotency_key)) {
    return errorResponse('INVALID_REQUEST', 'Missing required field: idempotency_key', 400, undefined, version);
  }
  if (!isNonEmptyString(buyer_did) || !buyer_did.trim().startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'buyer_did must be a DID string', 400, undefined, version);
  }
  if (worker_did !== undefined && worker_did !== null) {
    if (!isNonEmptyString(worker_did) || !worker_did.trim().startsWith('did:')) {
      return errorResponse('INVALID_REQUEST', 'worker_did must be null or a DID string', 400, undefined, version);
    }
  }
  if (!isNonEmptyString(currency) || currency.trim().toUpperCase() !== 'USD') {
    return errorResponse('UNSUPPORTED_CURRENCY', 'Only USD is supported', 400, undefined, version);
  }

  const principal = parsePositiveMinor(amount_minor);
  if (principal === null) {
    return errorResponse('INVALID_REQUEST', 'amount_minor must be a positive integer string', 400, undefined, version);
  }

  if (!fee_quote) {
    return errorResponse('INVALID_REQUEST', 'fee_quote is missing or invalid', 400, undefined, version);
  }

  // Validate fee quote arithmetic (fail-closed).
  const buyerFeeTotal = sumFeesMinor(fee_quote.fees.filter((f) => f.payer === 'buyer'));
  const workerFeeTotal = sumFeesMinor(fee_quote.fees.filter((f) => f.payer === 'worker'));
  const expectedBuyerTotal = principal + buyerFeeTotal;
  const expectedWorkerNet = principal - workerFeeTotal;

  const buyerTotal = parsePositiveMinor(fee_quote.buyer_total_minor);
  const workerNet = parseNonNegativeMinor(fee_quote.worker_net_minor);
  if (buyerTotal === null || workerNet === null) {
    return errorResponse('INVALID_REQUEST', 'fee_quote amounts invalid', 400, undefined, version);
  }

  if (buyerTotal !== expectedBuyerTotal) {
    return errorResponse(
      'FEE_QUOTE_MISMATCH',
      'fee_quote.buyer_total_minor does not match amount_minor + buyer fees',
      400,
      {
        expected_buyer_total_minor: expectedBuyerTotal.toString(),
        received_buyer_total_minor: buyerTotal.toString(),
      },
      version
    );
  }

  if (workerNet !== expectedWorkerNet) {
    return errorResponse(
      'FEE_QUOTE_MISMATCH',
      'fee_quote.worker_net_minor does not match amount_minor - worker fees',
      400,
      {
        expected_worker_net_minor: expectedWorkerNet.toString(),
        received_worker_net_minor: workerNet.toString(),
      },
      version
    );
  }

  const existing = await getEscrowByCreateIdempotencyKey(env.ESCROW_DB, idempotency_key.trim());
  if (existing) {
    const response: CreateEscrowResponseBody = {
      escrow_id: existing.escrow_id,
      status: 'held',
      held_amount_minor: existing.buyer_total_minor,
      dispute_window_ends_at: existing.dispute_window_ends_at,
      ledger_refs: {
        hold_transfer: existing.ledger_hold_event_id,
      },
    };
    return jsonResponse(response, 200, version);
  }

  let disputeWindowSeconds = 86400;
  if (dispute_window_seconds !== undefined) {
    if (typeof dispute_window_seconds !== 'number' || !Number.isFinite(dispute_window_seconds) || dispute_window_seconds <= 0) {
      return errorResponse('INVALID_REQUEST', 'dispute_window_seconds must be a positive number', 400, undefined, version);
    }
    disputeWindowSeconds = Math.floor(dispute_window_seconds);
  }

  if (metadata !== undefined && metadata !== null && !isRecord(metadata)) {
    return errorResponse('INVALID_REQUEST', 'metadata must be an object', 400, undefined, version);
  }

  const createdAt = nowIso();
  const heldAt = createdAt;
  const disputeWindowEndsAt = addSeconds(heldAt, disputeWindowSeconds);

  // 1) Hold funds on ledger (A -> H on buyer).
  let holdEventId: string;
  try {
    const holdResult = await ledgerV1Transfer(env, {
      idempotency_key: `escrow:create:${idempotency_key.trim()}:hold`,
      from: { account: buyer_did.trim(), bucket: 'A' },
      to: { account: buyer_did.trim(), bucket: 'H' },
      amount_minor: fee_quote.buyer_total_minor,
      metadata: {
        kind: 'escrow_hold',
        create_idempotency_key: idempotency_key.trim(),
        buyer_did: buyer_did.trim(),
        policy_id: fee_quote.policy_id,
        policy_version: fee_quote.policy_version,
        policy_hash_b64u: fee_quote.policy_hash_b64u,
      },
    });
    holdEventId = holdResult.event_id;
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('LEDGER_HOLD_FAILED', message, 502, undefined, version);
  }

  // 2) Persist escrow.
  const escrow_id = `esc_${crypto.randomUUID()}`;
  const record: EscrowRecord = {
    escrow_id,
    create_idempotency_key: idempotency_key.trim(),
    buyer_did: buyer_did.trim(),
    worker_did: worker_did === null || worker_did === undefined ? null : worker_did.trim(),
    currency: 'USD',
    amount_minor: principal.toString(),
    buyer_total_minor: buyerTotal.toString(),
    worker_net_minor: workerNet.toString(),
    fee_quote,
    metadata: metadata ? (metadata as Record<string, unknown>) : null,
    status: 'held',
    created_at: createdAt,
    updated_at: createdAt,
    held_at: heldAt,
    released_at: null,
    dispute_window_seconds: disputeWindowSeconds,
    dispute_window_ends_at: disputeWindowEndsAt,
    ledger_hold_event_id: holdEventId,
    ledger_worker_event_id: null,
    ledger_fee_event_ids: [],
    ledger_referral_event_ids: [],
    assign_idempotency_key: null,
    release_idempotency_key: null,
    dispute_idempotency_key: null,
    verification: null,
    dispute: null,
  };

  try {
    await insertEscrow(env.ESCROW_DB, record);
  } catch (err) {
    // If insert failed due to concurrency, try to return the existing record.
    const existingAfter = await getEscrowByCreateIdempotencyKey(env.ESCROW_DB, idempotency_key.trim());
    if (existingAfter) {
      const response: CreateEscrowResponseBody = {
        escrow_id: existingAfter.escrow_id,
        status: 'held',
        held_amount_minor: existingAfter.buyer_total_minor,
        dispute_window_ends_at: existingAfter.dispute_window_ends_at,
        ledger_refs: { hold_transfer: existingAfter.ledger_hold_event_id },
      };
      return jsonResponse(response, 200, version);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const response: CreateEscrowResponseBody = {
    escrow_id,
    status: 'held',
    held_amount_minor: record.buyer_total_minor,
    dispute_window_ends_at: record.dispute_window_ends_at,
    ledger_refs: {
      hold_transfer: record.ledger_hold_event_id,
    },
  };

  return jsonResponse(response, 201, version);
}

async function handleGetEscrow(escrowId: string, env: Env, version: string): Promise<Response> {
  const escrow = await getEscrowById(env.ESCROW_DB, escrowId);
  if (!escrow) {
    return errorResponse('NOT_FOUND', 'Escrow not found', 404, undefined, version);
  }

  return jsonResponse(
    {
      escrow_id: escrow.escrow_id,
      status: escrow.status,
      buyer_did: escrow.buyer_did,
      worker_did: escrow.worker_did,
      currency: escrow.currency,
      amount_minor: escrow.amount_minor,
      buyer_total_minor: escrow.buyer_total_minor,
      worker_net_minor: escrow.worker_net_minor,
      fee_quote: escrow.fee_quote,
      metadata: escrow.metadata,
      timestamps: {
        created_at: escrow.created_at,
        held_at: escrow.held_at,
        released_at: escrow.released_at,
        updated_at: escrow.updated_at,
      },
      dispute_window_seconds: escrow.dispute_window_seconds,
      dispute_window_ends_at: escrow.dispute_window_ends_at,
      ledger_refs: {
        hold_transfer: escrow.ledger_hold_event_id,
        worker_transfer: escrow.ledger_worker_event_id,
        fee_transfers: escrow.ledger_fee_event_ids,
        referral_transfers: escrow.ledger_referral_event_ids,
      },
      verification: escrow.verification,
      dispute: escrow.dispute,
    },
    200,
    version
  );
}

async function handleListEscrows(request: Request, env: Env, version: string): Promise<Response> {
  const url = new URL(request.url);

  const did = isNonEmptyString(url.searchParams.get('did')) ? url.searchParams.get('did')!.trim() : undefined;
  const buyer_did = isNonEmptyString(url.searchParams.get('buyer_did')) ? url.searchParams.get('buyer_did')!.trim() : undefined;
  const worker_did = isNonEmptyString(url.searchParams.get('worker_did')) ? url.searchParams.get('worker_did')!.trim() : undefined;
  const statusRaw = isNonEmptyString(url.searchParams.get('status')) ? url.searchParams.get('status')!.trim() : undefined;
  const fromRaw = isNonEmptyString(url.searchParams.get('from')) ? url.searchParams.get('from')!.trim() : undefined;
  const toRaw = isNonEmptyString(url.searchParams.get('to')) ? url.searchParams.get('to')!.trim() : undefined;
  const cursorRaw = isNonEmptyString(url.searchParams.get('cursor')) ? url.searchParams.get('cursor')!.trim() : null;

  let status: EscrowStatus | undefined;
  if (statusRaw !== undefined) {
    if (statusRaw !== 'held' && statusRaw !== 'released' && statusRaw !== 'frozen' && statusRaw !== 'cancelled') {
      return errorResponse('INVALID_REQUEST', 'status must be one of held|released|frozen|cancelled', 400, undefined, version);
    }
    status = statusRaw;
  }

  const from = fromRaw ? new Date(fromRaw) : null;
  if (fromRaw && (!from || !Number.isFinite(from.getTime()))) {
    return errorResponse('INVALID_REQUEST', 'from must be an ISO timestamp', 400, undefined, version);
  }

  const to = toRaw ? new Date(toRaw) : null;
  if (toRaw && (!to || !Number.isFinite(to.getTime()))) {
    return errorResponse('INVALID_REQUEST', 'to must be an ISO timestamp', 400, undefined, version);
  }

  const limitRaw = url.searchParams.get('limit');
  let limit = 50;
  if (isNonEmptyString(limitRaw)) {
    const parsed = Number.parseInt(limitRaw.trim(), 10);
    if (!Number.isInteger(parsed) || parsed <= 0) {
      return errorResponse('INVALID_REQUEST', 'limit must be a positive integer', 400, undefined, version);
    }
    limit = Math.min(parsed, 200);
  }

  const cursor = decodeEscrowCursor(cursorRaw);
  if (cursorRaw && !cursor) {
    return errorResponse('INVALID_CURSOR', 'cursor is invalid', 400, undefined, version);
  }

  const list = await listEscrows(env.ESCROW_DB, {
    did,
    buyer_did,
    worker_did,
    status,
    from: from ? from.toISOString() : undefined,
    to: to ? to.toISOString() : undefined,
    cursor: cursor ?? undefined,
    limit,
  });

  return jsonResponse(
    {
      escrows: list.escrows.map((escrow) => ({
        escrow_id: escrow.escrow_id,
        status: escrow.status,
        buyer_did: escrow.buyer_did,
        worker_did: escrow.worker_did,
        currency: escrow.currency,
        amount_minor: escrow.amount_minor,
        buyer_total_minor: escrow.buyer_total_minor,
        worker_net_minor: escrow.worker_net_minor,
        fee_quote: escrow.fee_quote,
        metadata: escrow.metadata,
        timestamps: {
          created_at: escrow.created_at,
          held_at: escrow.held_at,
          released_at: escrow.released_at,
          updated_at: escrow.updated_at,
        },
        ledger_refs: {
          hold_transfer: escrow.ledger_hold_event_id,
          worker_transfer: escrow.ledger_worker_event_id,
          fee_transfers: escrow.ledger_fee_event_ids,
          referral_transfers: escrow.ledger_referral_event_ids,
        },
      })),
      next_cursor: list.next_cursor ?? null,
    },
    200,
    version
  );
}

async function handleAssignEscrow(escrowId: string, request: Request, env: Env, version: string): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotency_key = bodyRaw.idempotency_key;
  const worker_did = bodyRaw.worker_did;

  if (!isNonEmptyString(idempotency_key)) {
    return errorResponse('INVALID_REQUEST', 'Missing required field: idempotency_key', 400, undefined, version);
  }

  if (!isNonEmptyString(worker_did) || !worker_did.trim().startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID string', 400, undefined, version);
  }

  const escrow = await getEscrowById(env.ESCROW_DB, escrowId);
  if (!escrow) {
    return errorResponse('NOT_FOUND', 'Escrow not found', 404, undefined, version);
  }

  if (escrow.status !== 'held') {
    return errorResponse('INVALID_STATUS', `Cannot assign worker in status '${escrow.status}'`, 409, undefined, version);
  }

  if (escrow.worker_did) {
    if (escrow.worker_did === worker_did.trim()) {
      const response: AssignEscrowResponseBody = { escrow_id: escrow.escrow_id, status: escrow.status, worker_did: escrow.worker_did };
      return jsonResponse(response, 200, version);
    }

    return errorResponse('WORKER_ALREADY_ASSIGNED', 'Escrow already assigned to a different worker', 409, undefined, version);
  }

  const now = nowIso();
  await updateEscrowAssign(env.ESCROW_DB, escrowId, worker_did.trim(), idempotency_key.trim(), now);

  const updated = await getEscrowById(env.ESCROW_DB, escrowId);
  if (!updated || !updated.worker_did) {
    return errorResponse('DB_WRITE_FAILED', 'Failed to update escrow assignment', 500, undefined, version);
  }

  const response: AssignEscrowResponseBody = { escrow_id: updated.escrow_id, status: updated.status, worker_did: updated.worker_did };
  return jsonResponse(response, 200, version);
}

async function handleReleaseEscrow(escrowId: string, request: Request, env: Env, version: string): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotency_key = bodyRaw.idempotency_key;
  const approved_by = bodyRaw.approved_by;
  const verificationRaw = bodyRaw.verification;

  if (!isNonEmptyString(idempotency_key)) {
    return errorResponse('INVALID_REQUEST', 'Missing required field: idempotency_key', 400, undefined, version);
  }

  if (!isNonEmptyString(approved_by) || !approved_by.trim().startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'approved_by must be a DID string', 400, undefined, version);
  }

  const escrow = await getEscrowById(env.ESCROW_DB, escrowId);
  if (!escrow) {
    return errorResponse('NOT_FOUND', 'Escrow not found', 404, undefined, version);
  }

  if (escrow.status === 'released') {
    const response: ReleaseEscrowResponseBody = {
      escrow_id: escrow.escrow_id,
      status: 'released',
      ledger_refs: {
        worker_transfer: escrow.ledger_worker_event_id ?? '',
        fee_transfers: escrow.ledger_fee_event_ids,
        referral_transfers: escrow.ledger_referral_event_ids,
      },
    };

    if (escrow.worker_did) {
      await emitEscrowOutcomeToClawrep(env, {
        schema_version: '1',
        source_event_id: `escrow:release:${escrow.escrow_id}:${escrow.release_idempotency_key ?? idempotency_key.trim()}`,
        source_service: 'escrow',
        kind: 'closure',
        did: escrow.worker_did,
        occurred_at: escrow.released_at ?? escrow.updated_at,
        closure: {
          value_usd: minorToUsd(escrow.worker_net_minor),
          closure_type: 'dispute_resolved',
          proof_tier: 'unknown',
          owner_verified: false,
        },
        metadata: {
          escrow_id: escrow.escrow_id,
          buyer_did: escrow.buyer_did,
          ledger_worker_event_id: escrow.ledger_worker_event_id,
        },
      });
    }

    return jsonResponse(response, 200, version);
  }

  if (escrow.status !== 'held') {
    return errorResponse('INVALID_STATUS', `Cannot release escrow in status '${escrow.status}'`, 409, undefined, version);
  }

  if (!escrow.worker_did) {
    return errorResponse('WORKER_NOT_ASSIGNED', 'Escrow has no worker assigned', 409, undefined, version);
  }

  if (approved_by.trim() !== escrow.buyer_did) {
    return errorResponse('UNAUTHORIZED', 'approved_by must match buyer_did', 401, undefined, version);
  }

  // Acquire idempotency lock: prevent double release with different idempotency keys.
  const now = nowIso();
  if (!escrow.release_idempotency_key) {
    await tryLockRelease(env.ESCROW_DB, escrowId, idempotency_key.trim(), now);
  }

  const locked = await getEscrowById(env.ESCROW_DB, escrowId);
  if (!locked) {
    return errorResponse('DB_READ_FAILED', 'Failed to read escrow', 500, undefined, version);
  }

  if (locked.release_idempotency_key && locked.release_idempotency_key !== idempotency_key.trim()) {
    return errorResponse(
      'IDEMPOTENCY_CONFLICT',
      'Release already in progress with a different idempotency_key',
      409,
      { release_idempotency_key: locked.release_idempotency_key },
      version
    );
  }

  if (!locked.worker_did) {
    return errorResponse('WORKER_NOT_ASSIGNED', 'Escrow has no worker assigned', 409, undefined, version);
  }

  const feeTotal = sumFeesMinor(locked.fee_quote.fees);
  const buyerTotal = parsePositiveMinor(locked.buyer_total_minor);
  const workerNet = parseNonNegativeMinor(locked.worker_net_minor);
  if (buyerTotal === null || workerNet === null) {
    return errorResponse('INTERNAL_ERROR', 'Stored amounts invalid', 500, undefined, version);
  }

  if (workerNet + feeTotal !== buyerTotal) {
    return errorResponse(
      'FEE_QUOTE_MISMATCH',
      'Stored fee quote does not sum to buyer_total_minor',
      500,
      {
        worker_net_minor: workerNet.toString(),
        fee_total_minor: feeTotal.toString(),
        buyer_total_minor: buyerTotal.toString(),
      },
      version
    );
  }

  const feeClearingDomain = env.FEE_CLEARING_DOMAIN?.trim().length ? env.FEE_CLEARING_DOMAIN!.trim() : 'clawcuts';
  const fallbackClearingAccount = `clearing:${feeClearingDomain}`;

  const releaseBaseId = `escrow:${locked.escrow_id}:release:${idempotency_key.trim()}`;

  let cutsApply: CutsApplyResponse;
  try {
    cutsApply = await clawcutsApplyFees(env, {
      idempotency_key: releaseBaseId,
      product: 'clawbounties',
      settlement_ref: locked.escrow_id,
      occurred_at: nowIso(),
      snapshot: locked.fee_quote,
      context: {
        escrow_id: locked.escrow_id,
        buyer_did: locked.buyer_did,
        worker_did: locked.worker_did,
        fallback_clearing_account: fallbackClearingAccount,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('FEE_APPLY_FAILED', message, 502, undefined, version);
  }

  const applyFeeTotal = parseNonNegativeMinor(cutsApply.fee_summary.total_fee_minor);
  const applyReferralTotal = parseNonNegativeMinor(cutsApply.fee_summary.referral_payout_minor);
  const applyRetainedTotal = parseNonNegativeMinor(cutsApply.fee_summary.platform_retained_minor);
  const applyBuyerTotal = parsePositiveMinor(cutsApply.fee_summary.buyer_total_minor);
  const applyWorkerNet = parseNonNegativeMinor(cutsApply.fee_summary.worker_net_minor);

  if (
    applyFeeTotal === null ||
    applyReferralTotal === null ||
    applyRetainedTotal === null ||
    applyBuyerTotal === null ||
    applyWorkerNet === null
  ) {
    return errorResponse('FEE_APPLY_MISMATCH', 'clawcuts apply summary is invalid', 502, undefined, version);
  }

  if (applyFeeTotal !== feeTotal || applyBuyerTotal !== buyerTotal || applyWorkerNet !== workerNet || applyRetainedTotal + applyReferralTotal !== applyFeeTotal) {
    return errorResponse(
      'FEE_APPLY_MISMATCH',
      'clawcuts apply summary does not match stored escrow snapshot',
      502,
      {
        expected_fee_total_minor: feeTotal.toString(),
        received_fee_total_minor: applyFeeTotal.toString(),
        expected_buyer_total_minor: buyerTotal.toString(),
        received_buyer_total_minor: applyBuyerTotal.toString(),
        expected_worker_net_minor: workerNet.toString(),
        received_worker_net_minor: applyWorkerNet.toString(),
      },
      version
    );
  }

  let workerEventId: string;
  const feeEventIds: string[] = [];
  const referralEventIds: string[] = [];

  try {
    // Worker payout
    const workerTransfer = await ledgerV1Transfer(env, {
      idempotency_key: `${releaseBaseId}:worker`,
      from: { account: locked.buyer_did, bucket: 'H' },
      to: { account: locked.worker_did, bucket: 'A' },
      amount_minor: locked.worker_net_minor,
      metadata: {
        kind: 'escrow_release_worker',
        escrow_id: locked.escrow_id,
        policy_id: locked.fee_quote.policy_id,
        policy_version: locked.fee_quote.policy_version,
        policy_hash_b64u: locked.fee_quote.policy_hash_b64u,
      },
    });
    workerEventId = workerTransfer.event_id;

    for (const transfer of cutsApply.transfer_plan.transfers) {
      const amount = parseNonNegativeMinor(transfer.amount_minor);
      if (amount === null || amount === 0n) continue;

      const transferResult = await ledgerV1Transfer(env, {
        idempotency_key: `${releaseBaseId}:fee:${transfer.transfer_index}`,
        from: { account: locked.buyer_did, bucket: 'H' },
        to: { account: transfer.to_account, bucket: transfer.to_bucket },
        amount_minor: transfer.amount_minor,
        metadata: {
          kind: transfer.split_kind === 'referral' ? 'escrow_release_referral' : 'escrow_release_fee',
          escrow_id: locked.escrow_id,
          fee_transfer_index: transfer.transfer_index,
          fee_index: transfer.fee_index,
          fee_kind: transfer.fee_kind,
          fee_payer: transfer.payer,
          split_kind: transfer.split_kind,
          to_account: transfer.to_account,
          to_bucket: transfer.to_bucket,
          referrer_did: transfer.referrer_did,
          referral_code: transfer.referral_code,
          policy_id: locked.fee_quote.policy_id,
          policy_version: locked.fee_quote.policy_version,
          policy_hash_b64u: locked.fee_quote.policy_hash_b64u,
        },
      });

      if (transfer.split_kind === 'referral') {
        referralEventIds.push(transferResult.event_id);
      } else {
        feeEventIds.push(transferResult.event_id);
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('LEDGER_RELEASE_FAILED', message, 502, undefined, version);
  }

  try {
    await clawcutsFinalizeFeeApply(env, {
      idempotency_key: cutsApply.idempotency_key,
      ledger_fee_event_ids: feeEventIds,
      ledger_referral_event_ids: referralEventIds,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('FEE_APPLY_FINALIZE_FAILED', message, 502, undefined, version);
  }

  let verification: Record<string, unknown> | null = null;
  if (verificationRaw !== undefined) {
    if (verificationRaw !== null && !isRecord(verificationRaw)) {
      return errorResponse('INVALID_REQUEST', 'verification must be an object', 400, undefined, version);
    }
    verification = verificationRaw ? (verificationRaw as Record<string, unknown>) : null;
  }

  const releasedAt = nowIso();
  await updateEscrowReleased(env.ESCROW_DB, escrowId, releasedAt, workerEventId, feeEventIds, referralEventIds, verification);

  const response: ReleaseEscrowResponseBody = {
    escrow_id: locked.escrow_id,
    status: 'released',
    ledger_refs: {
      worker_transfer: workerEventId,
      fee_transfers: feeEventIds,
      referral_transfers: referralEventIds,
    },
  };

  await emitEscrowOutcomeToClawrep(env, {
    schema_version: '1',
    source_event_id: `escrow:release:${locked.escrow_id}:${idempotency_key.trim()}`,
    source_service: 'escrow',
    kind: 'closure',
    did: locked.worker_did,
    occurred_at: releasedAt,
    closure: {
      value_usd: minorToUsd(locked.worker_net_minor),
      closure_type: 'manual_approve',
      proof_tier: 'unknown',
      owner_verified: false,
    },
    metadata: {
      escrow_id: locked.escrow_id,
      buyer_did: locked.buyer_did,
      approved_by: approved_by.trim(),
      ledger_worker_event_id: workerEventId,
      fee_event_count: feeEventIds.length,
      referral_event_count: referralEventIds.length,
      verification,
    },
  });

  return jsonResponse(response, 200, version);
}

async function handleDisputeEscrow(escrowId: string, request: Request, env: Env, version: string): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotency_key = bodyRaw.idempotency_key;
  const disputed_by = bodyRaw.disputed_by;

  if (!isNonEmptyString(idempotency_key)) {
    return errorResponse('INVALID_REQUEST', 'Missing required field: idempotency_key', 400, undefined, version);
  }

  if (!isNonEmptyString(disputed_by) || !disputed_by.trim().startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'disputed_by must be a DID string', 400, undefined, version);
  }

  const escrow = await getEscrowById(env.ESCROW_DB, escrowId);
  if (!escrow) {
    return errorResponse('NOT_FOUND', 'Escrow not found', 404, undefined, version);
  }

  if (escrow.status === 'frozen') {
    const response: DisputeEscrowResponseBody = {
      escrow_id: escrow.escrow_id,
      status: 'frozen',
      dispute_window_ends_at: escrow.dispute_window_ends_at,
    };

    if (escrow.worker_did) {
      await emitEscrowOutcomeToClawrep(env, {
        schema_version: '1',
        source_event_id: `escrow:dispute:${escrow.escrow_id}:${escrow.dispute_idempotency_key ?? idempotency_key.trim()}`,
        source_service: 'escrow',
        kind: 'penalty',
        did: escrow.worker_did,
        occurred_at: escrow.updated_at,
        penalty: {
          penalty_type: 'dispute_upheld_against_worker',
          severity: 2,
          reason: 'Escrow disputed',
        },
        metadata: {
          escrow_id: escrow.escrow_id,
          disputed_by: disputed_by.trim(),
          dispute: escrow.dispute,
        },
      });
    }

    return jsonResponse(response, 200, version);
  }

  if (escrow.status !== 'held') {
    return errorResponse('INVALID_STATUS', `Cannot dispute escrow in status '${escrow.status}'`, 409, undefined, version);
  }

  const now = new Date();
  const windowEnd = new Date(escrow.dispute_window_ends_at);
  if (Number.isFinite(windowEnd.getTime()) && now > windowEnd) {
    return errorResponse('DISPUTE_WINDOW_EXPIRED', 'Dispute window expired', 409, { dispute_window_ends_at: escrow.dispute_window_ends_at }, version);
  }

  // Acquire lock
  const lockNow = nowIso();
  if (!escrow.dispute_idempotency_key) {
    await tryLockDispute(env.ESCROW_DB, escrowId, idempotency_key.trim(), lockNow);
  }

  const locked = await getEscrowById(env.ESCROW_DB, escrowId);
  if (!locked) {
    return errorResponse('DB_READ_FAILED', 'Failed to read escrow', 500, undefined, version);
  }

  if (locked.dispute_idempotency_key && locked.dispute_idempotency_key !== idempotency_key.trim()) {
    return errorResponse(
      'IDEMPOTENCY_CONFLICT',
      'Dispute already in progress with a different idempotency_key',
      409,
      { dispute_idempotency_key: locked.dispute_idempotency_key },
      version
    );
  }

  const dispute: Record<string, unknown> = {
    disputed_by: disputed_by.trim(),
    reason: isNonEmptyString(bodyRaw.reason) ? bodyRaw.reason.trim() : undefined,
    description: isNonEmptyString(bodyRaw.description) ? bodyRaw.description.trim() : undefined,
    evidence_urls: Array.isArray(bodyRaw.evidence_urls) ? bodyRaw.evidence_urls : undefined,
    created_at: lockNow,
  };

  await updateEscrowDisputed(env.ESCROW_DB, escrowId, lockNow, dispute);

  const response: DisputeEscrowResponseBody = {
    escrow_id: locked.escrow_id,
    status: 'frozen',
    dispute_window_ends_at: locked.dispute_window_ends_at,
  };

  if (locked.worker_did) {
    await emitEscrowOutcomeToClawrep(env, {
      schema_version: '1',
      source_event_id: `escrow:dispute:${locked.escrow_id}:${idempotency_key.trim()}`,
      source_service: 'escrow',
      kind: 'penalty',
      did: locked.worker_did,
      occurred_at: lockNow,
      penalty: {
        penalty_type: 'dispute_upheld_against_worker',
        severity: 2,
        reason: isNonEmptyString(bodyRaw.reason) ? bodyRaw.reason.trim() : 'Escrow disputed',
      },
      metadata: {
        escrow_id: locked.escrow_id,
        buyer_did: locked.buyer_did,
        disputed_by: disputed_by.trim(),
        dispute,
      },
    });
  }

  return jsonResponse(response, 200, version);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    const version = env.ESCROW_VERSION?.trim().length ? env.ESCROW_VERSION.trim() : '0.1.0';

    // Public endpoints
    if (method === 'GET' || method === 'HEAD') {
      const origin = url.origin;

      if (path === '/') return htmlResponse(landingPage(origin, version), 200, version);
      if (path === '/docs') return htmlResponse(docsPage(origin), 200, version);
      if (path === '/skill.md') return textResponse(skillMarkdown(origin, version), 'text/markdown; charset=utf-8', 200, version);
      if (path === '/health') return jsonResponse({ status: 'ok', service: 'clawescrow', version }, 200, version);
      if (path === '/robots.txt') return textResponse(robotsTxt(origin), 'text/plain; charset=utf-8', 200, version);
      if (path === '/sitemap.xml') return textResponse(sitemapXml(origin), 'application/xml; charset=utf-8', 200, version);
      if (path === '/.well-known/security.txt') return textResponse(securityTxt(origin), 'text/plain; charset=utf-8', 200, version);
    }

    // Admin-gated API
    if (path.startsWith('/v1/')) {
      const adminError = requireAdmin(request, env, version);
      if (adminError) return adminError;

      if (path === '/v1/escrows' && method === 'POST') {
        return handleCreateEscrow(request, env, version);
      }

      if (path === '/v1/escrows' && method === 'GET') {
        return handleListEscrows(request, env, version);
      }

      const getMatch = path.match(/^\/v1\/escrows\/(esc_[a-f0-9-]+)$/);
      if (getMatch && method === 'GET') {
        return handleGetEscrow(getMatch[1], env, version);
      }

      const assignMatch = path.match(/^\/v1\/escrows\/(esc_[a-f0-9-]+)\/assign$/);
      if (assignMatch && method === 'POST') {
        return handleAssignEscrow(assignMatch[1], request, env, version);
      }

      const releaseMatch = path.match(/^\/v1\/escrows\/(esc_[a-f0-9-]+)\/release$/);
      if (releaseMatch && method === 'POST') {
        return handleReleaseEscrow(releaseMatch[1], request, env, version);
      }

      const disputeMatch = path.match(/^\/v1\/escrows\/(esc_[a-f0-9-]+)\/dispute$/);
      if (disputeMatch && method === 'POST') {
        return handleDisputeEscrow(disputeMatch[1], request, env, version);
      }

      return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
    }

    return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
  },
};
