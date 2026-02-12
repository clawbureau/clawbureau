import { sha256B64uUtf8 } from './crypto';

export interface Env {
  CUTS_VERSION: string;
  CUTS_DB: D1Database;
  CUTS_FEE_CLEARING_ACCOUNT?: string;
  CUTS_ADMIN_KEY?: string;
  CUTS_APPLY_KEY?: string;
}

type FeePayer = 'buyer' | 'worker';
type SplitKind = 'platform' | 'referral';
type SplitBucket = 'A' | 'F';
type PolicyStatus = 'draft' | 'active' | 'inactive';

type CodeSelector = 'true' | 'false' | '*';
type ClosureSelector = 'test' | 'requester' | 'quorum' | '*';

const POLICY_SCHEMA = 'clawcuts.policy.v3';
const DEFAULT_FEE_CLEARING_ACCOUNT = 'clearing:clawcuts';
const BOUNTIES_CLOSURES = new Set(['test', 'requester', 'quorum']);

let BOOTSTRAP_PROMISE: Promise<void> | null = null;

interface FeeSplit {
  kind: SplitKind;
  account: string;
  bucket: SplitBucket;
  amount_minor: string;
  referrer_did?: string;
  referral_code?: string;
}

interface FeeItem {
  kind: 'platform';
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

interface PolicyInfo {
  id: string;
  version: string;
  hash_b64u: string;
}

interface FeeQuote {
  principal_minor: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  total_fee_minor: string;
  referral_payout_minor: string;
  platform_retained_minor: string;
  fees: FeeItem[];
}

interface FeeSimulateResponse {
  policy: PolicyInfo;
  quote: FeeQuote;
}

interface PolicyRule {
  is_code_bounty: CodeSelector;
  closure_type: ClosureSelector;
  buyer_fee_bps: number;
  worker_fee_bps: number;
  min_fee_minor: string;
  referral_bps: number;
  referral_min_minor: string;
}

interface DiscountPolicy {
  enabled: boolean;
  max_bps: number;
}

interface PolicyDefinition {
  schema: typeof POLICY_SCHEMA;
  product: string;
  policy_id: string;
  version: string;
  currency: 'USD';
  rules: PolicyRule[];
  discount: DiscountPolicy;
}

interface PolicyVersionRow {
  product: string;
  policy_id: string;
  version: number;
  status: PolicyStatus;
  policy_json: string;
  policy_hash_b64u: string;
  notes: string | null;
  created_by: string;
  created_at: string;
  activated_by: string | null;
  activated_at: string | null;
  deactivated_by: string | null;
  deactivated_at: string | null;
}

interface PolicyAuditRow {
  audit_id: string;
  product: string;
  policy_id: string;
  policy_version: number | null;
  action: string;
  actor: string;
  created_at: string;
  details_json: string | null;
}

interface FeeApplySnapshot {
  policy_id: string;
  policy_version: string;
  policy_hash_b64u: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  fees: FeeItem[];
}

interface ApplyTransfer {
  transfer_index: number;
  fee_index: number;
  fee_kind: string;
  payer: FeePayer;
  split_kind: SplitKind;
  to_account: string;
  to_bucket: SplitBucket;
  amount_minor: string;
  referrer_did?: string;
  referral_code?: string;
}

interface SnapshotAnalysis {
  principal_minor: bigint;
  buyer_total_minor: bigint;
  worker_net_minor: bigint;
  total_fee_minor: bigint;
  buyer_fee_minor: bigint;
  worker_fee_minor: bigint;
  referral_fee_minor: bigint;
  platform_retained_minor: bigint;
  transfers: ApplyTransfer[];
}

interface FeeApplyEventRow {
  apply_id: string;
  idempotency_key: string;
  product: string;
  settlement_ref: string | null;
  month: string;
  currency: string;
  policy_id: string;
  policy_version: number;
  policy_hash_b64u: string;
  principal_minor: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  total_fee_minor: string;
  platform_fee_minor: string;
  referral_fee_minor: string;
  platform_retained_minor: string;
  transfer_plan_json: string;
  snapshot_json: string;
  context_json: string | null;
  ledger_fee_event_ids_json: string | null;
  ledger_referral_event_ids_json: string | null;
  created_at: string;
  finalized_at: string | null;
}

interface RevenueRow {
  product: string;
  policy_id: string;
  policy_version: string;
  policy_hash_b64u: string;
  transaction_count: number;
  gross_principal_minor: string;
  platform_fee_minor: string;
  referral_payout_minor: string;
  platform_retained_minor: string;
  buyer_total_minor: string;
  worker_net_minor: string;
}

function jsonResponse(body: unknown, status = 200, version?: string): Response {
  const headers = new Headers();
  headers.set('content-type', 'application/json; charset=utf-8');
  if (version) headers.set('X-Cuts-Version', version);
  return new Response(JSON.stringify(body, null, 2), { status, headers });
}

function textResponse(body: string, contentType: string, status = 200, version?: string): Response {
  const headers = new Headers({ 'content-type': contentType });
  if (version) headers.set('X-Cuts-Version', version);
  return new Response(body, { status, headers });
}

function errorResponse(
  code: string,
  message: string,
  status = 400,
  details?: Record<string, unknown>,
  version?: string
): Response {
  return jsonResponse({ error: code, message, details }, status, version);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function nowIso(): string {
  return new Date().toISOString();
}

function d1String(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return value.toString();
  return null;
}

function d1Number(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim().length > 0) {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function parsePositiveMinor(input: unknown): bigint | null {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (!/^[0-9]+$/.test(trimmed)) return null;
  try {
    const value = BigInt(trimmed);
    if (value <= 0n) return null;
    return value;
  } catch {
    return null;
  }
}

function parseNonNegativeMinor(input: unknown): bigint | null {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (!/^[0-9]+$/.test(trimmed)) return null;
  try {
    const value = BigInt(trimmed);
    if (value < 0n) return null;
    return value;
  } catch {
    return null;
  }
}

function parseNonNegativeMinorString(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (!/^[0-9]+$/.test(trimmed)) return null;
  return trimmed;
}

function parsePositiveInt(input: unknown): number | null {
  if (typeof input === 'number' && Number.isInteger(input) && input > 0) return input;
  if (typeof input === 'string' && /^[0-9]+$/.test(input.trim())) {
    const parsed = Number(input.trim());
    if (Number.isInteger(parsed) && parsed > 0) return parsed;
  }
  return null;
}

function parseBps(input: unknown): number | null {
  if (typeof input !== 'number' || !Number.isInteger(input)) return null;
  if (input < 0 || input > 10_000) return null;
  return input;
}

function parseCodeSelector(input: unknown): CodeSelector | null {
  if (input === 'true' || input === 'false' || input === '*') return input;
  return null;
}

function parseClosureSelector(input: unknown): ClosureSelector | null {
  if (input === 'test' || input === 'requester' || input === 'quorum' || input === '*') return input;
  return null;
}

function escapeCsv(value: string): string {
  if (/[",\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function toCsv(headers: string[], rows: string[][]): string {
  const lines = [headers.join(',')];
  for (const row of rows) {
    lines.push(row.map((cell) => escapeCsv(cell)).join(','));
  }
  return `${lines.join('\n')}\n`;
}

export function stableStringify(value: unknown): string {
  if (value === null) return 'null';

  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringify(entry)).join(',')}]`;
  }

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number': {
      if (!Number.isFinite(value)) throw new Error('Non-finite number');
      return JSON.stringify(value);
    }
    case 'boolean':
      return value ? 'true' : 'false';
    case 'bigint':
      return JSON.stringify(value.toString());
    case 'object': {
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(obj[key])}`).join(',')}}`;
    }
    default:
      return 'null';
  }
}

function getAuthToken(request: Request): string | null {
  const authorization = request.headers.get('authorization');
  if (authorization && authorization.trim().length > 0) {
    const trimmed = authorization.trim();
    if (trimmed.toLowerCase().startsWith('bearer ')) {
      return trimmed.slice(7).trim();
    }
    return trimmed;
  }

  const header = request.headers.get('x-admin-key');
  if (header && header.trim().length > 0) return header.trim();

  return null;
}

function requireAdmin(request: Request, env: Env, version: string): Response | null {
  const adminKey = env.CUTS_ADMIN_KEY?.trim();
  if (!adminKey) {
    return errorResponse('ADMIN_KEY_NOT_CONFIGURED', 'CUTS_ADMIN_KEY is not configured', 503, undefined, version);
  }

  const token = getAuthToken(request);
  if (!token) {
    return errorResponse('UNAUTHORIZED', 'Missing admin token', 401, undefined, version);
  }

  if (token !== adminKey) {
    return errorResponse('UNAUTHORIZED', 'Invalid admin token', 401, undefined, version);
  }

  return null;
}

function requireApplyAuth(request: Request, env: Env, version: string): Response | null {
  const applyKey = env.CUTS_APPLY_KEY?.trim() ?? null;
  const adminKey = env.CUTS_ADMIN_KEY?.trim() ?? null;

  if (!applyKey && !adminKey) {
    return errorResponse('APPLY_KEY_NOT_CONFIGURED', 'CUTS_APPLY_KEY or CUTS_ADMIN_KEY must be configured', 503, undefined, version);
  }

  const token = getAuthToken(request);
  if (!token) {
    return errorResponse('UNAUTHORIZED', 'Missing apply token', 401, undefined, version);
  }

  if (applyKey && token === applyKey) return null;
  if (adminKey && token === adminKey) return null;

  return errorResponse('UNAUTHORIZED', 'Invalid apply token', 401, undefined, version);
}

function parsePolicyRule(input: unknown): PolicyRule | null {
  if (!isRecord(input)) return null;

  const is_code_bounty = parseCodeSelector(input.is_code_bounty);
  const closure_type = parseClosureSelector(input.closure_type);
  const buyer_fee_bps = parseBps(input.buyer_fee_bps);
  const worker_fee_bps = parseBps(input.worker_fee_bps);
  const min_fee_minor = parseNonNegativeMinorString(input.min_fee_minor);
  const referral_bps = parseBps(input.referral_bps ?? 0);
  const referral_min_minor = parseNonNegativeMinorString(input.referral_min_minor ?? '0');

  if (
    !is_code_bounty ||
    !closure_type ||
    buyer_fee_bps === null ||
    worker_fee_bps === null ||
    !min_fee_minor ||
    referral_bps === null ||
    !referral_min_minor
  ) {
    return null;
  }

  return {
    is_code_bounty,
    closure_type,
    buyer_fee_bps,
    worker_fee_bps,
    min_fee_minor,
    referral_bps,
    referral_min_minor,
  };
}

function parseDiscountPolicy(input: unknown): DiscountPolicy | null {
  if (input === undefined || input === null) {
    return { enabled: false, max_bps: 0 };
  }

  if (!isRecord(input)) return null;
  const enabled = input.enabled;
  const max_bps_raw = input.max_bps;

  if (typeof enabled !== 'boolean') return null;

  if (!enabled) {
    return { enabled: false, max_bps: 0 };
  }

  const max_bps = parseBps(max_bps_raw);
  if (max_bps === null) return null;

  return { enabled: true, max_bps };
}

function canonicalPolicyObject(policy: PolicyDefinition): Record<string, unknown> {
  return {
    schema: policy.schema,
    product: policy.product,
    policy_id: policy.policy_id,
    version: policy.version,
    currency: policy.currency,
    discount: policy.discount,
    rules: policy.rules,
  };
}

async function hashPolicy(policy: PolicyDefinition): Promise<string> {
  const canonical = stableStringify(canonicalPolicyObject(policy));
  return sha256B64uUtf8(canonical);
}

function policyFromCreateInput(
  product: string,
  policyId: string,
  version: number,
  rules: PolicyRule[],
  discount: DiscountPolicy
): PolicyDefinition {
  return {
    schema: POLICY_SCHEMA,
    product,
    policy_id: policyId,
    version: version.toString(),
    currency: 'USD',
    rules,
    discount,
  };
}

function parseStoredPolicyDefinition(row: PolicyVersionRow): PolicyDefinition | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.policy_json);
  } catch {
    return null;
  }

  if (!isRecord(parsed)) return null;

  const schema = parsed.schema;
  const product = parsed.product;
  const policy_id = parsed.policy_id;
  const version = parsed.version;
  const currency = parsed.currency;
  const rulesRaw = parsed.rules;
  const discountRaw = parsed.discount;

  if (schema !== POLICY_SCHEMA) return null;
  if (!isNonEmptyString(product) || product.trim() !== row.product) return null;
  if (!isNonEmptyString(policy_id) || policy_id.trim() !== row.policy_id) return null;
  if (!isNonEmptyString(version) || version.trim() !== row.version.toString()) return null;
  if (currency !== 'USD') return null;
  if (!Array.isArray(rulesRaw)) return null;

  const rules: PolicyRule[] = [];
  for (const ruleRaw of rulesRaw) {
    const rule = parsePolicyRule(ruleRaw);
    if (!rule) return null;
    rules.push(rule);
  }

  const discount = parseDiscountPolicy(discountRaw);
  if (!discount) return null;

  return {
    schema: POLICY_SCHEMA,
    product: row.product,
    policy_id: row.policy_id,
    version: row.version.toString(),
    currency: 'USD',
    rules,
    discount,
  };
}

function parsePolicyVersionRow(input: unknown): PolicyVersionRow | null {
  if (!isRecord(input)) return null;

  const product = d1String(input.product);
  const policy_id = d1String(input.policy_id);
  const version = d1Number(input.version);
  const status = d1String(input.status);
  const policy_json = d1String(input.policy_json);
  const policy_hash_b64u = d1String(input.policy_hash_b64u);
  const created_by = d1String(input.created_by);
  const created_at = d1String(input.created_at);

  if (
    !product ||
    !policy_id ||
    version === null ||
    !Number.isInteger(version) ||
    version <= 0 ||
    !status ||
    (status !== 'draft' && status !== 'active' && status !== 'inactive') ||
    !policy_json ||
    !policy_hash_b64u ||
    !created_by ||
    !created_at
  ) {
    return null;
  }

  return {
    product,
    policy_id,
    version,
    status: status as PolicyStatus,
    policy_json,
    policy_hash_b64u,
    notes: d1String(input.notes),
    created_by,
    created_at,
    activated_by: d1String(input.activated_by),
    activated_at: d1String(input.activated_at),
    deactivated_by: d1String(input.deactivated_by),
    deactivated_at: d1String(input.deactivated_at),
  };
}

function parsePolicyAuditRow(input: unknown): PolicyAuditRow | null {
  if (!isRecord(input)) return null;

  const audit_id = d1String(input.audit_id);
  const product = d1String(input.product);
  const policy_id = d1String(input.policy_id);
  const action = d1String(input.action);
  const actor = d1String(input.actor);
  const created_at = d1String(input.created_at);

  const policyVersionRaw = d1Number(input.policy_version);
  const policy_version =
    policyVersionRaw === null || !Number.isInteger(policyVersionRaw) || policyVersionRaw <= 0 ? null : policyVersionRaw;

  if (!audit_id || !product || !policy_id || !action || !actor || !created_at) {
    return null;
  }

  return {
    audit_id,
    product,
    policy_id,
    policy_version,
    action,
    actor,
    created_at,
    details_json: d1String(input.details_json),
  };
}

function parseFeeApplyEventRow(input: unknown): FeeApplyEventRow | null {
  if (!isRecord(input)) return null;

  const apply_id = d1String(input.apply_id);
  const idempotency_key = d1String(input.idempotency_key);
  const product = d1String(input.product);
  const month = d1String(input.month);
  const currency = d1String(input.currency);
  const policy_id = d1String(input.policy_id);
  const policy_version = d1Number(input.policy_version);
  const policy_hash_b64u = d1String(input.policy_hash_b64u);
  const principal_minor = d1String(input.principal_minor);
  const buyer_total_minor = d1String(input.buyer_total_minor);
  const worker_net_minor = d1String(input.worker_net_minor);
  const total_fee_minor = d1String(input.total_fee_minor);
  const platform_fee_minor = d1String(input.platform_fee_minor);
  const referral_fee_minor = d1String(input.referral_fee_minor);
  const platform_retained_minor = d1String(input.platform_retained_minor);
  const transfer_plan_json = d1String(input.transfer_plan_json);
  const snapshot_json = d1String(input.snapshot_json);
  const created_at = d1String(input.created_at);

  if (
    !apply_id ||
    !idempotency_key ||
    !product ||
    !month ||
    !currency ||
    !policy_id ||
    policy_version === null ||
    !Number.isInteger(policy_version) ||
    policy_version <= 0 ||
    !policy_hash_b64u ||
    !principal_minor ||
    !buyer_total_minor ||
    !worker_net_minor ||
    !total_fee_minor ||
    !platform_fee_minor ||
    !referral_fee_minor ||
    !platform_retained_minor ||
    !transfer_plan_json ||
    !snapshot_json ||
    !created_at
  ) {
    return null;
  }

  return {
    apply_id,
    idempotency_key,
    product,
    settlement_ref: d1String(input.settlement_ref),
    month,
    currency,
    policy_id,
    policy_version,
    policy_hash_b64u,
    principal_minor,
    buyer_total_minor,
    worker_net_minor,
    total_fee_minor,
    platform_fee_minor,
    referral_fee_minor,
    platform_retained_minor,
    transfer_plan_json,
    snapshot_json,
    context_json: d1String(input.context_json),
    ledger_fee_event_ids_json: d1String(input.ledger_fee_event_ids_json),
    ledger_referral_event_ids_json: d1String(input.ledger_referral_event_ids_json),
    created_at,
    finalized_at: d1String(input.finalized_at),
  };
}

async function getPolicyVersionRow(env: Env, product: string, policyId: string, version: number): Promise<PolicyVersionRow | null> {
  const row = await env.CUTS_DB.prepare(
    `SELECT product, policy_id, version, status, policy_json, policy_hash_b64u, notes, created_by, created_at,
            activated_by, activated_at, deactivated_by, deactivated_at
       FROM policy_versions
      WHERE product = ? AND policy_id = ? AND version = ?`
  )
    .bind(product, policyId, version)
    .first();

  return parsePolicyVersionRow(row);
}

async function getActivePolicyVersionRow(env: Env, product: string, policyId: string): Promise<PolicyVersionRow | null> {
  const row = await env.CUTS_DB.prepare(
    `SELECT product, policy_id, version, status, policy_json, policy_hash_b64u, notes, created_by, created_at,
            activated_by, activated_at, deactivated_by, deactivated_at
       FROM policy_versions
      WHERE product = ? AND policy_id = ? AND status = 'active'
      ORDER BY version DESC
      LIMIT 1`
  )
    .bind(product, policyId)
    .first();

  return parsePolicyVersionRow(row);
}

async function getNextPolicyVersion(env: Env, product: string, policyId: string): Promise<number> {
  const row = await env.CUTS_DB.prepare(
    'SELECT COALESCE(MAX(version), 0) + 1 AS next_version FROM policy_versions WHERE product = ? AND policy_id = ?'
  )
    .bind(product, policyId)
    .first();

  const nextVersion = d1Number(isRecord(row) ? row.next_version : null);
  if (nextVersion === null || !Number.isInteger(nextVersion) || nextVersion <= 0) {
    throw new Error('POLICY_VERSION_COMPUTE_FAILED');
  }

  return nextVersion;
}

async function listPolicyVersions(env: Env, product: string, policyId: string): Promise<PolicyVersionRow[]> {
  const result = await env.CUTS_DB.prepare(
    `SELECT product, policy_id, version, status, policy_json, policy_hash_b64u, notes, created_by, created_at,
            activated_by, activated_at, deactivated_by, deactivated_at
       FROM policy_versions
      WHERE product = ? AND policy_id = ?
      ORDER BY version DESC`
  )
    .bind(product, policyId)
    .all();

  const rows = Array.isArray(result.results) ? result.results : [];
  const out: PolicyVersionRow[] = [];
  for (const row of rows) {
    const parsed = parsePolicyVersionRow(row);
    if (parsed) out.push(parsed);
  }
  return out;
}

async function listPolicyAuditEvents(env: Env, product: string, policyId: string): Promise<PolicyAuditRow[]> {
  const result = await env.CUTS_DB.prepare(
    `SELECT audit_id, product, policy_id, policy_version, action, actor, created_at, details_json
       FROM policy_audit_events
      WHERE product = ? AND policy_id = ?
      ORDER BY created_at DESC, audit_id DESC`
  )
    .bind(product, policyId)
    .all();

  const rows = Array.isArray(result.results) ? result.results : [];
  const out: PolicyAuditRow[] = [];
  for (const row of rows) {
    const parsed = parsePolicyAuditRow(row);
    if (parsed) out.push(parsed);
  }
  return out;
}

async function insertPolicyAudit(
  env: Env,
  params: {
    product: string;
    policy_id: string;
    policy_version: number | null;
    action: string;
    actor: string;
    created_at: string;
    details?: Record<string, unknown>;
  }
): Promise<void> {
  await env.CUTS_DB.prepare(
    `INSERT INTO policy_audit_events (
      audit_id,
      product,
      policy_id,
      policy_version,
      action,
      actor,
      created_at,
      details_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      `aud_${crypto.randomUUID()}`,
      params.product,
      params.policy_id,
      params.policy_version,
      params.action,
      params.actor,
      params.created_at,
      params.details ? JSON.stringify(params.details) : null
    )
    .run();
}

async function activatePolicyVersion(env: Env, product: string, policyId: string, version: number, actor: string, at: string): Promise<void> {
  await env.CUTS_DB.prepare(
    `UPDATE policy_versions
        SET status = 'inactive', deactivated_by = ?, deactivated_at = ?
      WHERE product = ? AND policy_id = ? AND status = 'active' AND version != ?`
  )
    .bind(actor, at, product, policyId, version)
    .run();

  const result = await env.CUTS_DB.prepare(
    `UPDATE policy_versions
        SET status = 'active', activated_by = ?, activated_at = ?, deactivated_by = NULL, deactivated_at = NULL
      WHERE product = ? AND policy_id = ? AND version = ?`
  )
    .bind(actor, at, product, policyId, version)
    .run();

  if ((result.meta.changes ?? 0) <= 0) {
    throw new Error('POLICY_NOT_FOUND');
  }
}

async function deactivatePolicyVersion(env: Env, product: string, policyId: string, version: number, actor: string, at: string): Promise<void> {
  const result = await env.CUTS_DB.prepare(
    `UPDATE policy_versions
        SET status = 'inactive', deactivated_by = ?, deactivated_at = ?
      WHERE product = ? AND policy_id = ? AND version = ?`
  )
    .bind(actor, at, product, policyId, version)
    .run();

  if ((result.meta.changes ?? 0) <= 0) {
    throw new Error('POLICY_NOT_FOUND');
  }
}

function defaultPolicySeeds(): Array<{
  product: string;
  policy_id: string;
  rules: PolicyRule[];
  discount: DiscountPolicy;
  notes: string;
}> {
  return [
    {
      product: 'clawbounties',
      policy_id: 'bounties_v1',
      discount: { enabled: true, max_bps: 2_500 },
      rules: [
        {
          is_code_bounty: 'true',
          closure_type: 'test',
          buyer_fee_bps: 500,
          worker_fee_bps: 0,
          min_fee_minor: '0',
          referral_bps: 0,
          referral_min_minor: '0',
        },
        {
          is_code_bounty: '*',
          closure_type: 'requester',
          buyer_fee_bps: 750,
          worker_fee_bps: 0,
          min_fee_minor: '25',
          referral_bps: 0,
          referral_min_minor: '0',
        },
        {
          is_code_bounty: '*',
          closure_type: 'quorum',
          buyer_fee_bps: 750,
          worker_fee_bps: 0,
          min_fee_minor: '25',
          referral_bps: 0,
          referral_min_minor: '0',
        },
      ],
      notes: 'System bootstrap policy (legacy bounties_v1 defaults)',
    },
    {
      product: 'clawtips',
      policy_id: 'tips_v1',
      discount: { enabled: false, max_bps: 0 },
      rules: [
        {
          is_code_bounty: '*',
          closure_type: '*',
          buyer_fee_bps: 0,
          worker_fee_bps: 0,
          min_fee_minor: '0',
          referral_bps: 0,
          referral_min_minor: '0',
        },
      ],
      notes: 'System bootstrap policy (legacy tips_v1 defaults)',
    },
  ];
}

async function ensureBootstrapPolicies(env: Env): Promise<void> {
  if (BOOTSTRAP_PROMISE) {
    return BOOTSTRAP_PROMISE;
  }

  BOOTSTRAP_PROMISE = (async () => {
    const actor = 'system:bootstrap';

    for (const seed of defaultPolicySeeds()) {
      const existing = await getPolicyVersionRow(env, seed.product, seed.policy_id, 1);
      if (existing) continue;

      const createdAt = nowIso();
      const definition = policyFromCreateInput(seed.product, seed.policy_id, 1, seed.rules, seed.discount);
      const hash = await hashPolicy(definition);

      try {
        await env.CUTS_DB.prepare(
          `INSERT INTO policy_versions (
            product,
            policy_id,
            version,
            status,
            policy_json,
            policy_hash_b64u,
            notes,
            created_by,
            created_at,
            activated_by,
            activated_at
          ) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            seed.product,
            seed.policy_id,
            1,
            JSON.stringify(definition),
            hash,
            seed.notes,
            actor,
            createdAt,
            actor,
            createdAt
          )
          .run();
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (!message.includes('UNIQUE')) {
          throw err;
        }
      }

      const inserted = await getPolicyVersionRow(env, seed.product, seed.policy_id, 1);
      if (!inserted) {
        throw new Error('POLICY_BOOTSTRAP_FAILED');
      }

      await insertPolicyAudit(env, {
        product: seed.product,
        policy_id: seed.policy_id,
        policy_version: 1,
        action: 'create_version',
        actor,
        created_at: createdAt,
        details: {
          source: 'bootstrap',
          status: 'active',
          policy_hash_b64u: hash,
        },
      });

      await insertPolicyAudit(env, {
        product: seed.product,
        policy_id: seed.policy_id,
        policy_version: 1,
        action: 'activate_version',
        actor,
        created_at: createdAt,
        details: {
          source: 'bootstrap',
          status: 'active',
          policy_hash_b64u: hash,
        },
      });
    }
  })().catch((err) => {
    BOOTSTRAP_PROMISE = null;
    throw err;
  });

  return BOOTSTRAP_PROMISE;
}

function selectRule(params: { closure_type: string; is_code_bounty: boolean }, policy: PolicyDefinition): PolicyRule | null {
  const codeSelector: CodeSelector = params.is_code_bounty ? 'true' : 'false';

  const exact =
    policy.rules.find((rule) => rule.closure_type === params.closure_type && rule.is_code_bounty === codeSelector) ?? null;
  if (exact) return exact;

  const wildcardCode =
    policy.rules.find((rule) => rule.closure_type === params.closure_type && rule.is_code_bounty === '*') ?? null;
  if (wildcardCode) return wildcardCode;

  const any = policy.rules.find((rule) => rule.closure_type === '*' && (rule.is_code_bounty === codeSelector || rule.is_code_bounty === '*')) ?? null;
  return any;
}

function ceilDiv(numerator: bigint, denominator: bigint): bigint {
  if (denominator <= 0n) throw new Error('Invalid divisor');
  return (numerator + denominator - 1n) / denominator;
}

export function computeFee(principalMinor: bigint, rateBps: number, minFeeMinor: bigint): { feeMinor: bigint; floorApplied: boolean } {
  if (rateBps < 0 || rateBps > 10_000) {
    throw new Error('INVALID_RATE_BPS');
  }

  const raw = rateBps === 0 ? 0n : ceilDiv(principalMinor * BigInt(rateBps), 10_000n);
  const floorApplied = raw < minFeeMinor;
  const feeMinor = floorApplied ? minFeeMinor : raw;

  return { feeMinor, floorApplied };
}

function computeDiscountMinor(amountMinor: bigint, discountBps: number): bigint {
  if (discountBps <= 0) return 0n;
  return (amountMinor * BigInt(discountBps)) / 10_000n;
}

function parseOptionalReferrer(params: Record<string, unknown>): { referrer_did: string; referral_code?: string } | null {
  const rawReferrer = params.referrer_did;
  if (!isNonEmptyString(rawReferrer)) return null;

  const referrer = rawReferrer.trim();
  if (!referrer.startsWith('did:')) return null;

  const rawCode = params.referral_code;
  const referral_code = isNonEmptyString(rawCode) ? rawCode.trim() : undefined;

  return referral_code ? { referrer_did: referrer, referral_code } : { referrer_did: referrer };
}

function parseDiscountBpsRequested(params: Record<string, unknown>): number | null {
  const value = params.discount_bps;
  if (value === undefined || value === null) return 0;
  if (typeof value !== 'number' || !Number.isInteger(value)) return null;
  if (value < 0 || value > 10_000) return null;
  return value;
}

function sumFeesMinor(fees: FeeItem[], payer?: FeePayer): bigint {
  let total = 0n;
  for (const fee of fees) {
    if (payer && fee.payer !== payer) continue;
    const amount = parseNonNegativeMinor(fee.amount_minor);
    if (amount === null) throw new Error('INVALID_FEE_AMOUNT');
    total += amount;
  }
  return total;
}

function normalizeFeeSplit(splitRaw: unknown): FeeSplit | null {
  if (!isRecord(splitRaw)) return null;

  const kind = splitRaw.kind;
  const account = splitRaw.account;
  const bucket = splitRaw.bucket;
  const amount_minor = splitRaw.amount_minor;

  if (kind !== 'platform' && kind !== 'referral') return null;
  if (!isNonEmptyString(account)) return null;
  if (bucket !== 'A' && bucket !== 'F') return null;

  const parsedAmount = parseNonNegativeMinorString(amount_minor);
  if (!parsedAmount) return null;

  if (kind === 'platform' && bucket !== 'F') return null;
  if (kind === 'referral' && bucket !== 'A') return null;

  const referrer_did = isNonEmptyString(splitRaw.referrer_did) ? splitRaw.referrer_did.trim() : undefined;
  const referral_code = isNonEmptyString(splitRaw.referral_code) ? splitRaw.referral_code.trim() : undefined;

  if (kind === 'referral' && (!referrer_did || !referrer_did.startsWith('did:'))) return null;

  return {
    kind,
    account: account.trim(),
    bucket,
    amount_minor: parsedAmount,
    ...(referrer_did ? { referrer_did } : {}),
    ...(referral_code ? { referral_code } : {}),
  };
}

function normalizeFeeItem(itemRaw: unknown): FeeItem | null {
  if (!isRecord(itemRaw)) return null;

  const kind = itemRaw.kind;
  const payer = itemRaw.payer;
  const amount_minor = itemRaw.amount_minor;
  const rate_bps = itemRaw.rate_bps;
  const min_fee_minor = itemRaw.min_fee_minor;
  const floor_applied = itemRaw.floor_applied;

  if (kind !== 'platform') return null;
  if (payer !== 'buyer' && payer !== 'worker') return null;

  const parsedAmount = parseNonNegativeMinorString(amount_minor);
  if (!parsedAmount) return null;

  if (typeof rate_bps !== 'number' || !Number.isFinite(rate_bps)) return null;

  const parsedMinFee = parseNonNegativeMinorString(min_fee_minor);
  if (!parsedMinFee) return null;

  if (typeof floor_applied !== 'boolean') return null;

  let splits: FeeSplit[] | undefined;
  if (itemRaw.splits !== undefined) {
    if (!Array.isArray(itemRaw.splits)) return null;
    const parsedSplits: FeeSplit[] = [];
    for (const splitRaw of itemRaw.splits) {
      const split = normalizeFeeSplit(splitRaw);
      if (!split) return null;
      parsedSplits.push(split);
    }

    if (parsedSplits.length > 0) {
      const splitTotal = parsedSplits.reduce((acc, split) => {
        const amount = parseNonNegativeMinor(split.amount_minor);
        if (amount === null) return acc;
        return acc + amount;
      }, 0n);

      const feeAmount = parseNonNegativeMinor(parsedAmount);
      if (feeAmount === null || splitTotal !== feeAmount) {
        return null;
      }

      splits = parsedSplits;
    }
  }

  const normalized: FeeItem = {
    kind: 'platform',
    payer,
    amount_minor: parsedAmount,
    rate_bps,
    min_fee_minor: parsedMinFee,
    floor_applied,
  };

  if (isNonEmptyString(itemRaw.base_amount_minor)) {
    const base = parseNonNegativeMinorString(itemRaw.base_amount_minor);
    if (!base) return null;
    normalized.base_amount_minor = base;
  }

  if (itemRaw.discount_bps_applied !== undefined) {
    const bps = parseBps(itemRaw.discount_bps_applied);
    if (bps === null) return null;
    normalized.discount_bps_applied = bps;
  }

  if (itemRaw.discount_minor !== undefined) {
    const discountMinor = parseNonNegativeMinorString(itemRaw.discount_minor);
    if (!discountMinor) return null;
    normalized.discount_minor = discountMinor;
  }

  if (splits && splits.length > 0) {
    normalized.splits = splits;
  }

  return normalized;
}

function withReferralSplits(
  fees: FeeItem[],
  params: {
    referral_bps: number;
    referral_min_minor: string;
    referrer: { referrer_did: string; referral_code?: string } | null;
    clearing_account: string;
  }
): { fees: FeeItem[]; referral_payout_minor: bigint } {
  const feeTotal = sumFeesMinor(fees);

  if (!params.referrer || params.referral_bps <= 0 || feeTotal <= 0n) {
    const feesWithPlatformSplit = fees.map((fee) => {
      const amount = parseNonNegativeMinor(fee.amount_minor) ?? 0n;
      if (amount <= 0n) return fee;
      return {
        ...fee,
        splits: [
          {
            kind: 'platform' as const,
            account: params.clearing_account,
            bucket: 'F' as const,
            amount_minor: amount.toString(),
          },
        ],
      };
    });

    return { fees: feesWithPlatformSplit, referral_payout_minor: 0n };
  }

  const referralMin = parseNonNegativeMinor(params.referral_min_minor) ?? 0n;
  let referralMinor = (feeTotal * BigInt(params.referral_bps)) / 10_000n;
  if (referralMinor > 0n && referralMinor < referralMin) {
    referralMinor = referralMin;
  }
  if (referralMinor > feeTotal) referralMinor = feeTotal;

  let remainingReferral = referralMinor;

  const nextFees: FeeItem[] = fees.map((fee) => {
    const feeAmount = parseNonNegativeMinor(fee.amount_minor) ?? 0n;
    if (feeAmount <= 0n) return fee;

    const referralChunk = remainingReferral > 0n ? (remainingReferral > feeAmount ? feeAmount : remainingReferral) : 0n;
    remainingReferral -= referralChunk;

    const platformChunk = feeAmount - referralChunk;
    const splits: FeeSplit[] = [];

    if (platformChunk > 0n) {
      splits.push({
        kind: 'platform',
        account: params.clearing_account,
        bucket: 'F',
        amount_minor: platformChunk.toString(),
      });
    }

    if (referralChunk > 0n) {
      splits.push({
        kind: 'referral',
        account: params.referrer!.referrer_did,
        bucket: 'A',
        amount_minor: referralChunk.toString(),
        referrer_did: params.referrer!.referrer_did,
        ...(params.referrer!.referral_code ? { referral_code: params.referrer!.referral_code } : {}),
      });
    }

    return { ...fee, splits };
  });

  return { fees: nextFees, referral_payout_minor: referralMinor };
}

function parseFeeApplySnapshot(input: unknown): FeeApplySnapshot | null {
  if (!isRecord(input)) return null;

  const policy_id = input.policy_id;
  const policy_version = input.policy_version;
  const policy_hash_b64u = input.policy_hash_b64u;
  const buyer_total_minor = input.buyer_total_minor;
  const worker_net_minor = input.worker_net_minor;
  const feesRaw = input.fees;

  if (!isNonEmptyString(policy_id)) return null;
  if (!isNonEmptyString(policy_version)) return null;
  if (!isNonEmptyString(policy_hash_b64u)) return null;

  const buyerTotal = parsePositiveMinor(buyer_total_minor);
  if (buyerTotal === null) return null;

  const workerNet = parseNonNegativeMinor(worker_net_minor);
  if (workerNet === null) return null;

  if (!Array.isArray(feesRaw)) return null;

  const fees: FeeItem[] = [];
  for (const feeRaw of feesRaw) {
    const fee = normalizeFeeItem(feeRaw);
    if (!fee) return null;
    fees.push(fee);
  }

  return {
    policy_id: policy_id.trim(),
    policy_version: policy_version.trim(),
    policy_hash_b64u: policy_hash_b64u.trim(),
    buyer_total_minor: buyerTotal.toString(),
    worker_net_minor: workerNet.toString(),
    fees,
  };
}

export function analyzeSnapshotForApply(snapshot: FeeApplySnapshot, fallbackClearingAccount: string): SnapshotAnalysis {
  const buyerTotal = parsePositiveMinor(snapshot.buyer_total_minor);
  const workerNet = parseNonNegativeMinor(snapshot.worker_net_minor);
  if (buyerTotal === null || workerNet === null) {
    throw new Error('SNAPSHOT_INVALID_AMOUNTS');
  }

  let totalFee = 0n;
  let buyerFee = 0n;
  let workerFee = 0n;
  let referralFee = 0n;

  const transfers: ApplyTransfer[] = [];

  for (let feeIndex = 0; feeIndex < snapshot.fees.length; feeIndex++) {
    const fee = snapshot.fees[feeIndex];
    if (!fee) throw new Error('SNAPSHOT_INVALID_FEE_ITEM');

    const amount = parseNonNegativeMinor(fee.amount_minor);
    if (amount === null) throw new Error('SNAPSHOT_INVALID_FEE_AMOUNT');

    totalFee += amount;
    if (fee.payer === 'buyer') buyerFee += amount;
    if (fee.payer === 'worker') workerFee += amount;

    const feeSplits = fee.splits && fee.splits.length > 0
      ? fee.splits
      : [
          {
            kind: 'platform' as const,
            account: fallbackClearingAccount,
            bucket: 'F' as const,
            amount_minor: fee.amount_minor,
          },
        ];

    let splitTotal = 0n;
    for (const split of feeSplits) {
      const splitAmount = parseNonNegativeMinor(split.amount_minor);
      if (splitAmount === null) throw new Error('SNAPSHOT_INVALID_SPLIT_AMOUNT');
      if (splitAmount === 0n) continue;

      splitTotal += splitAmount;
      if (split.kind === 'referral') referralFee += splitAmount;

      transfers.push({
        transfer_index: transfers.length,
        fee_index: feeIndex,
        fee_kind: fee.kind,
        payer: fee.payer,
        split_kind: split.kind,
        to_account: split.account,
        to_bucket: split.bucket,
        amount_minor: splitAmount.toString(),
        ...(split.referrer_did ? { referrer_did: split.referrer_did } : {}),
        ...(split.referral_code ? { referral_code: split.referral_code } : {}),
      });
    }

    if (splitTotal !== amount) {
      throw new Error('SNAPSHOT_SPLIT_SUM_MISMATCH');
    }
  }

  if (workerNet + totalFee !== buyerTotal) {
    throw new Error('SNAPSHOT_TOTAL_MISMATCH');
  }

  const principalFromBuyer = buyerTotal - buyerFee;
  const principalFromWorker = workerNet + workerFee;

  if (principalFromBuyer !== principalFromWorker || principalFromBuyer <= 0n) {
    throw new Error('SNAPSHOT_PRINCIPAL_MISMATCH');
  }

  const platformRetained = totalFee - referralFee;

  return {
    principal_minor: principalFromBuyer,
    buyer_total_minor: buyerTotal,
    worker_net_minor: workerNet,
    total_fee_minor: totalFee,
    buyer_fee_minor: buyerFee,
    worker_fee_minor: workerFee,
    referral_fee_minor: referralFee,
    platform_retained_minor: platformRetained,
    transfers,
  };
}

function parseMonthParam(month: string | null): string | null {
  if (!month) return null;
  const trimmed = month.trim();
  if (!/^\d{4}-\d{2}$/.test(trimmed)) return null;
  return trimmed;
}

function monthFromIsoOrNow(isoMaybe: string | null): string {
  if (isoMaybe && isoMaybe.trim().length > 0) {
    const date = new Date(isoMaybe);
    if (Number.isFinite(date.getTime())) {
      const year = date.getUTCFullYear().toString().padStart(4, '0');
      const month = (date.getUTCMonth() + 1).toString().padStart(2, '0');
      return `${year}-${month}`;
    }
  }

  const now = new Date();
  const year = now.getUTCFullYear().toString().padStart(4, '0');
  const month = (now.getUTCMonth() + 1).toString().padStart(2, '0');
  return `${year}-${month}`;
}

async function getFeeApplyEventByIdempotencyKey(env: Env, idempotencyKey: string): Promise<FeeApplyEventRow | null> {
  const row = await env.CUTS_DB.prepare(
    `SELECT
      apply_id,
      idempotency_key,
      product,
      settlement_ref,
      month,
      currency,
      policy_id,
      policy_version,
      policy_hash_b64u,
      principal_minor,
      buyer_total_minor,
      worker_net_minor,
      total_fee_minor,
      platform_fee_minor,
      referral_fee_minor,
      platform_retained_minor,
      transfer_plan_json,
      snapshot_json,
      context_json,
      ledger_fee_event_ids_json,
      ledger_referral_event_ids_json,
      created_at,
      finalized_at
    FROM fee_apply_events
    WHERE idempotency_key = ?`
  )
    .bind(idempotencyKey)
    .first();

  return parseFeeApplyEventRow(row);
}

function parseJsonArrayString(value: string | null): string[] {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0).map((entry) => entry.trim());
  } catch {
    return [];
  }
}

function arraysEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function parseIsoTimestamp(input: unknown): string | null {
  if (!isNonEmptyString(input)) return null;
  const trimmed = input.trim();
  const date = new Date(trimmed);
  if (!Number.isFinite(date.getTime())) return null;
  return date.toISOString();
}

function asVersionInt(version: string): number | null {
  if (!/^[0-9]+$/.test(version)) return null;
  const parsed = Number(version);
  if (!Number.isInteger(parsed) || parsed <= 0) return null;
  return parsed;
}

function renderSkillMarkdown(origin: string): string {
  const metadata = {
    name: 'clawcuts',
    version: '2',
    description: 'Fee policy control plane + simulation + deterministic settlement apply + reporting.',
    endpoints: [
      { method: 'GET', path: '/health' },
      { method: 'POST', path: '/v1/fees/simulate' },
      { method: 'POST', path: '/v1/fees/apply (auth)' },
      { method: 'POST', path: '/v1/fees/apply/finalize (auth)' },
      { method: 'POST', path: '/v1/policies/versions (admin)' },
      { method: 'POST', path: '/v1/policies/activate (admin)' },
      { method: 'POST', path: '/v1/policies/deactivate (admin)' },
      { method: 'GET', path: '/v1/policies/{product}/{policy_id}/active' },
      { method: 'GET', path: '/v1/policies/{product}/{policy_id}/history' },
      { method: 'GET', path: '/v1/reports/revenue/monthly (admin)' },
    ],
  };

  return `---\nmetadata: '${JSON.stringify(metadata)}'\n---\n\n# clawcuts\n\nEndpoints:\n- GET /health\n- POST /v1/fees/simulate\n- POST /v1/fees/apply (auth)\n- POST /v1/fees/apply/finalize (auth)\n- POST /v1/policies/versions (admin)\n- POST /v1/policies/activate (admin)\n- POST /v1/policies/deactivate (admin)\n- GET /v1/policies/{product}/{policy_id}/active\n- GET /v1/policies/{product}/{policy_id}/history(.csv)\n- GET /v1/reports/revenue/monthly?month=YYYY-MM[&product=...][&format=csv] (admin)\n\nSimulation example:\n\n\`\`\`bash\ncurl -sS \\\n  -X POST "${origin}/v1/fees/simulate" \\\n  -H 'content-type: application/json' \\\n  -d '{"product":"clawbounties","policy_id":"bounties_v1","amount_minor":"5000","currency":"USD","params":{"is_code_bounty":true,"closure_type":"test"}}'\n\`\`\`\n`;
}

async function handleCreatePolicyVersion(request: Request, env: Env, version: string): Promise<Response> {
  const adminCheck = requireAdmin(request, env, version);
  if (adminCheck) return adminCheck;

  const body = await request.json().catch(() => null);
  if (!isRecord(body)) {
    return errorResponse('INVALID_JSON', 'Request body must be a JSON object', 400, undefined, version);
  }

  const product = body.product;
  const policy_id = body.policy_id;
  const rulesRaw = body.rules;
  const discountRaw = body.discount;
  const notesRaw = body.notes;
  const actorRaw = body.actor;
  const activateRaw = body.activate;

  if (!isNonEmptyString(product)) {
    return errorResponse('INVALID_REQUEST', 'product is required', 400, undefined, version);
  }
  if (!isNonEmptyString(policy_id)) {
    return errorResponse('INVALID_REQUEST', 'policy_id is required', 400, undefined, version);
  }
  if (!Array.isArray(rulesRaw) || rulesRaw.length === 0) {
    return errorResponse('INVALID_REQUEST', 'rules must be a non-empty array', 400, undefined, version);
  }
  if (!isNonEmptyString(actorRaw)) {
    return errorResponse('INVALID_REQUEST', 'actor is required', 400, undefined, version);
  }

  const rules: PolicyRule[] = [];
  for (const ruleRaw of rulesRaw) {
    const parsedRule = parsePolicyRule(ruleRaw);
    if (!parsedRule) {
      return errorResponse('INVALID_REQUEST', 'rules contains invalid rule entries', 400, undefined, version);
    }
    rules.push(parsedRule);
  }

  const discount = parseDiscountPolicy(discountRaw);
  if (!discount) {
    return errorResponse('INVALID_REQUEST', 'discount is invalid', 400, undefined, version);
  }

  const activate = activateRaw === undefined ? false : Boolean(activateRaw);
  const notes = isNonEmptyString(notesRaw) ? notesRaw.trim() : null;
  const actor = actorRaw.trim();

  const normalizedProduct = product.trim();
  const normalizedPolicyId = policy_id.trim();

  let policyVersion: number;
  try {
    policyVersion = await getNextPolicyVersion(env, normalizedProduct, normalizedPolicyId);
  } catch {
    return errorResponse('POLICY_VERSION_COMPUTE_FAILED', 'Failed to compute next policy version', 500, undefined, version);
  }

  const definition = policyFromCreateInput(normalizedProduct, normalizedPolicyId, policyVersion, rules, discount);
  const policyHash = await hashPolicy(definition);
  const createdAt = nowIso();

  try {
    await env.CUTS_DB.prepare(
      `INSERT INTO policy_versions (
        product,
        policy_id,
        version,
        status,
        policy_json,
        policy_hash_b64u,
        notes,
        created_by,
        created_at
      ) VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?)`
    )
      .bind(
        normalizedProduct,
        normalizedPolicyId,
        policyVersion,
        JSON.stringify(definition),
        policyHash,
        notes,
        actor,
        createdAt
      )
      .run();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('UNIQUE')) {
      return errorResponse('VERSION_CONFLICT', 'Policy version conflict, retry request', 409, undefined, version);
    }
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  await insertPolicyAudit(env, {
    product: normalizedProduct,
    policy_id: normalizedPolicyId,
    policy_version: policyVersion,
    action: 'create_version',
    actor,
    created_at: createdAt,
    details: {
      status: 'draft',
      policy_hash_b64u: policyHash,
      notes,
    },
  });

  let status: PolicyStatus = 'draft';
  if (activate) {
    try {
      await activatePolicyVersion(env, normalizedProduct, normalizedPolicyId, policyVersion, actor, createdAt);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return errorResponse('POLICY_ACTIVATION_FAILED', message, 500, undefined, version);
    }

    await insertPolicyAudit(env, {
      product: normalizedProduct,
      policy_id: normalizedPolicyId,
      policy_version: policyVersion,
      action: 'activate_version',
      actor,
      created_at: createdAt,
      details: {
        policy_hash_b64u: policyHash,
      },
    });

    status = 'active';
  }

  return jsonResponse(
    {
      policy: {
        product: normalizedProduct,
        id: normalizedPolicyId,
        version: policyVersion.toString(),
        hash_b64u: policyHash,
        status,
      },
      created_at: createdAt,
    },
    201,
    version
  );
}

async function handleActivatePolicyVersion(request: Request, env: Env, version: string): Promise<Response> {
  const adminCheck = requireAdmin(request, env, version);
  if (adminCheck) return adminCheck;

  const body = await request.json().catch(() => null);
  if (!isRecord(body)) {
    return errorResponse('INVALID_JSON', 'Request body must be a JSON object', 400, undefined, version);
  }

  const product = body.product;
  const policy_id = body.policy_id;
  const versionRaw = body.version;
  const actorRaw = body.actor;

  if (!isNonEmptyString(product) || !isNonEmptyString(policy_id) || !isNonEmptyString(actorRaw)) {
    return errorResponse('INVALID_REQUEST', 'product, policy_id, and actor are required', 400, undefined, version);
  }

  const targetVersion = parsePositiveInt(versionRaw);
  if (!targetVersion) {
    return errorResponse('INVALID_REQUEST', 'version must be a positive integer', 400, undefined, version);
  }

  const target = await getPolicyVersionRow(env, product.trim(), policy_id.trim(), targetVersion);
  if (!target) {
    return errorResponse('POLICY_NOT_FOUND', 'Policy version not found', 404, undefined, version);
  }

  const at = nowIso();

  try {
    await activatePolicyVersion(env, product.trim(), policy_id.trim(), targetVersion, actorRaw.trim(), at);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorResponse('POLICY_ACTIVATION_FAILED', message, 500, undefined, version);
  }

  await insertPolicyAudit(env, {
    product: product.trim(),
    policy_id: policy_id.trim(),
    policy_version: targetVersion,
    action: 'activate_version',
    actor: actorRaw.trim(),
    created_at: at,
    details: {
      policy_hash_b64u: target.policy_hash_b64u,
    },
  });

  return jsonResponse(
    {
      policy: {
        product: target.product,
        id: target.policy_id,
        version: target.version.toString(),
        hash_b64u: target.policy_hash_b64u,
        status: 'active',
      },
      activated_at: at,
    },
    200,
    version
  );
}

async function handleDeactivatePolicyVersion(request: Request, env: Env, version: string): Promise<Response> {
  const adminCheck = requireAdmin(request, env, version);
  if (adminCheck) return adminCheck;

  const body = await request.json().catch(() => null);
  if (!isRecord(body)) {
    return errorResponse('INVALID_JSON', 'Request body must be a JSON object', 400, undefined, version);
  }

  const product = body.product;
  const policy_id = body.policy_id;
  const versionRaw = body.version;
  const actorRaw = body.actor;

  if (!isNonEmptyString(product) || !isNonEmptyString(policy_id) || !isNonEmptyString(actorRaw)) {
    return errorResponse('INVALID_REQUEST', 'product, policy_id, and actor are required', 400, undefined, version);
  }

  const targetVersion = parsePositiveInt(versionRaw);
  if (!targetVersion) {
    return errorResponse('INVALID_REQUEST', 'version must be a positive integer', 400, undefined, version);
  }

  const target = await getPolicyVersionRow(env, product.trim(), policy_id.trim(), targetVersion);
  if (!target) {
    return errorResponse('POLICY_NOT_FOUND', 'Policy version not found', 404, undefined, version);
  }

  const at = nowIso();

  try {
    await deactivatePolicyVersion(env, product.trim(), policy_id.trim(), targetVersion, actorRaw.trim(), at);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorResponse('POLICY_DEACTIVATION_FAILED', message, 500, undefined, version);
  }

  await insertPolicyAudit(env, {
    product: product.trim(),
    policy_id: policy_id.trim(),
    policy_version: targetVersion,
    action: 'deactivate_version',
    actor: actorRaw.trim(),
    created_at: at,
    details: {
      policy_hash_b64u: target.policy_hash_b64u,
    },
  });

  return jsonResponse(
    {
      policy: {
        product: target.product,
        id: target.policy_id,
        version: target.version.toString(),
        hash_b64u: target.policy_hash_b64u,
        status: 'inactive',
      },
      deactivated_at: at,
    },
    200,
    version
  );
}

async function handleGetActivePolicy(product: string, policyId: string, env: Env, version: string): Promise<Response> {
  await ensureBootstrapPolicies(env);

  const row = await getActivePolicyVersionRow(env, product, policyId);
  if (!row) {
    return errorResponse('POLICY_NOT_ACTIVE', 'No active policy version found', 404, undefined, version);
  }

  const definition = parseStoredPolicyDefinition(row);
  if (!definition) {
    return errorResponse('POLICY_CORRUPT', 'Stored policy definition is invalid', 500, undefined, version);
  }

  return jsonResponse(
    {
      policy: {
        product: row.product,
        id: row.policy_id,
        version: row.version.toString(),
        hash_b64u: row.policy_hash_b64u,
        status: row.status,
        notes: row.notes,
      },
      definition,
      timestamps: {
        created_at: row.created_at,
        activated_at: row.activated_at,
        deactivated_at: row.deactivated_at,
      },
      actor: {
        created_by: row.created_by,
        activated_by: row.activated_by,
        deactivated_by: row.deactivated_by,
      },
    },
    200,
    version
  );
}

async function handlePolicyHistory(product: string, policyId: string, env: Env, version: string): Promise<Response> {
  await ensureBootstrapPolicies(env);

  const versions = await listPolicyVersions(env, product, policyId);
  const audit = await listPolicyAuditEvents(env, product, policyId);

  if (versions.length === 0) {
    return errorResponse('POLICY_NOT_FOUND', 'Policy not found', 404, undefined, version);
  }

  return jsonResponse(
    {
      product,
      policy_id: policyId,
      versions: versions.map((row) => ({
        version: row.version.toString(),
        hash_b64u: row.policy_hash_b64u,
        status: row.status,
        notes: row.notes,
        created_at: row.created_at,
        activated_at: row.activated_at,
        deactivated_at: row.deactivated_at,
        created_by: row.created_by,
        activated_by: row.activated_by,
        deactivated_by: row.deactivated_by,
      })),
      audit: audit.map((row) => {
        let details: Record<string, unknown> | null = null;
        if (row.details_json) {
          try {
            const parsed = JSON.parse(row.details_json);
            if (isRecord(parsed)) details = parsed;
          } catch {
            details = null;
          }
        }

        return {
          audit_id: row.audit_id,
          action: row.action,
          actor: row.actor,
          policy_version: row.policy_version === null ? null : row.policy_version.toString(),
          created_at: row.created_at,
          details,
        };
      }),
    },
    200,
    version
  );
}

async function handlePolicyHistoryCsv(product: string, policyId: string, env: Env, version: string): Promise<Response> {
  await ensureBootstrapPolicies(env);

  const audit = await listPolicyAuditEvents(env, product, policyId);
  if (audit.length === 0) {
    return errorResponse('POLICY_NOT_FOUND', 'Policy not found', 404, undefined, version);
  }

  const csv = toCsv(
    ['product', 'policy_id', 'policy_version', 'action', 'actor', 'created_at', 'details_json'],
    audit.map((row) => [
      row.product,
      row.policy_id,
      row.policy_version === null ? '' : row.policy_version.toString(),
      row.action,
      row.actor,
      row.created_at,
      row.details_json ?? '',
    ])
  );

  return textResponse(csv, 'text/csv; charset=utf-8', 200, version);
}

async function handleSimulateFees(request: Request, env: Env, version: string): Promise<Response> {
  await ensureBootstrapPolicies(env);

  const body = await request.json().catch(() => null);
  if (!isRecord(body)) {
    return errorResponse('INVALID_JSON', 'Request body must be valid JSON', 400, undefined, version);
  }

  const product = body.product;
  const policy_id = body.policy_id;
  const policy_version_raw = body.policy_version;
  const currency = body.currency;
  const amount_minor = body.amount_minor;
  const params = body.params;

  if (!isNonEmptyString(product)) {
    return errorResponse('INVALID_REQUEST', 'product is required', 400, undefined, version);
  }
  if (!isNonEmptyString(policy_id)) {
    return errorResponse('INVALID_REQUEST', 'policy_id is required', 400, undefined, version);
  }
  if (!isNonEmptyString(currency) || currency.trim().toUpperCase() !== 'USD') {
    return errorResponse('UNSUPPORTED_CURRENCY', 'Only USD is supported (amount_minor in cents)', 400, undefined, version);
  }

  const principalMinor = parsePositiveMinor(amount_minor);
  if (principalMinor === null) {
    return errorResponse('INVALID_REQUEST', 'amount_minor must be a positive integer string', 400, undefined, version);
  }

  const normalizedProduct = product.trim();
  const normalizedPolicyId = policy_id.trim();

  let row: PolicyVersionRow | null = null;
  if (policy_version_raw !== undefined && policy_version_raw !== null) {
    const policyVersion = parsePositiveInt(policy_version_raw);
    if (!policyVersion) {
      return errorResponse('INVALID_REQUEST', 'policy_version must be a positive integer', 400, undefined, version);
    }

    row = await getPolicyVersionRow(env, normalizedProduct, normalizedPolicyId, policyVersion);
    if (!row) {
      return errorResponse('POLICY_NOT_FOUND', 'Requested policy version not found', 404, undefined, version);
    }
  } else {
    row = await getActivePolicyVersionRow(env, normalizedProduct, normalizedPolicyId);
    if (!row) {
      return errorResponse('POLICY_NOT_ACTIVE', 'No active policy version found', 404, undefined, version);
    }
  }

  const policy = parseStoredPolicyDefinition(row);
  if (!policy) {
    return errorResponse('POLICY_CORRUPT', 'Stored policy definition is invalid', 500, undefined, version);
  }

  if (!isRecord(params)) {
    return errorResponse('INVALID_REQUEST', 'params must be an object', 400, undefined, version);
  }

  let rule: PolicyRule | null = null;
  let closureType = '*';
  let isCodeBounty = false;

  if (policy.product === 'clawbounties') {
    const closureRaw = params.closure_type;
    if (!isNonEmptyString(closureRaw)) {
      return errorResponse('INVALID_REQUEST', 'params.closure_type is required for clawbounties policies', 400, undefined, version);
    }

    closureType = closureRaw.trim();
    if (!BOUNTIES_CLOSURES.has(closureType)) {
      return errorResponse('INVALID_REQUEST', 'params.closure_type must be one of test|requester|quorum', 400, undefined, version);
    }

    const codeRaw = params.is_code_bounty;
    if (typeof codeRaw !== 'boolean') {
      return errorResponse('INVALID_REQUEST', 'params.is_code_bounty must be a boolean', 400, undefined, version);
    }
    isCodeBounty = codeRaw;

    if (closureType === 'test' && !isCodeBounty) {
      return errorResponse('INVALID_REQUEST', 'closure_type=test requires params.is_code_bounty=true', 400, undefined, version);
    }

    rule = selectRule({ closure_type: closureType, is_code_bounty: isCodeBounty }, policy);
  } else {
    rule = policy.rules[0] ?? null;
  }

  if (!rule) {
    return errorResponse('RULE_NOT_FOUND', 'No fee rule matches the provided params', 400, undefined, version);
  }

  const buyerMinFee = parseNonNegativeMinor(rule.min_fee_minor);
  const referralMin = parseNonNegativeMinor(rule.referral_min_minor);
  if (buyerMinFee === null || referralMin === null) {
    return errorResponse('POLICY_CORRUPT', 'Policy contains invalid minor-unit values', 500, undefined, version);
  }

  const requestedDiscountBps = parseDiscountBpsRequested(params);
  if (requestedDiscountBps === null) {
    return errorResponse('INVALID_REQUEST', 'params.discount_bps must be an integer between 0 and 10000', 400, undefined, version);
  }

  const appliedDiscountBps = policy.discount.enabled ? Math.min(requestedDiscountBps, policy.discount.max_bps) : 0;

  const buyerFeeBase = computeFee(principalMinor, rule.buyer_fee_bps, buyerMinFee);
  const workerFee = computeFee(principalMinor, rule.worker_fee_bps, 0n);

  const buyerDiscountMinor = computeDiscountMinor(buyerFeeBase.feeMinor, appliedDiscountBps);
  const buyerFeeFinalMinor = buyerFeeBase.feeMinor - buyerDiscountMinor;

  const fees: FeeItem[] = [];

  const includeBuyerFee =
    buyerFeeFinalMinor > 0n ||
    rule.buyer_fee_bps > 0 ||
    buyerMinFee > 0n ||
    policy.product === 'clawtips' ||
    buyerDiscountMinor > 0n;

  if (includeBuyerFee) {
    fees.push({
      kind: 'platform',
      payer: 'buyer',
      amount_minor: buyerFeeFinalMinor.toString(),
      rate_bps: rule.buyer_fee_bps,
      min_fee_minor: rule.min_fee_minor,
      floor_applied: buyerFeeBase.floorApplied,
      ...(buyerFeeBase.feeMinor !== buyerFeeFinalMinor ? { base_amount_minor: buyerFeeBase.feeMinor.toString() } : {}),
      ...(appliedDiscountBps > 0 ? { discount_bps_applied: appliedDiscountBps } : {}),
      ...(buyerDiscountMinor > 0n ? { discount_minor: buyerDiscountMinor.toString() } : {}),
    });
  }

  if (workerFee.feeMinor > 0n || rule.worker_fee_bps > 0) {
    fees.push({
      kind: 'platform',
      payer: 'worker',
      amount_minor: workerFee.feeMinor.toString(),
      rate_bps: rule.worker_fee_bps,
      min_fee_minor: '0',
      floor_applied: workerFee.floorApplied,
    });
  }

  if (fees.length === 0) {
    fees.push({
      kind: 'platform',
      payer: 'buyer',
      amount_minor: '0',
      rate_bps: 0,
      min_fee_minor: '0',
      floor_applied: false,
    });
  }

  const referrer = parseOptionalReferrer(params);
  const splitResult = withReferralSplits(fees, {
    referral_bps: rule.referral_bps,
    referral_min_minor: rule.referral_min_minor,
    referrer,
    clearing_account: env.CUTS_FEE_CLEARING_ACCOUNT?.trim() || DEFAULT_FEE_CLEARING_ACCOUNT,
  });

  const feesWithSplits = splitResult.fees;

  const buyerFeeTotal = sumFeesMinor(feesWithSplits, 'buyer');
  const workerFeeTotal = sumFeesMinor(feesWithSplits, 'worker');
  const totalFeeMinor = buyerFeeTotal + workerFeeTotal;

  const buyerTotalMinor = principalMinor + buyerFeeTotal;
  const workerNetMinor = principalMinor - workerFeeTotal;
  const platformRetainedMinor = totalFeeMinor - splitResult.referral_payout_minor;

  const response: FeeSimulateResponse = {
    policy: {
      id: row.policy_id,
      version: row.version.toString(),
      hash_b64u: row.policy_hash_b64u,
    },
    quote: {
      principal_minor: principalMinor.toString(),
      buyer_total_minor: buyerTotalMinor.toString(),
      worker_net_minor: workerNetMinor.toString(),
      total_fee_minor: totalFeeMinor.toString(),
      referral_payout_minor: splitResult.referral_payout_minor.toString(),
      platform_retained_minor: platformRetainedMinor.toString(),
      fees: feesWithSplits,
    },
  };

  return jsonResponse(response, 200, version);
}

function buildFeeApplyResponse(row: FeeApplyEventRow, deduped: boolean): Response {
  let transfers: ApplyTransfer[] = [];
  try {
    const parsed = JSON.parse(row.transfer_plan_json);
    if (Array.isArray(parsed)) {
      transfers = parsed.filter((entry): entry is ApplyTransfer => isRecord(entry)) as ApplyTransfer[];
    }
  } catch {
    transfers = [];
  }

  const feeEventIds = parseJsonArrayString(row.ledger_fee_event_ids_json);
  const referralEventIds = parseJsonArrayString(row.ledger_referral_event_ids_json);

  return jsonResponse({
    apply_id: row.apply_id,
    idempotency_key: row.idempotency_key,
    deduped,
    product: row.product,
    settlement_ref: row.settlement_ref,
    month: row.month,
    policy: {
      id: row.policy_id,
      version: row.policy_version.toString(),
      hash_b64u: row.policy_hash_b64u,
    },
    fee_summary: {
      principal_minor: row.principal_minor,
      buyer_total_minor: row.buyer_total_minor,
      worker_net_minor: row.worker_net_minor,
      total_fee_minor: row.total_fee_minor,
      platform_fee_minor: row.platform_fee_minor,
      referral_payout_minor: row.referral_fee_minor,
      platform_retained_minor: row.platform_retained_minor,
    },
    transfer_plan: {
      transfers,
    },
    ledger_refs: {
      fee_transfers: feeEventIds,
      referral_transfers: referralEventIds,
    },
    finalized_at: row.finalized_at,
    created_at: row.created_at,
  });
}

async function handleApplyFees(request: Request, env: Env, version: string): Promise<Response> {
  const authCheck = requireApplyAuth(request, env, version);
  if (authCheck) return authCheck;

  await ensureBootstrapPolicies(env);

  const body = await request.json().catch(() => null);
  if (!isRecord(body)) {
    return errorResponse('INVALID_JSON', 'Request body must be a JSON object', 400, undefined, version);
  }

  const idempotency_key = body.idempotency_key;
  const product = body.product;
  const currency = body.currency;
  const settlement_ref = body.settlement_ref;
  const occurred_at = body.occurred_at;
  const snapshotRaw = body.snapshot;
  const contextRaw = body.context;

  if (!isNonEmptyString(idempotency_key)) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required', 400, undefined, version);
  }
  if (!isNonEmptyString(product)) {
    return errorResponse('INVALID_REQUEST', 'product is required', 400, undefined, version);
  }
  if (!isNonEmptyString(currency) || currency.trim().toUpperCase() !== 'USD') {
    return errorResponse('UNSUPPORTED_CURRENCY', 'Only USD is supported', 400, undefined, version);
  }

  const snapshot = parseFeeApplySnapshot(snapshotRaw);
  if (!snapshot) {
    return errorResponse('INVALID_REQUEST', 'snapshot is missing or invalid', 400, undefined, version);
  }

  const snapshotVersion = asVersionInt(snapshot.policy_version);
  if (!snapshotVersion) {
    return errorResponse('INVALID_REQUEST', 'snapshot.policy_version must be a positive integer string', 400, undefined, version);
  }

  const row = await getPolicyVersionRow(env, product.trim(), snapshot.policy_id, snapshotVersion);
  if (!row) {
    return errorResponse('POLICY_NOT_FOUND', 'snapshot references unknown policy version', 422, undefined, version);
  }

  if (row.policy_hash_b64u !== snapshot.policy_hash_b64u) {
    return errorResponse(
      'POLICY_HASH_MISMATCH',
      'snapshot.policy_hash_b64u does not match stored policy hash',
      422,
      {
        expected_policy_hash_b64u: row.policy_hash_b64u,
        received_policy_hash_b64u: snapshot.policy_hash_b64u,
      },
      version
    );
  }

  const normalizedSnapshotJson = JSON.stringify(snapshot);

  const existing = await getFeeApplyEventByIdempotencyKey(env, idempotency_key.trim());
  if (existing) {
    if (
      existing.product !== product.trim() ||
      existing.policy_id !== snapshot.policy_id ||
      existing.policy_version !== snapshotVersion ||
      existing.snapshot_json !== normalizedSnapshotJson
    ) {
      return errorResponse('IDEMPOTENCY_CONFLICT', 'idempotency_key already used with different payload', 409, undefined, version);
    }

    return buildFeeApplyResponse(existing, true);
  }

  let analysis: SnapshotAnalysis;
  try {
    analysis = analyzeSnapshotForApply(snapshot, env.CUTS_FEE_CLEARING_ACCOUNT?.trim() || DEFAULT_FEE_CLEARING_ACCOUNT);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'SNAPSHOT_INVALID';
    return errorResponse('SNAPSHOT_INVALID', message, 422, undefined, version);
  }

  if (analysis.total_fee_minor.toString() !== analysis.buyer_fee_minor.toString() && analysis.worker_fee_minor === 0n) {
    // no-op guard to keep TS from erasing worker fee usage in future refactors
  }

  const context = isRecord(contextRaw) ? contextRaw : null;
  const occurredAtIso = parseIsoTimestamp(occurred_at) ?? nowIso();
  const month = monthFromIsoOrNow(occurredAtIso);
  const createdAt = nowIso();
  const applyId = `cap_${crypto.randomUUID()}`;

  await env.CUTS_DB.prepare(
    `INSERT INTO fee_apply_events (
      apply_id,
      idempotency_key,
      product,
      settlement_ref,
      month,
      currency,
      policy_id,
      policy_version,
      policy_hash_b64u,
      principal_minor,
      buyer_total_minor,
      worker_net_minor,
      total_fee_minor,
      platform_fee_minor,
      referral_fee_minor,
      platform_retained_minor,
      transfer_plan_json,
      snapshot_json,
      context_json,
      ledger_fee_event_ids_json,
      ledger_referral_event_ids_json,
      created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      applyId,
      idempotency_key.trim(),
      product.trim(),
      isNonEmptyString(settlement_ref) ? settlement_ref.trim() : null,
      month,
      'USD',
      snapshot.policy_id,
      snapshotVersion,
      snapshot.policy_hash_b64u,
      analysis.principal_minor.toString(),
      analysis.buyer_total_minor.toString(),
      analysis.worker_net_minor.toString(),
      analysis.total_fee_minor.toString(),
      analysis.total_fee_minor.toString(),
      analysis.referral_fee_minor.toString(),
      analysis.platform_retained_minor.toString(),
      JSON.stringify(analysis.transfers),
      normalizedSnapshotJson,
      context ? JSON.stringify(context) : null,
      JSON.stringify([]),
      JSON.stringify([]),
      createdAt
    )
    .run();

  const inserted = await getFeeApplyEventByIdempotencyKey(env, idempotency_key.trim());
  if (!inserted) {
    return errorResponse('DB_READ_FAILED', 'Failed to read inserted apply event', 500, undefined, version);
  }

  return buildFeeApplyResponse(inserted, false);
}

async function handleFinalizeApply(request: Request, env: Env, version: string): Promise<Response> {
  const authCheck = requireApplyAuth(request, env, version);
  if (authCheck) return authCheck;

  const body = await request.json().catch(() => null);
  if (!isRecord(body)) {
    return errorResponse('INVALID_JSON', 'Request body must be a JSON object', 400, undefined, version);
  }

  const idempotency_key = body.idempotency_key;
  const feeRefsRaw = body.ledger_fee_event_ids;
  const referralRefsRaw = body.ledger_referral_event_ids;

  if (!isNonEmptyString(idempotency_key)) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required', 400, undefined, version);
  }
  if (!Array.isArray(feeRefsRaw) || !Array.isArray(referralRefsRaw)) {
    return errorResponse('INVALID_REQUEST', 'ledger_fee_event_ids and ledger_referral_event_ids must be arrays', 400, undefined, version);
  }

  const feeRefs = feeRefsRaw
    .filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
    .map((entry) => entry.trim());

  const referralRefs = referralRefsRaw
    .filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
    .map((entry) => entry.trim());

  const row = await getFeeApplyEventByIdempotencyKey(env, idempotency_key.trim());
  if (!row) {
    return errorResponse('NOT_FOUND', 'fee apply event not found', 404, undefined, version);
  }

  const existingFeeRefs = parseJsonArrayString(row.ledger_fee_event_ids_json);
  const existingReferralRefs = parseJsonArrayString(row.ledger_referral_event_ids_json);

  if (row.finalized_at) {
    if (!arraysEqual(existingFeeRefs, feeRefs) || !arraysEqual(existingReferralRefs, referralRefs)) {
      return errorResponse('IDEMPOTENCY_CONFLICT', 'finalize payload does not match existing ledger refs', 409, undefined, version);
    }

    return jsonResponse(
      {
        apply_id: row.apply_id,
        idempotency_key: row.idempotency_key,
        deduped: true,
        finalized_at: row.finalized_at,
        ledger_refs: {
          fee_transfers: existingFeeRefs,
          referral_transfers: existingReferralRefs,
        },
      },
      200,
      version
    );
  }

  const finalizedAt = nowIso();

  await env.CUTS_DB.prepare(
    `UPDATE fee_apply_events
        SET ledger_fee_event_ids_json = ?,
            ledger_referral_event_ids_json = ?,
            finalized_at = ?
      WHERE idempotency_key = ?`
  )
    .bind(JSON.stringify(feeRefs), JSON.stringify(referralRefs), finalizedAt, idempotency_key.trim())
    .run();

  return jsonResponse(
    {
      apply_id: row.apply_id,
      idempotency_key: row.idempotency_key,
      deduped: false,
      finalized_at: finalizedAt,
      ledger_refs: {
        fee_transfers: feeRefs,
        referral_transfers: referralRefs,
      },
    },
    200,
    version
  );
}

async function handleMonthlyRevenueReport(request: Request, env: Env, version: string): Promise<Response> {
  const adminCheck = requireAdmin(request, env, version);
  if (adminCheck) return adminCheck;

  const url = new URL(request.url);
  const month = parseMonthParam(url.searchParams.get('month'));
  if (!month) {
    return errorResponse('INVALID_REQUEST', 'month query param is required (YYYY-MM)', 400, undefined, version);
  }

  const productFilter = url.searchParams.get('product')?.trim() || null;
  const format = url.searchParams.get('format')?.trim().toLowerCase() || 'json';

  const query =
    productFilter && productFilter.length > 0
      ? env.CUTS_DB.prepare(
          `SELECT
            apply_id,
            idempotency_key,
            product,
            settlement_ref,
            month,
            currency,
            policy_id,
            policy_version,
            policy_hash_b64u,
            principal_minor,
            buyer_total_minor,
            worker_net_minor,
            total_fee_minor,
            platform_fee_minor,
            referral_fee_minor,
            platform_retained_minor,
            transfer_plan_json,
            snapshot_json,
            context_json,
            ledger_fee_event_ids_json,
            ledger_referral_event_ids_json,
            created_at,
            finalized_at
          FROM fee_apply_events
          WHERE month = ? AND product = ?
          ORDER BY product, policy_id, policy_version`
        ).bind(month, productFilter)
      : env.CUTS_DB.prepare(
          `SELECT
            apply_id,
            idempotency_key,
            product,
            settlement_ref,
            month,
            currency,
            policy_id,
            policy_version,
            policy_hash_b64u,
            principal_minor,
            buyer_total_minor,
            worker_net_minor,
            total_fee_minor,
            platform_fee_minor,
            referral_fee_minor,
            platform_retained_minor,
            transfer_plan_json,
            snapshot_json,
            context_json,
            ledger_fee_event_ids_json,
            ledger_referral_event_ids_json,
            created_at,
            finalized_at
          FROM fee_apply_events
          WHERE month = ?
          ORDER BY product, policy_id, policy_version`
        ).bind(month);

  const result = await query.all();
  const rawRows = Array.isArray(result.results) ? result.results : [];

  const rows: FeeApplyEventRow[] = [];
  for (const raw of rawRows) {
    const parsed = parseFeeApplyEventRow(raw);
    if (parsed) rows.push(parsed);
  }

  type Aggregate = {
    product: string;
    policy_id: string;
    policy_version: string;
    policy_hash_b64u: string;
    transaction_count: number;
    gross_principal_minor: bigint;
    platform_fee_minor: bigint;
    referral_payout_minor: bigint;
    platform_retained_minor: bigint;
    buyer_total_minor: bigint;
    worker_net_minor: bigint;
  };

  const map = new Map<string, Aggregate>();

  let totalsTx = 0;
  let totalsGross = 0n;
  let totalsPlatformFee = 0n;
  let totalsReferral = 0n;
  let totalsRetained = 0n;
  let totalsBuyer = 0n;
  let totalsWorker = 0n;

  for (const row of rows) {
    const key = `${row.product}:${row.policy_id}:${row.policy_version}:${row.policy_hash_b64u}`;

    const gross = BigInt(row.principal_minor);
    const platformFee = BigInt(row.platform_fee_minor);
    const referral = BigInt(row.referral_fee_minor);
    const retained = BigInt(row.platform_retained_minor);
    const buyerTotal = BigInt(row.buyer_total_minor);
    const workerNet = BigInt(row.worker_net_minor);

    const existing = map.get(key);
    if (existing) {
      existing.transaction_count += 1;
      existing.gross_principal_minor += gross;
      existing.platform_fee_minor += platformFee;
      existing.referral_payout_minor += referral;
      existing.platform_retained_minor += retained;
      existing.buyer_total_minor += buyerTotal;
      existing.worker_net_minor += workerNet;
    } else {
      map.set(key, {
        product: row.product,
        policy_id: row.policy_id,
        policy_version: row.policy_version.toString(),
        policy_hash_b64u: row.policy_hash_b64u,
        transaction_count: 1,
        gross_principal_minor: gross,
        platform_fee_minor: platformFee,
        referral_payout_minor: referral,
        platform_retained_minor: retained,
        buyer_total_minor: buyerTotal,
        worker_net_minor: workerNet,
      });
    }

    totalsTx += 1;
    totalsGross += gross;
    totalsPlatformFee += platformFee;
    totalsReferral += referral;
    totalsRetained += retained;
    totalsBuyer += buyerTotal;
    totalsWorker += workerNet;
  }

  const reportRows: RevenueRow[] = Array.from(map.values())
    .sort((a, b) => {
      const first = `${a.product}:${a.policy_id}:${a.policy_version}`;
      const second = `${b.product}:${b.policy_id}:${b.policy_version}`;
      return first.localeCompare(second);
    })
    .map((entry) => ({
      product: entry.product,
      policy_id: entry.policy_id,
      policy_version: entry.policy_version,
      policy_hash_b64u: entry.policy_hash_b64u,
      transaction_count: entry.transaction_count,
      gross_principal_minor: entry.gross_principal_minor.toString(),
      platform_fee_minor: entry.platform_fee_minor.toString(),
      referral_payout_minor: entry.referral_payout_minor.toString(),
      platform_retained_minor: entry.platform_retained_minor.toString(),
      buyer_total_minor: entry.buyer_total_minor.toString(),
      worker_net_minor: entry.worker_net_minor.toString(),
    }));

  if (format === 'csv') {
    const csv = toCsv(
      [
        'month',
        'product',
        'policy_id',
        'policy_version',
        'policy_hash_b64u',
        'transaction_count',
        'gross_principal_minor',
        'platform_fee_minor',
        'referral_payout_minor',
        'platform_retained_minor',
        'buyer_total_minor',
        'worker_net_minor',
      ],
      reportRows.map((row) => [
        month,
        row.product,
        row.policy_id,
        row.policy_version,
        row.policy_hash_b64u,
        row.transaction_count.toString(),
        row.gross_principal_minor,
        row.platform_fee_minor,
        row.referral_payout_minor,
        row.platform_retained_minor,
        row.buyer_total_minor,
        row.worker_net_minor,
      ])
    );

    return textResponse(csv, 'text/csv; charset=utf-8', 200, version);
  }

  return jsonResponse(
    {
      month,
      currency: 'USD',
      generated_at: nowIso(),
      filters: {
        product: productFilter,
      },
      totals: {
        transaction_count: totalsTx,
        gross_principal_minor: totalsGross.toString(),
        platform_fee_minor: totalsPlatformFee.toString(),
        referral_payout_minor: totalsReferral.toString(),
        platform_retained_minor: totalsRetained.toString(),
        buyer_total_minor: totalsBuyer.toString(),
        worker_net_minor: totalsWorker.toString(),
      },
      rows: reportRows,
    },
    200,
    version
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const version = env.CUTS_VERSION;
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    if (method === 'GET' && path === '/health') {
      return jsonResponse({ status: 'ok', service: 'clawcuts', version }, 200, version);
    }

    if (method === 'GET' && path === '/skill.md') {
      return textResponse(renderSkillMarkdown(url.origin), 'text/markdown; charset=utf-8', 200, version);
    }

    if (method === 'POST' && path === '/v1/fees/simulate') {
      return handleSimulateFees(request, env, version);
    }

    if (method === 'POST' && path === '/v1/fees/apply') {
      return handleApplyFees(request, env, version);
    }

    if (method === 'POST' && path === '/v1/fees/apply/finalize') {
      return handleFinalizeApply(request, env, version);
    }

    if (method === 'POST' && path === '/v1/policies/versions') {
      return handleCreatePolicyVersion(request, env, version);
    }

    if (method === 'POST' && path === '/v1/policies/activate') {
      return handleActivatePolicyVersion(request, env, version);
    }

    if (method === 'POST' && path === '/v1/policies/deactivate') {
      return handleDeactivatePolicyVersion(request, env, version);
    }

    const activeMatch = path.match(/^\/v1\/policies\/([^/]+)\/([^/]+)\/active$/);
    if (activeMatch && method === 'GET') {
      const productRaw = activeMatch[1];
      const policyIdRaw = activeMatch[2];
      if (!productRaw || !policyIdRaw) return errorResponse('NOT_FOUND', 'Not found', 404, undefined, version);

      const product = decodeURIComponent(productRaw);
      const policyId = decodeURIComponent(policyIdRaw);
      return handleGetActivePolicy(product, policyId, env, version);
    }

    const historyMatch = path.match(/^\/v1\/policies\/([^/]+)\/([^/]+)\/history$/);
    if (historyMatch && method === 'GET') {
      const productRaw = historyMatch[1];
      const policyIdRaw = historyMatch[2];
      if (!productRaw || !policyIdRaw) return errorResponse('NOT_FOUND', 'Not found', 404, undefined, version);

      const product = decodeURIComponent(productRaw);
      const policyId = decodeURIComponent(policyIdRaw);
      return handlePolicyHistory(product, policyId, env, version);
    }

    const historyCsvMatch = path.match(/^\/v1\/policies\/([^/]+)\/([^/]+)\/history\.csv$/);
    if (historyCsvMatch && method === 'GET') {
      const productRaw = historyCsvMatch[1];
      const policyIdRaw = historyCsvMatch[2];
      if (!productRaw || !policyIdRaw) return errorResponse('NOT_FOUND', 'Not found', 404, undefined, version);

      const product = decodeURIComponent(productRaw);
      const policyId = decodeURIComponent(policyIdRaw);
      return handlePolicyHistoryCsv(product, policyId, env, version);
    }

    if (method === 'GET' && path === '/v1/reports/revenue/monthly') {
      return handleMonthlyRevenueReport(request, env, version);
    }

    return errorResponse('NOT_FOUND', 'Not found', 404, undefined, version);
  },
};

export const __internals = {
  stableStringify,
  computeFee,
  analyzeSnapshotForApply,
};
