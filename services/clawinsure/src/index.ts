interface Env {
  INSURE_VERSION?: string;
  INSURE_DB: D1Database;

  INSURE_ADMIN_KEY?: string;
  INSURE_RISK_KEY?: string;
  CLAWSCOPE_BASE_URL?: string;
  INSURE_REQUIRED_AUDIENCE?: string;
  INSURE_SCOPE_REQUIRED?: string;

  CLAWREP_BASE_URL?: string;

  LEDGER_BASE_URL?: string;
  LEDGER_ADMIN_KEY?: string;

  TRIALS_BASE_URL?: string;
  TRIALS_ADMIN_KEY?: string;

  ESCROW_BASE_URL?: string;
  ESCROW_ADMIN_KEY?: string;

  INCOME_BASE_URL?: string;
}

type CoverageType = 'sla' | 'provider_bond' | 'dispute';
type PolicyStatus = 'active' | 'exhausted' | 'cancelled';
type ClaimStatus = 'submitted' | 'approved' | 'rejected' | 'paid';
type ClaimDecision = 'approved' | 'rejected';

interface QuoteRecord {
  quote_id: string;
  claimant_did: string;
  coverage_type: CoverageType;
  coverage_amount_minor: string;
  term_days: number;
  risk_score: number;
  risk_tier: number;
  dispute_rate_bps: number;
  premium_bps: number;
  premium_minor: string;
  quote_hash_b64u: string;
  source_refs: Record<string, unknown> | null;
  created_at: string;
  expires_at: string;
}

interface PolicyRecord {
  policy_id: string;
  create_idempotency_key: string;
  quote_id: string;
  policy_holder_did: string;
  coverage_type: CoverageType;
  coverage_amount_minor: string;
  premium_minor: string;
  premium_bps: number;
  risk_score: number;
  term_days: number;
  status: PolicyStatus;
  paid_out_minor: string;
  provider_bond_id: string | null;
  premium_transfer_event_id: string;
  source_refs: Record<string, unknown> | null;
  created_at: string;
  starts_at: string;
  ends_at: string;
  updated_at: string;
}

interface ProviderBondRecord {
  bond_id: string;
  policy_id: string;
  provider_did: string;
  bond_amount_minor: string;
  status: 'active' | 'claimed' | 'released';
  created_at: string;
  updated_at: string;
}

interface ClaimEvidence {
  proof_bundle_hash_b64u: string;
  receipt_refs: string[];
  artifact_refs: string[];
  trial_case_id?: string;
  escrow_id?: string;
}

interface ClaimRecord {
  claim_id: string;
  create_idempotency_key: string;
  policy_id: string;
  claimant_did: string;
  status: ClaimStatus;
  reason: string;
  requested_amount_minor: string;
  approved_amount_minor: string | null;
  trial_case_id: string | null;
  escrow_id: string | null;
  evidence: ClaimEvidence;
  evidence_resolution: Record<string, unknown> | null;
  adjudicate_idempotency_key: string | null;
  adjudication: Record<string, unknown> | null;
  adjudicated_at: string | null;
  payout_idempotency_key: string | null;
  payout_transfer_event_id: string | null;
  payout: Record<string, unknown> | null;
  paid_at: string | null;
  created_at: string;
  updated_at: string;
}

interface ClaimantAuthContext {
  mode: 'claimant';
  claimant_did: string;
  scope: string[];
  aud: string[];
  token_lane?: string;
}

class InsureError extends Error {
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
  const fromAuth = parseBearerToken(request.headers.get('authorization'));
  if (fromAuth) return fromAuth;
  return parseBearerToken(request.headers.get('x-admin-key'));
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
      'x-clawinsure-version': version,
    },
  });
}

function textResponse(text: string, status = 200, version = '0.1.0'): Response {
  return new Response(text, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'no-store',
      'x-clawinsure-version': version,
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
  return jsonResponse({ error: code, message, ...(details ? { details } : {}) }, status, version);
}

function responseFromError(err: unknown, version: string): Response {
  if (err instanceof InsureError) {
    return errorResponse(err.code, err.message, err.status, version, err.details);
  }
  const message = err instanceof Error ? err.message : String(err);
  return errorResponse('INTERNAL_ERROR', message, 500, version);
}

async function parseJsonBody(request: Request): Promise<unknown | null> {
  try {
    return await request.json();
  } catch {
    return null;
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

function parseMinor(value: unknown, field: string, options?: { allowZero?: boolean }): bigint {
  if (!isNonEmptyString(value)) {
    throw new InsureError(`${field} is required`, 'INVALID_REQUEST', 400, { field });
  }

  const trimmed = value.trim();
  if (!/^[0-9]+$/.test(trimmed)) {
    throw new InsureError(`${field} must be a non-negative integer string`, 'INVALID_REQUEST', 400, { field });
  }

  const out = BigInt(trimmed);
  const allowZero = options?.allowZero === true;
  if (!allowZero && out <= 0n) {
    throw new InsureError(`${field} must be greater than zero`, 'INVALID_REQUEST', 400, { field });
  }

  return out;
}

function parseIsoDate(value: unknown, field: string): string {
  if (!isNonEmptyString(value)) {
    throw new InsureError(`${field} is required`, 'INVALID_REQUEST', 400, { field });
  }
  const parsed = new Date(value.trim());
  if (Number.isNaN(parsed.getTime())) {
    throw new InsureError(`${field} must be a valid ISO timestamp`, 'INVALID_REQUEST', 400, { field });
  }
  return parsed.toISOString();
}

function parseCoverageType(value: unknown, field: string): CoverageType {
  if (!isNonEmptyString(value)) {
    throw new InsureError(`${field} is required`, 'INVALID_REQUEST', 400, { field });
  }
  const trimmed = value.trim();
  if (trimmed === 'sla' || trimmed === 'provider_bond' || trimmed === 'dispute') {
    return trimmed;
  }
  throw new InsureError(`${field} must be one of sla|provider_bond|dispute`, 'INVALID_REQUEST', 400, { field });
}

function parseClaimDecision(value: unknown): ClaimDecision {
  if (!isNonEmptyString(value)) {
    throw new InsureError('decision is required', 'INVALID_REQUEST', 400, { field: 'decision' });
  }
  const trimmed = value.trim();
  if (trimmed === 'approved' || trimmed === 'rejected') return trimmed;
  throw new InsureError('decision must be approved or rejected', 'INVALID_REQUEST', 400, { field: 'decision' });
}

function isDid(value: string): boolean {
  return /^did:[a-z0-9]+:[A-Za-z0-9._:-]+$/.test(value);
}

function getBaseUrl(value: string | undefined, envField: string): string {
  if (!value || value.trim().length === 0) {
    throw new InsureError(`${envField} is not configured`, 'DEPENDENCY_NOT_CONFIGURED', 503, { field: envField });
  }
  return value.trim();
}

function getRequiredSecret(value: string | undefined, envField: string): string {
  if (!value || value.trim().length === 0) {
    throw new InsureError(`${envField} is not configured`, 'DEPENDENCY_NOT_CONFIGURED', 503, { field: envField });
  }
  return value.trim();
}

function parseAudClaim(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === 'string').map((item) => item.trim()).filter(Boolean);
  }
  if (typeof value === 'string' && value.trim().length > 0) {
    return [value.trim()];
  }
  return [];
}

async function introspectClaimantToken(token: string, env: Env): Promise<ClaimantAuthContext> {
  const baseUrl = getBaseUrl(env.CLAWSCOPE_BASE_URL, 'CLAWSCOPE_BASE_URL');
  const response = await fetch(`${baseUrl}/v1/tokens/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
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
    throw new InsureError('Token introspection failed', 'AUTH_INTROSPECTION_FAILED', 502, {
      status: response.status,
      raw: isRecord(json) ? json : text,
    });
  }

  if (!isRecord(json) || typeof json.active !== 'boolean') {
    throw new InsureError('Invalid token introspection payload', 'AUTH_INTROSPECTION_INVALID', 502);
  }

  if (!json.active || json.revoked === true) {
    throw new InsureError('Token is inactive', 'UNAUTHORIZED', 401);
  }

  const sub = isNonEmptyString(json.sub) ? json.sub.trim() : null;
  if (!sub || !isDid(sub)) {
    throw new InsureError('Token subject is invalid', 'UNAUTHORIZED', 401, { claim: 'sub' });
  }

  const aud = parseAudClaim(json.aud);
  const requiredAudience = env.INSURE_REQUIRED_AUDIENCE?.trim();
  if (requiredAudience && !aud.includes(requiredAudience)) {
    throw new InsureError('Token audience is missing clawinsure domain', 'AUDIENCE_REQUIRED', 403, {
      required_audience: requiredAudience,
      aud,
    });
  }

  const scope = Array.isArray(json.scope)
    ? json.scope.filter((entry): entry is string => typeof entry === 'string').map((entry) => entry.trim()).filter(Boolean)
    : [];

  const requiredScope = env.INSURE_SCOPE_REQUIRED?.trim();
  if (requiredScope && !scope.includes(requiredScope)) {
    throw new InsureError('Token scope is insufficient', 'SCOPE_REQUIRED', 403, {
      required_scope: requiredScope,
      scope,
    });
  }

  return {
    mode: 'claimant',
    claimant_did: sub,
    scope,
    aud,
    token_lane: isNonEmptyString(json.token_lane) ? json.token_lane.trim() : undefined,
  };
}

function isAdminAuthorized(request: Request, env: Env): boolean {
  const configured = env.INSURE_ADMIN_KEY?.trim();
  if (!configured) return false;
  const provided = parseAdminToken(request);
  return !!provided && provided === configured;
}

function requireAdmin(request: Request, env: Env): void {
  const configured = env.INSURE_ADMIN_KEY?.trim();
  if (!configured) {
    throw new InsureError('INSURE_ADMIN_KEY is not configured', 'ADMIN_KEY_NOT_CONFIGURED', 503);
  }
  const provided = parseAdminToken(request);
  if (!provided) {
    throw new InsureError('Missing admin token', 'UNAUTHORIZED', 401);
  }
  if (provided !== configured) {
    throw new InsureError('Invalid admin token', 'UNAUTHORIZED', 401);
  }
}

function requireRiskService(request: Request, env: Env): void {
  const configured = env.INSURE_RISK_KEY?.trim();
  if (!configured) {
    throw new InsureError('INSURE_RISK_KEY is not configured', 'ADMIN_KEY_NOT_CONFIGURED', 503);
  }
  const provided = parseAdminToken(request);
  if (!provided) {
    throw new InsureError('Missing risk token', 'UNAUTHORIZED', 401);
  }
  if (provided !== configured) {
    throw new InsureError('Invalid risk token', 'UNAUTHORIZED', 401);
  }
}

async function requireClaimant(request: Request, env: Env): Promise<ClaimantAuthContext> {
  const token = parseBearerToken(request.headers.get('authorization'));
  if (!token) {
    throw new InsureError('Missing claimant bearer token', 'UNAUTHORIZED', 401);
  }
  return introspectClaimantToken(token, env);
}

function stableStringify(value: unknown): string {
  const seen = new WeakSet<object>();
  const normalize = (input: unknown): unknown => {
    if (Array.isArray(input)) return input.map((item) => normalize(item));
    if (isRecord(input)) {
      if (seen.has(input)) throw new Error('Circular structure');
      seen.add(input);
      const out: Record<string, unknown> = {};
      for (const key of Object.keys(input).sort()) {
        out[key] = normalize(input[key]);
      }
      seen.delete(input);
      return out;
    }
    return input;
  };

  return JSON.stringify(normalize(value));
}

async function sha256B64u(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return b64u(new Uint8Array(digest));
}

function b64u(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function clampInt(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Math.trunc(value)));
}

function divRoundUp(numerator: bigint, denominator: bigint): bigint {
  return (numerator + denominator - 1n) / denominator;
}

function basePremiumBps(coverageType: CoverageType): number {
  switch (coverageType) {
    case 'sla':
      return 650;
    case 'provider_bond':
      return 900;
    case 'dispute':
      return 1200;
  }
}

function computeRiskScore(params: { tier: number; dispute_rate_bps: number }): number {
  const base = 20 + (3 - params.tier) * 20;
  const disputePenalty = clampInt(Math.floor(params.dispute_rate_bps / 300), 0, 35);
  return clampInt(base + disputePenalty, 10, 95);
}

function computePremiumQuote(params: {
  coverage_amount_minor: bigint;
  coverage_type: CoverageType;
  risk_score: number;
}): { premium_bps: number; premium_minor: bigint; risk_multiplier_bps: number } {
  const base = basePremiumBps(params.coverage_type);
  const riskMultiplierBps = 7000 + clampInt(params.risk_score, 0, 100) * 35;
  const effectiveBps = Math.max(1, Math.ceil((base * riskMultiplierBps) / 10_000));

  const premiumMinor = divRoundUp(params.coverage_amount_minor * BigInt(effectiveBps), 10_000n);
  return {
    premium_bps: effectiveBps,
    premium_minor: premiumMinor > 0n ? premiumMinor : 1n,
    risk_multiplier_bps: riskMultiplierBps,
  };
}

function parseQuoteRow(row: unknown): QuoteRecord | null {
  if (!isRecord(row)) return null;

  const quote_id = d1String(row.quote_id);
  const claimant_did = d1String(row.claimant_did);
  const coverage_type_raw = d1String(row.coverage_type);
  const coverage_amount_minor = d1String(row.coverage_amount_minor);
  const term_days = d1Number(row.term_days);
  const risk_score = d1Number(row.risk_score);
  const risk_tier = d1Number(row.risk_tier);
  const dispute_rate_bps = d1Number(row.dispute_rate_bps);
  const premium_bps = d1Number(row.premium_bps);
  const premium_minor = d1String(row.premium_minor);
  const quote_hash_b64u = d1String(row.quote_hash_b64u);
  const created_at = d1String(row.created_at);
  const expires_at = d1String(row.expires_at);

  if (
    !quote_id ||
    !claimant_did ||
    !coverage_type_raw ||
    !coverage_amount_minor ||
    term_days === null ||
    risk_score === null ||
    risk_tier === null ||
    dispute_rate_bps === null ||
    premium_bps === null ||
    !premium_minor ||
    !quote_hash_b64u ||
    !created_at ||
    !expires_at
  ) {
    return null;
  }

  const coverage_type =
    coverage_type_raw === 'sla' || coverage_type_raw === 'provider_bond' || coverage_type_raw === 'dispute'
      ? coverage_type_raw
      : null;

  if (!coverage_type) return null;

  let source_refs: Record<string, unknown> | null = null;
  if (isNonEmptyString(row.source_refs_json)) {
    try {
      const parsed = JSON.parse(row.source_refs_json);
      source_refs = isRecord(parsed) ? parsed : null;
    } catch {
      source_refs = null;
    }
  }

  return {
    quote_id,
    claimant_did,
    coverage_type,
    coverage_amount_minor,
    term_days,
    risk_score,
    risk_tier,
    dispute_rate_bps,
    premium_bps,
    premium_minor,
    quote_hash_b64u,
    source_refs,
    created_at,
    expires_at,
  };
}

function parsePolicyRow(row: unknown): PolicyRecord | null {
  if (!isRecord(row)) return null;

  const policy_id = d1String(row.policy_id);
  const create_idempotency_key = d1String(row.create_idempotency_key);
  const quote_id = d1String(row.quote_id);
  const policy_holder_did = d1String(row.policy_holder_did);
  const coverage_type_raw = d1String(row.coverage_type);
  const coverage_amount_minor = d1String(row.coverage_amount_minor);
  const premium_minor = d1String(row.premium_minor);
  const premium_bps = d1Number(row.premium_bps);
  const risk_score = d1Number(row.risk_score);
  const term_days = d1Number(row.term_days);
  const status_raw = d1String(row.status);
  const paid_out_minor = d1String(row.paid_out_minor);
  const provider_bond_id = d1String(row.provider_bond_id);
  const premium_transfer_event_id = d1String(row.premium_transfer_event_id);
  const created_at = d1String(row.created_at);
  const starts_at = d1String(row.starts_at);
  const ends_at = d1String(row.ends_at);
  const updated_at = d1String(row.updated_at);

  if (
    !policy_id ||
    !create_idempotency_key ||
    !quote_id ||
    !policy_holder_did ||
    !coverage_type_raw ||
    !coverage_amount_minor ||
    !premium_minor ||
    premium_bps === null ||
    risk_score === null ||
    term_days === null ||
    !status_raw ||
    !paid_out_minor ||
    !premium_transfer_event_id ||
    !created_at ||
    !starts_at ||
    !ends_at ||
    !updated_at
  ) {
    return null;
  }

  const coverage_type =
    coverage_type_raw === 'sla' || coverage_type_raw === 'provider_bond' || coverage_type_raw === 'dispute'
      ? coverage_type_raw
      : null;

  const status = status_raw === 'active' || status_raw === 'exhausted' || status_raw === 'cancelled' ? status_raw : null;

  if (!coverage_type || !status) return null;

  let source_refs: Record<string, unknown> | null = null;
  if (isNonEmptyString(row.source_refs_json)) {
    try {
      const parsed = JSON.parse(row.source_refs_json);
      source_refs = isRecord(parsed) ? parsed : null;
    } catch {
      source_refs = null;
    }
  }

  return {
    policy_id,
    create_idempotency_key,
    quote_id,
    policy_holder_did,
    coverage_type,
    coverage_amount_minor,
    premium_minor,
    premium_bps,
    risk_score,
    term_days,
    status,
    paid_out_minor,
    provider_bond_id,
    premium_transfer_event_id,
    source_refs,
    created_at,
    starts_at,
    ends_at,
    updated_at,
  };
}

function parseProviderBondRow(row: unknown): ProviderBondRecord | null {
  if (!isRecord(row)) return null;
  const bond_id = d1String(row.bond_id);
  const policy_id = d1String(row.policy_id);
  const provider_did = d1String(row.provider_did);
  const bond_amount_minor = d1String(row.bond_amount_minor);
  const status_raw = d1String(row.status);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (!bond_id || !policy_id || !provider_did || !bond_amount_minor || !status_raw || !created_at || !updated_at) return null;
  const status = status_raw === 'active' || status_raw === 'claimed' || status_raw === 'released' ? status_raw : null;
  if (!status) return null;

  return {
    bond_id,
    policy_id,
    provider_did,
    bond_amount_minor,
    status,
    created_at,
    updated_at,
  };
}

function parseClaimEvidence(input: unknown): ClaimEvidence {
  if (!isRecord(input)) {
    throw new InsureError('evidence must be an object', 'INVALID_REQUEST', 400, { field: 'evidence' });
  }

  if (!isNonEmptyString(input.proof_bundle_hash_b64u)) {
    throw new InsureError('evidence.proof_bundle_hash_b64u is required', 'INVALID_REQUEST', 400, {
      field: 'evidence.proof_bundle_hash_b64u',
    });
  }

  if (!Array.isArray(input.receipt_refs) || input.receipt_refs.length === 0) {
    throw new InsureError('evidence.receipt_refs must be a non-empty array', 'INVALID_REQUEST', 400, {
      field: 'evidence.receipt_refs',
    });
  }

  if (!Array.isArray(input.artifact_refs) || input.artifact_refs.length === 0) {
    throw new InsureError('evidence.artifact_refs must be a non-empty array', 'INVALID_REQUEST', 400, {
      field: 'evidence.artifact_refs',
    });
  }

  const receipt_refs = input.receipt_refs
    .filter((entry): entry is string => typeof entry === 'string')
    .map((entry) => entry.trim())
    .filter(Boolean);
  const artifact_refs = input.artifact_refs
    .filter((entry): entry is string => typeof entry === 'string')
    .map((entry) => entry.trim())
    .filter(Boolean);

  if (receipt_refs.length === 0 || artifact_refs.length === 0) {
    throw new InsureError('Evidence refs must contain non-empty entries', 'INVALID_REQUEST', 400);
  }

  const evidence: ClaimEvidence = {
    proof_bundle_hash_b64u: input.proof_bundle_hash_b64u.trim(),
    receipt_refs,
    artifact_refs,
  };

  if (isNonEmptyString(input.trial_case_id)) {
    evidence.trial_case_id = input.trial_case_id.trim();
  }
  if (isNonEmptyString(input.escrow_id)) {
    evidence.escrow_id = input.escrow_id.trim();
  }

  return evidence;
}

function parseClaimRow(row: unknown): ClaimRecord | null {
  if (!isRecord(row)) return null;

  const claim_id = d1String(row.claim_id);
  const create_idempotency_key = d1String(row.create_idempotency_key);
  const policy_id = d1String(row.policy_id);
  const claimant_did = d1String(row.claimant_did);
  const status_raw = d1String(row.status);
  const reason = d1String(row.reason);
  const requested_amount_minor = d1String(row.requested_amount_minor);
  const approved_amount_minor = d1String(row.approved_amount_minor);
  const trial_case_id = d1String(row.trial_case_id);
  const escrow_id = d1String(row.escrow_id);
  const evidence_json = d1String(row.evidence_json);
  const adjudicate_idempotency_key = d1String(row.adjudicate_idempotency_key);
  const adjudication_json = d1String(row.adjudication_json);
  const adjudicated_at = d1String(row.adjudicated_at);
  const payout_idempotency_key = d1String(row.payout_idempotency_key);
  const payout_transfer_event_id = d1String(row.payout_transfer_event_id);
  const payout_json = d1String(row.payout_json);
  const paid_at = d1String(row.paid_at);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !claim_id ||
    !create_idempotency_key ||
    !policy_id ||
    !claimant_did ||
    !status_raw ||
    !reason ||
    !requested_amount_minor ||
    !evidence_json ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  const status =
    status_raw === 'submitted' || status_raw === 'approved' || status_raw === 'rejected' || status_raw === 'paid'
      ? status_raw
      : null;
  if (!status) return null;

  let evidenceRaw: unknown;
  try {
    evidenceRaw = JSON.parse(evidence_json);
  } catch {
    return null;
  }

  let evidence: ClaimEvidence;
  try {
    evidence = parseClaimEvidence(evidenceRaw);
  } catch {
    return null;
  }

  let adjudication: Record<string, unknown> | null = null;
  if (adjudication_json) {
    try {
      const parsed = JSON.parse(adjudication_json);
      adjudication = isRecord(parsed) ? parsed : null;
    } catch {
      adjudication = null;
    }
  }

  let payout: Record<string, unknown> | null = null;
  if (payout_json) {
    try {
      const parsed = JSON.parse(payout_json);
      payout = isRecord(parsed) ? parsed : null;
    } catch {
      payout = null;
    }
  }

  let evidence_resolution: Record<string, unknown> | null = null;
  if (isNonEmptyString(row.evidence_resolution_json)) {
    try {
      const parsed = JSON.parse(row.evidence_resolution_json);
      evidence_resolution = isRecord(parsed) ? parsed : null;
    } catch {
      evidence_resolution = null;
    }
  }

  return {
    claim_id,
    create_idempotency_key,
    policy_id,
    claimant_did,
    status,
    reason,
    requested_amount_minor,
    approved_amount_minor,
    trial_case_id,
    escrow_id,
    evidence,
    evidence_resolution,
    adjudicate_idempotency_key,
    adjudication,
    adjudicated_at,
    payout_idempotency_key,
    payout_transfer_event_id,
    payout,
    paid_at,
    created_at,
    updated_at,
  };
}

async function getQuoteById(db: D1Database, quoteId: string): Promise<QuoteRecord | null> {
  const row = await db.prepare('SELECT * FROM quotes WHERE quote_id = ?').bind(quoteId).first();
  return parseQuoteRow(row);
}

async function getPolicyById(db: D1Database, policyId: string): Promise<PolicyRecord | null> {
  const row = await db.prepare('SELECT * FROM policies WHERE policy_id = ?').bind(policyId).first();
  return parsePolicyRow(row);
}

async function getPolicyByCreateIdempotencyKey(db: D1Database, key: string): Promise<PolicyRecord | null> {
  const row = await db.prepare('SELECT * FROM policies WHERE create_idempotency_key = ?').bind(key).first();
  return parsePolicyRow(row);
}

async function getLatestClaimablePolicyByHolderDid(db: D1Database, holderDid: string): Promise<PolicyRecord | null> {
  const row = await db
    .prepare(
      `SELECT *
       FROM policies
       WHERE policy_holder_did = ?
         AND status IN ('active', 'exhausted')
       ORDER BY created_at DESC, policy_id DESC
       LIMIT 1`
    )
    .bind(holderDid)
    .first();

  return parsePolicyRow(row);
}

async function getClaimById(db: D1Database, claimId: string): Promise<ClaimRecord | null> {
  const row = await db.prepare('SELECT * FROM claims WHERE claim_id = ?').bind(claimId).first();
  return parseClaimRow(row);
}

async function getClaimByCreateIdempotencyKey(db: D1Database, key: string): Promise<ClaimRecord | null> {
  const row = await db.prepare('SELECT * FROM claims WHERE create_idempotency_key = ?').bind(key).first();
  return parseClaimRow(row);
}

async function getProviderBondByPolicyId(db: D1Database, policyId: string): Promise<ProviderBondRecord | null> {
  const row = await db.prepare('SELECT * FROM provider_bonds WHERE policy_id = ?').bind(policyId).first();
  return parseProviderBondRow(row);
}

async function fetchRepTier(did: string, env: Env): Promise<{ tier: number; dispute_rate_bps: number; raw: Record<string, unknown> }> {
  const baseUrl = getBaseUrl(env.CLAWREP_BASE_URL, 'CLAWREP_BASE_URL');
  const response = await fetch(`${baseUrl}/v1/tiers/${encodeURIComponent(did)}`);

  const text = await response.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (response.status === 404) {
    return {
      tier: 0,
      dispute_rate_bps: 0,
      raw: {
        source: 'default_fallback',
        status: 404,
      },
    };
  }

  if (!response.ok) {
    throw new InsureError('Failed to fetch clawrep tier', 'CLAWREP_FAILED', 502, {
      status: response.status,
      body: isRecord(json) ? json : text,
    });
  }

  if (!isRecord(json)) {
    throw new InsureError('Invalid clawrep tier response', 'CLAWREP_INVALID_RESPONSE', 502);
  }

  const tier = d1Number(json.tier);
  const disputeRate = d1Number(json.dispute_rate);

  if (tier === null || disputeRate === null) {
    throw new InsureError('Missing tier fields in clawrep response', 'CLAWREP_INVALID_RESPONSE', 502, {
      response: json,
    });
  }

  return {
    tier: clampInt(tier, 0, 3),
    dispute_rate_bps: clampInt(Math.round(disputeRate * 10_000), 0, 10_000),
    raw: json,
  };
}

async function resolveTrialCaseRef(trialCaseId: string, env: Env): Promise<Record<string, unknown>> {
  const baseUrl = getBaseUrl(env.TRIALS_BASE_URL, 'TRIALS_BASE_URL');
  const adminKey = getRequiredSecret(env.TRIALS_ADMIN_KEY, 'TRIALS_ADMIN_KEY');

  const response = await fetch(`${baseUrl}/v1/trials/cases/${encodeURIComponent(trialCaseId)}`, {
    method: 'GET',
    headers: { authorization: `Bearer ${adminKey}` },
  });

  const text = await response.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (response.status === 404) {
    throw new InsureError('Trial case reference is unresolved', 'TRIAL_REF_UNRESOLVED', 422, {
      trial_case_id: trialCaseId,
    });
  }

  if (!response.ok) {
    throw new InsureError('Failed to resolve trial reference', 'TRIAL_REF_FAILED', 502, {
      trial_case_id: trialCaseId,
      status: response.status,
      body: isRecord(json) ? json : text,
    });
  }

  const caseObj = isRecord(json) && isRecord(json.case) ? json.case : null;
  return {
    trial_case_id: trialCaseId,
    status: caseObj && isNonEmptyString(caseObj.status) ? caseObj.status : 'unknown',
    checked_at: nowIso(),
  };
}

async function resolveEscrowRef(escrowId: string, env: Env): Promise<Record<string, unknown>> {
  const baseUrl = getBaseUrl(env.ESCROW_BASE_URL, 'ESCROW_BASE_URL');
  const adminKey = getRequiredSecret(env.ESCROW_ADMIN_KEY, 'ESCROW_ADMIN_KEY');

  const response = await fetch(`${baseUrl}/v1/escrows/${encodeURIComponent(escrowId)}`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${adminKey}`,
      'x-admin-key': adminKey,
    },
  });

  const text = await response.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (response.status === 404) {
    throw new InsureError('Escrow reference is unresolved', 'ESCROW_REF_UNRESOLVED', 422, {
      escrow_id: escrowId,
    });
  }

  if (!response.ok) {
    throw new InsureError('Failed to resolve escrow reference', 'ESCROW_REF_FAILED', 502, {
      escrow_id: escrowId,
      status: response.status,
      body: isRecord(json) ? json : text,
    });
  }

  const escrowObj = isRecord(json) && isRecord(json.escrow) ? json.escrow : null;
  return {
    escrow_id: escrowId,
    status: escrowObj && isNonEmptyString(escrowObj.status) ? escrowObj.status : 'unknown',
    checked_at: nowIso(),
  };
}

async function validateEvidenceReferences(evidence: ClaimEvidence, env: Env): Promise<Record<string, unknown>> {
  const resolution: Record<string, unknown> = {
    checked_at: nowIso(),
  };

  if (evidence.trial_case_id) {
    resolution.trial_case = await resolveTrialCaseRef(evidence.trial_case_id, env);
  }

  if (evidence.escrow_id) {
    resolution.escrow = await resolveEscrowRef(evidence.escrow_id, env);
  }

  return resolution;
}

async function transferLedger(params: {
  env: Env;
  idempotency_key: string;
  from_account: string;
  from_bucket: 'A' | 'F';
  to_account: string;
  to_bucket: 'A' | 'F';
  amount_minor: string;
  metadata: Record<string, unknown>;
}): Promise<{ event_id: string }> {
  const baseUrl = getBaseUrl(params.env.LEDGER_BASE_URL, 'LEDGER_BASE_URL');
  const adminKey = getRequiredSecret(params.env.LEDGER_ADMIN_KEY, 'LEDGER_ADMIN_KEY');

  const response = await fetch(`${baseUrl}/v1/transfers`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${adminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: params.idempotency_key,
      currency: 'USD',
      from: {
        account: params.from_account,
        bucket: params.from_bucket,
      },
      to: {
        account: params.to_account,
        bucket: params.to_bucket,
      },
      amount_minor: params.amount_minor,
      metadata: params.metadata,
    }),
  });

  const text = await response.text();
  let json: unknown = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!response.ok) {
    const code = isRecord(json) && isNonEmptyString(json.code) ? json.code.trim() : 'LEDGER_TRANSFER_FAILED';
    const message = isRecord(json) && isNonEmptyString(json.error) ? json.error.trim() : 'Ledger transfer failed';
    const status = response.status === 400 && code === 'INSUFFICIENT_FUNDS' ? 409 : 502;
    throw new InsureError(message, code, status, {
      ledger_status: response.status,
      body: isRecord(json) ? json : text,
    });
  }

  if (!isRecord(json) || !isNonEmptyString(json.event_id)) {
    throw new InsureError('Invalid ledger transfer response', 'LEDGER_TRANSFER_INVALID', 502);
  }

  return { event_id: json.event_id.trim() };
}

function toPolicyResponse(policy: PolicyRecord, bond: ProviderBondRecord | null) {
  return {
    policy_id: policy.policy_id,
    quote_id: policy.quote_id,
    policy_holder_did: policy.policy_holder_did,
    coverage_type: policy.coverage_type,
    coverage_amount_minor: policy.coverage_amount_minor,
    premium_minor: policy.premium_minor,
    premium_bps: policy.premium_bps,
    risk_score: policy.risk_score,
    term_days: policy.term_days,
    status: policy.status,
    paid_out_minor: policy.paid_out_minor,
    premium_transfer_event_id: policy.premium_transfer_event_id,
    starts_at: policy.starts_at,
    ends_at: policy.ends_at,
    created_at: policy.created_at,
    updated_at: policy.updated_at,
    ...(bond
      ? {
          provider_bond: {
            bond_id: bond.bond_id,
            provider_did: bond.provider_did,
            bond_amount_minor: bond.bond_amount_minor,
            status: bond.status,
            created_at: bond.created_at,
          },
        }
      : {}),
  };
}

function policyMonthKey(policy: PolicyRecord): string {
  const dt = new Date(policy.created_at);
  const month = `${dt.getUTCMonth() + 1}`.padStart(2, '0');
  return `${dt.getUTCFullYear()}-${month}`;
}

function incomeStatementLink(env: Env, did: string, month: string): string {
  const base = env.INCOME_BASE_URL?.trim() || 'https://clawincome.com';
  const url = new URL('/v1/statements/monthly', base);
  url.searchParams.set('did', did);
  url.searchParams.set('month', month);
  return url.toString();
}

async function handlePostQuote(request: Request, env: Env, version: string): Promise<Response> {
  const auth = await requireClaimant(request, env);
  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    throw new InsureError('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  if (!isNonEmptyString(body.claimant_did) || !isDid(body.claimant_did.trim())) {
    throw new InsureError('claimant_did must be a DID', 'INVALID_REQUEST', 400, { field: 'claimant_did' });
  }

  const claimantDid = body.claimant_did.trim();
  if (claimantDid !== auth.claimant_did) {
    throw new InsureError('claimant_did does not match token subject', 'FORBIDDEN', 403, {
      claimant_did: claimantDid,
      token_sub: auth.claimant_did,
    });
  }

  const coverageType = parseCoverageType(body.coverage_type, 'coverage_type');
  const coverageAmountMinor = parseMinor(body.coverage_amount_minor, 'coverage_amount_minor');
  const termDays = d1Number(body.term_days);
  if (termDays === null || !Number.isInteger(termDays) || termDays < 1 || termDays > 365) {
    throw new InsureError('term_days must be an integer between 1 and 365', 'INVALID_REQUEST', 400, {
      field: 'term_days',
    });
  }

  const repTier = await fetchRepTier(claimantDid, env);
  const riskScore = computeRiskScore({
    tier: repTier.tier,
    dispute_rate_bps: repTier.dispute_rate_bps,
  });
  const premiumQuote = computePremiumQuote({
    coverage_amount_minor: coverageAmountMinor,
    coverage_type: coverageType,
    risk_score: riskScore,
  });

  const quoteId = `qte_${crypto.randomUUID()}`;
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const hashPayload = {
    quote_id: quoteId,
    claimant_did: claimantDid,
    coverage_type: coverageType,
    coverage_amount_minor: coverageAmountMinor.toString(),
    term_days: termDays,
    risk_score: riskScore,
    premium_bps: premiumQuote.premium_bps,
    premium_minor: premiumQuote.premium_minor.toString(),
    created_at: createdAt,
    expires_at: expiresAt,
  };

  const quoteHash = await sha256B64u(stableStringify(hashPayload));
  const sourceRefs = {
    clawrep: {
      tier: repTier.tier,
      dispute_rate_bps: repTier.dispute_rate_bps,
      raw: repTier.raw,
    },
    risk_multiplier_bps: premiumQuote.risk_multiplier_bps,
  };

  await env.INSURE_DB.prepare(
    `INSERT INTO quotes (
      quote_id, claimant_did, coverage_type, coverage_amount_minor, term_days,
      risk_score, risk_tier, dispute_rate_bps, premium_bps, premium_minor,
      quote_hash_b64u, source_refs_json, created_at, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      quoteId,
      claimantDid,
      coverageType,
      coverageAmountMinor.toString(),
      termDays,
      riskScore,
      repTier.tier,
      repTier.dispute_rate_bps,
      premiumQuote.premium_bps,
      premiumQuote.premium_minor.toString(),
      quoteHash,
      JSON.stringify(sourceRefs),
      createdAt,
      expiresAt
    )
    .run();

  return jsonResponse(
    {
      quote_id: quoteId,
      claimant_did: claimantDid,
      coverage_type: coverageType,
      coverage_amount_minor: coverageAmountMinor.toString(),
      term_days: termDays,
      risk: {
        risk_score: riskScore,
        risk_tier: repTier.tier,
        dispute_rate_bps: repTier.dispute_rate_bps,
      },
      premium: {
        premium_bps: premiumQuote.premium_bps,
        premium_minor: premiumQuote.premium_minor.toString(),
        currency: 'USD',
      },
      quote_hash_b64u: quoteHash,
      created_at: createdAt,
      expires_at: expiresAt,
    },
    201,
    version
  );
}

async function handlePostPolicy(request: Request, env: Env, version: string): Promise<Response> {
  const auth = await requireClaimant(request, env);
  const body = await parseJsonBody(request);
  if (!isRecord(body)) throw new InsureError('Invalid JSON body', 'INVALID_REQUEST', 400);

  if (!isNonEmptyString(body.idempotency_key)) {
    throw new InsureError('idempotency_key is required', 'INVALID_REQUEST', 400, { field: 'idempotency_key' });
  }

  if (!isNonEmptyString(body.quote_id)) {
    throw new InsureError('quote_id is required', 'INVALID_REQUEST', 400, { field: 'quote_id' });
  }

  const idempotencyKey = body.idempotency_key.trim();
  const quoteId = body.quote_id.trim();

  const existing = await getPolicyByCreateIdempotencyKey(env.INSURE_DB, idempotencyKey);
  if (existing) {
    const bond = existing.provider_bond_id ? await getProviderBondByPolicyId(env.INSURE_DB, existing.policy_id) : null;
    return jsonResponse({ policy: toPolicyResponse(existing, bond), replay: true }, 200, version);
  }

  const quote = await getQuoteById(env.INSURE_DB, quoteId);
  if (!quote) {
    throw new InsureError('Quote not found', 'NOT_FOUND', 404, { quote_id: quoteId });
  }

  if (quote.claimant_did !== auth.claimant_did) {
    throw new InsureError('Quote claimant does not match token subject', 'FORBIDDEN', 403, {
      quote_claimant_did: quote.claimant_did,
      token_sub: auth.claimant_did,
    });
  }

  if (new Date(quote.expires_at).getTime() < Date.now()) {
    throw new InsureError('Quote has expired', 'QUOTE_EXPIRED', 409, {
      quote_id: quote.quote_id,
      expires_at: quote.expires_at,
    });
  }

  const policyId = `pol_${crypto.randomUUID()}`;
  const createdAt = nowIso();
  const startsAt = createdAt;
  const endsAt = new Date(Date.now() + quote.term_days * 24 * 60 * 60 * 1000).toISOString();

  const premiumTransfer = await transferLedger({
    env,
    idempotency_key: `insure:policy:${idempotencyKey}:premium`,
    from_account: quote.claimant_did,
    from_bucket: 'A',
    to_account: 'clearing:clawinsure',
    to_bucket: 'F',
    amount_minor: quote.premium_minor,
    metadata: {
      source_domain: 'clawinsure',
      source_ref: policyId,
      transfer_kind: 'premium_collect',
      quote_id: quote.quote_id,
      claimant_did: quote.claimant_did,
    },
  });

  let providerBondId: string | null = null;
  if (quote.coverage_type === 'provider_bond') {
    providerBondId = `bnd_${crypto.randomUUID()}`;
  }

  const sourceRefs = {
    quote_hash_b64u: quote.quote_hash_b64u,
    premium_transfer_event_id: premiumTransfer.event_id,
  };

  await env.INSURE_DB.prepare(
    `INSERT INTO policies (
      policy_id, create_idempotency_key, quote_id, policy_holder_did, coverage_type,
      coverage_amount_minor, premium_minor, premium_bps, risk_score, term_days,
      status, paid_out_minor, provider_bond_id, premium_transfer_event_id,
      source_refs_json, created_at, starts_at, ends_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      policyId,
      idempotencyKey,
      quote.quote_id,
      quote.claimant_did,
      quote.coverage_type,
      quote.coverage_amount_minor,
      quote.premium_minor,
      quote.premium_bps,
      quote.risk_score,
      quote.term_days,
      'active',
      '0',
      providerBondId,
      premiumTransfer.event_id,
      JSON.stringify(sourceRefs),
      createdAt,
      startsAt,
      endsAt,
      createdAt
    )
    .run();

  if (providerBondId) {
    await env.INSURE_DB.prepare(
      `INSERT INTO provider_bonds (
        bond_id, policy_id, provider_did, bond_amount_minor, status, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(providerBondId, policyId, quote.claimant_did, quote.coverage_amount_minor, 'active', createdAt, createdAt)
      .run();
  }

  const policy = await getPolicyById(env.INSURE_DB, policyId);
  if (!policy) {
    throw new InsureError('Policy persistence failed', 'DB_WRITE_FAILED', 500);
  }

  const bond = providerBondId ? await getProviderBondByPolicyId(env.INSURE_DB, policyId) : null;

  return jsonResponse({ policy: toPolicyResponse(policy, bond), replay: false }, 201, version);
}

async function authorizePolicyRead(request: Request, env: Env, policy: PolicyRecord): Promise<void> {
  if (isAdminAuthorized(request, env)) return;
  const claimant = await requireClaimant(request, env);
  if (claimant.claimant_did !== policy.policy_holder_did) {
    throw new InsureError('Policy does not belong to token subject', 'FORBIDDEN', 403);
  }
}

async function handleGetPolicy(policyId: string, request: Request, env: Env, version: string): Promise<Response> {
  const policy = await getPolicyById(env.INSURE_DB, policyId);
  if (!policy) {
    throw new InsureError('Policy not found', 'NOT_FOUND', 404, { policy_id: policyId });
  }

  await authorizePolicyRead(request, env, policy);
  const bond = policy.provider_bond_id ? await getProviderBondByPolicyId(env.INSURE_DB, policy.policy_id) : null;
  return jsonResponse({ policy: toPolicyResponse(policy, bond) }, 200, version);
}

async function handlePostClaim(request: Request, env: Env, version: string): Promise<Response> {
  const auth = await requireClaimant(request, env);
  const body = await parseJsonBody(request);
  if (!isRecord(body)) throw new InsureError('Invalid JSON body', 'INVALID_REQUEST', 400);

  if (!isNonEmptyString(body.idempotency_key)) {
    throw new InsureError('idempotency_key is required', 'INVALID_REQUEST', 400, { field: 'idempotency_key' });
  }
  if (!isNonEmptyString(body.policy_id)) {
    throw new InsureError('policy_id is required', 'INVALID_REQUEST', 400, { field: 'policy_id' });
  }
  if (!isNonEmptyString(body.reason)) {
    throw new InsureError('reason is required', 'INVALID_REQUEST', 400, { field: 'reason' });
  }

  const idempotencyKey = body.idempotency_key.trim();
  const existing = await getClaimByCreateIdempotencyKey(env.INSURE_DB, idempotencyKey);
  if (existing) {
    return jsonResponse({ claim: existing, replay: true }, 200, version);
  }

  const policyId = body.policy_id.trim();
  const policy = await getPolicyById(env.INSURE_DB, policyId);
  if (!policy) throw new InsureError('Policy not found', 'NOT_FOUND', 404, { policy_id: policyId });
  if (policy.policy_holder_did !== auth.claimant_did) {
    throw new InsureError('Policy does not belong to token subject', 'FORBIDDEN', 403);
  }
  if (policy.status !== 'active' && policy.status !== 'exhausted') {
    throw new InsureError('Policy is not claimable', 'POLICY_NOT_CLAIMABLE', 409, { policy_status: policy.status });
  }

  const requestedAmount = parseMinor(body.requested_amount_minor, 'requested_amount_minor');
  const coverageMinor = parseMinor(policy.coverage_amount_minor, 'coverage_amount_minor', { allowZero: true });
  const paidOutMinor = parseMinor(policy.paid_out_minor, 'paid_out_minor', { allowZero: true });
  const remainingCoverage = coverageMinor > paidOutMinor ? coverageMinor - paidOutMinor : 0n;
  if (requestedAmount > remainingCoverage) {
    throw new InsureError('Requested amount exceeds remaining coverage', 'REQUEST_EXCEEDS_COVERAGE', 409, {
      requested_amount_minor: requestedAmount.toString(),
      remaining_coverage_minor: remainingCoverage.toString(),
    });
  }

  const evidence = parseClaimEvidence(body.evidence);
  const evidenceResolution = await validateEvidenceReferences(evidence, env);

  const claimId = `clm_${crypto.randomUUID()}`;
  const createdAt = nowIso();

  await env.INSURE_DB.prepare(
    `INSERT INTO claims (
      claim_id, create_idempotency_key, policy_id, claimant_did, status, reason,
      requested_amount_minor, approved_amount_minor, trial_case_id, escrow_id,
      evidence_json, evidence_resolution_json,
      adjudicate_idempotency_key, adjudication_json, adjudicated_at,
      payout_idempotency_key, payout_transfer_event_id, payout_json, paid_at,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)`
  )
    .bind(
      claimId,
      idempotencyKey,
      policyId,
      auth.claimant_did,
      'submitted',
      body.reason.trim(),
      requestedAmount.toString(),
      null,
      evidence.trial_case_id ?? null,
      evidence.escrow_id ?? null,
      JSON.stringify(evidence),
      JSON.stringify(evidenceResolution),
      createdAt,
      createdAt
    )
    .run();

  const claim = await getClaimById(env.INSURE_DB, claimId);
  if (!claim) throw new InsureError('Claim persistence failed', 'DB_WRITE_FAILED', 500);

  return jsonResponse({ claim, replay: false }, 201, version);
}

async function handleAutoClaim(request: Request, env: Env, version: string): Promise<Response> {
  requireRiskService(request, env);

  const body = await parseJsonBody(request);
  if (!isRecord(body)) {
    throw new InsureError('Invalid JSON body', 'INVALID_REQUEST', 400);
  }

  if (!isNonEmptyString(body.idempotency_key)) {
    throw new InsureError('idempotency_key is required', 'INVALID_REQUEST', 400, { field: 'idempotency_key' });
  }
  if (!isNonEmptyString(body.source_loss_event_id)) {
    throw new InsureError('source_loss_event_id is required', 'INVALID_REQUEST', 400, { field: 'source_loss_event_id' });
  }
  if (!isNonEmptyString(body.reason_code)) {
    throw new InsureError('reason_code is required', 'INVALID_REQUEST', 400, { field: 'reason_code' });
  }

  const idempotencyKey = body.idempotency_key.trim();
  const existing = await getClaimByCreateIdempotencyKey(env.INSURE_DB, idempotencyKey);
  if (existing) {
    return jsonResponse({ claim: existing, replay: true, auto: true }, 200, version);
  }

  const amountMinor = parseMinor(body.amount_minor, 'amount_minor');
  const currency = isNonEmptyString(body.currency) ? body.currency.trim() : 'USD';
  if (currency !== 'USD') {
    throw new InsureError('Only USD auto claims are supported', 'UNSUPPORTED_CURRENCY', 400, {
      field: 'currency',
      value: currency,
    });
  }

  let policy: PolicyRecord | null = null;
  if (isNonEmptyString(body.policy_id)) {
    policy = await getPolicyById(env.INSURE_DB, body.policy_id.trim());
  } else if (isNonEmptyString(body.account_did) && isDid(body.account_did.trim())) {
    policy = await getLatestClaimablePolicyByHolderDid(env.INSURE_DB, body.account_did.trim());
  }

  if (!policy) {
    throw new InsureError('No claimable policy found for auto claim', 'NOT_FOUND', 404, {
      account_did: isNonEmptyString(body.account_did) ? body.account_did.trim() : null,
      policy_id: isNonEmptyString(body.policy_id) ? body.policy_id.trim() : null,
    });
  }

  if (policy.status !== 'active' && policy.status !== 'exhausted') {
    throw new InsureError('Policy is not claimable', 'POLICY_NOT_CLAIMABLE', 409, {
      policy_id: policy.policy_id,
      policy_status: policy.status,
    });
  }

  const coverageMinor = parseMinor(policy.coverage_amount_minor, 'coverage_amount_minor', { allowZero: true });
  const paidOutMinor = parseMinor(policy.paid_out_minor, 'paid_out_minor', { allowZero: true });
  const remainingCoverage = coverageMinor > paidOutMinor ? coverageMinor - paidOutMinor : 0n;
  if (remainingCoverage <= 0n) {
    throw new InsureError('Policy has no remaining coverage', 'REQUEST_EXCEEDS_COVERAGE', 409, {
      policy_id: policy.policy_id,
      remaining_coverage_minor: '0',
    });
  }

  const requestedAmount = amountMinor > remainingCoverage ? remainingCoverage : amountMinor;

  const metadata = isRecord(body.metadata) ? body.metadata : null;
  const trialCaseId =
    metadata && isNonEmptyString(metadata.trial_case_id) ? metadata.trial_case_id.trim() :
    isNonEmptyString(body.trial_case_id) ? body.trial_case_id.trim() :
    undefined;
  const escrowId =
    metadata && isNonEmptyString(metadata.escrow_id) ? metadata.escrow_id.trim() :
    isNonEmptyString(body.escrow_id) ? body.escrow_id.trim() :
    undefined;

  const proofHash = await sha256B64u(
    stableStringify({
      source_loss_event_id: body.source_loss_event_id.trim(),
      reason_code: body.reason_code.trim(),
      account_id: isNonEmptyString(body.account_id) ? body.account_id.trim() : null,
      account_did: isNonEmptyString(body.account_did) ? body.account_did.trim() : null,
      amount_minor: amountMinor.toString(),
      currency,
      occurred_at: isNonEmptyString(body.occurred_at) ? parseIsoDate(body.occurred_at, 'occurred_at') : nowIso(),
      policy_id: policy.policy_id,
      metadata,
    })
  );

  const evidence: ClaimEvidence = {
    proof_bundle_hash_b64u: proofHash,
    receipt_refs: [`loss-event:${body.source_loss_event_id.trim()}`],
    artifact_refs: [`loss-event-envelope:${body.source_loss_event_id.trim()}`],
    ...(trialCaseId ? { trial_case_id: trialCaseId } : {}),
    ...(escrowId ? { escrow_id: escrowId } : {}),
  };

  const evidenceResolution = await validateEvidenceReferences(evidence, env);

  const claimId = `clm_${crypto.randomUUID()}`;
  const createdAt = nowIso();

  await env.INSURE_DB.prepare(
    `INSERT INTO claims (
      claim_id, create_idempotency_key, policy_id, claimant_did, status, reason,
      requested_amount_minor, approved_amount_minor, trial_case_id, escrow_id,
      evidence_json, evidence_resolution_json,
      adjudicate_idempotency_key, adjudication_json, adjudicated_at,
      payout_idempotency_key, payout_transfer_event_id, payout_json, paid_at,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?, ?)`
  )
    .bind(
      claimId,
      idempotencyKey,
      policy.policy_id,
      policy.policy_holder_did,
      'submitted',
      `auto_loss_event:${body.source_loss_event_id.trim()}:${body.reason_code.trim()}`,
      requestedAmount.toString(),
      null,
      trialCaseId ?? null,
      escrowId ?? null,
      JSON.stringify(evidence),
      JSON.stringify({
        ...evidenceResolution,
        source_loss_event_id: body.source_loss_event_id.trim(),
        created_by: 'auto_loss_event',
      }),
      createdAt,
      createdAt
    )
    .run();

  const claim = await getClaimById(env.INSURE_DB, claimId);
  if (!claim) {
    throw new InsureError('Claim persistence failed', 'DB_WRITE_FAILED', 500);
  }

  return jsonResponse(
    {
      claim,
      replay: false,
      auto: true,
      policy_id: policy.policy_id,
      source_loss_event_id: body.source_loss_event_id.trim(),
      requested_amount_minor: requestedAmount.toString(),
      capped_by_coverage: requestedAmount !== amountMinor,
    },
    201,
    version
  );
}

async function authorizeClaimRead(request: Request, env: Env, claim: ClaimRecord): Promise<void> {
  if (isAdminAuthorized(request, env)) return;
  const claimant = await requireClaimant(request, env);
  if (claimant.claimant_did !== claim.claimant_did) {
    throw new InsureError('Claim does not belong to token subject', 'FORBIDDEN', 403);
  }
}

async function handleGetClaim(claimId: string, request: Request, env: Env, version: string): Promise<Response> {
  const claim = await getClaimById(env.INSURE_DB, claimId);
  if (!claim) throw new InsureError('Claim not found', 'NOT_FOUND', 404, { claim_id: claimId });

  await authorizeClaimRead(request, env, claim);
  return jsonResponse({ claim }, 200, version);
}

async function handleAdjudicateClaim(claimId: string, request: Request, env: Env, version: string): Promise<Response> {
  requireAdmin(request, env);

  const claim = await getClaimById(env.INSURE_DB, claimId);
  if (!claim) throw new InsureError('Claim not found', 'NOT_FOUND', 404, { claim_id: claimId });

  const body = await parseJsonBody(request);
  if (!isRecord(body)) throw new InsureError('Invalid JSON body', 'INVALID_REQUEST', 400);
  if (!isNonEmptyString(body.idempotency_key)) {
    throw new InsureError('idempotency_key is required', 'INVALID_REQUEST', 400, { field: 'idempotency_key' });
  }

  const idempotencyKey = body.idempotency_key.trim();

  if (claim.adjudicate_idempotency_key) {
    if (claim.adjudicate_idempotency_key === idempotencyKey) {
      return jsonResponse({ claim, replay: true }, 200, version);
    }
    throw new InsureError('Claim already adjudicated with different idempotency key', 'IDEMPOTENCY_CONFLICT', 409, {
      claim_id: claim.claim_id,
      existing_idempotency_key: claim.adjudicate_idempotency_key,
    });
  }

  if (claim.status !== 'submitted') {
    throw new InsureError('Only submitted claims can be adjudicated', 'INVALID_STATE', 409, {
      claim_status: claim.status,
    });
  }

  const decision = parseClaimDecision(body.decision);

  const policy = await getPolicyById(env.INSURE_DB, claim.policy_id);
  if (!policy) throw new InsureError('Policy not found for claim', 'NOT_FOUND', 404, { policy_id: claim.policy_id });

  const resolutionCheck = await validateEvidenceReferences(claim.evidence, env);

  const requestedMinor = parseMinor(claim.requested_amount_minor, 'requested_amount_minor');
  let approvedMinor: bigint | null = null;

  if (decision === 'approved') {
    approvedMinor = parseMinor(body.approved_amount_minor, 'approved_amount_minor');
    if (approvedMinor > requestedMinor) {
      throw new InsureError('approved_amount_minor cannot exceed requested amount', 'INVALID_REQUEST', 400, {
        requested_amount_minor: requestedMinor.toString(),
      });
    }

    const coverageMinor = parseMinor(policy.coverage_amount_minor, 'coverage_amount_minor', { allowZero: true });
    const paidOutMinor = parseMinor(policy.paid_out_minor, 'paid_out_minor', { allowZero: true });
    const remainingCoverage = coverageMinor > paidOutMinor ? coverageMinor - paidOutMinor : 0n;
    if (approvedMinor > remainingCoverage) {
      throw new InsureError('approved_amount_minor exceeds remaining policy coverage', 'REQUEST_EXCEEDS_COVERAGE', 409, {
        approved_amount_minor: approvedMinor.toString(),
        remaining_coverage_minor: remainingCoverage.toString(),
      });
    }
  }

  const now = nowIso();
  const adjudication = {
    decision,
    reason: isNonEmptyString(body.reason) ? body.reason.trim() : null,
    adjudicated_by: 'admin',
    adjudicated_at: now,
    evidence_revalidation: resolutionCheck,
  };

  await env.INSURE_DB.prepare(
    `UPDATE claims
     SET status = ?,
         approved_amount_minor = ?,
         evidence_resolution_json = ?,
         adjudicate_idempotency_key = ?,
         adjudication_json = ?,
         adjudicated_at = ?,
         updated_at = ?
     WHERE claim_id = ?`
  )
    .bind(
      decision === 'approved' ? 'approved' : 'rejected',
      approvedMinor ? approvedMinor.toString() : null,
      JSON.stringify(resolutionCheck),
      idempotencyKey,
      JSON.stringify(adjudication),
      now,
      now,
      claim.claim_id
    )
    .run();

  const updated = await getClaimById(env.INSURE_DB, claim.claim_id);
  if (!updated) throw new InsureError('Claim update failed', 'DB_WRITE_FAILED', 500);

  return jsonResponse({ claim: updated, replay: false }, 200, version);
}

async function handleClaimPayout(claimId: string, request: Request, env: Env, version: string): Promise<Response> {
  requireAdmin(request, env);

  const claim = await getClaimById(env.INSURE_DB, claimId);
  if (!claim) throw new InsureError('Claim not found', 'NOT_FOUND', 404, { claim_id: claimId });

  const body = await parseJsonBody(request);
  if (!isRecord(body)) throw new InsureError('Invalid JSON body', 'INVALID_REQUEST', 400);

  if (!isNonEmptyString(body.idempotency_key)) {
    throw new InsureError('idempotency_key is required', 'INVALID_REQUEST', 400, { field: 'idempotency_key' });
  }

  const idempotencyKey = body.idempotency_key.trim();

  if (claim.payout_idempotency_key) {
    if (claim.payout_idempotency_key === idempotencyKey) {
      return jsonResponse({ claim, replay: true }, 200, version);
    }
    throw new InsureError('Claim already paid with different idempotency key', 'IDEMPOTENCY_CONFLICT', 409, {
      claim_id: claim.claim_id,
      existing_idempotency_key: claim.payout_idempotency_key,
    });
  }

  if (claim.status !== 'approved') {
    throw new InsureError('Only approved claims can be paid', 'INVALID_STATE', 409, {
      claim_status: claim.status,
    });
  }

  if (!claim.approved_amount_minor) {
    throw new InsureError('Approved amount is missing', 'INVALID_STATE', 500, {
      claim_id: claim.claim_id,
    });
  }

  if (claim.escrow_id) {
    const escrowRef = await resolveEscrowRef(claim.escrow_id, env);
    const escrowStatus = isNonEmptyString(escrowRef.status) ? escrowRef.status.trim() : 'unknown';
    if (escrowStatus === 'held') {
      throw new InsureError('Escrow is unresolved; payout blocked', 'ESCROW_UNRESOLVED', 409, {
        escrow_id: claim.escrow_id,
        escrow_status: escrowStatus,
      });
    }
  }

  const payoutTransfer = await transferLedger({
    env,
    idempotency_key: `insure:claim:${claim.claim_id}:payout:${idempotencyKey}`,
    from_account: 'clearing:clawinsure',
    from_bucket: 'F',
    to_account: claim.claimant_did,
    to_bucket: 'A',
    amount_minor: claim.approved_amount_minor,
    metadata: {
      source_domain: 'clawinsure',
      source_ref: claim.claim_id,
      transfer_kind: 'claim_payout',
      policy_id: claim.policy_id,
      claimant_did: claim.claimant_did,
    },
  });

  const policy = await getPolicyById(env.INSURE_DB, claim.policy_id);
  if (!policy) {
    throw new InsureError('Policy not found for payout', 'NOT_FOUND', 404, { policy_id: claim.policy_id });
  }

  const now = nowIso();
  const approvedMinor = parseMinor(claim.approved_amount_minor, 'approved_amount_minor');
  const previousPaidOut = parseMinor(policy.paid_out_minor, 'paid_out_minor', { allowZero: true });
  const coverageMinor = parseMinor(policy.coverage_amount_minor, 'coverage_amount_minor', { allowZero: true });
  const nextPaidOut = previousPaidOut + approvedMinor;
  const nextPolicyStatus: PolicyStatus = nextPaidOut >= coverageMinor ? 'exhausted' : 'active';

  const payout = {
    payout_transfer_event_id: payoutTransfer.event_id,
    paid_at: now,
    amount_minor: approvedMinor.toString(),
    income_statement_link: incomeStatementLink(env, claim.claimant_did, policyMonthKey(policy)),
  };

  await env.INSURE_DB.batch([
    env.INSURE_DB
      .prepare(
        `UPDATE claims
         SET status = 'paid',
             payout_idempotency_key = ?,
             payout_transfer_event_id = ?,
             payout_json = ?,
             paid_at = ?,
             updated_at = ?
         WHERE claim_id = ?`
      )
      .bind(idempotencyKey, payoutTransfer.event_id, JSON.stringify(payout), now, now, claim.claim_id),
    env.INSURE_DB
      .prepare(
        `UPDATE policies
         SET paid_out_minor = ?, status = ?, updated_at = ?
         WHERE policy_id = ?`
      )
      .bind(nextPaidOut.toString(), nextPolicyStatus, now, policy.policy_id),
  ]);

  const updatedClaim = await getClaimById(env.INSURE_DB, claim.claim_id);
  if (!updatedClaim) throw new InsureError('Claim payout update failed', 'DB_WRITE_FAILED', 500);

  return jsonResponse({ claim: updatedClaim, payout, replay: false }, 200, version);
}

async function handleRiskGet(did: string, env: Env, version: string): Promise<Response> {
  if (!isDid(did)) {
    throw new InsureError('did path parameter must be a DID', 'INVALID_REQUEST', 400, { field: 'did' });
  }

  const rep = await fetchRepTier(did, env);
  const riskScore = computeRiskScore({ tier: rep.tier, dispute_rate_bps: rep.dispute_rate_bps });

  return jsonResponse(
    {
      did,
      risk_score: riskScore,
      risk_tier: rep.tier,
      dispute_rate_bps: rep.dispute_rate_bps,
      risk_multiplier_bps: 7000 + riskScore * 35,
      generated_at: nowIso(),
      source: rep.raw,
    },
    200,
    version
  );
}

function parseListLimit(value: string | null, fallback = 100, max = 500): number {
  if (!value) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return Math.min(max, parsed);
}

function latencyStats(values: number[]): { avg_ms: number | null; p95_ms: number | null } {
  if (values.length === 0) return { avg_ms: null, p95_ms: null };
  const sorted = [...values].sort((a, b) => a - b);
  const avg = sorted.reduce((acc, n) => acc + n, 0) / sorted.length;
  const p95 = sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))];
  return { avg_ms: Math.round(avg), p95_ms: p95 };
}

async function handleClaimsReport(url: URL, request: Request, env: Env, version: string): Promise<Response> {
  requireAdmin(request, env);

  const from = url.searchParams.get('from');
  const to = url.searchParams.get('to');
  const status = url.searchParams.get('status');
  const did = url.searchParams.get('did');
  const limit = parseListLimit(url.searchParams.get('limit'), 100, 1000);

  const where: string[] = [];
  const binds: unknown[] = [];

  if (from) {
    const iso = parseIsoDate(from, 'from');
    where.push('created_at >= ?');
    binds.push(iso);
  }
  if (to) {
    const iso = parseIsoDate(to, 'to');
    where.push('created_at <= ?');
    binds.push(iso);
  }
  if (status) {
    if (!(status === 'submitted' || status === 'approved' || status === 'rejected' || status === 'paid')) {
      throw new InsureError('status filter is invalid', 'INVALID_REQUEST', 400, { field: 'status' });
    }
    where.push('status = ?');
    binds.push(status);
  }
  if (did) {
    if (!isDid(did)) {
      throw new InsureError('did filter is invalid', 'INVALID_REQUEST', 400, { field: 'did' });
    }
    where.push('claimant_did = ?');
    binds.push(did);
  }

  const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

  const result = await env.INSURE_DB.prepare(
    `SELECT * FROM claims
     ${whereSql}
     ORDER BY created_at DESC, claim_id DESC
     LIMIT ?`
  )
    .bind(...binds, limit)
    .all();

  const claims = (result.results ?? []).map(parseClaimRow).filter((row): row is ClaimRecord => row !== null);

  const totals = {
    total_claims: claims.length,
    submitted: 0,
    approved: 0,
    rejected: 0,
    paid: 0,
    requested_minor: 0n,
    approved_minor: 0n,
    paid_minor: 0n,
  };

  const adjudicationLatencies: number[] = [];
  const payoutLatencies: number[] = [];

  for (const claim of claims) {
    totals[claim.status] += 1;
    totals.requested_minor += parseMinor(claim.requested_amount_minor, 'requested_amount_minor');
    if (claim.approved_amount_minor) {
      totals.approved_minor += parseMinor(claim.approved_amount_minor, 'approved_amount_minor');
    }
    if (claim.status === 'paid' && claim.approved_amount_minor) {
      totals.paid_minor += parseMinor(claim.approved_amount_minor, 'approved_amount_minor');
    }

    if (claim.adjudicated_at) {
      const adjudicationMs = new Date(claim.adjudicated_at).getTime() - new Date(claim.created_at).getTime();
      if (Number.isFinite(adjudicationMs) && adjudicationMs >= 0) adjudicationLatencies.push(adjudicationMs);
    }

    if (claim.paid_at && claim.adjudicated_at) {
      const payoutMs = new Date(claim.paid_at).getTime() - new Date(claim.adjudicated_at).getTime();
      if (Number.isFinite(payoutMs) && payoutMs >= 0) payoutLatencies.push(payoutMs);
    }
  }

  const adjudicationStats = latencyStats(adjudicationLatencies);
  const payoutStats = latencyStats(payoutLatencies);

  return jsonResponse(
    {
      generated_at: nowIso(),
      window: {
        ...(from ? { from } : {}),
        ...(to ? { to } : {}),
      },
      filters: {
        ...(status ? { status } : {}),
        ...(did ? { did } : {}),
        limit,
      },
      totals: {
        total_claims: totals.total_claims,
        submitted: totals.submitted,
        approved: totals.approved,
        rejected: totals.rejected,
        paid: totals.paid,
        requested_minor: totals.requested_minor.toString(),
        approved_minor: totals.approved_minor.toString(),
        paid_minor: totals.paid_minor.toString(),
      },
      latency: {
        adjudication: adjudicationStats,
        payout: payoutStats,
      },
      claims,
    },
    200,
    version
  );
}

function docsHtml(origin: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawinsure docs</title>
  </head>
  <body>
    <main style="max-width: 900px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.45;">
      <h1>clawinsure</h1>
      <p>Deterministic insurance quotes, policies, claims adjudication, and payouts.</p>
      <ul>
        <li><code>POST ${origin}/v1/quotes</code></li>
        <li><code>POST ${origin}/v1/policies</code></li>
        <li><code>GET ${origin}/v1/policies/:id</code></li>
        <li><code>POST ${origin}/v1/claims</code></li>
        <li><code>POST ${origin}/v1/claims/auto</code> (risk service key)</li>
        <li><code>GET ${origin}/v1/claims/:id</code></li>
        <li><code>POST ${origin}/v1/claims/:id/adjudicate</code></li>
        <li><code>POST ${origin}/v1/claims/:id/payout</code></li>
        <li><code>GET ${origin}/v1/risk/:did</code></li>
        <li><code>GET ${origin}/v1/reports/claims</code></li>
      </ul>
    </main>
  </body>
</html>`;
}

export const __internals = {
  parseMinor,
  stableStringify,
  computeRiskScore,
  computePremiumQuote,
  parseClaimEvidence,
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const version = env.INSURE_VERSION?.trim() || '0.1.0';

    try {
      if (method === 'GET' && path === '/health') {
        return jsonResponse({ ok: true, service: 'clawinsure', version, now: nowIso() }, 200, version);
      }

      if (method === 'GET' && path === '/') {
        return textResponse('clawinsure\n/docs\n/health\n', 200, version);
      }

      if (method === 'GET' && path === '/docs') {
        return new Response(docsHtml(url.origin), {
          status: 200,
          headers: {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
            'x-clawinsure-version': version,
          },
        });
      }

      if (method === 'POST' && path === '/v1/quotes') {
        return await handlePostQuote(request, env, version);
      }

      if (method === 'POST' && path === '/v1/policies') {
        return await handlePostPolicy(request, env, version);
      }

      const policyMatch = path.match(/^\/v1\/policies\/(pol_[a-f0-9-]+)$/);
      if (policyMatch && method === 'GET') {
        return await handleGetPolicy(policyMatch[1], request, env, version);
      }

      if (method === 'POST' && path === '/v1/claims/auto') {
        return await handleAutoClaim(request, env, version);
      }

      if (method === 'POST' && path === '/v1/claims') {
        return await handlePostClaim(request, env, version);
      }

      const claimMatch = path.match(/^\/v1\/claims\/(clm_[a-f0-9-]+)$/);
      if (claimMatch && method === 'GET') {
        return await handleGetClaim(claimMatch[1], request, env, version);
      }

      const adjudicateMatch = path.match(/^\/v1\/claims\/(clm_[a-f0-9-]+)\/adjudicate$/);
      if (adjudicateMatch && method === 'POST') {
        return await handleAdjudicateClaim(adjudicateMatch[1], request, env, version);
      }

      const payoutMatch = path.match(/^\/v1\/claims\/(clm_[a-f0-9-]+)\/payout$/);
      if (payoutMatch && method === 'POST') {
        return await handleClaimPayout(payoutMatch[1], request, env, version);
      }

      const riskMatch = path.match(/^\/v1\/risk\/(.+)$/);
      if (riskMatch && method === 'GET') {
        return await handleRiskGet(decodeURIComponent(riskMatch[1]), env, version);
      }

      if (path === '/v1/reports/claims' && method === 'GET') {
        return await handleClaimsReport(url, request, env, version);
      }

      if (path === '/robots.txt' && method === 'GET') {
        return textResponse('User-agent: *\nAllow: /\n', 200, version);
      }

      return errorResponse('NOT_FOUND', 'Not found', 404, version, { path, method });
    } catch (err) {
      return responseFromError(err, version);
    }
  },
};
