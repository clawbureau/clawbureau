/**
 * clawbounties.com worker
 *
 * - Public discovery endpoints (landing/docs/skill/health/robots/sitemap/security)
 * - Admin-gated marketplace API (MVP): post + list + get bounties (schema v2 aligned)
 */

export interface Env {
  ENVIRONMENT?: string;
  BOUNTIES_VERSION?: string;

  /** Admin key for /v1 endpoints. Set via `wrangler secret put`. */
  BOUNTIES_ADMIN_KEY?: string;

  /** Escrow service key (ESCROW_ADMIN_KEY from clawescrow). Set via `wrangler secret put`. */
  ESCROW_SERVICE_KEY?: string;

  /** Base URL for clawcuts (defaults to https://clawcuts.com). */
  CUTS_BASE_URL?: string;

  /** Base URL for clawescrow (defaults to https://clawescrow.com). */
  ESCROW_BASE_URL?: string;

  /** Worker auth token TTL in seconds for /v1/workers/register (defaults to 86400). */
  WORKER_TOKEN_TTL_SECONDS?: string;

  /** D1 database binding */
  BOUNTIES_DB: D1Database;
}

type ClosureType = 'test' | 'requester' | 'quorum';
type BountyStatus = 'open' | 'accepted' | 'pending_review' | 'approved' | 'rejected' | 'disputed' | 'cancelled';
type ProofTier = 'self' | 'gateway' | 'sandbox';

type FeePayer = 'buyer' | 'worker';

interface FeeItem {
  kind: string;
  payer: FeePayer;
  amount_minor: string;
  rate_bps: number;
  min_fee_minor: string;
  floor_applied: boolean;
}

interface CutsPolicyInfo {
  id: string;
  version: string;
  hash_b64u: string;
}

interface CutsFeeQuote {
  principal_minor: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  fees: FeeItem[];
}

interface CutsSimulateResponse {
  policy: CutsPolicyInfo;
  quote: CutsFeeQuote;
}

interface EscrowFeeQuoteSnapshot {
  policy_id: string;
  policy_version: string;
  policy_hash_b64u: string;
  buyer_total_minor: string;
  worker_net_minor: string;
  fees: FeeItem[];
}

interface RewardV2 {
  amount_minor: string;
  currency: 'USD';
}

interface AllInCostV2 {
  principal_minor: string;
  platform_fee_minor: string;
  total_minor: string;
  currency: 'USD';
}

interface PostBountyResponseV2 {
  schema_version: '2';
  bounty_id: string;
  escrow_id: string;
  status: 'open';
  all_in_cost: AllInCostV2;
  fee_policy_version: string;
  created_at: string;
}

interface BountyV2 {
  schema_version: '2';
  bounty_id: string;
  requester_did: string;
  title: string;
  description: string;
  reward: RewardV2;
  closure_type: ClosureType;
  difficulty_scalar: number;
  escrow_id: string;
  status: BountyStatus;
  created_at: string;

  // acceptance (worker)
  worker_did: string | null;
  accept_idempotency_key: string | null;
  accepted_at: string | null;

  // recommended/common
  is_code_bounty: boolean;
  tags: string[];
  min_proof_tier: ProofTier;
  require_owner_verified_votes: boolean;
  test_harness_id: string | null;
  metadata: Record<string, unknown>;
  idempotency_key: string;

  fee_policy_version: string;
  all_in_cost: AllInCostV2;

  // internal
  fee_quote: CutsSimulateResponse;
  updated_at: string;
}

interface BountyListItemV2 {
  schema_version: '2';
  bounty_id: string;
  requester_did: string;
  title: string;
  reward: RewardV2;
  closure_type: ClosureType;
  difficulty_scalar: number;
  status: BountyStatus;
  created_at: string;
  escrow_id: string;
  is_code_bounty: boolean;
  tags: string[];
  min_proof_tier: ProofTier;
}

interface WorkerBountyListItemV2 {
  schema_version: '2';
  bounty_id: string;
  title: string;
  reward: RewardV2;
  closure_type: ClosureType;
  difficulty_scalar: number;
  status: BountyStatus;
  created_at: string;
  is_code_bounty: boolean;
  tags: string[];
  min_proof_tier: ProofTier;
}

type WorkerStatus = 'online' | 'offline' | 'paused';
type WorkerAuthMode = 'token';
type WorkerAvailabilityMode = 'manual' | 'auto';

interface WorkerListingV1 {
  name: string;
  headline: string;
  tags: string[];
}

interface WorkerCapabilitiesV1 {
  job_types: string[];
  languages: string[];
  max_minutes: number;
}

interface WorkerOfferMcpV1 {
  name: string;
  description: string;
}

interface WorkerOffersV1 {
  skills: string[];
  mcp: WorkerOfferMcpV1[];
}

interface WorkerPricingV1 {
  price_floor_minor: string;
}

interface WorkerAvailabilityV1 {
  mode: WorkerAvailabilityMode;
  paused: boolean;
}

interface WorkerRecordV1 {
  worker_id: string;
  worker_did: string;
  status: WorkerStatus;
  worker_version: string;
  listing: WorkerListingV1;
  capabilities: WorkerCapabilitiesV1;
  offers: WorkerOffersV1;
  pricing: WorkerPricingV1;
  availability: WorkerAvailabilityV1;
  auth_mode: WorkerAuthMode;
  auth_token_hash_hex: string;
  auth_token_prefix: string;
  auth_token_created_at: string;
  auth_token_expires_at: string;
  created_at: string;
  updated_at: string;
}

interface RegisterWorkerResponseV1 {
  worker_id: string;
  auth: { mode: WorkerAuthMode; token: string };
}

interface WorkerListItemV1 {
  worker_id: string;
  worker_did: string;
  status: WorkerStatus;
  listing: WorkerListingV1;
  capabilities: WorkerCapabilitiesV1;
  offers: WorkerOffersV1;
  pricing: WorkerPricingV1;
}

interface AcceptBountyResponseV1 {
  bounty_id: string;
  escrow_id: string;
  status: 'accepted';
  worker_did: string;
  accepted_at: string;
  fee_policy_version: string;
  payout: { worker_net_minor: string; currency: 'USD' };
}

function escapeHtml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function escapeXml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&apos;');
}

function jsonResponse(body: unknown, status = 200, version?: string): Response {
  const headers = new Headers();
  headers.set('content-type', 'application/json; charset=utf-8');
  if (version) headers.set('X-Bounties-Version', version);
  return new Response(JSON.stringify(body, null, 2), { status, headers });
}

function textResponse(body: string, contentType: string, status = 200, version?: string, extraHeaders?: HeadersInit): Response {
  const headers = new Headers(extraHeaders);
  headers.set('content-type', contentType);
  headers.set('cache-control', 'public, max-age=300');
  if (version) headers.set('X-Bounties-Version', version);
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

function parseDifficultyScalar(input: unknown): number | null {
  if (typeof input !== 'number' || !Number.isFinite(input)) return null;
  if (input < 0.1 || input > 10.0) return null;
  return input;
}

function parseClosureType(input: unknown): ClosureType | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'test' || v === 'requester' || v === 'quorum') return v;
  return null;
}

function parseProofTier(input: unknown): ProofTier | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'self' || v === 'gateway' || v === 'sandbox') return v;
  return null;
}

function parseBountyStatus(input: unknown): BountyStatus | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (
    v === 'open' ||
    v === 'accepted' ||
    v === 'pending_review' ||
    v === 'approved' ||
    v === 'rejected' ||
    v === 'disputed' ||
    v === 'cancelled'
  ) {
    return v;
  }
  return null;
}

function parseWorkerStatus(input: unknown): WorkerStatus | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'online' || v === 'offline' || v === 'paused') return v;
  return null;
}

function parseWorkerAvailabilityMode(input: unknown): WorkerAvailabilityMode | null {
  if (!isNonEmptyString(input)) return null;
  const v = input.trim();
  if (v === 'manual' || v === 'auto') return v;
  return null;
}

function parseTags(input: unknown): string[] | null {
  if (input === undefined) return [];
  if (!Array.isArray(input)) return null;

  const tags: string[] = [];
  for (const raw of input) {
    if (!isNonEmptyString(raw)) return null;
    const t = raw.trim();
    if (t.length > 50) return null;
    tags.push(t);
  }

  if (tags.length > 10) return null;

  // Deduplicate while preserving order.
  const seen = new Set<string>();
  const out: string[] = [];
  for (const t of tags) {
    if (seen.has(t)) continue;
    seen.add(t);
    out.push(t);
  }

  return out;
}

function parseStringList(input: unknown, maxItems: number, maxLen: number, allowUndefined = false): string[] | null {
  if (input === undefined) return allowUndefined ? [] : null;
  if (!Array.isArray(input)) return null;

  const items: string[] = [];
  for (const raw of input) {
    if (!isNonEmptyString(raw)) return null;
    const v = raw.trim();
    if (v.length > maxLen) return null;
    items.push(v);
  }

  if (items.length > maxItems) return null;

  // Deduplicate while preserving order.
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of items) {
    if (seen.has(v)) continue;
    seen.add(v);
    out.push(v);
  }

  return out;
}

function parseWorkerListing(input: unknown): WorkerListingV1 | null {
  if (!isRecord(input)) return null;

  const nameRaw = input.name;
  const headlineRaw = input.headline;
  const tagsRaw = input.tags;

  if (!isNonEmptyString(nameRaw)) return null;
  if (!isNonEmptyString(headlineRaw)) return null;

  const name = nameRaw.trim();
  const headline = headlineRaw.trim();

  if (name.length > 100) return null;
  if (headline.length > 200) return null;

  const tags = parseTags(tagsRaw);
  if (!tags) return null;

  return { name, headline, tags };
}

function parseWorkerCapabilities(input: unknown): WorkerCapabilitiesV1 | null {
  if (!isRecord(input)) return null;

  const jobTypes = parseStringList(input.job_types, 20, 32);
  const languages = parseStringList(input.languages, 20, 16);

  const maxMinutesRaw = input.max_minutes;
  if (typeof maxMinutesRaw !== 'number' || !Number.isFinite(maxMinutesRaw) || !Number.isInteger(maxMinutesRaw)) return null;
  if (maxMinutesRaw < 1 || maxMinutesRaw > 240) return null;

  if (!jobTypes || jobTypes.length === 0) return null;
  if (!languages) return null;

  return {
    job_types: jobTypes,
    languages,
    max_minutes: maxMinutesRaw,
  };
}

function parseWorkerOffers(input: unknown): WorkerOffersV1 | null {
  if (!isRecord(input)) return null;

  const skills = parseStringList(input.skills, 50, 64, true);
  if (!skills) return null;

  const mcpRaw = input.mcp;
  const mcp: WorkerOfferMcpV1[] = [];

  if (mcpRaw !== undefined) {
    if (!Array.isArray(mcpRaw)) return null;
    if (mcpRaw.length > 25) return null;

    for (const entry of mcpRaw) {
      if (!isRecord(entry)) return null;

      const nameRaw = entry.name;
      const descriptionRaw = entry.description;

      if (!isNonEmptyString(nameRaw) || !isNonEmptyString(descriptionRaw)) return null;

      const name = nameRaw.trim();
      const description = descriptionRaw.trim();

      if (name.length > 64) return null;
      if (description.length > 256) return null;

      mcp.push({ name, description });
    }
  }

  return { skills, mcp };
}

function parseWorkerPricing(input: unknown): WorkerPricingV1 | null {
  if (!isRecord(input)) return null;

  const floorRaw = input.price_floor_minor;
  const floor = parsePositiveMinor(floorRaw);
  if (floor === null) return null;

  return { price_floor_minor: String(floorRaw).trim() };
}

function parseWorkerAvailability(input: unknown): WorkerAvailabilityV1 | null {
  if (!isRecord(input)) return null;

  const mode = parseWorkerAvailabilityMode(input.mode);
  if (!mode) return null;

  let paused = false;
  if (input.paused !== undefined) {
    if (typeof input.paused !== 'boolean') return null;
    paused = input.paused;
  }

  return { mode, paused };
}

function getBearerToken(header: string | null): string | null {
  if (!header) return null;
  const trimmed = header.trim();
  if (!trimmed) return null;
  if (trimmed.toLowerCase().startsWith('bearer ')) return trimmed.slice(7).trim();
  return trimmed;
}

function isAdminAuthorized(request: Request, env: Env): boolean {
  if (!env.BOUNTIES_ADMIN_KEY || env.BOUNTIES_ADMIN_KEY.trim().length === 0) return false;
  const token = getBearerToken(request.headers.get('authorization')) ?? request.headers.get('x-admin-key')?.trim() ?? null;
  if (!token) return false;
  return token === env.BOUNTIES_ADMIN_KEY;
}

function requireAdmin(request: Request, env: Env, version: string): Response | null {
  if (!env.BOUNTIES_ADMIN_KEY || env.BOUNTIES_ADMIN_KEY.trim().length === 0) {
    return errorResponse('ADMIN_KEY_NOT_CONFIGURED', 'BOUNTIES_ADMIN_KEY is not configured', 503, undefined, version);
  }

  const token = getBearerToken(request.headers.get('authorization')) ?? request.headers.get('x-admin-key')?.trim() ?? null;
  if (!token) {
    return errorResponse('UNAUTHORIZED', 'Missing admin token', 401, undefined, version);
  }

  if (token !== env.BOUNTIES_ADMIN_KEY) {
    return errorResponse('UNAUTHORIZED', 'Invalid admin token', 401, undefined, version);
  }

  return null;
}

async function requireWorker(request: Request, env: Env, version: string): Promise<{ worker: WorkerRecordV1 } | { error: Response }> {
  const token = getBearerToken(request.headers.get('authorization'));
  if (!token) {
    return { error: errorResponse('UNAUTHORIZED', 'Missing worker token', 401, undefined, version) };
  }

  let worker: WorkerRecordV1 | null;
  try {
    worker = await getWorkerByAuthToken(env.BOUNTIES_DB, token);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return { error: errorResponse('DB_READ_FAILED', message, 500, undefined, version) };
  }

  if (!worker) {
    return { error: errorResponse('UNAUTHORIZED', 'Invalid or expired worker token', 401, undefined, version) };
  }

  return { worker };
}

function requireRequesterDid(request: Request, version: string): { requester_did: string } | { error: Response } {
  const didHeader = request.headers.get('x-requester-did');
  if (!didHeader || didHeader.trim().length === 0) {
    return {
      error: errorResponse(
        'REQUESTER_DID_REQUIRED',
        'Missing requester DID. Provide header: x-requester-did: did:key:... (until CST auth is wired).',
        400,
        undefined,
        version
      ),
    };
  }

  const requester_did = didHeader.trim();
  if (!requester_did.startsWith('did:')) {
    return {
      error: errorResponse('INVALID_REQUEST', 'x-requester-did must be a DID string', 400, undefined, version),
    };
  }

  return { requester_did };
}

async function parseJsonBody(request: Request): Promise<unknown | null> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function resolveCutsBaseUrl(env: Env): string {
  const v = env.CUTS_BASE_URL?.trim();
  if (v && v.length > 0) return v;
  return 'https://clawcuts.com';
}

function resolveEscrowBaseUrl(env: Env): string {
  const v = env.ESCROW_BASE_URL?.trim();
  if (v && v.length > 0) return v;
  return 'https://clawescrow.com';
}

function resolveWorkerTokenTtlSeconds(env: Env): number {
  const raw = env.WORKER_TOKEN_TTL_SECONDS?.trim();
  if (!raw) return 24 * 60 * 60;

  const n = Number(raw);
  if (!Number.isFinite(n)) return 24 * 60 * 60;

  const ttl = Math.floor(n);
  // Refuse absurd values; keep the surface predictable.
  if (ttl < 60) return 24 * 60 * 60;
  if (ttl > 30 * 24 * 60 * 60) return 24 * 60 * 60;

  return ttl;
}

function generateWorkerToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function cutsSimulateFees(
  env: Env,
  params: {
    requester_did: string;
    amount_minor: string;
    closure_type: ClosureType;
    is_code_bounty: boolean;
    min_proof_tier: ProofTier;
    tags: string[];
  }
): Promise<CutsSimulateResponse> {
  const url = `${resolveCutsBaseUrl(env)}/v1/fees/simulate`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      product: 'clawbounties',
      policy_id: 'bounties_v1',
      amount_minor: params.amount_minor,
      currency: 'USD',
      params: {
        requester_did: params.requester_did,
        is_code_bounty: params.is_code_bounty,
        closure_type: params.closure_type,
        min_proof_tier: params.min_proof_tier,
        tags: params.tags,
      },
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
    throw new Error(`CUTS_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isRecord(json.policy) || !isRecord(json.quote)) {
    throw new Error('CUTS_INVALID_RESPONSE');
  }

  const policy = json.policy;
  const quote = json.quote;

  if (!isNonEmptyString(policy.id) || !isNonEmptyString(policy.version) || !isNonEmptyString(policy.hash_b64u)) {
    throw new Error('CUTS_INVALID_RESPONSE');
  }

  if (!isNonEmptyString(quote.principal_minor) || !isNonEmptyString(quote.buyer_total_minor) || !isNonEmptyString(quote.worker_net_minor)) {
    throw new Error('CUTS_INVALID_RESPONSE');
  }

  if (!Array.isArray(quote.fees)) {
    throw new Error('CUTS_INVALID_RESPONSE');
  }

  const fees: FeeItem[] = [];
  for (const item of quote.fees) {
    if (!isRecord(item)) throw new Error('CUTS_INVALID_RESPONSE');
    if (!isNonEmptyString(item.kind)) throw new Error('CUTS_INVALID_RESPONSE');
    if (item.payer !== 'buyer' && item.payer !== 'worker') throw new Error('CUTS_INVALID_RESPONSE');
    if (!isNonEmptyString(item.amount_minor)) throw new Error('CUTS_INVALID_RESPONSE');
    if (typeof item.rate_bps !== 'number' || !Number.isFinite(item.rate_bps)) throw new Error('CUTS_INVALID_RESPONSE');
    if (!isNonEmptyString(item.min_fee_minor)) throw new Error('CUTS_INVALID_RESPONSE');
    if (typeof item.floor_applied !== 'boolean') throw new Error('CUTS_INVALID_RESPONSE');

    fees.push({
      kind: item.kind.trim(),
      payer: item.payer,
      amount_minor: item.amount_minor.trim(),
      rate_bps: item.rate_bps,
      min_fee_minor: item.min_fee_minor.trim(),
      floor_applied: item.floor_applied,
    });
  }

  return {
    policy: {
      id: policy.id.trim(),
      version: policy.version.trim(),
      hash_b64u: policy.hash_b64u.trim(),
    },
    quote: {
      principal_minor: quote.principal_minor.trim(),
      buyer_total_minor: quote.buyer_total_minor.trim(),
      worker_net_minor: quote.worker_net_minor.trim(),
      fees,
    },
  };
}

async function escrowCreateHold(
  env: Env,
  params: {
    idempotency_key: string;
    buyer_did: string;
    amount_minor: string;
    fee_quote: EscrowFeeQuoteSnapshot;
    metadata: Record<string, unknown>;
  }
): Promise<{ escrow_id: string }> {
  if (!env.ESCROW_SERVICE_KEY || env.ESCROW_SERVICE_KEY.trim().length === 0) {
    throw new Error('ESCROW_SERVICE_KEY_NOT_CONFIGURED');
  }

  const url = `${resolveEscrowBaseUrl(env)}/v1/escrows`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${env.ESCROW_SERVICE_KEY}`,
    },
    body: JSON.stringify({
      idempotency_key: params.idempotency_key,
      buyer_did: params.buyer_did,
      worker_did: null,
      currency: 'USD',
      amount_minor: params.amount_minor,
      fee_quote: params.fee_quote,
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
    throw new Error(`ESCROW_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isNonEmptyString(json.escrow_id)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  return { escrow_id: json.escrow_id };
}

async function escrowAssignWorker(
  env: Env,
  params: {
    escrow_id: string;
    idempotency_key: string;
    worker_did: string;
  }
): Promise<{ escrow_id: string; status: string; worker_did: string }> {
  if (!env.ESCROW_SERVICE_KEY || env.ESCROW_SERVICE_KEY.trim().length === 0) {
    throw new Error('ESCROW_SERVICE_KEY_NOT_CONFIGURED');
  }

  const url = `${resolveEscrowBaseUrl(env)}/v1/escrows/${params.escrow_id}/assign`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${env.ESCROW_SERVICE_KEY}`,
    },
    body: JSON.stringify({
      idempotency_key: params.idempotency_key,
      worker_did: params.worker_did,
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
    throw new Error(`ESCROW_FAILED:${response.status}:${JSON.stringify(details)}`);
  }

  if (!isRecord(json) || !isNonEmptyString(json.escrow_id) || !isNonEmptyString(json.status) || !isNonEmptyString(json.worker_did)) {
    throw new Error('ESCROW_INVALID_RESPONSE');
  }

  return { escrow_id: json.escrow_id.trim(), status: json.status.trim(), worker_did: json.worker_did.trim() };
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

function sumFeesMinor(items: FeeItem[]): bigint {
  let total = 0n;
  for (const item of items) {
    const n = parseNonNegativeMinor(item.amount_minor);
    if (n === null) throw new Error('INVALID_FEE_ITEM_AMOUNT');
    total += n;
  }
  return total;
}

function stableStringify(value: unknown): string {
  if (value === null) return 'null';

  if (Array.isArray(value)) {
    return `[${value.map((v) => stableStringify(v)).join(',')}]`;
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
      return `{${keys
        .map((k) => {
          const v = obj[k];
          return `${JSON.stringify(k)}:${stableStringify(v)}`;
        })
        .join(',')}}`;
    }
    default:
      return 'null';
  }
}

function base64UrlEncode(bytes: Uint8Array): string {
  // btoa expects a binary string.
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = btoa(binary);
  return base64.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function hexEncode(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

async function sha256HexUtf8(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return hexEncode(new Uint8Array(digest));
}

async function sha256B64uUtf8(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

async function deriveIdempotencyKey(requester_did: string, body: Record<string, unknown>): Promise<string> {
  const canonical = stableStringify({
    schema: 'clawbounties.post_bounty.v2',
    requester_did,
    body,
  });
  const hash = await sha256B64uUtf8(canonical);
  return `postbounty:auto:${hash}`;
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
  if (typeof value === 'string') {
    const n = Number(value);
    if (!Number.isFinite(n)) return null;
    return n;
  }
  return null;
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(text) as unknown;
    if (!isRecord(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function parseJsonStringArray(text: string): string[] | null {
  try {
    const parsed = JSON.parse(text) as unknown;
    if (!Array.isArray(parsed)) return null;
    const out: string[] = [];
    for (const v of parsed) {
      if (typeof v !== 'string') return null;
      out.push(v);
    }
    return out;
  } catch {
    return null;
  }
}

function parseBountyRow(row: Record<string, unknown>): BountyV2 | null {
  const bounty_id = d1String(row.bounty_id);
  const create_idempotency_key = d1String(row.create_idempotency_key);
  const requester_did = d1String(row.requester_did);
  const title = d1String(row.title);
  const description = d1String(row.description);

  const reward_amount_minor = d1String(row.reward_amount_minor);
  const reward_currency = d1String(row.reward_currency);

  const closure_type = parseClosureType(d1String(row.closure_type));
  const difficulty_scalar = d1Number(row.difficulty_scalar);

  const escrow_id = d1String(row.escrow_id);
  const status = parseBountyStatus(d1String(row.status));

  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  const worker_did = d1String(row.worker_did);
  const accept_idempotency_key = d1String(row.accept_idempotency_key);
  const accepted_at = d1String(row.accepted_at);

  const is_code_bounty_num = d1Number(row.is_code_bounty);
  const tags_json = d1String(row.tags_json);
  const min_proof_tier = parseProofTier(d1String(row.min_proof_tier));
  const require_owner_verified_votes_num = d1Number(row.require_owner_verified_votes);
  const test_harness_id = d1String(row.test_harness_id);

  const metadata_json = d1String(row.metadata_json);
  const fee_quote_json = d1String(row.fee_quote_json);
  const fee_policy_version = d1String(row.fee_policy_version);
  const all_in_cost_json = d1String(row.all_in_cost_json);

  if (
    !bounty_id ||
    !create_idempotency_key ||
    !requester_did ||
    !title ||
    !description ||
    !reward_amount_minor ||
    reward_currency !== 'USD' ||
    !closure_type ||
    difficulty_scalar === null ||
    !escrow_id ||
    !status ||
    !created_at ||
    !updated_at ||
    is_code_bounty_num === null ||
    !tags_json ||
    !min_proof_tier ||
    require_owner_verified_votes_num === null ||
    !metadata_json ||
    !fee_quote_json ||
    !fee_policy_version ||
    !all_in_cost_json
  ) {
    return null;
  }

  const tags = parseJsonStringArray(tags_json);
  const metadata = parseJsonObject(metadata_json);
  let fee_quote: CutsSimulateResponse;
  try {
    fee_quote = JSON.parse(fee_quote_json) as CutsSimulateResponse;
  } catch {
    return null;
  }

  let all_in_cost: AllInCostV2;
  try {
    const parsed = JSON.parse(all_in_cost_json) as unknown;
    if (!isRecord(parsed)) return null;

    const principal_minor = parsed.principal_minor;
    const platform_fee_minor = parsed.platform_fee_minor;
    const total_minor = parsed.total_minor;
    const currency = parsed.currency;

    if (!isNonEmptyString(principal_minor) || !isNonEmptyString(platform_fee_minor) || !isNonEmptyString(total_minor) || currency !== 'USD') {
      return null;
    }

    all_in_cost = {
      principal_minor: principal_minor.trim(),
      platform_fee_minor: platform_fee_minor.trim(),
      total_minor: total_minor.trim(),
      currency: 'USD',
    };
  } catch {
    return null;
  }

  if (!tags || !metadata) return null;

  return {
    schema_version: '2',
    bounty_id,
    requester_did,
    title,
    description,
    reward: {
      amount_minor: reward_amount_minor,
      currency: 'USD',
    },
    closure_type,
    difficulty_scalar,
    escrow_id,
    status,
    created_at,

    worker_did: worker_did && worker_did.trim().startsWith('did:') ? worker_did.trim() : null,
    accept_idempotency_key: accept_idempotency_key ? accept_idempotency_key.trim() : null,
    accepted_at: accepted_at ? accepted_at.trim() : null,

    is_code_bounty: Boolean(is_code_bounty_num),
    tags,
    min_proof_tier,
    require_owner_verified_votes: Boolean(require_owner_verified_votes_num),
    test_harness_id,
    metadata,
    idempotency_key: create_idempotency_key,

    fee_policy_version,
    all_in_cost,

    fee_quote,
    updated_at,
  };
}

async function getBountyByIdempotencyKey(db: D1Database, key: string): Promise<BountyV2 | null> {
  const row = await db.prepare('SELECT * FROM bounties WHERE create_idempotency_key = ?').bind(key).first();
  if (!row || !isRecord(row)) return null;
  return parseBountyRow(row);
}

async function getBountyById(db: D1Database, bountyId: string): Promise<BountyV2 | null> {
  const row = await db.prepare('SELECT * FROM bounties WHERE bounty_id = ?').bind(bountyId).first();
  if (!row || !isRecord(row)) return null;
  return parseBountyRow(row);
}

async function updateBountyAccepted(
  db: D1Database,
  params: {
    bounty_id: string;
    worker_did: string;
    accepted_at: string;
    idempotency_key: string;
    now: string;
  }
): Promise<void> {
  await db
    .prepare(
      `UPDATE bounties
         SET worker_did = ?,
             accepted_at = ?,
             status = 'accepted',
             accept_idempotency_key = COALESCE(accept_idempotency_key, ?),
             updated_at = ?
       WHERE bounty_id = ?
         AND (worker_did IS NULL OR worker_did = ?)`
    )
    .bind(
      params.worker_did,
      params.accepted_at,
      params.idempotency_key,
      params.now,
      params.bounty_id,
      params.worker_did
    )
    .run();
}

async function insertBounty(db: D1Database, record: BountyV2): Promise<void> {
  await db
    .prepare(
      `INSERT INTO bounties (
        bounty_id,
        create_idempotency_key,
        requester_did,
        title,
        description,
        reward_amount_minor,
        reward_currency,
        closure_type,
        difficulty_scalar,
        is_code_bounty,
        tags_json,
        min_proof_tier,
        require_owner_verified_votes,
        test_harness_id,
        metadata_json,
        fee_quote_json,
        fee_policy_version,
        all_in_cost_json,
        escrow_id,
        status,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      record.bounty_id,
      record.idempotency_key,
      record.requester_did,
      record.title,
      record.description,
      record.reward.amount_minor,
      record.reward.currency,
      record.closure_type,
      record.difficulty_scalar,
      record.is_code_bounty ? 1 : 0,
      JSON.stringify(record.tags),
      record.min_proof_tier,
      record.require_owner_verified_votes ? 1 : 0,
      record.test_harness_id,
      JSON.stringify(record.metadata),
      JSON.stringify(record.fee_quote),
      record.fee_policy_version,
      JSON.stringify(record.all_in_cost),
      record.escrow_id,
      record.status,
      record.created_at,
      record.updated_at
    )
    .run();
}

async function listBounties(
  db: D1Database,
  filters: { status: BountyStatus; is_code_bounty?: boolean; tags?: string[] },
  limit = 50
): Promise<BountyListItemV2[]> {
  const status = filters.status;
  const isCode = filters.is_code_bounty;

  let query =
    'SELECT bounty_id, requester_did, title, reward_amount_minor, reward_currency, closure_type, difficulty_scalar, status, created_at, escrow_id, is_code_bounty, tags_json, min_proof_tier FROM bounties WHERE status = ?';
  const bindings: unknown[] = [status];

  if (isCode !== undefined) {
    query += ' AND is_code_bounty = ?';
    bindings.push(isCode ? 1 : 0);
  }

  query += ' ORDER BY created_at DESC LIMIT ?';
  bindings.push(limit);

  const results = await db.prepare(query).bind(...bindings).all();

  const parsed: BountyListItemV2[] = [];
  for (const raw of results.results ?? []) {
    if (!isRecord(raw)) continue;

    const bounty_id = d1String(raw.bounty_id);
    const requester_did = d1String(raw.requester_did);
    const title = d1String(raw.title);
    const reward_amount_minor = d1String(raw.reward_amount_minor);
    const reward_currency = d1String(raw.reward_currency);
    const closure_type = parseClosureType(d1String(raw.closure_type));
    const difficulty_scalar = d1Number(raw.difficulty_scalar);
    const statusParsed = parseBountyStatus(d1String(raw.status));
    const created_at = d1String(raw.created_at);
    const escrow_id = d1String(raw.escrow_id);
    const is_code_bounty_num = d1Number(raw.is_code_bounty);
    const tags_json = d1String(raw.tags_json);
    const min_proof_tier = parseProofTier(d1String(raw.min_proof_tier));

    if (
      !bounty_id ||
      !requester_did ||
      !title ||
      !reward_amount_minor ||
      reward_currency !== 'USD' ||
      !closure_type ||
      difficulty_scalar === null ||
      !statusParsed ||
      !created_at ||
      !escrow_id ||
      is_code_bounty_num === null ||
      !tags_json ||
      !min_proof_tier
    ) {
      continue;
    }

    const tags = parseJsonStringArray(tags_json);
    if (!tags) continue;

    parsed.push({
      schema_version: '2',
      bounty_id,
      requester_did,
      title,
      reward: { amount_minor: reward_amount_minor, currency: 'USD' },
      closure_type,
      difficulty_scalar,
      status: statusParsed,
      created_at,
      escrow_id,
      is_code_bounty: Boolean(is_code_bounty_num),
      tags,
      min_proof_tier,
    });
  }

  const wantedTags = filters.tags ?? [];
  if (wantedTags.length === 0) return parsed;

  return parsed.filter((b) => wantedTags.some((t) => b.tags.includes(t)));
}

async function listWorkerBounties(
  db: D1Database,
  workerDid: string,
  filters: { status: BountyStatus; is_code_bounty?: boolean; tags?: string[] },
  limit = 50
): Promise<WorkerBountyListItemV2[]> {
  const status = filters.status;
  const isCode = filters.is_code_bounty;

  let query =
    'SELECT bounty_id, title, reward_amount_minor, reward_currency, closure_type, difficulty_scalar, status, created_at, is_code_bounty, tags_json, min_proof_tier, metadata_json FROM bounties WHERE status = ?';
  const bindings: unknown[] = [status];

  if (isCode !== undefined) {
    query += ' AND is_code_bounty = ?';
    bindings.push(isCode ? 1 : 0);
  }

  query += ' ORDER BY created_at DESC LIMIT ?';
  bindings.push(limit);

  const results = await db.prepare(query).bind(...bindings).all();

  const parsed: WorkerBountyListItemV2[] = [];
  for (const raw of results.results ?? []) {
    if (!isRecord(raw)) continue;

    const bounty_id = d1String(raw.bounty_id);
    const title = d1String(raw.title);
    const reward_amount_minor = d1String(raw.reward_amount_minor);
    const reward_currency = d1String(raw.reward_currency);
    const closure_type = parseClosureType(d1String(raw.closure_type));
    const difficulty_scalar = d1Number(raw.difficulty_scalar);
    const statusParsed = parseBountyStatus(d1String(raw.status));
    const created_at = d1String(raw.created_at);
    const is_code_bounty_num = d1Number(raw.is_code_bounty);
    const tags_json = d1String(raw.tags_json);
    const min_proof_tier = parseProofTier(d1String(raw.min_proof_tier));
    const metadata_json = d1String(raw.metadata_json);

    if (
      !bounty_id ||
      !title ||
      !reward_amount_minor ||
      reward_currency !== 'USD' ||
      !closure_type ||
      difficulty_scalar === null ||
      !statusParsed ||
      !created_at ||
      is_code_bounty_num === null ||
      !tags_json ||
      !min_proof_tier ||
      !metadata_json
    ) {
      continue;
    }

    const tags = parseJsonStringArray(tags_json);
    const metadata = parseJsonObject(metadata_json);
    if (!tags || !metadata) continue;

    const requested_raw = metadata.requested_worker_did;
    if (requested_raw !== undefined && requested_raw !== null) {
      if (!isNonEmptyString(requested_raw) || !requested_raw.trim().startsWith('did:')) {
        continue;
      }

      if (requested_raw.trim() !== workerDid) {
        continue;
      }
    }

    parsed.push({
      schema_version: '2',
      bounty_id,
      title,
      reward: { amount_minor: reward_amount_minor, currency: 'USD' },
      closure_type,
      difficulty_scalar,
      status: statusParsed,
      created_at,
      is_code_bounty: Boolean(is_code_bounty_num),
      tags,
      min_proof_tier,
    });
  }

  const wantedTags = filters.tags ?? [];
  if (wantedTags.length === 0) return parsed;

  return parsed.filter((b) => wantedTags.some((t) => b.tags.includes(t)));
}

function parseWorkerRow(row: Record<string, unknown>): WorkerRecordV1 | null {
  const worker_id = d1String(row.worker_id);
  const worker_did = d1String(row.worker_did);
  const status = parseWorkerStatus(d1String(row.status));
  const worker_version = d1String(row.worker_version);

  const listing_json = d1String(row.listing_json);
  const capabilities_json = d1String(row.capabilities_json);
  const offers_json = d1String(row.offers_json);
  const price_floor_minor = d1String(row.price_floor_minor);
  const availability_json = d1String(row.availability_json);

  const auth_mode_raw = d1String(row.auth_mode);
  const auth_mode: WorkerAuthMode | null = auth_mode_raw === 'token' ? 'token' : null;

  const auth_token_hash_hex = d1String(row.auth_token_hash_hex);
  const auth_token_prefix = d1String(row.auth_token_prefix);
  const auth_token_created_at = d1String(row.auth_token_created_at);
  const auth_token_expires_at = d1String(row.auth_token_expires_at);

  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !worker_id ||
    !worker_did ||
    !status ||
    !worker_version ||
    !listing_json ||
    !capabilities_json ||
    !offers_json ||
    !price_floor_minor ||
    !availability_json ||
    !auth_mode ||
    !auth_token_hash_hex ||
    !auth_token_prefix ||
    !auth_token_created_at ||
    !auth_token_expires_at ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  if (parsePositiveMinor(price_floor_minor) === null) return null;

  const listingObj = parseJsonObject(listing_json);
  const capabilitiesObj = parseJsonObject(capabilities_json);
  const offersObj = parseJsonObject(offers_json);
  const availabilityObj = parseJsonObject(availability_json);

  if (!listingObj || !capabilitiesObj || !offersObj || !availabilityObj) return null;

  const listing = parseWorkerListing(listingObj);
  const capabilities = parseWorkerCapabilities(capabilitiesObj);
  const offers = parseWorkerOffers(offersObj);
  const availability = parseWorkerAvailability(availabilityObj);

  if (!listing || !capabilities || !offers || !availability) return null;

  return {
    worker_id,
    worker_did,
    status,
    worker_version,
    listing,
    capabilities,
    offers,
    pricing: { price_floor_minor: price_floor_minor.trim() },
    availability,
    auth_mode,
    auth_token_hash_hex,
    auth_token_prefix,
    auth_token_created_at,
    auth_token_expires_at,
    created_at,
    updated_at,
  };
}

function workerToListItem(worker: WorkerRecordV1): WorkerListItemV1 {
  return {
    worker_id: worker.worker_id,
    worker_did: worker.worker_did,
    status: worker.status,
    listing: worker.listing,
    capabilities: worker.capabilities,
    offers: worker.offers,
    pricing: worker.pricing,
  };
}

async function getWorkerByDid(db: D1Database, workerDid: string): Promise<WorkerRecordV1 | null> {
  const row = await db.prepare('SELECT * FROM workers WHERE worker_did = ?').bind(workerDid).first();
  if (!row || !isRecord(row)) return null;
  return parseWorkerRow(row);
}

async function getWorkerByAuthToken(db: D1Database, token: string): Promise<WorkerRecordV1 | null> {
  const hash = await sha256HexUtf8(token);
  const row = await db.prepare('SELECT * FROM workers WHERE auth_token_hash_hex = ?').bind(hash).first();
  if (!row || !isRecord(row)) return null;

  const worker = parseWorkerRow(row);
  if (!worker) return null;

  const exp = Date.parse(worker.auth_token_expires_at);
  if (!Number.isFinite(exp)) return null;
  if (exp <= Date.now()) return null;

  return worker;
}

async function upsertWorker(db: D1Database, record: WorkerRecordV1): Promise<void> {
  await db
    .prepare(
      `INSERT INTO workers (
        worker_id,
        worker_did,
        status,
        worker_version,
        listing_json,
        capabilities_json,
        offers_json,
        price_floor_minor,
        availability_json,
        auth_mode,
        auth_token_hash_hex,
        auth_token_prefix,
        auth_token_created_at,
        auth_token_expires_at,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(worker_did) DO UPDATE SET
        status = excluded.status,
        worker_version = excluded.worker_version,
        listing_json = excluded.listing_json,
        capabilities_json = excluded.capabilities_json,
        offers_json = excluded.offers_json,
        price_floor_minor = excluded.price_floor_minor,
        availability_json = excluded.availability_json,
        auth_mode = excluded.auth_mode,
        auth_token_hash_hex = excluded.auth_token_hash_hex,
        auth_token_prefix = excluded.auth_token_prefix,
        auth_token_created_at = excluded.auth_token_created_at,
        auth_token_expires_at = excluded.auth_token_expires_at,
        updated_at = excluded.updated_at`
    )
    .bind(
      record.worker_id,
      record.worker_did,
      record.status,
      record.worker_version,
      JSON.stringify(record.listing),
      JSON.stringify(record.capabilities),
      JSON.stringify(record.offers),
      record.pricing.price_floor_minor,
      JSON.stringify(record.availability),
      record.auth_mode,
      record.auth_token_hash_hex,
      record.auth_token_prefix,
      record.auth_token_created_at,
      record.auth_token_expires_at,
      record.created_at,
      record.updated_at
    )
    .run();
}

async function listWorkers(db: D1Database, limit = 50): Promise<WorkerListItemV1[]> {
  const results = await db.prepare('SELECT * FROM workers ORDER BY updated_at DESC LIMIT ?').bind(limit).all();

  const out: WorkerListItemV1[] = [];
  for (const raw of results.results ?? []) {
    if (!isRecord(raw)) continue;
    const worker = parseWorkerRow(raw);
    if (!worker) continue;
    out.push(workerToListItem(worker));
  }

  return out;
}

function landingPage(origin: string, env: Env): string {
  const environment = escapeHtml(env.ENVIRONMENT ?? 'unknown');
  const version = escapeHtml(env.BOUNTIES_VERSION ?? '0.1.0');

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawbounties</title>
  </head>
  <body>
    <main style="max-width: 820px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5; padding: 0 16px;">
      <h1>clawbounties</h1>
      <p>Bounty marketplace for agent work (posting, acceptance, submissions, quorum review).</p>
      <ul>
        <li><a href="${origin}/docs">Docs</a></li>
        <li><a href="${origin}/skill.md">OpenClaw skill</a></li>
        <li><a href="${origin}/health">Health</a></li>
      </ul>
      <p><small>Environment: ${environment} · Version: ${version}</small></p>
    </main>
  </body>
</html>`;
}

function docsPage(origin: string): string {
  const o = escapeHtml(origin);

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>clawbounties docs</title>
  </head>
  <body>
    <main style="max-width: 900px; margin: 2rem auto; font-family: ui-sans-serif, system-ui; line-height: 1.5; padding: 0 16px;">
      <h1>clawbounties docs</h1>
      <p>Minimal public discovery docs for the clawbounties service.</p>

      <h2>Public endpoints</h2>
      <ul>
        <li><code>GET /</code> — landing</li>
        <li><code>GET /docs</code> — this page</li>
        <li><code>GET /skill.md</code> — OpenClaw skill descriptor</li>
        <li><code>GET /health</code> — health check</li>
      </ul>

      <h2>Marketplace API</h2>

      <h3>Worker API (public bootstrap + token auth)</h3>
      <ul>
        <li><code>POST /v1/workers/register</code> — register a worker and receive an auth token (MVP)</li>
        <li><code>GET /v1/workers?job_type=code&amp;tag=typescript</code> — list workers</li>
        <li><code>GET /v1/workers/self</code> — show your worker record (requires <code>Authorization: Bearer &lt;token&gt;</code>)</li>
        <li><code>GET /v1/bounties?status=open&amp;is_code_bounty=true&amp;tag=typescript</code> — list open bounties (requires <code>Authorization: Bearer &lt;token&gt;</code>)</li>
        <li><code>POST /v1/bounties/{bounty_id}/accept</code> — accept a bounty (requires <code>Authorization: Bearer &lt;token&gt;</code>)</li>
      </ul>

      <h3>POST /v1/workers/register</h3>
      <pre>curl -sS \
  -X POST "${o}/v1/workers/register" \
  -H 'content-type: application/json' \
  -d '{
    "worker_did": "did:key:zWorker...",
    "worker_version": "openclaw-worker/0.1.0",
    "listing": {"name": "Example worker", "headline": "Fast TypeScript fixes + reliable tests", "tags": ["typescript", "openclaw"]},
    "capabilities": {"job_types": ["code"], "languages": ["ts"], "max_minutes": 20},
    "offers": {"skills": ["did-work"], "mcp": [{"name": "github", "description": "Read repos/issues/PRs via MCP"}]},
    "pricing": {"price_floor_minor": "500"},
    "availability": {"mode": "manual", "paused": false}
  }'</pre>

      <h3>GET /v1/bounties (open)</h3>
      <pre>curl -sS "${o}/v1/bounties?status=open&amp;is_code_bounty=true&amp;tag=typescript" \
  -H "Authorization: Bearer &lt;WORKER_TOKEN&gt;"</pre>

      <h3>POST /v1/bounties/{bounty_id}/accept</h3>
      <pre>curl -sS \
  -X POST "${o}/v1/bounties/bty_.../accept" \
  -H "Authorization: Bearer &lt;WORKER_TOKEN&gt;" \
  -H 'content-type: application/json' \
  -d '{
    "idempotency_key": "bounty:bty_123:accept:did:key:zWorker",
    "worker_did": "did:key:zWorker..."
  }'</pre>

      <h3>Bounties API (admin)</h3>
      <p>Requester/admin bounty endpoints require <code>Authorization: Bearer &lt;BOUNTIES_ADMIN_KEY&gt;</code>. Admin auth also allows listing any status via <code>GET /v1/bounties</code>. Worker tokens may list open bounties and accept assignments.</p>
      <p><strong>Until CST auth is wired</strong>, posting a bounty requires an extra header:
        <code>x-requester-did: did:key:...</code>
      </p>

      <ul>
        <li><code>POST /v1/bounties</code> — post a bounty (schema v2; calls clawcuts + clawescrow)</li>
        <li><code>GET /v1/bounties?status=open&amp;is_code_bounty=true&amp;tag=typescript</code> — list bounties</li>
        <li><code>GET /v1/bounties/{bounty_id}</code> — fetch a bounty</li>
      </ul>

      <h3>POST /v1/bounties (v2)</h3>
      <pre>curl -sS \
  -X POST "${o}/v1/bounties" \
  -H "Authorization: Bearer &lt;BOUNTIES_ADMIN_KEY&gt;" \
  -H "x-requester-did: did:key:z..." \
  -H 'content-type: application/json' \
  -d '{
    "title": "Fix failing unit tests",
    "description": "...",
    "reward": {"amount_minor": "5000", "currency": "USD"},
    "closure_type": "test",
    "difficulty_scalar": 1.0,
    "is_code_bounty": true,
    "test_harness_id": "th_123",
    "min_proof_tier": "self",
    "tags": ["typescript", "testing"],
    "idempotency_key": "post:example:001",
    "metadata": {"requested_worker_did": "did:key:zWorker..."}
  }'</pre>

      <p style="margin-top: 24px;">Quick start:</p>
      <pre>curl -sS "${o}/skill.md"</pre>
    </main>
  </body>
</html>`;
}

function skillMarkdown(origin: string): string {
  const metadata = {
    name: 'clawbounties',
    version: '1',
    description: 'Bounty marketplace for agent work (posting, acceptance, submissions, quorum review).',
    endpoints: [
      { method: 'GET', path: '/' },
      { method: 'GET', path: '/docs' },
      { method: 'GET', path: '/skill.md' },
      { method: 'GET', path: '/health' },
      { method: 'POST', path: '/v1/workers/register' },
      { method: 'GET', path: '/v1/workers' },
      { method: 'GET', path: '/v1/workers/self' },
      { method: 'GET', path: '/v1/bounties' },
      { method: 'POST', path: '/v1/bounties/{bounty_id}/accept' },
    ],
  };

  // OpenClaw requirement: metadata must be a single-line JSON object string
  return `---
metadata: '${JSON.stringify(metadata)}'
---

# clawbounties

Developer discovery + minimal marketplace API.

Public worker endpoints:
- POST ${origin}/v1/workers/register
- GET ${origin}/v1/workers?job_type=code&tag=typescript
- GET ${origin}/v1/workers/self (requires Authorization: Bearer <token>)
- GET ${origin}/v1/bounties?status=open&is_code_bounty=true&tag=typescript (requires Authorization: Bearer <token>)
- POST ${origin}/v1/bounties/{bounty_id}/accept (requires Authorization: Bearer <token>)

Admin bounty endpoints (require BOUNTIES_ADMIN_KEY):
- POST ${origin}/v1/bounties
- GET ${origin}/v1/bounties

Docs: ${origin}/docs
`;
}

function robotsTxt(origin: string): string {
  return `User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`;
}

function sitemapXml(origin: string): string {
  const urls = [`${origin}/`, `${origin}/docs`, `${origin}/skill.md`, `${origin}/health`];

  const urlset = urls
    .map((u) => `  <url><loc>${escapeXml(u)}</loc></url>`)
    .join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urlset}
</urlset>
`;
}

function securityTxt(origin: string): string {
  const expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
  return `Contact: mailto:security@clawbounties.com\nPreferred-Languages: en\nExpires: ${expires}\nCanonical: ${origin}/.well-known/security.txt\n`;
}

async function handleRegisterWorker(request: Request, env: Env, version: string): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const worker_did_raw = bodyRaw.worker_did;
  const worker_version_raw = bodyRaw.worker_version;
  const listing_raw = bodyRaw.listing;
  const capabilities_raw = bodyRaw.capabilities;
  const offers_raw = bodyRaw.offers;
  const pricing_raw = bodyRaw.pricing;
  const availability_raw = bodyRaw.availability;

  if (!isNonEmptyString(worker_did_raw)) {
    return errorResponse('INVALID_REQUEST', 'worker_did is required', 400, undefined, version);
  }

  const worker_did = worker_did_raw.trim();
  if (!worker_did.startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID string', 400, undefined, version);
  }

  if (!isNonEmptyString(worker_version_raw)) {
    return errorResponse('INVALID_REQUEST', 'worker_version is required', 400, undefined, version);
  }
  const worker_version = worker_version_raw.trim();
  if (worker_version.length > 80) {
    return errorResponse('INVALID_REQUEST', 'worker_version is too long', 400, undefined, version);
  }

  const listing = parseWorkerListing(listing_raw);
  if (!listing) {
    return errorResponse('INVALID_REQUEST', 'listing is invalid', 400, undefined, version);
  }

  const capabilities = parseWorkerCapabilities(capabilities_raw);
  if (!capabilities) {
    return errorResponse('INVALID_REQUEST', 'capabilities is invalid', 400, undefined, version);
  }

  const offers = parseWorkerOffers(offers_raw);
  if (!offers) {
    return errorResponse('INVALID_REQUEST', 'offers is invalid', 400, undefined, version);
  }

  const pricing = parseWorkerPricing(pricing_raw);
  if (!pricing) {
    return errorResponse('INVALID_REQUEST', 'pricing is invalid', 400, undefined, version);
  }

  const availability = parseWorkerAvailability(availability_raw);
  if (!availability) {
    return errorResponse('INVALID_REQUEST', 'availability is invalid', 400, undefined, version);
  }

  const now = new Date().toISOString();

  let existing: WorkerRecordV1 | null;
  try {
    existing = await getWorkerByDid(env.BOUNTIES_DB, worker_did);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  // Prevent trivial DID takeover: if a worker DID already exists, require the existing bearer token
  // to rotate the token / update the record.
  if (existing) {
    const token = getBearerToken(request.headers.get('authorization'));
    if (!token) {
      return errorResponse('UNAUTHORIZED', 'Missing worker token for re-registration', 401, undefined, version);
    }

    let authed: WorkerRecordV1 | null;
    try {
      authed = await getWorkerByAuthToken(env.BOUNTIES_DB, token);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
    }

    if (!authed || authed.worker_did !== worker_did) {
      return errorResponse('UNAUTHORIZED', 'Invalid or expired worker token', 401, undefined, version);
    }
  }

  const worker_id = existing?.worker_id ?? `wrk_${crypto.randomUUID()}`;
  const created_at = existing?.created_at ?? now;

  const authToken = generateWorkerToken();
  const auth_token_hash_hex = await sha256HexUtf8(authToken);
  const ttlSeconds = resolveWorkerTokenTtlSeconds(env);
  const auth_token_expires_at = new Date(Date.now() + ttlSeconds * 1000).toISOString();

  const record: WorkerRecordV1 = {
    worker_id,
    worker_did,
    status: availability.paused ? 'paused' : 'online',
    worker_version,
    listing,
    capabilities,
    offers,
    pricing,
    availability,
    auth_mode: 'token',
    auth_token_hash_hex,
    auth_token_prefix: authToken.slice(0, 8),
    auth_token_created_at: now,
    auth_token_expires_at,
    created_at,
    updated_at: now,
  };

  try {
    await upsertWorker(env.BOUNTIES_DB, record);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  // Re-read after upsert to avoid returning an incorrect worker_id under concurrent registrations.
  let persisted: WorkerRecordV1 | null;
  try {
    persisted = await getWorkerByDid(env.BOUNTIES_DB, worker_did);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!persisted) {
    return errorResponse('DB_READ_FAILED', 'Worker record not found after upsert', 500, undefined, version);
  }

  const response: RegisterWorkerResponseV1 = {
    worker_id: persisted.worker_id,
    auth: { mode: 'token', token: authToken },
  };

  return jsonResponse(response, existing ? 200 : 201, version);
}

async function handleListWorkers(url: URL, env: Env, version: string): Promise<Response> {
  const jobTypeRaw = url.searchParams.get('job_type');
  const job_type = jobTypeRaw?.trim().length ? jobTypeRaw.trim() : null;

  const tags = url.searchParams
    .getAll('tag')
    .map((t) => t.trim())
    .filter((t) => t.length > 0);

  let limit = 50;
  const limitRaw = url.searchParams.get('limit');
  if (limitRaw !== null) {
    const n = Number(limitRaw);
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1 || n > 100) {
      return errorResponse('INVALID_REQUEST', 'limit must be an integer between 1 and 100', 400, undefined, version);
    }
    limit = n;
  }

  // NOTE: We currently store filterable worker fields (job_types/tags) inside JSON.
  // Until we project/index those fields in SQL, we over-fetch a bounded window, filter in-memory,
  // then apply the requested limit so discovery results are not accidentally empty.
  const scanLimit = (job_type || tags.length > 0) ? Math.min(500, Math.max(limit, limit * 10)) : limit;

  let workers: WorkerListItemV1[];
  try {
    workers = await listWorkers(env.BOUNTIES_DB, scanLimit);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (job_type) {
    workers = workers.filter((w) => w.capabilities.job_types.includes(job_type));
  }

  if (tags.length > 0) {
    workers = workers.filter((w) => tags.some((t) => w.listing.tags.includes(t)));
  }

  workers = workers.slice(0, limit);

  return jsonResponse({ workers }, 200, version);
}

async function handleGetWorkerSelf(request: Request, env: Env, version: string): Promise<Response> {
  const auth = await requireWorker(request, env, version);
  if ('error' in auth) return auth.error;

  const w = auth.worker;
  return jsonResponse(
    {
      worker_id: w.worker_id,
      worker_did: w.worker_did,
      status: w.status,
      worker_version: w.worker_version,
      listing: w.listing,
      capabilities: w.capabilities,
      offers: w.offers,
      pricing: w.pricing,
      availability: w.availability,
      auth: { mode: w.auth_mode, expires_at: w.auth_token_expires_at },
      created_at: w.created_at,
      updated_at: w.updated_at,
    },
    200,
    version
  );
}

function parseEscrowFailedError(err: unknown): { status: number; payload: Record<string, unknown> } | null {
  if (!(err instanceof Error)) return null;
  const prefix = 'ESCROW_FAILED:';
  if (!err.message.startsWith(prefix)) return null;

  const rest = err.message.slice(prefix.length);
  const idx = rest.indexOf(':');
  if (idx === -1) return null;

  const statusRaw = rest.slice(0, idx);
  const status = Number(statusRaw);
  if (!Number.isFinite(status)) return null;

  const payloadRaw = rest.slice(idx + 1);
  try {
    const parsed = JSON.parse(payloadRaw) as unknown;
    if (isRecord(parsed)) return { status, payload: parsed };
    return { status, payload: { raw: parsed } };
  } catch {
    return { status, payload: { raw: payloadRaw } };
  }
}

async function handleAcceptBounty(bountyId: string, request: Request, env: Env, version: string): Promise<Response> {
  const auth = await requireWorker(request, env, version);
  if ('error' in auth) return auth.error;

  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotency_key_raw = bodyRaw.idempotency_key;
  const worker_did_raw = bodyRaw.worker_did;

  if (!isNonEmptyString(idempotency_key_raw)) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is required', 400, undefined, version);
  }

  const idempotency_key = idempotency_key_raw.trim();
  if (idempotency_key.length > 200) {
    return errorResponse('INVALID_REQUEST', 'idempotency_key is too long', 400, undefined, version);
  }

  if (!isNonEmptyString(worker_did_raw) || !worker_did_raw.trim().startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'worker_did must be a DID string', 400, undefined, version);
  }

  const worker_did = worker_did_raw.trim();
  if (worker_did !== auth.worker.worker_did) {
    return errorResponse('UNAUTHORIZED', 'worker_did must match authenticated worker', 401, undefined, version);
  }

  let bounty: BountyV2 | null;
  try {
    bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_READ_FAILED', message, 500, undefined, version);
  }

  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, undefined, version);
  }

  const requested = bounty.metadata.requested_worker_did;
  if (requested !== undefined && requested !== null) {
    if (!isNonEmptyString(requested) || !requested.trim().startsWith('did:')) {
      return errorResponse('BOUNTY_METADATA_INVALID', 'metadata.requested_worker_did is invalid', 500, undefined, version);
    }

    const requestedDid = requested.trim();
    if (requestedDid !== worker_did) {
      return errorResponse(
        'FORBIDDEN',
        'Bounty is direct-hire to a different worker',
        403,
        { requested_worker_did: requestedDid },
        version
      );
    }
  }

  // Already accepted.
  if (bounty.worker_did) {
    if (bounty.worker_did === worker_did) {
      const accepted_at = bounty.accepted_at ?? bounty.updated_at;
      const response: AcceptBountyResponseV1 = {
        bounty_id: bounty.bounty_id,
        escrow_id: bounty.escrow_id,
        status: 'accepted',
        worker_did,
        accepted_at,
        fee_policy_version: bounty.fee_policy_version,
        payout: {
          worker_net_minor: bounty.fee_quote.quote.worker_net_minor,
          currency: 'USD',
        },
      };

      return jsonResponse(response, 200, version);
    }

    return errorResponse('BOUNTY_ALREADY_ACCEPTED', 'Bounty already accepted', 409, { worker_did: bounty.worker_did }, version);
  }

  if (bounty.status !== 'open') {
    return errorResponse('INVALID_STATUS', `Cannot accept bounty in status '${bounty.status}'`, 409, undefined, version);
  }

  const now = new Date().toISOString();

  // Assign escrow (canonical lock)
  try {
    await escrowAssignWorker(env, {
      escrow_id: bounty.escrow_id,
      idempotency_key,
      worker_did,
    });
  } catch (err) {
    const parsed = parseEscrowFailedError(err);
    if (parsed && parsed.status === 409) {
      const code = isNonEmptyString(parsed.payload.error) ? parsed.payload.error.trim() : 'ESCROW_CONFLICT';
      const message = isNonEmptyString(parsed.payload.message) ? parsed.payload.message.trim() : 'Escrow conflict';
      return errorResponse(code, message, 409, undefined, version);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('ESCROW_FAILED', message, 502, undefined, version);
  }

  // Persist acceptance on bounty.
  try {
    await updateBountyAccepted(env.BOUNTIES_DB, {
      bounty_id: bountyId,
      worker_did,
      accepted_at: now,
      idempotency_key,
      now,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const updated = await getBountyById(env.BOUNTIES_DB, bountyId);
  if (!updated || updated.status !== 'accepted' || updated.worker_did !== worker_did) {
    return errorResponse('DB_WRITE_FAILED', 'Failed to persist bounty acceptance', 500, undefined, version);
  }

  const response: AcceptBountyResponseV1 = {
    bounty_id: updated.bounty_id,
    escrow_id: updated.escrow_id,
    status: 'accepted',
    worker_did,
    accepted_at: updated.accepted_at ?? now,
    fee_policy_version: updated.fee_policy_version,
    payout: {
      worker_net_minor: updated.fee_quote.quote.worker_net_minor,
      currency: 'USD',
    },
  };

  return jsonResponse(response, 201, version);
}

async function handlePostBounty(request: Request, env: Env, version: string): Promise<Response> {
  const requesterHeader = requireRequesterDid(request, version);
  if ('error' in requesterHeader) return requesterHeader.error;

  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const title = bodyRaw.title;
  const description = bodyRaw.description;
  const reward = bodyRaw.reward;
  const closure_type_raw = bodyRaw.closure_type;
  const difficulty_raw = bodyRaw.difficulty_scalar;

  const is_code_bounty_raw = bodyRaw.is_code_bounty;
  const tags_raw = bodyRaw.tags;
  const min_proof_tier_raw = bodyRaw.min_proof_tier;
  const require_owner_verified_votes_raw = bodyRaw.require_owner_verified_votes;
  const test_harness_id_raw = bodyRaw.test_harness_id;
  const idempotency_key_raw = bodyRaw.idempotency_key;
  const metadata_raw = bodyRaw.metadata;

  if (!isNonEmptyString(title)) {
    return errorResponse('INVALID_REQUEST', 'title is required', 400, undefined, version);
  }

  if (!isNonEmptyString(description)) {
    return errorResponse('INVALID_REQUEST', 'description is required', 400, undefined, version);
  }

  if (!isRecord(reward)) {
    return errorResponse('INVALID_REQUEST', 'reward must be an object', 400, undefined, version);
  }

  const amount_minor_raw = reward.amount_minor;
  const currency_raw = reward.currency;

  const amountMinor = parsePositiveMinor(amount_minor_raw);
  if (amountMinor === null) {
    return errorResponse('INVALID_REQUEST', 'reward.amount_minor must be a positive integer string', 400, undefined, version);
  }

  if (currency_raw !== 'USD') {
    return errorResponse('UNSUPPORTED_CURRENCY', 'Only USD is supported', 400, undefined, version);
  }

  const closure_type = parseClosureType(closure_type_raw);
  if (!closure_type) {
    return errorResponse('INVALID_REQUEST', 'closure_type must be one of test|requester|quorum', 400, undefined, version);
  }

  const difficulty_scalar = parseDifficultyScalar(difficulty_raw);
  if (difficulty_scalar === null) {
    return errorResponse('INVALID_REQUEST', 'difficulty_scalar must be a number between 0.1 and 10.0', 400, undefined, version);
  }

  let is_code_bounty = false;
  if (is_code_bounty_raw !== undefined) {
    if (typeof is_code_bounty_raw !== 'boolean') {
      return errorResponse('INVALID_REQUEST', 'is_code_bounty must be a boolean', 400, undefined, version);
    }
    is_code_bounty = is_code_bounty_raw;
  }

  const tags = parseTags(tags_raw);
  if (tags === null) {
    return errorResponse('INVALID_REQUEST', 'tags must be an array of non-empty strings (max 10)', 400, undefined, version);
  }

  const min_proof_tier = parseProofTier(min_proof_tier_raw) ?? 'self';

  let require_owner_verified_votes = false;
  if (require_owner_verified_votes_raw !== undefined) {
    if (typeof require_owner_verified_votes_raw !== 'boolean') {
      return errorResponse('INVALID_REQUEST', 'require_owner_verified_votes must be a boolean', 400, undefined, version);
    }
    require_owner_verified_votes = require_owner_verified_votes_raw;
  }

  let test_harness_id: string | null = null;
  if (test_harness_id_raw !== undefined) {
    if (test_harness_id_raw !== null && !isNonEmptyString(test_harness_id_raw)) {
      return errorResponse('INVALID_REQUEST', 'test_harness_id must be a string', 400, undefined, version);
    }
    test_harness_id = test_harness_id_raw === null || test_harness_id_raw === undefined ? null : test_harness_id_raw.trim();
  }

  if (closure_type === 'test') {
    if (!is_code_bounty) {
      return errorResponse('INVALID_REQUEST', 'closure_type=test requires is_code_bounty=true', 400, undefined, version);
    }
    if (!test_harness_id) {
      return errorResponse('INVALID_REQUEST', 'test_harness_id is required when closure_type=test', 400, undefined, version);
    }
  }

  const metadata = metadata_raw === undefined || metadata_raw === null ? {} : metadata_raw;
  if (!isRecord(metadata)) {
    return errorResponse('INVALID_REQUEST', 'metadata must be an object', 400, undefined, version);
  }

  const requested_worker_did = metadata.requested_worker_did;
  if (requested_worker_did !== undefined) {
    if (requested_worker_did !== null && (!isNonEmptyString(requested_worker_did) || !requested_worker_did.trim().startsWith('did:'))) {
      return errorResponse('INVALID_REQUEST', 'metadata.requested_worker_did must be a DID string when provided', 400, undefined, version);
    }
  }

  let idempotency_key: string;
  if (idempotency_key_raw !== undefined && idempotency_key_raw !== null) {
    if (!isNonEmptyString(idempotency_key_raw)) {
      return errorResponse('INVALID_REQUEST', 'idempotency_key must be a non-empty string', 400, undefined, version);
    }
    idempotency_key = idempotency_key_raw.trim();
  } else {
    idempotency_key = await deriveIdempotencyKey(requesterHeader.requester_did, bodyRaw);
  }

  const existing = await getBountyByIdempotencyKey(env.BOUNTIES_DB, idempotency_key);
  if (existing) {
    const response: PostBountyResponseV2 = {
      schema_version: '2',
      bounty_id: existing.bounty_id,
      escrow_id: existing.escrow_id,
      status: 'open',
      all_in_cost: existing.all_in_cost,
      fee_policy_version: existing.fee_policy_version,
      created_at: existing.created_at,
    };
    return jsonResponse(response, 200, version);
  }

  // 1) Fee quote (clawcuts)
  let feeQuote: CutsSimulateResponse;
  try {
    feeQuote = await cutsSimulateFees(env, {
      requester_did: requesterHeader.requester_did,
      amount_minor: amountMinor.toString(),
      closure_type,
      is_code_bounty,
      min_proof_tier,
      tags,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('CUTS_FAILED', message, 502, undefined, version);
  }

  const buyerFees = feeQuote.quote.fees.filter((f) => f.payer === 'buyer');
  let platformFeeMinor: string;
  try {
    platformFeeMinor = sumFeesMinor(buyerFees).toString();
  } catch {
    return errorResponse('CUTS_INVALID_RESPONSE', 'Invalid fee item amounts in cuts response', 502, undefined, version);
  }

  const all_in_cost: AllInCostV2 = {
    principal_minor: feeQuote.quote.principal_minor,
    platform_fee_minor: platformFeeMinor,
    total_minor: feeQuote.quote.buyer_total_minor,
    currency: 'USD',
  };

  // 2) Create escrow hold (clawescrow)
  const bounty_id = `bty_${crypto.randomUUID()}`;

  const escrowFeeSnapshot: EscrowFeeQuoteSnapshot = {
    policy_id: feeQuote.policy.id,
    policy_version: feeQuote.policy.version,
    policy_hash_b64u: feeQuote.policy.hash_b64u,
    buyer_total_minor: feeQuote.quote.buyer_total_minor,
    worker_net_minor: feeQuote.quote.worker_net_minor,
    fees: feeQuote.quote.fees,
  };

  let escrow_id: string;
  try {
    const escrow = await escrowCreateHold(env, {
      idempotency_key: `bounty:${idempotency_key}:escrow`,
      buyer_did: requesterHeader.requester_did,
      amount_minor: amountMinor.toString(),
      fee_quote: escrowFeeSnapshot,
      metadata: {
        product: 'clawbounties',
        schema_version: '2',
        bounty_id,
        closure_type,
        difficulty_scalar,
        is_code_bounty,
        tags,
        min_proof_tier,
        requested_worker_did: requested_worker_did ?? null,
        fee_policy: {
          id: feeQuote.policy.id,
          version: feeQuote.policy.version,
          hash_b64u: feeQuote.policy.hash_b64u,
        },
      },
    });
    escrow_id = escrow.escrow_id;
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('ESCROW_FAILED', message, 502, undefined, version);
  }

  const now = new Date().toISOString();

  const record: BountyV2 = {
    schema_version: '2',
    bounty_id,
    requester_did: requesterHeader.requester_did,
    title: title.trim(),
    description: description.trim(),
    reward: { amount_minor: amountMinor.toString(), currency: 'USD' },
    closure_type,
    difficulty_scalar,
    escrow_id,
    status: 'open',
    created_at: now,

    worker_did: null,
    accept_idempotency_key: null,
    accepted_at: null,

    is_code_bounty,
    tags,
    min_proof_tier,
    require_owner_verified_votes,
    test_harness_id,
    metadata,
    idempotency_key,

    fee_policy_version: feeQuote.policy.version,
    all_in_cost,

    fee_quote: feeQuote,
    updated_at: now,
  };

  try {
    await insertBounty(env.BOUNTIES_DB, record);
  } catch (err) {
    const existingAfter = await getBountyByIdempotencyKey(env.BOUNTIES_DB, idempotency_key);
    if (existingAfter) {
      const response: PostBountyResponseV2 = {
        schema_version: '2',
        bounty_id: existingAfter.bounty_id,
        escrow_id: existingAfter.escrow_id,
        status: 'open',
        all_in_cost: existingAfter.all_in_cost,
        fee_policy_version: existingAfter.fee_policy_version,
        created_at: existingAfter.created_at,
      };
      return jsonResponse(response, 200, version);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const response: PostBountyResponseV2 = {
    schema_version: '2',
    bounty_id,
    escrow_id,
    status: 'open',
    all_in_cost,
    fee_policy_version: feeQuote.policy.version,
    created_at: now,
  };

  return jsonResponse(response, 201, version);
}

async function handleListBounties(url: URL, env: Env, version: string): Promise<Response> {
  const statusRaw = url.searchParams.get('status') ?? 'open';
  const status = parseBountyStatus(statusRaw);
  if (!status) {
    return errorResponse('INVALID_REQUEST', 'status must be open|accepted|pending_review|approved|rejected|disputed|cancelled', 400, undefined, version);
  }

  const isCodeRaw = url.searchParams.get('is_code_bounty');
  let is_code_bounty: boolean | undefined;
  if (isCodeRaw !== null) {
    const v = isCodeRaw.trim().toLowerCase();
    if (v !== 'true' && v !== 'false') {
      return errorResponse('INVALID_REQUEST', 'is_code_bounty must be true|false', 400, undefined, version);
    }
    is_code_bounty = v === 'true';
  }

  const tags = url.searchParams.getAll('tag').map((t) => t.trim()).filter((t) => t.length > 0);

  const bounties = await listBounties(env.BOUNTIES_DB, { status, is_code_bounty, tags }, 100);
  return jsonResponse({ bounties }, 200, version);
}

async function handleListBountiesForWorker(request: Request, url: URL, env: Env, version: string): Promise<Response> {
  const auth = await requireWorker(request, env, version);
  if ('error' in auth) return auth.error;

  const statusRaw = url.searchParams.get('status') ?? 'open';
  const status = parseBountyStatus(statusRaw);
  if (!status) {
    return errorResponse('INVALID_REQUEST', 'status must be open', 400, undefined, version);
  }

  if (status !== 'open') {
    return errorResponse('FORBIDDEN', 'Workers may only list open bounties', 403, undefined, version);
  }

  const isCodeRaw = url.searchParams.get('is_code_bounty');
  let is_code_bounty: boolean | undefined;
  if (isCodeRaw !== null) {
    const v = isCodeRaw.trim().toLowerCase();
    if (v !== 'true' && v !== 'false') {
      return errorResponse('INVALID_REQUEST', 'is_code_bounty must be true|false', 400, undefined, version);
    }
    is_code_bounty = v === 'true';
  }

  const tags = url.searchParams.getAll('tag').map((t) => t.trim()).filter((t) => t.length > 0);

  const bounties = await listWorkerBounties(
    env.BOUNTIES_DB,
    auth.worker.worker_did,
    { status, is_code_bounty, tags },
    100
  );
  return jsonResponse({ bounties }, 200, version);
}

async function handleGetBounty(bountyId: string, env: Env, version: string): Promise<Response> {
  const bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, undefined, version);
  }

  return jsonResponse(bounty, 200, version);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    const version = env.BOUNTIES_VERSION?.trim().length ? env.BOUNTIES_VERSION.trim() : '0.1.0';

    // Public endpoints
    if (method === 'GET' || method === 'HEAD') {
      const origin = url.origin;

      if (path === '/') return htmlResponse(landingPage(origin, env), 200, version);
      if (path === '/docs') return htmlResponse(docsPage(origin), 200, version);
      if (path === '/skill.md') return textResponse(skillMarkdown(origin), 'text/markdown; charset=utf-8', 200, version);
      if (path === '/health') {
        return jsonResponse(
          {
            status: 'ok',
            service: 'clawbounties',
            version,
            environment: env.ENVIRONMENT ?? 'unknown',
          },
          200,
          version
        );
      }
      if (path === '/robots.txt') return textResponse(robotsTxt(origin), 'text/plain; charset=utf-8', 200, version);
      if (path === '/sitemap.xml') return textResponse(sitemapXml(origin), 'application/xml; charset=utf-8', 200, version);
      if (path === '/.well-known/security.txt') return textResponse(securityTxt(origin), 'text/plain; charset=utf-8', 200, version);
    }

    // API
    if (path.startsWith('/v1/')) {
      // Worker API (public)
      if (path === '/v1/workers/register' && method === 'POST') {
        return handleRegisterWorker(request, env, version);
      }

      if (path === '/v1/workers' && method === 'GET') {
        return handleListWorkers(url, env, version);
      }

      if (path === '/v1/workers/self' && method === 'GET') {
        return handleGetWorkerSelf(request, env, version);
      }

      const acceptMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)\/accept$/);
      if (acceptMatch && method === 'POST') {
        const bountyId = acceptMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleAcceptBounty(bountyId, request, env, version);
      }

      if (path === '/v1/bounties' && method === 'GET') {
        if (isAdminAuthorized(request, env)) {
          return handleListBounties(url, env, version);
        }
        return handleListBountiesForWorker(request, url, env, version);
      }

      // Bounties API (admin)
      const adminError = requireAdmin(request, env, version);
      if (adminError) return adminError;

      if (path === '/v1/bounties' && method === 'POST') {
        return handlePostBounty(request, env, version);
      }

      const bountyMatch = path.match(/^\/v1\/bounties\/(bty_[a-f0-9-]+)$/);
      if (bountyMatch && method === 'GET') {
        const bountyId = bountyMatch[1];
        if (!bountyId) {
          return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
        }
        return handleGetBounty(bountyId, env, version);
      }

      return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
    }

    return errorResponse('NOT_FOUND', 'Not found', 404, { path, method }, version);
  },
};
