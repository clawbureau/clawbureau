/**
 * clawbounties.com worker
 *
 * - Public discovery endpoints (landing/docs/skill/health/robots/sitemap/security)
 * - Admin-gated marketplace API (MVP): post + list bounties
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

  /** D1 database binding */
  BOUNTIES_DB: D1Database;
}

type JobType = 'code' | 'research' | 'agent_pack';
type ClosureType = 'test' | 'requester' | 'quorum';

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

interface PostBountyResponseBody {
  bounty_id: string;
  escrow_id: string;
  status: 'open';
  fee_quote: {
    principal_minor: string;
    buyer_total_minor: string;
    policy_id: string;
    policy_version: string;
    policy_hash_b64u: string;
  };
}

interface BountyListItem {
  bounty_id: string;
  buyer_did: string;
  job_type: JobType;
  closure_type: ClosureType;
  title: string;
  reward_minor: string;
  currency: 'USD';
  status: string;
  created_at: string;
  escrow_id: string;
}

interface BountyRecord extends BountyListItem {
  create_idempotency_key: string;
  requested_worker_did: string | null;
  worker_did: string | null;
  description: string;
  fee_quote: CutsSimulateResponse;
  updated_at: string;
  test_spec: Record<string, unknown> | null;
  deliverable_spec: Record<string, unknown> | null;
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

function getBearerToken(header: string | null): string | null {
  if (!header) return null;
  const trimmed = header.trim();
  if (!trimmed) return null;
  if (trimmed.toLowerCase().startsWith('bearer ')) return trimmed.slice(7).trim();
  return trimmed;
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

async function cutsSimulateFees(env: Env, params: { job_type: JobType; closure_type: ClosureType; amount_minor: string }): Promise<CutsSimulateResponse> {
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
        job_type: params.job_type,
        closure_type: params.closure_type,
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

  // Shallow validate fees array.
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
    dispute_window_seconds?: number;
    metadata?: Record<string, unknown>;
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
      dispute_window_seconds: params.dispute_window_seconds,
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

function d1String(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return value.toString();
  return null;
}

function parseBountyRow(row: Record<string, unknown>): BountyRecord | null {
  const bounty_id = d1String(row.bounty_id);
  const create_idempotency_key = d1String(row.create_idempotency_key);
  const buyer_did = d1String(row.buyer_did);
  const job_type = d1String(row.job_type);
  const closure_type = d1String(row.closure_type);
  const title = d1String(row.title);
  const description = d1String(row.description);
  const reward_minor = d1String(row.reward_minor);
  const currency = d1String(row.currency);
  const fee_quote_json = d1String(row.fee_quote_json);
  const escrow_id = d1String(row.escrow_id);
  const status = d1String(row.status);
  const created_at = d1String(row.created_at);
  const updated_at = d1String(row.updated_at);

  if (
    !bounty_id ||
    !create_idempotency_key ||
    !buyer_did ||
    !job_type ||
    !closure_type ||
    !title ||
    !description ||
    !reward_minor ||
    currency !== 'USD' ||
    !fee_quote_json ||
    !escrow_id ||
    !status ||
    !created_at ||
    !updated_at
  ) {
    return null;
  }

  const job = job_type as JobType;
  if (job !== 'code' && job !== 'research' && job !== 'agent_pack') return null;

  const closure = closure_type as ClosureType;
  if (closure !== 'test' && closure !== 'requester' && closure !== 'quorum') return null;

  let fee_quote: CutsSimulateResponse;
  try {
    fee_quote = JSON.parse(fee_quote_json) as CutsSimulateResponse;
  } catch {
    return null;
  }

  const test_spec = row.test_spec_json ? (JSON.parse(d1String(row.test_spec_json) ?? 'null') as Record<string, unknown> | null) : null;
  const deliverable_spec = row.deliverable_spec_json
    ? (JSON.parse(d1String(row.deliverable_spec_json) ?? 'null') as Record<string, unknown> | null)
    : null;

  return {
    bounty_id,
    create_idempotency_key,
    buyer_did,
    requested_worker_did: d1String(row.requested_worker_did),
    worker_did: d1String(row.worker_did),
    job_type: job,
    closure_type: closure,
    title,
    description,
    reward_minor,
    currency: 'USD',
    fee_quote,
    escrow_id,
    status,
    created_at,
    updated_at,
    test_spec,
    deliverable_spec,
  };
}

async function getBountyByIdempotencyKey(db: D1Database, key: string): Promise<BountyRecord | null> {
  const row = await db.prepare('SELECT * FROM bounties WHERE create_idempotency_key = ?').bind(key).first();
  if (!row || !isRecord(row)) return null;
  return parseBountyRow(row);
}

async function getBountyById(db: D1Database, bountyId: string): Promise<BountyRecord | null> {
  const row = await db.prepare('SELECT * FROM bounties WHERE bounty_id = ?').bind(bountyId).first();
  if (!row || !isRecord(row)) return null;
  return parseBountyRow(row);
}

async function insertBounty(db: D1Database, record: BountyRecord): Promise<void> {
  await db
    .prepare(
      `INSERT INTO bounties (
        bounty_id,
        create_idempotency_key,
        buyer_did,
        requested_worker_did,
        worker_did,
        job_type,
        closure_type,
        title,
        description,
        reward_minor,
        currency,
        fee_quote_json,
        escrow_id,
        status,
        created_at,
        updated_at,
        test_spec_json,
        deliverable_spec_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      record.bounty_id,
      record.create_idempotency_key,
      record.buyer_did,
      record.requested_worker_did,
      record.worker_did,
      record.job_type,
      record.closure_type,
      record.title,
      record.description,
      record.reward_minor,
      record.currency,
      JSON.stringify(record.fee_quote),
      record.escrow_id,
      record.status,
      record.created_at,
      record.updated_at,
      record.test_spec ? JSON.stringify(record.test_spec) : null,
      record.deliverable_spec ? JSON.stringify(record.deliverable_spec) : null
    )
    .run();
}

async function listBounties(db: D1Database, filters: { status?: string; job_type?: JobType }, limit = 50): Promise<BountyListItem[]> {
  const status = filters.status ?? 'open';
  const job = filters.job_type;

  if (job) {
    const results = await db
      .prepare(
        `SELECT bounty_id, buyer_did, job_type, closure_type, title, reward_minor, currency, status, created_at, escrow_id
         FROM bounties
         WHERE status = ? AND job_type = ?
         ORDER BY created_at DESC
         LIMIT ?`
      )
      .bind(status, job, limit)
      .all();

    return (results.results ?? [])
      .filter(isRecord)
      .map((row) => ({
        bounty_id: d1String(row.bounty_id) ?? '',
        buyer_did: d1String(row.buyer_did) ?? '',
        job_type: row.job_type as JobType,
        closure_type: row.closure_type as ClosureType,
        title: d1String(row.title) ?? '',
        reward_minor: d1String(row.reward_minor) ?? '',
        currency: 'USD' as const,
        status: d1String(row.status) ?? '',
        created_at: d1String(row.created_at) ?? '',
        escrow_id: d1String(row.escrow_id) ?? '',
      }))
      .filter((b) => b.bounty_id.length > 0);
  }

  const results = await db
    .prepare(
      `SELECT bounty_id, buyer_did, job_type, closure_type, title, reward_minor, currency, status, created_at, escrow_id
       FROM bounties
       WHERE status = ?
       ORDER BY created_at DESC
       LIMIT ?`
    )
    .bind(status, limit)
    .all();

  return (results.results ?? [])
    .filter(isRecord)
    .map((row) => ({
      bounty_id: d1String(row.bounty_id) ?? '',
      buyer_did: d1String(row.buyer_did) ?? '',
      job_type: row.job_type as JobType,
      closure_type: row.closure_type as ClosureType,
      title: d1String(row.title) ?? '',
      reward_minor: d1String(row.reward_minor) ?? '',
      currency: 'USD' as const,
      status: d1String(row.status) ?? '',
      created_at: d1String(row.created_at) ?? '',
      escrow_id: d1String(row.escrow_id) ?? '',
    }))
    .filter((b) => b.bounty_id.length > 0);
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

      <h2>Marketplace API (admin)</h2>
      <p>All <code>/v1/*</code> endpoints require <code>Authorization: Bearer &lt;BOUNTIES_ADMIN_KEY&gt;</code>.</p>
      <ul>
        <li><code>POST /v1/bounties</code> — post a bounty (calls clawcuts + clawescrow)</li>
        <li><code>GET /v1/bounties?status=open&amp;job_type=code</code> — list bounties</li>
        <li><code>GET /v1/bounties/{bounty_id}</code> — fetch a bounty</li>
      </ul>

      <p style="margin-top: 24px;">Quick start:</p>
      <pre>curl -sS "${escapeHtml(origin)}/skill.md"</pre>
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
    ],
  };

  // OpenClaw requirement: metadata must be a single-line JSON object string
  const md = `---
metadata: '${JSON.stringify(metadata)}'
---

# clawbounties

Developer discovery + minimal marketplace API.

- Docs: ${origin}/docs
`;

  return md;
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

async function handlePostBounty(request: Request, env: Env, version: string): Promise<Response> {
  const bodyRaw = await parseJsonBody(request);
  if (!isRecord(bodyRaw)) {
    return errorResponse('INVALID_REQUEST', 'Invalid JSON body', 400, undefined, version);
  }

  const idempotency_key = bodyRaw.idempotency_key;
  const buyer_did = bodyRaw.buyer_did;
  const requested_worker_did = bodyRaw.requested_worker_did;
  const job_type = bodyRaw.job_type;
  const closure_type = bodyRaw.closure_type;
  const title = bodyRaw.title;
  const description = bodyRaw.description;
  const reward_minor = bodyRaw.reward_minor;
  const currency = bodyRaw.currency;
  const test_spec = bodyRaw.test_spec;
  const deliverable_spec = bodyRaw.deliverable_spec;
  const dispute_window_seconds = bodyRaw.dispute_window_seconds;

  if (!isNonEmptyString(idempotency_key)) {
    return errorResponse('INVALID_REQUEST', 'Missing required field: idempotency_key', 400, undefined, version);
  }

  const existing = await getBountyByIdempotencyKey(env.BOUNTIES_DB, idempotency_key.trim());
  if (existing) {
    const response: PostBountyResponseBody = {
      bounty_id: existing.bounty_id,
      escrow_id: existing.escrow_id,
      status: 'open',
      fee_quote: {
        principal_minor: existing.fee_quote.quote.principal_minor,
        buyer_total_minor: existing.fee_quote.quote.buyer_total_minor,
        policy_id: existing.fee_quote.policy.id,
        policy_version: existing.fee_quote.policy.version,
        policy_hash_b64u: existing.fee_quote.policy.hash_b64u,
      },
    };
    return jsonResponse(response, 200, version);
  }

  if (!isNonEmptyString(buyer_did) || !buyer_did.trim().startsWith('did:')) {
    return errorResponse('INVALID_REQUEST', 'buyer_did must be a DID string', 400, undefined, version);
  }

  if (requested_worker_did !== undefined) {
    if (requested_worker_did !== null && (!isNonEmptyString(requested_worker_did) || !requested_worker_did.trim().startsWith('did:'))) {
      return errorResponse('INVALID_REQUEST', 'requested_worker_did must be a DID string', 400, undefined, version);
    }
  }

  if (currency !== 'USD') {
    return errorResponse('UNSUPPORTED_CURRENCY', 'Only USD is supported', 400, undefined, version);
  }

  const reward = parsePositiveMinor(reward_minor);
  if (reward === null) {
    return errorResponse('INVALID_REQUEST', 'reward_minor must be a positive integer string', 400, undefined, version);
  }

  const job = job_type as JobType;
  if (job !== 'code' && job !== 'research' && job !== 'agent_pack') {
    return errorResponse('INVALID_REQUEST', 'job_type must be one of code|research|agent_pack', 400, undefined, version);
  }

  const closure = closure_type as ClosureType;
  if (closure !== 'test' && closure !== 'requester' && closure !== 'quorum') {
    return errorResponse('INVALID_REQUEST', 'closure_type must be one of test|requester|quorum', 400, undefined, version);
  }

  if (!isNonEmptyString(title)) {
    return errorResponse('INVALID_REQUEST', 'title is required', 400, undefined, version);
  }

  if (!isNonEmptyString(description)) {
    return errorResponse('INVALID_REQUEST', 'description is required', 400, undefined, version);
  }

  if (test_spec !== undefined && test_spec !== null && !isRecord(test_spec)) {
    return errorResponse('INVALID_REQUEST', 'test_spec must be an object', 400, undefined, version);
  }

  if (deliverable_spec !== undefined && deliverable_spec !== null && !isRecord(deliverable_spec)) {
    return errorResponse('INVALID_REQUEST', 'deliverable_spec must be an object', 400, undefined, version);
  }

  let disputeWindowSeconds: number | undefined;
  if (dispute_window_seconds !== undefined) {
    if (typeof dispute_window_seconds !== 'number' || !Number.isFinite(dispute_window_seconds) || dispute_window_seconds <= 0) {
      return errorResponse('INVALID_REQUEST', 'dispute_window_seconds must be a positive number', 400, undefined, version);
    }
    disputeWindowSeconds = Math.floor(dispute_window_seconds);
  }

  // 1) Fee quote (clawcuts)
  let feeQuote: CutsSimulateResponse;
  try {
    feeQuote = await cutsSimulateFees(env, {
      job_type: job,
      closure_type: closure,
      amount_minor: reward.toString(),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('CUTS_FAILED', message, 502, undefined, version);
  }

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
      idempotency_key: `bounty:${idempotency_key.trim()}:escrow`,
      buyer_did: buyer_did.trim(),
      amount_minor: reward.toString(),
      fee_quote: escrowFeeSnapshot,
      dispute_window_seconds: disputeWindowSeconds,
      metadata: {
        product: 'clawbounties',
        bounty_id,
      },
    });
    escrow_id = escrow.escrow_id;
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('ESCROW_FAILED', message, 502, undefined, version);
  }

  const now = new Date().toISOString();

  const record: BountyRecord = {
    bounty_id,
    create_idempotency_key: idempotency_key.trim(),
    buyer_did: buyer_did.trim(),
    requested_worker_did: requested_worker_did ? (requested_worker_did as string).trim() : null,
    worker_did: null,
    job_type: job,
    closure_type: closure,
    title: title.trim(),
    description: description.trim(),
    reward_minor: reward.toString(),
    currency: 'USD',
    fee_quote: feeQuote,
    escrow_id,
    status: 'open',
    created_at: now,
    updated_at: now,
    test_spec: test_spec ? (test_spec as Record<string, unknown>) : null,
    deliverable_spec: deliverable_spec ? (deliverable_spec as Record<string, unknown>) : null,
  };

  try {
    await insertBounty(env.BOUNTIES_DB, record);
  } catch (err) {
    const existingAfter = await getBountyByIdempotencyKey(env.BOUNTIES_DB, idempotency_key.trim());
    if (existingAfter) {
      const response: PostBountyResponseBody = {
        bounty_id: existingAfter.bounty_id,
        escrow_id: existingAfter.escrow_id,
        status: 'open',
        fee_quote: {
          principal_minor: existingAfter.fee_quote.quote.principal_minor,
          buyer_total_minor: existingAfter.fee_quote.quote.buyer_total_minor,
          policy_id: existingAfter.fee_quote.policy.id,
          policy_version: existingAfter.fee_quote.policy.version,
          policy_hash_b64u: existingAfter.fee_quote.policy.hash_b64u,
        },
      };
      return jsonResponse(response, 200, version);
    }

    const message = err instanceof Error ? err.message : 'Unknown error';
    return errorResponse('DB_WRITE_FAILED', message, 500, undefined, version);
  }

  const response: PostBountyResponseBody = {
    bounty_id,
    escrow_id,
    status: 'open',
    fee_quote: {
      principal_minor: feeQuote.quote.principal_minor,
      buyer_total_minor: feeQuote.quote.buyer_total_minor,
      policy_id: feeQuote.policy.id,
      policy_version: feeQuote.policy.version,
      policy_hash_b64u: feeQuote.policy.hash_b64u,
    },
  };

  return jsonResponse(response, 201, version);
}

async function handleListBounties(url: URL, env: Env, version: string): Promise<Response> {
  const status = url.searchParams.get('status') ?? 'open';
  const jobType = url.searchParams.get('job_type');

  let job: JobType | undefined;
  if (jobType) {
    const jt = jobType.trim() as JobType;
    if (jt !== 'code' && jt !== 'research' && jt !== 'agent_pack') {
      return errorResponse('INVALID_REQUEST', 'job_type must be code|research|agent_pack', 400, undefined, version);
    }
    job = jt;
  }

  const bounties = await listBounties(env.BOUNTIES_DB, { status: status.trim(), job_type: job }, 100);
  return jsonResponse({ bounties }, 200, version);
}

async function handleGetBounty(bountyId: string, env: Env, version: string): Promise<Response> {
  const bounty = await getBountyById(env.BOUNTIES_DB, bountyId);
  if (!bounty) {
    return errorResponse('NOT_FOUND', 'Bounty not found', 404, undefined, version);
  }

  return jsonResponse(
    {
      bounty_id: bounty.bounty_id,
      escrow_id: bounty.escrow_id,
      status: bounty.status,
      buyer_did: bounty.buyer_did,
      requested_worker_did: bounty.requested_worker_did,
      worker_did: bounty.worker_did,
      job_type: bounty.job_type,
      closure_type: bounty.closure_type,
      title: bounty.title,
      description: bounty.description,
      reward_minor: bounty.reward_minor,
      currency: bounty.currency,
      fee_quote: bounty.fee_quote,
      created_at: bounty.created_at,
      updated_at: bounty.updated_at,
      test_spec: bounty.test_spec,
      deliverable_spec: bounty.deliverable_spec,
    },
    200,
    version
  );
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

    // API (admin)
    if (path.startsWith('/v1/')) {
      const adminError = requireAdmin(request, env, version);
      if (adminError) return adminError;

      if (path === '/v1/bounties' && method === 'POST') {
        return handlePostBounty(request, env, version);
      }

      if (path === '/v1/bounties' && method === 'GET') {
        return handleListBounties(url, env, version);
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
