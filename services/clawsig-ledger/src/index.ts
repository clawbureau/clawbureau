/**
 * clawsig-ledger: VaaS API + Public Ledger + Badges + Agent Passports
 * Sections 2-5 of Gemini Deep Think Round 3: The Moonshot (Viral Flywheel)
 */
import {
  generateComplianceReport,
  type ComplianceFramework,
  type ComplianceBundleInput,
  type CompliancePolicyInput,
} from './stubs';
import { base64UrlEncode } from './utils';
import {
  authenticateRequestApiKey,
  buildPowChallenge,
  resolvePowDifficulty,
  verifyHashcashNonce,
} from './auth';
import { verifyProofBundleViaApi } from './verify-client';
import { resolveBadge, renderBadgeSvg } from './badges';
import { importOracleKey, signWithOracleKey } from './crypto';
import { handleQueue } from './queue-consumer';
import type {
  Env, VerifyRequest, VerifyResponse, LedgerIngestMessage,
  AgentRow, RunRow, AgentPassportVC, GlobalStatsResponse,
} from './types';

function json(data: unknown, status = 200, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'X-Clawsig-Ledger-Version': '1', ...extra },
  });
}
function errorJson(message: string, code: string, status = 400, extra?: Record<string, string>): Response {
  return json({ error: { code, message } }, status, extra);
}

function runIdFromBundleHash(bundleHashB64u: string): string {
  return `run_${bundleHashB64u.slice(0, 24)}`;
}

interface ExistingRunLookup {
  run_id: string;
  status: string;
  proof_tier: string;
  reason_code: string | null;
  failure_class: string | null;
  verification_source: string | null;
  auth_mode: string | null;
}

async function findExistingRunByBundleHash(
  env: Env,
  bundleHashB64u: string
): Promise<ExistingRunLookup | null> {
  const row = await env.LEDGER_DB.prepare(
    `SELECT run_id, status, proof_tier, reason_code, failure_class, verification_source, auth_mode
     FROM runs WHERE bundle_hash_b64u = ? LIMIT 1`
  )
    .bind(bundleHashB64u)
    .first<ExistingRunLookup>();

  return row ?? null;
}

// POST /v1/verify
async function handleVerify(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  let body: VerifyRequest;
  try { body = (await req.json()) as VerifyRequest; } catch { return errorJson('Invalid JSON', 'INVALID_JSON'); }
  if (!body.proof_bundle || typeof body.proof_bundle !== 'object') return errorJson('Missing proof_bundle', 'MISSING_REQUIRED_FIELD');

  const bundleJsonStr = JSON.stringify(body.proof_bundle);
  const bundleHashB64u = base64UrlEncode(
    new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bundleJsonStr))
    )
  );

  const auth = await authenticateRequestApiKey(req, env);
  if (auth.error_code === 'UNAUTHORIZED') {
    return errorJson('Invalid API key', 'UNAUTHORIZED', 401);
  }

  const isAuthenticated = auth.authenticated;
  const publishToLedger = body.publish_to_ledger !== false || !isAuthenticated;

  if (!isAuthenticated) {
    const powDifficulty = resolvePowDifficulty(env.VAAS_POW_DIFFICULTY);
    const challenge = buildPowChallenge(bundleHashB64u);
    const powHeaders = {
      'X-Hashcash-Challenge': challenge,
      'X-Hashcash-Difficulty': String(powDifficulty),
    };

    const nonce = req.headers.get('X-Hashcash-Nonce')?.trim();
    if (!nonce) {
      return errorJson('Hashcash proof is required', 'POW_REQUIRED', 401, powHeaders);
    }

    const powValid = await verifyHashcashNonce(challenge, nonce, powDifficulty);
    if (!powValid) {
      return errorJson('Hashcash proof is invalid', 'POW_INVALID', 401, powHeaders);
    }
  }

  let existingRun: ExistingRunLookup | null = null;
  try {
    existingRun = await findExistingRunByBundleHash(env, bundleHashB64u);
  } catch {
    return errorJson('Ledger database unavailable', 'LEDGER_DB_UNAVAILABLE', 503);
  }

  if (existingRun) {
    const status = existingRun.status === 'PASS' ? 'PASS' : 'FAIL';
    const reasonCode = existingRun.reason_code ?? (status === 'PASS' ? 'OK' : 'VERIFICATION_FAILED');
    const failureClass = existingRun.failure_class ?? 'none';
    const verificationSource = existingRun.verification_source ?? 'clawverify_api';
    const authMode = existingRun.auth_mode ?? (isAuthenticated ? 'api_key' : 'pow');

    const duplicateResponse: VerifyResponse = {
      status,
      tier: existingRun.proof_tier,
      reason_code: reasonCode,
      failure_class: failureClass,
      verification_source: verificationSource,
      auth_mode: authMode,
      run_id: existingRun.run_id,
      urls: {
        badge: `https://api.clawverify.com/v1/badges/${existingRun.run_id}.svg`,
        ledger: `https://explorer.clawsig.com/run/${existingRun.run_id}`,
      },
      rt_log_inclusion: { status: 'NOT_PUBLISHED' },
      compliance_reports: {},
    };

    return json(duplicateResponse, status === 'PASS' ? 200 : 422);
  }

  const verification = await verifyProofBundleViaApi(body.proof_bundle, env);

  const status = verification.status === 'VALID' ? 'PASS' : 'FAIL';
  const proofTier = verification.proof_tier;
  const agentDid = verification.agent_did ?? 'unknown';
  const runId = runIdFromBundleHash(bundleHashB64u);
  const reasonCode = status === 'PASS' ? 'OK' : verification.reason_code;
  const failureClass = verification.failure_class;
  const verificationSource = 'clawverify_api';
  const authMode = isAuthenticated ? 'api_key' : 'pow';

  const shouldPublishToLedger = publishToLedger && failureClass === 'none';

  const bundle = body.proof_bundle as Record<string, unknown>;
  const payload = (bundle.payload ?? bundle) as Record<string, unknown>;
  const receipts = payload.receipts as Array<{ payload?: { model?: string } }> | undefined;
  const modelsUsed = receipts ? [...new Set(receipts.map(r => r.payload?.model).filter(Boolean) as string[])] : [];

  const complianceReports: Record<string, unknown> = {};
  if (isAuthenticated && body.options?.emit_compliance_report && status === 'PASS') {
    for (const fw of body.options.emit_compliance_report) {
      try {
        const report = generateComplianceReport(
          fw as ComplianceFramework,
          payload as ComplianceBundleInput,
          body.wpc_policy_override
            ? (body.wpc_policy_override as CompliancePolicyInput)
            : undefined
        );
        complianceReports[fw] = {
          ...(typeof report === 'object' && report ? report : { report }),
          bundle_hash_b64u: bundleHashB64u,
        };
      } catch {
        complianceReports[fw] = { error: `Unknown framework: ${fw}` };
      }
    }
  }

  if (shouldPublishToLedger) {
    const msg: LedgerIngestMessage = {
      run_id: runId,
      bundle_hash_b64u: bundleHashB64u,
      agent_did: agentDid,
      proof_tier: proofTier,
      status,
      reason_code: reasonCode,
      failure_class: failureClass,
      verification_source: verificationSource,
      auth_mode: authMode,
      wpc_hash_b64u: typeof payload.wpc_hash_b64u === 'string' ? payload.wpc_hash_b64u : undefined,
      models_json: modelsUsed.length > 0 ? JSON.stringify(modelsUsed) : undefined,
      bundle_json: bundleJsonStr,
    };
    ctx.waitUntil(env.LEDGER_QUEUE.send(msg).catch(e => console.error('[vaas] Queue send failed:', e)));
  }

  const response: VerifyResponse = {
    status,
    tier: proofTier,
    reason_code: reasonCode,
    failure_class: failureClass,
    verification_source: verificationSource,
    auth_mode: authMode,
    run_id: runId,
    urls: { badge: `https://api.clawverify.com/v1/badges/${runId}.svg`, ledger: `https://explorer.clawsig.com/run/${runId}` },
    rt_log_inclusion: { status: shouldPublishToLedger ? 'PENDING_ASYNC' : 'NOT_PUBLISHED' },
    compliance_reports: complianceReports,
  };

  const statusCode = failureClass === 'none' ? (status === 'PASS' ? 200 : 422) : 503;

  return json(response, statusCode);
}

// GET /v1/badges/:run_id.svg
async function handleBadge(runId: string, env: Env, ctx: ExecutionContext, req: Request): Promise<Response> {
  const cacheKey = new Request(req.url, { method: 'GET' });
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) return cached;
  const row = await env.LEDGER_DB.prepare('SELECT status, proof_tier FROM runs WHERE run_id = ?').bind(runId).first<{ status: string; proof_tier: string }>();
  const svg = renderBadgeSvg(resolveBadge(row?.status ?? null, row?.proof_tier ?? null));
  const response = new Response(svg, { status: 200, headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=3600', 'Access-Control-Allow-Origin': '*' } });
  ctx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}

// GET /v1/passports/:did
async function handlePassport(did: string, env: Env): Promise<Response> {
  if (!env.ORACLE_SIGNING_KEY) return errorJson('Passport signing key not configured', 'DEPENDENCY_NOT_CONFIGURED', 503);
  const agent = await env.LEDGER_DB.prepare('SELECT * FROM agents WHERE did = ?').bind(did).first<AgentRow>();
  if (!agent) return errorJson('Agent not found', 'NOT_FOUND', 404);

  const rows = await env.LEDGER_DB.prepare('SELECT models_json FROM runs WHERE agent_did = ? AND models_json IS NOT NULL ORDER BY created_at DESC LIMIT 50').bind(did).all<{ models_json: string }>();
  const mc: Record<string, number> = {};
  for (const r of rows.results ?? []) { try { for (const m of JSON.parse(r.models_json) as string[]) mc[m] = (mc[m] ?? 0) + 1; } catch { /* skip */ } }
  const topModels = Object.entries(mc).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([m]) => m);

  const oracleKey = await importOracleKey(env.ORACLE_SIGNING_KEY);
  const now = new Date().toISOString();
  const credentialSubject = {
    id: did,
    reputation_metrics: { total_verified_runs: agent.verified_runs, gateway_tier_runs: agent.gateway_tier_runs, policy_violations: agent.policy_violations },
    top_models_used: topModels, first_seen_at: agent.first_seen_at,
  };
  const vcPayload = JSON.stringify({ type: ['VerifiableCredential', 'AgentPassport'], issuer: 'did:web:clawverify.com', issuanceDate: now, credentialSubject });
  const signatureValue = await signWithOracleKey(oracleKey.privateKey, vcPayload);

  const passport: AgentPassportVC = {
    '@context': ['https://www.w3.org/2018/credentials/v1', 'https://schemas.clawbureau.org/identity/v1'],
    type: ['VerifiableCredential', 'AgentPassport'], issuer: 'did:web:clawverify.com', issuanceDate: now,
    credentialSubject,
    proof: { type: 'Ed25519Signature2020', verificationMethod: 'did:web:clawverify.com#oracle-key-1', created: now, signatureValue },
  };
  return json(passport);
}

// GET /v1/ledger/agents/:did
async function handleAgentStats(did: string, env: Env, url: URL): Promise<Response> {
  const agent = await env.LEDGER_DB.prepare('SELECT * FROM agents WHERE did = ?').bind(did).first<AgentRow>();
  if (!agent) return errorJson('Agent not found', 'NOT_FOUND', 404);
  const page = Math.max(1, parseInt(url.searchParams.get('page') ?? '1', 10) || 1);
  const runs = await env.LEDGER_DB.prepare('SELECT * FROM runs WHERE agent_did = ? ORDER BY created_at DESC LIMIT 50 OFFSET ?').bind(did, (page - 1) * 50).all<RunRow>();
  return json({ agent, recent_runs: runs.results ?? [], page, page_size: 50 });
}

// GET /v1/ledger/runs/:run_id
async function handleRunDetail(runId: string, env: Env): Promise<Response> {
  const run = await env.LEDGER_DB.prepare('SELECT * FROM runs WHERE run_id = ?').bind(runId).first<RunRow>();
  if (!run) return errorJson('Run not found', 'NOT_FOUND', 404);
  return json({ run, bundle_url: `https://clawsig-public-bundles.r2.dev/bundles/${runId}.json` });
}

// GET /v1/ledger/stats
async function handleGlobalStats(env: Env): Promise<Response> {
  const asNumber = (value: unknown): number => {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string') {
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : 0;
    }
    return 0;
  };

  const base = await env.LEDGER_DB.prepare(`SELECT
    (SELECT COUNT(*) FROM agents) AS total_agents,
    (SELECT COUNT(*) FROM runs) AS total_runs,
    (SELECT COALESCE(SUM(gateway_tier_runs), 0) FROM agents) AS total_gateway_runs,
    (SELECT COALESCE(SUM(policy_violations), 0) FROM agents) AS total_violations,
    (SELECT COUNT(*) FROM runs WHERE created_at >= datetime('now', '-24 hours')) AS runs_24h,
    (SELECT COUNT(*) FROM runs WHERE status = 'FAIL' AND created_at >= datetime('now', '-24 hours')) AS fail_runs_24h
  `).first<Record<string, unknown>>();

  const topFailRows = await env.LEDGER_DB.prepare(`
    SELECT reason_code, COUNT(*) AS count
    FROM runs
    WHERE status = 'FAIL'
      AND reason_code IS NOT NULL
      AND reason_code != ''
      AND created_at >= datetime('now', '-24 hours')
    GROUP BY reason_code
    ORDER BY count DESC, reason_code ASC
    LIMIT 5
  `).all<{ reason_code: string; count: number | string }>();

  const runs24h = asNumber(base?.runs_24h);
  const failRuns24h = asNumber(base?.fail_runs_24h);
  const failRate24h = runs24h > 0 ? Number((failRuns24h / runs24h).toFixed(6)) : 0;

  const stats: GlobalStatsResponse = {
    total_agents: asNumber(base?.total_agents),
    total_runs: asNumber(base?.total_runs),
    total_gateway_runs: asNumber(base?.total_gateway_runs),
    total_violations: asNumber(base?.total_violations),
    runs_24h: runs24h,
    fail_runs_24h: failRuns24h,
    fail_rate_24h: failRate24h,
    top_fail_reason_codes: (topFailRows.results ?? []).map((row) => ({
      reason_code: row.reason_code,
      count: asNumber(row.count),
    })),
  };

  return json(stats);
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const { method } = req, p = url.pathname;

    if (method === 'OPTIONS') return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key, X-Hashcash-Nonce' } });
    if (method === 'GET' && p === '/health') return json({ status: 'ok', service: 'clawsig-ledger', version: env.SERVICE_VERSION });
    if (method === 'GET' && p === '/') return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>clawsig-ledger</title></head><body style="max-width:800px;margin:2rem auto;font-family:system-ui"><h1>clawsig-ledger</h1><p>VaaS + Public Ledger + Badges + Passports</p></body></html>`, { headers: { 'Content-Type': 'text/html' } });

    if (method === 'POST' && p === '/v1/verify') return handleVerify(req, env, ctx);
    let m = p.match(/^\/v1\/badges\/([^/]+)\.svg$/);
    if (method === 'GET' && m) return handleBadge(m[1]!, env, ctx, req);
    m = p.match(/^\/v1\/passports\/(.+)$/);
    if (method === 'GET' && m) return handlePassport(decodeURIComponent(m[1]!), env);
    m = p.match(/^\/v1\/ledger\/agents\/(.+)$/);
    if (method === 'GET' && m) return handleAgentStats(decodeURIComponent(m[1]!), env, url);
    m = p.match(/^\/v1\/ledger\/runs\/([^/]+)$/);
    if (method === 'GET' && m) return handleRunDetail(m[1]!, env);
    if (method === 'GET' && p === '/v1/ledger/stats') return handleGlobalStats(env);
    return errorJson('Not found', 'NOT_FOUND', 404);
  },
  async queue(batch: MessageBatch<LedgerIngestMessage>, env: Env): Promise<void> { await handleQueue(batch, env); },
};
