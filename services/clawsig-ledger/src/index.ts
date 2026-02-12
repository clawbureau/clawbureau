/**
 * clawsig-ledger: VaaS API + Public Ledger + Badges + Agent Passports
 * Sections 2-5 of Gemini Deep Think Round 3: The Moonshot (Viral Flywheel)
 */
import {
  verifyProofBundle, base64UrlEncode, generateComplianceReport,
  type ComplianceFramework, type ComplianceBundleInput, type CompliancePolicyInput,
} from '@clawbureau/clawverify-core';
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
function errorJson(message: string, code: string, status = 400): Response { return json({ error: { code, message } }, status); }
function csv(v: string | undefined): string[] { return v ? v.split(',').map(s => s.trim()).filter(Boolean) : []; }
function genRunId(): string {
  const b = new Uint8Array(8); crypto.getRandomValues(b);
  return `run_${Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('')}`;
}

// POST /v1/verify
async function handleVerify(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  let body: VerifyRequest;
  try { body = (await req.json()) as VerifyRequest; } catch { return errorJson('Invalid JSON', 'INVALID_JSON'); }
  if (!body.proof_bundle || typeof body.proof_bundle !== 'object') return errorJson('Missing proof_bundle', 'MISSING_REQUIRED_FIELD');

  const apiKey = req.headers.get('X-API-Key') ?? req.headers.get('Authorization')?.replace(/^Bearer\s+/i, '');
  const hasApiKey = !!(apiKey && env.VAAS_API_KEY_HASH);
  const publishToLedger = body.publish_to_ledger !== false || !hasApiKey;

  const verification = await verifyProofBundle(body.proof_bundle, {
    allowlistedReceiptSignerDids: csv(env.GATEWAY_RECEIPT_SIGNER_DIDS),
    allowlistedAttesterDids: csv(env.ATTESTATION_SIGNER_DIDS),
  });

  const isPassing = verification.result.status === 'VALID';
  const proofTier = verification.result.proof_tier ?? 'unknown';
  const agentDid = verification.result.agent_did ?? 'unknown';
  const runId = genRunId();

  const bundleJsonStr = JSON.stringify(body.proof_bundle);
  const bundleHashB64u = base64UrlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bundleJsonStr))));

  const bundle = body.proof_bundle as Record<string, unknown>;
  const payload = (bundle.payload ?? bundle) as Record<string, unknown>;
  const receipts = payload.receipts as Array<{ payload?: { model?: string } }> | undefined;
  const modelsUsed = receipts ? [...new Set(receipts.map(r => r.payload?.model).filter(Boolean) as string[])] : [];

  const complianceReports: Record<string, unknown> = {};
  if (hasApiKey && body.options?.emit_compliance_report && isPassing) {
    for (const fw of body.options.emit_compliance_report) {
      try {
        complianceReports[fw] = generateComplianceReport(fw as ComplianceFramework, payload as unknown as ComplianceBundleInput,
          body.wpc_policy_override ? (body.wpc_policy_override as CompliancePolicyInput) : undefined, { bundleHash: bundleHashB64u });
      } catch { complianceReports[fw] = { error: `Unknown framework: ${fw}` }; }
    }
  }

  if (publishToLedger) {
    const msg: LedgerIngestMessage = {
      run_id: runId, bundle_hash_b64u: bundleHashB64u, agent_did: agentDid, proof_tier: proofTier,
      status: isPassing ? 'PASS' : 'FAIL',
      wpc_hash_b64u: typeof payload.wpc_hash_b64u === 'string' ? payload.wpc_hash_b64u : undefined,
      models_json: modelsUsed.length > 0 ? JSON.stringify(modelsUsed) : undefined, bundle_json: bundleJsonStr,
    };
    ctx.waitUntil(env.LEDGER_QUEUE.send(msg).catch(e => console.error('[vaas] Queue send failed:', e)));
  }

  const response: VerifyResponse = {
    status: isPassing ? 'PASS' : 'FAIL', tier: proofTier,
    reason_code: isPassing ? 'OK' : (verification.error?.code ?? 'VERIFICATION_FAILED'), run_id: runId,
    urls: { badge: `https://api.clawverify.com/v1/badges/${runId}.svg`, ledger: `https://explorer.clawsig.com/run/${runId}` },
    rt_log_inclusion: { status: publishToLedger ? 'PENDING_ASYNC' : 'NOT_PUBLISHED' }, compliance_reports: complianceReports,
  };
  return json(response, isPassing ? 200 : 422);
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
  const stats = await env.LEDGER_DB.prepare(`SELECT
    (SELECT COUNT(*) FROM agents) AS total_agents, (SELECT COUNT(*) FROM runs) AS total_runs,
    (SELECT COALESCE(SUM(gateway_tier_runs),0) FROM agents) AS total_gateway_runs,
    (SELECT COALESCE(SUM(policy_violations),0) FROM agents) AS total_violations`).first<GlobalStatsResponse>();
  return json(stats ?? { total_agents: 0, total_runs: 0, total_gateway_runs: 0, total_violations: 0 });
}

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    const { method } = req, p = url.pathname;

    if (method === 'OPTIONS') return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key' } });
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
