import { compileSemanticTrace } from '@clawbureau/clawverify-core';
import type { ProofBundlePayload } from '@clawbureau/clawverify-core';
import { evaluateBehavioralRisk, embedTrace } from './evaluator.js';
import { handleIngestBatch } from './ingest.js';
import type { Env, IngestMessage, SentinelResult, TrajectoryMetadata } from './types.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
function errorResponse(message: string, status: number): Response {
  return jsonResponse({ error: message }, status);
}

/** POST /v1/sentinel/evaluate -- ~50ms Workers AI embedding latency per call */
async function handleEvaluate(request: Request, env: Env): Promise<Response> {
  let body: { trace_string?: string; proof_bundle?: Record<string, unknown> };
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON body', 400); }
  let traceString: string;
  if (body.trace_string) {
    traceString = body.trace_string;
  } else if (body.proof_bundle) {
    traceString = compileSemanticTrace(body.proof_bundle as unknown as ProofBundlePayload);
  } else {
    return errorResponse('Request must include trace_string or proof_bundle', 400);
  }
  const result: SentinelResult = await evaluateBehavioralRisk(traceString, env);
  return jsonResponse(result);
}

/** GET /v1/sentinel/stats */
async function handleStats(env: Env): Promise<Response> {
  try {
    const info = await env.SENTINEL_DB.describe();
    return jsonResponse({
      dimensions: info.dimensions, vector_count: info.vectorCount,
      processed_up_to: info.processedUpToDatetime, status: 'healthy',
    });
  } catch (err) {
    return jsonResponse({ status: 'error', error: err instanceof Error ? err.message : String(err) }, 503);
  }
}

/** POST /v1/sentinel/ingest -- manual ingest / backfill */
async function handleManualIngest(request: Request, env: Env): Promise<Response> {
  let body: { proof_bundle?: Record<string, unknown>; run_id?: string; status?: string; agent_did?: string; proof_tier?: string };
  try { body = await request.json(); } catch { return errorResponse('Invalid JSON body', 400); }
  if (!body.proof_bundle || !body.run_id) return errorResponse('proof_bundle and run_id required', 400);
  const bundle = body.proof_bundle as unknown as ProofBundlePayload;
  const traceString = compileSemanticTrace(bundle);
  const values = await embedTrace(traceString, env.AI);
  const metadata: TrajectoryMetadata = {
    run_id: body.run_id, agent_did: body.agent_did ?? bundle.agent_did ?? 'unknown',
    status: body.status ?? 'unknown', proof_tier: body.proof_tier ?? 'unknown', created_at: new Date().toISOString(),
  };
  await env.SENTINEL_DB.upsert([{
    id: body.run_id, values, metadata: metadata as unknown as Record<string, VectorizeVectorMetadata>,
  }]);
  return jsonResponse({ vector_id: body.run_id }, 201);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (env.SENTINEL_ENABLED !== 'true') return errorResponse('Sentinel is disabled', 503);
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === '/health' && request.method === 'GET') return jsonResponse({ status: 'ok', service: 'sentinel' });
    if (path === '/v1/sentinel/evaluate' && request.method === 'POST') return handleEvaluate(request, env);
    if (path === '/v1/sentinel/stats' && request.method === 'GET') return handleStats(env);
    if (path === '/v1/sentinel/ingest' && request.method === 'POST') return handleManualIngest(request, env);
    return errorResponse('Not found', 404);
  },
  async queue(batch: MessageBatch, env: Env): Promise<void> {
    if (env.SENTINEL_ENABLED !== 'true') {
      for (const msg of batch.messages) msg.ack();
      return;
    }
    await handleIngestBatch(batch as MessageBatch<IngestMessage>, env);
  },
} satisfies ExportedHandler<Env>;
