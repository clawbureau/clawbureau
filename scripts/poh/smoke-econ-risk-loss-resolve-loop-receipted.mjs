#!/usr/bin/env node

/**
 * CPL-US-006-ECON: Tool receipt SDK integration validation.
 *
 * Wires smoke-econ-risk-loss-resolve-loop with @clawbureau/clawsig-sdk:
 *   - Each HTTP call → run.recordToolCall({ toolName: 'http_fetch', args, result })
 *   - run.finalize() → produces proof bundle with tool receipts
 *   - Writes bundle to artifacts for offline verification
 *
 * Usage:
 *   node scripts/poh/smoke-econ-risk-loss-resolve-loop-receipted.mjs --env staging
 *   node scripts/poh/smoke-econ-risk-loss-resolve-loop-receipted.mjs --env prod
 *
 * Verify offline:
 *   node packages/clawverify-cli/dist/cli.js verify proof-bundle --input <bundle.json>
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createRun,
  generateKeyPair,
  importKeyPairJWK,
  exportKeyPairJWK,
  hashJsonB64u,
} from '../../packages/clawsig-sdk/dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');

// ---------------------------------------------------------------------------
// Env + auth helpers
// ---------------------------------------------------------------------------

const ENVS = {
  staging: {
    settle: 'https://staging.clawsettle.com',
    ledger: 'https://staging.clawledger.com',
  },
  prod: {
    settle: 'https://clawsettle.com',
    ledger: 'https://clawledger.com',
  },
};

function resolveEnv() {
  const idx = process.argv.indexOf('--env');
  const env = idx !== -1 ? process.argv[idx + 1] : 'staging';
  if (!ENVS[env]) throw new Error(`Unknown env: ${env}. Use staging|prod`);
  return { env, urls: ENVS[env] };
}

async function readSecret(service, key, envName) {
  const filePath = `${process.env.HOME}/.clawsecrets/${service}/${key}.${envName}`;
  try {
    return (await fs.readFile(filePath, 'utf-8')).trim();
  } catch {
    const envVar = process.env[key];
    if (envVar) return envVar.trim();
    throw new Error(`Secret not found: ${filePath} or env ${key}`);
  }
}

// ---------------------------------------------------------------------------
// Instrumented fetch — records every HTTP call as a tool receipt
// ---------------------------------------------------------------------------

async function instrumentedFetch(run, label, url, init = {}) {
  const method = init.method || 'GET';
  const start = Date.now();

  // Strip auth from args logged to bundle (hash-only, but still safe practice)
  const sanitizedHeaders = { ...init.headers };
  if (sanitizedHeaders.authorization) sanitizedHeaders.authorization = '[REDACTED]';
  if (sanitizedHeaders.Authorization) sanitizedHeaders.Authorization = '[REDACTED]';

  const args = {
    label,
    url,
    method,
    headers: sanitizedHeaders,
    body: init.body ? JSON.parse(init.body) : undefined,
  };

  let response, json, text, status;
  try {
    response = await fetch(url, init);
    status = response.status;
    text = await response.text();
    try { json = JSON.parse(text); } catch { json = null; }
  } catch (err) {
    const elapsed = Date.now() - start;
    await run.recordToolCall({
      toolName: 'http_fetch',
      toolVersion: '1.0',
      args,
      result: { error: err.message },
      resultStatus: 'error',
      latencyMs: elapsed,
    });
    throw err;
  }

  const elapsed = Date.now() - start;

  await run.recordToolCall({
    toolName: 'http_fetch',
    toolVersion: '1.0',
    args,
    result: { status, body: json ?? text },
    resultStatus: status >= 200 && status < 400 ? 'success' : 'error',
    latencyMs: elapsed,
  });

  return { status, ok: response.ok, json, text, elapsed_ms: elapsed };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const { env, urls } = resolveEnv();
  const settleAdminKey = await readSecret('clawsettle', 'SETTLE_ADMIN_KEY', env);

  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.resolve(REPO_ROOT, 'artifacts', 'simulations', 'econ-risk-loss-resolve-receipted', `${ts}-${env}`);
  await fs.mkdir(outDir, { recursive: true });

  // Resolve or generate keypair
  const keyFilePath = '/tmp/clawproof-key-econ-risk-max-002.json';
  let keyPair;
  try {
    const raw = JSON.parse(await fs.readFile(keyFilePath, 'utf-8'));
    keyPair = await importKeyPairJWK(raw);
    console.log('[sdk] Imported existing keypair');
  } catch {
    keyPair = await generateKeyPair();
    const exported = await exportKeyPairJWK(keyPair);
    await fs.writeFile(keyFilePath, JSON.stringify(exported, null, 2));
    console.log('[sdk] Generated new keypair');
  }

  // Create SDK run
  const run = await createRun({
    proxyBaseUrl: 'https://clawproxy.com',   // not used for tool-only runs
    keyPair,
    harness: {
      id: 'smoke-econ-risk-loss-resolve-loop-receipted',
      version: '1.0.0',
      runtime: `node/${process.version}`,
    },
  });

  console.log(`[sdk] Run created: ${run.runId} (agent=${run.agentDid})`);

  // Record run_start event
  await run.recordEvent({
    eventType: 'run_start',
    payload: { task: 'CPL-US-006-ECON', env, settle_base_url: urls.settle },
  });

  const sourceEventId = `smoke-loss-${crypto.randomUUID()}`;
  const accountDid = `did:key:z6Mk${crypto.randomUUID().replace(/-/g, '').slice(0, 32)}`;
  const createIdempotencyKey = `smoke:loss-event:${crypto.randomUUID()}`;
  const resolveIdempotencyKey = `smoke:loss-event:resolve:${crypto.randomUUID()}`;

  const steps = [];

  // -----------------------------------------------------------------------
  // Step 1: Create loss event
  // -----------------------------------------------------------------------
  console.log(`[${env}] Step 1: POST /v1/loss-events`);

  const createBody = {
    source_service: 'clawsettle-smoke-receipted',
    source_event_id: sourceEventId,
    account_did: accountDid,
    amount_minor: '250',
    currency: 'USD',
    reason_code: 'chargeback',
    severity: 'high',
    occurred_at: new Date().toISOString(),
    metadata: { smoke: true, env, receipted: true },
  };

  const create = await instrumentedFetch(run, 'create_loss_event', `${urls.settle}/v1/loss-events`, {
    method: 'POST',
    headers: {
      'authorization': `Bearer ${settleAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
      'idempotency-key': createIdempotencyKey,
    },
    body: JSON.stringify(createBody),
  });

  if (create.status !== 201 && create.status !== 200) {
    throw new Error(`create failed: ${create.status} ${create.text}`);
  }

  const lossEventId = create.json?.event?.loss_event_id;
  if (!lossEventId) throw new Error('loss_event_id missing from response');

  steps.push({ step: 'create_loss_event', status: create.status, loss_event_id: lossEventId, elapsed_ms: create.elapsed_ms });
  console.log(`  loss_event_id=${lossEventId} (${create.elapsed_ms}ms)`);

  // -----------------------------------------------------------------------
  // Step 2: Retry forwarding (apply)
  // -----------------------------------------------------------------------
  console.log(`[${env}] Step 2: POST /v1/loss-events/ops/retry (apply)`);

  const retryApply = await instrumentedFetch(run, 'retry_forwarding_apply', `${urls.settle}/v1/loss-events/ops/retry`, {
    method: 'POST',
    headers: {
      'authorization': `Bearer ${settleAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({ operation: 'apply', limit: 50, loss_event_id: lossEventId }),
  });

  if (retryApply.status !== 200) throw new Error(`retry apply failed: ${retryApply.status}`);
  steps.push({ step: 'retry_apply', status: retryApply.status, forwarded: retryApply.json?.forwarded, elapsed_ms: retryApply.elapsed_ms });
  console.log(`  forwarded=${retryApply.json?.forwarded} (${retryApply.elapsed_ms}ms)`);

  // -----------------------------------------------------------------------
  // Step 3: Readback loss event
  // -----------------------------------------------------------------------
  console.log(`[${env}] Step 3: GET /v1/loss-events/${lossEventId}`);

  const readback = await instrumentedFetch(run, 'readback_loss_event', `${urls.settle}/v1/loss-events/${encodeURIComponent(lossEventId)}`, {
    headers: { 'authorization': `Bearer ${settleAdminKey}` },
  });

  if (readback.status !== 200) throw new Error(`readback failed: ${readback.status}`);
  const eventStatus = readback.json?.event?.status;
  steps.push({ step: 'readback', status: readback.status, event_status: eventStatus, elapsed_ms: readback.elapsed_ms });
  console.log(`  event_status=${eventStatus} (${readback.elapsed_ms}ms)`);

  // -----------------------------------------------------------------------
  // Step 4: Readback outbox (apply)
  // -----------------------------------------------------------------------
  console.log(`[${env}] Step 4: GET outbox (apply)`);

  const applyOutbox = await instrumentedFetch(run, 'readback_apply_outbox',
    `${urls.settle}/v1/loss-events/outbox?operation=apply&loss_event_id=${encodeURIComponent(lossEventId)}&limit=50`, {
    headers: { 'authorization': `Bearer ${settleAdminKey}` },
  });

  if (applyOutbox.status !== 200) throw new Error(`outbox read failed: ${applyOutbox.status}`);
  const applyEntries = applyOutbox.json?.outbox ?? [];
  const applyForwarded = applyEntries.filter(e => e.status === 'forwarded').length;
  const applyFailed = applyEntries.filter(e => e.status === 'failed').length;
  steps.push({ step: 'outbox_apply', total: applyEntries.length, forwarded: applyForwarded, failed: applyFailed });
  console.log(`  outbox: forwarded=${applyForwarded} failed=${applyFailed}`);

  if (eventStatus !== 'forwarded') {
    console.log(`  ⚠ Event status is ${eventStatus}, not forwarded — skipping resolve (smoke targets used)`);
  }

  let resolveData = null;
  if (eventStatus === 'forwarded') {
    // -----------------------------------------------------------------------
    // Step 5: Resolve loss event
    // -----------------------------------------------------------------------
    console.log(`[${env}] Step 5: POST /v1/loss-events/${lossEventId}/resolve`);

    const resolve = await instrumentedFetch(run, 'resolve_loss_event',
      `${urls.settle}/v1/loss-events/${encodeURIComponent(lossEventId)}/resolve`, {
      method: 'POST',
      headers: {
        'authorization': `Bearer ${settleAdminKey}`,
        'content-type': 'application/json; charset=utf-8',
        'idempotency-key': resolveIdempotencyKey,
      },
      body: JSON.stringify({ reason: 'CPL-US-006-ECON smoke resolve' }),
    });

    if (resolve.status !== 201 && resolve.status !== 200) {
      throw new Error(`resolve failed: ${resolve.status} ${resolve.text}`);
    }

    resolveData = resolve.json;
    steps.push({ step: 'resolve', status: resolve.status, resolution_id: resolve.json?.resolution?.resolution_id, elapsed_ms: resolve.elapsed_ms });
    console.log(`  resolution_id=${resolve.json?.resolution?.resolution_id} (${resolve.elapsed_ms}ms)`);

    // -----------------------------------------------------------------------
    // Step 6: Retry forwarding (resolve)
    // -----------------------------------------------------------------------
    console.log(`[${env}] Step 6: POST /v1/loss-events/ops/retry (resolve)`);

    const retryResolve = await instrumentedFetch(run, 'retry_forwarding_resolve', `${urls.settle}/v1/loss-events/ops/retry`, {
      method: 'POST',
      headers: {
        'authorization': `Bearer ${settleAdminKey}`,
        'content-type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify({ operation: 'resolve', limit: 50, loss_event_id: lossEventId }),
    });

    if (retryResolve.status !== 200) throw new Error(`retry resolve failed: ${retryResolve.status}`);
    steps.push({ step: 'retry_resolve', status: retryResolve.status, forwarded: retryResolve.json?.forwarded, elapsed_ms: retryResolve.elapsed_ms });
    console.log(`  forwarded=${retryResolve.json?.forwarded} (${retryResolve.elapsed_ms}ms)`);

    // -----------------------------------------------------------------------
    // Step 7: Readback outbox (resolve)
    // -----------------------------------------------------------------------
    console.log(`[${env}] Step 7: GET outbox (resolve)`);

    const resolveOutbox = await instrumentedFetch(run, 'readback_resolve_outbox',
      `${urls.settle}/v1/loss-events/outbox?operation=resolve&loss_event_id=${encodeURIComponent(lossEventId)}&limit=50`, {
      headers: { 'authorization': `Bearer ${settleAdminKey}` },
    });

    if (resolveOutbox.status !== 200) throw new Error(`resolve outbox read failed: ${resolveOutbox.status}`);
    const resolveEntries = resolveOutbox.json?.outbox ?? [];
    steps.push({
      step: 'outbox_resolve',
      total: resolveEntries.length,
      forwarded: resolveEntries.filter(e => e.status === 'forwarded').length,
      failed: resolveEntries.filter(e => e.status === 'failed').length,
    });
  }

  // -----------------------------------------------------------------------
  // Finalize: produce proof bundle with tool receipts
  // -----------------------------------------------------------------------
  console.log(`\n[sdk] Finalizing proof bundle...`);

  await run.recordEvent({
    eventType: 'run_end',
    payload: { steps_completed: steps.length, env, loss_event_id: lossEventId },
  });

  const smokePayloadHash = await hashJsonB64u({ steps, env, loss_event_id: lossEventId });

  const result = await run.finalize({
    inputs: [
      {
        type: 'smoke_config',
        hashB64u: await hashJsonB64u({ env, settle_base_url: urls.settle }),
        metadata: { env, script: 'smoke-econ-risk-loss-resolve-loop-receipted.mjs' },
      },
    ],
    outputs: [
      {
        type: 'smoke_result',
        hashB64u: smokePayloadHash,
        metadata: { loss_event_id: lossEventId, step_count: steps.length },
      },
    ],
    urmMetadata: {
      task: 'CPL-US-006-ECON',
      description: 'Tool receipt SDK integration validation — loss event create/resolve lifecycle',
    },
  });

  // Write proof bundle
  const bundlePath = path.join(outDir, 'proof-bundle.json');
  await fs.writeFile(bundlePath, JSON.stringify(result.envelope, null, 2));
  console.log(`[sdk] Bundle written: ${bundlePath}`);

  // Write URM
  const urmPath = path.join(outDir, 'urm.json');
  await fs.writeFile(urmPath, JSON.stringify(result.urm, null, 2));
  console.log(`[sdk] URM written: ${urmPath}`);

  // Count receipts
  const toolReceiptCount = result.envelope.payload.tool_receipts?.length ?? 0;
  const eventCount = result.envelope.payload.event_chain?.length ?? 0;
  console.log(`[sdk] Events: ${eventCount}, Tool receipts: ${toolReceiptCount}`);

  // Write smoke summary
  const summary = {
    ok: true,
    env,
    run_id: run.runId,
    agent_did: run.agentDid,
    loss_event_id: lossEventId,
    sdk_integration: {
      tool_receipt_count: toolReceiptCount,
      event_chain_length: eventCount,
      bundle_id: result.envelope.payload.bundle_id,
      urm_id: result.urm.urm_id,
    },
    steps,
    generated_at: new Date().toISOString(),
  };

  await fs.writeFile(path.join(outDir, 'smoke.json'), JSON.stringify(summary, null, 2));
  console.log(`\n✅ ${env}: SDK integration complete — ${toolReceiptCount} tool receipts, ${eventCount} events`);
  console.log(`   Bundle: ${bundlePath}`);
}

main().catch(err => {
  console.error('Fatal:', err.message ?? err);
  process.exitCode = 1;
});
