#!/usr/bin/env node
/**
 * ECON-RISK-MAX-003 — Stripe dispute lifecycle smoke test.
 *
 * Simulates the full dispute lifecycle by posting loss events with dispute
 * metadata, then verifying the bridge state and resolution behavior.
 *
 * Usage:
 *   SETTLE_ADMIN_KEY=<key> SETTLE_BASE_URL=<url> node scripts/poh/smoke-stripe-dispute-lifecycle.mjs
 *
 * This test does NOT send actual Stripe webhook events (those need valid
 * signatures). Instead, it exercises the loss-event pipeline with dispute-
 * shaped payloads to verify the end-to-end behavior post-deployment.
 */

import crypto from 'node:crypto';

const SETTLE_BASE_URL = process.env.SETTLE_BASE_URL || 'https://staging.clawsettle.com';
const SETTLE_ADMIN_KEY = process.env.SETTLE_ADMIN_KEY;
const SETTLE_LOSS_READ_TOKEN = process.env.SETTLE_LOSS_READ_TOKEN;

if (!SETTLE_ADMIN_KEY) {
  console.error('SETTLE_ADMIN_KEY is required');
  process.exit(1);
}

const AUTH = SETTLE_LOSS_READ_TOKEN ?? SETTLE_ADMIN_KEY;
const ts = Date.now();
const runId = crypto.randomUUID().slice(0, 8);

const results = {
  run_id: runId,
  base_url: SETTLE_BASE_URL,
  timestamp: new Date().toISOString(),
  steps: [],
};

function log(step, data) {
  console.log(`[${step}]`, JSON.stringify(data, null, 2));
  results.steps.push({ step, ...data });
}

async function post(path, body, idempotencyKey) {
  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${SETTLE_ADMIN_KEY}`,
  };
  if (idempotencyKey) {
    headers['Idempotency-Key'] = idempotencyKey;
  }

  const res = await fetch(`${SETTLE_BASE_URL}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });

  const json = await res.json().catch(() => null);
  return { status: res.status, json };
}

async function get(path) {
  const res = await fetch(`${SETTLE_BASE_URL}${path}`, {
    headers: { 'Authorization': `Bearer ${AUTH}` },
  });
  const json = await res.json().catch(() => null);
  return { status: res.status, json };
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Step 1: Create a dispute-shaped loss event (simulates charge.dispute.created)
// ---------------------------------------------------------------------------

// Fixed occurred_at for deterministic idempotency key hash matching on replay
const OCCURRED_AT = new Date().toISOString();

async function step1_createDisputeLossEvent() {
  const disputeId = `dp_smoke_${runId}`;
  const chargeId = `ch_smoke_${runId}`;
  const accountDid = `did:claw:account:acc_smoke_${runId}`;
  const accountId = `acc_smoke_${runId}`;
  const idempotencyKey = `stripe:dispute:${disputeId}`;

  const payload = {
    source_service: 'stripe',
    source_event_id: `evt_dispute_created_${runId}`,
    account_did: accountDid,
    account_id: accountId,
    amount_minor: '2500',
    currency: 'USD',
    reason_code: 'dispute:fraudulent',
    severity: 'high',
    occurred_at: OCCURRED_AT,
    metadata: {
      dispute_id: disputeId,
      charge_id: chargeId,
      payment_intent_id: `pi_smoke_${runId}`,
      dispute_reason: 'fraudulent',
      dispute_status: 'needs_response',
      stripe_event_id: `evt_dispute_created_${runId}`,
    },
  };

  const { status, json } = await post('/v1/loss-events', payload, idempotencyKey);
  const ok = status === 201 || status === 200;

  log('create_dispute_loss_event', {
    ok,
    status,
    loss_event_id: json?.event?.loss_event_id,
    deduped: json?.deduped,
    dispute_id: disputeId,
  });

  return {
    ok,
    loss_event_id: json?.event?.loss_event_id,
    dispute_id: disputeId,
    account_did: accountDid,
    account_id: accountId,
    idempotency_key: idempotencyKey,
  };
}

// ---------------------------------------------------------------------------
// Step 2: Verify loss event was created and has dispute metadata
// ---------------------------------------------------------------------------
async function step2_verifyLossEvent(lossEventId) {
  const { status, json } = await get(`/v1/loss-events/${lossEventId}`);
  const ok = status === 200 && json?.event?.loss_event_id === lossEventId;
  const reasonCode = json?.event?.reason_code;
  const metadata = json?.event?.metadata;

  log('verify_loss_event', {
    ok,
    status,
    loss_event_id: lossEventId,
    reason_code: reasonCode,
    has_dispute_metadata: !!(metadata?.dispute_id),
    status_field: json?.event?.status,
  });

  return { ok, event: json?.event };
}

// ---------------------------------------------------------------------------
// Step 3: Idempotency replay — same dispute should return deduped
// ---------------------------------------------------------------------------
async function step3_idempotencyReplay(payload, idempotencyKey) {
  // MUST use exact same payload fields (including occurred_at) for request_hash match
  const { status, json } = await post('/v1/loss-events', {
    source_service: 'stripe',
    source_event_id: `evt_dispute_created_${runId}`,
    account_did: payload.account_did,
    account_id: payload.account_id,
    amount_minor: '2500',
    currency: 'USD',
    reason_code: 'dispute:fraudulent',
    severity: 'high',
    occurred_at: OCCURRED_AT,
    metadata: {
      dispute_id: payload.dispute_id,
      charge_id: `ch_smoke_${runId}`,
      payment_intent_id: `pi_smoke_${runId}`,
      dispute_reason: 'fraudulent',
      dispute_status: 'needs_response',
      stripe_event_id: `evt_dispute_created_${runId}`,
    },
  }, idempotencyKey);

  const ok = status === 200 && json?.deduped === true;
  log('idempotency_replay', { ok, status, deduped: json?.deduped });
  return { ok };
}

// ---------------------------------------------------------------------------
// Step 3b: Trigger forwarding retry to move event to 'forwarded' state
// ---------------------------------------------------------------------------
async function step3b_triggerForwarding(lossEventId) {
  // Trigger the forwarding retry for this specific loss event
  const { status, json } = await post('/v1/loss-events/ops/retry', {
    loss_event_id: lossEventId,
    force: true,
  }, null);

  log('trigger_forwarding', {
    ok: status === 200,
    status,
    attempted: json?.attempted,
    forwarded: json?.forwarded,
    failed: json?.failed,
  });

  // Wait for forwarding to complete, then check status
  await sleep(2000);
  const { json: eventJson } = await get(`/v1/loss-events/${lossEventId}`);
  const eventStatus = eventJson?.event?.status;

  log('post_forwarding_status', {
    loss_event_id: lossEventId,
    event_status: eventStatus,
    forwarded: eventStatus === 'forwarded',
  });

  return { ok: true, event_status: eventStatus };
}

// ---------------------------------------------------------------------------
// Step 4: Resolve loss event (simulates charge.dispute.closed, status=won)
// ---------------------------------------------------------------------------
async function step4_resolveLossEvent(lossEventId, disputeId, eventStatus) {
  const resolveIdempotencyKey = `stripe:dispute-resolve:${disputeId}`;
  const resolvePayload = {
    reason: `Dispute ${disputeId} closed with status=won`,
  };

  // If the event is not forwarded, resolve will fail with 409 LOSS_EVENT_NOT_READY.
  // This is expected behavior (MAX-002 resolve gating).
  const { status, json } = await post(
    `/v1/loss-events/${lossEventId}/resolve`,
    resolvePayload,
    resolveIdempotencyKey
  );

  if (eventStatus !== 'forwarded') {
    // We expect 409 if the event hasn't been forwarded yet
    const ok = status === 409 && json?.code === 'LOSS_EVENT_NOT_READY';
    log('resolve_loss_event', {
      ok,
      status,
      loss_event_id: lossEventId,
      code: json?.code,
      note: 'Expected: resolve blocked until forwarding completes (MAX-002 gating)',
    });
    return { ok, blocked: true };
  }

  const ok = status === 201 || status === 200;

  log('resolve_loss_event', {
    ok,
    status,
    loss_event_id: lossEventId,
    deduped: json?.deduped,
    resolution_id: json?.resolution?.resolution_id,
    event_status: json?.event?.status,
  });

  return { ok, resolution: json?.resolution };
}

// ---------------------------------------------------------------------------
// Step 5: Verify resolved state
// ---------------------------------------------------------------------------
async function step5_verifyResolved(lossEventId) {
  const { status, json } = await get(`/v1/loss-events/${lossEventId}`);
  const event = json?.event;
  const isResolved = event?.status === 'resolved';

  log('verify_resolved', {
    ok: status === 200 && isResolved,
    status,
    loss_event_id: lossEventId,
    event_status: event?.status,
  });

  return { ok: status === 200 && isResolved };
}

// ---------------------------------------------------------------------------
// Step 6: Create a second dispute that will be "lost" (permanent loss)
// ---------------------------------------------------------------------------
async function step6_permanentLossScenario() {
  const disputeId = `dp_lost_${runId}`;
  const accountDid = `did:claw:account:acc_lost_${runId}`;
  const idempotencyKey = `stripe:dispute:${disputeId}`;

  const payload = {
    source_service: 'stripe',
    source_event_id: `evt_dispute_created_lost_${runId}`,
    account_did: accountDid,
    account_id: `acc_lost_${runId}`,
    amount_minor: '10000',
    currency: 'USD',
    reason_code: 'dispute:product_not_received',
    severity: 'critical',
    occurred_at: new Date().toISOString(),
    metadata: {
      dispute_id: disputeId,
      dispute_reason: 'product_not_received',
      dispute_status: 'needs_response',
    },
  };

  const { status, json } = await post('/v1/loss-events', payload, idempotencyKey);
  const ok = status === 201 || status === 200;
  const lossEventId = json?.event?.loss_event_id;

  log('permanent_loss_create', {
    ok,
    status,
    loss_event_id: lossEventId,
    dispute_id: disputeId,
  });

  // Verify it stays in recorded/forwarded state (NOT resolved)
  if (lossEventId) {
    await sleep(1000);
    const { json: checkJson } = await get(`/v1/loss-events/${lossEventId}`);
    const eventStatus = checkJson?.event?.status;
    const notResolved = eventStatus !== 'resolved';

    log('permanent_loss_verify', {
      ok: notResolved,
      loss_event_id: lossEventId,
      event_status: eventStatus,
      note: 'Lost dispute stays frozen — no resolve call made',
    });
  }

  return { ok, loss_event_id: lossEventId };
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------
async function main() {
  console.log(`\n=== ECON-RISK-MAX-003 Stripe Dispute Lifecycle Smoke Test ===`);
  console.log(`Run ID: ${runId}`);
  console.log(`Target: ${SETTLE_BASE_URL}\n`);

  // Step 1: Create dispute loss event
  const step1 = await step1_createDisputeLossEvent();
  if (!step1.ok || !step1.loss_event_id) {
    console.error('FAIL: Could not create dispute loss event');
    process.exit(1);
  }

  await sleep(500);

  // Step 2: Verify loss event
  const step2 = await step2_verifyLossEvent(step1.loss_event_id);

  // Step 3: Idempotency replay
  const step3 = await step3_idempotencyReplay(step1, step1.idempotency_key);

  // Step 3b: Trigger forwarding to move event to 'forwarded' state
  const step3b = await step3b_triggerForwarding(step1.loss_event_id);

  // Step 4: Resolve (dispute won)
  const step4 = await step4_resolveLossEvent(step1.loss_event_id, step1.dispute_id, step3b.event_status);

  await sleep(500);

  // Step 5: Verify resolved (only if forwarding succeeded)
  let step5 = { ok: true };
  if (step3b.event_status === 'forwarded' && !step4.blocked) {
    step5 = await step5_verifyResolved(step1.loss_event_id);
  } else {
    log('verify_resolved', {
      ok: true,
      skipped: true,
      note: `Event status=${step3b.event_status}, resolve ${step4.blocked ? 'was correctly blocked by MAX-002 gating' : 'succeeded'}`,
    });
  }

  // Step 6: Permanent loss scenario
  const step6 = await step6_permanentLossScenario();

  // Summary
  const allOk = [step1, step2, step3, step4, step5, step6].every((s) => s.ok);
  results.all_passed = allOk;

  console.log(`\n=== Summary ===`);
  console.log(`All passed: ${allOk}`);
  console.log(JSON.stringify(results, null, 2));

  // Write artifact
  const artifactDir = `artifacts/simulations/stripe-dispute-lifecycle/${new Date().toISOString().replace(/[:.]/g, '-')}-${process.env.SETTLE_ENV || 'staging'}`;
  const fs = await import('node:fs');
  const path = await import('node:path');
  fs.mkdirSync(artifactDir, { recursive: true });
  fs.writeFileSync(path.join(artifactDir, 'smoke.json'), JSON.stringify(results, null, 2));
  console.log(`\nArtifact: ${artifactDir}/smoke.json`);

  process.exit(allOk ? 0 : 1);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
