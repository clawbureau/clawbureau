#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assert,
  parseArgs,
  resolveEnvName,
  randomDid,
} from './_clawbounties-sim-common.mjs';

function resolveSettleBaseUrl(envName, override) {
  if (override && override.trim().length > 0) return override.trim();
  return envName === 'prod' ? 'https://clawsettle.com' : 'https://staging.clawsettle.com';
}

function makeArtifactDir(repoRoot, envName) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.resolve(repoRoot, 'artifacts', 'simulations', 'econ-risk-loss-loop', `${timestamp}-${envName}`);
  return { dir, timestamp };
}

async function writeJson(filePath, payload) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

async function requestJson(url, init = {}) {
  const startedAt = Date.now();
  const response = await fetch(url, init);
  const text = await response.text();

  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  return {
    status: response.status,
    ok: response.ok,
    json,
    text,
    elapsed_ms: Date.now() - startedAt,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = resolveEnvName(args.get('env'));

  const settleBaseUrl = resolveSettleBaseUrl(envName, args.get('clawsettle-base-url'));
  const settleAdminKey = String(args.get('settle-admin-key') || process.env.SETTLE_ADMIN_KEY || '').trim();
  const settleLossReadToken = String(args.get('settle-loss-read-token') || process.env.SETTLE_LOSS_READ_TOKEN || '').trim();

  assert(settleAdminKey.length > 0, 'SETTLE_ADMIN_KEY (or --settle-admin-key) is required');

  const sourceEventId = String(args.get('source-event-id') || `smoke-loss-${crypto.randomUUID()}`).trim();
  const accountDid = String(args.get('account-did') || randomDid('loss-account')).trim();
  const accountId = String(args.get('account-id') || '').trim() || null;
  const idempotencyKey = String(args.get('idempotency-key') || `smoke:loss-event:${crypto.randomUUID()}`).trim();
  const amountMinor = String(args.get('amount-minor') || '250').trim();
  const reasonCode = String(args.get('reason-code') || 'chargeback').trim();
  const severity = String(args.get('severity') || 'high').trim();

  const metadata = {
    smoke: true,
    env: envName,
    ...(isTruthy(args.get('include-escrow-target'))
      ? {
          escrow_id: String(args.get('escrow-id') || '').trim() || 'esc_00000000-0000-0000-0000-000000000001',
        }
      : {}),
    ...(isTruthy(args.get('include-bounty-target'))
      ? {
          bounty_id: String(args.get('bounty-id') || '').trim() || 'bty_00000000-0000-0000-0000-000000000001',
        }
      : {}),
  };

  const createBody = {
    source_service: 'clawsettle-smoke',
    source_event_id: sourceEventId,
    account_did: accountDid,
    ...(accountId ? { account_id: accountId } : {}),
    amount_minor: amountMinor,
    currency: 'USD',
    reason_code: reasonCode,
    severity,
    occurred_at: new Date().toISOString(),
    metadata,
  };

  const steps = [];

  const create = await requestJson(`${settleBaseUrl}/v1/loss-events`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${settleAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
      'idempotency-key': idempotencyKey,
    },
    body: JSON.stringify(createBody),
  });

  assert(
    create.status === 201 || create.status === 200,
    `loss event create failed (${create.status}): ${create.text}`
  );
  const lossEventId = create.json?.event?.loss_event_id;
  assert(typeof lossEventId === 'string' && lossEventId.trim().length > 0, 'loss_event_id missing');

  steps.push({
    step: 'create_loss_event',
    status: create.status,
    elapsed_ms: create.elapsed_ms,
    deduped: create.json?.deduped === true,
    loss_event_id: lossEventId,
    target_count: create.json?.event?.target_count ?? null,
  });

  const retry = await requestJson(`${settleBaseUrl}/v1/loss-events/ops/retry`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${settleAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      limit: Number.parseInt(String(args.get('retry-limit') || '50'), 10),
      loss_event_id: lossEventId,
    }),
  });

  assert(retry.status === 200, `loss event retry failed (${retry.status}): ${retry.text}`);

  steps.push({
    step: 'retry_forwarding',
    status: retry.status,
    elapsed_ms: retry.elapsed_ms,
    attempted: retry.json?.attempted ?? null,
    forwarded: retry.json?.forwarded ?? null,
    failed: retry.json?.failed ?? null,
  });

  const readToken = settleLossReadToken || settleAdminKey;

  const getEvent = await requestJson(`${settleBaseUrl}/v1/loss-events/${encodeURIComponent(lossEventId)}`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${readToken}`,
    },
  });

  assert(getEvent.status === 200, `loss event get failed (${getEvent.status}): ${getEvent.text}`);

  const getOutbox = await requestJson(
    `${settleBaseUrl}/v1/loss-events/outbox?loss_event_id=${encodeURIComponent(lossEventId)}&limit=50`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${readToken}`,
      },
    }
  );

  assert(getOutbox.status === 200, `loss event outbox get failed (${getOutbox.status}): ${getOutbox.text}`);

  const outbox = Array.isArray(getOutbox.json?.outbox) ? getOutbox.json.outbox : [];
  const forwardedCount = outbox.filter((entry) => entry?.status === 'forwarded').length;
  const failedCount = outbox.filter((entry) => entry?.status === 'failed').length;

  steps.push({
    step: 'readback',
    event_status: getEvent.json?.event?.status ?? null,
    outbox_count: outbox.length,
    forwarded_count: forwardedCount,
    failed_count: failedCount,
  });

  const requireFullyForwarded = !isTruthy(args.get('allow-partial'));
  if (requireFullyForwarded) {
    assert(
      outbox.length > 0 && failedCount === 0 && forwardedCount === outbox.length,
      `outbox not fully forwarded (forwarded=${forwardedCount}, failed=${failedCount}, total=${outbox.length})`
    );
  }

  const summary = {
    ok: true,
    env: envName,
    settle_base_url: settleBaseUrl,
    loss_event_id: lossEventId,
    idempotency_key: idempotencyKey,
    require_fully_forwarded: requireFullyForwarded,
    event_status: getEvent.json?.event?.status ?? null,
    outbox: {
      total: outbox.length,
      forwarded: forwardedCount,
      failed: failedCount,
    },
    steps,
  };

  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const artifact = makeArtifactDir(repoRoot, envName);
  const smokePath = path.resolve(artifact.dir, 'smoke.json');

  await writeJson(smokePath, summary);

  console.log(JSON.stringify({ ok: true, artifact_dir: artifact.dir, smoke: smokePath }, null, 2));
}

function isTruthy(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
