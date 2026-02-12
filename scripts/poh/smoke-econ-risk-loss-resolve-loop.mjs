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

function resolveLedgerBaseUrl(envName, override) {
  if (override && override.trim().length > 0) return override.trim();
  return envName === 'prod' ? 'https://clawledger.com' : 'https://staging.clawledger.com';
}

function makeArtifactDir(repoRoot, envName) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.resolve(repoRoot, 'artifacts', 'simulations', 'econ-risk-loss-resolve-loop', `${timestamp}-${envName}`);
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

function isTruthy(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
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

  const createIdempotencyKey = String(
    args.get('idempotency-key') || `smoke:loss-event:${crypto.randomUUID()}`
  ).trim();

  const resolveIdempotencyKey = String(
    args.get('resolve-idempotency-key') || `smoke:loss-event:resolve:${crypto.randomUUID()}`
  ).trim();

  const amountMinor = String(args.get('amount-minor') || '250').trim();
  const reasonCode = String(args.get('reason-code') || 'chargeback').trim();
  const severity = String(args.get('severity') || 'high').trim();

  const resolveReason = String(args.get('resolve-reason') || 'smoke resolve').trim();

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
      'idempotency-key': createIdempotencyKey,
    },
    body: JSON.stringify(createBody),
  });

  assert(create.status === 201 || create.status === 200, `loss event create failed (${create.status}): ${create.text}`);

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

  const retryApply = await requestJson(`${settleBaseUrl}/v1/loss-events/ops/retry`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${settleAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      operation: 'apply',
      limit: Number.parseInt(String(args.get('retry-limit') || '50'), 10),
      loss_event_id: lossEventId,
    }),
  });

  assert(retryApply.status === 200, `loss event apply retry failed (${retryApply.status}): ${retryApply.text}`);

  steps.push({
    step: 'retry_forwarding_apply',
    status: retryApply.status,
    elapsed_ms: retryApply.elapsed_ms,
    attempted: retryApply.json?.attempted ?? null,
    forwarded: retryApply.json?.forwarded ?? null,
    failed: retryApply.json?.failed ?? null,
  });

  const readToken = settleLossReadToken || settleAdminKey;

  const getEvent = await requestJson(`${settleBaseUrl}/v1/loss-events/${encodeURIComponent(lossEventId)}`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${readToken}`,
    },
  });

  assert(getEvent.status === 200, `loss event get failed (${getEvent.status}): ${getEvent.text}`);

  const getApplyOutbox = await requestJson(
    `${settleBaseUrl}/v1/loss-events/outbox?operation=apply&loss_event_id=${encodeURIComponent(lossEventId)}&limit=50`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${readToken}`,
      },
    }
  );

  assert(getApplyOutbox.status === 200, `loss event outbox get failed (${getApplyOutbox.status}): ${getApplyOutbox.text}`);

  const applyOutbox = Array.isArray(getApplyOutbox.json?.outbox) ? getApplyOutbox.json.outbox : [];
  const applyForwarded = applyOutbox.filter((entry) => entry?.status === 'forwarded').length;
  const applyFailed = applyOutbox.filter((entry) => entry?.status === 'failed').length;

  steps.push({
    step: 'readback_apply',
    event_status: getEvent.json?.event?.status ?? null,
    outbox_count: applyOutbox.length,
    forwarded_count: applyForwarded,
    failed_count: applyFailed,
  });

  const requireFullyForwarded = !isTruthy(args.get('allow-partial'));
  if (requireFullyForwarded) {
    assert(
      applyOutbox.length > 0 && applyFailed === 0 && applyForwarded === applyOutbox.length,
      `apply outbox not fully forwarded (forwarded=${applyForwarded}, failed=${applyFailed}, total=${applyOutbox.length})`
    );
  }

  assert(getEvent.json?.event?.status === 'forwarded', `loss event must be forwarded before resolve; got ${getEvent.json?.event?.status}`);

  const resolve = await requestJson(`${settleBaseUrl}/v1/loss-events/${encodeURIComponent(lossEventId)}/resolve`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${settleAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
      'idempotency-key': resolveIdempotencyKey,
    },
    body: JSON.stringify({
      reason: resolveReason,
    }),
  });

  assert(resolve.status === 201 || resolve.status === 200, `loss event resolve failed (${resolve.status}): ${resolve.text}`);

  steps.push({
    step: 'resolve_loss_event',
    status: resolve.status,
    elapsed_ms: resolve.elapsed_ms,
    deduped: resolve.json?.deduped === true,
    resolution_id: resolve.json?.resolution?.resolution_id ?? null,
  });

  const retryResolve = await requestJson(`${settleBaseUrl}/v1/loss-events/ops/retry`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${settleAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      operation: 'resolve',
      limit: Number.parseInt(String(args.get('retry-limit') || '50'), 10),
      loss_event_id: lossEventId,
    }),
  });

  assert(retryResolve.status === 200, `loss event resolve retry failed (${retryResolve.status}): ${retryResolve.text}`);

  steps.push({
    step: 'retry_forwarding_resolve',
    status: retryResolve.status,
    elapsed_ms: retryResolve.elapsed_ms,
    attempted: retryResolve.json?.attempted ?? null,
    forwarded: retryResolve.json?.forwarded ?? null,
    failed: retryResolve.json?.failed ?? null,
  });

  const getResolveOutbox = await requestJson(
    `${settleBaseUrl}/v1/loss-events/outbox?operation=resolve&loss_event_id=${encodeURIComponent(lossEventId)}&limit=50`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${readToken}`,
      },
    }
  );

  assert(getResolveOutbox.status === 200, `loss event resolve outbox get failed (${getResolveOutbox.status}): ${getResolveOutbox.text}`);

  const resolveOutbox = Array.isArray(getResolveOutbox.json?.outbox) ? getResolveOutbox.json.outbox : [];
  const resolveForwarded = resolveOutbox.filter((entry) => entry?.status === 'forwarded').length;
  const resolveFailed = resolveOutbox.filter((entry) => entry?.status === 'failed').length;

  steps.push({
    step: 'readback_resolve',
    outbox_count: resolveOutbox.length,
    forwarded_count: resolveForwarded,
    failed_count: resolveFailed,
  });

  if (requireFullyForwarded) {
    assert(
      resolveOutbox.length > 0 && resolveFailed === 0 && resolveForwarded === resolveOutbox.length,
      `resolve outbox not fully forwarded (forwarded=${resolveForwarded}, failed=${resolveFailed}, total=${resolveOutbox.length})`
    );
  }

  let ledgerHold = null;
  const verifyLedgerHold = isTruthy(args.get('verify-ledger-hold'));
  const ledgerAdminKey = String(args.get('ledger-admin-key') || process.env.LEDGER_ADMIN_KEY || '').trim();

  if (verifyLedgerHold) {
    assert(ledgerAdminKey.length > 0, 'LEDGER_ADMIN_KEY (or --ledger-admin-key) is required when --verify-ledger-hold is set');

    const ledgerBaseUrl = resolveLedgerBaseUrl(envName, args.get('ledger-base-url'));
    const holdsRes = await requestJson(
      `${ledgerBaseUrl}/v1/risk/holds?source_loss_event_id=${encodeURIComponent(lossEventId)}&limit=10`,
      {
        method: 'GET',
        headers: {
          authorization: `Bearer ${ledgerAdminKey}`,
        },
      }
    );

    assert(holdsRes.status === 200, `ledger holds list failed (${holdsRes.status}): ${holdsRes.text}`);

    const holds = Array.isArray(holdsRes.json?.holds) ? holdsRes.json.holds : [];
    ledgerHold = holds.length > 0 ? holds[0] : null;

    steps.push({
      step: 'verify_ledger_hold',
      status: holdsRes.status,
      hold_count: holds.length,
      hold_status: ledgerHold?.status ?? null,
    });

    assert(ledgerHold && ledgerHold.status === 'released', `expected ledger hold to be released; got ${ledgerHold?.status}`);
  }

  const summary = {
    ok: true,
    env: envName,
    settle_base_url: settleBaseUrl,
    loss_event_id: lossEventId,
    idempotency_keys: {
      apply: createIdempotencyKey,
      resolve: resolveIdempotencyKey,
    },
    require_fully_forwarded: requireFullyForwarded,
    apply: {
      event_status: getEvent.json?.event?.status ?? null,
      outbox: {
        total: applyOutbox.length,
        forwarded: applyForwarded,
        failed: applyFailed,
      },
    },
    resolve: {
      resolution_id: resolve.json?.resolution?.resolution_id ?? null,
      outbox: {
        total: resolveOutbox.length,
        forwarded: resolveForwarded,
        failed: resolveFailed,
      },
    },
    ledger_hold: ledgerHold,
    steps,
  };

  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const artifact = makeArtifactDir(repoRoot, envName);

  await writeJson(path.resolve(artifact.dir, 'smoke.json'), summary);

  console.log(JSON.stringify({ ok: true, artifact_dir: artifact.dir }, null, 2));
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
