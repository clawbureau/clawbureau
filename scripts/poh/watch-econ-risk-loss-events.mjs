#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, resolveEnvName, assert } from './_clawbounties-sim-common.mjs';

function resolveSettleBaseUrl(envName, override) {
  if (override && override.trim().length > 0) return override.trim();
  return envName === 'prod' ? 'https://clawsettle.com' : 'https://staging.clawsettle.com';
}

function nowIso() {
  return new Date().toISOString();
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

async function writeJson(filePath, payload) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

function computeStatusBuckets(events) {
  const buckets = {
    recorded: 0,
    processing: 0,
    partially_forwarded: 0,
    forwarded: 0,
    failed: 0,
    unknown: 0,
  };

  for (const event of events) {
    const status = typeof event?.status === 'string' ? event.status : 'unknown';
    if (status in buckets) {
      buckets[status] += 1;
    } else {
      buckets.unknown += 1;
    }
  }

  return buckets;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = resolveEnvName(args.get('env'));

  const settleBaseUrl = resolveSettleBaseUrl(envName, args.get('clawsettle-base-url'));
  const readToken = String(
    args.get('settle-loss-read-token') ||
      process.env.SETTLE_LOSS_READ_TOKEN ||
      args.get('settle-admin-key') ||
      process.env.SETTLE_ADMIN_KEY ||
      ''
  ).trim();

  assert(readToken.length > 0, 'SETTLE_LOSS_READ_TOKEN or SETTLE_ADMIN_KEY is required');

  const limit = Number.parseInt(String(args.get('limit') || '200'), 10);
  assert(Number.isInteger(limit) && limit > 0, '--limit must be a positive integer');

  const eventsRes = await requestJson(`${settleBaseUrl}/v1/loss-events?limit=${limit}`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${readToken}`,
    },
  });

  assert(eventsRes.status === 200, `loss events list failed (${eventsRes.status}): ${eventsRes.text}`);

  const outboxRes = await requestJson(`${settleBaseUrl}/v1/loss-events/outbox?limit=${limit}`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${readToken}`,
    },
  });

  assert(outboxRes.status === 200, `loss outbox list failed (${outboxRes.status}): ${outboxRes.text}`);

  const events = Array.isArray(eventsRes.json?.events) ? eventsRes.json.events : [];
  const outbox = Array.isArray(outboxRes.json?.outbox) ? outboxRes.json.outbox : [];

  const eventBuckets = computeStatusBuckets(events);
  const outboxBuckets = {
    pending: outbox.filter((entry) => entry?.status === 'pending').length,
    forwarded: outbox.filter((entry) => entry?.status === 'forwarded').length,
    failed: outbox.filter((entry) => entry?.status === 'failed').length,
  };

  const outboxByTarget = {};
  for (const entry of outbox) {
    const target = typeof entry?.target_service === 'string' ? entry.target_service : 'unknown';
    const status = typeof entry?.status === 'string' ? entry.status : 'unknown';
    if (!outboxByTarget[target]) {
      outboxByTarget[target] = {
        pending: 0,
        forwarded: 0,
        failed: 0,
        unknown: 0,
      };
    }

    if (status === 'pending' || status === 'forwarded' || status === 'failed') {
      outboxByTarget[target][status] += 1;
    } else {
      outboxByTarget[target].unknown += 1;
    }
  }

  const summary = {
    ok: true,
    env: envName,
    settle_base_url: settleBaseUrl,
    generated_at: nowIso(),
    limit,
    event_count: events.length,
    event_status_buckets: eventBuckets,
    outbox_count: outbox.length,
    outbox_status_buckets: outboxBuckets,
    outbox_by_target: outboxByTarget,
    deterministic_error_buckets: {
      event_failed_count: eventBuckets.failed,
      outbox_failed_count: outboxBuckets.failed,
    },
  };

  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const artifactDir = path.resolve(repoRoot, 'artifacts', 'ops', 'econ-risk', `${stamp}-${envName}-loss-event-watch`);

  await writeJson(path.resolve(artifactDir, 'summary.json'), summary);
  await writeJson(path.resolve(artifactDir, 'events.json'), eventsRes.json ?? null);
  await writeJson(path.resolve(artifactDir, 'outbox.json'), outboxRes.json ?? null);

  console.log(JSON.stringify({ ok: true, artifact_dir: artifactDir }, null, 2));
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
