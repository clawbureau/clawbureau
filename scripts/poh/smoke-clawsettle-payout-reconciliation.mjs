#!/usr/bin/env node

/**
 * Smoke: clawsettle payout reconciliation + ops controls
 *
 * Validates:
 * - stuck payout visibility
 * - targeted retry controls
 * - failed payout visibility
 * - daily reconciliation JSON + CSV deterministic artifact hash
 *
 * Optional flags:
 *   --env staging|prod
 *   --clawsettle-base-url <url>
 *   --ledger-base-url <url>
 *   --clawsettle-resolve-ip <ipv4>
 */

import process from 'node:process';
import http from 'node:http';
import https from 'node:https';

function parseArgs(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;

    const key = token.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) {
      args.set(key, next);
      i += 1;
    } else {
      args.set(key, 'true');
    }
  }
  return args;
}

function assert(cond, message) {
  if (!cond) {
    throw new Error(`ASSERT_FAILED: ${message}`);
  }
}

function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function signStripe(secret, timestamp, rawBody) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false,
    ['sign']
  );

  const payload = `${timestamp}.${rawBody}`;
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return toHex(new Uint8Array(sig));
}

async function requestWithOptionalResolve(url, init, resolveIp) {
  if (!resolveIp) {
    const res = await fetch(url, init);
    const text = await res.text();

    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }

    return {
      status: res.status,
      headers: Object.fromEntries(res.headers.entries()),
      text,
      json,
    };
  }

  const parsed = new URL(url);
  const transport = parsed.protocol === 'https:' ? https : http;

  const method = init?.method ?? 'GET';
  const headers = init?.headers ?? {};
  const body = init?.body ?? null;

  const options = {
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    path: `${parsed.pathname}${parsed.search}`,
    method,
    headers,
    servername: parsed.hostname,
    lookup: (_hostname, optsOrCb, cbMaybe) => {
      const cb = typeof optsOrCb === 'function' ? optsOrCb : cbMaybe;
      if (typeof cb !== 'function') {
        throw new Error('lookup callback missing');
      }

      const opts = typeof optsOrCb === 'function' ? {} : (optsOrCb || {});
      if (opts && opts.all) {
        cb(null, [{ address: resolveIp, family: 4 }]);
        return;
      }

      cb(null, resolveIp, 4);
    },
  };

  const result = await new Promise((resolve, reject) => {
    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const out = Buffer.concat(chunks).toString('utf8');
        const headersOut = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (Array.isArray(v)) {
            headersOut[k] = v.join(', ');
          } else if (typeof v === 'string') {
            headersOut[k] = v;
          }
        }

        resolve({ statusCode: res.statusCode ?? 500, body: out, headers: headersOut });
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(body);
    }

    req.end();
  });

  const data = result;
  let json = null;
  try {
    json = JSON.parse(data.body);
  } catch {
    json = null;
  }

  return {
    status: data.statusCode,
    headers: data.headers,
    text: data.body,
    json,
  };
}

async function httpJson(url, init, resolveIp) {
  return requestWithOptionalResolve(url, init, resolveIp);
}

function authHeaders(adminKey) {
  return {
    authorization: `Bearer ${adminKey}`,
    'content-type': 'application/json; charset=utf-8',
  };
}

async function postStripeWebhook({
  clawsettleBaseUrl,
  clawsettleResolveIp,
  stripeSecret,
  nowSec,
  event,
}) {
  const rawBody = JSON.stringify(event);
  const sig = await signStripe(stripeSecret, nowSec, rawBody);

  return httpJson(
    `${clawsettleBaseUrl}/v1/stripe/webhook`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'stripe-signature': `t=${nowSec},v1=${sig}`,
      },
      body: rawBody,
    },
    clawsettleResolveIp
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = String(args.get('env') || 'staging').toLowerCase();

  const clawsettleBaseUrl =
    String(args.get('clawsettle-base-url') || '') ||
    (envName === 'prod' || envName === 'production'
      ? 'https://clawsettle.com'
      : 'https://staging.clawsettle.com');

  const clawsettleResolveIp = String(args.get('clawsettle-resolve-ip') || '').trim() || null;

  const ledgerBaseUrl =
    String(args.get('ledger-base-url') || '') ||
    (envName === 'prod' || envName === 'production'
      ? 'https://clawledger.com'
      : 'https://staging.clawledger.com');

  const stripeSecret = process.env.STRIPE_WEBHOOK_SIGNING_SECRET;
  assert(stripeSecret && stripeSecret.trim().length > 0, 'Missing STRIPE_WEBHOOK_SIGNING_SECRET env var');

  const ledgerAdminKey = process.env.LEDGER_ADMIN_KEY;
  assert(ledgerAdminKey && ledgerAdminKey.trim().length > 0, 'Missing LEDGER_ADMIN_KEY env var');

  const settleAdminKey = process.env.SETTLE_ADMIN_KEY;
  assert(settleAdminKey && settleAdminKey.trim().length > 0, 'Missing SETTLE_ADMIN_KEY env var');

  const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const did = `did:key:smokerecon${suffix}`;

  const createAccount = await httpJson(`${ledgerBaseUrl}/accounts`, {
    method: 'POST',
    headers: authHeaders(ledgerAdminKey.trim()),
    body: JSON.stringify({ did }),
  });

  assert(createAccount.status === 201, `create account expected 201, got ${createAccount.status}: ${createAccount.text}`);
  const accountId = createAccount.json?.id;
  const accountDid = createAccount.json?.did;
  assert(typeof accountId === 'string' && accountId.length > 0, 'missing account id');
  assert(typeof accountDid === 'string' && accountDid.length > 0, 'missing account did');

  const nowSec = Math.floor(Date.now() / 1000);
  const expectedLivemode = envName === 'prod' || envName === 'production';

  const fund = await httpJson(
    `${ledgerBaseUrl}/v1/payments/settlements/ingest`,
    {
      method: 'POST',
      headers: {
        ...authHeaders(ledgerAdminKey.trim()),
        'idempotency-key': `smoke:recon:fund:${suffix}`,
      },
      body: JSON.stringify({
        provider: 'stripe',
        external_payment_id: `pi_recon_fund_${suffix}`,
        direction: 'payin',
        status: 'confirmed',
        account_id: accountId,
        amount_minor: '4000',
        currency: 'USD',
      }),
    }
  );

  assert(fund.status === 201, `fund ingest expected 201, got ${fund.status}: ${fund.text}`);

  const onboard = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts/connect/onboard`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ account_id: accountId }),
    },
    clawsettleResolveIp
  );

  assert(onboard.status === 201 || onboard.status === 200, `onboard expected 201/200, got ${onboard.status}: ${onboard.text}`);

  const payoutCreate = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'idempotency-key': `smoke:recon:payout:${suffix}`,
      },
      body: JSON.stringify({
        account_id: accountId,
        amount_minor: '900',
        currency: 'USD',
      }),
    },
    clawsettleResolveIp
  );

  assert(payoutCreate.status === 201, `payout create expected 201, got ${payoutCreate.status}: ${payoutCreate.text}`);
  const payout = payoutCreate.json?.payout;
  assert(payout && typeof payout.id === 'string', `missing payout id: ${payoutCreate.text}`);
  assert(typeof payout.external_payout_id === 'string', `missing external payout id: ${payoutCreate.text}`);

  // Force a lifecycle failure: drain held bucket before payout.failed webhook is processed.
  const tamperHeld = await httpJson(
    `${ledgerBaseUrl}/v1/transfers`,
    {
      method: 'POST',
      headers: authHeaders(ledgerAdminKey.trim()),
      body: JSON.stringify({
        idempotency_key: `smoke:recon:tamper-held:${suffix}`,
        currency: 'USD',
        from: {
          account: accountDid,
          bucket: 'H',
        },
        to: {
          account: accountDid,
          bucket: 'A',
        },
        amount_minor: '900',
        metadata: {
          smoke: 'tamper-held-before-failed-webhook',
        },
      }),
    }
  );

  assert(tamperHeld.status === 200, `tamper held expected 200, got ${tamperHeld.status}: ${tamperHeld.text}`);

  const failedWebhook = await postStripeWebhook({
    clawsettleBaseUrl,
    clawsettleResolveIp,
    stripeSecret: stripeSecret.trim(),
    nowSec,
    event: {
      id: `evt_smoke_recon_failed_${suffix}`,
      type: 'payout.failed',
      created: nowSec,
      livemode: expectedLivemode,
      data: {
        object: {
          id: payout.external_payout_id,
          amount: 900,
          currency: 'usd',
          created: nowSec,
          metadata: {
            account_id: accountId,
          },
        },
      },
    },
  });

  assert(failedWebhook.status === 502, `failed webhook expected 502 while stuck, got ${failedWebhook.status}: ${failedWebhook.text}`);
  assert(failedWebhook.json?.code === 'LEDGER_INGEST_FAILED', `failed webhook expected LEDGER_INGEST_FAILED, got ${failedWebhook.text}`);

  const payoutAfterFailure = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts/${encodeURIComponent(payout.id)}`,
    {
      method: 'GET',
      headers: { 'content-type': 'application/json; charset=utf-8' },
    },
    clawsettleResolveIp
  );

  assert(payoutAfterFailure.status === 200, `payout lookup expected 200, got ${payoutAfterFailure.status}: ${payoutAfterFailure.text}`);
  assert(
    payoutAfterFailure.json?.payout?.status === 'finalizing_failed',
    `expected finalizing_failed, got ${payoutAfterFailure.text}`
  );

  const stuckList = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts/ops/stuck?older_than_minutes=0&limit=20`,
    {
      method: 'GET',
      headers: authHeaders(settleAdminKey.trim()),
    },
    clawsettleResolveIp
  );

  assert(stuckList.status === 200, `stuck list expected 200, got ${stuckList.status}: ${stuckList.text}`);
  assert(
    Array.isArray(stuckList.json?.payouts) && stuckList.json.payouts.some((row) => row.id === payout.id),
    `stuck list expected payout ${payout.id}, got ${stuckList.text}`
  );

  // Re-lock held funds so targeted retry can complete rollback deterministically.
  const relockHeld = await httpJson(
    `${ledgerBaseUrl}/v1/transfers`,
    {
      method: 'POST',
      headers: authHeaders(ledgerAdminKey.trim()),
      body: JSON.stringify({
        idempotency_key: `smoke:recon:relock-held:${suffix}`,
        currency: 'USD',
        from: {
          account: accountDid,
          bucket: 'A',
        },
        to: {
          account: accountDid,
          bucket: 'H',
        },
        amount_minor: '900',
        metadata: {
          smoke: 'restore-held-for-retry',
        },
      }),
    }
  );

  assert(relockHeld.status === 200, `relock held expected 200, got ${relockHeld.status}: ${relockHeld.text}`);

  const retry = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts/${encodeURIComponent(payout.id)}/retry`,
    {
      method: 'POST',
      headers: authHeaders(settleAdminKey.trim()),
      body: JSON.stringify({}),
    },
    clawsettleResolveIp
  );

  assert(retry.status === 200, `retry expected 200, got ${retry.status}: ${retry.text}`);
  assert(retry.json?.status === 'failed', `retry expected status failed, got ${retry.text}`);

  const failedList = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts/ops/failed?limit=20`,
    {
      method: 'GET',
      headers: authHeaders(settleAdminKey.trim()),
    },
    clawsettleResolveIp
  );

  assert(failedList.status === 200, `failed list expected 200, got ${failedList.status}: ${failedList.text}`);
  assert(
    Array.isArray(failedList.json?.payouts) && failedList.json.payouts.some((row) => row.id === payout.id),
    `failed list expected payout ${payout.id}, got ${failedList.text}`
  );

  const date = new Date().toISOString().slice(0, 10);

  const reconJson = await httpJson(
    `${clawsettleBaseUrl}/v1/reconciliation/payouts/daily?date=${encodeURIComponent(date)}&format=json`,
    {
      method: 'GET',
      headers: authHeaders(settleAdminKey.trim()),
    },
    clawsettleResolveIp
  );

  assert(reconJson.status === 200, `reconciliation json expected 200, got ${reconJson.status}: ${reconJson.text}`);
  assert(typeof reconJson.json?.artifact_sha256 === 'string', `missing artifact hash: ${reconJson.text}`);

  const reconCsv = await httpJson(
    `${clawsettleBaseUrl}/v1/reconciliation/payouts/daily?date=${encodeURIComponent(date)}&format=csv`,
    {
      method: 'GET',
      headers: authHeaders(settleAdminKey.trim()),
    },
    clawsettleResolveIp
  );

  assert(reconCsv.status === 200, `reconciliation csv expected 200, got ${reconCsv.status}: ${reconCsv.text}`);
  assert(
    String(reconCsv.headers['content-type'] || '').includes('text/csv'),
    `reconciliation csv expected text/csv, got headers=${JSON.stringify(reconCsv.headers)}`
  );

  const csvHash = reconCsv.headers['x-clawsettle-report-sha256'];
  assert(typeof csvHash === 'string' && csvHash.length > 0, 'missing x-clawsettle-report-sha256 header');
  assert(csvHash === reconJson.json?.artifact_sha256, `csv hash/header mismatch: csv=${csvHash} json=${reconJson.json?.artifact_sha256}`);

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        clawsettle_base_url: clawsettleBaseUrl,
        clawsettle_resolve_ip: clawsettleResolveIp,
        ledger_base_url: ledgerBaseUrl,
        account_id: accountId,
        payout_id: payout.id,
        failed_webhook: {
          status: failedWebhook.status,
          code: failedWebhook.json?.code,
        },
        stuck_visibility: {
          status: stuckList.status,
          count: Array.isArray(stuckList.json?.payouts) ? stuckList.json.payouts.length : 0,
        },
        retry: {
          status: retry.status,
          payout_status: retry.json?.status,
          retried: retry.json?.retried,
        },
        failed_visibility: {
          status: failedList.status,
          count: Array.isArray(failedList.json?.payouts) ? failedList.json.payouts.length : 0,
        },
        reconciliation: {
          date,
          json_status: reconJson.status,
          csv_status: reconCsv.status,
          artifact_sha256: reconJson.json?.artifact_sha256,
          csv_header_hash: csvHash,
          csv_preview: reconCsv.text.split('\n').slice(0, 2),
        },
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
