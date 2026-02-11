#!/usr/bin/env node

/**
 * Smoke: clawsettle payout initiation + lifecycle exact-once behavior
 *
 * Validates:
 * - POST /v1/payouts/connect/onboard
 * - POST /v1/payouts idempotency + lock semantics
 * - payout.paid finalize exact-once
 * - payout.failed rollback exact-once
 * - no double-credit/double-release on replay
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

  const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const did = `did:key:smokepayout${suffix}`;

  const createAccount = await httpJson(`${ledgerBaseUrl}/accounts`, {
    method: 'POST',
    headers: authHeaders(ledgerAdminKey.trim()),
    body: JSON.stringify({ did }),
  });

  assert(createAccount.status === 201, `create account expected 201, got ${createAccount.status}: ${createAccount.text}`);

  const accountId = createAccount.json?.id;
  assert(typeof accountId === 'string' && accountId.length > 0, 'missing account id');

  const nowSec = Math.floor(Date.now() / 1000);
  const expectedLivemode = envName === 'prod' || envName === 'production';

  const fundIngest = await httpJson(
    `${ledgerBaseUrl}/v1/payments/settlements/ingest`,
    {
      method: 'POST',
      headers: {
        ...authHeaders(ledgerAdminKey.trim()),
        'idempotency-key': `smoke:payout:fund:${suffix}`,
      },
      body: JSON.stringify({
        provider: 'stripe',
        external_payment_id: `pi_fund_${suffix}`,
        direction: 'payin',
        status: 'confirmed',
        account_id: accountId,
        amount_minor: '5000',
        currency: 'USD',
        metadata: { smoke: true },
      }),
    }
  );

  assert(fundIngest.status === 201, `fund ingest expected 201, got ${fundIngest.status}: ${fundIngest.text}`);

  const onboard = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts/connect/onboard`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({
        account_id: accountId,
        refresh_url: 'https://example.com/refresh',
        return_url: 'https://example.com/return',
      }),
    },
    clawsettleResolveIp
  );

  assert(onboard.status === 201 || onboard.status === 200, `onboard expected 201/200, got ${onboard.status}: ${onboard.text}`);
  assert(onboard.json?.ok === true, `onboard expected ok=true, got ${onboard.text}`);

  const payoutCreate = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'idempotency-key': `smoke:payout:create:paid:${suffix}`,
      },
      body: JSON.stringify({
        account_id: accountId,
        amount_minor: '1200',
        currency: 'USD',
        metadata: { smoke_case: 'paid' },
      }),
    },
    clawsettleResolveIp
  );

  assert(payoutCreate.status === 201, `payout create expected 201, got ${payoutCreate.status}: ${payoutCreate.text}`);
  assert(payoutCreate.json?.ok === true, `payout create expected ok=true, got ${payoutCreate.text}`);
  assert(payoutCreate.json?.deduped === false, `payout create expected deduped=false, got ${payoutCreate.text}`);

  const payout1 = payoutCreate.json?.payout;
  assert(payout1 && typeof payout1.id === 'string', `missing payout in response: ${payoutCreate.text}`);
  assert(payout1.status === 'submitted', `expected payout status submitted, got ${payoutCreate.text}`);
  assert(typeof payout1.external_payout_id === 'string', `missing external payout id: ${payoutCreate.text}`);

  const payoutReplay = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'idempotency-key': `smoke:payout:create:paid:${suffix}`,
      },
      body: JSON.stringify({
        account_id: accountId,
        amount_minor: '1200',
        currency: 'USD',
        metadata: { smoke_case: 'paid' },
      }),
    },
    clawsettleResolveIp
  );

  assert(payoutReplay.status === 200, `payout replay expected 200, got ${payoutReplay.status}: ${payoutReplay.text}`);
  assert(payoutReplay.json?.deduped === true, `payout replay expected deduped=true, got ${payoutReplay.text}`);
  assert(payoutReplay.json?.payout?.id === payout1.id, `payout replay id mismatch: ${payoutReplay.text}`);

  const afterLock = await httpJson(
    `${ledgerBaseUrl}/accounts/id/${encodeURIComponent(accountId)}`,
    {
      method: 'GET',
      headers: authHeaders(ledgerAdminKey.trim()),
    }
  );

  assert(afterLock.status === 200, `after lock account expected 200, got ${afterLock.status}: ${afterLock.text}`);
  assert(afterLock.json?.balances?.available === '3800', `after lock available expected 3800, got ${afterLock.text}`);
  assert(afterLock.json?.balances?.held === '1200', `after lock held expected 1200, got ${afterLock.text}`);

  const payoutPaidWebhook = await postStripeWebhook({
    clawsettleBaseUrl,
    clawsettleResolveIp,
    stripeSecret: stripeSecret.trim(),
    nowSec,
    event: {
      id: `evt_smoke_payout_paid_${suffix}`,
      type: 'payout.paid',
      created: nowSec,
      livemode: expectedLivemode,
      data: {
        object: {
          id: payout1.external_payout_id,
          amount: 1200,
          currency: 'usd',
          created: nowSec,
          metadata: {
            account_id: accountId,
          },
        },
      },
    },
  });

  assert(payoutPaidWebhook.status === 200, `payout.paid webhook expected 200, got ${payoutPaidWebhook.status}: ${payoutPaidWebhook.text}`);

  const payoutPaidReplay = await postStripeWebhook({
    clawsettleBaseUrl,
    clawsettleResolveIp,
    stripeSecret: stripeSecret.trim(),
    nowSec,
    event: {
      id: `evt_smoke_payout_paid_${suffix}`,
      type: 'payout.paid',
      created: nowSec,
      livemode: expectedLivemode,
      data: {
        object: {
          id: payout1.external_payout_id,
          amount: 1200,
          currency: 'usd',
          created: nowSec,
          metadata: {
            account_id: accountId,
          },
        },
      },
    },
  });

  assert(payoutPaidReplay.status === 200, `payout.paid replay expected 200, got ${payoutPaidReplay.status}: ${payoutPaidReplay.text}`);
  assert(payoutPaidReplay.json?.deduped === true, `payout.paid replay expected deduped=true, got ${payoutPaidReplay.text}`);

  const payout1Status = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts/${encodeURIComponent(payout1.id)}`,
    {
      method: 'GET',
      headers: { 'content-type': 'application/json; charset=utf-8' },
    },
    clawsettleResolveIp
  );

  assert(payout1Status.status === 200, `payout status expected 200, got ${payout1Status.status}: ${payout1Status.text}`);
  assert(payout1Status.json?.payout?.status === 'paid', `payout status expected paid, got ${payout1Status.text}`);

  const afterPaid = await httpJson(
    `${ledgerBaseUrl}/accounts/id/${encodeURIComponent(accountId)}`,
    {
      method: 'GET',
      headers: authHeaders(ledgerAdminKey.trim()),
    }
  );

  assert(afterPaid.status === 200, `after paid account expected 200, got ${afterPaid.status}: ${afterPaid.text}`);
  assert(afterPaid.json?.balances?.available === '3800', `after paid available expected 3800, got ${afterPaid.text}`);
  assert(afterPaid.json?.balances?.held === '0', `after paid held expected 0, got ${afterPaid.text}`);

  const payoutCreateFailed = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'idempotency-key': `smoke:payout:create:failed:${suffix}`,
      },
      body: JSON.stringify({
        account_id: accountId,
        amount_minor: '700',
        currency: 'USD',
        metadata: { smoke_case: 'failed' },
      }),
    },
    clawsettleResolveIp
  );

  assert(payoutCreateFailed.status === 201, `second payout create expected 201, got ${payoutCreateFailed.status}: ${payoutCreateFailed.text}`);
  const payout2 = payoutCreateFailed.json?.payout;
  assert(payout2 && typeof payout2.id === 'string', `missing payout2 in response: ${payoutCreateFailed.text}`);

  const afterSecondLock = await httpJson(
    `${ledgerBaseUrl}/accounts/id/${encodeURIComponent(accountId)}`,
    {
      method: 'GET',
      headers: authHeaders(ledgerAdminKey.trim()),
    }
  );

  assert(afterSecondLock.status === 200, `after second lock expected 200, got ${afterSecondLock.status}: ${afterSecondLock.text}`);
  assert(afterSecondLock.json?.balances?.available === '3100', `after second lock available expected 3100, got ${afterSecondLock.text}`);
  assert(afterSecondLock.json?.balances?.held === '700', `after second lock held expected 700, got ${afterSecondLock.text}`);

  const payoutFailedWebhook = await postStripeWebhook({
    clawsettleBaseUrl,
    clawsettleResolveIp,
    stripeSecret: stripeSecret.trim(),
    nowSec,
    event: {
      id: `evt_smoke_payout_failed_${suffix}`,
      type: 'payout.failed',
      created: nowSec,
      livemode: expectedLivemode,
      data: {
        object: {
          id: payout2.external_payout_id,
          amount: 700,
          currency: 'usd',
          created: nowSec,
          metadata: {
            account_id: accountId,
          },
        },
      },
    },
  });

  assert(payoutFailedWebhook.status === 200, `payout.failed webhook expected 200, got ${payoutFailedWebhook.status}: ${payoutFailedWebhook.text}`);

  const payoutFailedReplay = await postStripeWebhook({
    clawsettleBaseUrl,
    clawsettleResolveIp,
    stripeSecret: stripeSecret.trim(),
    nowSec,
    event: {
      id: `evt_smoke_payout_failed_${suffix}`,
      type: 'payout.failed',
      created: nowSec,
      livemode: expectedLivemode,
      data: {
        object: {
          id: payout2.external_payout_id,
          amount: 700,
          currency: 'usd',
          created: nowSec,
          metadata: {
            account_id: accountId,
          },
        },
      },
    },
  });

  assert(payoutFailedReplay.status === 200, `payout.failed replay expected 200, got ${payoutFailedReplay.status}: ${payoutFailedReplay.text}`);
  assert(payoutFailedReplay.json?.deduped === true, `payout.failed replay expected deduped=true, got ${payoutFailedReplay.text}`);

  const payout2Status = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts/${encodeURIComponent(payout2.id)}`,
    {
      method: 'GET',
      headers: { 'content-type': 'application/json; charset=utf-8' },
    },
    clawsettleResolveIp
  );

  assert(payout2Status.status === 200, `payout2 status expected 200, got ${payout2Status.status}: ${payout2Status.text}`);
  assert(payout2Status.json?.payout?.status === 'failed', `payout2 status expected failed, got ${payout2Status.text}`);

  const afterFailed = await httpJson(
    `${ledgerBaseUrl}/accounts/id/${encodeURIComponent(accountId)}`,
    {
      method: 'GET',
      headers: authHeaders(ledgerAdminKey.trim()),
    }
  );

  assert(afterFailed.status === 200, `after failed account expected 200, got ${afterFailed.status}: ${afterFailed.text}`);
  assert(afterFailed.json?.balances?.available === '3800', `after failed available expected 3800, got ${afterFailed.text}`);
  assert(afterFailed.json?.balances?.held === '0', `after failed held expected 0, got ${afterFailed.text}`);

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        clawsettle_base_url: clawsettleBaseUrl,
        clawsettle_resolve_ip: clawsettleResolveIp,
        ledger_base_url: ledgerBaseUrl,
        account_id: accountId,
        payout_paid: {
          payout_id: payout1.id,
          external_payout_id: payout1.external_payout_id,
          create_status: payoutCreate.status,
          replay_status: payoutReplay.status,
          webhook_status: payoutPaidWebhook.status,
          webhook_replay_deduped: payoutPaidReplay.json?.deduped,
          final_status: payout1Status.json?.payout?.status,
        },
        payout_failed: {
          payout_id: payout2.id,
          external_payout_id: payout2.external_payout_id,
          create_status: payoutCreateFailed.status,
          webhook_status: payoutFailedWebhook.status,
          webhook_replay_deduped: payoutFailedReplay.json?.deduped,
          final_status: payout2Status.json?.payout?.status,
        },
        balances: {
          after_lock: {
            available: afterLock.json?.balances?.available,
            held: afterLock.json?.balances?.held,
          },
          after_paid: {
            available: afterPaid.json?.balances?.available,
            held: afterPaid.json?.balances?.held,
          },
          after_failed: {
            available: afterFailed.json?.balances?.available,
            held: afterFailed.json?.balances?.held,
          },
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
