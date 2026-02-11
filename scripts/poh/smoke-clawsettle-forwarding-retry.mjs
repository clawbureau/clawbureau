#!/usr/bin/env node

/**
 * Smoke: clawsettle durable forwarding outbox + retry
 *
 * Validates: initial ledger failure -> durable retry -> success -> no double-credit.
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

function deriveAccountId(did) {
  let hash = 0;
  for (let i = 0; i < did.length; i++) {
    const char = did.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }

  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `acc_${hex}`;
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

  const text = await new Promise((resolve, reject) => {
    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const out = Buffer.concat(chunks).toString('utf8');
        resolve({ statusCode: res.statusCode ?? 500, body: out });
      });
    });

    req.on('error', reject);

    if (body) {
      req.write(body);
    }

    req.end();
  });

  const data = text;
  let json = null;
  try {
    json = JSON.parse(data.body);
  } catch {
    json = null;
  }

  return {
    status: data.statusCode,
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
  const did = `did:key:smokeclawsettleretry${suffix}`;
  const derivedAccountId = deriveAccountId(did);
  const nowSec = Math.floor(Date.now() / 1000);
  const expectedLivemode = envName === 'prod' || envName === 'production';

  const event = {
    id: `evt_retry_${envName}_${suffix}`,
    type: 'payment_intent.succeeded',
    created: nowSec,
    livemode: expectedLivemode,
    data: {
      object: {
        id: `pi_retry_${envName}_${suffix}`,
        amount_received: 1234,
        currency: 'usd',
        payment_method_types: ['card'],
        created: nowSec,
        metadata: {
          account_id: derivedAccountId,
        },
      },
    },
  };

  const rawBody = JSON.stringify(event);
  const signature = await signStripe(stripeSecret.trim(), nowSec, rawBody);
  const stripeHeader = `t=${nowSec},v1=${signature}`;

  // 1) Webhook should fail while account is absent in ledger, but schedule retry.
  const firstWebhook = await httpJson(
    `${clawsettleBaseUrl}/v1/stripe/webhook`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'stripe-signature': stripeHeader,
      },
      body: rawBody,
    },
    clawsettleResolveIp
  );

  assert(
    firstWebhook.status === 502,
    `first webhook expected 502, got ${firstWebhook.status}: ${firstWebhook.text}`
  );
  assert(
    firstWebhook.json?.code === 'LEDGER_INGEST_FAILED',
    `first webhook expected LEDGER_INGEST_FAILED, got ${firstWebhook.text}`
  );
  assert(
    firstWebhook.json?.details?.retry_scheduled === true,
    `first webhook expected retry_scheduled=true, got ${firstWebhook.text}`
  );

  // 2) Create account to unblock forwarding.
  const createAccount = await httpJson(`${ledgerBaseUrl}/accounts`, {
    method: 'POST',
    headers: authHeaders(ledgerAdminKey.trim()),
    body: JSON.stringify({ did }),
  });

  assert(
    createAccount.status === 201,
    `create account expected 201, got ${createAccount.status}: ${createAccount.text}`
  );
  assert(
    createAccount.json?.id === derivedAccountId,
    `derived account mismatch; expected ${derivedAccountId}, got ${createAccount.text}`
  );

  // 3) Retry forwarding once (should succeed once only).
  const retry1 = await httpJson(
    `${clawsettleBaseUrl}/v1/stripe/forwarding/retry`,
    {
      method: 'POST',
      headers: authHeaders(settleAdminKey.trim()),
      body: JSON.stringify({ limit: 20, force: true, event_id: event.id }),
    },
    clawsettleResolveIp
  );

  assert(retry1.status === 200, `retry #1 expected 200, got ${retry1.status}: ${retry1.text}`);
  assert(retry1.json?.ok === true, `retry #1 expected ok=true, got ${retry1.text}`);
  assert(retry1.json?.attempted >= 1, `retry #1 expected attempted>=1, got ${retry1.text}`);
  assert(retry1.json?.forwarded >= 1, `retry #1 expected forwarded>=1, got ${retry1.text}`);
  assert(retry1.json?.failed === 0, `retry #1 expected failed=0, got ${retry1.text}`);

  // 4) Retry again should not re-forward successful event.
  const retry2 = await httpJson(
    `${clawsettleBaseUrl}/v1/stripe/forwarding/retry`,
    {
      method: 'POST',
      headers: authHeaders(settleAdminKey.trim()),
      body: JSON.stringify({ limit: 20, force: true, event_id: event.id }),
    },
    clawsettleResolveIp
  );

  assert(retry2.status === 200, `retry #2 expected 200, got ${retry2.status}: ${retry2.text}`);
  assert(retry2.json?.ok === true, `retry #2 expected ok=true, got ${retry2.text}`);
  assert(retry2.json?.forwarded === 0, `retry #2 expected forwarded=0, got ${retry2.text}`);

  // 5) Replay webhook must be deduped and not double-credit.
  const replay = await httpJson(
    `${clawsettleBaseUrl}/v1/stripe/webhook`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'stripe-signature': stripeHeader,
      },
      body: rawBody,
    },
    clawsettleResolveIp
  );

  assert(replay.status === 200, `replay expected 200, got ${replay.status}: ${replay.text}`);
  assert(replay.json?.deduped === true, `replay expected deduped=true, got ${replay.text}`);
  assert(
    replay.json?.forwarded_to_ledger === true,
    `replay expected forwarded_to_ledger=true, got ${replay.text}`
  );

  const settlementLookup = await httpJson(
    `${ledgerBaseUrl}/v1/payments/settlements/stripe/${encodeURIComponent(event.data.object.id)}?direction=payin`,
    {
      method: 'GET',
      headers: authHeaders(ledgerAdminKey.trim()),
    }
  );

  assert(
    settlementLookup.status === 200,
    `settlement lookup expected 200, got ${settlementLookup.status}: ${settlementLookup.text}`
  );

  const account = await httpJson(
    `${ledgerBaseUrl}/accounts/id/${encodeURIComponent(derivedAccountId)}`,
    {
      method: 'GET',
      headers: authHeaders(ledgerAdminKey.trim()),
    }
  );

  assert(account.status === 200, `account expected 200, got ${account.status}: ${account.text}`);
  assert(
    account.json?.balances?.available === '1234',
    `account available expected 1234, got ${account.text}`
  );

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        clawsettle_base_url: clawsettleBaseUrl,
        clawsettle_resolve_ip: clawsettleResolveIp,
        ledger_base_url: ledgerBaseUrl,
        did,
        account_id: derivedAccountId,
        event_id: event.id,
        payment_intent_id: event.data.object.id,
        first_webhook: {
          status: firstWebhook.status,
          code: firstWebhook.json?.code,
          retry_scheduled: firstWebhook.json?.details?.retry_scheduled,
          next_retry_at: firstWebhook.json?.details?.next_retry_at,
          ledger_status: firstWebhook.json?.details?.ledger_status,
        },
        retry_1: {
          status: retry1.status,
          attempted: retry1.json?.attempted,
          forwarded: retry1.json?.forwarded,
          failed: retry1.json?.failed,
        },
        retry_2: {
          status: retry2.status,
          attempted: retry2.json?.attempted,
          forwarded: retry2.json?.forwarded,
          failed: retry2.json?.failed,
        },
        replay: {
          status: replay.status,
          deduped: replay.json?.deduped,
          forwarded_to_ledger: replay.json?.forwarded_to_ledger,
        },
        settlement_lookup: {
          status: settlementLookup.status,
          count: Array.isArray(settlementLookup.json?.settlements)
            ? settlementLookup.json.settlements.length
            : 0,
          top_status: Array.isArray(settlementLookup.json?.settlements)
            ? settlementLookup.json.settlements[0]?.status
            : undefined,
        },
        account: {
          status: account.status,
          available: account.json?.balances?.available,
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
