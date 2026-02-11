#!/usr/bin/env node

/**
 * Smoke: clawsettle Stripe webhook verification + ledger forwarding + livemode guard
 *
 * Optional flags:
 *   --env staging|prod
 *   --clawsettle-base-url <url>
 *   --ledger-base-url <url>
 *   --clawsettle-resolve-ip <ipv4>   (forces DNS resolution for clawsettle host)
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

  const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const did = `did:key:smokeclawsettle${suffix}`;

  const createAccount = await httpJson(`${ledgerBaseUrl}/accounts`, {
    method: 'POST',
    headers: authHeaders(ledgerAdminKey.trim()),
    body: JSON.stringify({ did }),
  });

  assert(
    createAccount.status === 201,
    `create account expected 201, got ${createAccount.status}: ${createAccount.text}`
  );

  const accountId = createAccount.json?.id;
  assert(typeof accountId === 'string' && accountId.length > 0, 'missing account id in create response');

  const nowSec = Math.floor(Date.now() / 1000);
  const expectedLivemode = envName === 'prod' || envName === 'production';

  const event = {
    id: `evt_smoke_${envName}_${suffix}`,
    type: 'payment_intent.succeeded',
    created: nowSec,
    livemode: expectedLivemode,
    data: {
      object: {
        id: `pi_smoke_${envName}_${suffix}`,
        amount_received: 1234,
        currency: 'usd',
        payment_method_types: ['card'],
        created: nowSec,
        metadata: {
          account_id: accountId,
        },
      },
    },
  };

  const rawBody = JSON.stringify(event);
  const signature = await signStripe(stripeSecret.trim(), nowSec, rawBody);
  const stripeHeader = `t=${nowSec},v1=${signature}`;

  const webhook = await httpJson(
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

  assert(webhook.status === 200, `webhook expected 200, got ${webhook.status}: ${webhook.text}`);
  assert(webhook.json?.ok === true, `webhook expected ok=true, got ${webhook.text}`);
  assert(webhook.json?.deduped === false, `webhook expected deduped=false, got ${webhook.text}`);
  assert(webhook.json?.forwarded_to_ledger === true, `webhook expected forwarded_to_ledger=true, got ${webhook.text}`);
  assert(webhook.json?.idempotency_key === `stripe:event:${event.id}`, `webhook unexpected idempotency key: ${webhook.text}`);

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

  const tampered = await httpJson(
    `${clawsettleBaseUrl}/v1/stripe/webhook`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'stripe-signature': `t=${nowSec},v1=deadbeef`,
      },
      body: rawBody,
    },
    clawsettleResolveIp
  );

  assert(tampered.status === 401, `tampered expected 401, got ${tampered.status}: ${tampered.text}`);
  assert(tampered.json?.code === 'SIGNATURE_INVALID', `tampered expected SIGNATURE_INVALID, got ${tampered.text}`);

  const mismatchEvent = {
    id: `evt_smoke_livemode_mismatch_${envName}_${suffix}`,
    type: 'payment_intent.succeeded',
    created: nowSec,
    livemode: !expectedLivemode,
    data: {
      object: {
        id: `pi_smoke_livemode_mismatch_${envName}_${suffix}`,
        amount_received: 1,
        currency: 'usd',
        payment_method_types: ['card'],
        created: nowSec,
        metadata: {
          account_id: accountId,
        },
      },
    },
  };

  const mismatchBody = JSON.stringify(mismatchEvent);
  const mismatchSig = await signStripe(stripeSecret.trim(), nowSec, mismatchBody);

  const livemodeMismatch = await httpJson(
    `${clawsettleBaseUrl}/v1/stripe/webhook`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'stripe-signature': `t=${nowSec},v1=${mismatchSig}`,
      },
      body: mismatchBody,
    },
    clawsettleResolveIp
  );

  assert(
    livemodeMismatch.status === 422,
    `livemode mismatch expected 422, got ${livemodeMismatch.status}: ${livemodeMismatch.text}`
  );
  assert(
    livemodeMismatch.json?.code === 'LIVEMODE_MISMATCH',
    `livemode mismatch expected LIVEMODE_MISMATCH, got ${livemodeMismatch.text}`
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

  const account = await httpJson(`${ledgerBaseUrl}/accounts/id/${encodeURIComponent(accountId)}`, {
    method: 'GET',
    headers: authHeaders(ledgerAdminKey.trim()),
  });

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
        account_id: accountId,
        event_id: event.id,
        payment_intent_id: event.data.object.id,
        webhook: {
          status: webhook.status,
          deduped: webhook.json?.deduped,
          forwarded_to_ledger: webhook.json?.forwarded_to_ledger,
          idempotency_key: webhook.json?.idempotency_key,
        },
        replay: {
          status: replay.status,
          deduped: replay.json?.deduped,
        },
        tampered: {
          status: tampered.status,
          code: tampered.json?.code,
        },
        livemode_guard: {
          expected_livemode: expectedLivemode,
          mismatch_status: livemodeMismatch.status,
          mismatch_code: livemodeMismatch.json?.code,
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
