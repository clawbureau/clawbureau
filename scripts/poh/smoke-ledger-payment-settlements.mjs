#!/usr/bin/env node

/**
 * Smoke: machine-payment settlement ingestion in clawledger
 *
 * Validates:
 *  - confirmed payin settlement ingest
 *  - idempotency replay on same key
 *  - reversal path (confirmed -> reversed)
 */

import process from 'node:process';

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

async function httpJson(url, init) {
  const res = await fetch(url, init);
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  return { status: res.status, text, json };
}

function authHeaders(adminKey) {
  return {
    Authorization: `Bearer ${adminKey}`,
    'Content-Type': 'application/json; charset=utf-8',
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = String(args.get('env') || 'staging').toLowerCase();

  const ledgerBaseUrl =
    String(args.get('ledger-base-url') || '') ||
    (envName === 'prod' || envName === 'production'
      ? 'https://clawledger.com'
      : 'https://staging.clawledger.com');

  const adminKey = process.env.LEDGER_ADMIN_KEY;
  assert(adminKey && adminKey.trim().length > 0, 'Missing LEDGER_ADMIN_KEY env var');

  const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const did = `did:key:smokeledger${suffix}`;

  const createAccount = await httpJson(`${ledgerBaseUrl}/accounts`, {
    method: 'POST',
    headers: authHeaders(adminKey.trim()),
    body: JSON.stringify({ did }),
  });

  assert(
    createAccount.status === 201,
    `POST /accounts expected 201, got ${createAccount.status}: ${createAccount.text}`
  );

  const accountId = createAccount.json?.id;
  assert(typeof accountId === 'string' && accountId.length > 0, 'account id missing in create response');

  const provider = 'provider_sim';
  const externalPaymentId = `pay_${envName}_${suffix}`;
  const idempotencyKey = `payset:${envName}:${suffix}:1`;

  const confirmedPayload = {
    provider,
    external_payment_id: externalPaymentId,
    direction: 'payin',
    status: 'confirmed',
    account_id: accountId,
    amount_minor: '2500',
    currency: 'USD',
    network: 'sim_network',
    rail: 'sim_rail',
    metadata: {
      smoke: true,
      env: envName,
    },
  };

  const confirmed = await httpJson(`${ledgerBaseUrl}/v1/payments/settlements/ingest`, {
    method: 'POST',
    headers: {
      ...authHeaders(adminKey.trim()),
      'Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify(confirmedPayload),
  });

  assert(
    confirmed.status === 201,
    `confirmed ingest expected 201, got ${confirmed.status}: ${confirmed.text}`
  );
  assert(
    confirmed.json?.settlement?.status === 'confirmed',
    `confirmed ingest expected settlement.status=confirmed, got ${confirmed.text}`
  );
  assert(
    confirmed.json?.event?.event_type === 'payin_settle',
    `confirmed ingest expected payin_settle event, got ${confirmed.text}`
  );

  const replay = await httpJson(`${ledgerBaseUrl}/v1/payments/settlements/ingest`, {
    method: 'POST',
    headers: {
      ...authHeaders(adminKey.trim()),
      'Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify(confirmedPayload),
  });

  assert(
    replay.status === 200,
    `replay expected 200, got ${replay.status}: ${replay.text}`
  );
  assert(
    replay.json?.idempotency?.replayed === true,
    `replay expected idempotency.replayed=true, got ${replay.text}`
  );

  const reversal = await httpJson(`${ledgerBaseUrl}/v1/payments/settlements/ingest`, {
    method: 'POST',
    headers: {
      ...authHeaders(adminKey.trim()),
      'Idempotency-Key': `payset:${envName}:${suffix}:2`,
    },
    body: JSON.stringify({
      ...confirmedPayload,
      status: 'reversed',
    }),
  });

  assert(
    reversal.status === 200 || reversal.status === 201,
    `reversal ingest expected 200/201, got ${reversal.status}: ${reversal.text}`
  );
  assert(
    reversal.json?.settlement?.status === 'reversed',
    `reversal expected settlement.status=reversed, got ${reversal.text}`
  );
  assert(
    reversal.json?.event?.event_type === 'payin_reverse',
    `reversal expected payin_reverse event, got ${reversal.text}`
  );

  const lookup = await httpJson(
    `${ledgerBaseUrl}/v1/payments/settlements/${encodeURIComponent(provider)}/${encodeURIComponent(externalPaymentId)}`,
    {
      method: 'GET',
      headers: authHeaders(adminKey.trim()),
    }
  );

  assert(lookup.status === 200, `lookup expected 200, got ${lookup.status}: ${lookup.text}`);
  assert(
    Array.isArray(lookup.json?.settlements) && lookup.json.settlements.length >= 1,
    `lookup expected settlements array, got ${lookup.text}`
  );

  const account = await httpJson(`${ledgerBaseUrl}/accounts/id/${encodeURIComponent(accountId)}`, {
    method: 'GET',
    headers: authHeaders(adminKey.trim()),
  });

  assert(account.status === 200, `account lookup expected 200, got ${account.status}: ${account.text}`);
  assert(
    account.json?.balances?.available === '0',
    `account expected available=0 after confirm+reversal, got ${account.text}`
  );

  const list = await httpJson(
    `${ledgerBaseUrl}/v1/payments/settlements?provider=${encodeURIComponent(provider)}&limit=1`,
    {
      method: 'GET',
      headers: authHeaders(adminKey.trim()),
    }
  );

  assert(list.status === 200, `list expected 200, got ${list.status}: ${list.text}`);

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        ledger_base_url: ledgerBaseUrl,
        account_id: accountId,
        provider,
        external_payment_id: externalPaymentId,
        confirmed: {
          status: confirmed.status,
          settlement_status: confirmed.json?.settlement?.status,
          event_type: confirmed.json?.event?.event_type,
          settlement_id: confirmed.json?.settlement?.id,
        },
        replay: {
          status: replay.status,
          replayed: replay.json?.idempotency?.replayed,
          deduped: replay.json?.idempotency?.deduped,
        },
        reversal: {
          status: reversal.status,
          settlement_status: reversal.json?.settlement?.status,
          event_type: reversal.json?.event?.event_type,
        },
        account: {
          status: account.status,
          available: account.json?.balances?.available,
        },
        lookup: {
          status: lookup.status,
          count: Array.isArray(lookup.json?.settlements) ? lookup.json.settlements.length : 0,
          top_status: Array.isArray(lookup.json?.settlements)
            ? lookup.json.settlements[0]?.status
            : undefined,
        },
        list: {
          status: list.status,
          count: Array.isArray(list.json?.settlements) ? list.json.settlements.length : 0,
          next_cursor: list.json?.next_cursor,
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
