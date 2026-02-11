#!/usr/bin/env node

/**
 * Smoke: machine-payment settlement ingestion in clawledger
 *
 * Validates:
 *  - confirmed payin settlement ingest
 *  - idempotency replay on same key
 *  - reversal path (confirmed -> reversed)
 *  - optional parallel ingest burst (exactly-once side effects)
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

async function ingestSettlement(ledgerBaseUrl, adminKey, idempotencyKey, payload) {
  return httpJson(`${ledgerBaseUrl}/v1/payments/settlements/ingest`, {
    method: 'POST',
    headers: {
      ...authHeaders(adminKey),
      'Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify(payload),
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = String(args.get('env') || 'staging').toLowerCase();

  const parallelBurstRaw = args.get('parallel-burst');
  const parallelBurst = parallelBurstRaw === undefined
    ? 6
    : Number.parseInt(String(parallelBurstRaw), 10);

  assert(
    Number.isFinite(parallelBurst) && parallelBurst >= 0,
    'parallel-burst must be an integer >= 0'
  );

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

  const confirmed = await ingestSettlement(
    ledgerBaseUrl,
    adminKey.trim(),
    idempotencyKey,
    confirmedPayload
  );

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

  const replay = await ingestSettlement(
    ledgerBaseUrl,
    adminKey.trim(),
    idempotencyKey,
    confirmedPayload
  );

  assert(
    replay.status === 200,
    `replay expected 200, got ${replay.status}: ${replay.text}`
  );
  assert(
    replay.json?.idempotency?.replayed === true,
    `replay expected idempotency.replayed=true, got ${replay.text}`
  );

  const reversal = await ingestSettlement(
    ledgerBaseUrl,
    adminKey.trim(),
    `payset:${envName}:${suffix}:2`,
    {
      ...confirmedPayload,
      status: 'reversed',
    }
  );

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

  let burst = null;

  if (parallelBurst >= 2) {
    const burstExternalPaymentId = `pay_burst_${envName}_${suffix}`;
    const burstAmountMinor = '777';

    const burstPayload = {
      provider,
      external_payment_id: burstExternalPaymentId,
      direction: 'payin',
      status: 'confirmed',
      account_id: accountId,
      amount_minor: burstAmountMinor,
      currency: 'USD',
      metadata: {
        smoke: true,
        env: envName,
        burst: true,
      },
    };

    const confirmedBurstResults = await Promise.all(
      Array.from({ length: parallelBurst }, (_, i) =>
        ingestSettlement(
          ledgerBaseUrl,
          adminKey.trim(),
          `payset:${envName}:${suffix}:burst:confirmed:${i + 1}`,
          burstPayload
        )
      )
    );

    for (const [i, result] of confirmedBurstResults.entries()) {
      assert(
        result.status === 200 || result.status === 201,
        `burst confirmed[${i}] expected 200/201, got ${result.status}: ${result.text}`
      );
    }

    const burstLookupAfterConfirm = await httpJson(
      `${ledgerBaseUrl}/v1/payments/settlements/${encodeURIComponent(provider)}/${encodeURIComponent(burstExternalPaymentId)}?direction=payin`,
      {
        method: 'GET',
        headers: authHeaders(adminKey.trim()),
      }
    );

    assert(
      burstLookupAfterConfirm.status === 200,
      `burst confirm lookup expected 200, got ${burstLookupAfterConfirm.status}: ${burstLookupAfterConfirm.text}`
    );

    const accountAfterBurstConfirm = await httpJson(
      `${ledgerBaseUrl}/accounts/id/${encodeURIComponent(accountId)}`,
      {
        method: 'GET',
        headers: authHeaders(adminKey.trim()),
      }
    );

    assert(
      accountAfterBurstConfirm.status === 200,
      `account after burst confirm expected 200, got ${accountAfterBurstConfirm.status}: ${accountAfterBurstConfirm.text}`
    );

    assert(
      accountAfterBurstConfirm.json?.balances?.available === burstAmountMinor,
      `account after burst confirm expected available=${burstAmountMinor}, got ${accountAfterBurstConfirm.text}`
    );

    const reversalBurstResults = await Promise.all(
      Array.from({ length: parallelBurst }, (_, i) =>
        ingestSettlement(
          ledgerBaseUrl,
          adminKey.trim(),
          `payset:${envName}:${suffix}:burst:reversed:${i + 1}`,
          {
            ...burstPayload,
            status: 'reversed',
          }
        )
      )
    );

    for (const [i, result] of reversalBurstResults.entries()) {
      assert(
        result.status === 200 || result.status === 201,
        `burst reversal[${i}] expected 200/201, got ${result.status}: ${result.text}`
      );
    }

    const accountAfterBurstReversal = await httpJson(
      `${ledgerBaseUrl}/accounts/id/${encodeURIComponent(accountId)}`,
      {
        method: 'GET',
        headers: authHeaders(adminKey.trim()),
      }
    );

    assert(
      accountAfterBurstReversal.status === 200,
      `account after burst reversal expected 200, got ${accountAfterBurstReversal.status}: ${accountAfterBurstReversal.text}`
    );

    assert(
      accountAfterBurstReversal.json?.balances?.available === '0',
      `account after burst reversal expected available=0, got ${accountAfterBurstReversal.text}`
    );

    const burstLookupAfterReversal = await httpJson(
      `${ledgerBaseUrl}/v1/payments/settlements/${encodeURIComponent(provider)}/${encodeURIComponent(burstExternalPaymentId)}?direction=payin`,
      {
        method: 'GET',
        headers: authHeaders(adminKey.trim()),
      }
    );

    assert(
      burstLookupAfterReversal.status === 200,
      `burst reversal lookup expected 200, got ${burstLookupAfterReversal.status}: ${burstLookupAfterReversal.text}`
    );

    const confirmedDedupedCount = confirmedBurstResults.filter(
      (x) => x.json?.idempotency?.deduped === true
    ).length;

    const reversalDedupedCount = reversalBurstResults.filter(
      (x) => x.json?.idempotency?.deduped === true
    ).length;

    burst = {
      enabled: true,
      parallel_burst: parallelBurst,
      external_payment_id: burstExternalPaymentId,
      confirmed: {
        total_requests: confirmedBurstResults.length,
        success_2xx: confirmedBurstResults.filter((x) => x.status >= 200 && x.status < 300).length,
        deduped_count: confirmedDedupedCount,
      },
      reversal: {
        total_requests: reversalBurstResults.length,
        success_2xx: reversalBurstResults.filter((x) => x.status >= 200 && x.status < 300).length,
        deduped_count: reversalDedupedCount,
      },
      account_available_after_confirm: accountAfterBurstConfirm.json?.balances?.available,
      account_available_after_reversal: accountAfterBurstReversal.json?.balances?.available,
      lookup_after_reversal_status: Array.isArray(burstLookupAfterReversal.json?.settlements)
        ? burstLookupAfterReversal.json.settlements[0]?.status
        : undefined,
    };
  }

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
        burst,
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
