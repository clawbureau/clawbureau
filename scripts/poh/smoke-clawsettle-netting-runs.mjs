#!/usr/bin/env node

/**
 * Smoke: clawsettle netting runs (MPY-US-011 / CST-US-002)
 *
 * Validates:
 * - POST /v1/netting/runs (admin, idempotent execute)
 * - GET /v1/netting/runs/:id
 * - GET /v1/netting/runs/:id/report?format=json|csv
 * - exact-once replay semantics (no duplicate money effects)
 * - deterministic report hash parity across JSON/CSV
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

function parseMinor(value, label) {
  if (typeof value !== 'string' || !/^[0-9]+$/.test(value)) {
    throw new Error(`ASSERT_FAILED: invalid ${label}: ${String(value)}`);
  }
  return BigInt(value);
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

async function getClearingAvailable(ledgerBaseUrl, ledgerAdminKey, domain) {
  const response = await httpJson(`${ledgerBaseUrl}/clearing/accounts/domain/${encodeURIComponent(domain)}`, {
    method: 'GET',
    headers: authHeaders(ledgerAdminKey),
  });

  if (response.status === 404) {
    return 0n;
  }

  assert(response.status === 200, `clearing account lookup expected 200/404, got ${response.status}: ${response.text}`);
  return parseMinor(response.json?.balances?.available, `${domain}.balances.available`);
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

  const settleAdminKey = process.env.SETTLE_ADMIN_KEY;
  assert(settleAdminKey && settleAdminKey.trim().length > 0, 'Missing SETTLE_ADMIN_KEY env var');

  const stripeSecretRaw = process.env.STRIPE_WEBHOOK_SIGNING_SECRET?.trim() || '';
  const ledgerAdminKeyRaw = process.env.LEDGER_ADMIN_KEY?.trim() || '';
  const fullBootstrap = stripeSecretRaw.length > 0 && ledgerAdminKeyRaw.length > 0;

  const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const expectedLivemode = envName === 'prod' || envName === 'production';
  const nowSec = Math.floor(Date.now() / 1000);

  if (!fullBootstrap) {
    const runCreate = await httpJson(
      `${clawsettleBaseUrl}/v1/netting/runs`,
      {
        method: 'POST',
        headers: {
          ...authHeaders(settleAdminKey.trim()),
          'idempotency-key': `smoke:netting:existing:${suffix}`,
        },
        body: JSON.stringify({
          currency: 'USD',
          limit: 500,
        }),
      },
      clawsettleResolveIp
    );

    assert(runCreate.status === 201, `existing-mode netting run expected 201, got ${runCreate.status}: ${runCreate.text}`);
    assert(runCreate.json?.ok === true, `existing-mode run expected ok=true, got ${runCreate.text}`);
    assert(runCreate.json?.run?.status === 'applied', `existing-mode run expected applied, got ${runCreate.text}`);

    const runId = runCreate.json?.run?.id;
    assert(typeof runId === 'string' && runId.length > 0, `existing-mode run missing id: ${runCreate.text}`);

    const runReplay = await httpJson(
      `${clawsettleBaseUrl}/v1/netting/runs`,
      {
        method: 'POST',
        headers: {
          ...authHeaders(settleAdminKey.trim()),
          'idempotency-key': `smoke:netting:existing:${suffix}`,
        },
        body: JSON.stringify({
          currency: 'USD',
          limit: 500,
        }),
      },
      clawsettleResolveIp
    );

    assert(runReplay.status === 200, `existing-mode netting replay expected 200, got ${runReplay.status}: ${runReplay.text}`);
    assert(runReplay.json?.deduped === true, `existing-mode replay expected deduped=true, got ${runReplay.text}`);

    const reportJson = await httpJson(
      `${clawsettleBaseUrl}/v1/netting/runs/${encodeURIComponent(runId)}/report?format=json`,
      {
        method: 'GET',
        headers: authHeaders(settleAdminKey.trim()),
      },
      clawsettleResolveIp
    );

    assert(reportJson.status === 200, `existing-mode report json expected 200, got ${reportJson.status}: ${reportJson.text}`);

    const reportCsv = await httpJson(
      `${clawsettleBaseUrl}/v1/netting/runs/${encodeURIComponent(runId)}/report?format=csv`,
      {
        method: 'GET',
        headers: authHeaders(settleAdminKey.trim()),
      },
      clawsettleResolveIp
    );

    assert(reportCsv.status === 200, `existing-mode report csv expected 200, got ${reportCsv.status}: ${reportCsv.text}`);
    const csvHash = reportCsv.headers['x-clawsettle-report-sha256'];
    assert(typeof csvHash === 'string', 'existing-mode csv hash header missing');
    assert(csvHash === reportJson.json?.artifact_sha256, 'existing-mode csv/json report hash mismatch');

    const runNoop = await httpJson(
      `${clawsettleBaseUrl}/v1/netting/runs`,
      {
        method: 'POST',
        headers: {
          ...authHeaders(settleAdminKey.trim()),
          'idempotency-key': `smoke:netting:existing-noop:${suffix}`,
        },
        body: JSON.stringify({
          currency: 'USD',
          limit: 500,
        }),
      },
      clawsettleResolveIp
    );

    assert(runNoop.status === 201, `existing-mode noop run expected 201, got ${runNoop.status}: ${runNoop.text}`);
    assert(runNoop.json?.run?.candidate_count === 0, `existing-mode noop candidate_count expected 0, got ${runNoop.text}`);

    console.log(
      JSON.stringify(
        {
          ok: true,
          mode: 'existing-paid-payouts',
          env: envName,
          clawsettle_base_url: clawsettleBaseUrl,
          clawsettle_resolve_ip: clawsettleResolveIp,
          run_id: runId,
          run_status: runCreate.json?.run?.status,
          run_candidate_count: runCreate.json?.run?.candidate_count,
          run_total_amount_minor: runCreate.json?.run?.total_amount_minor,
          replay_deduped: runReplay.json?.deduped,
          report_artifact_sha256: reportJson.json?.artifact_sha256,
          csv_header_hash: csvHash,
          noop_candidate_count: runNoop.json?.run?.candidate_count,
          note: 'Executed existing-data mode because STRIPE_WEBHOOK_SIGNING_SECRET and/or LEDGER_ADMIN_KEY were not set locally.',
        },
        null,
        2
      )
    );

    return;
  }

  const stripeSecret = stripeSecretRaw;
  const ledgerAdminKey = ledgerAdminKeyRaw;
  const did = `did:key:smokenetting${suffix}`;

  const createAccount = await httpJson(`${ledgerBaseUrl}/accounts`, {
    method: 'POST',
    headers: authHeaders(ledgerAdminKey.trim()),
    body: JSON.stringify({ did }),
  });

  assert(createAccount.status === 201, `create account expected 201, got ${createAccount.status}: ${createAccount.text}`);
  const accountId = createAccount.json?.id;
  assert(typeof accountId === 'string' && accountId.length > 0, 'missing account id');

  const fundIngest = await httpJson(
    `${ledgerBaseUrl}/v1/payments/settlements/ingest`,
    {
      method: 'POST',
      headers: {
        ...authHeaders(ledgerAdminKey.trim()),
        'idempotency-key': `smoke:netting:fund:${suffix}`,
      },
      body: JSON.stringify({
        provider: 'stripe',
        external_payment_id: `pi_netting_fund_${suffix}`,
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

  assert(onboard.status === 201 || onboard.status === 200, `onboard expected 200/201, got ${onboard.status}: ${onboard.text}`);

  const payout1 = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'idempotency-key': `smoke:netting:payout1:${suffix}`,
      },
      body: JSON.stringify({
        account_id: accountId,
        amount_minor: '1200',
        currency: 'USD',
        metadata: { smoke_case: 'netting' },
      }),
    },
    clawsettleResolveIp
  );

  assert(payout1.status === 201, `payout1 create expected 201, got ${payout1.status}: ${payout1.text}`);
  assert(payout1.json?.payout?.status === 'submitted', `payout1 expected submitted, got ${payout1.text}`);

  const payout2 = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'idempotency-key': `smoke:netting:payout2:${suffix}`,
      },
      body: JSON.stringify({
        account_id: accountId,
        amount_minor: '800',
        currency: 'USD',
        metadata: { smoke_case: 'netting' },
      }),
    },
    clawsettleResolveIp
  );

  assert(payout2.status === 201, `payout2 create expected 201, got ${payout2.status}: ${payout2.text}`);
  assert(payout2.json?.payout?.status === 'submitted', `payout2 expected submitted, got ${payout2.text}`);

  const payoutOne = payout1.json?.payout;
  const payoutTwo = payout2.json?.payout;

  assert(typeof payoutOne?.id === 'string', `payout1 missing id: ${payout1.text}`);
  assert(typeof payoutOne?.external_payout_id === 'string', `payout1 missing external id: ${payout1.text}`);
  assert(typeof payoutTwo?.id === 'string', `payout2 missing id: ${payout2.text}`);
  assert(typeof payoutTwo?.external_payout_id === 'string', `payout2 missing external id: ${payout2.text}`);

  const paidWebhook1 = await postStripeWebhook({
    clawsettleBaseUrl,
    clawsettleResolveIp,
    stripeSecret: stripeSecret.trim(),
    nowSec,
    event: {
      id: `evt_smoke_netting_paid_1_${suffix}`,
      type: 'payout.paid',
      created: nowSec,
      livemode: expectedLivemode,
      data: {
        object: {
          id: payoutOne.external_payout_id,
          amount: 1200,
          currency: 'usd',
          created: nowSec,
          metadata: { account_id: accountId },
        },
      },
    },
  });

  assert(paidWebhook1.status === 200, `payout1 paid webhook expected 200, got ${paidWebhook1.status}: ${paidWebhook1.text}`);

  const paidWebhook2 = await postStripeWebhook({
    clawsettleBaseUrl,
    clawsettleResolveIp,
    stripeSecret: stripeSecret.trim(),
    nowSec,
    event: {
      id: `evt_smoke_netting_paid_2_${suffix}`,
      type: 'payout.paid',
      created: nowSec,
      livemode: expectedLivemode,
      data: {
        object: {
          id: payoutTwo.external_payout_id,
          amount: 800,
          currency: 'usd',
          created: nowSec,
          metadata: { account_id: accountId },
        },
      },
    },
  });

  assert(paidWebhook2.status === 200, `payout2 paid webhook expected 200, got ${paidWebhook2.status}: ${paidWebhook2.text}`);

  const payoutOneStatus = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts/${encodeURIComponent(payoutOne.id)}`,
    {
      method: 'GET',
      headers: { 'content-type': 'application/json; charset=utf-8' },
    },
    clawsettleResolveIp
  );

  const payoutTwoStatus = await httpJson(
    `${clawsettleBaseUrl}/v1/payouts/${encodeURIComponent(payoutTwo.id)}`,
    {
      method: 'GET',
      headers: { 'content-type': 'application/json; charset=utf-8' },
    },
    clawsettleResolveIp
  );

  assert(payoutOneStatus.status === 200, `payout1 status expected 200, got ${payoutOneStatus.status}: ${payoutOneStatus.text}`);
  assert(payoutTwoStatus.status === 200, `payout2 status expected 200, got ${payoutTwoStatus.status}: ${payoutTwoStatus.text}`);
  assert(payoutOneStatus.json?.payout?.status === 'paid', `payout1 expected paid, got ${payoutOneStatus.text}`);
  assert(payoutTwoStatus.json?.payout?.status === 'paid', `payout2 expected paid, got ${payoutTwoStatus.text}`);

  const sourceDomain = 'clawsettle.payouts';
  const targetDomain = 'clawsettle.netting';

  const sourceBefore = await getClearingAvailable(ledgerBaseUrl, ledgerAdminKey.trim(), sourceDomain);
  const targetBefore = await getClearingAvailable(ledgerBaseUrl, ledgerAdminKey.trim(), targetDomain);

  const runCreate = await httpJson(
    `${clawsettleBaseUrl}/v1/netting/runs`,
    {
      method: 'POST',
      headers: {
        ...authHeaders(settleAdminKey.trim()),
        'idempotency-key': `smoke:netting:run:${suffix}`,
      },
      body: JSON.stringify({
        currency: 'USD',
        limit: 50,
      }),
    },
    clawsettleResolveIp
  );

  assert(runCreate.status === 201, `netting run create expected 201, got ${runCreate.status}: ${runCreate.text}`);
  assert(runCreate.json?.ok === true, `netting run create expected ok=true, got ${runCreate.text}`);
  assert(runCreate.json?.run?.status === 'applied', `netting run create expected applied, got ${runCreate.text}`);
  assert(runCreate.json?.run?.candidate_count === 2, `netting run candidate_count expected 2, got ${runCreate.text}`);

  const runId = runCreate.json?.run?.id;
  assert(typeof runId === 'string' && runId.length > 0, `netting run missing id: ${runCreate.text}`);

  const nettedAmount = parseMinor(runCreate.json?.run?.total_amount_minor, 'run.total_amount_minor');
  assert(nettedAmount === 2000n, `netted amount expected 2000, got ${String(nettedAmount)}`);

  const runReplay = await httpJson(
    `${clawsettleBaseUrl}/v1/netting/runs`,
    {
      method: 'POST',
      headers: {
        ...authHeaders(settleAdminKey.trim()),
        'idempotency-key': `smoke:netting:run:${suffix}`,
      },
      body: JSON.stringify({
        currency: 'USD',
        limit: 50,
      }),
    },
    clawsettleResolveIp
  );

  assert(runReplay.status === 200, `netting run replay expected 200, got ${runReplay.status}: ${runReplay.text}`);
  assert(runReplay.json?.deduped === true, `netting run replay expected deduped=true, got ${runReplay.text}`);
  assert(runReplay.json?.run?.id === runId, `netting replay run id mismatch: ${runReplay.text}`);

  const runStatus = await httpJson(
    `${clawsettleBaseUrl}/v1/netting/runs/${encodeURIComponent(runId)}`,
    {
      method: 'GET',
      headers: authHeaders(settleAdminKey.trim()),
    },
    clawsettleResolveIp
  );

  assert(runStatus.status === 200, `netting run status expected 200, got ${runStatus.status}: ${runStatus.text}`);
  assert(runStatus.json?.run?.status === 'applied', `netting run status expected applied, got ${runStatus.text}`);

  const reportJson = await httpJson(
    `${clawsettleBaseUrl}/v1/netting/runs/${encodeURIComponent(runId)}/report?format=json`,
    {
      method: 'GET',
      headers: authHeaders(settleAdminKey.trim()),
    },
    clawsettleResolveIp
  );

  assert(reportJson.status === 200, `netting report json expected 200, got ${reportJson.status}: ${reportJson.text}`);
  assert(typeof reportJson.json?.artifact_sha256 === 'string', `netting report json missing artifact hash: ${reportJson.text}`);

  const reportCsv = await httpJson(
    `${clawsettleBaseUrl}/v1/netting/runs/${encodeURIComponent(runId)}/report?format=csv`,
    {
      method: 'GET',
      headers: authHeaders(settleAdminKey.trim()),
    },
    clawsettleResolveIp
  );

  assert(reportCsv.status === 200, `netting report csv expected 200, got ${reportCsv.status}: ${reportCsv.text}`);
  const csvHash = reportCsv.headers['x-clawsettle-report-sha256'];
  assert(typeof csvHash === 'string', 'netting report csv missing x-clawsettle-report-sha256 header');
  assert(csvHash === reportJson.json?.artifact_sha256, 'netting report csv/json hash mismatch');

  const sourceAfter = await getClearingAvailable(ledgerBaseUrl, ledgerAdminKey.trim(), sourceDomain);
  const targetAfter = await getClearingAvailable(ledgerBaseUrl, ledgerAdminKey.trim(), targetDomain);

  assert(sourceAfter === sourceBefore - nettedAmount, `source clearing mismatch: before=${sourceBefore} after=${sourceAfter} netted=${nettedAmount}`);
  assert(targetAfter === targetBefore + nettedAmount, `target clearing mismatch: before=${targetBefore} after=${targetAfter} netted=${nettedAmount}`);

  const runNoop = await httpJson(
    `${clawsettleBaseUrl}/v1/netting/runs`,
    {
      method: 'POST',
      headers: {
        ...authHeaders(settleAdminKey.trim()),
        'idempotency-key': `smoke:netting:run-noop:${suffix}`,
      },
      body: JSON.stringify({
        currency: 'USD',
        limit: 50,
      }),
    },
    clawsettleResolveIp
  );

  assert(runNoop.status === 201, `noop netting run expected 201, got ${runNoop.status}: ${runNoop.text}`);
  assert(runNoop.json?.run?.candidate_count === 0, `noop netting run candidate_count expected 0, got ${runNoop.text}`);
  assert(runNoop.json?.run?.total_amount_minor === '0', `noop netting run total expected 0, got ${runNoop.text}`);

  const sourceAfterNoop = await getClearingAvailable(ledgerBaseUrl, ledgerAdminKey.trim(), sourceDomain);
  const targetAfterNoop = await getClearingAvailable(ledgerBaseUrl, ledgerAdminKey.trim(), targetDomain);

  assert(sourceAfterNoop === sourceAfter, `source clearing changed after noop run: before=${sourceAfter} after=${sourceAfterNoop}`);
  assert(targetAfterNoop === targetAfter, `target clearing changed after noop run: before=${targetAfter} after=${targetAfterNoop}`);

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        clawsettle_base_url: clawsettleBaseUrl,
        clawsettle_resolve_ip: clawsettleResolveIp,
        ledger_base_url: ledgerBaseUrl,
        account_id: accountId,
        payouts: [
          {
            payout_id: payoutOne.id,
            external_payout_id: payoutOne.external_payout_id,
            status: payoutOneStatus.json?.payout?.status,
          },
          {
            payout_id: payoutTwo.id,
            external_payout_id: payoutTwo.external_payout_id,
            status: payoutTwoStatus.json?.payout?.status,
          },
        ],
        netting_run: {
          run_id: runId,
          status: runStatus.json?.run?.status,
          candidate_count: runStatus.json?.run?.candidate_count,
          applied_count: runStatus.json?.run?.applied_count,
          failed_count: runStatus.json?.run?.failed_count,
          total_amount_minor: runStatus.json?.run?.total_amount_minor,
          replay_deduped: runReplay.json?.deduped,
        },
        report: {
          artifact_sha256: reportJson.json?.artifact_sha256,
          csv_header_hash: csvHash,
          entries: reportJson.json?.entries?.length,
        },
        balances: {
          source_domain: sourceDomain,
          target_domain: targetDomain,
          before: {
            source_available: sourceBefore.toString(),
            target_available: targetBefore.toString(),
          },
          after: {
            source_available: sourceAfter.toString(),
            target_available: targetAfter.toString(),
          },
          after_noop: {
            source_available: sourceAfterNoop.toString(),
            target_available: targetAfterNoop.toString(),
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
