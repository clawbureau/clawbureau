#!/usr/bin/env node

/**
 * Smoke: clawproxy platform-paid funded-account precheck
 *
 * Validates (staging-first):
 *  - deny-before-fund: platform-paid request fails closed with 402 PAYMENT_REQUIRED
 *  - allow-after-fund: once ledger account is funded, request proceeds and receipt includes funding-check context
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

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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

  return {
    status: res.status,
    text,
    json,
  };
}

function authHeaders(adminKey) {
  return {
    authorization: `Bearer ${adminKey}`,
    'content-type': 'application/json; charset=utf-8',
  };
}

async function issueCst({ scopeBaseUrl, scopeAdminKey, did }) {
  const out = await httpJson(`${scopeBaseUrl}/v1/tokens/issue`, {
    method: 'POST',
    headers: authHeaders(scopeAdminKey),
    body: JSON.stringify({
      sub: did,
      aud: 'clawproxy.com',
      scope: ['proxy:call', 'clawproxy:call'],
      payment_account_did: did,
      ttl_sec: 900,
    }),
  });

  assert(out.status === 200, `issue CST expected 200, got ${out.status}: ${out.text}`);
  assert(isRecord(out.json) && typeof out.json.token === 'string', `issue CST response missing token: ${out.text}`);
  assert(
    typeof out.json.token_scope_hash_b64u === 'string',
    `issue CST response missing token_scope_hash_b64u: ${out.text}`
  );

  return {
    token: out.json.token,
    token_scope_hash_b64u: out.json.token_scope_hash_b64u,
  };
}

async function callProxyPlatformPaid({ proxyBaseUrl, did, cst, model, prompt }) {
  return httpJson(`${proxyBaseUrl}/v1/proxy/openai`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-cst': cst,
      'x-client-did': did,
      'x-payment-account-did': did,
      'x-idempotency-key': `nonce_${crypto.randomUUID()}`,
    },
    body: JSON.stringify({
      model,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = String(args.get('env') || 'staging').toLowerCase();

  const proxyBaseUrl =
    String(args.get('proxy-base-url') || '') ||
    (envName === 'prod' || envName === 'production'
      ? 'https://clawproxy.com'
      : 'https://staging.clawproxy.com');

  const ledgerBaseUrl =
    String(args.get('ledger-base-url') || '') ||
    (envName === 'prod' || envName === 'production'
      ? 'https://clawledger.com'
      : 'https://staging.clawledger.com');

  const scopeBaseUrl =
    String(args.get('scope-base-url') || '') ||
    (envName === 'prod' || envName === 'production'
      ? 'https://clawscope.com'
      : 'https://staging.clawscope.com');

  const model = String(args.get('model') || 'gpt-4o-mini');

  const ledgerAdminKey = process.env.LEDGER_ADMIN_KEY;
  assert(ledgerAdminKey && ledgerAdminKey.trim().length > 0, 'Missing LEDGER_ADMIN_KEY env var');

  const scopeAdminKey = process.env.SCOPE_ADMIN_KEY;
  assert(scopeAdminKey && scopeAdminKey.trim().length > 0, 'Missing SCOPE_ADMIN_KEY env var');

  const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const did = `did:key:smokeproxyfunding${suffix}`;

  const cst = await issueCst({
    scopeBaseUrl,
    scopeAdminKey: scopeAdminKey.trim(),
    did,
  });

  // 1) Deny-before-fund
  const denyBeforeFund = await callProxyPlatformPaid({
    proxyBaseUrl,
    did,
    cst: cst.token,
    model,
    prompt: `smoke deny-before-fund ${suffix}`,
  });

  assert(
    denyBeforeFund.status === 402,
    `deny-before-fund expected 402, got ${denyBeforeFund.status}: ${denyBeforeFund.text}`
  );
  assert(
    denyBeforeFund.json?.error?.code === 'PAYMENT_REQUIRED',
    `deny-before-fund expected error.code=PAYMENT_REQUIRED, got ${denyBeforeFund.text}`
  );

  // 2) Create account + fund it in ledger
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
  assert(typeof accountId === 'string' && accountId.length > 0, 'create account response missing id');

  const fundAmountMinor = '1500';
  const fundSettlement = await httpJson(`${ledgerBaseUrl}/v1/payments/settlements/ingest`, {
    method: 'POST',
    headers: {
      ...authHeaders(ledgerAdminKey.trim()),
      'idempotency-key': `payset:smoke-proxy-funding:${suffix}:1`,
    },
    body: JSON.stringify({
      provider: 'provider_sim',
      external_payment_id: `pay_proxy_funding_${suffix}`,
      direction: 'payin',
      status: 'confirmed',
      account_id: accountId,
      amount_minor: fundAmountMinor,
      currency: 'USD',
      metadata: {
        smoke: true,
        env: envName,
        story: 'MPY-US-004',
      },
    }),
  });

  assert(
    fundSettlement.status === 201 || fundSettlement.status === 200,
    `fund settlement expected 200/201, got ${fundSettlement.status}: ${fundSettlement.text}`
  );

  const accountAfterFund = await httpJson(`${ledgerBaseUrl}/accounts/id/${encodeURIComponent(accountId)}`, {
    method: 'GET',
    headers: authHeaders(ledgerAdminKey.trim()),
  });

  assert(
    accountAfterFund.status === 200,
    `account after fund expected 200, got ${accountAfterFund.status}: ${accountAfterFund.text}`
  );
  assert(
    accountAfterFund.json?.balances?.available === fundAmountMinor,
    `account available expected ${fundAmountMinor}, got ${accountAfterFund.text}`
  );

  // 3) Allow-after-fund
  const allowAfterFund = await callProxyPlatformPaid({
    proxyBaseUrl,
    did,
    cst: cst.token,
    model,
    prompt: `smoke allow-after-fund ${suffix}`,
  });

  assert(
    allowAfterFund.status !== 402,
    `allow-after-fund should not be blocked with 402, got ${allowAfterFund.status}: ${allowAfterFund.text}`
  );

  // Provider may still reject upstream keys; we assert gateway precheck passed by requiring receipt context.
  assert(
    isRecord(allowAfterFund.json) && isRecord(allowAfterFund.json._receipt),
    `allow-after-fund expected _receipt in response, got ${allowAfterFund.text}`
  );

  const payment = allowAfterFund.json._receipt.payment;
  assert(isRecord(payment), `allow-after-fund expected _receipt.payment, got ${allowAfterFund.text}`);
  assert(payment.mode === 'platform', `expected payment.mode=platform, got ${allowAfterFund.text}`);
  assert(payment.paid === true, `expected payment.paid=true, got ${allowAfterFund.text}`);
  assert(
    isRecord(payment.fundingCheck) && payment.fundingCheck.status === 'funded',
    `expected payment.fundingCheck.status=funded, got ${allowAfterFund.text}`
  );

  const envelopeMeta = allowAfterFund.json?._receipt_envelope?.payload?.metadata;
  assert(isRecord(envelopeMeta), `expected _receipt_envelope.payload.metadata, got ${allowAfterFund.text}`);
  assert(
    envelopeMeta.payment_mode === 'platform',
    `expected metadata.payment_mode=platform, got ${allowAfterFund.text}`
  );
  assert(
    isRecord(envelopeMeta.payment_funding_check),
    `expected metadata.payment_funding_check, got ${allowAfterFund.text}`
  );
  assert(
    envelopeMeta.payment_funding_check.account_did === did,
    `expected metadata.payment_funding_check.account_did=${did}, got ${allowAfterFund.text}`
  );

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        proxy_base_url: proxyBaseUrl,
        ledger_base_url: ledgerBaseUrl,
        scope_base_url: scopeBaseUrl,
        did,
        account_id: accountId,
        token_scope_hash_b64u: cst.token_scope_hash_b64u,
        deny_before_fund: {
          status: denyBeforeFund.status,
          code: denyBeforeFund.json?.error?.code,
          message: denyBeforeFund.json?.error?.message,
        },
        funding: {
          settlement_status: fundSettlement.status,
          account_available_after_fund: accountAfterFund.json?.balances?.available,
        },
        allow_after_fund: {
          status: allowAfterFund.status,
          payment_mode: allowAfterFund.json?._receipt?.payment?.mode,
          payment_paid: allowAfterFund.json?._receipt?.payment?.paid,
          funding_status: allowAfterFund.json?._receipt?.payment?.fundingCheck?.status,
          funding_account_id: allowAfterFund.json?._receipt?.payment?.fundingCheck?.accountId,
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
