#!/usr/bin/env node

/**
 * Smoke: clawproxy CST payment_account_did binding enforcement (MPY-US-005)
 *
 * Validates:
 *  - mismatch denial: PAYMENT_ACCOUNT_CLAIM_MISMATCH
 *  - required-claim missing denial: PAYMENT_ACCOUNT_BINDING_REQUIRED (when flag enabled)
 *  - matched+funded allow path with signed binding + funding metadata
 *  - BYOK path unchanged (no claim-binding gate)
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

function normalizeDidLike(input) {
  const trimmed = String(input || '').trim();
  return trimmed.startsWith('did:') ? trimmed : `did:${trimmed}`;
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

async function issueCst({
  scopeBaseUrl,
  scopeAdminKey,
  subDid,
  paymentAccountDid,
}) {
  const payload = {
    sub: subDid,
    aud: 'clawproxy.com',
    scope: ['proxy:call', 'clawproxy:call'],
    ttl_sec: 900,
  };

  if (paymentAccountDid) {
    payload.payment_account_did = paymentAccountDid;
  }

  const out = await httpJson(`${scopeBaseUrl}/v1/tokens/issue`, {
    method: 'POST',
    headers: authHeaders(scopeAdminKey),
    body: JSON.stringify(payload),
  });

  assert(out.status === 200, `issue CST expected 200, got ${out.status}: ${out.text}`);
  assert(isRecord(out.json) && typeof out.json.token === 'string', `issue CST response missing token: ${out.text}`);

  return {
    token: out.json.token,
    token_scope_hash_b64u: out.json.token_scope_hash_b64u,
    payment_account_did: out.json.payment_account_did,
  };
}

async function callProxyPlatformPaid({
  proxyBaseUrl,
  cst,
  clientDid,
  paymentAccountDid,
  model,
  prompt,
}) {
  const headers = {
    'content-type': 'application/json; charset=utf-8',
    'x-cst': cst,
    'x-client-did': clientDid,
    'x-idempotency-key': `nonce_${crypto.randomUUID()}`,
  };

  if (paymentAccountDid) {
    headers['x-payment-account-did'] = paymentAccountDid;
  }

  return httpJson(`${proxyBaseUrl}/v1/proxy/openai`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      model,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
}

async function callProxyByok({ proxyBaseUrl, model, prompt }) {
  return httpJson(`${proxyBaseUrl}/v1/proxy/openai`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-provider-api-key': 'sk-user-byok-invalid-smoke',
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

  const mismatchSubDid = normalizeDidLike(`key:smokebindsub${suffix}`);
  const mismatchClaimDid = normalizeDidLike(`key:smokebindclaim${suffix}`);
  const mismatchHeaderDid = normalizeDidLike(`key:smokebindheader${suffix}`);

  const requiredMissingSubDid = normalizeDidLike(`key:smokebindmissing${suffix}`);

  const fundedDid = normalizeDidLike(`key:smokebindfunded${suffix}`);

  // 1) claim/header mismatch denial
  const mismatchToken = await issueCst({
    scopeBaseUrl,
    scopeAdminKey: scopeAdminKey.trim(),
    subDid: mismatchSubDid,
    paymentAccountDid: mismatchClaimDid,
  });

  const mismatchCall = await callProxyPlatformPaid({
    proxyBaseUrl,
    cst: mismatchToken.token,
    clientDid: mismatchSubDid,
    paymentAccountDid: mismatchHeaderDid,
    model,
    prompt: `smoke claim mismatch ${suffix}`,
  });

  assert(
    mismatchCall.status === 401,
    `claim mismatch expected 401, got ${mismatchCall.status}: ${mismatchCall.text}`
  );
  assert(
    mismatchCall.json?.error?.code === 'PAYMENT_ACCOUNT_CLAIM_MISMATCH',
    `claim mismatch expected PAYMENT_ACCOUNT_CLAIM_MISMATCH, got ${mismatchCall.text}`
  );

  // 2) claim required + missing denial
  const missingClaimToken = await issueCst({
    scopeBaseUrl,
    scopeAdminKey: scopeAdminKey.trim(),
    subDid: requiredMissingSubDid,
  });

  const requiredMissingCall = await callProxyPlatformPaid({
    proxyBaseUrl,
    cst: missingClaimToken.token,
    clientDid: requiredMissingSubDid,
    paymentAccountDid: requiredMissingSubDid,
    model,
    prompt: `smoke claim required missing ${suffix}`,
  });

  assert(
    requiredMissingCall.status === 401,
    `required-claim-missing expected 401, got ${requiredMissingCall.status}: ${requiredMissingCall.text}`
  );
  assert(
    requiredMissingCall.json?.error?.code === 'PAYMENT_ACCOUNT_BINDING_REQUIRED',
    `required-claim-missing expected PAYMENT_ACCOUNT_BINDING_REQUIRED, got ${requiredMissingCall.text}`
  );

  // 3) matched + funded allow path
  const fundedToken = await issueCst({
    scopeBaseUrl,
    scopeAdminKey: scopeAdminKey.trim(),
    subDid: fundedDid,
    paymentAccountDid: fundedDid,
  });

  const denyBeforeFund = await callProxyPlatformPaid({
    proxyBaseUrl,
    cst: fundedToken.token,
    clientDid: fundedDid,
    paymentAccountDid: fundedDid,
    model,
    prompt: `smoke deny before fund ${suffix}`,
  });

  assert(
    denyBeforeFund.status === 402,
    `matched deny-before-fund expected 402, got ${denyBeforeFund.status}: ${denyBeforeFund.text}`
  );
  assert(
    denyBeforeFund.json?.error?.code === 'PAYMENT_REQUIRED',
    `matched deny-before-fund expected PAYMENT_REQUIRED, got ${denyBeforeFund.text}`
  );

  const createAccount = await httpJson(`${ledgerBaseUrl}/accounts`, {
    method: 'POST',
    headers: authHeaders(ledgerAdminKey.trim()),
    body: JSON.stringify({ did: fundedDid }),
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
      'idempotency-key': `payset:smoke-account-binding:${suffix}:1`,
    },
    body: JSON.stringify({
      provider: 'provider_sim',
      external_payment_id: `pay_binding_${suffix}`,
      direction: 'payin',
      status: 'confirmed',
      account_id: accountId,
      amount_minor: fundAmountMinor,
      currency: 'USD',
      metadata: {
        smoke: true,
        env: envName,
        story: 'MPY-US-005',
      },
    }),
  });

  assert(
    fundSettlement.status === 201 || fundSettlement.status === 200,
    `fund settlement expected 200/201, got ${fundSettlement.status}: ${fundSettlement.text}`
  );

  const allowAfterFund = await callProxyPlatformPaid({
    proxyBaseUrl,
    cst: fundedToken.token,
    clientDid: fundedDid,
    paymentAccountDid: fundedDid,
    model,
    prompt: `smoke allow after fund ${suffix}`,
  });

  assert(
    allowAfterFund.status !== 402,
    `allow-after-fund should not be blocked with 402, got ${allowAfterFund.status}: ${allowAfterFund.text}`
  );

  assert(
    isRecord(allowAfterFund.json) && isRecord(allowAfterFund.json._receipt),
    `allow-after-fund expected _receipt in response, got ${allowAfterFund.text}`
  );

  const payment = allowAfterFund.json._receipt.payment;
  assert(isRecord(payment), `allow-after-fund expected _receipt.payment, got ${allowAfterFund.text}`);
  assert(payment.mode === 'platform', `expected payment.mode=platform, got ${allowAfterFund.text}`);
  assert(payment.paid === true, `expected payment.paid=true, got ${allowAfterFund.text}`);
  assert(
    isRecord(payment.accountBinding) && payment.accountBinding.status === 'matched',
    `expected payment.accountBinding.status=matched, got ${allowAfterFund.text}`
  );
  assert(
    payment.accountBinding.claimPresent === true,
    `expected payment.accountBinding.claimPresent=true, got ${allowAfterFund.text}`
  );
  assert(
    payment.accountBinding.claimAccountDid === fundedDid,
    `expected payment.accountBinding.claimAccountDid=${fundedDid}, got ${allowAfterFund.text}`
  );
  assert(
    payment.accountBinding.effectiveAccountDidSource === 'cst-payment-account-did',
    `expected payment.accountBinding.effectiveAccountDidSource=cst-payment-account-did, got ${allowAfterFund.text}`
  );

  const envelopeMeta = allowAfterFund.json?._receipt_envelope?.payload?.metadata;
  assert(isRecord(envelopeMeta), `expected _receipt_envelope.payload.metadata, got ${allowAfterFund.text}`);
  assert(
    envelopeMeta.payment_mode === 'platform',
    `expected metadata.payment_mode=platform, got ${allowAfterFund.text}`
  );
  assert(
    isRecord(envelopeMeta.payment_account_binding),
    `expected metadata.payment_account_binding, got ${allowAfterFund.text}`
  );
  assert(
    envelopeMeta.payment_account_binding.claim_present === true,
    `expected metadata.payment_account_binding.claim_present=true, got ${allowAfterFund.text}`
  );
  assert(
    envelopeMeta.payment_account_binding.claim_account_did === fundedDid,
    `expected metadata.payment_account_binding.claim_account_did=${fundedDid}, got ${allowAfterFund.text}`
  );
  assert(
    envelopeMeta.payment_account_binding.effective_account_did_source === 'cst-payment-account-did',
    `expected metadata.payment_account_binding.effective_account_did_source=cst-payment-account-did, got ${allowAfterFund.text}`
  );

  // 4) BYOK unchanged
  const byokCall = await callProxyByok({
    proxyBaseUrl,
    model,
    prompt: `smoke byok unchanged ${suffix}`,
  });

  assert(
    byokCall.status !== 500,
    `BYOK path should not fail with server error, got ${byokCall.status}: ${byokCall.text}`
  );

  const claimCodes = new Set([
    'PAYMENT_ACCOUNT_BINDING_REQUIRED',
    'PAYMENT_ACCOUNT_CLAIM_MISMATCH',
    'PAYMENT_ACCOUNT_CLAIM_INVALID',
  ]);

  const byokErrorCode = byokCall.json?.error?.code;
  assert(
    !claimCodes.has(byokErrorCode),
    `BYOK path should not return claim-binding error code, got ${byokErrorCode}`
  );

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        proxy_base_url: proxyBaseUrl,
        ledger_base_url: ledgerBaseUrl,
        scope_base_url: scopeBaseUrl,
        mismatch_denial: {
          status: mismatchCall.status,
          code: mismatchCall.json?.error?.code,
        },
        required_claim_missing_denial: {
          status: requiredMissingCall.status,
          code: requiredMissingCall.json?.error?.code,
        },
        matched_funded_allow: {
          status: allowAfterFund.status,
          payment_mode: allowAfterFund.json?._receipt?.payment?.mode,
          account_binding_status: allowAfterFund.json?._receipt?.payment?.accountBinding?.status,
          account_binding_source:
            allowAfterFund.json?._receipt?.payment?.accountBinding?.effectiveAccountDidSource,
          funding_status: allowAfterFund.json?._receipt?.payment?.fundingCheck?.status,
          funding_account_id: allowAfterFund.json?._receipt?.payment?.fundingCheck?.accountId,
        },
        byok: {
          status: byokCall.status,
          code: byokCall.json?.error?.code,
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
