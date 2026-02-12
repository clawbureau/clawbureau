#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseArgs,
  assert,
  resolveEnvName,
  resolveScopeBaseUrl,
  issueRequesterScopedToken,
  randomDid,
} from './_clawbounties-sim-common.mjs';

function resolveInsureBaseUrl(envName, override) {
  if (override && override.trim().length > 0) return override.trim();
  return envName === 'prod' ? 'https://clawinsure.com' : 'https://staging.clawinsure.com';
}

function resolveInsureAudience(envName, override) {
  if (override && override.trim().length > 0) return override.trim();
  return envName === 'prod' ? 'clawinsure.com' : 'staging.clawinsure.com';
}

function resolveLedgerBaseUrl(envName, override) {
  if (override && override.trim().length > 0) return override.trim();
  return envName === 'prod' ? 'https://clawledger.com' : 'https://staging.clawledger.com';
}

function monthKeyNow() {
  const now = new Date();
  const month = `${now.getUTCMonth() + 1}`.padStart(2, '0');
  return `${now.getUTCFullYear()}-${month}`;
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

async function ensureFundedClaimant({ ledgerBaseUrl, ledgerAdminKey, claimantDid, amountMinor = '5000' }) {
  const accountRes = await requestJson(`${ledgerBaseUrl}/accounts`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${ledgerAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({ did: claimantDid }),
  });

  assert(accountRes.status === 201, `ledger account create failed (${accountRes.status}): ${accountRes.text}`);
  assert(typeof accountRes.json?.id === 'string', 'ledger account id missing');

  const promoMint = await requestJson(`${ledgerBaseUrl}/promo/mint`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${ledgerAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotencyKey: `smoke:clawinsure:promo:${claimantDid}:${crypto.randomUUID()}`,
      accountId: accountRes.json.id,
      amount: amountMinor,
      reason: 'seed claimant account for clawinsure smoke',
    }),
  });

  assert(promoMint.status === 201, `promo mint failed (${promoMint.status}): ${promoMint.text}`);

  const moveToAvailable = await requestJson(`${ledgerBaseUrl}/v1/transfers`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${ledgerAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: `smoke:clawinsure:promo-to-available:${claimantDid}:${crypto.randomUUID()}`,
      currency: 'USD',
      from: {
        account: claimantDid,
        bucket: 'P',
      },
      to: {
        account: claimantDid,
        bucket: 'A',
      },
      amount_minor: amountMinor,
      metadata: {
        source: 'smoke-clawinsure-mvp',
        funding_flow: 'promo_to_available',
      },
    }),
  });

  assert(
    moveToAvailable.status === 200,
    `promo->available transfer failed (${moveToAvailable.status}): ${moveToAvailable.text}`
  );

  return {
    account_id: accountRes.json.id,
    promo_event_id: promoMint.json?.eventId ?? null,
    fund_event_id: moveToAvailable.json?.event_id ?? null,
  };
}

function makeArtifactDir(repoRoot, envName) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.resolve(repoRoot, 'artifacts', 'simulations', 'clawinsure', `${timestamp}-${envName}`);
  return { dir, timestamp };
}

async function writeJson(filePath, payload) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = resolveEnvName(args.get('env'));

  const insureBaseUrl = resolveInsureBaseUrl(envName, args.get('clawinsure-base-url'));
  const ledgerBaseUrl = resolveLedgerBaseUrl(envName, args.get('clawledger-base-url'));
  const scopeBaseUrl = resolveScopeBaseUrl(envName, args.get('scope-base-url'));
  const scopeAdminKey = String(args.get('scope-admin-key') || process.env.SCOPE_ADMIN_KEY || process.env.CLAWSCOPE_ADMIN_KEY || '').trim();
  const insureAdminKey = String(args.get('insure-admin-key') || process.env.INSURE_ADMIN_KEY || '').trim();
  const ledgerAdminKey = String(args.get('ledger-admin-key') || process.env.LEDGER_ADMIN_KEY || '').trim();

  assert(scopeAdminKey.length > 0, 'scope-admin-key / SCOPE_ADMIN_KEY is required');
  assert(insureAdminKey.length > 0, 'INSURE_ADMIN_KEY (or --insure-admin-key) is required');
  assert(ledgerAdminKey.length > 0, 'LEDGER_ADMIN_KEY (or --ledger-admin-key) is required for smoke funding');

  const claimantDid = String(args.get('claimant-did') || '').trim() || randomDid('insure-claimant');
  const claimantScopes = String(args.get('claimant-scopes') || 'clawbounties:bounty:create')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  assert(claimantScopes.length > 0, 'claimant-scopes must not be empty');

  const claimantTokenIssued = await issueRequesterScopedToken({
    scopeBaseUrl,
    scopeAdminKey,
    requesterDid: claimantDid,
    audience: resolveInsureAudience(envName, args.get('claimant-audience')),
    scopes: claimantScopes,
    ttlSec: 900,
    source: 'smoke-clawinsure-mvp',
    paymentAccountDid: claimantDid,
  });

  const claimantToken = claimantTokenIssued.token;

  const steps = [];

  const funding = await ensureFundedClaimant({
    ledgerBaseUrl,
    ledgerAdminKey,
    claimantDid,
    amountMinor: String(args.get('seed-amount-minor') || '5000'),
  });
  steps.push({
    step: 'seed_funding',
    status: 201,
    account_id: funding.account_id,
    promo_event_id: funding.promo_event_id,
    fund_event_id: funding.fund_event_id,
  });

  const quoteRes = await requestJson(`${insureBaseUrl}/v1/quotes`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${claimantToken}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      claimant_did: claimantDid,
      coverage_type: 'provider_bond',
      coverage_amount_minor: '1200',
      term_days: 30,
    }),
  });

  assert(quoteRes.status === 201, `quote failed (${quoteRes.status}): ${quoteRes.text}`);
  assert(typeof quoteRes.json?.quote_id === 'string', 'quote_id missing');
  assert(typeof quoteRes.json?.premium?.premium_minor === 'string', 'premium_minor missing');

  const quoteId = quoteRes.json.quote_id;
  steps.push({ step: 'quote', status: quoteRes.status, quote_id: quoteId, elapsed_ms: quoteRes.elapsed_ms });

  const policyIdempotencyKey = `smoke:clawinsure:policy:${crypto.randomUUID()}`;

  const policyRes = await requestJson(`${insureBaseUrl}/v1/policies`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${claimantToken}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: policyIdempotencyKey,
      quote_id: quoteId,
    }),
  });

  assert(policyRes.status === 201, `policy create failed (${policyRes.status}): ${policyRes.text}`);
  assert(typeof policyRes.json?.policy?.policy_id === 'string', 'policy_id missing');

  const policyId = policyRes.json.policy.policy_id;
  steps.push({ step: 'policy_create', status: policyRes.status, policy_id: policyId, elapsed_ms: policyRes.elapsed_ms });

  const policyReplay = await requestJson(`${insureBaseUrl}/v1/policies`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${claimantToken}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: policyIdempotencyKey,
      quote_id: quoteId,
    }),
  });

  assert(policyReplay.status === 200, `policy replay failed (${policyReplay.status}): ${policyReplay.text}`);
  assert(policyReplay.json?.replay === true, 'policy replay did not return replay=true');
  steps.push({ step: 'policy_replay', status: policyReplay.status, elapsed_ms: policyReplay.elapsed_ms });

  const policyGet = await requestJson(`${insureBaseUrl}/v1/policies/${encodeURIComponent(policyId)}`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${claimantToken}`,
    },
  });

  assert(policyGet.status === 200, `policy get failed (${policyGet.status}): ${policyGet.text}`);
  steps.push({ step: 'policy_get', status: policyGet.status, elapsed_ms: policyGet.elapsed_ms });

  const badClaimRes = await requestJson(`${insureBaseUrl}/v1/claims`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${claimantToken}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: `smoke:clawinsure:bad-claim:${crypto.randomUUID()}`,
      policy_id: policyId,
      reason: 'unresolved trial reference check',
      requested_amount_minor: '100',
      evidence: {
        proof_bundle_hash_b64u: 'hash_bad_claim',
        receipt_refs: ['receipt:bad:1'],
        artifact_refs: ['artifact:bad:1'],
        trial_case_id: `trc_${crypto.randomUUID()}`,
      },
    }),
  });

  assert(badClaimRes.status === 422, `expected unresolved ref 422, got ${badClaimRes.status}: ${badClaimRes.text}`);
  steps.push({ step: 'claim_unresolved_ref', status: badClaimRes.status, elapsed_ms: badClaimRes.elapsed_ms });

  const claimCreateKey = `smoke:clawinsure:claim:${crypto.randomUUID()}`;
  const claimRes = await requestJson(`${insureBaseUrl}/v1/claims`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${claimantToken}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: claimCreateKey,
      policy_id: policyId,
      reason: 'smoke coverage claim',
      requested_amount_minor: '50',
      evidence: {
        proof_bundle_hash_b64u: 'hash_valid_claim',
        receipt_refs: ['receipt:valid:1'],
        artifact_refs: ['artifact:valid:1'],
      },
    }),
  });

  assert(claimRes.status === 201, `claim create failed (${claimRes.status}): ${claimRes.text}`);
  assert(typeof claimRes.json?.claim?.claim_id === 'string', 'claim_id missing');

  const claimId = claimRes.json.claim.claim_id;
  steps.push({ step: 'claim_create', status: claimRes.status, claim_id: claimId, elapsed_ms: claimRes.elapsed_ms });

  const claimReplay = await requestJson(`${insureBaseUrl}/v1/claims`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${claimantToken}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: claimCreateKey,
      policy_id: policyId,
      reason: 'smoke coverage claim',
      requested_amount_minor: '50',
      evidence: {
        proof_bundle_hash_b64u: 'hash_valid_claim',
        receipt_refs: ['receipt:valid:1'],
        artifact_refs: ['artifact:valid:1'],
      },
    }),
  });

  assert(claimReplay.status === 200, `claim replay failed (${claimReplay.status}): ${claimReplay.text}`);
  assert(claimReplay.json?.replay === true, 'claim replay did not return replay=true');
  steps.push({ step: 'claim_replay', status: claimReplay.status, elapsed_ms: claimReplay.elapsed_ms });

  const claimGet = await requestJson(`${insureBaseUrl}/v1/claims/${encodeURIComponent(claimId)}`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${claimantToken}`,
    },
  });

  assert(claimGet.status === 200, `claim get failed (${claimGet.status}): ${claimGet.text}`);
  steps.push({ step: 'claim_get', status: claimGet.status, elapsed_ms: claimGet.elapsed_ms });

  const adjudicateKey = `smoke:clawinsure:adjudicate:${crypto.randomUUID()}`;
  const adjudicateRes = await requestJson(`${insureBaseUrl}/v1/claims/${encodeURIComponent(claimId)}/adjudicate`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${insureAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: adjudicateKey,
      decision: 'approved',
      approved_amount_minor: '40',
      reason: 'smoke adjudication',
    }),
  });

  assert(adjudicateRes.status === 200, `adjudicate failed (${adjudicateRes.status}): ${adjudicateRes.text}`);
  assert(adjudicateRes.json?.claim?.status === 'approved', 'claim status not approved after adjudication');
  steps.push({ step: 'adjudicate', status: adjudicateRes.status, elapsed_ms: adjudicateRes.elapsed_ms });

  const adjudicateReplay = await requestJson(`${insureBaseUrl}/v1/claims/${encodeURIComponent(claimId)}/adjudicate`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${insureAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: adjudicateKey,
      decision: 'approved',
      approved_amount_minor: '40',
      reason: 'smoke adjudication replay',
    }),
  });

  assert(adjudicateReplay.status === 200, `adjudicate replay failed (${adjudicateReplay.status}): ${adjudicateReplay.text}`);
  assert(adjudicateReplay.json?.replay === true, 'adjudicate replay did not return replay=true');
  steps.push({ step: 'adjudicate_replay', status: adjudicateReplay.status, elapsed_ms: adjudicateReplay.elapsed_ms });

  const payoutKey = `smoke:clawinsure:payout:${crypto.randomUUID()}`;
  const payoutRes = await requestJson(`${insureBaseUrl}/v1/claims/${encodeURIComponent(claimId)}/payout`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${insureAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: payoutKey,
    }),
  });

  assert(payoutRes.status === 200, `payout failed (${payoutRes.status}): ${payoutRes.text}`);
  assert(payoutRes.json?.claim?.status === 'paid', 'claim status not paid after payout');
  assert(typeof payoutRes.json?.payout?.payout_transfer_event_id === 'string', 'payout transfer ref missing');
  steps.push({ step: 'payout', status: payoutRes.status, elapsed_ms: payoutRes.elapsed_ms });

  const payoutReplay = await requestJson(`${insureBaseUrl}/v1/claims/${encodeURIComponent(claimId)}/payout`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${insureAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: payoutKey,
    }),
  });

  assert(payoutReplay.status === 200, `payout replay failed (${payoutReplay.status}): ${payoutReplay.text}`);
  assert(payoutReplay.json?.replay === true, 'payout replay did not return replay=true');
  steps.push({ step: 'payout_replay', status: payoutReplay.status, elapsed_ms: payoutReplay.elapsed_ms });

  const riskRes = await requestJson(`${insureBaseUrl}/v1/risk/${claimantDid}`, {
    method: 'GET',
  });

  assert(riskRes.status === 200, `risk endpoint failed (${riskRes.status}): ${riskRes.text}`);
  assert(typeof riskRes.json?.risk_score === 'number', 'risk score missing');
  steps.push({ step: 'risk', status: riskRes.status, elapsed_ms: riskRes.elapsed_ms });

  const reportRes = await requestJson(`${insureBaseUrl}/v1/reports/claims?did=${encodeURIComponent(claimantDid)}&limit=20`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${insureAdminKey}`,
    },
  });

  assert(reportRes.status === 200, `claims report failed (${reportRes.status}): ${reportRes.text}`);
  assert(typeof reportRes.json?.totals?.total_claims === 'number', 'report totals.total_claims missing');
  steps.push({ step: 'claims_report', status: reportRes.status, elapsed_ms: reportRes.elapsed_ms });

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, '../..');
  const artifact = makeArtifactDir(repoRoot, envName);
  await fs.mkdir(artifact.dir, { recursive: true });

  const summary = {
    ok: true,
    env: envName,
    generated_at: new Date().toISOString(),
    base_urls: {
      clawinsure: insureBaseUrl,
      clawledger: ledgerBaseUrl,
    },
    claimant: {
      did: claimantDid,
      token_hash: claimantTokenIssued.token_hash,
      token_kid: claimantTokenIssued.kid,
      scope: claimantScopes,
      audience: resolveInsureAudience(envName, args.get('claimant-audience')),
    },
    quote_id: quoteId,
    policy_id: policyId,
    claim_id: claimId,
    steps,
    assertions: {
      quote_created: quoteRes.status === 201,
      policy_idempotent: policyReplay.status === 200 && policyReplay.json?.replay === true,
      unresolved_ref_fail_closed: badClaimRes.status === 422,
      claim_idempotent: claimReplay.status === 200 && claimReplay.json?.replay === true,
      adjudication_idempotent: adjudicateReplay.status === 200 && adjudicateReplay.json?.replay === true,
      payout_idempotent: payoutReplay.status === 200 && payoutReplay.json?.replay === true,
      payout_transfer_recorded: typeof payoutRes.json?.payout?.payout_transfer_event_id === 'string',
    },
  };

  await writeJson(path.resolve(artifact.dir, 'smoke.json'), summary);

  console.log(
    JSON.stringify(
      {
        ...summary,
        artifact_dir: artifact.dir,
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(JSON.stringify({ ok: false, error: message }, null, 2));
  process.exit(1);
});
