#!/usr/bin/env node

/**
 * Smoke: clawcuts monetization control plane + deterministic apply + reporting.
 *
 * Validates CCU-US-001/002/003/004/006 end-to-end against live services:
 * - policy version create + activate + audit history (JSON + CSV)
 * - fee simulation with discount + referral split metadata
 * - escrow release uses stored snapshot + emits fee/referral ledger transfers
 * - clawcuts apply idempotency replay safety
 * - monthly revenue report JSON + CSV segmented by product/policy/version
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

function assert(condition, message) {
  if (!condition) {
    throw new Error(`ASSERT_FAILED: ${message}`);
  }
}

async function httpJson(url, init = {}) {
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

function monthNowUtc() {
  const now = new Date();
  const y = now.getUTCFullYear().toString().padStart(4, '0');
  const m = (now.getUTCMonth() + 1).toString().padStart(2, '0');
  return `${y}-${m}`;
}

function randomDid(prefix) {
  return `did:key:${prefix}${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
}

function adminHeaders(adminKey) {
  return {
    'content-type': 'application/json; charset=utf-8',
    authorization: `Bearer ${adminKey}`,
  };
}

function ledgerHeaders(adminKey, idempotencyKey) {
  return {
    'content-type': 'application/json; charset=utf-8',
    'x-admin-key': adminKey,
    ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {}),
  };
}

async function createLedgerAccount(ledgerBaseUrl, ledgerAdminKey, did) {
  const res = await httpJson(`${ledgerBaseUrl}/accounts`, {
    method: 'POST',
    headers: ledgerHeaders(ledgerAdminKey),
    body: JSON.stringify({ did }),
  });

  assert(res.status === 201, `create account expected 201, got ${res.status}: ${res.text}`);
  const accountId = res.json?.id;
  assert(typeof accountId === 'string' && accountId.length > 0, `missing account id: ${res.text}`);
  return { did, account_id: accountId };
}

async function fundLedgerAccount(ledgerBaseUrl, ledgerAdminKey, accountId, suffix, amountMinor) {
  const res = await httpJson(`${ledgerBaseUrl}/v1/payments/settlements/ingest`, {
    method: 'POST',
    headers: ledgerHeaders(ledgerAdminKey, `smoke:clawcuts:fund:${suffix}`),
    body: JSON.stringify({
      provider: 'stripe',
      external_payment_id: `pi_smoke_clawcuts_${suffix}`,
      direction: 'payin',
      status: 'confirmed',
      account_id: accountId,
      amount_minor: amountMinor,
      currency: 'USD',
      metadata: { smoke: true, source: 'clawcuts-monetization' },
    }),
  });

  assert(res.status === 201, `fund ingest expected 201, got ${res.status}: ${res.text}`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = String(args.get('env') || 'staging').toLowerCase();
  const isProd = envName === 'prod' || envName === 'production';

  const clawcutsBaseUrl =
    String(args.get('clawcuts-base-url') || '') || (isProd ? 'https://clawcuts.com' : 'https://staging.clawcuts.com');
  const escrowBaseUrl =
    String(args.get('escrow-base-url') || '') || (isProd ? 'https://clawescrow.com' : 'https://staging.clawescrow.com');
  const ledgerBaseUrl =
    String(args.get('ledger-base-url') || '') || (isProd ? 'https://clawledger.com' : 'https://staging.clawledger.com');

  const cutsAdminKey = process.env.CUTS_ADMIN_KEY?.trim();
  const escrowAdminKey = process.env.ESCROW_ADMIN_KEY?.trim();
  const ledgerAdminKey = process.env.LEDGER_ADMIN_KEY?.trim();

  assert(cutsAdminKey, 'Missing CUTS_ADMIN_KEY');
  assert(escrowAdminKey, 'Missing ESCROW_ADMIN_KEY');

  const actor = String(args.get('actor') || process.env.CUTS_POLICY_ACTOR || 'did:key:ops-smoke');
  const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;

  const defaultBuyerDid = isProd ? 'did:key:clawea-recon-smoke-did_mli3pv88_9e03d699' : 'did:key:zsimrequesterbatch0001';
  const defaultWorkerDid = isProd
    ? 'did:key:z6MkrSgJD4hSdkFapKNP4mLzYBGBkGQQJ4hTc9msMoE6NHjL'
    : 'did:key:z6MkivEXPpgFKDiRMUZfp3mKJzqZBRKXG3GKrsFWR1f9Qc3N';

  const bootstrapLedger = String(args.get('bootstrap-ledger') || '').toLowerCase() === 'true';

  let buyerDid = String(args.get('buyer-did') || defaultBuyerDid);
  let workerDid = String(args.get('worker-did') || defaultWorkerDid);

  // 1) Create + activate a new bounties policy version with referral splits enabled.
  const createPolicy = await httpJson(`${clawcutsBaseUrl}/v1/policies/versions`, {
    method: 'POST',
    headers: adminHeaders(cutsAdminKey),
    body: JSON.stringify({
      product: 'clawbounties',
      policy_id: 'bounties_v1',
      actor,
      activate: true,
      notes: `ccu-ops-001 smoke ${suffix}`,
      discount: { enabled: true, max_bps: 2000 },
      rules: [
        {
          is_code_bounty: 'true',
          closure_type: 'test',
          buyer_fee_bps: 500,
          worker_fee_bps: 0,
          min_fee_minor: '0',
          referral_bps: 1500,
          referral_min_minor: '0',
        },
        {
          is_code_bounty: '*',
          closure_type: 'requester',
          buyer_fee_bps: 750,
          worker_fee_bps: 0,
          min_fee_minor: '25',
          referral_bps: 3000,
          referral_min_minor: '1',
        },
        {
          is_code_bounty: '*',
          closure_type: 'quorum',
          buyer_fee_bps: 750,
          worker_fee_bps: 0,
          min_fee_minor: '25',
          referral_bps: 3000,
          referral_min_minor: '1',
        },
      ],
    }),
  });

  assert(createPolicy.status === 201, `create policy expected 201, got ${createPolicy.status}: ${createPolicy.text}`);

  const policyVersion = createPolicy.json?.policy?.version;
  const policyHash = createPolicy.json?.policy?.hash_b64u;
  assert(typeof policyVersion === 'string' && policyVersion.length > 0, `missing policy version: ${createPolicy.text}`);
  assert(typeof policyHash === 'string' && policyHash.length > 0, `missing policy hash: ${createPolicy.text}`);

  // 2) Audit history API + CSV evidence.
  const historyJson = await httpJson(`${clawcutsBaseUrl}/v1/policies/clawbounties/bounties_v1/history`);
  assert(historyJson.status === 200, `history json expected 200, got ${historyJson.status}: ${historyJson.text}`);

  const auditRows = Array.isArray(historyJson.json?.audit) ? historyJson.json.audit : [];
  const sawActor = auditRows.some((row) => row?.actor === actor);
  assert(sawActor, `history audit missing actor ${actor}`);

  const historyCsv = await httpJson(`${clawcutsBaseUrl}/v1/policies/clawbounties/bounties_v1/history.csv`);
  assert(historyCsv.status === 200, `history csv expected 200, got ${historyCsv.status}: ${historyCsv.text}`);
  assert(historyCsv.text.includes(actor), 'history csv missing actor evidence');

  // 3) Simulate fee quote with referrer + discount and pinned policy version.
  let referrerDid = String(args.get('referrer-did') || workerDid);

  if (bootstrapLedger) {
    assert(ledgerAdminKey, 'Missing LEDGER_ADMIN_KEY (required when --bootstrap-ledger=true)');

    const buyer = await createLedgerAccount(ledgerBaseUrl, ledgerAdminKey, randomDid('buyer'));
    const worker = await createLedgerAccount(ledgerBaseUrl, ledgerAdminKey, randomDid('worker'));
    buyerDid = buyer.did;
    workerDid = worker.did;

    if (!args.get('referrer-did')) {
      referrerDid = worker.did;
    } else if (referrerDid !== worker.did) {
      await createLedgerAccount(ledgerBaseUrl, ledgerAdminKey, referrerDid);
    }

    await fundLedgerAccount(ledgerBaseUrl, ledgerAdminKey, buyer.account_id, suffix, '50000');
  }

  const simulate = await httpJson(`${clawcutsBaseUrl}/v1/fees/simulate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      product: 'clawbounties',
      policy_id: 'bounties_v1',
      policy_version: Number(policyVersion),
      amount_minor: '10000',
      currency: 'USD',
      params: {
        is_code_bounty: false,
        closure_type: 'requester',
        referrer_did: referrerDid,
        referral_code: `SMOKE-${suffix}`,
        discount_bps: 1000,
      },
    }),
  });

  assert(simulate.status === 200, `simulate expected 200, got ${simulate.status}: ${simulate.text}`);
  assert(simulate.json?.policy?.version === policyVersion, `simulate policy version mismatch: ${simulate.text}`);
  assert(simulate.json?.policy?.hash_b64u === policyHash, `simulate policy hash mismatch: ${simulate.text}`);

  const quote = simulate.json?.quote;
  assert(quote && Array.isArray(quote.fees), `simulate quote missing fees: ${simulate.text}`);
  assert(typeof quote.buyer_total_minor === 'string' && typeof quote.worker_net_minor === 'string', 'simulate totals missing');

  const referralMinor = BigInt(quote.referral_payout_minor ?? '0');
  assert(referralMinor > 0n, `expected referral payout > 0, got ${simulate.text}`);

  // 4) Escrow hold + assign + release.
  const createEscrow = await httpJson(`${escrowBaseUrl}/v1/escrows`, {
    method: 'POST',
    headers: adminHeaders(escrowAdminKey),
    body: JSON.stringify({
      idempotency_key: `smoke:clawcuts:create:${suffix}`,
      buyer_did: buyerDid,
      worker_did: null,
      currency: 'USD',
      amount_minor: '10000',
      fee_quote: {
        policy_id: 'bounties_v1',
        policy_version: policyVersion,
        policy_hash_b64u: policyHash,
        buyer_total_minor: quote.buyer_total_minor,
        worker_net_minor: quote.worker_net_minor,
        fees: quote.fees,
      },
      metadata: {
        smoke: true,
        policy_version: policyVersion,
        referrer_did: referrerDid,
      },
    }),
  });

  assert(createEscrow.status === 201, `create escrow expected 201, got ${createEscrow.status}: ${createEscrow.text}`);
  const escrowId = createEscrow.json?.escrow_id;
  assert(typeof escrowId === 'string' && escrowId.length > 0, `missing escrow id: ${createEscrow.text}`);

  const assignEscrow = await httpJson(`${escrowBaseUrl}/v1/escrows/${escrowId}/assign`, {
    method: 'POST',
    headers: adminHeaders(escrowAdminKey),
    body: JSON.stringify({
      idempotency_key: `smoke:clawcuts:assign:${suffix}`,
      worker_did: workerDid,
    }),
  });

  assert(assignEscrow.status === 200, `assign expected 200, got ${assignEscrow.status}: ${assignEscrow.text}`);

  const releaseKey = `smoke:clawcuts:release:${suffix}`;
  const releaseEscrow = await httpJson(`${escrowBaseUrl}/v1/escrows/${escrowId}/release`, {
    method: 'POST',
    headers: adminHeaders(escrowAdminKey),
    body: JSON.stringify({
      idempotency_key: releaseKey,
      approved_by: buyerDid,
      verification: {
        smoke: true,
        proof_bundle_hash_b64u: `smoke_${suffix}`,
        clawverify_ref: `cvf_smoke_${suffix}`,
      },
    }),
  });

  assert(releaseEscrow.status === 200, `release expected 200, got ${releaseEscrow.status}: ${releaseEscrow.text}`);

  const workerTransfer = releaseEscrow.json?.ledger_refs?.worker_transfer;
  const feeTransfers = Array.isArray(releaseEscrow.json?.ledger_refs?.fee_transfers)
    ? releaseEscrow.json.ledger_refs.fee_transfers
    : [];
  const referralTransfers = Array.isArray(releaseEscrow.json?.ledger_refs?.referral_transfers)
    ? releaseEscrow.json.ledger_refs.referral_transfers
    : [];

  assert(typeof workerTransfer === 'string' && workerTransfer.length > 0, `missing worker transfer: ${releaseEscrow.text}`);
  assert(feeTransfers.length > 0, `expected fee transfers, got ${releaseEscrow.text}`);
  assert(referralTransfers.length > 0, `expected referral transfers, got ${releaseEscrow.text}`);

  // Replay release must be idempotent.
  const releaseReplay = await httpJson(`${escrowBaseUrl}/v1/escrows/${escrowId}/release`, {
    method: 'POST',
    headers: adminHeaders(escrowAdminKey),
    body: JSON.stringify({
      idempotency_key: releaseKey,
      approved_by: buyerDid,
    }),
  });

  assert(releaseReplay.status === 200, `release replay expected 200, got ${releaseReplay.status}: ${releaseReplay.text}`);
  const replayFeeTransfers = releaseReplay.json?.ledger_refs?.fee_transfers ?? [];
  const replayReferralTransfers = releaseReplay.json?.ledger_refs?.referral_transfers ?? [];
  assert(JSON.stringify(replayFeeTransfers) === JSON.stringify(feeTransfers), 'fee transfer replay mismatch');
  assert(JSON.stringify(replayReferralTransfers) === JSON.stringify(referralTransfers), 'referral transfer replay mismatch');

  // 6) Apply endpoint idempotency proof (same key+payload returns deduped).
  const applyReplay = await httpJson(`${clawcutsBaseUrl}/v1/fees/apply`, {
    method: 'POST',
    headers: adminHeaders(cutsAdminKey),
    body: JSON.stringify({
      idempotency_key: `escrow:${escrowId}:release:${releaseKey}`,
      product: 'clawbounties',
      currency: 'USD',
      settlement_ref: escrowId,
      occurred_at: new Date().toISOString(),
      snapshot: {
        policy_id: 'bounties_v1',
        policy_version: policyVersion,
        policy_hash_b64u: policyHash,
        buyer_total_minor: quote.buyer_total_minor,
        worker_net_minor: quote.worker_net_minor,
        fees: quote.fees,
      },
      context: {
        smoke: true,
      },
    }),
  });

  assert(applyReplay.status === 200, `apply replay expected 200, got ${applyReplay.status}: ${applyReplay.text}`);
  assert(applyReplay.json?.deduped === true, `apply replay expected deduped=true, got ${applyReplay.text}`);

  // 7) Revenue report JSON + CSV.
  const reportMonth = monthNowUtc();
  const reportJson = await httpJson(
    `${clawcutsBaseUrl}/v1/reports/revenue/monthly?month=${encodeURIComponent(reportMonth)}&product=clawbounties`,
    {
      method: 'GET',
      headers: adminHeaders(cutsAdminKey),
    }
  );

  assert(reportJson.status === 200, `report json expected 200, got ${reportJson.status}: ${reportJson.text}`);
  const reportRows = Array.isArray(reportJson.json?.rows) ? reportJson.json.rows : [];
  const matchingReportRow = reportRows.find((row) => row?.policy_version === policyVersion && row?.policy_hash_b64u === policyHash);
  assert(matchingReportRow, `report missing policy/version row: ${reportJson.text}`);
  assert(BigInt(matchingReportRow.referral_payout_minor ?? '0') > 0n, `expected referral payout in report: ${reportJson.text}`);

  const reportCsv = await httpJson(
    `${clawcutsBaseUrl}/v1/reports/revenue/monthly?month=${encodeURIComponent(reportMonth)}&product=clawbounties&format=csv`,
    {
      method: 'GET',
      headers: adminHeaders(cutsAdminKey),
    }
  );

  assert(reportCsv.status === 200, `report csv expected 200, got ${reportCsv.status}: ${reportCsv.text}`);
  assert(reportCsv.text.includes(policyVersion), 'report csv missing policy version');

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: isProd ? 'prod' : 'staging',
        policy: {
          id: 'bounties_v1',
          version: policyVersion,
          hash_b64u: policyHash,
        },
        escrow: {
          escrow_id: escrowId,
          release_idempotency_key: releaseKey,
          worker_transfer: workerTransfer,
          fee_transfer_count: feeTransfers.length,
          referral_transfer_count: referralTransfers.length,
        },
        report: {
          month: reportMonth,
          matched_policy_version: matchingReportRow.policy_version,
          matched_policy_hash_b64u: matchingReportRow.policy_hash_b64u,
          platform_fee_minor: matchingReportRow.platform_fee_minor,
          referral_payout_minor: matchingReportRow.referral_payout_minor,
          platform_retained_minor: matchingReportRow.platform_retained_minor,
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
