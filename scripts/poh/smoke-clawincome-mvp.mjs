#!/usr/bin/env node

/**
 * Smoke: clawincome MVP end-to-end (CIN-OPS-001)
 *
 * - bootstraps a fresh buyer/worker escrow release (ledger + clawcuts + escrow)
 * - validates clawincome auth + own-data privacy controls
 * - validates statement/invoice/tax-lot/income endpoints
 * - validates snapshot idempotency (same did/month/report_type)
 */

import process from 'node:process';
import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const DNS_OVERRIDES = new Map();

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

function configureDnsOverrides(overrides) {
  for (const [host, ip] of Object.entries(overrides)) {
    if (typeof host !== 'string' || host.trim().length === 0) continue;
    if (typeof ip !== 'string' || ip.trim().length === 0) continue;
    DNS_OVERRIDES.set(host.trim(), ip.trim());
  }
}

function normalizeHeaders(headersInput) {
  if (!headersInput) return [];

  if (Array.isArray(headersInput)) {
    return headersInput
      .map(([name, value]) => [String(name), String(value)])
      .filter(([name]) => name.trim().length > 0);
  }

  if (typeof headersInput.entries === 'function') {
    return Array.from(headersInput.entries()).map(([name, value]) => [String(name), String(value)]);
  }

  if (typeof headersInput === 'object') {
    return Object.entries(headersInput).map(([name, value]) => [String(name), String(value)]);
  }

  return [];
}

function parseCurlHeaders(raw) {
  const headers = {};
  const lines = raw.split(/\r?\n/);
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx <= 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key.length === 0) continue;
    headers[key] = value;
  }
  return headers;
}

async function httpViaCurl(url, init = {}, resolveIp = null) {
  const started = Date.now();
  const target = new URL(url);

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawincome-smoke-'));
  const headerFile = path.join(tempDir, 'headers.txt');
  const bodyFile = path.join(tempDir, 'body.txt');

  const args = [
    '-sS',
    '-X',
    init.method || 'GET',
    '-D',
    headerFile,
    '-o',
    bodyFile,
    '-w',
    '%{http_code}',
  ];

  if (resolveIp) {
    const port = target.port ? Number.parseInt(target.port, 10) : (target.protocol === 'https:' ? 443 : 80);
    args.push('--resolve', `${target.hostname}:${port}:${resolveIp}`);
  }

  for (const [name, value] of normalizeHeaders(init.headers)) {
    args.push('-H', `${name}: ${value}`);
  }

  if (typeof init.body === 'string') {
    args.push('--data', init.body);
  }

  args.push(url);

  try {
    const { stdout } = await execFileAsync('curl', args, {
      timeout: 60_000,
      maxBuffer: 1024 * 1024,
    });

    const status = Number.parseInt(String(stdout || '').trim(), 10);
    const text = await fs.readFile(bodyFile, 'utf8');
    const rawHeaders = await fs.readFile(headerFile, 'utf8');

    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }

    return {
      status: Number.isFinite(status) ? status : 0,
      text,
      json,
      headers: parseCurlHeaders(rawHeaders),
      elapsed_ms: Date.now() - started,
    };
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true });
  }
}

async function http(url, init = {}) {
  const started = Date.now();
  try {
    const response = await fetch(url, init);
    const text = await response.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }

    return {
      status: response.status,
      text,
      json,
      headers: Object.fromEntries(response.headers.entries()),
      elapsed_ms: Date.now() - started,
    };
  } catch (err) {
    const target = new URL(url);
    const overrideIp = DNS_OVERRIDES.get(target.hostname) ?? null;
    if (!overrideIp) {
      throw err;
    }

    return httpViaCurl(url, init, overrideIp);
  }
}

function monthNowUtc() {
  const now = new Date();
  const y = String(now.getUTCFullYear()).padStart(4, '0');
  const m = String(now.getUTCMonth() + 1).padStart(2, '0');
  return `${y}-${m}`;
}

function yearNowUtc() {
  return String(new Date().getUTCFullYear());
}

function monthRange(month) {
  const match = /^(\d{4})-(\d{2})$/.exec(month);
  if (!match) throw new Error(`invalid month: ${month}`);
  const year = Number.parseInt(match[1], 10);
  const monthIndex = Number.parseInt(match[2], 10) - 1;
  const start = new Date(Date.UTC(year, monthIndex, 1, 0, 0, 0, 0));
  const end = new Date(Date.UTC(year, monthIndex + 1, 1, 0, 0, 0, 0));
  return {
    from: start.toISOString(),
    to: end.toISOString(),
  };
}

function randomDid(prefix) {
  return `did:key:z${prefix}${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
}

function adminHeaders(key) {
  return {
    authorization: `Bearer ${key}`,
    'content-type': 'application/json; charset=utf-8',
  };
}

function ledgerHeaders(key, idempotencyKey = null) {
  return {
    'x-admin-key': key,
    ...(idempotencyKey ? { 'idempotency-key': idempotencyKey } : {}),
    'content-type': 'application/json; charset=utf-8',
  };
}

async function createLedgerAccount(ledgerBaseUrl, ledgerAdminKey, did) {
  const res = await http(`${ledgerBaseUrl}/accounts`, {
    method: 'POST',
    headers: ledgerHeaders(ledgerAdminKey),
    body: JSON.stringify({ did }),
  });

  assert(res.status === 201, `create ledger account expected 201, got ${res.status}: ${res.text}`);
  const accountId = res.json?.id;
  assert(typeof accountId === 'string' && accountId.length > 0, `missing account id: ${res.text}`);
  return {
    did,
    account_id: accountId,
  };
}

async function fundLedgerAccount(ledgerBaseUrl, ledgerAdminKey, accountId, suffix, amountMinor) {
  const res = await http(`${ledgerBaseUrl}/v1/payments/settlements/ingest`, {
    method: 'POST',
    headers: ledgerHeaders(ledgerAdminKey, `smoke:clawincome:fund:${suffix}`),
    body: JSON.stringify({
      provider: 'stripe',
      external_payment_id: `pi_smoke_clawincome_${suffix}`,
      direction: 'payin',
      status: 'confirmed',
      account_id: accountId,
      amount_minor: amountMinor,
      currency: 'USD',
      metadata: {
        smoke: true,
        source: 'clawincome-mvp',
      },
    }),
  });

  assert(res.status === 201, `fund ingest expected 201, got ${res.status}: ${res.text}`);
}

async function issueScopedToken({ scopeBaseUrl, scopeAdminKey, did, audience, scopes, source }) {
  const res = await http(`${scopeBaseUrl}/v1/tokens/issue`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${scopeAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      sub: did,
      aud: audience,
      scope: scopes,
      ttl_sec: 3600,
      token_lane: 'legacy',
      owner_did: did,
      controller_did: did,
      agent_did: did,
      payment_account_did: did,
      mission_id: `${source}:${did}`,
    }),
  });

  assert(res.status === 200 || res.status === 201, `issue token expected 200/201, got ${res.status}: ${res.text}`);
  const token = res.json?.token;
  assert(typeof token === 'string' && token.length > 0, `missing issued token: ${res.text}`);
  return token;
}

async function simulateFeeQuote(clawcutsBaseUrl, policyId) {
  const res = await http(`${clawcutsBaseUrl}/v1/fees/simulate`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      product: 'clawbounties',
      policy_id: policyId,
      amount_minor: '10000',
      currency: 'USD',
      params: {
        is_code_bounty: false,
        closure_type: 'requester',
      },
    }),
  });

  assert(res.status === 200, `simulate expected 200, got ${res.status}: ${res.text}`);

  const policy = res.json?.policy;
  const quote = res.json?.quote;
  assert(policy && typeof policy.version === 'string' && typeof policy.hash_b64u === 'string', `simulate missing policy: ${res.text}`);
  assert(quote && Array.isArray(quote.fees), `simulate missing quote fees: ${res.text}`);
  assert(typeof quote.buyer_total_minor === 'string' && typeof quote.worker_net_minor === 'string', `simulate missing totals: ${res.text}`);

  return {
    policy_version: policy.version,
    policy_hash_b64u: policy.hash_b64u,
    quote,
  };
}

async function createEscrowAndRelease({
  escrowBaseUrl,
  escrowAdminKey,
  buyerDid,
  workerDid,
  suffix,
  feeQuote,
  policyId,
  policyVersion,
  policyHash,
}) {
  const createRes = await http(`${escrowBaseUrl}/v1/escrows`, {
    method: 'POST',
    headers: adminHeaders(escrowAdminKey),
    body: JSON.stringify({
      idempotency_key: `smoke:clawincome:create:${suffix}`,
      buyer_did: buyerDid,
      worker_did: null,
      currency: 'USD',
      amount_minor: '10000',
      fee_quote: {
        policy_id: policyId,
        policy_version: policyVersion,
        policy_hash_b64u: policyHash,
        buyer_total_minor: feeQuote.buyer_total_minor,
        worker_net_minor: feeQuote.worker_net_minor,
        fees: feeQuote.fees,
      },
      metadata: {
        smoke: true,
        source: 'clawincome-mvp',
      },
    }),
  });

  assert(createRes.status === 201, `create escrow expected 201, got ${createRes.status}: ${createRes.text}`);
  const escrowId = createRes.json?.escrow_id;
  assert(typeof escrowId === 'string' && escrowId.length > 0, `create escrow missing id: ${createRes.text}`);

  const assignRes = await http(`${escrowBaseUrl}/v1/escrows/${escrowId}/assign`, {
    method: 'POST',
    headers: adminHeaders(escrowAdminKey),
    body: JSON.stringify({
      idempotency_key: `smoke:clawincome:assign:${suffix}`,
      worker_did: workerDid,
    }),
  });

  assert(assignRes.status === 200, `assign expected 200, got ${assignRes.status}: ${assignRes.text}`);

  const releaseKey = `smoke:clawincome:release:${suffix}`;
  const releaseRes = await http(`${escrowBaseUrl}/v1/escrows/${escrowId}/release`, {
    method: 'POST',
    headers: adminHeaders(escrowAdminKey),
    body: JSON.stringify({
      idempotency_key: releaseKey,
      approved_by: buyerDid,
      verification: {
        smoke: true,
        proof_bundle_hash_b64u: `smoke_${suffix}`,
      },
    }),
  });

  assert(releaseRes.status === 200, `release expected 200, got ${releaseRes.status}: ${releaseRes.text}`);

  const workerTransfer = releaseRes.json?.ledger_refs?.worker_transfer;
  const feeTransfers = Array.isArray(releaseRes.json?.ledger_refs?.fee_transfers)
    ? releaseRes.json.ledger_refs.fee_transfers
    : [];

  assert(typeof workerTransfer === 'string' && workerTransfer.length > 0, `release missing worker transfer: ${releaseRes.text}`);
  assert(feeTransfers.length > 0, `release missing fee transfers: ${releaseRes.text}`);

  return {
    escrow_id: escrowId,
    release_idempotency_key: releaseKey,
    worker_transfer: workerTransfer,
    fee_transfer_count: feeTransfers.length,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = String(args.get('env') || 'staging').toLowerCase();
  const isProd = envName === 'prod' || envName === 'production';

  const clawincomeBaseUrl = String(args.get('clawincome-base-url') || '') || (isProd ? 'https://clawincome.com' : 'https://staging.clawincome.com');
  const clawscopeBaseUrl = String(args.get('clawscope-base-url') || '') || (isProd ? 'https://clawscope.com' : 'https://staging.clawscope.com');
  const clawcutsBaseUrl = String(args.get('clawcuts-base-url') || '') || (isProd ? 'https://clawcuts.com' : 'https://staging.clawcuts.com');
  const clawescrowBaseUrl = String(args.get('escrow-base-url') || '') || (isProd ? 'https://clawescrow.com' : 'https://staging.clawescrow.com');
  const clawledgerBaseUrl = String(args.get('ledger-base-url') || '') || (isProd ? 'https://clawledger.com' : 'https://staging.clawledger.com');

  const clawincomeResolveIp = String(args.get('clawincome-resolve-ip') || '').trim();
  if (clawincomeResolveIp.length > 0) {
    const incomeHost = new URL(clawincomeBaseUrl).hostname;
    configureDnsOverrides({
      [incomeHost]: clawincomeResolveIp,
    });
  }

  const ledgerAdminKey = String(args.get('ledger-admin-key') || process.env.LEDGER_ADMIN_KEY || '').trim();
  const escrowAdminKey = String(args.get('escrow-admin-key') || process.env.ESCROW_ADMIN_KEY || '').trim();
  const scopeAdminKey = String(args.get('scope-admin-key') || process.env.SCOPE_ADMIN_KEY || process.env.CLAWSCOPE_ADMIN_KEY || '').trim();
  const incomeAdminKey = String(args.get('income-admin-key') || process.env.INCOME_ADMIN_KEY || '').trim();

  assert(ledgerAdminKey.length > 0, 'Missing LEDGER_ADMIN_KEY');
  assert(escrowAdminKey.length > 0, 'Missing ESCROW_ADMIN_KEY');
  assert(scopeAdminKey.length > 0, 'Missing SCOPE_ADMIN_KEY/CLAWSCOPE_ADMIN_KEY');
  assert(incomeAdminKey.length > 0, 'Missing INCOME_ADMIN_KEY');

  const suffix = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  const buyerDid = randomDid('cinbuyer');
  const workerDid = randomDid('cinworker');
  const outsiderDid = randomDid('cinoutsider');

  const month = monthNowUtc();
  const year = yearNowUtc();
  const { from, to } = monthRange(month);

  const buyerAccount = await createLedgerAccount(clawledgerBaseUrl, ledgerAdminKey, buyerDid);
  await createLedgerAccount(clawledgerBaseUrl, ledgerAdminKey, workerDid);
  await createLedgerAccount(clawledgerBaseUrl, ledgerAdminKey, outsiderDid);
  await fundLedgerAccount(clawledgerBaseUrl, ledgerAdminKey, buyerAccount.account_id, suffix, '50000');

  const policyId = String(args.get('policy-id') || 'bounties_v1');
  const simulated = await simulateFeeQuote(clawcutsBaseUrl, policyId);

  const escrow = await createEscrowAndRelease({
    escrowBaseUrl: clawescrowBaseUrl,
    escrowAdminKey,
    buyerDid,
    workerDid,
    suffix,
    feeQuote: simulated.quote,
    policyId,
    policyVersion: simulated.policy_version,
    policyHash: simulated.policy_hash_b64u,
  });

  const scopeRequired = String(args.get('scope') || process.env.INCOME_SCOPE_REQUIRED || 'clawincome:read').trim();

  const buyerToken = await issueScopedToken({
    scopeBaseUrl: clawscopeBaseUrl,
    scopeAdminKey,
    did: buyerDid,
    audience: clawincomeBaseUrl,
    scopes: [scopeRequired],
    source: 'smoke-clawincome',
  });

  const outsiderToken = await issueScopedToken({
    scopeBaseUrl: clawscopeBaseUrl,
    scopeAdminKey,
    did: outsiderDid,
    audience: clawincomeBaseUrl,
    scopes: [scopeRequired],
    source: 'smoke-clawincome',
  });

  const statementUrl = `${clawincomeBaseUrl}/v1/statements/monthly?did=${encodeURIComponent(buyerDid)}&month=${encodeURIComponent(month)}`;

  const statement1 = await http(statementUrl, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${buyerToken}`,
    },
  });

  assert(statement1.status === 200, `statement json expected 200, got ${statement1.status}: ${statement1.text}`);
  const statementSnapshotId = statement1.json?.snapshot?.id;
  const statementSnapshotHash = statement1.json?.snapshot?.hash_b64u;
  assert(typeof statementSnapshotId === 'string' && statementSnapshotId.length > 0, `statement missing snapshot id: ${statement1.text}`);
  assert(typeof statementSnapshotHash === 'string' && statementSnapshotHash.length > 0, `statement missing snapshot hash: ${statement1.text}`);

  const statement2 = await http(statementUrl, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${buyerToken}`,
    },
  });

  assert(statement2.status === 200, `statement replay expected 200, got ${statement2.status}: ${statement2.text}`);
  assert(statement2.json?.snapshot?.id === statementSnapshotId, 'statement snapshot id should be idempotent for did+month');
  assert(statement2.json?.snapshot?.hash_b64u === statementSnapshotHash, 'statement snapshot hash should be idempotent for did+month');

  const statementCsv = await http(
    `${clawincomeBaseUrl}/v1/statements/monthly.csv?did=${encodeURIComponent(buyerDid)}&month=${encodeURIComponent(month)}`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${buyerToken}`,
      },
    }
  );

  assert(statementCsv.status === 200, `statement csv expected 200, got ${statementCsv.status}: ${statementCsv.text}`);
  assert(typeof statementCsv.headers['x-clawincome-source-snapshot-id'] === 'string', 'statement csv missing source snapshot header');
  assert(statementCsv.headers['x-clawincome-source-snapshot-id'] === statementSnapshotId, 'statement csv source snapshot id mismatch');

  const invoices = await http(
    `${clawincomeBaseUrl}/v1/invoices?did=${encodeURIComponent(buyerDid)}&month=${encodeURIComponent(month)}`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${buyerToken}`,
      },
    }
  );

  assert(invoices.status === 200, `invoices expected 200, got ${invoices.status}: ${invoices.text}`);
  const invoiceRows = Array.isArray(invoices.json?.invoices) ? invoices.json.invoices : [];
  assert(invoiceRows.length > 0, `invoices should contain at least one row: ${invoices.text}`);
  assert(invoiceRows.some((row) => row?.escrow_id === escrow.escrow_id), `invoices missing escrow ${escrow.escrow_id}`);

  const taxLots = await http(
    `${clawincomeBaseUrl}/v1/tax-lots?did=${encodeURIComponent(buyerDid)}&year=${encodeURIComponent(year)}`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${buyerToken}`,
      },
    }
  );

  assert(taxLots.status === 200, `tax-lots expected 200, got ${taxLots.status}: ${taxLots.text}`);
  const lots = Array.isArray(taxLots.json?.tax_lots) ? taxLots.json.tax_lots : [];
  assert(lots.some((lot) => lot?.category === 'expense' && lot?.source_ref === escrow.escrow_id), `tax-lots missing expense lot for escrow ${escrow.escrow_id}`);

  const incomePage1 = await http(
    `${clawincomeBaseUrl}/v1/income?did=${encodeURIComponent(buyerDid)}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&limit=1`,
    {
      method: 'GET',
      headers: {
        authorization: `Bearer ${buyerToken}`,
      },
    }
  );

  assert(incomePage1.status === 200, `income page1 expected 200, got ${incomePage1.status}: ${incomePage1.text}`);
  const incomeItems1 = Array.isArray(incomePage1.json?.items) ? incomePage1.json.items : [];
  assert(incomeItems1.length >= 1, `income should return at least one item: ${incomePage1.text}`);
  const nextCursor = incomePage1.json?.page_info?.next_cursor;

  let incomePage2Returned = 0;
  if (typeof nextCursor === 'string' && nextCursor.length > 0) {
    const incomePage2 = await http(
      `${clawincomeBaseUrl}/v1/income?did=${encodeURIComponent(buyerDid)}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&limit=1&cursor=${encodeURIComponent(nextCursor)}`,
      {
        method: 'GET',
        headers: {
          authorization: `Bearer ${buyerToken}`,
        },
      }
    );

    assert(incomePage2.status === 200, `income page2 expected 200, got ${incomePage2.status}: ${incomePage2.text}`);
    const incomeItems2 = Array.isArray(incomePage2.json?.items) ? incomePage2.json.items : [];
    incomePage2Returned = incomeItems2.length;
  }

  const forbidden = await http(statementUrl, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${outsiderToken}`,
    },
  });

  assert(forbidden.status === 403, `cross-did access should be forbidden, got ${forbidden.status}: ${forbidden.text}`);
  const forbiddenCode = forbidden.json?.code ?? forbidden.json?.error;
  assert(forbiddenCode === 'FORBIDDEN', `cross-did access error code should be FORBIDDEN: ${forbidden.text}`);

  const adminRead = await http(statementUrl, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${incomeAdminKey}`,
    },
  });

  assert(adminRead.status === 200, `income admin read expected 200, got ${adminRead.status}: ${adminRead.text}`);

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: isProd ? 'prod' : 'staging',
        did: buyerDid,
        month,
        year,
        escrow,
        statements: {
          snapshot_id: statementSnapshotId,
          snapshot_hash_b64u: statementSnapshotHash,
          csv_source_snapshot_id: statementCsv.headers['x-clawincome-source-snapshot-id'] ?? null,
          csv_snapshot_id: statementCsv.headers['x-clawincome-snapshot-id'] ?? null,
        },
        invoices: {
          count: invoiceRows.length,
        },
        tax_lots: {
          count: lots.length,
        },
        income: {
          page1_count: incomeItems1.length,
          page2_count: incomePage2Returned,
          next_cursor_present: typeof nextCursor === 'string' && nextCursor.length > 0,
        },
        privacy: {
          cross_did_status: forbidden.status,
          admin_read_status: adminRead.status,
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
