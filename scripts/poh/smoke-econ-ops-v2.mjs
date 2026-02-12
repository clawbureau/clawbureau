#!/usr/bin/env node
/**
 * ECON-OPS-002 Task 4: Smoke suite for operational intelligence endpoints.
 *
 * Usage:
 *   node scripts/poh/smoke-econ-ops-v2.mjs --env staging
 *   node scripts/poh/smoke-econ-ops-v2.mjs --env prod
 */
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

let sdk = null;
try { sdk = await import('../../packages/clawsig-sdk/dist/index.js'); } catch { /* noop */ }

const envArg = process.argv.find(a => a.startsWith('--env='))?.split('=')[1]
  ?? (process.argv.includes('--env') ? process.argv[process.argv.indexOf('--env') + 1] : 'staging');

const BASE = envArg === 'prod' ? 'https://clawsettle.com' : 'https://staging.clawsettle.com';

function loadSecret(name, env) {
  for (const p of [
    resolve(process.env.HOME, `.clawsecrets/clawsettle/${name}.${env}`),
    resolve(process.env.HOME, `.clawsecrets/clawsettle/${name}`),
  ]) { try { return readFileSync(p, 'utf-8').trim(); } catch { /* next */ } }
  return process.env[name] ?? '';
}

const ADMIN_KEY = loadSecret('SETTLE_ADMIN_KEY', envArg);
if (!ADMIN_KEY) { console.error(`❌ SETTLE_ADMIN_KEY not found for ${envArg}`); process.exit(1); }

const auth = { 'Authorization': `Bearer ${ADMIN_KEY}` };
const outDir = resolve(__dirname, '../../artifacts/simulations/econ-ops-v2',
  `${new Date().toISOString().replace(/[:.]/g, '-')}-${envArg}`);
mkdirSync(outDir, { recursive: true });

let runRef = null;
if (sdk?.createRun) {
  try { runRef = await sdk.createRun({ proxyBaseUrl: BASE, runLabel: 'ECON-OPS-002-smoke' }); }
  catch { /* no key pair */ }
}
if (runRef) console.log(`[sdk] Run: ${runRef.runId}`);

async function api(label, url, opts = {}) {
  const t0 = Date.now();
  const res = await fetch(url, opts);
  const ms = Date.now() - t0;
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 500) }; }
  if (runRef) runRef.recordToolCall({
    toolName: label, args: { url, method: opts.method ?? 'GET' },
    result: { status: res.status, latencyMs: ms }, resultStatus: res.status < 400 ? 'pass' : 'fail', latencyMs: ms,
  });
  return { status: res.status, json, ms };
}

const results = [];
let passed = 0, total = 0;
function check(name, pass, detail = '') {
  total++; if (pass) passed++;
  results.push({ step: name, pass, detail });
  console.log(`  ${pass ? '✓' : '❌'} ${name}${detail ? ` (${detail})` : ''}`);
}

// === Step 1: Health history ===
console.log(`[${envArg}] Step 1: Health history`);
const histRes = await api('ops:health:history', `${BASE}/v1/ops/health/history?hours=1`, { headers: auth });
check('Health history endpoint 200', histRes.status === 200, `status=${histRes.status}`);
check('Health history returns snapshots array', Array.isArray(histRes.json?.snapshots), `count=${histRes.json?.count}`);

// === Step 2: Health trends ===
console.log(`[${envArg}] Step 2: Health trends`);
const trendsRes = await api('ops:health:trends', `${BASE}/v1/ops/health/trends?days=1`, { headers: auth });
check('Health trends endpoint 200', trendsRes.status === 200, `status=${trendsRes.status}`);
check('Health trends has per_service', typeof trendsRes.json?.per_service === 'object',
  `snapshots=${trendsRes.json?.total_snapshots}`);
check('Health trends has period', trendsRes.json?.period?.days !== undefined,
  `days=${trendsRes.json?.period?.days}`);

// === Step 3: Webhook SLA ===
console.log(`[${envArg}] Step 3: Webhook SLA`);
const slaRes = await api('ops:webhooks:sla', `${BASE}/v1/ops/webhooks/sla?hours=1`, { headers: auth });
check('Webhook SLA endpoint 200', slaRes.status === 200, `status=${slaRes.status}`);
check('Webhook SLA has processing_ms', typeof slaRes.json?.processing_ms === 'object',
  `p50=${slaRes.json?.processing_ms?.p50} p95=${slaRes.json?.processing_ms?.p95} p99=${slaRes.json?.processing_ms?.p99}`);
check('Webhook SLA has success_rate', typeof slaRes.json?.success_rate_pct === 'number',
  `rate=${slaRes.json?.success_rate_pct}% total=${slaRes.json?.total_deliveries}`);

// === Step 4: Webhook failures ===
console.log(`[${envArg}] Step 4: Webhook failures`);
const failRes = await api('ops:webhooks:failures', `${BASE}/v1/ops/webhooks/failures?since=${new Date(Date.now()-86400000).toISOString()}`, { headers: auth });
check('Webhook failures endpoint 200', failRes.status === 200, `status=${failRes.status}`);
check('Webhook failures returns array', Array.isArray(failRes.json?.failures), `count=${failRes.json?.count}`);

// === Step 5: Active alerts ===
console.log(`[${envArg}] Step 5: Active alerts`);
const alertsRes = await api('ops:alerts:active', `${BASE}/v1/ops/alerts/active`, { headers: auth });
check('Active alerts endpoint 200', alertsRes.status === 200, `status=${alertsRes.status}`);
check('Active alerts returns array', Array.isArray(alertsRes.json?.alerts), `count=${alertsRes.json?.count}`);

// === Step 6: Legacy health endpoint still works ===
console.log(`[${envArg}] Step 6: Legacy health endpoint`);
const legacyRes = await api('economy:health', `${BASE}/v1/economy/health`, { headers: auth });
check('Legacy health 200', legacyRes.status === 200, `status=${legacyRes.status}`);
const svcsUp = legacyRes.json?.services?.filter?.(s => s.status === 'up')?.length ?? 0;
check('Services reachable', svcsUp >= 5, `${svcsUp}/7 up`);

// === Step 7: Legacy ops alerts endpoint ===
console.log(`[${envArg}] Step 7: Legacy ops alerts`);
const legacyAlerts = await api('ops:alerts:list', `${BASE}/v1/ops/alerts?limit=5`, { headers: auth });
check('Legacy alerts 200', legacyAlerts.status === 200, `status=${legacyAlerts.status}`);

// === Finalize ===
if (runRef) {
  console.log(`\n[sdk] Finalizing proof bundle...`);
  try {
    const { envelope, urm } = runRef.finalize({
      inputs: [{ type: 'env', label: envArg }],
      outputs: [{ type: 'results', passed, total }],
    });
    writeFileSync(resolve(outDir, 'proof-bundle.json'), JSON.stringify(envelope, null, 2));
    writeFileSync(resolve(outDir, 'urm.json'), JSON.stringify(urm, null, 2));
    console.log(`   Bundle: ${resolve(outDir, 'proof-bundle.json')}`);
  } catch (e) { console.log(`   ⚠️ SDK finalize: ${e.message}`); }
}

const smoke = {
  epic: 'ECON-OPS-002', env: envArg, timestamp: new Date().toISOString(), passed, total, results,
  endpoints: { history: histRes.json?.count, trends_snapshots: trendsRes.json?.total_snapshots,
    sla_deliveries: slaRes.json?.total_deliveries, failures: failRes.json?.count,
    active_alerts: alertsRes.json?.count, services_up: svcsUp },
};
writeFileSync(resolve(outDir, 'smoke.json'), JSON.stringify(smoke, null, 2));

console.log(`\n${passed === total ? '✅' : '⚠️'} ${envArg}: ${passed}/${total} passed`);
if (runRef) console.log(`   SDK: ${runRef.toolCalls?.length ?? 0} tool receipts`);
console.log(`   Written to: ${outDir}`);
process.exit(passed === total ? 0 : 1);
