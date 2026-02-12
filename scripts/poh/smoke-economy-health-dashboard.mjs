#!/usr/bin/env node

/**
 * ECON-OPS-001: Smoke test for economy health dashboard.
 *
 * Tests:
 *   1. GET /v1/economy/health → full aggregated report
 *   2. POST /v1/ops/alerts/check → trigger alert evaluation
 *   3. GET /v1/ops/alerts → query alerts
 *   4. Auth enforcement (401 without token)
 *
 * Usage:
 *   node scripts/poh/smoke-economy-health-dashboard.mjs --env staging
 *   node scripts/poh/smoke-economy-health-dashboard.mjs --env prod
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ENVS = {
  staging: 'https://staging.clawsettle.com',
  prod: 'https://clawsettle.com',
};

function resolveEnv() {
  const idx = process.argv.indexOf('--env');
  const env = idx !== -1 ? process.argv[idx + 1] : 'staging';
  if (!ENVS[env]) throw new Error(`Unknown env: ${env}. Use staging|prod`);
  return { env, baseUrl: ENVS[env] };
}

function resolveToken(envName) {
  const tokenFile = `${process.env.HOME}/.clawsecrets/clawsettle/SETTLE_ADMIN_KEY.${envName}`;
  if (fs.existsSync(tokenFile)) return fs.readFileSync(tokenFile, 'utf-8').trim();
  if (process.env.SETTLE_ADMIN_KEY) return process.env.SETTLE_ADMIN_KEY.trim();
  throw new Error('No admin token found');
}

async function main() {
  const { env, baseUrl } = resolveEnv();
  const token = resolveToken(env);
  const results = [];
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.resolve(__dirname, '../../artifacts/simulations/economy-health-dashboard', `${ts}-${env}`);
  fs.mkdirSync(outDir, { recursive: true });

  const headers = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`,
  };

  // -----------------------------------------------------------------------
  // Step 1: GET /v1/economy/health
  // -----------------------------------------------------------------------
  console.log(`[${env}] Step 1: GET /v1/economy/health`);
  let healthReport = null;
  try {
    const res = await fetch(`${baseUrl}/v1/economy/health`, { headers });
    const body = await res.json();
    healthReport = body;
    const pass = res.status === 200
      && typeof body.overall_status === 'string'
      && Array.isArray(body.services)
      && body.services.length >= 6
      && body.settlement != null
      && body.alerts != null;
    results.push({
      step: 'economy_health',
      status: res.status,
      pass,
      overall_status: body.overall_status,
      service_count: body.services?.length,
      services_up: body.services?.filter(s => s.status === 'up').length,
      services_down: body.services?.filter(s => s.status === 'down').length,
      disputes_open: body.settlement?.disputes?.total_open,
      outbox_apply_failed: body.settlement?.outbox?.apply?.failed,
      outbox_resolve_failed: body.settlement?.outbox?.resolve?.failed,
      recon_mismatches: body.settlement?.recon?.mismatch_count,
      alerts: body.alerts,
    });
    console.log(`  status=${res.status} pass=${pass} overall=${body.overall_status}`);
    console.log(`  services: ${body.services?.map(s => `${s.service}=${s.status}`).join(', ')}`);
    // Write full health report
    fs.writeFileSync(path.join(outDir, 'health-report.json'), JSON.stringify(body, null, 2));
  } catch (err) {
    results.push({ step: 'economy_health', pass: false, error: err.message });
    console.log(`  ERROR: ${err.message}`);
  }

  // -----------------------------------------------------------------------
  // Step 2: POST /v1/ops/alerts/check
  // -----------------------------------------------------------------------
  console.log(`[${env}] Step 2: POST /v1/ops/alerts/check`);
  try {
    const res = await fetch(`${baseUrl}/v1/ops/alerts/check`, { method: 'POST', headers });
    const body = await res.json();
    const pass = res.status === 200 && body.ok === true && typeof body.alerts_written === 'number';
    results.push({
      step: 'ops_alerts_check',
      status: res.status,
      pass,
      alerts_written: body.alerts_written,
    });
    console.log(`  status=${res.status} pass=${pass} alerts_written=${body.alerts_written}`);
  } catch (err) {
    results.push({ step: 'ops_alerts_check', pass: false, error: err.message });
    console.log(`  ERROR: ${err.message}`);
  }

  // -----------------------------------------------------------------------
  // Step 3: GET /v1/ops/alerts
  // -----------------------------------------------------------------------
  console.log(`[${env}] Step 3: GET /v1/ops/alerts`);
  try {
    const res = await fetch(`${baseUrl}/v1/ops/alerts?limit=10`, { headers });
    const body = await res.json();
    const pass = res.status === 200 && body.ok === true && Array.isArray(body.alerts);
    results.push({
      step: 'ops_alerts_query',
      status: res.status,
      pass,
      alert_count: body.count,
    });
    console.log(`  status=${res.status} pass=${pass} alert_count=${body.count}`);
  } catch (err) {
    results.push({ step: 'ops_alerts_query', pass: false, error: err.message });
    console.log(`  ERROR: ${err.message}`);
  }

  // -----------------------------------------------------------------------
  // Step 4: GET /v1/ops/alerts?severity=critical
  // -----------------------------------------------------------------------
  console.log(`[${env}] Step 4: GET /v1/ops/alerts?severity=critical`);
  try {
    const res = await fetch(`${baseUrl}/v1/ops/alerts?severity=critical&limit=5`, { headers });
    const body = await res.json();
    const pass = res.status === 200 && body.ok === true;
    results.push({
      step: 'ops_alerts_filtered',
      status: res.status,
      pass,
      alert_count: body.count,
    });
    console.log(`  status=${res.status} pass=${pass} alert_count=${body.count}`);
  } catch (err) {
    results.push({ step: 'ops_alerts_filtered', pass: false, error: err.message });
    console.log(`  ERROR: ${err.message}`);
  }

  // -----------------------------------------------------------------------
  // Step 5: Auth enforcement
  // -----------------------------------------------------------------------
  console.log(`[${env}] Step 5: Auth enforcement`);
  try {
    const res = await fetch(`${baseUrl}/v1/economy/health`);
    const pass = res.status === 401;
    results.push({ step: 'auth_enforcement', status: res.status, pass });
    console.log(`  status=${res.status} pass=${pass}`);
  } catch (err) {
    results.push({ step: 'auth_enforcement', pass: false, error: err.message });
  }

  // -----------------------------------------------------------------------
  // Summary
  // -----------------------------------------------------------------------
  const allPass = results.every(r => r.pass);
  const summary = {
    env,
    base_url: baseUrl,
    generated_at: new Date().toISOString(),
    all_pass: allPass,
    steps: results,
  };

  fs.writeFileSync(path.join(outDir, 'smoke.json'), JSON.stringify(summary, null, 2));
  console.log(`\n${allPass ? '✅' : '❌'} ${env}: ${results.filter(r => r.pass).length}/${results.length} passed`);
  console.log(`  Written to ${outDir}/smoke.json`);

  if (!allPass) process.exit(1);
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
