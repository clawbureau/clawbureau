#!/usr/bin/env node
/**
 * refresh-clawbureau-verifier-config.mjs
 *
 * Fetches current signer DIDs from production and staging clawproxy deployments,
 * updates the committed verifier config, and prints a diff.
 *
 * Usage:
 *   node scripts/protocol/refresh-clawbureau-verifier-config.mjs
 *
 * Environment:
 *   PROD_URL  — production proxy URL (default: https://proxy.clawbureau.com)
 *   STAGING_URL — staging proxy URL (default: https://staging.proxy.clawbureau.com)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../..');
const CONFIG_PATH = resolve(ROOT, 'packages/schema/fixtures/clawverify.config.clawbureau.v1.json');

const PROD_URL = process.env.PROD_URL || 'https://proxy.clawbureau.com';
const STAGING_URL = process.env.STAGING_URL || 'https://staging.proxy.clawbureau.com';

async function fetchSignerDid(baseUrl) {
  const url = `${baseUrl}/v1/did`;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) {
      console.error(`  ⚠ ${url} → HTTP ${res.status}`);
      return null;
    }
    const data = await res.json();
    const did = data?.deployment?.receiptSignerDidKey || data?.did;
    if (!did) {
      console.error(`  ⚠ ${url} → no receiptSignerDidKey in response`);
      return null;
    }
    return did;
  } catch (err) {
    console.error(`  ⚠ ${url} → ${err.message}`);
    return null;
  }
}

async function main() {
  console.log('Fetching signer DIDs...\n');

  const [prodDid, stagingDid] = await Promise.all([
    fetchSignerDid(PROD_URL),
    fetchSignerDid(STAGING_URL),
  ]);

  console.log(`  Production:  ${prodDid || '(unavailable)'}`);
  console.log(`  Staging:     ${stagingDid || '(unavailable)'}\n`);

  // Read current config
  const configRaw = readFileSync(CONFIG_PATH, 'utf-8');
  const config = JSON.parse(configRaw);
  const oldDids = config.trusted_signer_dids || [];

  // Build new DID set (preserve existing, add new)
  const didSet = new Set(oldDids);
  if (prodDid) didSet.add(prodDid);
  if (stagingDid) didSet.add(stagingDid);
  const newDids = [...didSet].sort();

  // Check for changes
  const added = newDids.filter(d => !oldDids.includes(d));
  const removed = oldDids.filter(d => !newDids.includes(d));

  if (added.length === 0 && removed.length === 0) {
    console.log('✅ No changes — verifier config is up to date.\n');
    console.log(`  Trusted DIDs (${newDids.length}):`);
    for (const d of newDids) console.log(`    ${d}`);
    return;
  }

  // Update config
  config.trusted_signer_dids = newDids;
  const newConfigRaw = JSON.stringify(config, null, 2) + '\n';
  writeFileSync(CONFIG_PATH, newConfigRaw);

  console.log('📝 Updated verifier config:\n');
  if (added.length > 0) {
    console.log('  Added:');
    for (const d of added) console.log(`    + ${d}`);
  }
  if (removed.length > 0) {
    console.log('  Removed:');
    for (const d of removed) console.log(`    - ${d}`);
  }
  console.log(`\n  Total trusted DIDs: ${newDids.length}`);
  console.log(`  Config path: ${CONFIG_PATH}`);
  console.log('\n  Review the diff, then commit.');
}

main().catch(err => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
