#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      out[key] = true;
      continue;
    }
    out[key] = next;
    i += 1;
  }
  return out;
}

async function requestJson(url, { method = 'GET', headers = {}, body } = {}) {
  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }

  return { status: response.status, ok: response.ok, json };
}

function assertStatus(label, response, expected) {
  if (response.status !== expected) {
    throw new Error(
      `${label} expected HTTP ${expected}, got ${response.status}: ${JSON.stringify(response.json)}`
    );
  }
}

function safePick(obj, fields) {
  if (!obj || typeof obj !== 'object') return null;
  const out = {};
  for (const field of fields) {
    out[field] = obj[field];
  }
  return out;
}

async function issueLegacy(scopeBaseUrl, adminKey, sub, aud) {
  return requestJson(`${scopeBaseUrl.replace(/\/$/, '')}/v1/tokens/issue`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${adminKey}`,
      'content-type': 'application/json',
    },
    body: {
      sub,
      aud,
      scope: ['clawproxy:call'],
      ttl_sec: 900,
    },
  });
}

async function introspect(scopeBaseUrl, token) {
  return requestJson(`${scopeBaseUrl.replace(/\/$/, '')}/v1/tokens/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: { token },
  });
}

async function rotationContract(scopeBaseUrl) {
  return requestJson(`${scopeBaseUrl.replace(/\/$/, '')}/v1/keys/rotation-contract`);
}

async function main() {
  const args = parseArgs(process.argv);

  if (!args['staging-admin-key'] || !args['prod-admin-key']) {
    throw new Error('Missing required args: --staging-admin-key and --prod-admin-key');
  }

  const stagingScopeUrl = args['staging-scope-url'] || 'https://staging.clawscope.com';
  const prodScopeUrl = args['prod-scope-url'] || 'https://clawscope.com';

  const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir =
    args['out-dir'] ||
    path.join(rootDir, 'artifacts', 'smoke', 'identity-control-plane', `${timestamp}-kid-interop`);
  mkdirSync(outDir, { recursive: true });

  const result = {
    generated_at: new Date().toISOString(),
    scope_urls: {
      staging: stagingScopeUrl,
      prod: prodScopeUrl,
    },
    steps: {},
  };

  const stagingIssue = await issueLegacy(
    stagingScopeUrl,
    String(args['staging-admin-key']),
    'did:key:zKidInteropStagingSub111111111111111111111111111111',
    'staging.clawproxy.com'
  );
  assertStatus('stagingIssue', stagingIssue, 200);

  const stagingToken = stagingIssue.json?.token;
  const stagingKid = stagingIssue.json?.kid;

  result.steps.staging_issue = safePick(stagingIssue.json, [
    'token_hash',
    'token_lane',
    'legacy_exchange_mode',
    'kid',
    'iat',
    'exp',
  ]);

  const stagingIntrospectLocal = await introspect(stagingScopeUrl, stagingToken);
  assertStatus('stagingIntrospectLocal', stagingIntrospectLocal, 200);
  result.steps.staging_introspect_local = safePick(stagingIntrospectLocal.json, [
    'active',
    'token_hash',
    'kid',
    'kid_source',
  ]);

  const stagingIntrospectProd = await introspect(prodScopeUrl, stagingToken);
  assertStatus('stagingIntrospectProd', stagingIntrospectProd, 200);
  result.steps.staging_introspect_prod = safePick(stagingIntrospectProd.json, [
    'active',
    'token_hash',
    'kid',
    'kid_source',
  ]);

  const prodIssue = await issueLegacy(
    prodScopeUrl,
    String(args['prod-admin-key']),
    'did:key:zKidInteropProdSub111111111111111111111111111111111',
    'clawproxy.com'
  );
  assertStatus('prodIssue', prodIssue, 200);

  const prodToken = prodIssue.json?.token;
  const prodKid = prodIssue.json?.kid;

  result.steps.prod_issue = safePick(prodIssue.json, [
    'token_hash',
    'token_lane',
    'legacy_exchange_mode',
    'kid',
    'iat',
    'exp',
  ]);

  const prodIntrospectLocal = await introspect(prodScopeUrl, prodToken);
  assertStatus('prodIntrospectLocal', prodIntrospectLocal, 200);
  result.steps.prod_introspect_local = safePick(prodIntrospectLocal.json, [
    'active',
    'token_hash',
    'kid',
    'kid_source',
  ]);

  const prodIntrospectStaging = await introspect(stagingScopeUrl, prodToken);
  assertStatus('prodIntrospectStaging', prodIntrospectStaging, 200);
  result.steps.prod_introspect_staging = safePick(prodIntrospectStaging.json, [
    'active',
    'token_hash',
    'kid',
    'kid_source',
  ]);

  const stagingContract = await rotationContract(stagingScopeUrl);
  assertStatus('stagingContract', stagingContract, 200);
  result.steps.staging_rotation_contract = safePick(stagingContract.json, [
    'contract_version',
    'active_kid',
    'accepted_kids',
    'verify_only_kids',
    'expiring_kids',
  ]);

  const prodContract = await rotationContract(prodScopeUrl);
  assertStatus('prodContract', prodContract, 200);
  result.steps.prod_rotation_contract = safePick(prodContract.json, [
    'contract_version',
    'active_kid',
    'accepted_kids',
    'verify_only_kids',
    'expiring_kids',
  ]);

  if (!Array.isArray(stagingContract.json?.accepted_kids) || !stagingContract.json.accepted_kids.includes(prodKid)) {
    throw new Error('staging rotation contract does not include prod kid in accepted_kids');
  }

  if (!Array.isArray(prodContract.json?.accepted_kids) || !prodContract.json.accepted_kids.includes(stagingKid)) {
    throw new Error('prod rotation contract does not include staging kid in accepted_kids');
  }

  const summary = [
    `generated_at: ${result.generated_at}`,
    `staging_issue_kid: ${stagingKid}`,
    `prod_issue_kid: ${prodKid}`,
    `staging->prod introspect: ${result.steps.staging_introspect_prod?.active}`,
    `prod->staging introspect: ${result.steps.prod_introspect_staging?.active}`,
  ];

  writeFileSync(path.join(outDir, 'result.json'), JSON.stringify(result, null, 2));
  writeFileSync(path.join(outDir, 'summary.txt'), `${summary.join('\n')}\n`);

  console.log(JSON.stringify({ ok: true, out_dir: outDir }, null, 2));
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(JSON.stringify({ ok: false, error: message }, null, 2));
  process.exit(1);
});
