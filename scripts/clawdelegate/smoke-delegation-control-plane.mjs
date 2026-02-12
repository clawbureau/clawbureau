#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function parseArgs(argv) {
  const out = {
    env: 'staging',
    baseUrl: '',
    outDir: '',
    adminKey: process.env.CLAWDELEGATE_ADMIN_KEY ?? '',
    delegatorDid: process.env.CLAWDELEGATE_SMOKE_DELEGATOR_DID ?? '',
    delegateDid: process.env.CLAWDELEGATE_SMOKE_DELEGATE_DID ?? '',
    deployVersion: '',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--env' && argv[i + 1]) {
      out.env = String(argv[++i]);
      continue;
    }
    if (arg === '--base-url' && argv[i + 1]) {
      out.baseUrl = String(argv[++i]);
      continue;
    }
    if (arg === '--out-dir' && argv[i + 1]) {
      out.outDir = String(argv[++i]);
      continue;
    }
    if (arg === '--admin-key' && argv[i + 1]) {
      out.adminKey = String(argv[++i]);
      continue;
    }
    if (arg === '--delegator-did' && argv[i + 1]) {
      out.delegatorDid = String(argv[++i]);
      continue;
    }
    if (arg === '--delegate-did' && argv[i + 1]) {
      out.delegateDid = String(argv[++i]);
      continue;
    }
    if (arg === '--deploy-version' && argv[i + 1]) {
      out.deployVersion = String(argv[++i]);
      continue;
    }
  }

  return out;
}

function timestampForPath(date = new Date()) {
  return date.toISOString().replace(/:/g, '-').replace(/\./g, '-');
}

function toJsonText(value) {
  return JSON.stringify(value, null, 2);
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

  return {
    status: response.status,
    ok: response.ok,
    json,
    text,
    headers: Object.fromEntries(response.headers.entries()),
  };
}

function assertStatus(label, response, expected) {
  if (response.status !== expected) {
    throw new Error(`${label} expected HTTP ${expected}, got ${response.status}: ${JSON.stringify(response.json)}`);
  }
}

function assertCondition(label, condition, context) {
  if (!condition) {
    throw new Error(`${label} assertion failed: ${JSON.stringify(context)}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.env !== 'staging' && args.env !== 'prod') {
    throw new Error('--env must be staging or prod');
  }
  if (!args.adminKey) {
    throw new Error('CLAWDELEGATE_ADMIN_KEY is required (or pass --admin-key)');
  }
  if (!args.delegatorDid || !args.delegatorDid.startsWith('did:')) {
    throw new Error('CLAWDELEGATE_SMOKE_DELEGATOR_DID is required and must be a DID (or pass --delegator-did)');
  }
  if (!args.delegateDid || !args.delegateDid.startsWith('did:')) {
    throw new Error('CLAWDELEGATE_SMOKE_DELEGATE_DID is required and must be a DID (or pass --delegate-did)');
  }
  if (args.delegatorDid === args.delegateDid) {
    throw new Error('delegator and delegate DIDs must differ');
  }

  const baseUrl =
    args.baseUrl ||
    (args.env === 'prod'
      ? 'https://clawdelegate.com'
      : 'https://staging.clawdelegate.com');

  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const ts = timestampForPath();
  const outDir = args.outDir || path.join(root, 'artifacts', 'smoke', 'clawdelegate', `${ts}-${args.env}`);
  mkdirSync(outDir, { recursive: true });

  const aud = args.env === 'prod' ? ['clawproxy.com'] : ['staging.clawproxy.com'];
  const scope = ['proxy:call', 'clawproxy:call'];

  const now = Date.now();
  const idempotencyCreate = `dlg_smoke_create_${now}`;
  const idempotencySpend = `dlg_smoke_spend_${now}`;

  const authHeaders = {
    authorization: `Bearer ${args.adminKey}`,
    'content-type': 'application/json',
  };

  const createRes = await requestJson(`${baseUrl}/v1/delegations`, {
    method: 'POST',
    headers: authHeaders,
    body: {
      idempotency_key: idempotencyCreate,
      delegator_did: args.delegatorDid,
      delegate_did: args.delegateDid,
      aud,
      scope,
      ttl_seconds: 900,
      spend_cap_minor: '100',
      created_by: args.delegatorDid,
    },
  });
  assertStatus('delegation.create', createRes, 201);

  const delegation = createRes.json?.delegation;
  const delegationId = delegation?.delegation_id;
  assertCondition('delegation.id.present', typeof delegationId === 'string' && delegationId.startsWith('dlg_'), createRes.json);

  const getRes = await requestJson(`${baseUrl}/v1/delegations/${encodeURIComponent(delegationId)}`, {
    method: 'GET',
    headers: authHeaders,
  });
  assertStatus('delegation.get', getRes, 200);

  const approveRes = await requestJson(`${baseUrl}/v1/delegations/${encodeURIComponent(delegationId)}/approve`, {
    method: 'POST',
    headers: authHeaders,
    body: {
      approved_by: args.delegatorDid,
    },
  });
  assertStatus('delegation.approve', approveRes, 200);

  const issueRes = await requestJson(`${baseUrl}/v1/delegations/${encodeURIComponent(delegationId)}/tokens/issue`, {
    method: 'POST',
    headers: authHeaders,
    body: {
      issued_by: args.delegatorDid,
      ttl_seconds: 300,
    },
  });
  assertStatus('delegation.issue', issueRes, 201);

  const tokenHash = issueRes.json?.token_hash;
  const tokenScopeHash = issueRes.json?.token_scope_hash_b64u;
  assertCondition('delegation.issue.token_hash', typeof tokenHash === 'string' && /^[a-f0-9]{64}$/.test(tokenHash), issueRes.json);
  assertCondition('delegation.issue.token_scope_hash', typeof tokenScopeHash === 'string' && /^[A-Za-z0-9_-]{43}$/.test(tokenScopeHash), issueRes.json);

  const spendAuthorize = await requestJson(`${baseUrl}/v1/delegations/${encodeURIComponent(delegationId)}/spend/authorize`, {
    method: 'POST',
    headers: authHeaders,
    body: {
      idempotency_key: idempotencySpend,
      actor_did: args.delegateDid,
      token_hash: tokenHash,
      token_scope_hash_b64u: tokenScopeHash,
      amount_minor: '5',
      reason: 'smoke-authorize',
    },
  });
  assertStatus('delegation.spend.authorize', spendAuthorize, 200);
  assertCondition(
    'delegation.spend.authorize.status',
    spendAuthorize.json?.result?.status === 'applied',
    spendAuthorize.json
  );

  const spendReplay = await requestJson(`${baseUrl}/v1/delegations/${encodeURIComponent(delegationId)}/spend/authorize`, {
    method: 'POST',
    headers: authHeaders,
    body: {
      idempotency_key: idempotencySpend,
      actor_did: args.delegateDid,
      token_hash: tokenHash,
      token_scope_hash_b64u: tokenScopeHash,
      amount_minor: '5',
      reason: 'smoke-authorize-replay',
    },
  });
  assertStatus('delegation.spend.replay', spendReplay, 200);
  assertCondition('delegation.spend.replay.status', spendReplay.json?.result?.status === 'already_applied', spendReplay.json);

  const auditRes = await requestJson(`${baseUrl}/v1/delegations/${encodeURIComponent(delegationId)}/audit?limit=50`, {
    method: 'GET',
    headers: authHeaders,
  });
  assertStatus('delegation.audit', auditRes, 200);

  const auditEvents = Array.isArray(auditRes.json?.events) ? auditRes.json.events : [];
  const auditTypes = auditEvents
    .map((event) => (typeof event?.event_type === 'string' ? event.event_type : null))
    .filter((value) => typeof value === 'string');

  assertCondition('delegation.audit.created', auditTypes.includes('delegation_created'), auditTypes);
  assertCondition('delegation.audit.approved', auditTypes.includes('delegation_approved'), auditTypes);
  assertCondition('delegation.audit.issued', auditTypes.includes('delegated_cst_issued'), auditTypes);
  assertCondition('delegation.audit.spend', auditTypes.includes('spend_authorize'), auditTypes);

  const exportRes = await requestJson(`${baseUrl}/v1/delegations/${encodeURIComponent(delegationId)}/audit/export?limit=200`, {
    method: 'GET',
    headers: authHeaders,
  });
  assertStatus('delegation.audit.export', exportRes, 200);
  assertCondition('delegation.audit.export.hash', typeof exportRes.headers['x-audit-sha256-b64u'] === 'string', exportRes.headers);

  const revokeRes = await requestJson(`${baseUrl}/v1/delegations/${encodeURIComponent(delegationId)}/revoke`, {
    method: 'POST',
    headers: authHeaders,
    body: {
      revoked_by: args.delegatorDid,
      reason: 'smoke-revoke',
    },
  });
  assertStatus('delegation.revoke', revokeRes, 200);

  const summary = {
    scenario: 'CDL-MAX-001 delegation control-plane smoke',
    env: args.env,
    base_url: baseUrl,
    deploy_version: args.deployVersion || null,
    delegation_id: delegationId,
    delegator_did: args.delegatorDid,
    delegate_did: args.delegateDid,
    checks: {
      create: createRes.status,
      get: getRes.status,
      approve: approveRes.status,
      issue: issueRes.status,
      spend_authorize: spendAuthorize.status,
      spend_replay: spendReplay.status,
      audit: auditRes.status,
      audit_export: exportRes.status,
      revoke: revokeRes.status,
    },
    assertions: {
      spend_applied: spendAuthorize.json?.result?.status === 'applied',
      spend_replay_idempotent: spendReplay.json?.result?.status === 'already_applied',
      audit_has_created: auditTypes.includes('delegation_created'),
      audit_has_approved: auditTypes.includes('delegation_approved'),
      audit_has_issued: auditTypes.includes('delegated_cst_issued'),
      audit_has_spend: auditTypes.includes('spend_authorize'),
      export_hash_header_present: typeof exportRes.headers['x-audit-sha256-b64u'] === 'string',
    },
    responses: {
      create: createRes.json,
      approve: approveRes.json,
      issue: {
        delegation_id: issueRes.json?.delegation_id,
        token_hash: issueRes.json?.token_hash,
        token_scope_hash_b64u: issueRes.json?.token_scope_hash_b64u,
        exp: issueRes.json?.exp,
      },
      spend_authorize: spendAuthorize.json,
      spend_replay: spendReplay.json,
      revoke: revokeRes.json,
    },
    generated_at: new Date().toISOString(),
  };

  const resultPath = path.join(outDir, 'result.json');
  writeFileSync(resultPath, toJsonText(summary));

  console.log(toJsonText({ ok: true, out_dir: outDir, result: resultPath, delegation_id: delegationId }));
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`[smoke-delegation-control-plane] ${message}`);
  process.exitCode = 1;
});
