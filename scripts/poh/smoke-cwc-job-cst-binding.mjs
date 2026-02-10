#!/usr/bin/env node

/**
 * Smoke test: POH-US-021 — CWC job-scoped CST binding (receipt non-transferability).
 *
 * Staging-only mutating flow:
 *   1) Create (or reuse) a WPC in clawcontrols (requires admin token).
 *   2) Register a worker (public) to obtain worker auth token.
 *   3) Inject TWO accepted CWC bounties directly into staging D1 (bypass cuts/escrow).
 *   4) Mint job CSTs via POST /v1/bounties/{id}/cst.
 *   5) Produce a gateway receipt using CST for bounty B, then submit to bounty A → MUST fail
 *      with CWC token_scope_hash mismatch.
 *   6) Produce a gateway receipt using CST for bounty A, then submit to bounty A → MUST succeed
 *      and move bounty A to pending_review.
 *   7) After pending_review, POST /v1/bounties/{id}/cst and POST /accept must fail with INVALID_STATUS.
 *
 * Usage:
 *   node scripts/poh/smoke-cwc-job-cst-binding.mjs --env staging \
 *     --provider openai --model gpt-4o-mini
 *
 * Required env vars:
 *   - OPENAI_API_KEY (when --provider openai)
 *   - CLAWCONTROLS_ADMIN_TOKEN (optional; else read from ~/.claw-secrets/clawcontrols/production/ADMIN_TOKEN.txt)
 *
 * Notes:
 * - Uses `wrangler d1 execute --remote --env staging` so you must be logged in with wrangler.
 * - This script intentionally avoids POST /v1/bounties (escrow/cuts side effects).
 */

import process from 'node:process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';

function parseArgs(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) continue;
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith('--')) {
      args.set(key, next);
      i++;
    } else {
      args.set(key, 'true');
    }
  }
  return args;
}

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERT_FAILED: ${msg}`);
}

function isRecord(x) {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function base64UrlEncode(bytes) {
  const base64 = Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function sha256B64u(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

async function hashJsonB64u(value) {
  const data = new TextEncoder().encode(JSON.stringify(value));
  return sha256B64u(data);
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }

  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let result = '';
  for (let i = 0; i < leadingZeros; i++) result += '1';
  for (let i = digits.length - 1; i >= 0; i--) result += BASE58_ALPHABET[digits[i]];
  return result;
}

async function didFromPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  const pubBytes = new Uint8Array(raw);
  const multicodec = new Uint8Array(2 + pubBytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(pubBytes, 2);
  return `did:key:z${base58Encode(multicodec)}`;
}

async function signEd25519(privateKey, messageBytes) {
  const sigBuffer = await crypto.subtle.sign('Ed25519', privateKey, messageBytes);
  return base64UrlEncode(new Uint8Array(sigBuffer));
}

/**
 * RFC 8785 — JSON Canonicalization Scheme (JCS)
 * Minimal implementation (matches the one used in services/clawbounties).
 */
function jcsCanonicalize(value) {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new Error('Non-finite number not allowed in JCS');
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map(jcsCanonicalize).join(',')}]`;
      }

      const obj = value;
      const keys = Object.keys(obj).sort();
      const parts = [];
      for (const k of keys) {
        parts.push(`${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`);
      }
      return `{${parts.join(',')}}`;
    }
    default:
      throw new Error(`Unsupported value type for JCS: ${typeof value}`);
  }
}

function normalizeStringList(values) {
  const out = [];
  for (const v of values) {
    const s = String(v).trim();
    if (!s) continue;
    out.push(s);
  }
  return Array.from(new Set(out)).sort();
}

async function computeTokenScopeHashB64uV1({ sub, aud, scope, policy_hash_b64u, mission_id }) {
  const audList = normalizeStringList([aud]);
  const scopeList = normalizeStringList(scope);

  const out = {
    token_version: '1',
    sub: sub.trim(),
    aud: audList,
    scope: scopeList,
  };

  if (typeof policy_hash_b64u === 'string' && policy_hash_b64u.trim().length > 0) {
    out.policy_hash_b64u = policy_hash_b64u.trim();
  }

  if (typeof mission_id === 'string' && mission_id.trim().length > 0) {
    out.mission_id = mission_id.trim();
  }

  return sha256B64u(new TextEncoder().encode(jcsCanonicalize(out)));
}

function sqlStringLiteral(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
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
  return { res, status: res.status, text, json };
}

const args = parseArgs(process.argv.slice(2));
const envName = (args.get('env') || 'staging').toLowerCase();
const provider = (args.get('provider') || 'openai').toLowerCase();
const model = args.get('model') || 'gpt-4o-mini';

const bountiesBaseUrl = envName === 'prod' || envName === 'production' ? 'https://clawbounties.com' : 'https://staging.clawbounties.com';
const proxyBaseUrl = envName === 'prod' || envName === 'production' ? 'https://clawproxy.com' : 'https://staging.clawproxy.com';
const controlsBaseUrl = 'https://clawcontrols.com';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const clawbountiesServiceDir = path.resolve(repoRoot, 'services/clawbounties');

function runWranglerD1Execute({ dbName, env, sql, json = false }) {
  const argv = ['d1', 'execute', dbName, '--remote', '--yes'];
  if (env) argv.push('--env', env);
  if (json) argv.push('--json');
  argv.push('--command', sql);

  const out = execFileSync('wrangler', argv, {
    cwd: clawbountiesServiceDir,
    encoding: 'utf-8',
    stdio: json ? ['ignore', 'pipe', 'pipe'] : 'inherit',
  });

  return out;
}

function readSecretFileOrEnv({ envVar, filePath }) {
  const fromEnv = process.env[envVar];
  if (fromEnv && fromEnv.trim().length > 0) return fromEnv.trim();

  if (filePath && existsSync(filePath)) {
    return readFileSync(filePath, 'utf-8').trim();
  }

  return null;
}

async function createWpcPolicy({ issuerDid }) {
  const adminToken = readSecretFileOrEnv({
    envVar: 'CLAWCONTROLS_ADMIN_TOKEN',
    filePath: path.join(os.homedir(), '.claw-secrets', 'clawcontrols', 'production', 'ADMIN_TOKEN.txt'),
  });

  assert(adminToken, 'Missing CLAWCONTROLS_ADMIN_TOKEN (or ~/.claw-secrets/clawcontrols/production/ADMIN_TOKEN.txt)');

  const wpc = {
    policy_version: '1',
    policy_id: `smoke_poh_us_021_${crypto.randomUUID()}`,
    issuer_did: issuerDid,
    allowed_providers: provider === 'openai' ? ['openai'] : provider === 'anthropic' ? ['anthropic'] : ['google'],
    allowed_models: [String(model)],
    receipt_privacy_mode: 'hash_only',
    metadata: { smoke: true, story: 'POH-US-021' },
  };

  const out = await httpJson(`${controlsBaseUrl}/v1/wpc`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${adminToken}`,
    },
    body: JSON.stringify({ wpc }),
  });

  assert(out.status === 200 || out.status === 201, `WPC create expected 200/201, got ${out.status}: ${out.text}`);
  assert(isRecord(out.json) && out.json.ok === true && typeof out.json.policy_hash_b64u === 'string', 'WPC create response missing policy_hash_b64u');

  return { policy_hash_b64u: out.json.policy_hash_b64u.trim() };
}

async function registerWorker({ did }) {
  const body = {
    worker_did: did,
    worker_version: 'smoke/0.1.0',
    listing: {
      name: 'Smoke worker (POH-US-021)',
      headline: 'Automated smoke tests',
      tags: ['smoke', 'cwc', 'poh-us-021'],
    },
    capabilities: {
      job_types: ['code'],
      languages: ['ts'],
      max_minutes: 5,
    },
    offers: {
      skills: ['did-work'],
      mcp: [],
    },
    pricing: {
      price_floor_minor: '1',
    },
    availability: {
      mode: 'manual',
      paused: false,
    },
  };

  const out = await httpJson(`${bountiesBaseUrl}/v1/workers/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body),
  });

  assert(out.status === 200 || out.status === 201, `worker register expected 200/201, got ${out.status}: ${out.text}`);
  assert(out.json && out.json.auth && typeof out.json.auth.token === 'string', 'worker register response missing auth.token');

  return { worker_id: out.json.worker_id, token: out.json.auth.token };
}

async function makeCwcEnvelopes({ buyerDid, buyerKeys, workerDid, workerKeys, policyHashB64u }) {
  const now = new Date().toISOString();

  const payload = {
    cwc_version: '1',
    cwc_id: `cwc_${crypto.randomUUID()}`,
    buyer_did: buyerDid,
    worker_did: workerDid,
    wpc_policy_hash_b64u: policyHashB64u,
    required_proof_tier: 'gateway',
    receipt_privacy_mode: 'hash_only',
    metadata: { smoke: true, story: 'POH-US-021' },
  };

  const payload_hash_b64u = await sha256B64u(new TextEncoder().encode(jcsCanonicalize(payload)));

  const buyerSig = await signEd25519(buyerKeys.privateKey, new TextEncoder().encode(payload_hash_b64u));
  const workerSig = await signEd25519(workerKeys.privateKey, new TextEncoder().encode(payload_hash_b64u));

  const buyerEnvelope = {
    envelope_version: '1',
    envelope_type: 'confidential_work_contract',
    payload,
    payload_hash_b64u,
    hash_algorithm: 'SHA-256',
    signature_b64u: buyerSig,
    algorithm: 'Ed25519',
    signer_did: buyerDid,
    issued_at: now,
  };

  const workerEnvelope = {
    envelope_version: '1',
    envelope_type: 'confidential_work_contract',
    payload,
    payload_hash_b64u,
    hash_algorithm: 'SHA-256',
    signature_b64u: workerSig,
    algorithm: 'Ed25519',
    signer_did: workerDid,
    issued_at: now,
  };

  return { payload, payload_hash_b64u, buyerEnvelope, workerEnvelope };
}

function insertAcceptedCwcBountyStaging({
  bountyId,
  title,
  requesterDid,
  workerDid,
  cwc,
  tokenScopeHashB64u,
}) {
  const now = new Date().toISOString();
  const rewardMinor = '1000';

  const tagsJson = JSON.stringify(['smoke', 'cwc', 'poh-us-021']);
  const metadataJson = JSON.stringify({ smoke: true, requested_worker_did: workerDid });

  // Minimal objects used by clawbounties code paths.
  const feeQuoteJson = JSON.stringify({ quote: { worker_net_minor: rewardMinor, principal_minor: rewardMinor, buyer_total_minor: rewardMinor, fees: [] }, policy: { id: 'smoke', version: 'smoke', hash_b64u: 'smoke' } });
  const allInCostJson = JSON.stringify({ principal_minor: rewardMinor, platform_fee_minor: '0', total_minor: rewardMinor, currency: 'USD' });

  const sql = `INSERT INTO bounties (
    bounty_id,
    create_idempotency_key,
    requester_did,
    title,
    description,
    reward_amount_minor,
    reward_currency,
    closure_type,
    difficulty_scalar,
    is_code_bounty,
    tags_json,
    min_proof_tier,
    require_owner_verified_votes,
    test_harness_id,
    metadata_json,
    cwc_hash_b64u,
    cwc_wpc_policy_hash_b64u,
    cwc_required_proof_tier,
    cwc_token_scope_hash_b64u,
    cwc_buyer_envelope_json,
    cwc_worker_envelope_json,
    fee_quote_json,
    fee_policy_version,
    all_in_cost_json,
    escrow_id,
    status,
    created_at,
    updated_at,
    worker_did,
    accept_idempotency_key,
    accepted_at
  ) VALUES (
    ${sqlStringLiteral(bountyId)},
    ${sqlStringLiteral(`post:smoke:${crypto.randomUUID()}`)},
    ${sqlStringLiteral(requesterDid)},
    ${sqlStringLiteral(title)},
    ${sqlStringLiteral('Smoke test bounty (injected)')},
    ${sqlStringLiteral(rewardMinor)},
    ${sqlStringLiteral('USD')},
    ${sqlStringLiteral('requester')},
    1.0,
    0,
    ${sqlStringLiteral(tagsJson)},
    ${sqlStringLiteral('gateway')},
    0,
    NULL,
    ${sqlStringLiteral(metadataJson)},
    ${sqlStringLiteral(cwc.payload_hash_b64u)},
    ${sqlStringLiteral(cwc.payload.wpc_policy_hash_b64u)},
    ${sqlStringLiteral('gateway')},
    ${sqlStringLiteral(tokenScopeHashB64u)},
    ${sqlStringLiteral(JSON.stringify(cwc.buyerEnvelope))},
    ${sqlStringLiteral(JSON.stringify(cwc.workerEnvelope))},
    ${sqlStringLiteral(feeQuoteJson)},
    ${sqlStringLiteral('smoke')},
    ${sqlStringLiteral(allInCostJson)},
    ${sqlStringLiteral(`escrow_smoke_${crypto.randomUUID()}`)},
    ${sqlStringLiteral('accepted')},
    ${sqlStringLiteral(now)},
    ${sqlStringLiteral(now)},
    ${sqlStringLiteral(workerDid)},
    ${sqlStringLiteral(`accept:smoke:${crypto.randomUUID()}`)},
    ${sqlStringLiteral(now)}
  );`;

  runWranglerD1Execute({ dbName: 'clawbounties-staging', env: 'staging', sql });
}

async function issueBountyCst({ bountyId, workerToken }) {
  const out = await httpJson(`${bountiesBaseUrl}/v1/bounties/${bountyId}/cst`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${workerToken}`,
    },
  });

  assert(out.status === 200, `issue CST expected 200, got ${out.status}: ${out.text}`);
  assert(isRecord(out.json) && isRecord(out.json.cwc_auth) && typeof out.json.cwc_auth.cst === 'string', 'issue CST response missing cwc_auth.cst');

  return {
    cst: out.json.cwc_auth.cst.trim(),
    token_scope_hash_b64u: out.json.cwc_auth.token_scope_hash_b64u.trim(),
    policy_hash_b64u: out.json.cwc_auth.policy_hash_b64u.trim(),
  };
}

function buildEventChain({ runId }) {
  const now = new Date();
  const t0 = new Date(now.getTime()).toISOString();
  const t1 = new Date(now.getTime() + 500).toISOString();
  const t2 = new Date(now.getTime() + 1000).toISOString();

  return (async () => {
    const e1PayloadHash = await hashJsonB64u({ type: 'run_start' });
    const e1Header = {
      event_id: `evt_${crypto.randomUUID()}`,
      run_id: runId,
      event_type: 'run_start',
      timestamp: t0,
      payload_hash_b64u: e1PayloadHash,
      prev_hash_b64u: null,
    };
    const e1Hash = await hashJsonB64u(e1Header);

    const e2PayloadHash = await hashJsonB64u({ type: 'llm_call', provider, model });
    const e2Header = {
      event_id: `evt_${crypto.randomUUID()}`,
      run_id: runId,
      event_type: 'llm_call',
      timestamp: t1,
      payload_hash_b64u: e2PayloadHash,
      prev_hash_b64u: e1Hash,
    };
    const e2Hash = await hashJsonB64u(e2Header);

    const e3PayloadHash = await hashJsonB64u({ type: 'run_end' });
    const e3Header = {
      event_id: `evt_${crypto.randomUUID()}`,
      run_id: runId,
      event_type: 'run_end',
      timestamp: t2,
      payload_hash_b64u: e3PayloadHash,
      prev_hash_b64u: e2Hash,
    };
    const e3Hash = await hashJsonB64u(e3Header);

    const eventChain = [
      { ...e1Header, event_hash_b64u: e1Hash },
      { ...e2Header, event_hash_b64u: e2Hash },
      { ...e3Header, event_hash_b64u: e3Hash },
    ];

    return { eventChain, llmEventHash: e2Hash };
  })();
}

async function callClawproxy({ cst, runId, eventHash, nonce }) {
  let providerKey = null;
  if (provider === 'openai') providerKey = process.env.OPENAI_API_KEY;
  if (provider === 'anthropic') providerKey = process.env.ANTHROPIC_API_KEY;
  if (provider === 'google') providerKey = process.env.GOOGLE_API_KEY;

  assert(providerKey && providerKey.trim().length > 0, `Missing provider API key env var for provider=${provider} (expected OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_API_KEY)`);

  const url = provider === 'openai'
    ? `${proxyBaseUrl}/v1/chat/completions`
    : provider === 'anthropic'
      ? `${proxyBaseUrl}/v1/messages`
      : `${proxyBaseUrl}/v1/chat/completions`;

  // Use OpenAI-compatible payload for openai. For other providers this script may need adjustment.
  const body = {
    model,
    messages: [{ role: 'user', content: 'smoke: POH-US-021' }],
    max_tokens: 1,
    temperature: 0,
  };

  const out = await httpJson(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-cst': cst,
      'x-provider-api-key': providerKey.trim(),
      'x-run-id': runId,
      'x-event-hash': eventHash,
      'x-idempotency-key': nonce,
    },
    body: JSON.stringify(body),
  });

  assert(out.status === 200, `clawproxy call expected 200, got ${out.status}: ${out.text}`);
  assert(isRecord(out.json) && out.json._receipt_envelope, 'clawproxy response missing _receipt_envelope');

  return out.json._receipt_envelope;
}

async function buildProofBundleEnvelope({ agentDid, privateKey, eventChain, receiptEnvelope }) {
  const harness = { id: 'smoke', version: '1', runtime: 'host' };
  const configHash = await hashJsonB64u(harness);

  const payload = {
    bundle_version: '1',
    bundle_id: `bundle_${crypto.randomUUID()}`,
    agent_did: agentDid,
    event_chain: eventChain,
    receipts: [receiptEnvelope],
    metadata: {
      harness: {
        id: harness.id,
        version: harness.version,
        runtime: harness.runtime,
        config_hash_b64u: configHash,
      },
    },
  };

  const payloadHash = await hashJsonB64u(payload);
  const signature = await signEd25519(privateKey, new TextEncoder().encode(payloadHash));

  return {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: agentDid,
    issued_at: new Date().toISOString(),
  };
}

async function submit({ bountyId, workerDid, workerToken, proofBundleEnvelope, idempotencyKey }) {
  const body = {
    worker_did: workerDid,
    idempotency_key: idempotencyKey,
    proof_bundle_envelope: proofBundleEnvelope,
    artifacts: [],
    result_summary: 'smoke submission',
  };

  return httpJson(`${bountiesBaseUrl}/v1/bounties/${bountyId}/submit`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${workerToken}`,
    },
    body: JSON.stringify(body),
  });
}

async function acceptIdempotent({ bountyId, workerDid, workerToken }) {
  const body = {
    worker_did: workerDid,
    idempotency_key: `accept:smoke:${crypto.randomUUID()}`,
  };

  return httpJson(`${bountiesBaseUrl}/v1/bounties/${bountyId}/accept`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${workerToken}`,
    },
    body: JSON.stringify(body),
  });
}

async function main() {
  // Non-mutating check
  const health = await httpJson(`${bountiesBaseUrl}/health`, { method: 'GET' });
  assert(health.status === 200, `health expected 200, got ${health.status}`);
  assert(health.json && health.json.status === 'ok', 'health body invalid');

  if (envName === 'prod' || envName === 'production') {
    console.log(JSON.stringify({ ok: true, env: envName, mode: 'non_mutating' }, null, 2));
    return;
  }

  // 1) Generate buyer + worker DIDs
  const buyerKeys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const workerKeys = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

  const buyerDid = await didFromPublicKey(buyerKeys.publicKey);
  const workerDid = await didFromPublicKey(workerKeys.publicKey);

  // 2) Create WPC policy in registry
  const wpc = await createWpcPolicy({ issuerDid: buyerDid });

  // 3) Register worker (get auth token)
  const workerAuth = await registerWorker({ did: workerDid });

  // 4) Create CWC envelopes (buyer + worker)
  const cwc = await makeCwcEnvelopes({
    buyerDid,
    buyerKeys,
    workerDid,
    workerKeys,
    policyHashB64u: wpc.policy_hash_b64u,
  });

  // 5) Inject 2 accepted bounties
  const bountyA = `bty_${crypto.randomUUID()}`;
  const bountyB = `bty_${crypto.randomUUID()}`;

  const tokenScopeA = await computeTokenScopeHashB64uV1({
    sub: workerDid,
    aud: 'clawproxy.com',
    scope: ['proxy:call', 'clawproxy:call'],
    policy_hash_b64u: wpc.policy_hash_b64u,
    mission_id: bountyA,
  });

  const tokenScopeB = await computeTokenScopeHashB64uV1({
    sub: workerDid,
    aud: 'clawproxy.com',
    scope: ['proxy:call', 'clawproxy:call'],
    policy_hash_b64u: wpc.policy_hash_b64u,
    mission_id: bountyB,
  });

  insertAcceptedCwcBountyStaging({
    bountyId: bountyA,
    title: 'Smoke CWC bounty A (POH-US-021)',
    requesterDid: buyerDid,
    workerDid,
    cwc,
    tokenScopeHashB64u: tokenScopeA,
  });

  insertAcceptedCwcBountyStaging({
    bountyId: bountyB,
    title: 'Smoke CWC bounty B (POH-US-021)',
    requesterDid: buyerDid,
    workerDid,
    cwc,
    tokenScopeHashB64u: tokenScopeB,
  });

  // 6) Mint CSTs
  const cstA = await issueBountyCst({ bountyId: bountyA, workerToken: workerAuth.token });
  const cstB = await issueBountyCst({ bountyId: bountyB, workerToken: workerAuth.token });

  assert(cstA.token_scope_hash_b64u === tokenScopeA, 'CST A token_scope_hash_b64u mismatch vs expected');
  assert(cstB.token_scope_hash_b64u === tokenScopeB, 'CST B token_scope_hash_b64u mismatch vs expected');

  // 7) Produce receipt for B, submit to A (must fail token_scope)
  const runB = `run_${crypto.randomUUID()}`;
  const chainB = await buildEventChain({ runId: runB });

  const receiptB = await callClawproxy({
    cst: cstB.cst,
    runId: runB,
    eventHash: chainB.llmEventHash,
    nonce: `nonce_${crypto.randomUUID()}`,
  });

  const bundleB = await buildProofBundleEnvelope({
    agentDid: workerDid,
    privateKey: workerKeys.privateKey,
    eventChain: chainB.eventChain,
    receiptEnvelope: receiptB,
  });

  const mismatchSubmit = await submit({
    bountyId: bountyA,
    workerDid,
    workerToken: workerAuth.token,
    proofBundleEnvelope: bundleB,
    idempotencyKey: `submit:smoke:mismatch:${crypto.randomUUID()}`,
  });

  assert(mismatchSubmit.status === 422, `mismatch submit expected 422, got ${mismatchSubmit.status}: ${mismatchSubmit.text}`);

  // 8) Produce receipt for A, submit to A (must succeed)
  const runA = `run_${crypto.randomUUID()}`;
  const chainA = await buildEventChain({ runId: runA });

  const receiptA = await callClawproxy({
    cst: cstA.cst,
    runId: runA,
    eventHash: chainA.llmEventHash,
    nonce: `nonce_${crypto.randomUUID()}`,
  });

  const bundleA = await buildProofBundleEnvelope({
    agentDid: workerDid,
    privateKey: workerKeys.privateKey,
    eventChain: chainA.eventChain,
    receiptEnvelope: receiptA,
  });

  const okSubmit = await submit({
    bountyId: bountyA,
    workerDid,
    workerToken: workerAuth.token,
    proofBundleEnvelope: bundleA,
    idempotencyKey: `submit:smoke:ok:${crypto.randomUUID()}`,
  });

  assert(okSubmit.status === 201, `ok submit expected 201, got ${okSubmit.status}: ${okSubmit.text}`);

  // 9) After submission, bounty A should no longer be in accepted state.
  // /cst and /accept must fail closed.
  const cstAfter = await httpJson(`${bountiesBaseUrl}/v1/bounties/${bountyA}/cst`, {
    method: 'POST',
    headers: { authorization: `Bearer ${workerAuth.token}` },
  });

  const acceptAfter = await acceptIdempotent({ bountyId: bountyA, workerDid, workerToken: workerAuth.token });

  // Expect 409 INVALID_STATUS (once POH-US-021 follow-up gating is deployed)
  assert(cstAfter.status === 409, `post-submit /cst expected 409, got ${cstAfter.status}: ${cstAfter.text}`);
  assert(acceptAfter.status === 409, `post-submit /accept expected 409, got ${acceptAfter.status}: ${acceptAfter.text}`);

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        bountyA,
        bountyB,
        policy_hash_b64u: wpc.policy_hash_b64u,
        token_scope_hash_a: tokenScopeA,
        token_scope_hash_b: tokenScopeB,
        mismatch_submit_status: mismatchSubmit.status,
        ok_submit_status: okSubmit.status,
        post_submit_cst_status: cstAfter.status,
        post_submit_accept_status: acceptAfter.status,
      },
      null,
      2,
    ),
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
