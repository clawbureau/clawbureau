#!/usr/bin/env node

/**
 * Smoke test: Marketplace sandbox-tier submissions (CEA-US-010 wiring)
 *
 * Staging-only mutating flow:
 *  1) Register a worker (public) to obtain worker auth token.
 *  2) Inject an ACCEPTED bounty into staging D1 with min_proof_tier = "sandbox".
 *     - We intentionally bypass POST /v1/bounties + /accept to avoid cuts/escrow side effects.
 *  3) Mint a job-scoped CST via POST /v1/bounties/{id}/cst.
 *  4) Produce a gateway receipt via clawproxy (CST-bound) and build a gateway-tier proof bundle.
 *  5) Submit WITHOUT execution_attestations → expect 422 (min_proof_tier sandbox not met; tier should be gateway).
 *  6) Produce a second gateway-tier proof bundle, mint execution attestation from clawea, then submit WITH
 *     execution_attestations[] → expect 201 and stored proof_tier = "sandbox".
 *  7) Query staging D1 to confirm execution_attestations_json was persisted.
 *
 * Usage:
 *   OPENAI_API_KEY=... CLAWEA_TENANT_KEY=... node scripts/poh/smoke-marketplace-sandbox-execution-attestation.mjs \
 *     --env staging --clawea-agent <claweaAgentId> --provider openai --model gpt-4o-mini
 *
 * Notes:
 * - Requires wrangler login (uses: wrangler d1 execute --remote --env staging).
 */

import process from 'node:process';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

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

  let out = '';
  for (let i = 0; i < leadingZeros; i++) out += '1';
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]];
  return out;
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
const claweaAgentId = args.get('clawea-agent') || process.env.CLAWEA_AGENT_ID;

assert(envName === 'staging', 'This smoke is staging-only (mutating)');
assert(typeof claweaAgentId === 'string' && claweaAgentId.trim().length > 0, 'Missing --clawea-agent <id> (or CLAWEA_AGENT_ID)');

const bountiesBaseUrl = 'https://staging.clawbounties.com';
const proxyBaseUrl = 'https://staging.clawproxy.com';
const claweaBaseUrl = 'https://staging.clawea.com';

const tenantKey = process.env.CLAWEA_TENANT_KEY;
assert(typeof tenantKey === 'string' && tenantKey.trim().length > 0, 'Missing CLAWEA_TENANT_KEY');

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

function insertAcceptedBountyStaging({ workerDid, title }) {
  const bountyId = `bty_${crypto.randomUUID()}`;
  const now = new Date().toISOString();

  const rewardMinor = '1000';

  const tagsJson = JSON.stringify(['smoke', 'sandbox-tier']);
  const metadataJson = JSON.stringify({ smoke: true, story: 'marketplace-sandbox-tier' });
  const feeQuoteJson = JSON.stringify({ quote: { worker_net_minor: rewardMinor }, policy: { version: 'smoke' } });
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
    ${sqlStringLiteral('did:key:zSmokeRequester')},
    ${sqlStringLiteral(title)},
    ${sqlStringLiteral('Smoke bounty (injected; avoids cuts/escrow)')},
    ${sqlStringLiteral(rewardMinor)},
    ${sqlStringLiteral('USD')},
    ${sqlStringLiteral('requester')},
    1.0,
    0,
    ${sqlStringLiteral(tagsJson)},
    ${sqlStringLiteral('sandbox')},
    0,
    NULL,
    ${sqlStringLiteral(metadataJson)},
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
  return { bountyId };
}

async function registerWorker({ did }) {
  const body = {
    worker_did: did,
    worker_version: 'smoke/0.1.0',
    listing: {
      name: 'Smoke worker (sandbox-tier)',
      headline: 'smoke',
      tags: ['smoke'],
    },
    capabilities: {
      job_types: ['coding'],
      languages: ['ts'],
      max_minutes: 10,
    },
    offers: {
      skills: ['smoke'],
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
  assert(isRecord(out.json) && isRecord(out.json.auth) && typeof out.json.auth.token === 'string', 'worker register response missing auth.token');

  return { token: out.json.auth.token.trim() };
}

async function issueJobCst({ bountyId, workerToken }) {
  const out = await httpJson(`${bountiesBaseUrl}/v1/bounties/${bountyId}/cst`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${workerToken}`,
    },
  });

  assert(out.status === 200, `issue CST expected 200, got ${out.status}: ${out.text}`);

  const jobAuth = out.json?.job_auth;
  assert(isRecord(jobAuth) && typeof jobAuth.cst === 'string', 'issue CST response missing job_auth.cst');
  assert(typeof jobAuth.token_scope_hash_b64u === 'string', 'issue CST response missing job_auth.token_scope_hash_b64u');

  return {
    cst: jobAuth.cst.trim(),
    token_scope_hash_b64u: jobAuth.token_scope_hash_b64u.trim(),
  };
}

async function buildEventChain({ runId }) {
  const now = new Date();
  const t0 = new Date(now.getTime()).toISOString();
  const t1 = new Date(now.getTime() + 500).toISOString();
  const t2 = new Date(now.getTime() + 1000).toISOString();

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
}

async function callClawproxy({ cst, runId, eventHash, nonce }) {
  let providerKey = null;
  if (provider === 'openai') providerKey = process.env.OPENAI_API_KEY;
  if (provider === 'anthropic') providerKey = process.env.ANTHROPIC_API_KEY;
  if (provider === 'google') providerKey = process.env.GOOGLE_API_KEY;

  assert(providerKey && providerKey.trim().length > 0, `Missing provider API key env var for provider=${provider} (expected OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_API_KEY)`);

  const url =
    provider === 'openai'
      ? `${proxyBaseUrl}/v1/chat/completions`
      : provider === 'anthropic'
        ? `${proxyBaseUrl}/v1/messages`
        : `${proxyBaseUrl}/v1/proxy/google`;

  const body = {
    model,
    messages: [{ role: 'user', content: 'smoke: sandbox-tier submission' }],
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

async function submit({ bountyId, workerDid, workerToken, proofBundleEnvelope, executionAttestations, idempotencyKey }) {
  const body = {
    worker_did: workerDid,
    idempotency_key: idempotencyKey,
    proof_bundle_envelope: proofBundleEnvelope,
    artifacts: [],
    result_summary: 'smoke submission',
    ...(executionAttestations ? { execution_attestations: executionAttestations } : {}),
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

async function mintExecutionAttestation({ proofBundleEnvelope }) {
  const out = await httpJson(`${claweaBaseUrl}/v1/agents/${claweaAgentId}/execution-attestation`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${tenantKey}`,
    },
    body: JSON.stringify({ proof_bundle_envelope: proofBundleEnvelope }),
  });

  assert(out.status === 200, `clawea mint expected 200, got ${out.status}: ${out.text}`);
  assert(isRecord(out.json) && out.json.ok === true && isRecord(out.json.envelope), 'clawea mint response missing envelope');

  return out.json.envelope;
}

async function main() {
  // 1) Worker DID + token
  const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const workerDid = await didFromPublicKey(kp.publicKey);
  const workerToken = (await registerWorker({ did: workerDid })).token;

  // 2) Inject accepted bounty requiring sandbox tier
  const bountyTitle = `Smoke: sandbox-tier bounty (${new Date().toISOString()})`;
  const { bountyId } = insertAcceptedBountyStaging({ workerDid, title: bountyTitle });

  // 3) Job CST
  const { cst } = await issueJobCst({ bountyId, workerToken });

  // 4) Run A: gateway-tier bundle
  const runIdA = `run_${crypto.randomUUID()}`;
  const chainA = await buildEventChain({ runId: runIdA });
  const receiptA = await callClawproxy({
    cst,
    runId: runIdA,
    eventHash: chainA.llmEventHash,
    nonce: `nonce_${crypto.randomUUID()}`,
  });

  const bundleA = await buildProofBundleEnvelope({
    agentDid: workerDid,
    privateKey: kp.privateKey,
    eventChain: chainA.eventChain,
    receiptEnvelope: receiptA,
  });

  const subA = await submit({
    bountyId,
    workerDid,
    workerToken,
    proofBundleEnvelope: bundleA,
    executionAttestations: null,
    idempotencyKey: `submit:smoke:noatt:${crypto.randomUUID()}`,
  });

  assert(subA.status === 422, `submit without execution attestation expected 422, got ${subA.status}: ${subA.text}`);
  const tierA = subA.json?.verification?.proof_bundle?.tier ?? null;
  assert(tierA === 'gateway', `expected tier=gateway on 422, got ${tierA}`);

  // 5) Run B: gateway-tier bundle + execution attestation → sandbox
  const runIdB = `run_${crypto.randomUUID()}`;
  const chainB = await buildEventChain({ runId: runIdB });
  const receiptB = await callClawproxy({
    cst,
    runId: runIdB,
    eventHash: chainB.llmEventHash,
    nonce: `nonce_${crypto.randomUUID()}`,
  });

  const bundleB = await buildProofBundleEnvelope({
    agentDid: workerDid,
    privateKey: kp.privateKey,
    eventChain: chainB.eventChain,
    receiptEnvelope: receiptB,
  });

  const execEnvelope = await mintExecutionAttestation({ proofBundleEnvelope: bundleB });

  const subB = await submit({
    bountyId,
    workerDid,
    workerToken,
    proofBundleEnvelope: bundleB,
    executionAttestations: [execEnvelope],
    idempotencyKey: `submit:smoke:withatt:${crypto.randomUUID()}`,
  });

  assert(subB.status === 201, `submit with execution attestation expected 201, got ${subB.status}: ${subB.text}`);
  const tierB = subB.json?.verification?.proof_bundle?.tier ?? null;
  assert(tierB === 'sandbox', `expected tier=sandbox on 201, got ${tierB}`);

  const submissionIdB = subB.json?.submission_id;
  assert(typeof submissionIdB === 'string' && submissionIdB.startsWith('sub_'), 'submit response missing submission_id');

  // 6) Confirm persistence
  const sel = runWranglerD1Execute({
    dbName: 'clawbounties-staging',
    env: 'staging',
    json: true,
    sql: `SELECT submission_id, proof_tier, execution_attestations_json FROM submissions WHERE submission_id = ${sqlStringLiteral(submissionIdB)} LIMIT 1;`,
  });

  let persisted = null;
  try {
    const parsed = JSON.parse(sel);
    persisted = parsed?.[0]?.results?.[0] ?? null;
  } catch {
    persisted = null;
  }

  assert(persisted && typeof persisted.execution_attestations_json === 'string' && persisted.execution_attestations_json.length > 0, 'execution_attestations_json not persisted');

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        provider,
        model,
        bounty_id: bountyId,
        worker_did: workerDid,
        clawea_agent_id: claweaAgentId,
        submit_without_attestation: {
          status: subA.status,
          tier: tierA,
          reason: subA.json?.verification?.proof_bundle?.reason ?? null,
        },
        submit_with_attestation: {
          status: subB.status,
          tier: tierB,
          submission_id: submissionIdB,
        },
        persisted: {
          proof_tier: persisted?.proof_tier ?? null,
          execution_attestations_json_bytes: String(persisted.execution_attestations_json).length,
        },
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
