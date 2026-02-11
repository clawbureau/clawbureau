#!/usr/bin/env node

/**
 * Smoke test: Marketplace sandbox-tier submissions (CEA-US-010 wiring)
 *
 * Staging-only mutating flow:
 *  1) Register a worker (public) to obtain worker auth token.
 *  2) Inject an OPEN bounty into staging D1 with min_proof_tier = "sandbox" (avoid cuts/escrow side effects).
 *  3) Accept the bounty via API.
 *  4) Submit a valid self-tier proof bundle WITHOUT execution attestation → expect 422 (tier gate failure).
 *  5) Mint an execution attestation from clawea (bound to run_id + proof bundle hash).
 *  6) Submit again WITH execution_attestations[] → expect 201 and stored proof_tier = "sandbox".
 *  7) Query staging D1 to confirm execution_attestations_json was persisted.
 *
 * Usage:
 *   CLAWEA_TENANT_KEY=... node scripts/poh/smoke-marketplace-sandbox-execution-attestation.mjs \
 *     --env staging --clawea-agent <claweaAgentId>
 *
 * Notes:
 * - Requires wrangler login (uses: wrangler d1 execute --remote --env staging).
 * - Intentionally avoids POST /v1/bounties (cuts/escrow side effects).
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

function base64urlEncode(data) {
  return Buffer.from(data)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes) {
  if (bytes.length === 0) return '';

  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      const x = digits[i] * 256 + carry;
      digits[i] = x % 58;
      carry = Math.floor(x / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  // leading zeros
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((d) => BASE58_ALPHABET[d])
    .join('');
}

async function sha256B64uJson(value) {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return base64urlEncode(new Uint8Array(hash));
}

async function makeDidKeyEd25519() {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

  const publicKeyBytes = new Uint8Array(await crypto.subtle.exportKey('raw', keypair.publicKey));

  const prefixed = new Uint8Array(2 + publicKeyBytes.length);
  prefixed[0] = 0xed;
  prefixed[1] = 0x01;
  prefixed.set(publicKeyBytes, 2);

  const did = `did:key:z${base58Encode(prefixed)}`;
  return { did, privateKey: keypair.privateKey };
}

async function signB64uEd25519(privateKey, msg) {
  const msgBytes = new TextEncoder().encode(msg);
  const sigBuf = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, msgBytes);
  return base64urlEncode(new Uint8Array(sigBuf));
}

async function buildProofBundleEnvelope({ agentDid, agentPrivateKey, runId }) {
  // Minimal 1-event chain
  const e1PayloadHash = await sha256B64uJson({ type: 'llm_call' });
  const e1Header = {
    event_id: `evt_${crypto.randomUUID()}`,
    run_id: runId,
    event_type: 'llm_call',
    timestamp: new Date().toISOString(),
    payload_hash_b64u: e1PayloadHash,
    prev_hash_b64u: null,
  };
  const e1Hash = await sha256B64uJson(e1Header);

  const bundlePayload = {
    bundle_version: '1',
    bundle_id: `bundle_${crypto.randomUUID()}`,
    agent_did: agentDid,
    event_chain: [
      {
        ...e1Header,
        event_hash_b64u: e1Hash,
      },
    ],
  };

  const payloadHash = await sha256B64uJson(bundlePayload);
  const signature = await signB64uEd25519(agentPrivateKey, payloadHash);

  const envelope = {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload: bundlePayload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: agentDid,
    issued_at: new Date().toISOString(),
  };

  return { envelope, payloadHash };
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

function sqlStringLiteral(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

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

function insertOpenBountyStaging({ title, minProofTier }) {
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
    updated_at
  ) VALUES (
    ${sqlStringLiteral(bountyId)},
    ${sqlStringLiteral(`post:smoke:${crypto.randomUUID()}`)},
    ${sqlStringLiteral('did:key:zSmokeRequester')},
    ${sqlStringLiteral(title)},
    ${sqlStringLiteral('Smoke bounty (injected; avoid cuts/escrow side effects)')},
    ${sqlStringLiteral(rewardMinor)},
    ${sqlStringLiteral('USD')},
    ${sqlStringLiteral('requester')},
    1.0,
    0,
    ${sqlStringLiteral(tagsJson)},
    ${sqlStringLiteral(minProofTier)},
    0,
    NULL,
    ${sqlStringLiteral(metadataJson)},
    ${sqlStringLiteral(feeQuoteJson)},
    ${sqlStringLiteral('smoke')},
    ${sqlStringLiteral(allInCostJson)},
    ${sqlStringLiteral(`escrow_smoke_${crypto.randomUUID()}`)},
    ${sqlStringLiteral('open')},
    ${sqlStringLiteral(now)},
    ${sqlStringLiteral(now)}
  );`;

  runWranglerD1Execute({ dbName: 'clawbounties-staging', env: 'staging', sql });

  return { bountyId };
}

async function registerWorker({ baseUrl, did }) {
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

  const out = await httpJson(`${baseUrl}/v1/workers/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body),
  });

  assert(out.status === 200 || out.status === 201, `worker register expected 200/201, got ${out.status}: ${out.text}`);
  assert(isRecord(out.json) && isRecord(out.json.auth) && typeof out.json.auth.token === 'string', 'worker register response missing auth.token');

  return { token: out.json.auth.token };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = (args.get('env') || 'staging').toLowerCase();
  const claweaAgentId = args.get('clawea-agent') || process.env.CLAWEA_AGENT_ID;

  assert(envName === 'staging', 'This smoke script is staging-only (mutating)');

  const bountiesBaseUrl = 'https://staging.clawbounties.com';
  const claweaBaseUrl = 'https://staging.clawea.com';

  const tenantKey = process.env.CLAWEA_TENANT_KEY;
  assert(typeof tenantKey === 'string' && tenantKey.trim().length > 0, 'Missing CLAWEA_TENANT_KEY');
  assert(typeof claweaAgentId === 'string' && claweaAgentId.trim().length > 0, 'Missing --clawea-agent <id> (or CLAWEA_AGENT_ID)');

  // 1) Worker DID + token
  const worker = await makeDidKeyEd25519();
  const reg = await registerWorker({ baseUrl: bountiesBaseUrl, did: worker.did });

  // 2) Inject open bounty (sandbox tier)
  const bountyTitle = `Smoke: sandbox-tier submission (${new Date().toISOString()})`;
  const injected = insertOpenBountyStaging({ title: bountyTitle, minProofTier: 'sandbox' });

  // 3) Accept via API
  const accept = await httpJson(`${bountiesBaseUrl}/v1/bounties/${injected.bountyId}/accept`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${reg.token}`,
    },
    body: JSON.stringify({
      idempotency_key: `accept:smoke:${crypto.randomUUID()}`,
      worker_did: worker.did,
    }),
  });

  assert(accept.status === 200 || accept.status === 201, `accept expected 200/201, got ${accept.status}: ${accept.text}`);

  // 4) Build minimal proof bundle (self-tier)
  const runId = `run_${crypto.randomUUID()}`;
  const { envelope: proofBundleEnvelope } = await buildProofBundleEnvelope({
    agentDid: worker.did,
    agentPrivateKey: worker.privateKey,
    runId,
  });

  const submitNoAtt = await httpJson(`${bountiesBaseUrl}/v1/bounties/${injected.bountyId}/submit`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${reg.token}`,
    },
    body: JSON.stringify({
      worker_did: worker.did,
      idempotency_key: `submit:smoke:noatt:${crypto.randomUUID()}`,
      proof_bundle_envelope: proofBundleEnvelope,
      artifacts: [],
      result_summary: 'smoke: missing execution attestation',
    }),
  });

  assert(submitNoAtt.status === 422, `submit without execution attestation expected 422, got ${submitNoAtt.status}: ${submitNoAtt.text}`);

  // 5) Mint execution attestation
  const mint = await httpJson(`${claweaBaseUrl}/v1/agents/${claweaAgentId}/execution-attestation`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${tenantKey}`,
    },
    body: JSON.stringify({ proof_bundle_envelope: proofBundleEnvelope }),
  });

  assert(mint.status === 200, `clawea mint expected 200, got ${mint.status}: ${mint.text}`);
  assert(isRecord(mint.json) && mint.json.ok === true && isRecord(mint.json.envelope), 'clawea mint response missing envelope');

  const execEnvelope = mint.json.envelope;

  // 6) Submit with execution attestation
  const submitWithAtt = await httpJson(`${bountiesBaseUrl}/v1/bounties/${injected.bountyId}/submit`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${reg.token}`,
    },
    body: JSON.stringify({
      worker_did: worker.did,
      idempotency_key: `submit:smoke:withatt:${crypto.randomUUID()}`,
      proof_bundle_envelope: proofBundleEnvelope,
      execution_attestations: [execEnvelope],
      artifacts: [],
      result_summary: 'smoke: sandbox attested',
    }),
  });

  assert(submitWithAtt.status === 201, `submit with execution attestation expected 201, got ${submitWithAtt.status}: ${submitWithAtt.text}`);
  assert(isRecord(submitWithAtt.json) && isRecord(submitWithAtt.json.verification) && isRecord(submitWithAtt.json.verification.proof_bundle), 'submit response missing verification');
  const tier = submitWithAtt.json.verification.proof_bundle.tier;
  assert(tier === 'sandbox', `expected stored tier sandbox, got ${tier}`);

  const submissionId = submitWithAtt.json.submission_id;
  assert(typeof submissionId === 'string' && submissionId.startsWith('sub_'), 'submit response missing submission_id');

  // 7) Confirm evidence persisted
  const sel = runWranglerD1Execute({
    dbName: 'clawbounties-staging',
    env: 'staging',
    json: true,
    sql: `SELECT submission_id, proof_tier, execution_attestations_json FROM submissions WHERE submission_id = ${sqlStringLiteral(submissionId)} LIMIT 1;`,
  });

  let persisted = null;
  try {
    const parsed = JSON.parse(sel);
    const row = parsed?.[0]?.results?.[0];
    persisted = row ?? null;
  } catch {
    persisted = null;
  }

  assert(persisted && typeof persisted.execution_attestations_json === 'string' && persisted.execution_attestations_json.length > 0, 'execution_attestations_json not persisted');

  const out = {
    ok: true,
    env: envName,
    bounty_id: injected.bountyId,
    submission_id: submissionId,
    worker_did: worker.did,
    clawea_agent_id: claweaAgentId,
    submit_without_attestation: {
      status: submitNoAtt.status,
      proof_tier: submitNoAtt.json?.verification?.proof_bundle?.tier ?? null,
      reason: submitNoAtt.json?.verification?.proof_bundle?.reason ?? null,
    },
    submit_with_attestation: {
      status: submitWithAtt.status,
      proof_tier: tier,
    },
    persisted: {
      proof_tier: persisted?.proof_tier ?? null,
      execution_attestations_json_bytes: persisted?.execution_attestations_json ? String(persisted.execution_attestations_json).length : 0,
    },
  };

  console.log(JSON.stringify(out, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
