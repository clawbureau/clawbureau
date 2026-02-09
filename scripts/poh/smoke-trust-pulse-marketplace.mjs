#!/usr/bin/env node

/**
 * Smoke test: Trust Pulse storage + retrieval in clawbounties.
 *
 * This script exercises the end-to-end path:
 *  - register worker
 *  - create an accepted bounty (via D1 injection on staging)
 *  - submit a proof bundle + URM + trust_pulse
 *  - fetch stored trust_pulse by submission_id (worker auth)
 *  - verify auth gating + error cases
 *
 * Usage:
 *   node scripts/poh/smoke-trust-pulse-marketplace.mjs --env staging
 *   node scripts/poh/smoke-trust-pulse-marketplace.mjs --env prod
 */

import process from 'node:process';
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

const args = parseArgs(process.argv.slice(2));
const envName = (args.get('env') || 'staging').toLowerCase();

const baseUrl =
  envName === 'prod' || envName === 'production'
    ? 'https://clawbounties.com'
    : 'https://staging.clawbounties.com';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const clawbountiesServiceDir = path.resolve(repoRoot, 'services/clawbounties');

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

function sqlStringLiteral(value) {
  // D1 uses SQLite string literal rules.
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

async function registerWorker({ did }) {
  const body = {
    worker_did: did,
    worker_version: 'smoke/0.1.0',
    listing: {
      name: 'Smoke worker',
      headline: 'Automated smoke tests',
      tags: ['smoke', 'trust-pulse'],
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

  const out = await httpJson(`${baseUrl}/v1/workers/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body),
  });

  assert(out.status === 200 || out.status === 201, `worker register expected 200/201, got ${out.status}: ${out.text}`);
  assert(out.json && out.json.auth && typeof out.json.auth.token === 'string', 'worker register response missing auth.token');

  return { worker_id: out.json.worker_id, token: out.json.auth.token };
}

function runWranglerD1Execute({ dbName, env, sql }) {
  const args = ['d1', 'execute', dbName, '--remote'];
  if (env) args.push('--env', env);
  args.push('--command', sql);

  execFileSync('wrangler', args, {
    cwd: clawbountiesServiceDir,
    stdio: 'inherit',
  });
}

function insertAcceptedBountyStaging({ workerDid, title }) {
  const bountyId = `bty_${crypto.randomUUID()}`;
  const now = new Date().toISOString();

  const rewardMinor = '1000';

  const tagsJson = JSON.stringify(['smoke', 'trust-pulse']);
  const metadataJson = JSON.stringify({ smoke: true });
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
    ${sqlStringLiteral('Smoke test bounty (injected)')},
    ${sqlStringLiteral(rewardMinor)},
    ${sqlStringLiteral('USD')},
    ${sqlStringLiteral('requester')},
    1.0,
    0,
    ${sqlStringLiteral(tagsJson)},
    ${sqlStringLiteral('self')},
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

async function buildTrustPulse({ runId, agentDid }) {
  const now = new Date().toISOString();
  return {
    trust_pulse_version: '1',
    trust_pulse_id: `tp_${crypto.randomUUID()}`,
    run_id: runId,
    agent_did: agentDid,
    issued_at: now,
    evidence_class: 'self_reported',
    tier_uplift: false,
    started_at: now,
    ended_at: now,
    duration_ms: 0,
    tools: [{ name: 'smoke', calls: 1 }],
    files: [{ path: 'README.md', touches: 1 }],
  };
}

async function buildProofArtifacts({ agentDid, privateKey, trustPulse, trustPulsePointerHashOverride }) {
  const runId = trustPulse.run_id;
  const now = new Date();

  const t0 = new Date(now.getTime()).toISOString();
  const t1 = new Date(now.getTime() + 1000).toISOString();
  const t2 = new Date(now.getTime() + 2000).toISOString();

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

  const e2PayloadHash = await hashJsonB64u({ type: 'llm_call', model: 'smoke-model' });
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

  const trustPulseHash = await hashJsonB64u(trustPulse);

  const trustPulsePointer = {
    schema: 'https://schemas.clawbureau.org/claw.poh.trust_pulse.v1.json',
    artifact_hash_b64u: trustPulsePointerHashOverride ?? trustPulseHash,
    evidence_class: 'self_reported',
    tier_uplift: false,
  };

  const harness = { id: 'smoke', version: '1', runtime: 'host' };
  const configHash = await hashJsonB64u(harness);

  const urm = {
    urm_version: '1',
    urm_id: `urm_${crypto.randomUUID()}`,
    run_id: runId,
    agent_did: agentDid,
    issued_at: new Date(now.getTime() + 2500).toISOString(),
    harness: {
      id: harness.id,
      version: harness.version,
      runtime: harness.runtime,
      config_hash_b64u: configHash,
    },
    inputs: [],
    outputs: [
      {
        type: 'trust_pulse',
        hash_b64u: trustPulseHash,
        content_type: 'application/json',
        metadata: trustPulsePointer,
      },
    ],
    event_chain_root_hash_b64u: eventChain[0].event_hash_b64u,
    metadata: {
      trust_pulse: trustPulsePointer,
    },
  };

  const urmHash = await hashJsonB64u(urm);
  const urmRef = {
    urm_version: '1',
    urm_id: urm.urm_id,
    resource_type: 'universal_run_manifest',
    resource_hash_b64u: urmHash,
  };

  const payload = {
    bundle_version: '1',
    bundle_id: `bundle_${crypto.randomUUID()}`,
    agent_did: agentDid,
    urm: urmRef,
    event_chain: eventChain,
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
  const sigMsg = new TextEncoder().encode(payloadHash);
  const signature = await signEd25519(privateKey, sigMsg);

  const envelope = {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: agentDid,
    issued_at: new Date(now.getTime() + 3000).toISOString(),
  };

  return {
    runId,
    trustPulseHash,
    envelope,
    urm,
  };
}

async function submit({ bountyId, workerDid, workerToken, proofBundleEnvelope, urm, trustPulse, idempotencyKey }) {
  const body = {
    worker_did: workerDid,
    idempotency_key: idempotencyKey,
    proof_bundle_envelope: proofBundleEnvelope,
    urm,
    artifacts: [],
    result_summary: 'smoke submission',
    ...(trustPulse ? { trust_pulse: trustPulse } : {}),
  };

  const out = await httpJson(`${baseUrl}/v1/bounties/${bountyId}/submit`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=utf-8',
      authorization: `Bearer ${workerToken}`,
    },
    body: JSON.stringify(body),
  });

  return out;
}

async function getStoredTrustPulse({ submissionId, token }) {
  return httpJson(`${baseUrl}/v1/submissions/${submissionId}/trust-pulse`, {
    method: 'GET',
    headers: { authorization: `Bearer ${token}` },
  });
}

async function nonMutatingChecks() {
  const health = await httpJson(`${baseUrl}/health`, { method: 'GET' });
  assert(health.status === 200, `health expected 200, got ${health.status}`);
  assert(health.json && health.json.status === 'ok', 'health body invalid');

  const viewer = await httpJson(`${baseUrl}/trust-pulse?submission_id=sub_00000000-0000-0000-0000-000000000000`, { method: 'GET' });
  assert(viewer.status === 200, `viewer expected 200, got ${viewer.status}`);
  assert(viewer.text.includes('Load from submission'), 'viewer missing Load from submission UI');

  const unauth = await httpJson(`${baseUrl}/v1/submissions/sub_00000000-0000-0000-0000-000000000000/trust-pulse`, { method: 'GET' });
  assert(unauth.status === 401, `unauth GET trust-pulse expected 401, got ${unauth.status}`);

  return true;
}

async function main() {
  await nonMutatingChecks();

  if (envName === 'prod' || envName === 'production') {
    console.log(JSON.stringify({ ok: true, env: envName, mode: 'non_mutating' }, null, 2));
    return;
  }

  // 1) Generate agent DID/key
  const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const agentDid = await didFromPublicKey(kp.publicKey);

  // 2) Register worker
  const w1 = await registerWorker({ did: agentDid });

  // 3) Create 3 accepted bounties (staging-only) assigned to this worker
  const b1 = insertAcceptedBountyStaging({ workerDid: agentDid, title: 'Smoke: trust pulse happy path' });
  const b2 = insertAcceptedBountyStaging({ workerDid: agentDid, title: 'Smoke: trust pulse missing' });
  const b3 = insertAcceptedBountyStaging({ workerDid: agentDid, title: 'Smoke: trust pulse hash mismatch' });

  // 4) Happy path: submit with trust_pulse, URM pointer matches hash
  const runId1 = `run_${crypto.randomUUID()}`;
  const tp1 = await buildTrustPulse({ runId: runId1, agentDid });
  const a1 = await buildProofArtifacts({ agentDid, privateKey: kp.privateKey, trustPulse: tp1 });

  const s1 = await submit({
    bountyId: b1.bountyId,
    workerDid: agentDid,
    workerToken: w1.token,
    proofBundleEnvelope: a1.envelope,
    urm: a1.urm,
    trustPulse: tp1,
    idempotencyKey: `submit:smoke:tp1:${crypto.randomUUID()}`,
  });

  assert(s1.status === 201, `happy-path submit expected 201, got ${s1.status}: ${s1.text}`);
  assert(s1.json && typeof s1.json.submission_id === 'string', 'happy-path submit missing submission_id');

  const submissionId1 = s1.json.submission_id;

  const g1 = await getStoredTrustPulse({ submissionId: submissionId1, token: w1.token });
  assert(g1.status === 200, `GET trust-pulse expected 200, got ${g1.status}: ${g1.text}`);
  assert(g1.json && g1.json.status === 'verified', `expected stored status=verified, got ${JSON.stringify(g1.json)}`);
  assert(g1.json.hash_b64u === a1.trustPulseHash, 'stored hash_b64u mismatch');
  assert(g1.json.trust_pulse && g1.json.trust_pulse.run_id === runId1, 'stored trust_pulse.run_id mismatch');

  // 5) Auth gating: second worker cannot fetch
  const kp2 = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const did2 = await didFromPublicKey(kp2.publicKey);
  const w2 = await registerWorker({ did: did2 });
  const g1bad = await getStoredTrustPulse({ submissionId: submissionId1, token: w2.token });
  assert(g1bad.status === 403, `cross-worker GET expected 403, got ${g1bad.status}: ${g1bad.text}`);

  // 6) Submission without trust_pulse: stored retrieval is 404
  const runId2 = `run_${crypto.randomUUID()}`;
  const tp2 = await buildTrustPulse({ runId: runId2, agentDid });
  const a2 = await buildProofArtifacts({ agentDid, privateKey: kp.privateKey, trustPulse: tp2 });

  const s2 = await submit({
    bountyId: b2.bountyId,
    workerDid: agentDid,
    workerToken: w1.token,
    proofBundleEnvelope: a2.envelope,
    urm: a2.urm,
    trustPulse: null,
    idempotencyKey: `submit:smoke:notp:${crypto.randomUUID()}`,
  });

  assert(s2.status === 201, `no-trust-pulse submit expected 201, got ${s2.status}: ${s2.text}`);
  assert(s2.json && typeof s2.json.submission_id === 'string', 'no-trust-pulse submit missing submission_id');

  const g2 = await getStoredTrustPulse({ submissionId: s2.json.submission_id, token: w1.token });
  assert(g2.status === 404, `GET trust-pulse (missing) expected 404, got ${g2.status}: ${g2.text}`);
  assert(g2.json && g2.json.error === 'TRUST_PULSE_NOT_FOUND', 'expected TRUST_PULSE_NOT_FOUND');

  // 7) Hash mismatch: URM pointer != trust_pulse hash (fail-closed)
  const runId3 = `run_${crypto.randomUUID()}`;
  const tp3 = await buildTrustPulse({ runId: runId3, agentDid });
  const wrongHash = await hashJsonB64u({ ...tp3, trust_pulse_id: `tp_${crypto.randomUUID()}` });

  const a3 = await buildProofArtifacts({
    agentDid,
    privateKey: kp.privateKey,
    trustPulse: tp3,
    trustPulsePointerHashOverride: wrongHash,
  });

  const s3 = await submit({
    bountyId: b3.bountyId,
    workerDid: agentDid,
    workerToken: w1.token,
    proofBundleEnvelope: a3.envelope,
    urm: a3.urm,
    trustPulse: tp3,
    idempotencyKey: `submit:smoke:hashmismatch:${crypto.randomUUID()}`,
  });

  assert(s3.status === 400, `hash-mismatch submit expected 400, got ${s3.status}: ${s3.text}`);
  assert(s3.json && s3.json.error === 'TRUST_PULSE_HASH_MISMATCH', 'expected TRUST_PULSE_HASH_MISMATCH');

  console.log(
    JSON.stringify(
      {
        ok: true,
        env: envName,
        baseUrl,
        worker_did: agentDid,
        worker_token_prefix: w1.token.slice(0, 8),
        bounty_ids: [b1.bountyId, b2.bountyId, b3.bountyId],
        submission_id_happy_path: submissionId1,
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
