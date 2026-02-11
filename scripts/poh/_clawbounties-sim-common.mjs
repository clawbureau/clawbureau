#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function parseArgs(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i += 1) {
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

export function assert(condition, message) {
  if (!condition) {
    throw new Error(`ASSERT_FAILED: ${message}`);
  }
}

export function resolveEnvName(raw) {
  const env = String(raw || 'staging').toLowerCase();
  if (env === 'prod' || env === 'production') return 'prod';
  return 'staging';
}

export function resolveBountiesBaseUrl(envName, override) {
  if (override && override.trim().length > 0) return override.trim();
  return envName === 'prod' ? 'https://clawbounties.com' : 'https://staging.clawbounties.com';
}

export function resolveVerifyBaseUrl(envName, override) {
  if (override && override.trim().length > 0) return override.trim();
  return envName === 'prod' ? 'https://clawverify.com' : 'https://staging.clawverify.com';
}

export function resolveTrialsBaseUrl(envName, override) {
  if (override && override.trim().length > 0) return override.trim();
  return envName === 'prod' ? 'https://clawtrials.com' : 'https://staging.clawtrials.com';
}

export function requireEnv(name) {
  const value = process.env[name];
  assert(value && value.trim().length > 0, `Missing required env var: ${name}`);
  return value.trim();
}

export function randomDid(prefix = 'sim') {
  const entropy = crypto.randomUUID().replaceAll('-', '');
  return `did:key:z${prefix}${entropy}`;
}

function base64UrlEncode(bytes) {
  const base64 = Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base58Encode(bytes) {
  let leadingZeros = 0;
  for (const byte of bytes) {
    if (byte !== 0) break;
    leadingZeros += 1;
  }

  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
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
  for (let i = 0; i < leadingZeros; i += 1) result += '1';
  for (let i = digits.length - 1; i >= 0; i -= 1) result += BASE58_ALPHABET[digits[i]];
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

async function sha256B64u(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

async function hashJsonB64u(value) {
  const data = new TextEncoder().encode(JSON.stringify(value));
  return sha256B64u(data);
}

export async function generateAgentIdentity() {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const did = await didFromPublicKey(keypair.publicKey);
  return {
    did,
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
  };
}

export async function httpJson(url, init) {
  const started = Date.now();
  const res = await fetch(url, init);
  const elapsedMs = Date.now() - started;
  const text = await res.text();

  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  return {
    status: res.status,
    text,
    json,
    elapsed_ms: elapsedMs,
    ok: res.ok,
  };
}

function authHeaders({ adminKey, workerToken, requesterDid, contentType = true } = {}) {
  const headers = {};
  if (contentType) {
    headers['content-type'] = 'application/json; charset=utf-8';
  }
  if (adminKey) {
    headers.authorization = `Bearer ${adminKey}`;
  }
  if (workerToken) {
    headers.authorization = `Bearer ${workerToken}`;
  }
  if (requesterDid) {
    headers['x-requester-did'] = requesterDid;
  }
  return headers;
}

export async function registerWorker(baseUrl, workerDid, tags = ['simulation', 'smoke']) {
  const body = {
    worker_did: workerDid,
    worker_version: 'sim/1.0.0',
    listing: {
      name: `Sim worker ${workerDid.slice(-8)}`,
      headline: 'Automated simulation worker',
      tags,
    },
    capabilities: {
      job_types: ['code'],
      languages: ['ts', 'js'],
      max_minutes: 30,
    },
    offers: {
      skills: ['simulation'],
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
    headers: authHeaders({}),
    body: JSON.stringify(body),
  });

  assert(out.status === 200 || out.status === 201, `worker register failed (${out.status}): ${out.text}`);
  assert(out.json && out.json.auth && typeof out.json.auth.token === 'string', 'worker register missing auth token');

  return {
    worker_id: out.json.worker_id,
    worker_did: workerDid,
    token: out.json.auth.token,
    elapsed_ms: out.elapsed_ms,
  };
}

export async function postBounty({
  baseUrl,
  adminKey,
  requesterDid,
  closureType,
  testHarnessId = null,
  isCodeBounty = false,
  minProofTier = 'self',
  title,
  description,
  amountMinor = '500',
  tags = ['simulation'],
  metadata = {},
  idempotencyKey,
}) {
  const body = {
    requester_did: requesterDid,
    title,
    description,
    reward: {
      amount_minor: amountMinor,
      currency: 'USD',
    },
    closure_type: closureType,
    difficulty_scalar: 1,
    is_code_bounty: isCodeBounty,
    tags,
    min_proof_tier: minProofTier,
    test_harness_id: testHarnessId,
    metadata,
    idempotency_key: idempotencyKey,
  };

  const out = await httpJson(`${baseUrl}/v1/bounties`, {
    method: 'POST',
    headers: authHeaders({ adminKey, requesterDid }),
    body: JSON.stringify(body),
  });

  return out;
}

export async function acceptBounty({ baseUrl, bountyId, workerDid, workerToken, idempotencyKey }) {
  return httpJson(`${baseUrl}/v1/bounties/${encodeURIComponent(bountyId)}/accept`, {
    method: 'POST',
    headers: authHeaders({ workerToken }),
    body: JSON.stringify({
      worker_did: workerDid,
      idempotency_key: idempotencyKey,
    }),
  });
}

export async function submitBounty({
  baseUrl,
  bountyId,
  workerDid,
  workerToken,
  idempotencyKey,
  proofBundleEnvelope,
  urm,
  commitProofEnvelope = null,
  resultSummary = 'simulation submission',
  artifacts = [],
  agentPack = null,
}) {
  const body = {
    worker_did: workerDid,
    idempotency_key: idempotencyKey,
    proof_bundle_envelope: proofBundleEnvelope,
    urm,
    result_summary: resultSummary,
    artifacts,
    ...(agentPack ? { agent_pack: agentPack } : {}),
    ...(commitProofEnvelope ? { commit_proof_envelope: commitProofEnvelope } : {}),
  };

  return httpJson(`${baseUrl}/v1/bounties/${encodeURIComponent(bountyId)}/submit`, {
    method: 'POST',
    headers: authHeaders({ workerToken }),
    body: JSON.stringify(body),
  });
}

export async function approveBounty({
  baseUrl,
  bountyId,
  adminKey,
  requesterDid,
  submissionId,
  idempotencyKey,
}) {
  return httpJson(`${baseUrl}/v1/bounties/${encodeURIComponent(bountyId)}/approve`, {
    method: 'POST',
    headers: authHeaders({ adminKey, requesterDid }),
    body: JSON.stringify({
      requester_did: requesterDid,
      submission_id: submissionId,
      idempotency_key: idempotencyKey,
    }),
  });
}

export async function rejectBounty({
  baseUrl,
  bountyId,
  adminKey,
  requesterDid,
  submissionId,
  idempotencyKey,
  reason = 'simulation rejection',
}) {
  return httpJson(`${baseUrl}/v1/bounties/${encodeURIComponent(bountyId)}/reject`, {
    method: 'POST',
    headers: authHeaders({ adminKey, requesterDid }),
    body: JSON.stringify({
      requester_did: requesterDid,
      submission_id: submissionId,
      idempotency_key: idempotencyKey,
      reason,
    }),
  });
}

export async function getBounty({ baseUrl, bountyId, adminKey }) {
  return httpJson(`${baseUrl}/v1/bounties/${encodeURIComponent(bountyId)}`, {
    method: 'GET',
    headers: adminKey ? authHeaders({ adminKey, contentType: false }) : {},
  });
}

export async function listBountySubmissions({
  baseUrl,
  bountyId,
  adminKey = null,
  requesterDid = null,
  workerToken = null,
  params = {},
}) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null) continue;
    qs.set(k, String(v));
  }

  const url = `${baseUrl}/v1/bounties/${encodeURIComponent(bountyId)}/submissions${qs.toString() ? `?${qs.toString()}` : ''}`;
  return httpJson(url, {
    method: 'GET',
    headers: {
      ...(adminKey ? authHeaders({ adminKey, contentType: false }) : {}),
      ...(workerToken ? authHeaders({ workerToken, contentType: false }) : {}),
      ...(requesterDid ? { 'x-requester-did': requesterDid } : {}),
    },
  });
}

export async function getSubmissionDetail({
  baseUrl,
  submissionId,
  adminKey = null,
  requesterDid = null,
  workerToken = null,
}) {
  return httpJson(`${baseUrl}/v1/submissions/${encodeURIComponent(submissionId)}`, {
    method: 'GET',
    headers: {
      ...(adminKey ? authHeaders({ adminKey, contentType: false }) : {}),
      ...(workerToken ? authHeaders({ workerToken, contentType: false }) : {}),
      ...(requesterDid ? { 'x-requester-did': requesterDid } : {}),
    },
  });
}

export async function buildProofArtifacts({ agentDid, privateKey, runId, harnessId = 'sim-harness' }) {
  const now = Date.now();
  const t0 = new Date(now).toISOString();
  const t1 = new Date(now + 1000).toISOString();

  const eventA = {
    event_id: `evt_${crypto.randomUUID()}`,
    run_id: runId,
    event_type: 'run_start',
    timestamp: t0,
    payload_hash_b64u: await hashJsonB64u({ event: 'run_start' }),
    prev_hash_b64u: null,
  };
  const eventAHash = await hashJsonB64u(eventA);

  const eventB = {
    event_id: `evt_${crypto.randomUUID()}`,
    run_id: runId,
    event_type: 'run_end',
    timestamp: t1,
    payload_hash_b64u: await hashJsonB64u({ event: 'run_end' }),
    prev_hash_b64u: eventAHash,
  };
  const eventBHash = await hashJsonB64u(eventB);

  const eventChain = [
    { ...eventA, event_hash_b64u: eventAHash },
    { ...eventB, event_hash_b64u: eventBHash },
  ];

  const harness = {
    id: harnessId,
    version: '1',
    runtime: 'simulation',
  };

  const harnessConfigHash = await hashJsonB64u(harness);

  const urm = {
    urm_version: '1',
    urm_id: `urm_${crypto.randomUUID()}`,
    run_id: runId,
    agent_did: agentDid,
    issued_at: new Date(now + 1500).toISOString(),
    harness: {
      id: harness.id,
      version: harness.version,
      runtime: harness.runtime,
      config_hash_b64u: harnessConfigHash,
    },
    inputs: [],
    outputs: [],
    event_chain_root_hash_b64u: eventAHash,
    metadata: {
      harness,
    },
  };

  const urmHash = await hashJsonB64u(urm);

  const payload = {
    bundle_version: '1',
    bundle_id: `bundle_${crypto.randomUUID()}`,
    agent_did: agentDid,
    urm: {
      urm_version: '1',
      urm_id: urm.urm_id,
      resource_type: 'universal_run_manifest',
      resource_hash_b64u: urmHash,
    },
    event_chain: eventChain,
    metadata: {
      harness,
    },
  };

  const payloadHash = await hashJsonB64u(payload);
  const signature = await signEd25519(privateKey, new TextEncoder().encode(payloadHash));

  const envelope = {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: agentDid,
    issued_at: new Date(now + 2000).toISOString(),
  };

  return {
    envelope,
    urm,
    payload_hash_b64u: payloadHash,
  };
}

export async function buildCommitProofEnvelope({
  signerDid,
  privateKey,
  repoClaimId = 'repo:github:clawbureau/clawbureau',
  repository = 'github.com/clawbureau/clawbureau',
  commitSha = '261271e',
  branch = 'main',
  runId,
  proofBundleHash,
}) {
  const payload = {
    proof_version: '1',
    repo_claim_id: repoClaimId,
    commit_sha: commitSha,
    repository,
    branch,
    run_id: runId,
    proof_bundle_hash_b64u: proofBundleHash,
    harness: {
      id: 'sim-harness',
      version: '1',
    },
  };

  const payloadHash = await hashJsonB64u(payload);
  const signature = await signEd25519(privateKey, new TextEncoder().encode(payloadHash));

  return {
    envelope_version: '1',
    envelope_type: 'commit_proof',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: signerDid,
    issued_at: new Date().toISOString(),
  };
}

export function extractErrorCode(response) {
  if (response?.json && typeof response.json.error === 'string' && response.json.error.trim().length > 0) {
    return response.json.error.trim();
  }
  return `HTTP_${response?.status ?? 'UNKNOWN'}`;
}

export async function sleep(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export async function waitForSubmissionTerminal({
  baseUrl,
  submissionId,
  workerToken,
  requesterDid,
  adminKey,
  timeoutMs = 15_000,
  intervalMs = 800,
}) {
  const start = Date.now();
  let last = null;

  while (Date.now() - start <= timeoutMs) {
    const res = await getSubmissionDetail({
      baseUrl,
      submissionId,
      workerToken,
      requesterDid,
      adminKey,
    });
    last = res;

    if (res.status === 200 && res.json?.submission?.status) {
      const status = res.json.submission.status;
      if (status === 'approved' || status === 'rejected' || status === 'invalid') {
        return res;
      }
    }

    await sleep(intervalMs);
  }

  return last;
}

export function computeLatencyStats(samples) {
  const values = samples.filter((n) => Number.isFinite(n)).map((n) => Number(n));
  if (values.length === 0) {
    return { count: 0, min_ms: null, max_ms: null, avg_ms: null, p95_ms: null };
  }

  values.sort((a, b) => a - b);
  const sum = values.reduce((acc, n) => acc + n, 0);
  const p95Index = Math.min(values.length - 1, Math.floor(values.length * 0.95));

  return {
    count: values.length,
    min_ms: values[0],
    max_ms: values[values.length - 1],
    avg_ms: Math.round((sum / values.length) * 100) / 100,
    p95_ms: values[p95Index],
  };
}

export async function createArtifactDir(repoRoot, prefix = 'run') {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.resolve(repoRoot, 'artifacts', 'simulations', 'clawbounties', `${timestamp}-${prefix}`);
  await fs.mkdir(dir, { recursive: true });
  return { dir, timestamp };
}

export async function writeJson(filePath, payload) {
  await fs.writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

export async function appendNdjson(filePath, rows) {
  const text = rows.map((row) => JSON.stringify(row)).join('\n') + (rows.length > 0 ? '\n' : '');
  await fs.writeFile(filePath, text, 'utf8');
}
