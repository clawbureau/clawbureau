#!/usr/bin/env node

/**
 * CEA-US-049H / CBT-OPS-001
 *
 * Staging simulation launcher for requester-closure bounty flow using real API calls:
 *   1) Issue scoped requester token via clawea token broker
 *   2) Register worker
 *   3) POST /v1/bounties (closure_type=requester)
 *   4) POST /v1/bounties/:id/accept
 *   5) POST /v1/bounties/:id/submit
 *   6) GET  /v1/bounties/:id/submissions
 *   7) POST /v1/bounties/:id/approve or /reject
 *
 * No D1 injection, no clawtrials dependency.
 */

import process from "node:process";
import path from "node:path";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

function parseArgs(argv) {
  const out = new Map();
  for (let i = 0; i < argv.length; i++) {
    const entry = argv[i];
    if (!entry.startsWith("--")) continue;
    const key = entry.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      out.set(key, next);
      i++;
    } else {
      out.set(key, "true");
    }
  }
  return out;
}

function assert(cond, message) {
  if (!cond) throw new Error(`ASSERT_FAILED: ${message}`);
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function base64UrlEncode(bytes) {
  const base64 = Buffer.from(bytes).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256B64uBytes(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

async function sha256B64uText(text) {
  return sha256B64uBytes(new TextEncoder().encode(text));
}

async function sha256B64uJson(value) {
  return sha256B64uBytes(new TextEncoder().encode(JSON.stringify(value)));
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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

  let result = "";
  for (let i = 0; i < leadingZeros; i++) result += "1";
  for (let i = digits.length - 1; i >= 0; i--) result += BASE58_ALPHABET[digits[i]];
  return result;
}

async function didFromPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey("raw", publicKey);
  const pubBytes = new Uint8Array(raw);
  const multicodec = new Uint8Array(2 + pubBytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(pubBytes, 2);
  return `did:key:z${base58Encode(multicodec)}`;
}

async function signEd25519(privateKey, messageBytes) {
  const sigBuffer = await crypto.subtle.sign("Ed25519", privateKey, messageBytes);
  return base64UrlEncode(new Uint8Array(sigBuffer));
}

async function httpJson(url, init = {}) {
  const res = await fetch(url, init);
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { res, status: res.status, text, json };
}

function resolveEnvConfig(name) {
  const envName = String(name || "staging").trim().toLowerCase();
  const prod = envName === "prod" || envName === "production";

  return {
    envName: prod ? "production" : "staging",
    clawbountiesBaseUrl: prod ? "https://clawbounties.com" : "https://staging.clawbounties.com",
    claweaBaseUrl: prod ? "https://clawea.com" : "https://staging.clawea.com",
    requesterAudience: prod ? "clawbounties.com" : "staging.clawbounties.com",
  };
}

function readTokenFromSecretFile(filePath) {
  const raw = readFileSync(filePath, "utf-8").trim();
  if (!raw) return null;

  if (!raw.startsWith("{")) {
    return raw;
  }

  try {
    const parsed = JSON.parse(raw);
    if (!isRecord(parsed)) return null;

    const candidates = [
      parsed.api_key,
      parsed.tenant_api_key,
      parsed.token,
      parsed.bearer,
      parsed.value,
      parsed.secret,
    ];

    for (const value of candidates) {
      if (typeof value === "string" && value.trim().length > 0) {
        return value.trim();
      }
    }
  } catch {
    return null;
  }

  return null;
}

function resolveTenantToken(args) {
  const fromArg = args.get("tenant-token");
  if (fromArg && fromArg.trim().length > 0) return fromArg.trim();

  const fromEnv = process.env.CLAWEA_TENANT_TOKEN;
  if (fromEnv && fromEnv.trim().length > 0) return fromEnv.trim();

  const secretFile = args.get("tenant-secret-file");
  if (secretFile) {
    const token = readTokenFromSecretFile(secretFile);
    if (token) return token;
  }

  return null;
}

async function issueRequesterToken(params) {
  const {
    claweaBaseUrl,
    tenantToken,
    requesterDid,
    audience,
    ttlSeconds,
    scopes,
    runLabel,
  } = params;

  const body = {
    audience,
    ttl_seconds: ttlSeconds,
    scope: scopes,
    context: {
      source: "smoke-requester-closure-simulation",
      run_label: runLabel,
    },
  };

  if (requesterDid) {
    body.requester_did = requesterDid;
  }

  const out = await httpJson(`${claweaBaseUrl}/v1/billing/clawbounties/requester-token`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${tenantToken}`,
      "content-type": "application/json; charset=utf-8",
    },
    body: JSON.stringify(body),
  });

  assert(out.status === 200 || out.status === 201, `requester token issue failed (${out.status}): ${out.text}`);
  assert(isRecord(out.json), "requester token issue response must be an object");
  assert(isRecord(out.json.token), "requester token issue response missing token object");
  assert(typeof out.json.token.value === "string", "requester token issue response missing token.value");
  assert(typeof out.json.requester_did === "string", "requester token issue response missing requester_did");

  return {
    requester_did: out.json.requester_did,
    token: out.json.token.value,
    token_hash: typeof out.json.token.token_hash === "string" ? out.json.token.token_hash : null,
    expires_at: typeof out.json.token.expires_at === "string" ? out.json.token.expires_at : null,
  };
}

async function registerWorker(clawbountiesBaseUrl, workerDid) {
  const body = {
    worker_did: workerDid,
    worker_version: "sim/requester-closure/1.0.0",
    listing: {
      name: "Requester closure sim worker",
      headline: "Simulation worker",
      tags: ["simulation", "requester", "closure"],
    },
    capabilities: {
      job_types: ["code"],
      languages: ["ts"],
      max_minutes: 15,
    },
    offers: {
      skills: ["did-work"],
      mcp: [],
    },
    pricing: {
      price_floor_minor: "1",
    },
    availability: {
      mode: "manual",
      paused: false,
    },
  };

  const out = await httpJson(`${clawbountiesBaseUrl}/v1/workers/register`, {
    method: "POST",
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(body),
  });

  assert(out.status === 200 || out.status === 201, `worker register failed (${out.status}): ${out.text}`);
  assert(isRecord(out.json) && isRecord(out.json.auth), "worker register response missing auth object");
  assert(typeof out.json.auth.token === "string", "worker register response missing auth.token");

  return {
    worker_id: typeof out.json.worker_id === "string" ? out.json.worker_id : null,
    worker_token: out.json.auth.token,
  };
}

async function buildProofBundleEnvelope(workerDid, workerPrivateKey, runMarker) {
  const runId = `run_${crypto.randomUUID()}`;
  const now = new Date().toISOString();

  const payloadHash = await sha256B64uText(`simulation:${runMarker}:${runId}`);
  const eventHeader = {
    event_id: `evt_${crypto.randomUUID()}`,
    run_id: runId,
    event_type: "llm_call",
    timestamp: now,
    payload_hash_b64u: payloadHash,
    prev_hash_b64u: null,
  };

  const eventHash = await sha256B64uJson(eventHeader);
  const eventChain = [{ ...eventHeader, event_hash_b64u: eventHash }];

  const payload = {
    bundle_version: "1",
    bundle_id: `bundle_${crypto.randomUUID()}`,
    agent_did: workerDid,
    event_chain: eventChain,
    metadata: {
      harness: {
        id: "requester-closure-sim",
        version: "1",
        runtime: "host",
      },
      simulation: {
        marker: runMarker,
      },
    },
  };

  const bundlePayloadHash = await sha256B64uJson(payload);
  const signature = await signEd25519(workerPrivateKey, new TextEncoder().encode(bundlePayloadHash));

  return {
    envelope_version: "1",
    envelope_type: "proof_bundle",
    payload,
    payload_hash_b64u: bundlePayloadHash,
    hash_algorithm: "SHA-256",
    signature_b64u: signature,
    algorithm: "Ed25519",
    signer_did: workerDid,
    issued_at: new Date().toISOString(),
  };
}

async function postBounty(params) {
  const {
    clawbountiesBaseUrl,
    requesterToken,
    requesterDid,
    workerDid,
    idempotencyKey,
    title,
    rewardMinor,
  } = params;

  return httpJson(`${clawbountiesBaseUrl}/v1/bounties`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${requesterToken}`,
      "content-type": "application/json; charset=utf-8",
    },
    body: JSON.stringify({
      requester_did: requesterDid,
      title,
      description: "Requester closure simulation run",
      reward: { amount_minor: String(rewardMinor), currency: "USD" },
      closure_type: "requester",
      difficulty_scalar: 1.0,
      is_code_bounty: false,
      min_proof_tier: "self",
      tags: ["simulation", "requester-closure"],
      idempotency_key: idempotencyKey,
      metadata: {
        requested_worker_did: workerDid,
        simulation: true,
      },
    }),
  });
}

async function acceptBounty(params) {
  const { clawbountiesBaseUrl, bountyId, workerToken, workerDid, idempotencyKey } = params;

  return httpJson(`${clawbountiesBaseUrl}/v1/bounties/${encodeURIComponent(bountyId)}/accept`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${workerToken}`,
      "content-type": "application/json; charset=utf-8",
    },
    body: JSON.stringify({
      worker_did: workerDid,
      idempotency_key: idempotencyKey,
    }),
  });
}

async function submitBounty(params) {
  const {
    clawbountiesBaseUrl,
    bountyId,
    workerToken,
    workerDid,
    idempotencyKey,
    proofBundleEnvelope,
  } = params;

  return httpJson(`${clawbountiesBaseUrl}/v1/bounties/${encodeURIComponent(bountyId)}/submit`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${workerToken}`,
      "content-type": "application/json; charset=utf-8",
    },
    body: JSON.stringify({
      worker_did: workerDid,
      idempotency_key: idempotencyKey,
      proof_bundle_envelope: proofBundleEnvelope,
      artifacts: [],
      result_summary: "simulation submission",
    }),
  });
}

async function listBountySubmissions(clawbountiesBaseUrl, bountyId, requesterToken) {
  return httpJson(`${clawbountiesBaseUrl}/v1/bounties/${encodeURIComponent(bountyId)}/submissions?limit=20`, {
    method: "GET",
    headers: {
      authorization: `Bearer ${requesterToken}`,
    },
  });
}

async function decideBounty(params) {
  const {
    clawbountiesBaseUrl,
    bountyId,
    requesterToken,
    requesterDid,
    submissionId,
    idempotencyKey,
    decision,
  } = params;

  const endpoint = decision === "reject" ? "reject" : "approve";
  const body = {
    requester_did: requesterDid,
    submission_id: submissionId,
    idempotency_key: idempotencyKey,
    ...(decision === "reject" ? { reason: "simulation rejection path" } : {}),
  };

  return httpJson(`${clawbountiesBaseUrl}/v1/bounties/${encodeURIComponent(bountyId)}/${endpoint}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${requesterToken}`,
      "content-type": "application/json; charset=utf-8",
    },
    body: JSON.stringify(body),
  });
}

async function getSubmissionDetail(clawbountiesBaseUrl, submissionId, requesterToken) {
  return httpJson(`${clawbountiesBaseUrl}/v1/submissions/${encodeURIComponent(submissionId)}`, {
    method: "GET",
    headers: {
      authorization: `Bearer ${requesterToken}`,
    },
  });
}

function pickDecision(mode, index) {
  const m = String(mode || "approve").trim().toLowerCase();
  if (m === "approve") return "approve";
  if (m === "reject") return "reject";
  return index % 2 === 0 ? "approve" : "reject";
}

function isoForPath(iso) {
  return iso.replace(/[:.]/g, "-");
}

function writeArtifacts(params) {
  const { repoRoot, envName, runs, decisionMode, result } = params;
  const ts = new Date().toISOString();
  const dir = path.join(
    repoRoot,
    "artifacts",
    "simulations",
    "clawbounties-requester-closure",
    `${isoForPath(ts)}-${envName}-runs-${runs}`
  );

  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, "result.json"), JSON.stringify(result, null, 2));

  const md = [
    `# Requester Closure Simulation (${envName})`,
    "",
    `- runs: ${runs}`,
    `- reward_minor: ${result.summary.reward_minor}`,
    `- decision_mode: ${decisionMode}`,
    `- completed_at: ${ts}`,
    `- succeeded: ${result.summary.succeeded}`,
    `- failed: ${result.summary.failed}`,
    `- approvals: ${result.summary.approvals}`,
    `- rejections: ${result.summary.rejections}`,
    `- duration_ms: ${result.summary.duration_ms}`,
    "",
    "## Notes",
    "- Uses scoped requester tokens from clawea token broker.",
    "- Uses real staging APIs (no D1 injection).",
    "- Uses closure_type=requester and self-tier proof bundles.",
  ].join("\n");

  writeFileSync(path.join(dir, "summary.md"), md);

  return { dir, timestamp: ts };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envCfg = resolveEnvConfig(args.get("env") || "staging");

  const allowProd = String(args.get("allow-prod") || "false").toLowerCase() === "true";
  if (envCfg.envName === "production" && !allowProd) {
    throw new Error("Refusing to run mutating simulation on production without --allow-prod true");
  }

  const runs = Math.max(1, Math.min(1000, Number(args.get("runs") || "10")));
  const decisionMode = String(args.get("decision") || "mixed").trim().toLowerCase();
  assert(["approve", "reject", "mixed"].includes(decisionMode), "--decision must be approve|reject|mixed");
  const rewardMinor = Math.max(1, Math.min(1000, Math.floor(Number(args.get("reward-minor") || "1"))));

  const tenantToken = resolveTenantToken(args);
  assert(tenantToken, "Missing tenant token (use --tenant-token, CLAWEA_TENANT_TOKEN, or --tenant-secret-file)");

  const ttlSeconds = Math.max(60, Math.min(3600, Number(args.get("token-ttl-seconds") || "900")));

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, "../..");

  const startedAt = Date.now();

  const health = await httpJson(`${envCfg.clawbountiesBaseUrl}/health`, { method: "GET" });
  assert(health.status === 200, `clawbounties health failed: ${health.status}`);

  const workerKeys = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const workerDid = await didFromPublicKey(workerKeys.publicKey);

  const tokenScopes = [
    "clawbounties:bounty:create",
    "clawbounties:bounty:approve",
    "clawbounties:bounty:reject",
    "clawbounties:bounty:read",
  ];

  const requestedRequesterDidRaw = args.get("requester-did");
  const requestedRequesterDid = requestedRequesterDidRaw && requestedRequesterDidRaw.trim().length > 0
    ? requestedRequesterDidRaw.trim()
    : null;

  const requesterTokenIssued = await issueRequesterToken({
    claweaBaseUrl: envCfg.claweaBaseUrl,
    tenantToken,
    requesterDid: requestedRequesterDid,
    audience: [envCfg.requesterAudience],
    ttlSeconds,
    scopes: tokenScopes,
    runLabel: `requester-closure-sim-${crypto.randomUUID()}`,
  });

  const requesterDid = requesterTokenIssued.requester_did;

  const worker = await registerWorker(envCfg.clawbountiesBaseUrl, workerDid);

  const runResults = [];

  for (let i = 0; i < runs; i++) {
    const runIndex = i + 1;
    const runId = `sim_${crypto.randomUUID()}`;
    const decision = pickDecision(decisionMode, i);

    const entry = {
      run_index: runIndex,
      run_id: runId,
      decision,
      ok: false,
      bounty_id: null,
      submission_id: null,
      post_status: null,
      accept_status: null,
      submit_status: null,
      review_list_status: null,
      review_item_status: null,
      decision_status: null,
      error: null,
    };

    try {
      const post = await postBounty({
        clawbountiesBaseUrl: envCfg.clawbountiesBaseUrl,
        requesterToken: requesterTokenIssued.token,
        requesterDid,
        workerDid,
        idempotencyKey: `sim:${runId}:post`,
        title: `Simulation run ${runIndex}`,
        rewardMinor,
      });
      entry.post_status = post.status;
      assert(post.status === 200 || post.status === 201, `post failed (${post.status})`);
      assert(isRecord(post.json) && typeof post.json.bounty_id === "string", "post response missing bounty_id");
      entry.bounty_id = post.json.bounty_id;

      const accept = await acceptBounty({
        clawbountiesBaseUrl: envCfg.clawbountiesBaseUrl,
        bountyId: entry.bounty_id,
        workerToken: worker.worker_token,
        workerDid,
        idempotencyKey: `sim:${runId}:accept`,
      });
      entry.accept_status = accept.status;
      assert(accept.status === 200 || accept.status === 201, `accept failed (${accept.status})`);

      const proofBundleEnvelope = await buildProofBundleEnvelope(workerDid, workerKeys.privateKey, runId);
      const submit = await submitBounty({
        clawbountiesBaseUrl: envCfg.clawbountiesBaseUrl,
        bountyId: entry.bounty_id,
        workerToken: worker.worker_token,
        workerDid,
        idempotencyKey: `sim:${runId}:submit`,
        proofBundleEnvelope,
      });
      entry.submit_status = submit.status;
      assert(submit.status === 201, `submit failed (${submit.status})`);
      assert(isRecord(submit.json) && typeof submit.json.submission_id === "string", "submit response missing submission_id");
      entry.submission_id = submit.json.submission_id;

      const reviewList = await listBountySubmissions(
        envCfg.clawbountiesBaseUrl,
        entry.bounty_id,
        requesterTokenIssued.token
      );
      entry.review_list_status = reviewList.status;
      assert(reviewList.status === 200, `review list failed (${reviewList.status})`);

      const decisionRes = await decideBounty({
        clawbountiesBaseUrl: envCfg.clawbountiesBaseUrl,
        bountyId: entry.bounty_id,
        requesterToken: requesterTokenIssued.token,
        requesterDid,
        submissionId: entry.submission_id,
        idempotencyKey: `sim:${runId}:${decision}`,
        decision,
      });
      entry.decision_status = decisionRes.status;
      assert(decisionRes.status === 200, `${decision} failed (${decisionRes.status})`);

      const reviewItem = await getSubmissionDetail(
        envCfg.clawbountiesBaseUrl,
        entry.submission_id,
        requesterTokenIssued.token
      );
      entry.review_item_status = reviewItem.status;
      assert(reviewItem.status === 200, `review item failed (${reviewItem.status})`);

      entry.ok = true;
    } catch (err) {
      entry.error = err instanceof Error ? err.message : String(err);
    }

    runResults.push(entry);
  }

  const summary = {
    runs,
    reward_minor: rewardMinor,
    succeeded: runResults.filter((r) => r.ok).length,
    failed: runResults.filter((r) => !r.ok).length,
    approvals: runResults.filter((r) => r.ok && r.decision === "approve").length,
    rejections: runResults.filter((r) => r.ok && r.decision === "reject").length,
    duration_ms: Date.now() - startedAt,
  };

  const result = {
    env: envCfg.envName,
    requester_did: requesterDid,
    worker_did: workerDid,
    requester_token: {
      token_hash: requesterTokenIssued.token_hash,
      expires_at: requesterTokenIssued.expires_at,
      scopes: tokenScopes,
      audience: envCfg.requesterAudience,
    },
    summary,
    runs: runResults,
  };

  const artifact = writeArtifacts({
    repoRoot,
    envName: envCfg.envName,
    runs,
    decisionMode,
    result,
  });

  console.log(
    JSON.stringify(
      {
        ok: summary.failed === 0,
        env: envCfg.envName,
        runs,
        summary,
        artifact_dir: artifact.dir,
      },
      null,
      2
    )
  );

  if (summary.failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
