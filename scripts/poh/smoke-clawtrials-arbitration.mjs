#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseArgs,
  assert,
  resolveEnvName,
  resolveBountiesBaseUrl,
  resolveTrialsBaseUrl,
  resolveScopeBaseUrl,
  resolveRequesterAudience,
  resolveWorkerAudience,
  resolveRequesterScopes,
  resolveWorkerScopes,
  issueRequesterScopedToken,
  issueWorkerScopedToken,
  registerWorker,
  postBounty,
  acceptBounty,
  submitBounty,
  rejectBounty,
  buildProofArtifacts,
  randomDid,
} from './_clawbounties-sim-common.mjs';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

function base58Encode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      const x = (digits[i] << 8) + carry;
      digits[i] = x % 58;
      carry = (x / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  for (let i = 0; i < bytes.length && bytes[i] === 0; i += 1) {
    digits.push(0);
  }

  return digits
    .reverse()
    .map((digit) => BASE58_ALPHABET[digit])
    .join('');
}

function b64u(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function createDidKeyPair() {
  const keypair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const rawPublic = new Uint8Array(await crypto.subtle.exportKey('raw', keypair.publicKey));

  const prefixed = new Uint8Array(ED25519_MULTICODEC_PREFIX.length + rawPublic.length);
  prefixed.set(ED25519_MULTICODEC_PREFIX, 0);
  prefixed.set(rawPublic, ED25519_MULTICODEC_PREFIX.length);

  return {
    did: `did:key:z${base58Encode(prefixed)}`,
    privateKey: keypair.privateKey,
  };
}

async function signMessage(privateKey, message) {
  const bytes = new TextEncoder().encode(message);
  const signature = await crypto.subtle.sign('Ed25519', privateKey, bytes);
  return b64u(new Uint8Array(signature));
}

async function requestJson(url, init = {}) {
  const startedAt = Date.now();
  const response = await fetch(url, init);
  const text = await response.text();

  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }

  return {
    status: response.status,
    ok: response.ok,
    text,
    json,
    headers: Object.fromEntries(response.headers.entries()),
    elapsed_ms: Date.now() - startedAt,
  };
}

function resolveClaimBaseUrl(envName, override) {
  if (override && override.trim().length > 0) return override.trim();
  return envName === 'prod' ? 'https://clawclaim.com' : 'https://staging.clawclaim.com';
}

function resolveAudience(envName) {
  return envName === 'prod' ? 'clawbounties.com' : 'staging.clawbounties.com';
}

async function bindDid(claimBaseUrl, did, privateKey) {
  const challenge = await requestJson(`${claimBaseUrl}/v1/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({ did }),
  });

  assert(challenge.status === 200, `bind challenge failed (${challenge.status}): ${challenge.text}`);
  assert(typeof challenge.json?.challenge_id === 'string', 'bind challenge missing challenge_id');
  assert(typeof challenge.json?.message === 'string', 'bind challenge missing message');

  const signature = await signMessage(privateKey, challenge.json.message);

  const bind = await requestJson(`${claimBaseUrl}/v1/bind`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      did,
      challenge_id: challenge.json.challenge_id,
      signature_b64u: signature,
    }),
  });

  assert(bind.status === 200, `bind failed (${bind.status}): ${bind.text}`);
}

async function issueScopedTokenViaClaim({ claimBaseUrl, ownerDid, privateKey, audience, scope, ttlSec = 600 }) {
  const challenge = await requestJson(`${claimBaseUrl}/v1/scoped-tokens/challenges`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      owner_did: ownerDid,
      aud: [audience],
      scope,
      ttl_sec: ttlSec,
    }),
  });

  assert(challenge.status === 200, `scope challenge failed (${challenge.status}): ${challenge.text}`);
  assert(typeof challenge.json?.challenge_id === 'string', 'scope challenge missing challenge_id');
  assert(typeof challenge.json?.message === 'string', 'scope challenge missing message');

  const signature = await signMessage(privateKey, challenge.json.message);

  const exchange = await requestJson(`${claimBaseUrl}/v1/scoped-tokens/exchange`, {
    method: 'POST',
    headers: { 'content-type': 'application/json; charset=utf-8' },
    body: JSON.stringify({
      owner_did: ownerDid,
      challenge_id: challenge.json.challenge_id,
      signature_b64u: signature,
    }),
  });

  assert(exchange.status === 200, `scope exchange failed (${exchange.status}): ${exchange.text}`);
  assert(typeof exchange.json?.token === 'string' && exchange.json.token.length > 0, 'scope exchange missing token');

  return {
    token: exchange.json.token,
    token_hash: typeof exchange.json?.token_hash === 'string' ? exchange.json.token_hash : null,
    kid: typeof exchange.json?.kid === 'string' ? exchange.json.kid : null,
  };
}

function requesterScopes() {
  return [
    'clawbounties:bounty:create',
    'clawbounties:bounty:reject',
    'clawbounties:bounty:read',
  ];
}

function workerScopes() {
  return [
    'clawbounties:worker:self:read',
    'clawbounties:bounty:accept',
    'clawbounties:bounty:submit',
    'clawbounties:submission:read',
  ];
}

async function getTrialCase(trialsBaseUrl, trialsAdminKey, caseId) {
  const res = await requestJson(`${trialsBaseUrl}/v1/trials/cases/${encodeURIComponent(caseId)}`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${trialsAdminKey}`,
    },
  });

  return res;
}

async function decideTrialCase({ trialsBaseUrl, trialsAdminKey, caseId, idempotencyKey, outcome, decidedBy, rationale }) {
  return requestJson(`${trialsBaseUrl}/v1/trials/cases/${encodeURIComponent(caseId)}/decision`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${trialsAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: idempotencyKey,
      outcome,
      decided_by: decidedBy,
      rationale,
    }),
  });
}

async function appealTrialCase({ trialsBaseUrl, trialsAdminKey, caseId, idempotencyKey, appealedBy, reason }) {
  return requestJson(`${trialsBaseUrl}/v1/trials/cases/${encodeURIComponent(caseId)}/appeal`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${trialsAdminKey}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      idempotency_key: idempotencyKey,
      appealed_by: appealedBy,
      reason,
    }),
  });
}

function makeArtifactDir(repoRoot, envName) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dir = path.resolve(repoRoot, 'artifacts', 'simulations', 'clawtrials', `${timestamp}-${envName}`);
  return { dir, timestamp };
}

async function writeJson(filePath, payload) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = resolveEnvName(args.get('env'));

  const bountiesBaseUrl = resolveBountiesBaseUrl(envName, args.get('clawbounties-base-url'));
  const trialsBaseUrl = resolveTrialsBaseUrl(envName, args.get('clawtrials-base-url'));
  const claimBaseUrl = resolveClaimBaseUrl(envName, args.get('clawclaim-base-url'));
  const scopeBaseUrl = resolveScopeBaseUrl(envName, args.get('scope-base-url'));

  assert(trialsBaseUrl && trialsBaseUrl.trim().length > 0, 'clawtrials base URL is required');

  const trialsAdminKey = String(args.get('trials-admin-key') || process.env.TRIALS_ADMIN_KEY || '').trim();
  assert(trialsAdminKey.length > 0, 'TRIALS_ADMIN_KEY (or --trials-admin-key) is required');

  const scopeAdminKey = String(args.get('scope-admin-key') || process.env.SCOPE_ADMIN_KEY || process.env.CLAWSCOPE_ADMIN_KEY || '').trim();

  const requesterIdentity = await createDidKeyPair();
  const workerIdentity = await createDidKeyPair();
  const judgeDid = randomDid('judge');

  const requesterDidArg = String(args.get('requester-did') || '').trim();
  const requesterDid = requesterDidArg || requesterIdentity.did;

  let requesterToken;
  let workerToken;

  if (scopeAdminKey.length > 0) {
    const requesterIssued = await issueRequesterScopedToken({
      scopeBaseUrl,
      scopeAdminKey,
      requesterDid,
      audience: resolveRequesterAudience(envName, args.get('requester-audience')),
      scopes: resolveRequesterScopes(args.get('requester-scopes')),
      ttlSec: 900,
      source: 'smoke-clawtrials-arbitration',
      paymentAccountDid: requesterDid,
    });

    const workerIssued = await issueWorkerScopedToken({
      scopeBaseUrl,
      scopeAdminKey,
      workerDid: workerIdentity.did,
      audience: resolveWorkerAudience(envName, args.get('worker-audience')),
      scopes: resolveWorkerScopes(args.get('worker-scopes')),
      ttlSec: 900,
      source: 'smoke-clawtrials-arbitration',
      paymentAccountDid: workerIdentity.did,
    });

    requesterToken = requesterIssued;
    workerToken = workerIssued;
  } else {
    assert(!requesterDidArg || requesterDidArg === requesterIdentity.did, 'requester-did override requires scope-admin-key path');

    await bindDid(claimBaseUrl, requesterIdentity.did, requesterIdentity.privateKey);
    await bindDid(claimBaseUrl, workerIdentity.did, workerIdentity.privateKey);

    const aud = resolveAudience(envName);

    requesterToken = await issueScopedTokenViaClaim({
      claimBaseUrl,
      ownerDid: requesterIdentity.did,
      privateKey: requesterIdentity.privateKey,
      audience: aud,
      scope: requesterScopes(),
      ttlSec: 900,
    });

    workerToken = await issueScopedTokenViaClaim({
      claimBaseUrl,
      ownerDid: workerIdentity.did,
      privateKey: workerIdentity.privateKey,
      audience: aud,
      scope: workerScopes(),
      ttlSec: 900,
    });
  }

  const steps = [];

  const workerRegistration = await registerWorker(bountiesBaseUrl, workerIdentity.did, ['simulation', 'trials']);
  steps.push({ step: 'register_worker', status: 200, elapsed_ms: workerRegistration.elapsed_ms });

  const postRes = await postBounty({
    baseUrl: bountiesBaseUrl,
    requesterToken: requesterToken.token,
    requesterDid,
    closureType: 'requester',
    isCodeBounty: false,
    title: `clawtrials arbitration smoke ${new Date().toISOString()}`,
    description: 'Dispute flow routed into clawtrials arbitration',
    amountMinor: '250',
    tags: ['simulation', 'trials'],
    metadata: { simulation: true, flow: 'trials-arbitration' },
    idempotencyKey: `smoke:trials:post:${crypto.randomUUID()}`,
    strictAuth: true,
  });

  assert(postRes.status === 200 || postRes.status === 201, `post bounty failed (${postRes.status}): ${postRes.text}`);
  assert(typeof postRes.json?.bounty_id === 'string', 'post bounty missing bounty_id');

  const bountyId = postRes.json.bounty_id;
  steps.push({ step: 'post_bounty', status: postRes.status, bounty_id: bountyId, elapsed_ms: postRes.elapsed_ms });

  const acceptRes = await acceptBounty({
    baseUrl: bountiesBaseUrl,
    bountyId,
    workerDid: workerIdentity.did,
    workerToken: workerToken.token,
    idempotencyKey: `smoke:trials:accept:${crypto.randomUUID()}`,
  });

  assert(acceptRes.status === 200 || acceptRes.status === 201, `accept bounty failed (${acceptRes.status}): ${acceptRes.text}`);
  steps.push({ step: 'accept_bounty', status: acceptRes.status, elapsed_ms: acceptRes.elapsed_ms });

  const proof = await buildProofArtifacts({
    agentDid: workerIdentity.did,
    privateKey: workerIdentity.privateKey,
    runId: `run_${crypto.randomUUID()}`,
    harnessId: 'sim-trials',
  });

  const submitRes = await submitBounty({
    baseUrl: bountiesBaseUrl,
    bountyId,
    workerDid: workerIdentity.did,
    workerToken: workerToken.token,
    idempotencyKey: `smoke:trials:submit:${crypto.randomUUID()}`,
    proofBundleEnvelope: proof.envelope,
    urm: proof.urm,
    resultSummary: 'submission for arbitration smoke',
    artifacts: [{ kind: 'log', uri: 'sim://clawtrials/smoke' }],
  });

  assert(submitRes.status === 200 || submitRes.status === 201, `submit failed (${submitRes.status}): ${submitRes.text}`);
  assert(typeof submitRes.json?.submission_id === 'string', 'submit response missing submission_id');

  const submissionId = submitRes.json.submission_id;
  steps.push({ step: 'submit', status: submitRes.status, submission_id: submissionId, elapsed_ms: submitRes.elapsed_ms });

  const rejectIdempotencyKey = `smoke:trials:reject:${crypto.randomUUID()}`;
  const rejectRes = await rejectBounty({
    baseUrl: bountiesBaseUrl,
    bountyId,
    requesterToken: requesterToken.token,
    requesterDid,
    submissionId,
    idempotencyKey: rejectIdempotencyKey,
    reason: 'Requester disputes submission quality',
    strictAuth: true,
  });

  assert(rejectRes.status === 200, `reject failed (${rejectRes.status}): ${rejectRes.text}`);
  assert(rejectRes.json?.status === 'disputed', `reject status mismatch: ${rejectRes.text}`);
  assert(typeof rejectRes.json?.trial_case?.case_id === 'string', `reject missing trial_case: ${rejectRes.text}`);

  const caseId = rejectRes.json.trial_case.case_id;
  steps.push({
    step: 'reject_and_intake_trial',
    status: rejectRes.status,
    trial_case_id: caseId,
    judge_did: rejectRes.json?.trial_case?.judge_did ?? null,
    elapsed_ms: rejectRes.elapsed_ms,
  });

  const getCaseRes = await getTrialCase(trialsBaseUrl, trialsAdminKey, caseId);
  assert(getCaseRes.status === 200, `get trial case failed (${getCaseRes.status}): ${getCaseRes.text}`);
  assert(getCaseRes.json?.case?.status === 'open', `expected open trial case, got ${getCaseRes.json?.case?.status}`);

  steps.push({ step: 'get_trial_case', status: getCaseRes.status, elapsed_ms: getCaseRes.elapsed_ms });

  const decisionIdempotency = `smoke:trials:decision:${crypto.randomUUID()}`;
  const decisionRes = await decideTrialCase({
    trialsBaseUrl,
    trialsAdminKey,
    caseId,
    idempotencyKey: decisionIdempotency,
    outcome: 'worker_award',
    decidedBy: judgeDid,
    rationale: 'Evidence satisfies completion criteria',
  });

  assert(decisionRes.status === 200, `decision failed (${decisionRes.status}): ${decisionRes.text}`);
  assert(decisionRes.json?.case?.status === 'decided', `decision case status mismatch: ${decisionRes.text}`);
  assert(decisionRes.json?.case?.resolution?.status === 'released', `decision did not enforce release: ${decisionRes.text}`);

  steps.push({ step: 'decision_enforced', status: decisionRes.status, elapsed_ms: decisionRes.elapsed_ms });

  const decisionReplay = await decideTrialCase({
    trialsBaseUrl,
    trialsAdminKey,
    caseId,
    idempotencyKey: decisionIdempotency,
    outcome: 'worker_award',
    decidedBy: judgeDid,
    rationale: 'Replay check',
  });

  assert(decisionReplay.status === 200, `decision replay failed (${decisionReplay.status}): ${decisionReplay.text}`);
  steps.push({ step: 'decision_replay', status: decisionReplay.status, elapsed_ms: decisionReplay.elapsed_ms });

  const decisionConflict = await decideTrialCase({
    trialsBaseUrl,
    trialsAdminKey,
    caseId,
    idempotencyKey: `smoke:trials:decision-conflict:${crypto.randomUUID()}`,
    outcome: 'worker_award',
    decidedBy: judgeDid,
    rationale: 'Conflict check',
  });

  assert(decisionConflict.status === 409, `decision conflict expected 409, got ${decisionConflict.status}: ${decisionConflict.text}`);
  steps.push({ step: 'decision_conflict', status: decisionConflict.status, elapsed_ms: decisionConflict.elapsed_ms });

  const appealRes = await appealTrialCase({
    trialsBaseUrl,
    trialsAdminKey,
    caseId,
    idempotencyKey: `smoke:trials:appeal:${crypto.randomUUID()}`,
    appealedBy: requesterDid,
    reason: 'Requesting appeal review',
  });

  assert(appealRes.status === 200, `appeal failed (${appealRes.status}): ${appealRes.text}`);
  assert(appealRes.json?.case?.status === 'appealed', `appeal case status mismatch: ${appealRes.text}`);
  steps.push({ step: 'appeal', status: appealRes.status, elapsed_ms: appealRes.elapsed_ms });

  const appealDecision = await decideTrialCase({
    trialsBaseUrl,
    trialsAdminKey,
    caseId,
    idempotencyKey: `smoke:trials:appeal-decision:${crypto.randomUUID()}`,
    outcome: 'worker_award',
    decidedBy: judgeDid,
    rationale: 'Appeal reaffirmed',
  });

  assert(appealDecision.status === 200, `appeal decision failed (${appealDecision.status}): ${appealDecision.text}`);
  assert(appealDecision.json?.case?.status === 'decided', `appeal decision status mismatch: ${appealDecision.text}`);
  steps.push({ step: 'appeal_decision', status: appealDecision.status, elapsed_ms: appealDecision.elapsed_ms });

  const outcomeChangeAttempt = await decideTrialCase({
    trialsBaseUrl,
    trialsAdminKey,
    caseId,
    idempotencyKey: `smoke:trials:appeal-change:${crypto.randomUUID()}`,
    outcome: 'requester_refund',
    decidedBy: judgeDid,
    rationale: 'Invalid outcome change attempt',
  });

  assert(
    outcomeChangeAttempt.status === 409,
    `outcome change expected 409, got ${outcomeChangeAttempt.status}: ${outcomeChangeAttempt.text}`
  );
  steps.push({ step: 'appeal_outcome_change_blocked', status: outcomeChangeAttempt.status, elapsed_ms: outcomeChangeAttempt.elapsed_ms });

  const metricsRes = await requestJson(`${trialsBaseUrl}/v1/trials/reports/disputes`, {
    method: 'GET',
    headers: { authorization: `Bearer ${trialsAdminKey}` },
  });

  assert(metricsRes.status === 200, `metrics failed (${metricsRes.status}): ${metricsRes.text}`);
  assert(typeof metricsRes.json?.totals?.total_cases === 'number', 'metrics missing totals.total_cases');
  steps.push({ step: 'metrics', status: metricsRes.status, elapsed_ms: metricsRes.elapsed_ms });

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, '../..');
  const artifact = makeArtifactDir(repoRoot, envName);
  await fs.mkdir(artifact.dir, { recursive: true });

  const summary = {
    ok: true,
    env: envName,
    generated_at: new Date().toISOString(),
    base_urls: {
      clawbounties: bountiesBaseUrl,
      clawtrials: trialsBaseUrl,
      clawclaim: claimBaseUrl,
    },
    requester: {
      did: requesterDid,
      token_hash: requesterToken.token_hash,
      token_kid: requesterToken.kid,
    },
    worker: {
      did: workerIdentity.did,
      token_hash: workerToken.token_hash,
      token_kid: workerToken.kid,
    },
    judge_did: judgeDid,
    bounty_id: bountyId,
    submission_id: submissionId,
    trial_case_id: caseId,
    steps,
    assertions: {
      dispute_intake: true,
      judge_assignment_present: Boolean(rejectRes.json?.trial_case?.judge_did),
      decision_enforcement_released: decisionRes.json?.case?.resolution?.status === 'released',
      replay_safe: decisionReplay.status === 200 && decisionConflict.status === 409,
      appeal_supported: appealRes.status === 200 && appealDecision.status === 200,
      appeal_outcome_change_blocked: outcomeChangeAttempt.status === 409,
    },
  };

  await writeJson(path.resolve(artifact.dir, 'smoke.json'), summary);

  console.log(
    JSON.stringify(
      {
        ...summary,
        artifact_dir: artifact.dir,
      },
      null,
      2
    )
  );
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(
    JSON.stringify(
      {
        ok: false,
        error: message,
      },
      null,
      2
    )
  );
  process.exit(1);
});
