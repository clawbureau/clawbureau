#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseArgs,
  assert,
  resolveEnvName,
  resolveBountiesBaseUrl,
  resolveScopeBaseUrl,
  resolveRequesterAudience,
  resolveRequesterScopes,
  resolveWorkerAudience,
  resolveWorkerScopes,
  issueRequesterScopedToken,
  issueWorkerScopedToken,
  randomDid,
  generateAgentIdentity,
  registerWorker,
  postBounty,
  acceptBounty,
  submitBounty,
  approveBounty,
  listBountySubmissions,
  getSubmissionDetail,
  buildProofArtifacts,
  waitForSubmissionTerminal,
  createArtifactDir,
  writeJson,
} from './_clawbounties-sim-common.mjs';

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = resolveEnvName(args.get('env'));
  const baseUrl = resolveBountiesBaseUrl(envName, args.get('clawbounties-base-url'));

  const strictAuthRaw = String(args.get('strict-auth') ?? 'true').trim().toLowerCase();
  const strictAuth = !(strictAuthRaw === 'false' || strictAuthRaw === '0' || strictAuthRaw === 'no' || strictAuthRaw === 'off');

  const scopeBaseUrl = resolveScopeBaseUrl(envName, args.get('scope-base-url'));
  const scopeAdminKey = String(args.get('scope-admin-key') || process.env.SCOPE_ADMIN_KEY || process.env.CLAWSCOPE_ADMIN_KEY || '').trim();

  const requesterDid = String(args.get('requester-did') || '').trim() || randomDid('requester');
  assert(requesterDid.startsWith('did:'), 'requester-did must be a DID string');

  let requesterToken = String(args.get('requester-token') || process.env.REQUESTER_SCOPED_TOKEN || '').trim();
  let requesterTokenSource = 'provided';
  let requesterTokenKid = null;
  let requesterTokenHash = null;

  if (!requesterToken) {
    assert(
      scopeAdminKey.length > 0,
      'Missing requester auth input. Provide --requester-token / REQUESTER_SCOPED_TOKEN or set --scope-admin-key / SCOPE_ADMIN_KEY for clawscope issuance.'
    );

    const audience = resolveRequesterAudience(envName, args.get('requester-audience'));
    const scopes = resolveRequesterScopes(args.get('requester-scopes'));
    const ttlSec = Number.parseInt(String(args.get('requester-token-ttl-sec') || '3600'), 10);
    assert(Number.isFinite(ttlSec) && ttlSec > 0, 'requester-token-ttl-sec must be a positive integer');

    const issued = await issueRequesterScopedToken({
      scopeBaseUrl,
      scopeAdminKey,
      requesterDid,
      audience,
      scopes,
      ttlSec,
      source: 'smoke-clawbounties-e2e-requester',
    });

    requesterToken = issued.token;
    requesterTokenSource = 'clawscope-issue';
    requesterTokenKid = issued.kid;
    requesterTokenHash = issued.token_hash;
  }

  const identity = await generateAgentIdentity();
  const workerDid = identity.did;

  let workerToken = String(args.get('worker-token') || process.env.WORKER_SCOPED_TOKEN || '').trim();
  let workerTokenSource = workerToken ? 'provided' : 'clawscope-issue';
  let workerTokenKid = null;
  let workerTokenHash = null;

  const steps = [];

  const worker = await registerWorker(baseUrl, workerDid, ['simulation', 'requester-flow']);
  steps.push({ step: 'register_worker', ok: true, elapsed_ms: worker.elapsed_ms });

  if (!workerToken) {
    assert(scopeAdminKey.length > 0, 'scope-admin-key / SCOPE_ADMIN_KEY is required to mint worker scoped token');
    const audience = resolveWorkerAudience(envName, args.get('worker-audience'));
    const scopes = resolveWorkerScopes(args.get('worker-scopes'));
    const ttlSec = Number.parseInt(String(args.get('worker-token-ttl-sec') || '3600'), 10);
    assert(Number.isFinite(ttlSec) && ttlSec > 0, 'worker-token-ttl-sec must be a positive integer');

    const issuedWorker = await issueWorkerScopedToken({
      scopeBaseUrl,
      scopeAdminKey,
      workerDid,
      audience,
      scopes,
      ttlSec,
      source: 'smoke-clawbounties-e2e-requester',
    });

    workerToken = issuedWorker.token;
    workerTokenKid = issuedWorker.kid;
    workerTokenHash = issuedWorker.token_hash;
  }

  const postRes = await postBounty({
    baseUrl,
    requesterToken,
    requesterDid,
    closureType: 'requester',
    isCodeBounty: false,
    title: `Requester E2E ${new Date().toISOString()}`,
    description: 'Requester flow simulation (API-only)',
    amountMinor: '250',
    tags: ['simulation', 'requester'],
    metadata: { simulation: true, flow: 'requester' },
    idempotencyKey: `sim:req:post:${crypto.randomUUID()}`,
    strictAuth,
  });

  assert(postRes.status === 200 || postRes.status === 201, `post bounty failed (${postRes.status}): ${postRes.text}`);
  assert(postRes.json && typeof postRes.json.bounty_id === 'string', 'post bounty response missing bounty_id');
  const bountyId = postRes.json.bounty_id;
  steps.push({ step: 'post_bounty', ok: true, elapsed_ms: postRes.elapsed_ms, bounty_id: bountyId });

  const acceptRes = await acceptBounty({
    baseUrl,
    bountyId,
    workerDid,
    workerToken,
    idempotencyKey: `sim:req:accept:${crypto.randomUUID()}`,
  });

  assert(acceptRes.status === 200 || acceptRes.status === 201, `accept bounty failed (${acceptRes.status}): ${acceptRes.text}`);
  steps.push({ step: 'accept_bounty', ok: true, elapsed_ms: acceptRes.elapsed_ms });

  const runId = `run_${crypto.randomUUID()}`;
  const proof = await buildProofArtifacts({
    agentDid: workerDid,
    privateKey: identity.privateKey,
    runId,
    harnessId: 'sim-requester',
  });

  const submitRes = await submitBounty({
    baseUrl,
    bountyId,
    workerDid,
    workerToken,
    idempotencyKey: `sim:req:submit:${crypto.randomUUID()}`,
    proofBundleEnvelope: proof.envelope,
    urm: proof.urm,
    resultSummary: 'requester flow submission',
    artifacts: [{ kind: 'log', uri: 'sim://requester-flow' }],
  });

  assert(submitRes.status === 201 || submitRes.status === 200, `submit failed (${submitRes.status}): ${submitRes.text}`);
  assert(submitRes.json && typeof submitRes.json.submission_id === 'string', 'submit response missing submission_id');
  const submissionId = submitRes.json.submission_id;
  steps.push({ step: 'submit', ok: true, elapsed_ms: submitRes.elapsed_ms, submission_id: submissionId });

  const listRes = await listBountySubmissions({
    baseUrl,
    bountyId,
    requesterToken,
    requesterDid,
    params: { limit: 20 },
    strictAuth,
  });
  assert(listRes.status === 200, `list submissions failed (${listRes.status}): ${listRes.text}`);
  assert(Array.isArray(listRes.json?.submissions), 'list submissions response missing array');
  assert(listRes.json.submissions.some((s) => s.submission_id === submissionId), 'submission not present in list endpoint response');
  steps.push({ step: 'list_submissions', ok: true, elapsed_ms: listRes.elapsed_ms, count: listRes.json.submissions.length });

  const detailBefore = await getSubmissionDetail({
    baseUrl,
    submissionId,
    requesterToken,
    requesterDid,
    strictAuth,
  });
  assert(detailBefore.status === 200, `get submission detail failed (${detailBefore.status}): ${detailBefore.text}`);
  assert(detailBefore.json?.submission?.status === 'pending_review', `expected pending_review before approval, got ${detailBefore.json?.submission?.status}`);
  steps.push({ step: 'get_submission_before_approval', ok: true, elapsed_ms: detailBefore.elapsed_ms, status: detailBefore.json.submission.status });

  const approveRes = await approveBounty({
    baseUrl,
    bountyId,
    requesterToken,
    requesterDid,
    submissionId,
    idempotencyKey: `sim:req:approve:${crypto.randomUUID()}`,
    strictAuth,
  });

  assert(approveRes.status === 200, `approve failed (${approveRes.status}): ${approveRes.text}`);
  assert(approveRes.json?.status === 'approved', `approve response unexpected status: ${approveRes.text}`);
  steps.push({ step: 'approve', ok: true, elapsed_ms: approveRes.elapsed_ms });

  const terminal = await waitForSubmissionTerminal({
    baseUrl,
    submissionId,
    requesterToken,
    requesterDid,
    timeoutMs: 20_000,
    intervalMs: 1_000,
    strictAuth,
  });

  assert(terminal?.status === 200, `poll submission terminal failed (${terminal?.status}): ${terminal?.text}`);
  assert(terminal?.json?.submission?.status === 'approved', `expected approved submission, got ${terminal?.json?.submission?.status}`);
  steps.push({ step: 'wait_terminal', ok: true, elapsed_ms: terminal.elapsed_ms, final_status: terminal.json.submission.status });

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, '../..');
  const artifact = await createArtifactDir(repoRoot, 'requester-e2e');

  const summary = {
    ok: true,
    env: envName,
    base_url: baseUrl,
    requester_did: requesterDid,
    requester_token_source: requesterTokenSource,
    requester_token_kid: requesterTokenKid,
    requester_token_hash: requesterTokenHash,
    worker_did: workerDid,
    worker_token_source: workerTokenSource,
    worker_token_kid: workerTokenKid,
    worker_token_hash: workerTokenHash,
    strict_auth: strictAuth,
    bounty_id: bountyId,
    submission_id: submissionId,
    steps,
    final_submission_status: terminal.json.submission.status,
    generated_at: new Date().toISOString(),
  };

  await writeJson(path.resolve(artifact.dir, 'requester-smoke.json'), summary);

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
