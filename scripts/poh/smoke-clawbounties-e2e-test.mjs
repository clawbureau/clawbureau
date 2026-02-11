#!/usr/bin/env node

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseArgs,
  assert,
  resolveEnvName,
  resolveBountiesBaseUrl,
  resolveTrialsBaseUrl,
  requireEnv,
  randomDid,
  generateAgentIdentity,
  registerWorker,
  postBounty,
  acceptBounty,
  submitBounty,
  listBountySubmissions,
  getSubmissionDetail,
  buildProofArtifacts,
  buildCommitProofEnvelope,
  waitForSubmissionTerminal,
  createArtifactDir,
  writeJson,
  httpJson,
  extractErrorCode,
} from './_clawbounties-sim-common.mjs';

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = resolveEnvName(args.get('env'));

  const baseUrl = resolveBountiesBaseUrl(envName, args.get('clawbounties-base-url'));
  const trialsBaseUrl = resolveTrialsBaseUrl(envName, args.get('clawtrials-base-url'));
  const harnessId = String(args.get('harness-id') || 'th_smoke_pass_v1');
  const expectFinal = String(args.get('expect-final') || 'approved').trim();

  const adminKey = requireEnv('BOUNTIES_ADMIN_KEY');
  const requesterDid = String(args.get('requester-did') || '').trim() || randomDid('requester');
  assert(requesterDid.startsWith('did:'), 'requester-did must be a DID string');

  const harnessHealth = await httpJson(`${trialsBaseUrl}/health`, { method: 'GET' });
  assert(harnessHealth.status === 200, `clawtrials health failed (${harnessHealth.status}): ${harnessHealth.text}`);

  const harnessCatalog = await httpJson(`${trialsBaseUrl}/v1/harness/catalog`, { method: 'GET' });
  assert(harnessCatalog.status === 200, `clawtrials catalog failed (${harnessCatalog.status}): ${harnessCatalog.text}`);

  const identity = await generateAgentIdentity();
  const workerDid = identity.did;

  const steps = [
    { step: 'check_harness_health', ok: true, elapsed_ms: harnessHealth.elapsed_ms },
    {
      step: 'check_harness_catalog',
      ok: true,
      elapsed_ms: harnessCatalog.elapsed_ms,
      harness_count: Array.isArray(harnessCatalog.json?.harnesses) ? harnessCatalog.json.harnesses.length : 0,
    },
  ];

  const worker = await registerWorker(baseUrl, workerDid, ['simulation', 'test-flow']);
  steps.push({ step: 'register_worker', ok: true, elapsed_ms: worker.elapsed_ms });

  const postRes = await postBounty({
    baseUrl,
    adminKey,
    requesterDid,
    closureType: 'test',
    isCodeBounty: true,
    testHarnessId: harnessId,
    title: `Test-lane E2E ${new Date().toISOString()}`,
    description: 'Test closure simulation (API-only)',
    amountMinor: '300',
    tags: ['simulation', 'test-lane'],
    metadata: { simulation: true, flow: 'test' },
    idempotencyKey: `sim:test:post:${crypto.randomUUID()}`,
  });

  assert(postRes.status === 200 || postRes.status === 201, `post bounty failed (${postRes.status}): ${postRes.text}`);
  assert(postRes.json && typeof postRes.json.bounty_id === 'string', 'post bounty response missing bounty_id');
  const bountyId = postRes.json.bounty_id;
  steps.push({ step: 'post_bounty', ok: true, elapsed_ms: postRes.elapsed_ms, bounty_id: bountyId, harness_id: harnessId });

  const acceptRes = await acceptBounty({
    baseUrl,
    bountyId,
    workerDid,
    workerToken: worker.token,
    idempotencyKey: `sim:test:accept:${crypto.randomUUID()}`,
  });

  assert(acceptRes.status === 200 || acceptRes.status === 201, `accept bounty failed (${acceptRes.status}): ${acceptRes.text}`);
  steps.push({ step: 'accept_bounty', ok: true, elapsed_ms: acceptRes.elapsed_ms });

  const runId = `run_${crypto.randomUUID()}`;
  const proof = await buildProofArtifacts({
    agentDid: workerDid,
    privateKey: identity.privateKey,
    runId,
    harnessId,
  });

  const commitProofEnvelope = await buildCommitProofEnvelope({
    signerDid: workerDid,
    privateKey: identity.privateKey,
    runId,
    proofBundleHash: proof.payload_hash_b64u,
  });

  const submitRes = await submitBounty({
    baseUrl,
    bountyId,
    workerDid,
    workerToken: worker.token,
    idempotencyKey: `sim:test:submit:${crypto.randomUUID()}`,
    proofBundleEnvelope: proof.envelope,
    commitProofEnvelope,
    urm: proof.urm,
    resultSummary: 'test flow submission',
    artifacts: [{ kind: 'log', uri: 'sim://test-flow' }],
  });

  if (!(submitRes.status === 201 || submitRes.status === 200)) {
    const code = extractErrorCode(submitRes);
    throw new Error(`submit failed (${submitRes.status}, ${code}): ${submitRes.text}`);
  }

  assert(submitRes.json && typeof submitRes.json.submission_id === 'string', 'submit response missing submission_id');
  const submissionId = submitRes.json.submission_id;
  steps.push({ step: 'submit', ok: true, elapsed_ms: submitRes.elapsed_ms, submission_id: submissionId });

  const listRes = await listBountySubmissions({
    baseUrl,
    bountyId,
    workerToken: worker.token,
    params: { limit: 20 },
  });
  assert(listRes.status === 200, `list submissions failed (${listRes.status}): ${listRes.text}`);
  assert(Array.isArray(listRes.json?.submissions), 'list submissions response missing array');
  assert(listRes.json.submissions.some((s) => s.submission_id === submissionId), 'submission not present in list endpoint response');
  steps.push({ step: 'list_submissions', ok: true, elapsed_ms: listRes.elapsed_ms, count: listRes.json.submissions.length });

  const detail = await getSubmissionDetail({
    baseUrl,
    submissionId,
    workerToken: worker.token,
  });
  assert(detail.status === 200, `get submission detail failed (${detail.status}): ${detail.text}`);
  steps.push({ step: 'get_submission_detail', ok: true, elapsed_ms: detail.elapsed_ms, status: detail.json?.submission?.status ?? null });

  const terminal = await waitForSubmissionTerminal({
    baseUrl,
    submissionId,
    workerToken: worker.token,
    timeoutMs: 20_000,
    intervalMs: 1_000,
  });

  assert(terminal?.status === 200, `poll submission terminal failed (${terminal?.status}): ${terminal?.text}`);
  assert(terminal?.json?.submission?.status === expectFinal, `expected final status ${expectFinal}, got ${terminal?.json?.submission?.status}`);
  steps.push({ step: 'wait_terminal', ok: true, elapsed_ms: terminal.elapsed_ms, final_status: terminal.json.submission.status });

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, '../..');
  const artifact = await createArtifactDir(repoRoot, 'test-e2e');

  const summary = {
    ok: true,
    env: envName,
    base_url: baseUrl,
    clawtrials_base_url: trialsBaseUrl,
    requester_did: requesterDid,
    worker_did: workerDid,
    bounty_id: bountyId,
    submission_id: submissionId,
    harness_id: harnessId,
    expected_final_status: expectFinal,
    final_submission_status: terminal.json.submission.status,
    steps,
    generated_at: new Date().toISOString(),
  };

  await writeJson(path.resolve(artifact.dir, 'test-smoke.json'), summary);

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
