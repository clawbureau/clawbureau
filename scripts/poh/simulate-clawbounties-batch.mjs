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
  approveBounty,
  rejectBounty,
  listBountySubmissions,
  getSubmissionDetail,
  buildProofArtifacts,
  buildCommitProofEnvelope,
  waitForSubmissionTerminal,
  createArtifactDir,
  writeJson,
  appendNdjson,
  computeLatencyStats,
  httpJson,
  extractErrorCode,
} from './_clawbounties-sim-common.mjs';

function nowIso() {
  return new Date().toISOString();
}

function pickClosureType(index) {
  return index % 2 === 0 ? 'requester' : 'test';
}

function expectedRequesterDecision(index) {
  return index % 4 === 0 ? 'rejected' : 'approved';
}

async function runRequesterJob({
  jobId,
  index,
  baseUrl,
  adminKey,
  requesterDid,
}) {
  const startedAt = nowIso();
  const stepResults = [];

  function pushStep(step) {
    stepResults.push(step);
  }

  try {
    const identity = await generateAgentIdentity();
    const workerDid = identity.did;

    const worker = await registerWorker(baseUrl, workerDid, ['simulation', 'batch', 'requester']);
    pushStep({ step: 'register_worker', ok: true, elapsed_ms: worker.elapsed_ms, status: 201 });

    const postRes = await postBounty({
      baseUrl,
      requesterToken: adminKey,
      requesterDid,
      closureType: 'requester',
      isCodeBounty: false,
      title: `Batch requester ${jobId}`,
      description: `Batch requester job ${jobId}`,
      amountMinor: '200',
      tags: ['simulation', 'batch', 'requester'],
      metadata: { simulation: true, flow: 'requester', job_id: jobId },
      idempotencyKey: `sim:batch:req:post:${jobId}`,
    });

    if (!(postRes.status === 200 || postRes.status === 201)) {
      pushStep({ step: 'post_bounty', ok: false, elapsed_ms: postRes.elapsed_ms, status: postRes.status, error_code: extractErrorCode(postRes) });
      return {
        job_id: jobId,
        closure_type: 'requester',
        ok: false,
        error_code: extractErrorCode(postRes),
        error_message: postRes.text,
        step_results: stepResults,
        started_at: startedAt,
        ended_at: nowIso(),
      };
    }

    const bountyId = postRes.json?.bounty_id;
    pushStep({ step: 'post_bounty', ok: true, elapsed_ms: postRes.elapsed_ms, status: postRes.status, bounty_id: bountyId });

    const acceptRes = await acceptBounty({
      baseUrl,
      bountyId,
      workerDid,
      workerToken: worker.token,
      idempotencyKey: `sim:batch:req:accept:${jobId}`,
    });

    if (!(acceptRes.status === 200 || acceptRes.status === 201)) {
      pushStep({ step: 'accept_bounty', ok: false, elapsed_ms: acceptRes.elapsed_ms, status: acceptRes.status, error_code: extractErrorCode(acceptRes) });
      return {
        job_id: jobId,
        closure_type: 'requester',
        ok: false,
        bounty_id: bountyId,
        error_code: extractErrorCode(acceptRes),
        error_message: acceptRes.text,
        step_results: stepResults,
        started_at: startedAt,
        ended_at: nowIso(),
      };
    }

    pushStep({ step: 'accept_bounty', ok: true, elapsed_ms: acceptRes.elapsed_ms, status: acceptRes.status });

    const runId = `run_${crypto.randomUUID()}`;
    const proof = await buildProofArtifacts({
      agentDid: workerDid,
      privateKey: identity.privateKey,
      runId,
      harnessId: 'sim-batch-requester',
    });

    const submitRes = await submitBounty({
      baseUrl,
      bountyId,
      workerDid,
      workerToken: worker.token,
      idempotencyKey: `sim:batch:req:submit:${jobId}`,
      proofBundleEnvelope: proof.envelope,
      urm: proof.urm,
      resultSummary: `batch requester submission ${jobId}`,
      artifacts: [{ kind: 'log', uri: `sim://batch/requester/${jobId}` }],
    });

    if (!(submitRes.status === 200 || submitRes.status === 201)) {
      pushStep({ step: 'submit', ok: false, elapsed_ms: submitRes.elapsed_ms, status: submitRes.status, error_code: extractErrorCode(submitRes) });
      return {
        job_id: jobId,
        closure_type: 'requester',
        ok: false,
        bounty_id: bountyId,
        error_code: extractErrorCode(submitRes),
        error_message: submitRes.text,
        step_results: stepResults,
        started_at: startedAt,
        ended_at: nowIso(),
      };
    }

    const submissionId = submitRes.json?.submission_id;
    pushStep({ step: 'submit', ok: true, elapsed_ms: submitRes.elapsed_ms, status: submitRes.status, submission_id: submissionId });

    const listRes = await listBountySubmissions({
      baseUrl,
      bountyId,
      requesterToken: adminKey,
      requesterDid,
      params: { limit: 20 },
    });

    if (listRes.status !== 200) {
      pushStep({ step: 'list_submissions', ok: false, elapsed_ms: listRes.elapsed_ms, status: listRes.status, error_code: extractErrorCode(listRes) });
    } else {
      pushStep({ step: 'list_submissions', ok: true, elapsed_ms: listRes.elapsed_ms, status: listRes.status, count: Array.isArray(listRes.json?.submissions) ? listRes.json.submissions.length : 0 });
    }

    const detailBefore = await getSubmissionDetail({
      baseUrl,
      submissionId,
      requesterToken: adminKey,
      requesterDid,
    });

    if (detailBefore.status !== 200) {
      pushStep({ step: 'get_submission_detail', ok: false, elapsed_ms: detailBefore.elapsed_ms, status: detailBefore.status, error_code: extractErrorCode(detailBefore) });
      return {
        job_id: jobId,
        closure_type: 'requester',
        ok: false,
        bounty_id: bountyId,
        submission_id: submissionId,
        error_code: extractErrorCode(detailBefore),
        error_message: detailBefore.text,
        step_results: stepResults,
        started_at: startedAt,
        ended_at: nowIso(),
      };
    }

    pushStep({
      step: 'get_submission_detail',
      ok: true,
      elapsed_ms: detailBefore.elapsed_ms,
      status: detailBefore.status,
      submission_status: detailBefore.json?.submission?.status ?? null,
    });

    const decision = expectedRequesterDecision(index);
    let decisionRes;

    if (decision === 'approved') {
      decisionRes = await approveBounty({
        baseUrl,
        bountyId,
        requesterToken: adminKey,
        requesterDid,
        submissionId,
        idempotencyKey: `sim:batch:req:approve:${jobId}`,
      });
    } else {
      decisionRes = await rejectBounty({
        baseUrl,
        bountyId,
        requesterToken: adminKey,
        requesterDid,
        submissionId,
        idempotencyKey: `sim:batch:req:reject:${jobId}`,
        reason: `batch deterministic rejection ${jobId}`,
      });
    }

    if (decisionRes.status !== 200) {
      pushStep({
        step: decision === 'approved' ? 'approve' : 'reject',
        ok: false,
        elapsed_ms: decisionRes.elapsed_ms,
        status: decisionRes.status,
        error_code: extractErrorCode(decisionRes),
      });
      return {
        job_id: jobId,
        closure_type: 'requester',
        ok: false,
        bounty_id: bountyId,
        submission_id: submissionId,
        error_code: extractErrorCode(decisionRes),
        error_message: decisionRes.text,
        step_results: stepResults,
        started_at: startedAt,
        ended_at: nowIso(),
      };
    }

    pushStep({
      step: decision === 'approved' ? 'approve' : 'reject',
      ok: true,
      elapsed_ms: decisionRes.elapsed_ms,
      status: decisionRes.status,
    });

    const terminal = await waitForSubmissionTerminal({
      baseUrl,
      submissionId,
      requesterToken: adminKey,
      requesterDid,
      timeoutMs: 20_000,
      intervalMs: 700,
    });

    const finalStatus = terminal?.json?.submission?.status ?? null;
    const expectedFinal = decision === 'approved' ? 'approved' : 'rejected';

    const terminalOk = terminal?.status === 200 && finalStatus === expectedFinal;
    pushStep({
      step: 'wait_terminal',
      ok: terminalOk,
      elapsed_ms: terminal?.elapsed_ms ?? null,
      status: terminal?.status ?? null,
      final_status: finalStatus,
      expected_final: expectedFinal,
      error_code: terminalOk ? null : extractErrorCode(terminal ?? {}),
    });

    return {
      job_id: jobId,
      closure_type: 'requester',
      decision,
      ok: terminalOk,
      bounty_id: bountyId,
      submission_id: submissionId,
      final_status: finalStatus,
      error_code: terminalOk ? null : extractErrorCode(terminal ?? {}),
      error_message: terminalOk ? null : terminal?.text ?? 'terminal state check failed',
      step_results: stepResults,
      started_at: startedAt,
      ended_at: nowIso(),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      job_id: jobId,
      closure_type: 'requester',
      ok: false,
      error_code: 'UNCAUGHT',
      error_message: message,
      step_results: stepResults,
      started_at: startedAt,
      ended_at: nowIso(),
    };
  }
}

async function runTestJob({
  jobId,
  baseUrl,
  adminKey,
  requesterDid,
  harnessId,
}) {
  const startedAt = nowIso();
  const stepResults = [];

  function pushStep(step) {
    stepResults.push(step);
  }

  try {
    const identity = await generateAgentIdentity();
    const workerDid = identity.did;

    const worker = await registerWorker(baseUrl, workerDid, ['simulation', 'batch', 'test']);
    pushStep({ step: 'register_worker', ok: true, elapsed_ms: worker.elapsed_ms, status: 201 });

    const postRes = await postBounty({
      baseUrl,
      adminKey,
      requesterDid,
      closureType: 'test',
      isCodeBounty: true,
      testHarnessId: harnessId,
      title: `Batch test ${jobId}`,
      description: `Batch test job ${jobId}`,
      amountMinor: '200',
      tags: ['simulation', 'batch', 'test'],
      metadata: { simulation: true, flow: 'test', job_id: jobId },
      idempotencyKey: `sim:batch:test:post:${jobId}`,
    });

    if (!(postRes.status === 200 || postRes.status === 201)) {
      pushStep({ step: 'post_bounty', ok: false, elapsed_ms: postRes.elapsed_ms, status: postRes.status, error_code: extractErrorCode(postRes) });
      return {
        job_id: jobId,
        closure_type: 'test',
        ok: false,
        error_code: extractErrorCode(postRes),
        error_message: postRes.text,
        step_results: stepResults,
        started_at: startedAt,
        ended_at: nowIso(),
      };
    }

    const bountyId = postRes.json?.bounty_id;
    pushStep({ step: 'post_bounty', ok: true, elapsed_ms: postRes.elapsed_ms, status: postRes.status, bounty_id: bountyId, harness_id: harnessId });

    const acceptRes = await acceptBounty({
      baseUrl,
      bountyId,
      workerDid,
      workerToken: worker.token,
      idempotencyKey: `sim:batch:test:accept:${jobId}`,
    });

    if (!(acceptRes.status === 200 || acceptRes.status === 201)) {
      pushStep({ step: 'accept_bounty', ok: false, elapsed_ms: acceptRes.elapsed_ms, status: acceptRes.status, error_code: extractErrorCode(acceptRes) });
      return {
        job_id: jobId,
        closure_type: 'test',
        ok: false,
        bounty_id: bountyId,
        error_code: extractErrorCode(acceptRes),
        error_message: acceptRes.text,
        step_results: stepResults,
        started_at: startedAt,
        ended_at: nowIso(),
      };
    }

    pushStep({ step: 'accept_bounty', ok: true, elapsed_ms: acceptRes.elapsed_ms, status: acceptRes.status });

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
      idempotencyKey: `sim:batch:test:submit:${jobId}`,
      proofBundleEnvelope: proof.envelope,
      commitProofEnvelope,
      urm: proof.urm,
      resultSummary: `batch test submission ${jobId}`,
      artifacts: [{ kind: 'log', uri: `sim://batch/test/${jobId}` }],
    });

    if (!(submitRes.status === 200 || submitRes.status === 201)) {
      pushStep({ step: 'submit', ok: false, elapsed_ms: submitRes.elapsed_ms, status: submitRes.status, error_code: extractErrorCode(submitRes) });
      return {
        job_id: jobId,
        closure_type: 'test',
        ok: false,
        bounty_id: bountyId,
        error_code: extractErrorCode(submitRes),
        error_message: submitRes.text,
        step_results: stepResults,
        started_at: startedAt,
        ended_at: nowIso(),
      };
    }

    const submissionId = submitRes.json?.submission_id;
    pushStep({ step: 'submit', ok: true, elapsed_ms: submitRes.elapsed_ms, status: submitRes.status, submission_id: submissionId });

    const listRes = await listBountySubmissions({
      baseUrl,
      bountyId,
      workerToken: worker.token,
      params: { limit: 20 },
    });

    if (listRes.status !== 200) {
      pushStep({ step: 'list_submissions', ok: false, elapsed_ms: listRes.elapsed_ms, status: listRes.status, error_code: extractErrorCode(listRes) });
    } else {
      pushStep({ step: 'list_submissions', ok: true, elapsed_ms: listRes.elapsed_ms, status: listRes.status, count: Array.isArray(listRes.json?.submissions) ? listRes.json.submissions.length : 0 });
    }

    const detail = await getSubmissionDetail({
      baseUrl,
      submissionId,
      workerToken: worker.token,
    });

    if (detail.status !== 200) {
      pushStep({ step: 'get_submission_detail', ok: false, elapsed_ms: detail.elapsed_ms, status: detail.status, error_code: extractErrorCode(detail) });
      return {
        job_id: jobId,
        closure_type: 'test',
        ok: false,
        bounty_id: bountyId,
        submission_id: submissionId,
        error_code: extractErrorCode(detail),
        error_message: detail.text,
        step_results: stepResults,
        started_at: startedAt,
        ended_at: nowIso(),
      };
    }

    pushStep({
      step: 'get_submission_detail',
      ok: true,
      elapsed_ms: detail.elapsed_ms,
      status: detail.status,
      submission_status: detail.json?.submission?.status ?? null,
    });

    const terminal = await waitForSubmissionTerminal({
      baseUrl,
      submissionId,
      workerToken: worker.token,
      timeoutMs: 20_000,
      intervalMs: 700,
    });

    const finalStatus = terminal?.json?.submission?.status ?? null;
    const terminalOk = terminal?.status === 200 && (finalStatus === 'approved' || finalStatus === 'rejected');

    pushStep({
      step: 'wait_terminal',
      ok: terminalOk,
      elapsed_ms: terminal?.elapsed_ms ?? null,
      status: terminal?.status ?? null,
      final_status: finalStatus,
      error_code: terminalOk ? null : extractErrorCode(terminal ?? {}),
    });

    return {
      job_id: jobId,
      closure_type: 'test',
      ok: terminalOk,
      bounty_id: bountyId,
      submission_id: submissionId,
      final_status: finalStatus,
      error_code: terminalOk ? null : extractErrorCode(terminal ?? {}),
      error_message: terminalOk ? null : terminal?.text ?? 'terminal state check failed',
      step_results: stepResults,
      started_at: startedAt,
      ended_at: nowIso(),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      job_id: jobId,
      closure_type: 'test',
      ok: false,
      error_code: 'UNCAUGHT',
      error_message: message,
      step_results: stepResults,
      started_at: startedAt,
      ended_at: nowIso(),
    };
  }
}

async function runWithConcurrency(jobs, concurrency, workerFn) {
  const results = new Array(jobs.length);
  let cursor = 0;

  async function runner() {
    while (true) {
      const idx = cursor;
      cursor += 1;
      if (idx >= jobs.length) return;

      const job = jobs[idx];
      results[idx] = await workerFn(job, idx);
    }
  }

  const workers = [];
  for (let i = 0; i < Math.max(1, concurrency); i += 1) {
    workers.push(runner());
  }

  await Promise.all(workers);
  return results;
}

function summarize(results, {
  envName,
  baseUrl,
  trialsBaseUrl,
  total,
  concurrency,
  harnessId,
  runLabel,
  requesterDidMode,
  requesterDid,
}) {
  const stepBuckets = new Map();
  const errorBuckets = {};
  const closureBreakdown = {
    requester: { total: 0, success: 0, failed: 0 },
    test: { total: 0, success: 0, failed: 0 },
  };
  const stuckStateCounts = {
    pending_review: 0,
    unknown: 0,
  };

  for (const result of results) {
    const closure = result.closure_type;
    closureBreakdown[closure].total += 1;
    if (result.ok) {
      closureBreakdown[closure].success += 1;
    } else {
      closureBreakdown[closure].failed += 1;
      const code = result.error_code || 'UNKNOWN';
      errorBuckets[code] = (errorBuckets[code] || 0) + 1;
    }

    if (result.final_status === 'pending_review') {
      stuckStateCounts.pending_review += 1;
    }
    if (!result.final_status) {
      stuckStateCounts.unknown += 1;
    }

    for (const step of result.step_results ?? []) {
      const key = step.step;
      if (!stepBuckets.has(key)) {
        stepBuckets.set(key, {
          success: 0,
          failure: 0,
          latencies: [],
        });
      }
      const bucket = stepBuckets.get(key);
      if (step.ok) bucket.success += 1;
      else bucket.failure += 1;
      if (typeof step.elapsed_ms === 'number') {
        bucket.latencies.push(step.elapsed_ms);
      }
    }
  }

  const stepSummary = {};
  for (const [step, bucket] of stepBuckets.entries()) {
    stepSummary[step] = {
      success: bucket.success,
      failure: bucket.failure,
      latency: computeLatencyStats(bucket.latencies),
    };
  }

  const successJobs = results.filter((r) => r.ok).length;
  const failedJobs = results.length - successJobs;

  return {
    ok: failedJobs === 0,
    run_label: runLabel,
    env: envName,
    base_url: baseUrl,
    clawtrials_base_url: trialsBaseUrl,
    total_jobs: total,
    concurrency,
    harness_id: harnessId,
    requester_did_mode: requesterDidMode,
    requester_did: requesterDid,
    success_jobs: successJobs,
    failed_jobs: failedJobs,
    closure_type_breakdown: closureBreakdown,
    deterministic_error_buckets: errorBuckets,
    stuck_state_counts: stuckStateCounts,
    step_metrics: stepSummary,
    generated_at: nowIso(),
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = resolveEnvName(args.get('env'));

  const total = Number.parseInt(String(args.get('total') || '10'), 10);
  assert(Number.isFinite(total) && total > 0, 'total must be a positive integer');

  const concurrency = Number.parseInt(String(args.get('concurrency') || '4'), 10);
  assert(Number.isFinite(concurrency) && concurrency > 0, 'concurrency must be a positive integer');

  const runLabel = String(args.get('label') || `batch-${total}`);
  const harnessId = String(args.get('harness-id') || 'th_smoke_pass_v1');

  const baseUrl = resolveBountiesBaseUrl(envName, args.get('clawbounties-base-url'));
  const trialsBaseUrl = resolveTrialsBaseUrl(envName, args.get('clawtrials-base-url'));

  const adminKey = requireEnv('BOUNTIES_ADMIN_KEY');

  const requesterDidOverrideRaw = String(args.get('requester-did') || '').trim();
  const requesterDidOverride = requesterDidOverrideRaw.length > 0 ? requesterDidOverrideRaw : null;
  if (requesterDidOverride) {
    assert(requesterDidOverride.startsWith('did:'), 'requester-did must be a DID string when provided');
  }

  const bountiesHealth = await httpJson(`${baseUrl}/health`, { method: 'GET' });
  assert(bountiesHealth.status === 200, `clawbounties health failed (${bountiesHealth.status}): ${bountiesHealth.text}`);

  const trialsHealth = await httpJson(`${trialsBaseUrl}/health`, { method: 'GET' });
  assert(trialsHealth.status === 200, `clawtrials health failed (${trialsHealth.status}): ${trialsHealth.text}`);

  const jobs = Array.from({ length: total }, (_, index) => {
    const closureType = pickClosureType(index);
    return {
      index,
      job_id: `${runLabel}-${String(index + 1).padStart(3, '0')}`,
      closure_type: closureType,
      requester_did: requesterDidOverride ?? randomDid(`req${index}`),
    };
  });

  const results = await runWithConcurrency(jobs, concurrency, async (job, idx) => {
    if (job.closure_type === 'requester') {
      return runRequesterJob({
        jobId: job.job_id,
        index: idx,
        baseUrl,
        adminKey,
        requesterDid: job.requester_did,
      });
    }

    return runTestJob({
      jobId: job.job_id,
      baseUrl,
      adminKey,
      requesterDid: job.requester_did,
      harnessId,
    });
  });

  const summary = summarize(results, {
    envName,
    baseUrl,
    trialsBaseUrl,
    total,
    concurrency,
    harnessId,
    runLabel,
    requesterDidMode: requesterDidOverride ? 'fixed' : 'per-job',
    requesterDid: requesterDidOverride,
  });

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, '../..');
  const artifact = await createArtifactDir(repoRoot, `batch-${total}`);

  await writeJson(path.resolve(artifact.dir, 'summary.json'), {
    ...summary,
    preflight: {
      clawbounties_health_ms: bountiesHealth.elapsed_ms,
      clawtrials_health_ms: trialsHealth.elapsed_ms,
    },
  });

  await appendNdjson(path.resolve(artifact.dir, 'jobs.ndjson'), results);

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

  if (!summary.ok) {
    process.exitCode = 1;
  }
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
