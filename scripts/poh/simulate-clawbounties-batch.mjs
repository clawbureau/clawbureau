#!/usr/bin/env node

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

const TERMINAL_STATUSES = new Set(['approved', 'rejected', 'invalid']);

function parseBoolean(raw, fallback = false) {
  if (raw === undefined || raw === null) return fallback;
  const value = String(raw).trim().toLowerCase();
  if (value === '1' || value === 'true' || value === 'yes' || value === 'on') return true;
  if (value === '0' || value === 'false' || value === 'no' || value === 'off') return false;
  return fallback;
}

function resolveScopeAdminKey(args) {
  const fromArg = String(args.get('scope-admin-key') || '').trim();
  if (fromArg) return fromArg;

  const fromEnv = String(process.env.SCOPE_ADMIN_KEY || process.env.CLAWSCOPE_ADMIN_KEY || '').trim();
  return fromEnv || null;
}

async function resolveRequesterAuth({
  args,
  envName,
  requesterDid,
}) {
  const direct = String(args.get('requester-token') || process.env.REQUESTER_SCOPED_TOKEN || '').trim();
  if (direct) {
    return {
      requesterToken: direct,
      requesterTokenSource: 'provided',
      requesterTokenKid: null,
      requesterTokenHash: null,
      requesterAudience: resolveRequesterAudience(envName, args.get('requester-audience')),
      scopeBaseUrl: resolveScopeBaseUrl(envName, args.get('scope-base-url')),
    };
  }

  const scopeAdminKey = resolveScopeAdminKey(args);
  assert(
    scopeAdminKey,
    'Missing requester auth input. Provide --requester-token / REQUESTER_SCOPED_TOKEN or set --scope-admin-key / SCOPE_ADMIN_KEY to auto-issue via clawscope.'
  );

  const requesterAudience = resolveRequesterAudience(envName, args.get('requester-audience'));
  const scopeBaseUrl = resolveScopeBaseUrl(envName, args.get('scope-base-url'));
  const scopes = resolveRequesterScopes(args.get('requester-scopes'));
  const ttlSeconds = Number.parseInt(String(args.get('requester-token-ttl-sec') || '3600'), 10);
  assert(Number.isFinite(ttlSeconds) && ttlSeconds > 0, 'requester-token-ttl-sec must be a positive integer');

  const issued = await issueRequesterScopedToken({
    scopeBaseUrl,
    scopeAdminKey,
    requesterDid,
    audience: requesterAudience,
    scopes,
    ttlSec: ttlSeconds,
    source: 'simulate-clawbounties-batch',
  });

  return {
    requesterToken: issued.token,
    requesterTokenSource: 'clawscope-issue',
    requesterTokenKid: issued.kid,
    requesterTokenHash: issued.token_hash,
    requesterAudience,
    scopeBaseUrl,
  };
}

async function issueWorkerTokenForJob({
  workerDid,
  strictAuth,
  scopeAdminKey,
  scopeBaseUrl,
  workerAudience,
  workerScopes,
  workerTokenTtlSec,
  source,
  legacyWorkerToken,
}) {
  if (!strictAuth) {
    return {
      token: legacyWorkerToken,
      source: 'legacy-register',
      kid: null,
      token_hash: null,
    };
  }

  assert(scopeAdminKey, 'scope-admin-key / SCOPE_ADMIN_KEY is required in strict auth mode');

  const issued = await issueWorkerScopedToken({
    scopeBaseUrl,
    scopeAdminKey,
    workerDid,
    audience: workerAudience,
    scopes: workerScopes,
    ttlSec: workerTokenTtlSec,
    source,
  });

  return {
    token: issued.token,
    source: 'clawscope-issue',
    kid: issued.kid,
    token_hash: issued.token_hash,
  };
}

function classifyErrorBucket(errorCode, errorMessage) {
  const code = String(errorCode || 'UNKNOWN').trim().toUpperCase();
  const message = String(errorMessage || '').toUpperCase();

  if (code === 'ABORTED') return 'ABORTED';
  if (message.includes('INSUFFICIENT_FUNDS') || code === 'INSUFFICIENT_FUNDS') return 'INSUFFICIENT_FUNDS';

  if (
    code === 'REQUESTER_TOKEN_REQUIRED' ||
    code === 'REQUESTER_TOKEN_INVALID' ||
    code === 'REQUESTER_SCOPE_REQUIRED' ||
    code === 'REQUESTER_SUB_MISMATCH' ||
    code === 'REQUESTER_AUDIENCE_REQUIRED' ||
    code === 'REQUESTER_SUB_INVALID' ||
    code === 'REQUESTER_CONTROL_CLAIM_REQUIRED' ||
    code === 'REQUESTER_CONTROL_CLAIM_INVALID' ||
    code === 'REQUESTER_CONTROL_BINDING_MISMATCH' ||
    code === 'REQUESTER_SENSITIVE_AUTH_REVALIDATION_FAILED' ||
    code === 'SENSITIVE_TRANSITION_REQUIRES_SCOPED_TOKEN' ||
    code === 'WORKER_TOKEN_REQUIRED' ||
    code === 'WORKER_TOKEN_INVALID' ||
    code === 'WORKER_SCOPE_REQUIRED' ||
    code === 'WORKER_SUB_MISMATCH' ||
    code === 'WORKER_SUB_INVALID' ||
    code === 'WORKER_AUDIENCE_REQUIRED' ||
    code === 'WORKER_CONTROL_CLAIM_REQUIRED' ||
    code === 'WORKER_CONTROL_CLAIM_INVALID' ||
    code === 'WORKER_CONTROL_BINDING_MISMATCH' ||
    code === 'WORKER_TOKEN_CANONICAL_REQUIRED' ||
    code === 'UNAUTHORIZED' ||
    code === 'FORBIDDEN'
  ) {
    return 'AUTH_CONTRACT';
  }

  if (code === 'TEST_HARNESS_INVALID') return 'TEST_HARNESS_INVALID';
  if (
    code === 'TEST_HARNESS_UNAVAILABLE' ||
    code === 'TEST_HARNESS_INVALID_RESPONSE' ||
    code === 'TEST_HARNESS_FAILED' ||
    code === 'TEST_HARNESS_NOT_CONFIGURED'
  ) {
    return 'TEST_HARNESS_UNAVAILABLE';
  }

  if (code === 'ESCROW_FAILED' || code === 'AUTO_APPROVAL_ESCROW_FAILED' || code === 'AUTO_REJECTION_ESCROW_FAILED') {
    return 'ESCROW_UPSTREAM';
  }

  if (code === 'HTTP_429') return 'RATE_LIMITED';
  if (code.startsWith('HTTP_5') || code.endsWith('_UNAVAILABLE') || code.endsWith('_UPSTREAM_ERROR')) {
    return 'UPSTREAM_UNAVAILABLE';
  }

  if (code.startsWith('DB_')) return 'DB_ERROR';
  if (code.startsWith('VERIFY_') || code === 'PROOF_INVALID' || code === 'COMMIT_PROOF_INVALID') {
    return 'VERIFY_PIPELINE';
  }

  if (code === 'UNCAUGHT') return 'UNCAUGHT';
  return 'OTHER';
}

function isRetriableErrorBucket(bucket) {
  return (
    bucket === 'RATE_LIMITED' ||
    bucket === 'UPSTREAM_UNAVAILABLE' ||
    bucket === 'TEST_HARNESS_UNAVAILABLE' ||
    bucket === 'ESCROW_UPSTREAM'
  );
}

function buildSkippedJobResult(job, reason) {
  return {
    job_id: job.job_id,
    closure_type: job.closure_type,
    ok: false,
    skipped: true,
    error_code: 'ABORTED',
    error_bucket: 'ABORTED',
    error_message: reason,
    step_results: [],
    started_at: null,
    ended_at: nowIso(),
    final_status: null,
  };
}

async function runRequesterJob({
  jobId,
  index,
  baseUrl,
  requesterToken,
  requesterDid,
  rewardMinor,
  strictAuth,
  scopeAdminKey,
  scopeBaseUrl,
  workerAudience,
  workerScopes,
  workerTokenTtlSec,
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

    const workerAuth = await issueWorkerTokenForJob({
      workerDid,
      strictAuth,
      scopeAdminKey,
      scopeBaseUrl,
      workerAudience,
      workerScopes,
      workerTokenTtlSec,
      source: `simulate-clawbounties-batch:requester:${jobId}`,
      legacyWorkerToken: worker.token,
    });
    pushStep({ step: 'issue_worker_token', ok: true, source: workerAuth.source, kid: workerAuth.kid });

    const postRes = await postBounty({
      baseUrl,
      requesterToken,
      requesterDid,
      closureType: 'requester',
      isCodeBounty: false,
      title: `Batch requester ${jobId}`,
      description: `Batch requester job ${jobId}`,
      amountMinor: rewardMinor,
      tags: ['simulation', 'batch', 'requester'],
      metadata: { simulation: true, flow: 'requester', job_id: jobId },
      idempotencyKey: `sim:batch:req:post:${jobId}`,
      strictAuth,
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
      workerToken: workerAuth.token,
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
      workerToken: workerAuth.token,
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
      requesterToken,
      requesterDid,
      params: { limit: 20 },
      strictAuth,
    });

    if (listRes.status !== 200) {
      pushStep({ step: 'list_submissions', ok: false, elapsed_ms: listRes.elapsed_ms, status: listRes.status, error_code: extractErrorCode(listRes) });
    } else {
      pushStep({ step: 'list_submissions', ok: true, elapsed_ms: listRes.elapsed_ms, status: listRes.status, count: Array.isArray(listRes.json?.submissions) ? listRes.json.submissions.length : 0 });
    }

    const detailBefore = await getSubmissionDetail({
      baseUrl,
      submissionId,
      requesterToken,
      requesterDid,
      strictAuth,
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
        requesterToken,
        requesterDid,
        submissionId,
        idempotencyKey: `sim:batch:req:approve:${jobId}`,
        strictAuth,
      });
    } else {
      decisionRes = await rejectBounty({
        baseUrl,
        bountyId,
        requesterToken,
        requesterDid,
        submissionId,
        idempotencyKey: `sim:batch:req:reject:${jobId}`,
        reason: `batch deterministic rejection ${jobId}`,
        strictAuth,
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
      requesterToken,
      requesterDid,
      timeoutMs: 20_000,
      intervalMs: 700,
      strictAuth,
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
  requesterToken,
  requesterDid,
  harnessId,
  rewardMinor,
  strictAuth,
  scopeAdminKey,
  scopeBaseUrl,
  workerAudience,
  workerScopes,
  workerTokenTtlSec,
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

    const workerAuth = await issueWorkerTokenForJob({
      workerDid,
      strictAuth,
      scopeAdminKey,
      scopeBaseUrl,
      workerAudience,
      workerScopes,
      workerTokenTtlSec,
      source: `simulate-clawbounties-batch:test:${jobId}`,
      legacyWorkerToken: worker.token,
    });
    pushStep({ step: 'issue_worker_token', ok: true, source: workerAuth.source, kid: workerAuth.kid });

    const postRes = await postBounty({
      baseUrl,
      requesterToken,
      requesterDid,
      closureType: 'test',
      isCodeBounty: true,
      testHarnessId: harnessId,
      title: `Batch test ${jobId}`,
      description: `Batch test job ${jobId}`,
      amountMinor: rewardMinor,
      tags: ['simulation', 'batch', 'test'],
      metadata: { simulation: true, flow: 'test', job_id: jobId },
      idempotencyKey: `sim:batch:test:post:${jobId}`,
      strictAuth,
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
      workerToken: workerAuth.token,
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
      workerToken: workerAuth.token,
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
      workerToken: workerAuth.token,
      params: { limit: 20 },
      strictAuth,
    });

    if (listRes.status !== 200) {
      pushStep({ step: 'list_submissions', ok: false, elapsed_ms: listRes.elapsed_ms, status: listRes.status, error_code: extractErrorCode(listRes) });
    } else {
      pushStep({ step: 'list_submissions', ok: true, elapsed_ms: listRes.elapsed_ms, status: listRes.status, count: Array.isArray(listRes.json?.submissions) ? listRes.json.submissions.length : 0 });
    }

    const detail = await getSubmissionDetail({
      baseUrl,
      submissionId,
      workerToken: workerAuth.token,
      strictAuth,
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
      workerToken: workerAuth.token,
      timeoutMs: 20_000,
      intervalMs: 700,
      strictAuth,
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

async function runFundingPreflight({
  baseUrl,
  requesterToken,
  requesterDid,
  amountMinor,
  runLabel,
  strictAuth,
}) {
  const startedAt = nowIso();

  const response = await postBounty({
    baseUrl,
    requesterToken,
    requesterDid,
    closureType: 'requester',
    isCodeBounty: false,
    title: `Funding preflight ${runLabel}`,
    description: 'Funding preflight probe for batch simulation orchestration',
    amountMinor,
    tags: ['simulation', 'funding-preflight'],
    metadata: {
      simulation: true,
      preflight: 'funding',
      run_label: runLabel,
    },
    idempotencyKey: `sim:batch:funding-preflight:${runLabel}:${requesterDid}:${amountMinor}`,
    strictAuth,
  });

  const errorCode = response.ok ? null : extractErrorCode(response);
  const errorMessage = response.ok ? null : response.text;

  return {
    ok: response.status === 200 || response.status === 201,
    status: response.status,
    error_code: errorCode,
    error_bucket: errorCode ? classifyErrorBucket(errorCode, errorMessage) : null,
    error_message: errorMessage,
    bounty_id: response.json?.bounty_id ?? null,
    elapsed_ms: response.elapsed_ms,
    started_at: startedAt,
    ended_at: nowIso(),
  };
}

async function runWithBackpressure(jobs, options, workerFn) {
  const results = new Array(jobs.length);
  let cursor = 0;
  let stopRequested = false;
  let stopReason = null;
  let throttleUntil = 0;
  let dynamicCooldownMs = 0;

  const telemetry = {
    enabled: options.enabled,
    base_cooldown_ms: options.baseCooldownMs,
    step_cooldown_ms: options.stepCooldownMs,
    max_cooldown_ms: options.maxCooldownMs,
    insufficient_funds_stop_threshold: options.insufficientFundsStopThreshold,
    retriable_failures: 0,
    insufficient_funds_failures: 0,
    cooldown_wait_events: 0,
    total_cooldown_ms: 0,
    executed_jobs: 0,
    skipped_jobs: 0,
    aborted: false,
    abort_reason: null,
  };

  async function waitForThrottle() {
    if (!options.enabled) return;
    const waitMs = throttleUntil - Date.now();
    if (waitMs <= 0) return;

    telemetry.cooldown_wait_events += 1;
    telemetry.total_cooldown_ms += waitMs;
    await new Promise((resolve) => setTimeout(resolve, waitMs));
  }

  function registerResult(result) {
    telemetry.executed_jobs += 1;

    if (!result.ok) {
      const bucket = result.error_bucket ?? classifyErrorBucket(result.error_code, result.error_message);
      result.error_bucket = bucket;

      if (bucket === 'INSUFFICIENT_FUNDS') {
        telemetry.insufficient_funds_failures += 1;
        if (
          options.insufficientFundsStopThreshold > 0 &&
          telemetry.insufficient_funds_failures >= options.insufficientFundsStopThreshold
        ) {
          stopRequested = true;
          stopReason = `INSUFFICIENT_FUNDS_THRESHOLD_REACHED:${telemetry.insufficient_funds_failures}`;
          telemetry.aborted = true;
          telemetry.abort_reason = stopReason;
        }
      }

      if (options.enabled && isRetriableErrorBucket(bucket)) {
        telemetry.retriable_failures += 1;
        dynamicCooldownMs = Math.min(
          options.maxCooldownMs,
          Math.max(options.baseCooldownMs, dynamicCooldownMs + options.stepCooldownMs)
        );
        throttleUntil = Math.max(throttleUntil, Date.now() + dynamicCooldownMs);
      }
    } else if (options.enabled && dynamicCooldownMs > 0) {
      dynamicCooldownMs = Math.max(0, dynamicCooldownMs - options.stepCooldownMs);
    }
  }

  async function runner() {
    while (true) {
      if (stopRequested) return;

      const idx = cursor;
      cursor += 1;
      if (idx >= jobs.length) return;

      await waitForThrottle();
      if (stopRequested) return;

      const job = jobs[idx];
      if (!job) return;

      const result = await workerFn(job, idx);
      if (!result.ok && !result.error_bucket) {
        result.error_bucket = classifyErrorBucket(result.error_code, result.error_message);
      }

      results[idx] = result;
      registerResult(result);
    }
  }

  const workers = [];
  for (let i = 0; i < Math.max(1, options.concurrency); i += 1) {
    workers.push(runner());
  }
  await Promise.all(workers);

  for (let i = 0; i < jobs.length; i += 1) {
    if (!results[i]) {
      results[i] = buildSkippedJobResult(jobs[i], stopReason ?? 'ABORTED');
      telemetry.skipped_jobs += 1;
    }
  }

  return { results, telemetry };
}

function summarize(results, {
  envName,
  baseUrl,
  trialsBaseUrl,
  total,
  concurrency,
  harnessId,
  rewardMinor,
  runLabel,
  requesterDidMode,
  requesterDid,
  requesterTokenSource,
  requesterTokenKid,
  requesterTokenHash,
  requesterAudience,
  scopeBaseUrl,
  strictAuth,
  fundingPreflight,
  backpressure,
}) {
  const stepBuckets = new Map();
  const rawErrorBuckets = {};
  const classifiedErrorBuckets = {};
  const terminalStatusBreakdown = {};

  const closureBreakdown = {
    requester: { total: 0, success: 0, failed: 0 },
    test: { total: 0, success: 0, failed: 0 },
  };

  const stuckStateCounts = {
    pending_review: 0,
    unknown: 0,
    non_terminal_other: 0,
    total: 0,
  };

  const stuckJobsSample = [];

  for (const result of results) {
    const closure = result.closure_type === 'test' ? 'test' : 'requester';
    closureBreakdown[closure].total += 1;

    if (result.ok) {
      closureBreakdown[closure].success += 1;
    } else {
      closureBreakdown[closure].failed += 1;
      const code = result.error_code || 'UNKNOWN';
      rawErrorBuckets[code] = (rawErrorBuckets[code] || 0) + 1;

      const bucket = result.error_bucket || classifyErrorBucket(result.error_code, result.error_message);
      classifiedErrorBuckets[bucket] = (classifiedErrorBuckets[bucket] || 0) + 1;
    }

    const statusKey = result.final_status ?? (result.skipped ? 'skipped' : 'unknown');
    terminalStatusBreakdown[statusKey] = (terminalStatusBreakdown[statusKey] || 0) + 1;

    const isStuck = !result.skipped && (!result.final_status || !TERMINAL_STATUSES.has(result.final_status));
    if (isStuck) {
      stuckStateCounts.total += 1;
      if (result.final_status === 'pending_review') {
        stuckStateCounts.pending_review += 1;
      } else if (!result.final_status) {
        stuckStateCounts.unknown += 1;
      } else {
        stuckStateCounts.non_terminal_other += 1;
      }

      if (stuckJobsSample.length < 20) {
        const lastStep = Array.isArray(result.step_results) && result.step_results.length > 0
          ? result.step_results[result.step_results.length - 1]?.step ?? null
          : null;

        stuckJobsSample.push({
          job_id: result.job_id,
          closure_type: result.closure_type,
          final_status: result.final_status ?? null,
          error_code: result.error_code ?? null,
          error_bucket: result.error_bucket ?? null,
          last_step: lastStep,
        });
      }
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

  if (fundingPreflight?.ok === false && fundingPreflight.error_code) {
    const code = fundingPreflight.error_code;
    const bucket = fundingPreflight.error_bucket || classifyErrorBucket(code, fundingPreflight.error_message);
    rawErrorBuckets[code] = (rawErrorBuckets[code] || 0) + 1;
    classifiedErrorBuckets[bucket] = (classifiedErrorBuckets[bucket] || 0) + 1;
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

  const overallOk =
    failedJobs === 0 &&
    (fundingPreflight?.ok !== false) &&
    !backpressure?.aborted;

  return {
    ok: overallOk,
    run_label: runLabel,
    env: envName,
    base_url: baseUrl,
    clawtrials_base_url: trialsBaseUrl,
    scope_base_url: scopeBaseUrl,
    requester_audience: requesterAudience,
    strict_auth: strictAuth,
    requester_token_source: requesterTokenSource,
    requester_token_kid: requesterTokenKid,
    requester_token_hash: requesterTokenHash,
    total_jobs: total,
    concurrency,
    reward_minor: rewardMinor,
    harness_id: harnessId,
    requester_did_mode: requesterDidMode,
    requester_did: requesterDid,
    success_jobs: successJobs,
    failed_jobs: failedJobs,
    skipped_jobs: backpressure?.skipped_jobs ?? 0,
    aborted: backpressure?.aborted ?? false,
    abort_reason: backpressure?.abort_reason ?? null,
    closure_type_breakdown: closureBreakdown,
    deterministic_error_buckets: rawErrorBuckets,
    raw_error_buckets: rawErrorBuckets,
    classified_error_buckets: classifiedErrorBuckets,
    stuck_state_counts: stuckStateCounts,
    terminal_status_breakdown: terminalStatusBreakdown,
    stuck_jobs_sample: stuckJobsSample,
    step_metrics: stepSummary,
    funding_preflight: fundingPreflight,
    backpressure,
    generated_at: nowIso(),
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = resolveEnvName(args.get('env'));

  const total = Number.parseInt(String(args.get('total') || '10'), 10);
  assert(Number.isFinite(total) && total > 0, 'total must be a positive integer');

  const requestedConcurrency = Number.parseInt(String(args.get('concurrency') || '4'), 10);
  assert(Number.isFinite(requestedConcurrency) && requestedConcurrency > 0, 'concurrency must be a positive integer');

  const maxConcurrency = Number.parseInt(String(args.get('max-concurrency') || '12'), 10);
  assert(Number.isFinite(maxConcurrency) && maxConcurrency > 0, 'max-concurrency must be a positive integer');

  const concurrency = Math.min(maxConcurrency, requestedConcurrency);

  const rewardMinor = String(args.get('reward-minor') || '200').trim();
  assert(/^[0-9]+$/.test(rewardMinor), 'reward-minor must be a non-negative integer string');
  assert(BigInt(rewardMinor) > 0n, 'reward-minor must be > 0');

  const runLabel = String(args.get('label') || `batch-${total}`);
  const harnessId = String(args.get('harness-id') || 'th_smoke_pass_v1');

  const strictAuth = parseBoolean(args.get('strict-auth'), true);

  const fundingPreflightEnabled = parseBoolean(args.get('funding-preflight'), true);
  const fundingPreflightAmountMinor = String(args.get('funding-preflight-amount-minor') || rewardMinor).trim();
  assert(/^[0-9]+$/.test(fundingPreflightAmountMinor), 'funding-preflight-amount-minor must be an integer string');

  const continueOnFundingFailure = parseBoolean(args.get('continue-on-funding-failure'), false);

  const backpressureEnabled = parseBoolean(args.get('backpressure-enabled'), true);
  const baseCooldownMs = Number.parseInt(String(args.get('backpressure-base-cooldown-ms') || '1200'), 10);
  const stepCooldownMs = Number.parseInt(String(args.get('backpressure-step-cooldown-ms') || '600'), 10);
  const maxCooldownMs = Number.parseInt(String(args.get('backpressure-max-cooldown-ms') || '8000'), 10);
  const insufficientFundsStopThreshold = Number.parseInt(
    String(args.get('insufficient-funds-stop-threshold') || '3'),
    10
  );

  assert(Number.isFinite(baseCooldownMs) && baseCooldownMs >= 0, 'backpressure-base-cooldown-ms must be >= 0');
  assert(Number.isFinite(stepCooldownMs) && stepCooldownMs >= 0, 'backpressure-step-cooldown-ms must be >= 0');
  assert(Number.isFinite(maxCooldownMs) && maxCooldownMs >= 0, 'backpressure-max-cooldown-ms must be >= 0');
  assert(
    Number.isFinite(insufficientFundsStopThreshold) && insufficientFundsStopThreshold >= 0,
    'insufficient-funds-stop-threshold must be >= 0'
  );

  const baseUrl = resolveBountiesBaseUrl(envName, args.get('clawbounties-base-url'));
  const trialsBaseUrl = resolveTrialsBaseUrl(envName, args.get('clawtrials-base-url'));

  const scopeAdminKey = resolveScopeAdminKey(args);
  const scopeBaseUrl = resolveScopeBaseUrl(envName, args.get('scope-base-url'));
  const workerAudience = resolveWorkerAudience(envName, args.get('worker-audience'));
  const workerScopes = resolveWorkerScopes(args.get('worker-scopes'));
  const workerTokenTtlSec = Number.parseInt(String(args.get('worker-token-ttl-sec') || '3600'), 10);
  assert(Number.isFinite(workerTokenTtlSec) && workerTokenTtlSec > 0, 'worker-token-ttl-sec must be a positive integer');

  if (strictAuth) {
    assert(scopeAdminKey, 'scope-admin-key / SCOPE_ADMIN_KEY is required in strict auth mode');
  }

  const requesterDidRaw = String(args.get('requester-did') || '').trim();
  const requesterDid = requesterDidRaw.length > 0 ? requesterDidRaw : randomDid('requester-batch');
  assert(requesterDid.startsWith('did:'), 'requester-did must be a DID string');

  const requesterAuth = await resolveRequesterAuth({
    args,
    envName,
    requesterDid,
  });
  const requesterToken = requesterAuth.requesterToken;

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
      requester_did: requesterDid,
    };
  });

  const fundingRequesterDid = requesterDid;
  const fundingPreflight = fundingPreflightEnabled
    ? await runFundingPreflight({
        baseUrl,
        requesterToken,
        requesterDid: fundingRequesterDid,
        amountMinor: fundingPreflightAmountMinor,
        runLabel,
        strictAuth,
      })
    : {
        ok: true,
        skipped: true,
        reason: 'disabled',
      };

  let results;
  let backpressure;

  if (!fundingPreflight.ok && !continueOnFundingFailure) {
    const reason = `FUNDING_PREFLIGHT_FAILED:${fundingPreflight.error_code ?? 'UNKNOWN'}`;
    results = jobs.map((job) => buildSkippedJobResult(job, reason));
    backpressure = {
      enabled: backpressureEnabled,
      base_cooldown_ms: baseCooldownMs,
      step_cooldown_ms: stepCooldownMs,
      max_cooldown_ms: maxCooldownMs,
      insufficient_funds_stop_threshold: insufficientFundsStopThreshold,
      retriable_failures: 0,
      insufficient_funds_failures: fundingPreflight.error_bucket === 'INSUFFICIENT_FUNDS' ? 1 : 0,
      cooldown_wait_events: 0,
      total_cooldown_ms: 0,
      executed_jobs: 0,
      skipped_jobs: jobs.length,
      aborted: true,
      abort_reason: reason,
    };
  } else {
    const run = await runWithBackpressure(
      jobs,
      {
        concurrency,
        enabled: backpressureEnabled,
        baseCooldownMs,
        stepCooldownMs,
        maxCooldownMs,
        insufficientFundsStopThreshold,
      },
      async (job, idx) => {
        if (job.closure_type === 'requester') {
          return runRequesterJob({
            jobId: job.job_id,
            index: idx,
            baseUrl,
            requesterToken,
            requesterDid: job.requester_did,
            rewardMinor,
            strictAuth,
            scopeAdminKey,
            scopeBaseUrl,
            workerAudience,
            workerScopes,
            workerTokenTtlSec,
          });
        }

        return runTestJob({
          jobId: job.job_id,
          baseUrl,
          requesterToken,
          requesterDid: job.requester_did,
          harnessId,
          rewardMinor,
          strictAuth,
          scopeAdminKey,
          scopeBaseUrl,
          workerAudience,
          workerScopes,
          workerTokenTtlSec,
        });
      }
    );

    results = run.results;
    backpressure = run.telemetry;
  }

  const summary = summarize(results, {
    envName,
    baseUrl,
    trialsBaseUrl,
    total,
    concurrency,
    harnessId,
    rewardMinor,
    runLabel,
    requesterDidMode: 'fixed',
    requesterDid,
    requesterTokenSource: requesterAuth.requesterTokenSource,
    requesterTokenKid: requesterAuth.requesterTokenKid,
    requesterTokenHash: requesterAuth.requesterTokenHash,
    requesterAudience: requesterAuth.requesterAudience,
    scopeBaseUrl: requesterAuth.scopeBaseUrl,
    strictAuth,
    fundingPreflight,
    backpressure,
  });

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, '../..');
  const artifact = await createArtifactDir(repoRoot, `batch-${total}`);

  await writeJson(path.resolve(artifact.dir, 'summary.json'), {
    ...summary,
    preflight: {
      clawbounties_health_ms: bountiesHealth.elapsed_ms,
      clawtrials_health_ms: trialsHealth.elapsed_ms,
      clawbounties_health_status: bountiesHealth.status,
      clawtrials_health_status: trialsHealth.status,
      requested_concurrency: requestedConcurrency,
      applied_concurrency: concurrency,
      max_concurrency: maxConcurrency,
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
