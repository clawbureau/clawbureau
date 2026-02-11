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
  resolveRequesterScopes,
  issueRequesterScopedToken,
  randomDid,
  generateAgentIdentity,
  registerWorker,
  postBounty,
  acceptBounty,
  submitBounty,
  listBountySubmissions,
  buildProofArtifacts,
  buildCommitProofEnvelope,
  waitForSubmissionTerminal,
  createArtifactDir,
  writeJson,
  httpJson,
  extractErrorCode,
} from './_clawbounties-sim-common.mjs';

function nowIso() {
  return new Date().toISOString();
}

function resolveScopeAdminKey(args) {
  const fromArg = String(args.get('scope-admin-key') || '').trim();
  if (fromArg) return fromArg;

  const fromEnv = String(process.env.SCOPE_ADMIN_KEY || process.env.CLAWSCOPE_ADMIN_KEY || '').trim();
  return fromEnv || null;
}

async function resolveRequesterAuth({ args, envName, requesterDid }) {
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
    source: 'gate-clawbounties-prod-readiness',
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

function resolveAdminKey(args) {
  const fromArg = String(args.get('admin-key') || '').trim();
  if (fromArg) return fromArg;

  const fromEnv = String(process.env.BOUNTIES_ADMIN_KEY || '').trim();
  return fromEnv || null;
}

function buildPostPayload(requesterDid, { closureType = 'requester', isCode = false, harnessId = null, amountMinor = '50' } = {}) {
  return {
    requester_did: requesterDid,
    title: `Gate preflight ${new Date().toISOString()}`,
    description: 'CBT-OPS-003 production gate preflight',
    reward: {
      amount_minor: amountMinor,
      currency: 'USD',
    },
    closure_type: closureType,
    difficulty_scalar: 1,
    is_code_bounty: isCode,
    tags: ['simulation', 'prod-gate'],
    min_proof_tier: 'self',
    test_harness_id: harnessId,
    metadata: {
      simulation: true,
      gate_preflight: true,
    },
    idempotency_key: `sim:prod-gate:post:${closureType}:${crypto.randomUUID()}`,
  };
}

async function runCheck(checks, blockers, {
  id,
  description,
  required = true,
  fn,
}) {
  const startedAt = Date.now();

  try {
    const output = await fn();
    checks.push({
      id,
      description,
      required,
      ok: true,
      elapsed_ms: Date.now() - startedAt,
      output: output ?? null,
    });
    return output;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    checks.push({
      id,
      description,
      required,
      ok: false,
      elapsed_ms: Date.now() - startedAt,
      error: message,
    });

    if (required) blockers.push(`${id}: ${message}`);
    return null;
  }
}

function renderGateMarkdown(report) {
  const lines = [];
  lines.push('# CBT-OPS-003 Prod Gate Report');
  lines.push('');
  lines.push(`- Generated at: ${report.generated_at}`);
  lines.push(`- Environment: ${report.env}`);
  lines.push(`- Recommendation: **${report.recommendation.status}**`);
  lines.push('');

  if (report.recommendation.blockers.length > 0) {
    lines.push('## Blockers');
    for (const blocker of report.recommendation.blockers) {
      lines.push(`- ${blocker}`);
    }
    lines.push('');
  } else {
    lines.push('## Blockers');
    lines.push('- None detected by deterministic preflight pack.');
    lines.push('');
  }

  lines.push('## Required checks');
  for (const check of report.checks.filter((item) => item.required)) {
    lines.push(`- [${check.ok ? 'x' : ' '}] ${check.id} (${check.elapsed_ms}ms)`);
  }
  lines.push('');

  lines.push('## Optional checks');
  for (const check of report.checks.filter((item) => !item.required)) {
    lines.push(`- [${check.ok ? 'x' : ' '}] ${check.id} (${check.elapsed_ms}ms)`);
  }
  lines.push('');

  lines.push('## Governance note');
  lines.push('- Passing this gate does not bypass governance. Explicit GO PROD approval is still required.');

  return `${lines.join('\n')}\n`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const envName = resolveEnvName(args.get('env'));

  const baseUrl = resolveBountiesBaseUrl(envName, args.get('clawbounties-base-url'));
  const trialsBaseUrl = resolveTrialsBaseUrl(envName, args.get('clawtrials-base-url'));
  const requesterDid = String(args.get('requester-did') || '').trim() || randomDid('gate-requester');
  assert(requesterDid.startsWith('did:'), 'requester-did must be a DID string');

  const requesterAuth = await resolveRequesterAuth({ args, envName, requesterDid });
  const requesterToken = requesterAuth.requesterToken;
  const adminKey = resolveAdminKey(args);

  const checks = [];
  const blockers = [];

  const context = {
    workerDid: null,
    requesterBountyId: null,
    testBountyId: null,
    testSubmissionId: null,
    invalidHarnessBountyId: null,
    invalidHarnessSubmissionId: null,
  };

  let workerToken = null;
  let workerPrivateKey = null;

  await runCheck(checks, blockers, {
    id: 'routes.clawbounties.health',
    description: 'clawbounties domain health endpoint responds with 200',
    fn: async () => {
      const res = await httpJson(`${baseUrl}/health`, { method: 'GET' });
      assert(res.status === 200, `expected 200, got ${res.status}`);
      return {
        status: res.status,
        version: res.json?.version ?? null,
        environment: res.json?.environment ?? null,
      };
    },
  });

  await runCheck(checks, blockers, {
    id: 'routes.clawtrials.health',
    description: 'clawtrials domain health endpoint responds with 200',
    fn: async () => {
      const res = await httpJson(`${trialsBaseUrl}/health`, { method: 'GET' });
      assert(res.status === 200, `expected 200, got ${res.status}`);
      return {
        status: res.status,
        version: res.json?.version ?? null,
        environment: res.json?.environment ?? null,
      };
    },
  });

  await runCheck(checks, blockers, {
    id: 'routes.clawtrials.catalog',
    description: 'clawtrials catalog endpoint exposes deterministic harness IDs',
    fn: async () => {
      const res = await httpJson(`${trialsBaseUrl}/v1/harness/catalog`, { method: 'GET' });
      assert(res.status === 200, `expected 200, got ${res.status}`);

      const harnesses = Array.isArray(res.json?.harnesses) ? res.json.harnesses : [];
      const ids = harnesses.map((entry) => entry?.id).filter((value) => typeof value === 'string');
      assert(ids.includes('th_smoke_pass_v1'), 'th_smoke_pass_v1 missing from catalog');
      assert(ids.includes('th_smoke_fail_v1'), 'th_smoke_fail_v1 missing from catalog');

      return {
        status: res.status,
        harness_count: harnesses.length,
        harness_ids: ids,
      };
    },
  });

  await runCheck(checks, blockers, {
    id: 'routes.clawtrials.harness-run',
    description: 'clawtrials /v1/harness/run returns deterministic response for pass harness',
    fn: async () => {
      const body = {
        schema_version: '1',
        test_harness_id: 'th_smoke_pass_v1',
        submission_id: `sub_${crypto.randomUUID()}`,
        bounty_id: `bty_${crypto.randomUUID()}`,
        proof_bundle_hash: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        output: { result_summary: 'gate preflight pass smoke' },
        timeout_ms: 120000,
      };

      const res = await httpJson(`${trialsBaseUrl}/v1/harness/run`, {
        method: 'POST',
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify(body),
      });

      assert(res.status === 200, `expected 200, got ${res.status}`);
      assert(res.json?.passed === true, 'expected passed=true from th_smoke_pass_v1');

      return {
        status: res.status,
        passed: res.json?.passed ?? null,
        total_tests: res.json?.total_tests ?? null,
        failed_tests: res.json?.failed_tests ?? null,
      };
    },
  });

  await runCheck(checks, blockers, {
    id: 'auth.requester.post-missing-token',
    description: 'POST /v1/bounties fails closed without requester token',
    fn: async () => {
      const payload = buildPostPayload(requesterDid, {
        closureType: 'requester',
        amountMinor: String(args.get('amount-minor') || '50'),
      });

      const res = await httpJson(`${baseUrl}/v1/bounties`, {
        method: 'POST',
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify(payload),
      });

      assert(res.status === 401, `expected 401, got ${res.status}`);
      assert(res.json?.error === 'REQUESTER_TOKEN_REQUIRED', `expected REQUESTER_TOKEN_REQUIRED, got ${res.json?.error}`);

      return {
        status: res.status,
        error: res.json?.error ?? null,
      };
    },
  });

  await runCheck(checks, blockers, {
    id: 'auth.requester.post-valid-token',
    description: 'POST /v1/bounties succeeds with valid requester scoped token',
    fn: async () => {
      const postRes = await postBounty({
        baseUrl,
        requesterToken,
        requesterDid,
        closureType: 'requester',
        isCodeBounty: false,
        title: `Gate requester ${new Date().toISOString()}`,
        description: 'Requester auth contract check',
        amountMinor: String(args.get('amount-minor') || '50'),
        tags: ['simulation', 'prod-gate', 'requester-auth'],
        metadata: { gate: true, check: 'requester_post_valid' },
        idempotencyKey: `sim:prod-gate:req:${crypto.randomUUID()}`,
      });

      if (!(postRes.status === 200 || postRes.status === 201)) {
        const code = extractErrorCode(postRes);
        throw new Error(`expected 200/201, got ${postRes.status} (${code}): ${postRes.text}`);
      }

      const bountyId = postRes.json?.bounty_id;
      assert(typeof bountyId === 'string', 'response missing bounty_id');
      context.requesterBountyId = bountyId;

      return {
        status: postRes.status,
        bounty_id: bountyId,
      };
    },
  });

  await runCheck(checks, blockers, {
    id: 'auth.worker.register-and-self',
    description: 'worker token can be minted and used for /v1/workers/self',
    fn: async () => {
      const identity = await generateAgentIdentity();
      const workerDid = identity.did;
      const worker = await registerWorker(baseUrl, workerDid, ['simulation', 'prod-gate']);

      context.workerDid = workerDid;
      workerToken = worker.token;
      workerPrivateKey = identity.privateKey;

      const selfRes = await httpJson(`${baseUrl}/v1/workers/self`, {
        method: 'GET',
        headers: { authorization: `Bearer ${worker.token}` },
      });

      assert(selfRes.status === 200, `expected 200, got ${selfRes.status}`);
      assert(selfRes.json?.worker_did === workerDid, 'worker_did mismatch on /v1/workers/self');

      return {
        register_status: 201,
        self_status: selfRes.status,
        worker_did: workerDid,
      };
    },
  });

  await runCheck(checks, blockers, {
    id: 'auth.requester.submission-list',
    description: 'requester token can access /v1/bounties/{id}/submissions for own bounty',
    fn: async () => {
      assert(context.requesterBountyId, 'requester bounty id not available');

      const listRes = await listBountySubmissions({
        baseUrl,
        bountyId: context.requesterBountyId,
        requesterToken,
        requesterDid,
        params: { limit: 10 },
      });

      assert(listRes.status === 200, `expected 200, got ${listRes.status}`);
      assert(Array.isArray(listRes.json?.submissions), 'submissions payload must be an array');

      return {
        status: listRes.status,
        submission_count: listRes.json.submissions.length,
      };
    },
  });

  await runCheck(checks, blockers, {
    id: 'harness.integration.auto-decision',
    description: 'closure_type=test submission auto-decides via clawtrials harness',
    fn: async () => {
      assert(context.workerDid && workerToken && workerPrivateKey, 'worker context not initialized');

      const postRes = await postBounty({
        baseUrl,
        requesterToken,
        requesterDid,
        closureType: 'test',
        isCodeBounty: true,
        testHarnessId: 'th_smoke_pass_v1',
        title: `Gate test lane ${new Date().toISOString()}`,
        description: 'Harness integration contract check',
        amountMinor: String(args.get('amount-minor') || '50'),
        tags: ['simulation', 'prod-gate', 'test-lane'],
        metadata: { gate: true, check: 'test_lane_auto_decision' },
        idempotencyKey: `sim:prod-gate:test:${crypto.randomUUID()}`,
      });

      if (!(postRes.status === 200 || postRes.status === 201)) {
        const code = extractErrorCode(postRes);
        throw new Error(`post test bounty failed (${postRes.status}, ${code}): ${postRes.text}`);
      }

      const bountyId = postRes.json?.bounty_id;
      assert(typeof bountyId === 'string', 'test bounty response missing bounty_id');
      context.testBountyId = bountyId;

      const acceptRes = await acceptBounty({
        baseUrl,
        bountyId,
        workerDid: context.workerDid,
        workerToken,
        idempotencyKey: `sim:prod-gate:test:accept:${crypto.randomUUID()}`,
      });
      assert(acceptRes.status === 200 || acceptRes.status === 201, `accept failed (${acceptRes.status}): ${acceptRes.text}`);

      const runId = `run_${crypto.randomUUID()}`;
      const proofWithSigner = await buildProofArtifacts({
        agentDid: context.workerDid,
        privateKey: workerPrivateKey,
        runId,
        harnessId: 'th_smoke_pass_v1',
      });

      const commitProofEnvelope = await buildCommitProofEnvelope({
        signerDid: context.workerDid,
        privateKey: workerPrivateKey,
        runId,
        proofBundleHash: proofWithSigner.payload_hash_b64u,
      });

      const submitRes = await submitBounty({
        baseUrl,
        bountyId,
        workerDid: context.workerDid,
        workerToken,
        idempotencyKey: `sim:prod-gate:test:submit:${crypto.randomUUID()}`,
        proofBundleEnvelope: proofWithSigner.envelope,
        commitProofEnvelope,
        urm: proofWithSigner.urm,
        resultSummary: 'gate test-lane submit',
        artifacts: [{ kind: 'log', uri: 'sim://prod-gate/test-lane' }],
      });

      if (!(submitRes.status === 200 || submitRes.status === 201)) {
        const code = extractErrorCode(submitRes);
        throw new Error(`submit failed (${submitRes.status}, ${code}): ${submitRes.text}`);
      }

      const submissionId = submitRes.json?.submission_id;
      assert(typeof submissionId === 'string', 'submit response missing submission_id');
      context.testSubmissionId = submissionId;

      const terminal = await waitForSubmissionTerminal({
        baseUrl,
        submissionId,
        workerToken,
        timeoutMs: 25_000,
        intervalMs: 1000,
      });

      assert(terminal?.status === 200, `terminal poll failed (${terminal?.status}): ${terminal?.text}`);
      assert(terminal?.json?.submission?.status === 'approved', `expected approved, got ${terminal?.json?.submission?.status}`);

      return {
        post_status: postRes.status,
        submit_status: submitRes.status,
        final_status: terminal.json.submission.status,
        bounty_id: bountyId,
        submission_id: submissionId,
      };
    },
  });

  await runCheck(checks, blockers, {
    id: 'harness.integration.invalid-replay',
    description: 'invalid harness replay remains deterministic + fail-closed',
    fn: async () => {
      assert(context.workerDid && workerToken && workerPrivateKey, 'worker context not initialized');

      const postRes = await postBounty({
        baseUrl,
        requesterToken,
        requesterDid,
        closureType: 'test',
        isCodeBounty: true,
        testHarnessId: 'th_missing_invalid_case_v2',
        title: `Gate invalid harness ${new Date().toISOString()}`,
        description: 'Deterministic invalid harness replay check',
        amountMinor: String(args.get('amount-minor') || '50'),
        tags: ['simulation', 'prod-gate', 'invalid-harness'],
        metadata: { gate: true, check: 'invalid_harness_replay' },
        idempotencyKey: `sim:prod-gate:invalid:${crypto.randomUUID()}`,
      });

      if (!(postRes.status === 200 || postRes.status === 201)) {
        const code = extractErrorCode(postRes);
        throw new Error(`post invalid harness bounty failed (${postRes.status}, ${code}): ${postRes.text}`);
      }

      const bountyId = postRes.json?.bounty_id;
      assert(typeof bountyId === 'string', 'invalid harness bounty_id missing');
      context.invalidHarnessBountyId = bountyId;

      const acceptRes = await acceptBounty({
        baseUrl,
        bountyId,
        workerDid: context.workerDid,
        workerToken,
        idempotencyKey: `sim:prod-gate:invalid:accept:${crypto.randomUUID()}`,
      });
      assert(acceptRes.status === 200 || acceptRes.status === 201, `accept failed (${acceptRes.status}): ${acceptRes.text}`);

      const runId = `run_${crypto.randomUUID()}`;
      const proof = await buildProofArtifacts({
        agentDid: context.workerDid,
        privateKey: workerPrivateKey,
        runId,
        harnessId: 'th_missing_invalid_case_v2',
      });
      const commitProofEnvelope = await buildCommitProofEnvelope({
        signerDid: context.workerDid,
        privateKey: workerPrivateKey,
        runId,
        proofBundleHash: proof.payload_hash_b64u,
      });

      const replayKey = `sim:prod-gate:invalid:submit:${crypto.randomUUID()}`;
      const submitParams = {
        baseUrl,
        bountyId,
        workerDid: context.workerDid,
        workerToken,
        idempotencyKey: replayKey,
        proofBundleEnvelope: proof.envelope,
        commitProofEnvelope,
        urm: proof.urm,
        resultSummary: 'invalid harness replay',
        artifacts: [{ kind: 'log', uri: 'sim://prod-gate/invalid-harness' }],
      };

      const first = await submitBounty(submitParams);
      const replay = await submitBounty(submitParams);

      assert(first.status === 422, `expected first status 422, got ${first.status}`);
      assert(replay.status === 422, `expected replay status 422, got ${replay.status}`);
      assert(extractErrorCode(first) === 'TEST_HARNESS_INVALID', `expected TEST_HARNESS_INVALID, got ${extractErrorCode(first)}`);
      assert(extractErrorCode(replay) === 'TEST_HARNESS_INVALID', `expected replay TEST_HARNESS_INVALID, got ${extractErrorCode(replay)}`);
      assert(String(first.json?.message || '').includes('HARNESS_NOT_FOUND'), 'first message missing HARNESS_NOT_FOUND');
      assert(String(replay.json?.message || '').includes('HARNESS_NOT_FOUND'), 'replay message missing HARNESS_NOT_FOUND');

      context.invalidHarnessSubmissionId = first.json?.details?.submission_id ?? null;

      return {
        bounty_id: bountyId,
        first_status: first.status,
        replay_status: replay.status,
        first_error: extractErrorCode(first),
        replay_error: extractErrorCode(replay),
      };
    },
  });

  await runCheck(checks, blockers, {
    id: 'auth.admin.get-bounty',
    description: 'admin key can read bounty detail endpoint',
    required: false,
    fn: async () => {
      assert(adminKey, 'admin key not provided (set --admin-key or BOUNTIES_ADMIN_KEY)');
      assert(context.requesterBountyId, 'requester bounty id missing');

      const res = await httpJson(`${baseUrl}/v1/bounties/${encodeURIComponent(context.requesterBountyId)}`, {
        method: 'GET',
        headers: {
          authorization: `Bearer ${adminKey}`,
        },
      });

      assert(res.status === 200, `expected 200, got ${res.status}`);
      return {
        status: res.status,
        bounty_id: res.json?.bounty_id ?? null,
      };
    },
  });

  const requiredFailures = checks.filter((item) => item.required && !item.ok);
  let recommendation = 'READY_FOR_PROD_GOVERNANCE_REVIEW';

  if (requiredFailures.length > 0) {
    const hasFundingBlocker = blockers.some((entry) => entry.toUpperCase().includes('INSUFFICIENT_FUNDS'));
    recommendation = hasFundingBlocker ? 'BLOCKED_INSUFFICIENT_FUNDS' : 'BLOCKED';
  }

  const report = {
    ok: requiredFailures.length === 0,
    env: envName,
    base_url: baseUrl,
    clawtrials_base_url: trialsBaseUrl,
    scope_base_url: requesterAuth.scopeBaseUrl,
    requester_audience: requesterAuth.requesterAudience,
    requester_did: requesterDid,
    requester_token_source: requesterAuth.requesterTokenSource,
    requester_token_kid: requesterAuth.requesterTokenKid,
    requester_token_hash: requesterAuth.requesterTokenHash,
    recommendation: {
      status: recommendation,
      blockers,
      governance_note: 'Explicit GO PROD approval is still required before production deploy.',
    },
    checks,
    resources: context,
    generated_at: nowIso(),
  };

  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(__dirname, '../..');
  const artifact = await createArtifactDir(repoRoot, 'prod-gate');

  const reportPath = path.resolve(artifact.dir, 'gate-report.json');
  const markdownPath = path.resolve(artifact.dir, 'gate-report.md');

  await writeJson(reportPath, report);
  await fs.writeFile(markdownPath, renderGateMarkdown(report), 'utf8');

  console.log(
    JSON.stringify(
      {
        ...report,
        artifact_dir: artifact.dir,
      },
      null,
      2
    )
  );

  if (!report.ok) {
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
