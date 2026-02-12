#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function parseArgs(argv) {
  const out = {
    env: 'staging',
    baseUrl: '',
    outDir: '',
    repAdminKey: process.env.CLAWREP_ADMIN_KEY ?? '',
    repIngestKey: process.env.CLAWREP_INGEST_KEY ?? '',
    deployVersion: '',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--env' && argv[i + 1]) {
      out.env = String(argv[++i]);
      continue;
    }
    if (arg === '--base-url' && argv[i + 1]) {
      out.baseUrl = String(argv[++i]);
      continue;
    }
    if (arg === '--out-dir' && argv[i + 1]) {
      out.outDir = String(argv[++i]);
      continue;
    }
    if (arg === '--admin-key' && argv[i + 1]) {
      out.repAdminKey = String(argv[++i]);
      continue;
    }
    if (arg === '--ingest-key' && argv[i + 1]) {
      out.repIngestKey = String(argv[++i]);
      continue;
    }
    if (arg === '--deploy-version' && argv[i + 1]) {
      out.deployVersion = String(argv[++i]);
      continue;
    }
  }

  return out;
}

function timestampForPath(date = new Date()) {
  return date.toISOString().replace(/:/g, '-').replace(/\./g, '-');
}

function toJsonText(value) {
  return JSON.stringify(value, null, 2);
}

async function requestJson(url, { method = 'GET', headers = {}, body } = {}) {
  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }

  return {
    status: response.status,
    ok: response.ok,
    json,
    text,
  };
}

function assertStatus(label, response, expected) {
  if (response.status !== expected) {
    throw new Error(`${label} expected HTTP ${expected}, got ${response.status}: ${JSON.stringify(response.json)}`);
  }
}

function assertCondition(label, condition, context) {
  if (!condition) {
    throw new Error(`${label} assertion failed: ${JSON.stringify(context)}`);
  }
}

async function sleep(ms) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(label, fn, { attempts = 8, delayMs = 750 } = {}) {
  let last = null;
  for (let i = 0; i < attempts; i += 1) {
    last = await fn();
    if (last) return last;
    if (i < attempts - 1) {
      await sleep(delayMs);
    }
  }
  throw new Error(`${label} timed out after ${attempts} attempts`);
}

function makeDid(seed) {
  return `did:key:z6Mk${seed}`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.env !== 'staging' && args.env !== 'prod') {
    throw new Error('--env must be staging or prod');
  }
  if (!args.repAdminKey) {
    throw new Error('CLAWREP_ADMIN_KEY is required (or pass --admin-key)');
  }
  if (!args.repIngestKey) {
    throw new Error('CLAWREP_INGEST_KEY is required (or pass --ingest-key)');
  }

  const baseUrl =
    args.baseUrl ||
    (args.env === 'prod' ? 'https://clawrep.com' : 'https://clawrep-staging.generaite.workers.dev');

  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const ts = timestampForPath();
  const outDir = args.outDir || path.join(root, 'artifacts', 'smoke', 'clawrep', `${ts}-${args.env}`);
  mkdirSync(outDir, { recursive: true });

  const now = Date.now();
  const didA = makeDid(`repA${now}`);
  const didB = makeDid(`repB${now}`);
  const didC = makeDid(`repC${now}`);
  const didD = makeDid(`repD${now}`);

  const commonIngestHeaders = {
    authorization: `Bearer ${args.repIngestKey}`,
    'content-type': 'application/json',
  };

  const commonAdminHeaders = {
    authorization: `Bearer ${args.repAdminKey}`,
    'content-type': 'application/json',
  };

  // 1) ingest + replay idempotency
  const ingestSourceId = `rep_evt_${now}_a`;
  const ingestBody = {
    schema_version: '1',
    source_event_id: ingestSourceId,
    did: didA,
    event_type: 'closure',
    value_usd: 125,
    closure_type: 'quorum_approve',
    proof_tier: 'gateway',
    owner_verified: true,
    owner_attestation_ref: `att_${now}`,
  };

  const ingestFirst = await requestJson(`${baseUrl}/v1/events/ingest`, {
    method: 'POST',
    headers: commonIngestHeaders,
    body: ingestBody,
  });
  assertStatus('ingest.first', ingestFirst, 202);

  const ingestReplay = await requestJson(`${baseUrl}/v1/events/ingest`, {
    method: 'POST',
    headers: commonIngestHeaders,
    body: ingestBody,
  });
  assertStatus('ingest.replay', ingestReplay, 200);
  assertCondition('ingest.replay.duplicate', ingestReplay.json?.duplicate === true, ingestReplay.json);

  const repAfterReplay = await requestJson(`${baseUrl}/v1/rep/${encodeURIComponent(didA)}`);
  assertStatus('rep.after_replay', repAfterReplay, 200);
  assertCondition('rep.events_count.idempotent', repAfterReplay.json?.events_count === 1, repAfterReplay.json);

  const ingestReplaySmoke = {
    env: args.env,
    base_url: baseUrl,
    did: didA,
    source_event_id: ingestSourceId,
    first_ingest: { status: ingestFirst.status, body: ingestFirst.json },
    replay_ingest: { status: ingestReplay.status, body: ingestReplay.json },
    rep_after_replay: repAfterReplay.json,
    assertions: {
      replay_duplicate: ingestReplay.json?.duplicate === true,
      event_count_stable: repAfterReplay.json?.events_count === 1,
    },
  };

  // 1b) ingest-loop closure/penalty/recovery
  const loopClosureSourceId = `rep_loop_${now}_closure`;
  const loopPenaltySourceId = `rep_loop_${now}_penalty`;
  const loopRecoverySourceId = `rep_loop_${now}_recovery`;

  const loopClosure = await requestJson(`${baseUrl}/v1/events/ingest-loop`, {
    method: 'POST',
    headers: commonIngestHeaders,
    body: {
      schema_version: '1',
      source_event_id: loopClosureSourceId,
      source_service: 'smoke-harness',
      kind: 'closure',
      did: didA,
      closure: {
        value_usd: 40,
        closure_type: 'manual_approve',
        proof_tier: 'gateway',
        owner_verified: false,
      },
      metadata: {
        smoke_case: 'loop-closure',
      },
    },
  });
  assertStatus('ingest.loop.closure', loopClosure, 202);

  const loopPenalty = await requestJson(`${baseUrl}/v1/events/ingest-loop`, {
    method: 'POST',
    headers: commonIngestHeaders,
    body: {
      schema_version: '1',
      source_event_id: loopPenaltySourceId,
      source_service: 'smoke-harness',
      kind: 'penalty',
      did: didA,
      penalty: {
        penalty_type: 'dispute_upheld_against_worker',
        severity: 1,
        reason: 'smoke-loop-penalty',
      },
      metadata: {
        smoke_case: 'loop-penalty',
      },
    },
  });
  assertStatus('ingest.loop.penalty', loopPenalty, 202);

  const loopRecovery = await requestJson(`${baseUrl}/v1/events/ingest-loop`, {
    method: 'POST',
    headers: commonIngestHeaders,
    body: {
      schema_version: '1',
      source_event_id: loopRecoverySourceId,
      source_service: 'smoke-harness',
      kind: 'recovery',
      did: didA,
      recovery: {
        recovery_type: 'appeal_upheld_for_worker',
        severity: 1,
        reason: 'smoke-loop-recovery',
      },
      metadata: {
        smoke_case: 'loop-recovery',
      },
    },
  });
  assertStatus('ingest.loop.recovery', loopRecovery, 202);

  const repAfterLoop = await waitFor(
    'rep.after_loop',
    async () => {
      const rep = await requestJson(`${baseUrl}/v1/rep/${encodeURIComponent(didA)}`);
      if (rep.status !== 200) return null;
      const eventsCount = Number(rep.json?.events_count ?? 0);
      if (eventsCount >= 4) return rep;
      return null;
    },
    { attempts: 40, delayMs: 1000 }
  );

  const ingestLoopSmoke = {
    env: args.env,
    base_url: baseUrl,
    did: didA,
    closure: { status: loopClosure.status, body: loopClosure.json },
    penalty: { status: loopPenalty.status, body: loopPenalty.json },
    recovery: { status: loopRecovery.status, body: loopRecovery.json },
    rep_after_loop: repAfterLoop.json,
    assertions: {
      closure_accepted: loopClosure.status === 202,
      penalty_accepted: loopPenalty.status === 202,
      recovery_accepted: loopRecovery.status === 202,
      events_count_progressed: Number(repAfterLoop.json?.events_count ?? 0) >= 4,
    },
  };

  // Seed additional reviewers for deterministic selection checks
  const seeded = [
    { did: didB, value_usd: 220, owner_verified: true, proof_tier: 'sandbox' },
    { did: didC, value_usd: 175, owner_verified: false, proof_tier: 'gateway' },
    { did: didD, value_usd: 95, owner_verified: true, proof_tier: 'self' },
  ];

  for (let i = 0; i < seeded.length; i += 1) {
    const row = seeded[i];
    const res = await requestJson(`${baseUrl}/v1/events/ingest`, {
      method: 'POST',
      headers: commonIngestHeaders,
      body: {
        schema_version: '1',
        source_event_id: `rep_evt_${now}_seed_${i}`,
        did: row.did,
        event_type: 'closure',
        value_usd: row.value_usd,
        closure_type: 'quorum_approve',
        proof_tier: row.proof_tier,
        owner_verified: row.owner_verified,
      },
    });
    assertStatus(`ingest.seed.${i}`, res, 202);
  }

  // 2) reviewer selection determinism
  const selectPayload = {
    bounty_id: `bnty_${now}`,
    difficulty_scalar: 2,
    quorum_size: 2,
    min_reputation_score: 10,
    require_owner_verified: false,
    exclude_dids: [didA],
    submission_proof_tier: 'gateway',
    requester_did: didA,
    worker_did: didB,
  };

  const selectFirst = await requestJson(`${baseUrl}/v1/reviewers/select`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: selectPayload,
  });
  assertStatus('reviewers.select.first', selectFirst, 200);

  const selectSecond = await requestJson(`${baseUrl}/v1/reviewers/select`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: selectPayload,
  });
  assertStatus('reviewers.select.second', selectSecond, 200);

  assertCondition(
    'reviewers.select.deterministic',
    JSON.stringify(selectFirst.json?.reviewers ?? []) === JSON.stringify(selectSecond.json?.reviewers ?? []),
    { first: selectFirst.json, second: selectSecond.json }
  );

  const firstReviewerDid = String(selectFirst.json?.reviewers?.[0]?.reviewer_did ?? '');
  assertCondition('reviewers.select.non_empty', firstReviewerDid.startsWith('did:'), selectFirst.json);

  const reviewerInfo = await requestJson(`${baseUrl}/v1/reviewers/${encodeURIComponent(firstReviewerDid)}`);
  assertStatus('reviewers.get', reviewerInfo, 200);

  const reviewerSelectionSmoke = {
    env: args.env,
    base_url: baseUrl,
    request: selectPayload,
    first_selection: selectFirst.json,
    second_selection: selectSecond.json,
    reviewer_info: reviewerInfo.json,
    assertions: {
      deterministic_ordering:
        JSON.stringify(selectFirst.json?.reviewers ?? []) === JSON.stringify(selectSecond.json?.reviewers ?? []),
      reviewer_info_found: reviewerInfo.status === 200,
      selection_metadata_present: Array.isArray(selectFirst.json?.selection_metadata?.selected_reasoning),
    },
  };

  // 3) deterministic penalty + decay
  const penaltySourceId = `rep_penalty_${now}_a`;
  const penaltyApply = await requestJson(`${baseUrl}/v1/penalties/apply`, {
    method: 'POST',
    headers: commonAdminHeaders,
    body: {
      schema_version: '1',
      source_event_id: penaltySourceId,
      did: didA,
      penalty_type: 'dispute_upheld_against_reviewer',
      severity: 2,
      reason: 'deterministic-dispute-penalty-smoke',
    },
  });
  assertStatus('penalty.apply', penaltyApply, 202);

  const repBeforeDecay = await requestJson(`${baseUrl}/v1/rep/${encodeURIComponent(didA)}`);
  assertStatus('rep.before_decay', repBeforeDecay, 200);

  const runDay = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const decayRunFirst = await requestJson(`${baseUrl}/v1/decay/run`, {
    method: 'POST',
    headers: commonAdminHeaders,
    body: { schema_version: '1', run_day: runDay },
  });
  assertStatus('decay.run.first', decayRunFirst, 200);

  const decayRunSecond = await requestJson(`${baseUrl}/v1/decay/run`, {
    method: 'POST',
    headers: commonAdminHeaders,
    body: { schema_version: '1', run_day: runDay },
  });
  assertStatus('decay.run.second', decayRunSecond, 200);
  assertCondition('decay.idempotent', decayRunSecond.json?.status === 'already_applied', decayRunSecond.json);

  const repAfterDecay = await requestJson(`${baseUrl}/v1/rep/${encodeURIComponent(didA)}`);
  assertStatus('rep.after_decay', repAfterDecay, 200);

  const decayPenaltySmoke = {
    env: args.env,
    base_url: baseUrl,
    did: didA,
    penalty_apply: penaltyApply.json,
    rep_before_decay: repBeforeDecay.json,
    decay_first: decayRunFirst.json,
    decay_second: decayRunSecond.json,
    rep_after_decay: repAfterDecay.json,
    assertions: {
      penalty_reduced_score:
        Number(repBeforeDecay.json?.reputation_score ?? 0) < Number(repAfterLoop.json?.reputation_score ?? 0),
      decay_idempotent: decayRunSecond.json?.status === 'already_applied',
      decay_non_increasing:
        Number(repAfterDecay.json?.reputation_score ?? 0) <= Number(repBeforeDecay.json?.reputation_score ?? 0),
    },
  };

  // 4) tier calculation
  const tierA = await requestJson(`${baseUrl}/v1/tiers/${encodeURIComponent(didA)}`);
  const tierB = await requestJson(`${baseUrl}/v1/tiers/${encodeURIComponent(didB)}`);
  assertStatus('tiers.didA', tierA, 200);
  assertStatus('tiers.didB', tierB, 200);

  assertCondition('tiers.valid.didA', Number.isInteger(tierA.json?.tier) && tierA.json?.tier >= 0 && tierA.json?.tier <= 3, tierA.json);
  assertCondition('tiers.valid.didB', Number.isInteger(tierB.json?.tier) && tierB.json?.tier >= 0 && tierB.json?.tier <= 3, tierB.json);

  const tierCalculationSmoke = {
    env: args.env,
    base_url: baseUrl,
    didA: tierA.json,
    didB: tierB.json,
    assertions: {
      didA_tier_range: Number.isInteger(tierA.json?.tier) && tierA.json?.tier >= 0 && tierA.json?.tier <= 3,
      didB_tier_range: Number.isInteger(tierB.json?.tier) && tierB.json?.tier >= 0 && tierB.json?.tier <= 3,
    },
  };

  // 5) queue + SLO + drift ops
  const queueStatus = await requestJson(`${baseUrl}/v1/ops/queue/status`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${args.repAdminKey}`,
    },
  });
  assertStatus('ops.queue.status', queueStatus, 200);

  const queueReplay = await requestJson(`${baseUrl}/v1/ops/queue/replay`, {
    method: 'POST',
    headers: commonAdminHeaders,
    body: {
      source_event_id: 'nonexistent-replay-target',
      limit: 5,
    },
  });
  assertCondition('ops.queue.replay.status', [200, 500].includes(queueReplay.status), queueReplay.json);

  const sloIngest = await requestJson(`${baseUrl}/v1/ops/slo/ingest?window_hours=24`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${args.repAdminKey}`,
    },
  });
  assertStatus('ops.slo.ingest', sloIngest, 200);

  const driftRecompute = await requestJson(`${baseUrl}/v1/ops/drift/recompute`, {
    method: 'POST',
    headers: commonAdminHeaders,
    body: {
      limit: 50,
      apply_repair: false,
    },
  });
  assertStatus('ops.drift.recompute', driftRecompute, 200);

  const driftLatest = await requestJson(`${baseUrl}/v1/ops/drift/latest`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${args.repAdminKey}`,
    },
  });
  assertStatus('ops.drift.latest', driftLatest, 200);

  const opsSmoke = {
    env: args.env,
    base_url: baseUrl,
    queue_status: queueStatus.json,
    queue_replay: { status: queueReplay.status, body: queueReplay.json },
    slo_ingest: sloIngest.json,
    drift_recompute: driftRecompute.json,
    drift_latest: driftLatest.json,
    assertions: {
      queue_status_has_counts: typeof queueStatus.json?.event_status_counts === 'object' && queueStatus.json?.event_status_counts !== null,
      slo_has_success_rate: typeof sloIngest.json?.success_rate === 'number',
      drift_report_has_totals: typeof driftRecompute.json?.total_profiles_checked === 'number',
      drift_latest_present: typeof driftLatest.json?.created_at === 'string',
    },
  };

  const auditEvents = await requestJson(`${baseUrl}/v1/audit/events?limit=25`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${args.repAdminKey}`,
    },
  });
  assertStatus('audit.events', auditEvents, 200);

  const deploySummary = {
    env: args.env,
    generated_at: new Date().toISOString(),
    deploy_version: args.deployVersion || null,
    base_url: baseUrl,
    smoke_files: {
      ingest_replay: path.join(outDir, 'ingest-replay-smoke.json'),
      ingest_loop: path.join(outDir, 'ingest-loop-smoke.json'),
      reviewer_selection: path.join(outDir, 'reviewer-selection-smoke.json'),
      decay_penalty: path.join(outDir, 'decay-penalty-smoke.json'),
      tier_calculation: path.join(outDir, 'tier-calculation-smoke.json'),
      ops: path.join(outDir, 'ops-smoke.json'),
    },
    audit_snapshot: {
      events_count: Array.isArray(auditEvents.json?.events) ? auditEvents.json.events.length : 0,
      next_cursor: auditEvents.json?.next_cursor ?? null,
    },
    pass: {
      ingest_replay: Object.values(ingestReplaySmoke.assertions).every(Boolean),
      ingest_loop: Object.values(ingestLoopSmoke.assertions).every(Boolean),
      reviewer_selection: Object.values(reviewerSelectionSmoke.assertions).every(Boolean),
      decay_penalty: Object.values(decayPenaltySmoke.assertions).every(Boolean),
      tier_calculation: Object.values(tierCalculationSmoke.assertions).every(Boolean),
      ops: Object.values(opsSmoke.assertions).every(Boolean),
    },
  };

  writeFileSync(path.join(outDir, 'ingest-replay-smoke.json'), toJsonText(ingestReplaySmoke));
  writeFileSync(path.join(outDir, 'ingest-loop-smoke.json'), toJsonText(ingestLoopSmoke));
  writeFileSync(path.join(outDir, 'reviewer-selection-smoke.json'), toJsonText(reviewerSelectionSmoke));
  writeFileSync(path.join(outDir, 'decay-penalty-smoke.json'), toJsonText(decayPenaltySmoke));
  writeFileSync(path.join(outDir, 'tier-calculation-smoke.json'), toJsonText(tierCalculationSmoke));
  writeFileSync(path.join(outDir, 'ops-smoke.json'), toJsonText(opsSmoke));
  writeFileSync(path.join(outDir, 'deploy-summary.json'), toJsonText(deploySummary));

  const summaryLines = [
    `clawrep smoke (${args.env})`,
    `generated_at=${deploySummary.generated_at}`,
    `base_url=${baseUrl}`,
    `deploy_version=${deploySummary.deploy_version ?? 'n/a'}`,
    `didA=${didA}`,
    `didB=${didB}`,
    `audit_events=${deploySummary.audit_snapshot.events_count}`,
    `pass=${Object.values(deploySummary.pass).every(Boolean) ? 'true' : 'false'}`,
  ];

  writeFileSync(path.join(outDir, 'summary.txt'), `${summaryLines.join('\n')}\n`);
  process.stdout.write(`${summaryLines.join('\n')}\n`);

  if (!Object.values(deploySummary.pass).every(Boolean)) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
