#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const DEFAULT_WORKER_DID = 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    workerDid: DEFAULT_WORKER_DID,
    objectiveProfileName: 'arena-autonomous',
    taskFingerprint: 'typescript:worker:api-hardening',
    targetOpenBounties: 25,
    seedLimit: 25,
    seedRewardMinor: '25',
    targetClaims: 15,
    claimLimit: 80,
    claimBudgetMinor: '10000000',
    targetSubmissions: 15,
    submissionLimit: 120,
    targetDecisions: 15,
    decisionLimit: 120,
    decisionMode: 'approve_valid',
    gateEnforce: false,
    windowHours: 72,
    dryRun: false,
    outputPath: null,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--bounties-base') {
      args.bountiesBase = argv[i + 1] ?? args.bountiesBase;
      i += 1;
      continue;
    }
    if (arg === '--admin-key') {
      args.adminKey = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--worker-did') {
      args.workerDid = argv[i + 1] ?? args.workerDid;
      i += 1;
      continue;
    }
    if (arg === '--objective-profile-name') {
      args.objectiveProfileName = argv[i + 1] ?? args.objectiveProfileName;
      i += 1;
      continue;
    }
    if (arg === '--task-fingerprint') {
      args.taskFingerprint = argv[i + 1] ?? args.taskFingerprint;
      i += 1;
      continue;
    }
    if (arg === '--target-open-bounties') {
      args.targetOpenBounties = Number.parseInt(argv[i + 1] ?? String(args.targetOpenBounties), 10);
      i += 1;
      continue;
    }
    if (arg === '--seed-limit') {
      args.seedLimit = Number.parseInt(argv[i + 1] ?? String(args.seedLimit), 10);
      i += 1;
      continue;
    }
    if (arg === '--seed-reward-minor') {
      args.seedRewardMinor = argv[i + 1] ?? args.seedRewardMinor;
      i += 1;
      continue;
    }
    if (arg === '--target-claims') {
      args.targetClaims = Number.parseInt(argv[i + 1] ?? String(args.targetClaims), 10);
      i += 1;
      continue;
    }
    if (arg === '--claim-limit') {
      args.claimLimit = Number.parseInt(argv[i + 1] ?? String(args.claimLimit), 10);
      i += 1;
      continue;
    }
    if (arg === '--claim-budget-minor') {
      args.claimBudgetMinor = argv[i + 1] ?? args.claimBudgetMinor;
      i += 1;
      continue;
    }
    if (arg === '--target-submissions') {
      args.targetSubmissions = Number.parseInt(argv[i + 1] ?? String(args.targetSubmissions), 10);
      i += 1;
      continue;
    }
    if (arg === '--submission-limit') {
      args.submissionLimit = Number.parseInt(argv[i + 1] ?? String(args.submissionLimit), 10);
      i += 1;
      continue;
    }
    if (arg === '--target-decisions') {
      args.targetDecisions = Number.parseInt(argv[i + 1] ?? String(args.targetDecisions), 10);
      i += 1;
      continue;
    }
    if (arg === '--decision-limit') {
      args.decisionLimit = Number.parseInt(argv[i + 1] ?? String(args.decisionLimit), 10);
      i += 1;
      continue;
    }
    if (arg === '--decision-mode') {
      args.decisionMode = argv[i + 1] ?? args.decisionMode;
      i += 1;
      continue;
    }
    if (arg === '--window-hours') {
      args.windowHours = Number.parseInt(argv[i + 1] ?? String(args.windowHours), 10);
      i += 1;
      continue;
    }
    if (arg === '--gate-enforce') {
      args.gateEnforce = true;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
    if (arg === '--output') {
      args.outputPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
  }

  if (!args.adminKey) {
    throw new Error('Missing admin key. Pass --admin-key or set BOUNTIES_ADMIN_KEY.');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function defaultOutputPath() {
  const root = path.join(
    process.cwd(),
    'artifacts',
    'ops',
    'arena-productization',
    `${nowLabel()}-agp-us-069-autonomous-desk-cycle`,
  );
  return path.join(root, 'summary.json');
}

function stableJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(',')}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
}

async function postJson(url, adminKey, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-admin-key': adminKey,
    },
    body: stableJson(body),
  });

  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = { raw: text };
  }

  if (!response.ok) {
    throw new Error(`Request failed (${response.status}): ${JSON.stringify(payload)}`);
  }

  return payload;
}

async function getJson(url, adminKey) {
  const response = await fetch(url, {
    headers: {
      'x-admin-key': adminKey,
    },
  });

  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = { raw: text };
  }

  if (!response.ok) {
    throw new Error(`Request failed (${response.status}): ${JSON.stringify(payload)}`);
  }

  return payload;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const base = args.bountiesBase.replace(/\/$/, '');
  const runLabel = nowLabel();

  const endpoints = {
    discover: `${base}/v1/arena/desk/discover-loop`,
    claim: `${base}/v1/arena/desk/claim-loop`,
    submit: `${base}/v1/arena/desk/submit-loop`,
    decision: `${base}/v1/arena/desk/decision-loop`,
    mission: `${base}/v1/arena/mission?window_hours=${args.windowHours}`,
    kpiGate: `${base}/v1/arena/desk/kpi-gate`,
    selfTune: `${base}/v1/arena/desk/self-tune-rollout`,
  };

  const discoverRequest = {
    target_open_bounties: args.targetOpenBounties,
    seed_limit: args.seedLimit,
    seed_reward_minor: args.seedRewardMinor,
    objective_profile_name: args.objectiveProfileName,
    discover_id: `discover_${runLabel}`,
    dry_run: args.dryRun,
  };

  const claimRequest = {
    limit: args.claimLimit,
    target_claims: args.targetClaims,
    budget_minor: args.claimBudgetMinor,
    objective_profile_name: args.objectiveProfileName,
    dry_run: args.dryRun,
    loop_id: `claim_${runLabel}`,
  };

  const submitRequest = {
    worker_did: args.workerDid,
    target_submissions: args.targetSubmissions,
    limit: args.submissionLimit,
    dry_run: args.dryRun,
  };

  const decisionRequest = {
    decision_mode: args.decisionMode,
    target_decisions: args.targetDecisions,
    limit: args.decisionLimit,
    require_claimed: true,
    loop_id: `decision_${runLabel}`,
    dry_run: args.dryRun,
  };

  if (args.dryRun) {
    const preview = {
      ok: true,
      story: 'AGP-US-069',
      generated_at: new Date().toISOString(),
      dry_run: true,
      endpoints,
      requests: {
        discover: discoverRequest,
        claim: claimRequest,
        submit: submitRequest,
        decision: decisionRequest,
      },
    };

    const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, `${JSON.stringify(preview, null, 2)}\n`);

    process.stdout.write(`ARENA_AUTONOMOUS_CYCLE_RESULT ${outputPath}\n`);
    process.stdout.write(`${JSON.stringify({ dry_run: true }, null, 2)}\n`);
    return;
  }

  const discoverResult = await postJson(endpoints.discover, args.adminKey, discoverRequest);
  const claimResult = await postJson(endpoints.claim, args.adminKey, claimRequest);

  const claimedBountyIds = Array.isArray(claimResult.decisions)
    ? claimResult.decisions
        .filter((entry) => entry && entry.status === 'claimed' && typeof entry.bounty_id === 'string')
        .map((entry) => entry.bounty_id)
    : [];

  const submitRequestResolved = {
    ...submitRequest,
    bounty_ids: claimedBountyIds,
  };
  const submitResult = await postJson(endpoints.submit, args.adminKey, submitRequestResolved);

  const decisionCandidates = Array.isArray(submitResult.decisions)
    ? submitResult.decisions
        .filter(
          (entry) =>
            entry &&
            entry.submission_status === 'pending_review' &&
            entry.proof_verify_status === 'valid' &&
            typeof entry.bounty_id === 'string',
        )
        .map((entry) => entry.bounty_id)
    : [];

  const decisionRequestResolved = {
    ...decisionRequest,
    bounty_ids: decisionCandidates,
  };
  const decisionResult = await postJson(endpoints.decision, args.adminKey, decisionRequestResolved);

  const missionResult = await getJson(endpoints.mission, args.adminKey);
  const kpiGateResult = await postJson(endpoints.kpiGate, args.adminKey, {
    worker_did: args.workerDid,
    window_hours: args.windowHours,
    enforce: args.gateEnforce,
  });

  const selfTuneResult = await postJson(endpoints.selfTune, args.adminKey, {
    task_fingerprint: args.taskFingerprint,
    worker_did: args.workerDid,
    window_hours: args.windowHours,
    gate_enforce: args.gateEnforce,
    objective_profile_name: args.objectiveProfileName,
  });

  const summary = {
    ok: true,
    story: 'AGP-US-069',
    generated_at: new Date().toISOString(),
    dry_run: false,
    endpoints,
    requests: {
      discover: discoverRequest,
      claim: claimRequest,
      submit: submitRequestResolved,
      decision: decisionRequestResolved,
    },
    results: {
      discover: discoverResult,
      claim: claimResult,
      submit: submitResult,
      decision: decisionResult,
      mission: missionResult,
      kpi_gate: kpiGateResult,
      self_tune: selfTuneResult,
    },
    targets: {
      target_open_bounties: args.targetOpenBounties,
      target_claims: args.targetClaims,
      target_submissions: args.targetSubmissions,
      target_decisions: args.targetDecisions,
    },
    achieved: {
      open_after: Number(discoverResult?.totals?.open_after ?? 0),
      claimed: Number(claimResult?.totals?.claimed ?? 0),
      submitted: Number(submitResult?.totals?.successful_pending_review ?? 0),
      decisions_applied:
        Number(decisionResult?.totals?.approved ?? 0) + Number(decisionResult?.totals?.rejected ?? 0),
      gate_status: kpiGateResult?.kpi?.gate_status ?? null,
      rollout_status: selfTuneResult?.rollout_status ?? null,
    },
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`ARENA_AUTONOMOUS_CYCLE_RESULT ${outputPath}\n`);
  process.stdout.write(
    `${JSON.stringify(
      {
        open_after: summary.achieved.open_after,
        claimed: summary.achieved.claimed,
        submitted: summary.achieved.submitted,
        decisions_applied: summary.achieved.decisions_applied,
        gate_status: summary.achieved.gate_status,
        rollout_status: summary.achieved.rollout_status,
      },
      null,
      2,
    )}\n`,
  );
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
