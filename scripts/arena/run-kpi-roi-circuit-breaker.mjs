#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    taskFingerprint: 'AEM-FP-UI-DUEL-V1',
    objectiveProfileName: 'ui_duel',
    experimentId: null,
    experimentArm: null,
    workerDid: 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    windowHours: 24,
    roiLimit: 2000,
    minOnlineWorkers: 3,
    minClaimSuccessRate: 0.8,
    minSubmissionSuccessRate: 0.8,
    minProofValidRate: 0.95,
    maxClaimSubmissionGap: 5,
    maxAcceptedBacklog: 5,
    roiMinSampleCount: 5,
    roiMinFirstPassAcceptRate: 0.5,
    roiMaxOverrideRate: 0.3,
    roiMaxReworkRate: 0.2,
    roiMaxCostPerAcceptedBountyUsd: 2,
    enforce: true,
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
    if (arg === '--task-fingerprint') {
      args.taskFingerprint = argv[i + 1] ?? args.taskFingerprint;
      i += 1;
      continue;
    }
    if (arg === '--objective-profile-name') {
      args.objectiveProfileName = argv[i + 1] ?? args.objectiveProfileName;
      i += 1;
      continue;
    }
    if (arg === '--experiment-id') {
      args.experimentId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--experiment-arm') {
      args.experimentArm = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--worker-did') {
      args.workerDid = argv[i + 1] ?? args.workerDid;
      i += 1;
      continue;
    }
    if (arg === '--window-hours') {
      args.windowHours = Number.parseInt(argv[i + 1] ?? String(args.windowHours), 10);
      i += 1;
      continue;
    }
    if (arg === '--roi-limit') {
      args.roiLimit = Number.parseInt(argv[i + 1] ?? String(args.roiLimit), 10);
      i += 1;
      continue;
    }

    if (arg === '--min-online-workers') {
      args.minOnlineWorkers = Number.parseInt(argv[i + 1] ?? String(args.minOnlineWorkers), 10);
      i += 1;
      continue;
    }
    if (arg === '--min-claim-success-rate') {
      args.minClaimSuccessRate = Number.parseFloat(argv[i + 1] ?? String(args.minClaimSuccessRate));
      i += 1;
      continue;
    }
    if (arg === '--min-submission-success-rate') {
      args.minSubmissionSuccessRate = Number.parseFloat(argv[i + 1] ?? String(args.minSubmissionSuccessRate));
      i += 1;
      continue;
    }
    if (arg === '--min-proof-valid-rate') {
      args.minProofValidRate = Number.parseFloat(argv[i + 1] ?? String(args.minProofValidRate));
      i += 1;
      continue;
    }
    if (arg === '--max-claim-submission-gap') {
      args.maxClaimSubmissionGap = Number.parseInt(argv[i + 1] ?? String(args.maxClaimSubmissionGap), 10);
      i += 1;
      continue;
    }
    if (arg === '--max-accepted-backlog') {
      args.maxAcceptedBacklog = Number.parseInt(argv[i + 1] ?? String(args.maxAcceptedBacklog), 10);
      i += 1;
      continue;
    }

    if (arg === '--roi-min-sample-count') {
      args.roiMinSampleCount = Number.parseInt(argv[i + 1] ?? String(args.roiMinSampleCount), 10);
      i += 1;
      continue;
    }
    if (arg === '--roi-min-first-pass-accept-rate') {
      args.roiMinFirstPassAcceptRate = Number.parseFloat(argv[i + 1] ?? String(args.roiMinFirstPassAcceptRate));
      i += 1;
      continue;
    }
    if (arg === '--roi-max-override-rate') {
      args.roiMaxOverrideRate = Number.parseFloat(argv[i + 1] ?? String(args.roiMaxOverrideRate));
      i += 1;
      continue;
    }
    if (arg === '--roi-max-rework-rate') {
      args.roiMaxReworkRate = Number.parseFloat(argv[i + 1] ?? String(args.roiMaxReworkRate));
      i += 1;
      continue;
    }
    if (arg === '--roi-max-cost-per-accepted-bounty-usd') {
      args.roiMaxCostPerAcceptedBountyUsd = Number.parseFloat(argv[i + 1] ?? String(args.roiMaxCostPerAcceptedBountyUsd));
      i += 1;
      continue;
    }

    if (arg === '--no-enforce') {
      args.enforce = false;
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

  if (!Number.isFinite(args.windowHours) || args.windowHours <= 0) {
    throw new Error('--window-hours must be a positive integer');
  }

  if (!Number.isFinite(args.roiLimit) || args.roiLimit <= 0) {
    throw new Error('--roi-limit must be a positive integer');
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
    `${nowLabel()}-agp-us-079-kpi-roi-circuit-breaker`,
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

async function postJson(url, adminKey, body, { allow409 = false } = {}) {
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

  if (!response.ok && !(allow409 && response.status === 409)) {
    throw new Error(`POST failed (${response.status}): ${JSON.stringify(payload)}`);
  }

  return {
    status: response.status,
    payload,
  };
}

function readPath(objectValue, pathList, fallback = null) {
  let current = objectValue;
  for (const key of pathList) {
    if (!current || typeof current !== 'object' || !(key in current)) return fallback;
    current = current[key];
  }
  return current ?? fallback;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const base = args.bountiesBase.replace(/\/$/, '');

  const circuitUrl = `${base}/v1/arena/desk/circuit-breaker`;
  const requestBody = {
    task_fingerprint: args.taskFingerprint,
    objective_profile_name: args.objectiveProfileName,
    experiment_id: args.experimentId,
    experiment_arm: args.experimentArm,
    worker_did: args.workerDid,
    window_hours: args.windowHours,
    roi_limit: args.roiLimit,
    min_online_workers: args.minOnlineWorkers,
    min_claim_success_rate: args.minClaimSuccessRate,
    min_submission_success_rate: args.minSubmissionSuccessRate,
    min_proof_valid_rate: args.minProofValidRate,
    max_claim_submission_gap: args.maxClaimSubmissionGap,
    max_accepted_backlog: args.maxAcceptedBacklog,
    roi_min_sample_count: args.roiMinSampleCount,
    roi_min_first_pass_accept_rate: args.roiMinFirstPassAcceptRate,
    roi_max_override_rate: args.roiMaxOverrideRate,
    roi_max_rework_rate: args.roiMaxReworkRate,
    roi_max_cost_per_accepted_bounty_usd: args.roiMaxCostPerAcceptedBountyUsd,
    enforce: args.enforce,
  };

  if (args.dryRun) {
    const preview = {
      ok: true,
      story: 'AGP-US-079',
      dry_run: true,
      generated_at: new Date().toISOString(),
      endpoint: circuitUrl,
      request_body: requestBody,
    };

    const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, `${JSON.stringify(preview, null, 2)}\n`);

    process.stdout.write(`ARENA_KPI_ROI_CIRCUIT_BREAKER_RESULT ${outputPath}\n`);
    process.stdout.write(`${JSON.stringify({ dry_run: true })}\n`);
    return;
  }

  const result = await postJson(circuitUrl, args.adminKey, requestBody, { allow409: true });

  const summary = {
    ok: result.status !== 409,
    story: 'AGP-US-079',
    generated_at: new Date().toISOString(),
    endpoint_base: base,
    request: requestBody,
    http_status: result.status,
    circuit_status: readPath(result.payload, ['circuit', 'status'], null),
    reason_codes: readPath(result.payload, ['circuit', 'reason_codes'], []),
    gate: readPath(result.payload, ['circuit', 'gate'], null),
    mission_gate_status: readPath(result.payload, ['mission', 'kpi', 'gate_status'], null),
    roi_status: readPath(result.payload, ['roi', 'status'], null),
    roi_metrics: readPath(result.payload, ['roi', 'metrics'], null),
    payload: result.payload,
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`ARENA_KPI_ROI_CIRCUIT_BREAKER_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify({ ok: summary.ok, http_status: summary.http_status, circuit_status: summary.circuit_status })}\n`);

  if (!summary.ok) {
    process.exitCode = 2;
  }
}

main().catch((err) => {
  process.stderr.write(`run-kpi-roi-circuit-breaker failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
