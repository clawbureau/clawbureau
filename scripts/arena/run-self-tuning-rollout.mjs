#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    taskFingerprint: '',
    environment: null,
    workerDid: 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    windowHours: 24,
    minOnlineWorkers: 3,
    minClaimSuccessRate: 0.8,
    minSubmissionSuccessRate: 0.8,
    minProofValidRate: 0.95,
    maxClaimSubmissionGap: 5,
    maxAcceptedBacklog: 5,
    gateEnforce: true,
    maxRuns: 80,
    minSamples: 6,
    minConfidence: 0.62,
    objectiveProfileName: null,
    experimentId: null,
    experimentArm: null,
    requirePromotion: false,
    allowFail: false,
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
      args.taskFingerprint = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--environment') {
      args.environment = argv[i + 1] ?? null;
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
    if (arg === '--gate-enforce') {
      args.gateEnforce = true;
      continue;
    }
    if (arg === '--no-gate-enforce') {
      args.gateEnforce = false;
      continue;
    }
    if (arg === '--max-runs') {
      args.maxRuns = Number.parseInt(argv[i + 1] ?? String(args.maxRuns), 10);
      i += 1;
      continue;
    }
    if (arg === '--min-samples') {
      args.minSamples = Number.parseInt(argv[i + 1] ?? String(args.minSamples), 10);
      i += 1;
      continue;
    }
    if (arg === '--min-confidence') {
      args.minConfidence = Number.parseFloat(argv[i + 1] ?? String(args.minConfidence));
      i += 1;
      continue;
    }
    if (arg === '--objective-profile-name') {
      args.objectiveProfileName = argv[i + 1] ?? null;
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
    if (arg === '--require-promotion') {
      args.requirePromotion = true;
      continue;
    }
    if (arg === '--allow-fail') {
      args.allowFail = true;
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

  if (!args.taskFingerprint) {
    throw new Error('Missing task fingerprint. Pass --task-fingerprint.');
  }

  if (!args.dryRun && !args.adminKey) {
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
    `${nowLabel()}-agp-us-063-self-tuning-rollout`,
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

  if (!response.ok && response.status !== 409) {
    throw new Error(`Request failed (${response.status}): ${JSON.stringify(payload)}`);
  }

  return {
    httpStatus: response.status,
    payload,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const rolloutUrl = `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/desk/self-tune-rollout`;

  const rolloutRequest = {
    task_fingerprint: args.taskFingerprint,
    environment: args.environment,
    worker_did: args.workerDid,
    window_hours: args.windowHours,
    min_online_workers: args.minOnlineWorkers,
    min_claim_success_rate: args.minClaimSuccessRate,
    min_submission_success_rate: args.minSubmissionSuccessRate,
    min_proof_valid_rate: args.minProofValidRate,
    max_claim_submission_gap: args.maxClaimSubmissionGap,
    max_accepted_backlog: args.maxAcceptedBacklog,
    gate_enforce: args.gateEnforce,
    max_runs: args.maxRuns,
    min_samples: args.minSamples,
    min_confidence: args.minConfidence,
    objective_profile_name: args.objectiveProfileName,
    experiment_id: args.experimentId,
    experiment_arm: args.experimentArm,
  };

  const rolloutResult = args.dryRun
    ? {
      httpStatus: 200,
      payload: {
        schema_version: 'arena_self_tune_rollout.v1',
        dry_run: true,
        rollout_status: 'PROMOTED',
        promotion_status: 'PROMOTED',
        gate: {
          enforce: args.gateEnforce,
          passed: true,
          blocked: false,
        },
        preview: {
          endpoint: rolloutUrl,
          request: rolloutRequest,
        },
      },
    }
    : await postJson(rolloutUrl, args.adminKey, rolloutRequest);

  const rolloutStatus = rolloutResult.payload?.rollout_status ?? 'UNKNOWN';
  const promoted = rolloutStatus === 'PROMOTED';
  const gateBlocked = rolloutResult.payload?.gate?.blocked === true;

  const summary = {
    ok: (!gateBlocked && (!args.requirePromotion || promoted)) || args.allowFail || args.dryRun,
    generated_at: new Date().toISOString(),
    dry_run: args.dryRun,
    endpoint: rolloutUrl,
    request: rolloutRequest,
    rollout_result: rolloutResult,
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`ARENA_SELF_TUNE_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify(rolloutResult.payload, null, 2)}\n`);

  if (!args.dryRun && !summary.ok) {
    process.exit(2);
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
