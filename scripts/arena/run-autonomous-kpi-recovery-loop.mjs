#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    workerDid: 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    windowHours: 24,
    limit: 80,
    targetSubmissions: null,
    allowWorkerRebindOnMismatch: true,
    runSubmitLoop: false,
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

    if (arg === '--limit') {
      args.limit = Number.parseInt(argv[i + 1] ?? String(args.limit), 10);
      i += 1;
      continue;
    }

    if (arg === '--target-submissions') {
      args.targetSubmissions = Number.parseInt(argv[i + 1] ?? '0', 10);
      i += 1;
      continue;
    }

    if (arg === '--no-worker-rebind') {
      args.allowWorkerRebindOnMismatch = false;
      continue;
    }

    if (arg === '--run-submit-loop') {
      args.runSubmitLoop = true;
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

  if (!Number.isFinite(args.limit) || args.limit <= 0) {
    throw new Error('--limit must be a positive integer');
  }

  if (args.targetSubmissions !== null && (!Number.isFinite(args.targetSubmissions) || args.targetSubmissions < 0)) {
    throw new Error('--target-submissions must be >= 0');
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
    `${nowLabel()}-agp-us-076-kpi-gate-recovery`,
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
    throw new Error(`GET failed (${response.status}): ${JSON.stringify(payload)}`);
  }

  return payload;
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

function metric(snapshot, pathList, fallback = null) {
  let current = snapshot;
  for (const key of pathList) {
    if (!current || typeof current !== 'object' || !(key in current)) {
      return fallback;
    }
    current = current[key];
  }
  return current ?? fallback;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const base = args.bountiesBase.replace(/\/$/, '');

  const missionUrl = `${base}/v1/arena/mission?worker_did=${encodeURIComponent(args.workerDid)}&window_hours=${args.windowHours}`;
  const submitUrl = `${base}/v1/arena/desk/submit-loop`;
  const gateUrl = `${base}/v1/arena/desk/kpi-gate`;

  if (args.dryRun) {
    const preview = {
      ok: true,
      story: 'AGP-US-076',
      dry_run: true,
      generated_at: new Date().toISOString(),
      endpoints: {
        mission: missionUrl,
        submit_loop: submitUrl,
        kpi_gate: gateUrl,
      },
      planned_submit_body: {
        enabled: args.runSubmitLoop,
        worker_did: args.workerDid,
        target_submissions: args.targetSubmissions,
        limit: args.limit,
        allow_worker_rebind_on_mismatch: args.allowWorkerRebindOnMismatch,
      },
      planned_gate_body: {
        worker_did: args.workerDid,
        window_hours: args.windowHours,
        enforce: args.enforce,
      },
    };

    const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, `${JSON.stringify(preview, null, 2)}\n`);

    process.stdout.write(`ARENA_KPI_RECOVERY_RESULT ${outputPath}\n`);
    process.stdout.write(`${JSON.stringify({ dry_run: true })}\n`);
    return;
  }

  const beforeMission = await getJson(missionUrl, args.adminKey);
  const claimGap = Number(metric(beforeMission, ['backlog', 'claim_submission_gap'], 0) ?? 0);
  const gapBountyIdsRaw = metric(beforeMission, ['backlog', 'claim_submission_gap_bounty_ids'], []);
  const gapBountyIds = Array.isArray(gapBountyIdsRaw)
    ? gapBountyIdsRaw.map((entry) => String(entry).trim()).filter((entry) => entry.startsWith('bty_'))
    : [];

  const targetSubmissions = args.runSubmitLoop
    ? (args.targetSubmissions !== null ? args.targetSubmissions : claimGap)
    : 0;

  let submitLoop = {
    skipped: true,
    reason: args.runSubmitLoop ? 'NO_GAP' : 'SUBMIT_LOOP_DISABLED',
    request: null,
    response: null,
  };

  if (args.runSubmitLoop && targetSubmissions > 0) {
    const submitBody = {
      worker_did: args.workerDid,
      target_submissions: targetSubmissions,
      limit: args.limit,
      allow_worker_rebind_on_mismatch: args.allowWorkerRebindOnMismatch,
      bounty_ids: gapBountyIds,
    };

    const submitResult = await postJson(submitUrl, args.adminKey, submitBody);
    submitLoop = {
      skipped: false,
      reason: null,
      request: submitBody,
      response_status: submitResult.status,
      response: submitResult.payload,
    };
  }

  const afterMission = await getJson(missionUrl, args.adminKey);
  const kpiGateBody = {
    worker_did: args.workerDid,
    window_hours: args.windowHours,
    enforce: args.enforce,
  };
  const kpiGateResult = await postJson(gateUrl, args.adminKey, kpiGateBody, { allow409: true });

  const beforeGateStatus = metric(beforeMission, ['kpi', 'gate_status'], null);
  const afterGateStatus = metric(afterMission, ['kpi', 'gate_status'], null);
  const gateStatus = metric(kpiGateResult.payload, ['kpi', 'gate_status'], null);

  const summary = {
    ok: kpiGateResult.status !== 409,
    story: 'AGP-US-076',
    generated_at: new Date().toISOString(),
    endpoint_base: base,
    worker_did: args.workerDid,
    window_hours: args.windowHours,
    run_submit_loop: args.runSubmitLoop,
    before: {
      gate_status: beforeGateStatus,
      reason_codes: metric(beforeMission, ['kpi', 'reason_codes'], []),
      submission_success_rate: metric(beforeMission, ['kpi', 'submission_success_rate'], null),
      proof_valid_rate: metric(beforeMission, ['kpi', 'proof_valid_rate'], null),
      claim_submission_gap: metric(beforeMission, ['backlog', 'claim_submission_gap'], null),
      claim_submission_gap_bounty_ids: gapBountyIds,
      raw: beforeMission,
    },
    submit_loop: submitLoop,
    after: {
      gate_status: afterGateStatus,
      reason_codes: metric(afterMission, ['kpi', 'reason_codes'], []),
      submission_success_rate: metric(afterMission, ['kpi', 'submission_success_rate'], null),
      proof_valid_rate: metric(afterMission, ['kpi', 'proof_valid_rate'], null),
      claim_submission_gap: metric(afterMission, ['backlog', 'claim_submission_gap'], null),
      raw: afterMission,
    },
    kpi_gate: {
      enforce: args.enforce,
      http_status: kpiGateResult.status,
      gate_status: gateStatus,
      payload: kpiGateResult.payload,
    },
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`ARENA_KPI_RECOVERY_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify({
    before_gate_status: beforeGateStatus,
    after_gate_status: afterGateStatus,
    kpi_gate_http_status: kpiGateResult.status,
    claim_gap_before: claimGap,
    claim_gap_after: metric(afterMission, ['backlog', 'claim_submission_gap'], null),
  })}\n`);

  if (args.enforce && kpiGateResult.status === 409) {
    throw new Error('KPI gate remains blocked after recovery loop');
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
