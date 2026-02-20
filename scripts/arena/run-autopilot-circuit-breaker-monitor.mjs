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
    maxRuns: 50,
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

    if (arg === '--max-runs') {
      args.maxRuns = Number.parseInt(argv[i + 1] ?? String(args.maxRuns), 10);
      i += 1;
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

  if (!Number.isFinite(args.maxRuns) || args.maxRuns <= 0) {
    throw new Error('--max-runs must be a positive integer');
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
    `${nowLabel()}-agp-us-080-circuit-breaker-hardening`,
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

  const autopilotUrl = `${base}/v1/arena/manager/autopilot`;
  const requestBody = {
    task_fingerprint: args.taskFingerprint,
    objective_profile_name: args.objectiveProfileName,
    experiment_id: args.experimentId,
    experiment_arm: args.experimentArm,
    max_runs: args.maxRuns,
    require_hard_gate_pass: true,
    allow_fallback: true,
    use_active_policy: true,
    required_skills: [],
    required_tools: [],
  };

  if (args.dryRun) {
    const preview = {
      ok: true,
      story: 'AGP-US-080',
      dry_run: true,
      generated_at: new Date().toISOString(),
      endpoint: autopilotUrl,
      request_body: requestBody,
    };

    const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, `${JSON.stringify(preview, null, 2)}\n`);

    process.stdout.write(`ARENA_AUTOPILOT_CIRCUIT_MONITOR_RESULT ${outputPath}\n`);
    process.stdout.write(`${JSON.stringify({ dry_run: true })}\n`);
    return;
  }

  const result = await postJson(autopilotUrl, args.adminKey, requestBody);

  const autopilotStatus = readPath(result.payload, ['autopilot', 'status'], null);
  const reasonCodes = readPath(result.payload, ['autopilot', 'reason_codes'], []);
  const circuitStatus = readPath(result.payload, ['autopilot', 'circuit_breaker', 'status'], null);
  const circuitReasonCodes = readPath(result.payload, ['autopilot', 'circuit_breaker', 'reason_codes'], []);

  const hasCircuitBreakerBinding = Boolean(circuitStatus)
    && Array.isArray(reasonCodes)
    && reasonCodes.some((code) => code === 'ARENA_AUTOPILOT_CIRCUIT_BREAKER_PASS' || code === 'ARENA_AUTOPILOT_CIRCUIT_BREAKER_TRIPPED');

  const summary = {
    ok: hasCircuitBreakerBinding,
    story: 'AGP-US-080',
    generated_at: new Date().toISOString(),
    endpoint_base: base,
    request: requestBody,
    http_status: result.status,
    autopilot_status: autopilotStatus,
    reason_codes: reasonCodes,
    circuit_breaker: {
      status: circuitStatus,
      reason_codes: circuitReasonCodes,
      mission_gate_status: readPath(result.payload, ['autopilot', 'circuit_breaker', 'mission_gate_status'], null),
      roi_status: readPath(result.payload, ['autopilot', 'circuit_breaker', 'roi_status'], null),
    },
    payload: result.payload,
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`ARENA_AUTOPILOT_CIRCUIT_MONITOR_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify({ ok: summary.ok, autopilot_status: summary.autopilot_status, circuit_status: summary.circuit_breaker.status })}\n`);

  if (!summary.ok) {
    process.exitCode = 2;
  }
}

main().catch((err) => {
  process.stderr.write(`run-autopilot-circuit-breaker-monitor failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
