#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_BOUNTIES_BASE = 'https://staging.clawbounties.com';
const DEFAULT_OUTPUT_ROOT = 'artifacts/ops/arena-productization';

function parseArgs(argv) {
  const args = {
    bountiesBase: DEFAULT_BOUNTIES_BASE,
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    taskFingerprint: null,
    objectiveProfileName: null,
    experimentId: null,
    experimentArm: null,
    environment: null,
    maxRuns: 80,
    minSamples: 6,
    minConfidence: 0.62,
    outputRoot: DEFAULT_OUTPUT_ROOT,
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--bounties-base') {
      args.bountiesBase = argv[i + 1] ?? DEFAULT_BOUNTIES_BASE;
      i += 1;
      continue;
    }
    if (arg === '--admin-key') {
      args.adminKey = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--task-fingerprint') {
      args.taskFingerprint = argv[i + 1] ?? null;
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
    if (arg === '--environment') {
      args.environment = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--max-runs') {
      args.maxRuns = Number(argv[i + 1] ?? 80);
      i += 1;
      continue;
    }
    if (arg === '--min-samples') {
      args.minSamples = Number(argv[i + 1] ?? 6);
      i += 1;
      continue;
    }
    if (arg === '--min-confidence') {
      args.minConfidence = Number(argv[i + 1] ?? 0.62);
      i += 1;
      continue;
    }
    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? DEFAULT_OUTPUT_ROOT;
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
  }

  if (!args.taskFingerprint || !String(args.taskFingerprint).trim()) {
    throw new Error('--task-fingerprint is required');
  }

  if (!Number.isFinite(args.maxRuns) || args.maxRuns <= 0) {
    throw new Error('--max-runs must be a positive number');
  }

  if (!Number.isFinite(args.minSamples) || args.minSamples <= 0) {
    throw new Error('--min-samples must be a positive number');
  }

  if (!Number.isFinite(args.minConfidence) || args.minConfidence < 0 || args.minConfidence > 1) {
    throw new Error('--min-confidence must be within [0,1]');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function slugify(value) {
  return String(value ?? 'unknown')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80) || 'unknown';
}

async function requestJson(url, { adminKey, method = 'GET', body } = {}) {
  const headers = {
    Accept: 'application/json',
  };

  if (adminKey) headers['x-admin-key'] = adminKey;
  if (method !== 'GET') headers['content-type'] = 'application/json';

  const response = await fetch(url, {
    method,
    headers,
    body: body ? stableJson(body) : undefined,
  });

  const raw = await response.text();
  let json;
  try {
    json = JSON.parse(raw);
  } catch {
    json = { raw };
  }

  if (!response.ok) {
    const error = new Error(`${method} ${url} failed with ${response.status}`);
    error.status = response.status;
    error.response = json;
    throw error;
  }

  return json;
}

function asRecord(value) {
  return value && typeof value === 'object' ? value : null;
}

function asString(value) {
  return typeof value === 'string' ? value : null;
}

function asNumber(value, fallback = 0) {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function asStringArray(value) {
  return Array.isArray(value) ? value.filter((entry) => typeof entry === 'string') : [];
}

function buildQuery(params) {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === '') continue;
    query.set(key, String(value));
  }
  return query.toString();
}

function buildSummary({ args, endpointBase, postPayload, getPayload, routePayload, outputDir }) {
  const postRec = asRecord(postPayload);
  const getRec = asRecord(getPayload);
  const routeRec = asRecord(routePayload);

  const optimizer = getRec ?? postRec ?? {};
  const gates = asRecord(optimizer.gates) ?? {};

  const sampleCount = Math.trunc(asNumber(gates.sample_count, 0));
  const confidenceScore = asNumber(gates.confidence_score, 0);
  const promotionStatus = asString(optimizer.promotion_status) ?? 'unknown';
  const reasonCodes = asStringArray(optimizer.reason_codes);

  const activePolicy = asRecord(optimizer.current_active_policy);
  const shadowPolicy = asRecord(optimizer.candidate_shadow_policy);
  const routeRecommended = asString(asRecord(routeRec?.recommended)?.contender_id);

  const activeContender = asString(activePolicy?.contender_id);
  const shadowContender = asString(shadowPolicy?.contender_id);

  const checks = {
    real_samples_present: sampleCount > 0,
    shadow_policy_present: Boolean(shadowContender),
    promoted_active_matches_shadow:
      promotionStatus !== 'PROMOTED' || (Boolean(activeContender) && activeContender === shadowContender),
    route_uses_active_policy_when_promoted:
      promotionStatus !== 'PROMOTED' || (Boolean(activeContender) && routeRecommended === activeContender),
    not_ready_reason_codes_present:
      promotionStatus !== 'NOT_READY' || reasonCodes.some((code) => code.startsWith('ARENA_POLICY_NOT_READY_')),
  };

  const allChecksPassed = Object.values(checks).every(Boolean);

  return {
    ok: allChecksPassed,
    generated_at: new Date().toISOString(),
    story: 'AGP-US-055',
    endpoint_base: endpointBase,
    output_dir: outputDir,
    task_fingerprint: args.taskFingerprint,
    objective_profile_name: args.objectiveProfileName,
    experiment_id: args.experimentId,
    experiment_arm: args.experimentArm,
    environment: args.environment,
    gates: {
      min_samples: args.minSamples,
      min_confidence: args.minConfidence,
      sample_count: sampleCount,
      confidence_score: Number(confidenceScore.toFixed(4)),
    },
    status: {
      promotion_status: promotionStatus,
      active_contender_id: activeContender,
      shadow_contender_id: shadowContender,
      route_recommended_contender_id: routeRecommended,
      reason_codes: reasonCodes,
    },
    checks,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const endpointBase = args.bountiesBase.replace(/\/$/, '');
  const slug = slugify(args.taskFingerprint);
  const outputDir = path.join(args.outputRoot, `${nowLabel()}-agp-us-055-policy-optimizer-${slug}`);

  const postBody = {
    task_fingerprint: args.taskFingerprint,
    objective_profile_name: args.objectiveProfileName,
    experiment_id: args.experimentId,
    experiment_arm: args.experimentArm,
    environment: args.environment,
    max_runs: Math.trunc(args.maxRuns),
    min_samples: Math.trunc(args.minSamples),
    min_confidence: args.minConfidence,
  };

  const getQuery = buildQuery({
    task_fingerprint: args.taskFingerprint,
    objective_profile_name: args.objectiveProfileName,
    experiment_id: args.experimentId,
    experiment_arm: args.experimentArm,
    environment: args.environment,
  });

  const routeBody = {
    task_fingerprint: args.taskFingerprint,
    objective_profile_name: args.objectiveProfileName,
    experiment_id: args.experimentId,
    experiment_arm: args.experimentArm,
    environment: args.environment,
    max_runs: Math.trunc(args.maxRuns),
    require_hard_gate_pass: true,
    allow_fallback: true,
    use_active_policy: true,
  };

  if (args.dryRun) {
    console.log(JSON.stringify({
      ok: true,
      mode: 'dry-run',
      output_dir: outputDir,
      post_endpoint: `${endpointBase}/v1/arena/policy-optimizer`,
      get_endpoint: `${endpointBase}/v1/arena/policy-optimizer?${getQuery}`,
      route_endpoint: `${endpointBase}/v1/arena/manager/route`,
      post_body: postBody,
      route_body: routeBody,
    }, null, 2));
    return;
  }

  if (!args.adminKey.trim()) {
    throw new Error('admin key is required unless --dry-run is set (provide --admin-key or BOUNTIES_ADMIN_KEY env)');
  }

  mkdirSync(outputDir, { recursive: true });

  const postEndpoint = `${endpointBase}/v1/arena/policy-optimizer`;
  const getEndpoint = `${endpointBase}/v1/arena/policy-optimizer?${getQuery}`;
  const routeEndpoint = `${endpointBase}/v1/arena/manager/route`;

  const postPayload = await requestJson(postEndpoint, {
    adminKey: args.adminKey.trim(),
    method: 'POST',
    body: postBody,
  });

  const getPayload = await requestJson(getEndpoint, {
    adminKey: args.adminKey.trim(),
    method: 'GET',
  });

  const routePayload = await requestJson(routeEndpoint, {
    adminKey: args.adminKey.trim(),
    method: 'POST',
    body: routeBody,
  });

  const summary = buildSummary({
    args,
    endpointBase,
    postPayload,
    getPayload,
    routePayload,
    outputDir,
  });

  const postPath = path.join(outputDir, 'policy-optimizer.post.json');
  const getPath = path.join(outputDir, 'policy-optimizer.get.json');
  const routePath = path.join(outputDir, 'route-with-active-policy.json');
  const summaryPath = path.join(outputDir, 'summary.json');

  writeFileSync(postPath, `${stableJson(postPayload)}\n`);
  writeFileSync(getPath, `${stableJson(getPayload)}\n`);
  writeFileSync(routePath, `${stableJson(routePayload)}\n`);
  writeFileSync(summaryPath, `${stableJson(summary)}\n`);

  console.log(JSON.stringify({
    ...summary,
    artifacts: {
      post: postPath,
      get: getPath,
      route: routePath,
      summary: summaryPath,
    },
  }, null, 2));

  if (!summary.ok) {
    process.exitCode = 2;
  }
}

main().catch((err) => {
  console.error(JSON.stringify({
    ok: false,
    error: err instanceof Error ? err.message : String(err),
    status: err && typeof err === 'object' && 'status' in err ? err.status : undefined,
    details: err && typeof err === 'object' && 'response' in err ? err.response : undefined,
  }, null, 2));
  process.exit(1);
});
