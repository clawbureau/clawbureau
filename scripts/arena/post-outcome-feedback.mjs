#!/usr/bin/env node

import { createHash } from 'node:crypto';

const DEFAULT_BOUNTIES_BASE = 'https://staging.clawbounties.com';

function parseBooleanFlag(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return null;
}

function parseArgs(argv) {
  const args = {
    bountyId: null,
    arenaId: null,
    contenderId: null,
    outcomeStatus: null,
    reviewTimeMinutes: 0,
    timeToAcceptMinutes: null,
    predictedConfidence: null,
    recommendation: null,
    reviewerDecision: null,
    reviewerRationale: null,
    decisionTags: [],
    reworkRequired: null,
    reworkRequiredProvided: false,
    decisionRationale: null,
    overrideRationale: null,
    overrideReasonCode: null,
    notes: null,
    source: 'human-review',
    idempotencyKey: null,
    bountiesBase: DEFAULT_BOUNTIES_BASE,
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--bounty-id') {
      args.bountyId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--arena-id') {
      args.arenaId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--contender-id') {
      args.contenderId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--outcome-status') {
      args.outcomeStatus = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--review-time-minutes') {
      args.reviewTimeMinutes = Number(argv[i + 1] ?? 0);
      i += 1;
      continue;
    }
    if (arg === '--time-to-accept-minutes') {
      args.timeToAcceptMinutes = Number(argv[i + 1] ?? 0);
      i += 1;
      continue;
    }
    if (arg === '--predicted-confidence') {
      args.predictedConfidence = Number(argv[i + 1] ?? 0);
      i += 1;
      continue;
    }
    if (arg === '--recommendation') {
      args.recommendation = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--reviewer-decision') {
      args.reviewerDecision = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--reviewer-rationale') {
      args.reviewerRationale = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--decision-tag') {
      const value = argv[i + 1] ?? '';
      if (value.trim()) args.decisionTags.push(value.trim());
      i += 1;
      continue;
    }
    if (arg === '--decision-tags') {
      const value = argv[i + 1] ?? '';
      args.decisionTags.push(
        ...value
          .split(',')
          .map((tag) => tag.trim())
          .filter((tag) => tag.length > 0),
      );
      i += 1;
      continue;
    }
    if (arg === '--rework-required') {
      args.reworkRequiredProvided = true;
      args.reworkRequired = parseBooleanFlag(argv[i + 1] ?? '');
      i += 1;
      continue;
    }
    if (arg === '--decision-rationale') {
      args.decisionRationale = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--override-rationale') {
      args.overrideRationale = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--override-reason-code') {
      args.overrideReasonCode = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--notes') {
      args.notes = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--source') {
      args.source = argv[i + 1] ?? 'human-review';
      i += 1;
      continue;
    }
    if (arg === '--idempotency-key') {
      args.idempotencyKey = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
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
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
  }

  if (!args.bountyId || !args.arenaId || !args.outcomeStatus) {
    throw new Error('Usage: node scripts/arena/post-outcome-feedback.mjs --bounty-id <bty_...> --arena-id <arena_...> --outcome-status <ACCEPTED|OVERRIDDEN|REWORK|REJECTED|DISPUTED> [--contender-id <id>] [--review-time-minutes <n>] [--time-to-accept-minutes <n>] [--predicted-confidence <0..1>] [--recommendation <APPROVE|REQUEST_CHANGES|REJECT>] [--reviewer-decision <approve|request_changes|reject>] [--reviewer-rationale <text>] [--decision-tag <tag>] [--decision-tags a,b,c] [--rework-required <true|false>] [--decision-rationale <text>] [--override-rationale <text>] [--override-reason-code <ARENA_OVERRIDE_...>] [--notes <text>] [--bounties-base <url>] [--admin-key <key>] [--dry-run]');
  }

  if (String(args.outcomeStatus).toUpperCase() === 'OVERRIDDEN' && !args.overrideReasonCode) {
    throw new Error('--override-reason-code is required when --outcome-status OVERRIDDEN');
  }

  if (
    args.reviewerDecision &&
    args.reviewerDecision !== 'approve' &&
    args.reviewerDecision !== 'request_changes' &&
    args.reviewerDecision !== 'reject'
  ) {
    throw new Error('--reviewer-decision must be one of approve|request_changes|reject');
  }

  if (args.reworkRequiredProvided && args.reworkRequired === null) {
    throw new Error('--rework-required must be true|false|1|0|yes|no');
  }

  args.decisionTags = [...new Set(args.decisionTags.map((tag) => tag.trim()).filter((tag) => tag.length > 0))].slice(0, 20);

  return args;
}

function sha256b64u(input) {
  return createHash('sha256').update(input).digest('base64url');
}

function buildIdempotencyKey(args) {
  return `arena-outcome:${sha256b64u([
    args.bountyId,
    args.arenaId,
    args.contenderId ?? '',
    args.outcomeStatus,
    String(args.overrideReasonCode ?? ''),
    String(args.reviewerDecision ?? ''),
    String(args.reworkRequired ?? ''),
    String(args.reviewerRationale ?? ''),
    String(args.decisionTags.join(',')),
    String(args.reviewTimeMinutes),
    String(args.timeToAcceptMinutes ?? ''),
    String(args.notes ?? ''),
  ].join('|'))}`;
}

async function requestJson(url, { method = 'GET', adminKey, body } = {}) {
  const headers = { Accept: 'application/json' };
  if (adminKey) headers['x-admin-key'] = adminKey;

  const init = { method, headers };
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const response = await fetch(url, init);
  const text = await response.text();

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = { raw: text };
  }

  if (!response.ok) {
    const err = new Error(`${method} ${url} failed with ${response.status}`);
    err.status = response.status;
    err.response = parsed;
    throw err;
  }

  return parsed;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.dryRun && !args.adminKey.trim()) {
    throw new Error('admin key is required unless --dry-run is set (provide --admin-key or BOUNTIES_ADMIN_KEY env)');
  }

  const metadata = {
    ...(args.decisionRationale ? { decision_rationale: args.decisionRationale } : {}),
    ...(args.overrideRationale ? { override_rationale: args.overrideRationale } : {}),
    ...(args.decisionTags.length > 0 ? { calibration_signal_tags: args.decisionTags } : {}),
  };

  const payload = {
    idempotency_key: args.idempotencyKey ?? buildIdempotencyKey(args),
    arena_id: args.arenaId,
    contender_id: args.contenderId ?? undefined,
    outcome_status: args.outcomeStatus,
    review_time_minutes: args.reviewTimeMinutes,
    time_to_accept_minutes: args.timeToAcceptMinutes,
    predicted_confidence: args.predictedConfidence,
    recommendation: args.recommendation,
    reviewer_decision: args.reviewerDecision,
    reviewer_rationale: args.reviewerRationale,
    decision_taxonomy_tags: args.decisionTags.length > 0 ? args.decisionTags : undefined,
    rework_required: args.reworkRequiredProvided ? args.reworkRequired : undefined,
    override_reason_code: args.overrideReasonCode,
    notes: args.notes,
    source: args.source,
    metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
  };

  const endpoint = `${args.bountiesBase.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(args.bountyId)}/arena/outcome`;

  if (args.dryRun) {
    console.log(JSON.stringify({ ok: true, mode: 'dry-run', endpoint, payload }, null, 2));
    return;
  }

  const response = await requestJson(endpoint, {
    method: 'POST',
    adminKey: args.adminKey.trim(),
    body: payload,
  });

  const arenaOutcomes = await requestJson(
    `${args.bountiesBase.replace(/\/$/, '')}/v1/arena/${encodeURIComponent(args.arenaId)}/outcomes?limit=50`,
    {
      method: 'GET',
      adminKey: args.adminKey.trim(),
    },
  );

  console.log(JSON.stringify({ ok: true, response, arena_outcomes: arenaOutcomes }, null, 2));
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
