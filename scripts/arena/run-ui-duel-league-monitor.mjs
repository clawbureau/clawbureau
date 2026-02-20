#!/usr/bin/env node

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

function parseArgs(argv) {
  const args = {
    stageBase: 'https://staging.clawbounties.com',
    prodBase: 'https://clawbounties.com',
    stageAdminKey: process.env.BOUNTIES_ADMIN_KEY_STAGING ?? process.env.BOUNTIES_ADMIN_KEY ?? '',
    prodAdminKey: process.env.BOUNTIES_ADMIN_KEY_PROD ?? process.env.BOUNTIES_ADMIN_KEY ?? '',
    taskFingerprint: 'frontend:clawbounties:ux-redesign',
    objectiveProfileName: 'ui-duel-balanced',
    maxRuns: 80,
    rounds: 3,
    intervalSeconds: 10,
    minAnalyzedRuns: 1,
    expectedLeader: 'contender_gpt_5_3_codex_xhigh_pi',
    requiredContenders: [
      'contender_gpt_5_3_codex_xhigh_pi',
      'contender_gemini_3_1_pro_preview_pi',
    ],
    enforce: true,
    dryRun: false,
    outputPath: null,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--stage-base') {
      args.stageBase = argv[i + 1] ?? args.stageBase;
      i += 1;
      continue;
    }
    if (arg === '--prod-base') {
      args.prodBase = argv[i + 1] ?? args.prodBase;
      i += 1;
      continue;
    }
    if (arg === '--stage-admin-key') {
      args.stageAdminKey = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--prod-admin-key') {
      args.prodAdminKey = argv[i + 1] ?? '';
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
    if (arg === '--max-runs') {
      args.maxRuns = Number.parseInt(argv[i + 1] ?? String(args.maxRuns), 10);
      i += 1;
      continue;
    }
    if (arg === '--rounds') {
      args.rounds = Number.parseInt(argv[i + 1] ?? String(args.rounds), 10);
      i += 1;
      continue;
    }
    if (arg === '--interval-seconds') {
      args.intervalSeconds = Number.parseInt(argv[i + 1] ?? String(args.intervalSeconds), 10);
      i += 1;
      continue;
    }
    if (arg === '--min-analyzed-runs') {
      args.minAnalyzedRuns = Number.parseInt(argv[i + 1] ?? String(args.minAnalyzedRuns), 10);
      i += 1;
      continue;
    }
    if (arg === '--expected-leader') {
      args.expectedLeader = argv[i + 1] ?? args.expectedLeader;
      i += 1;
      continue;
    }
    if (arg === '--required-contenders') {
      const raw = argv[i + 1] ?? '';
      args.requiredContenders = raw
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
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

  if (!Number.isFinite(args.maxRuns) || args.maxRuns <= 0) {
    throw new Error('--max-runs must be a positive integer');
  }
  if (!Number.isFinite(args.rounds) || args.rounds <= 0) {
    throw new Error('--rounds must be a positive integer');
  }
  if (!Number.isFinite(args.intervalSeconds) || args.intervalSeconds < 0) {
    throw new Error('--interval-seconds must be >= 0');
  }
  if (!Number.isFinite(args.minAnalyzedRuns) || args.minAnalyzedRuns < 1) {
    throw new Error('--min-analyzed-runs must be >= 1');
  }

  if (!args.dryRun) {
    if (!args.stageAdminKey) throw new Error('Missing staging admin key');
    if (!args.prodAdminKey) throw new Error('Missing production admin key');
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
    `${nowLabel()}-agp-us-077-ui-duel-league-monitor`,
  );
  return path.join(root, 'summary.json');
}

function stableJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => stableJson(entry)).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function postCoach(baseUrl, adminKey, body) {
  const response = await fetch(`${baseUrl.replace(/\/$/, '')}/v1/arena/manager/coach`, {
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
    throw new Error(`coach request failed (${response.status}): ${JSON.stringify(payload)}`);
  }

  return payload;
}

function extractLeagueSnapshot(payload) {
  const recommended = payload && typeof payload === 'object' ? payload.recommended ?? null : null;
  const backups = payload && typeof payload === 'object' && Array.isArray(payload.backups) ? payload.backups : [];
  const analyzedRuns = payload && typeof payload === 'object' ? Number(payload.analyzed_runs ?? 0) : 0;
  const recommendedContenderId = recommended && typeof recommended === 'object' ? String(recommended.contender_id ?? '') : '';

  const contenders = [];
  if (recommended && typeof recommended === 'object') contenders.push(recommended);
  for (const entry of backups) {
    if (!entry || typeof entry !== 'object') continue;
    const contenderId = String(entry.contender_id ?? '').trim();
    if (!contenderId) continue;
    if (contenders.some((row) => String(row.contender_id ?? '') === contenderId)) continue;
    contenders.push(entry);
  }

  return {
    analyzed_runs: Number.isFinite(analyzedRuns) ? analyzedRuns : 0,
    recommended_contender_id: recommendedContenderId || null,
    reason_codes: recommended && typeof recommended === 'object' && Array.isArray(recommended.reason_codes)
      ? recommended.reason_codes.map((entry) => String(entry))
      : [],
    contenders: contenders.map((entry) => {
      const evidence = entry && typeof entry === 'object' && entry.evidence && typeof entry.evidence === 'object'
        ? entry.evidence
        : null;

      const appearances = Number(entry.appearances ?? evidence?.appearances ?? 0);
      const wins = Number(entry.wins ?? evidence?.wins ?? 0);
      const winRate = Number(entry.win_rate ?? evidence?.win_rate ?? (appearances > 0 ? wins / appearances : 0));
      const avgScore = Number(entry.avg_score ?? evidence?.avg_score ?? 0);
      const hardGatePassRate = Number(entry.hard_gate_pass_rate ?? evidence?.hard_gate_pass_rate ?? 0);

      return {
        contender_id: String(entry.contender_id ?? ''),
        wins,
        appearances,
        win_rate: winRate,
        avg_score: avgScore,
        hard_gate_pass_rate: hardGatePassRate,
      };
    }),
  };
}

function evaluateEnvironment(snapshot, args) {
  const reasonCodes = [];
  if (snapshot.analyzed_runs < args.minAnalyzedRuns) {
    reasonCodes.push('ARENA_UI_DUEL_LEAGUE_INSUFFICIENT_RUNS');
  }
  if (args.expectedLeader && snapshot.recommended_contender_id !== args.expectedLeader) {
    reasonCodes.push('ARENA_UI_DUEL_LEAGUE_LEADER_DRIFT');
  }

  const contenderIds = new Set(snapshot.contenders.map((entry) => entry.contender_id));
  const missing = args.requiredContenders.filter((entry) => !contenderIds.has(entry));
  if (missing.length > 0) {
    reasonCodes.push('ARENA_UI_DUEL_LEAGUE_MISSING_CONTENDER');
  }

  if (reasonCodes.length === 0) reasonCodes.push('ARENA_UI_DUEL_LEAGUE_HEALTHY');

  return {
    ok: reasonCodes.length === 1 && reasonCodes[0] === 'ARENA_UI_DUEL_LEAGUE_HEALTHY',
    reason_codes: reasonCodes,
    missing_contenders: missing,
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const coachBody = {
    task_fingerprint: args.taskFingerprint,
    objective_profile_name: args.objectiveProfileName,
    environment: 'staging',
    max_runs: args.maxRuns,
    require_hard_gate_pass: false,
    allow_fallback: true,
    use_active_policy: true,
  };

  if (args.dryRun) {
    const preview = {
      ok: true,
      story: 'AGP-US-077',
      dry_run: true,
      generated_at: new Date().toISOString(),
      rounds: args.rounds,
      interval_seconds: args.intervalSeconds,
      coach_body: coachBody,
      expected_leader: args.expectedLeader,
      required_contenders: args.requiredContenders,
      endpoints: {
        staging: `${args.stageBase.replace(/\/$/, '')}/v1/arena/manager/coach`,
        production: `${args.prodBase.replace(/\/$/, '')}/v1/arena/manager/coach`,
      },
    };

    const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
    mkdirSync(path.dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, `${JSON.stringify(preview, null, 2)}\n`);

    process.stdout.write(`ARENA_UI_DUEL_LEAGUE_MONITOR_RESULT ${outputPath}\n`);
    process.stdout.write(`${JSON.stringify({ dry_run: true })}\n`);
    return;
  }

  const rounds = [];
  for (let round = 1; round <= args.rounds; round += 1) {
    const stagePayload = await postCoach(args.stageBase, args.stageAdminKey, { ...coachBody, environment: 'staging' });
    const prodPayload = await postCoach(args.prodBase, args.prodAdminKey, { ...coachBody, environment: 'production' });

    rounds.push({
      round,
      captured_at: new Date().toISOString(),
      staging: extractLeagueSnapshot(stagePayload),
      production: extractLeagueSnapshot(prodPayload),
    });

    if (round < args.rounds && args.intervalSeconds > 0) {
      await sleep(args.intervalSeconds * 1000);
    }
  }

  const latest = rounds[rounds.length - 1] ?? null;
  const stageEval = latest ? evaluateEnvironment(latest.staging, args) : { ok: false, reason_codes: ['ARENA_UI_DUEL_LEAGUE_EMPTY'], missing_contenders: [] };
  const prodEval = latest ? evaluateEnvironment(latest.production, args) : { ok: false, reason_codes: ['ARENA_UI_DUEL_LEAGUE_EMPTY'], missing_contenders: [] };

  const ok = stageEval.ok && prodEval.ok;

  const summary = {
    ok,
    story: 'AGP-US-077',
    generated_at: new Date().toISOString(),
    task_fingerprint: args.taskFingerprint,
    objective_profile_name: args.objectiveProfileName,
    rounds: args.rounds,
    interval_seconds: args.intervalSeconds,
    expected_leader: args.expectedLeader,
    required_contenders: args.requiredContenders,
    latest,
    health: {
      staging: stageEval,
      production: prodEval,
    },
    snapshots: rounds,
  };

  const outputPath = args.outputPath ? path.resolve(args.outputPath) : defaultOutputPath();
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`ARENA_UI_DUEL_LEAGUE_MONITOR_RESULT ${outputPath}\n`);
  process.stdout.write(`${JSON.stringify({
    ok,
    rounds: rounds.length,
    stage_reason_codes: stageEval.reason_codes,
    prod_reason_codes: prodEval.reason_codes,
    stage_leader: latest?.staging?.recommended_contender_id ?? null,
    prod_leader: latest?.production?.recommended_contender_id ?? null,
  })}\n`);

  if (args.enforce && !ok) {
    throw new Error('UI duel league monitor failed health checks');
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
