#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { computeMaintainabilityScore, computeUiDuelScores } from './lib/ui-duel-score.mjs';

function parseArgs(argv) {
  const args = {
    baseUrl: 'https://staging.clawbounties.com',
    uiPath: '/duel',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    contenderId: '',
    contractPath: path.join(process.cwd(), 'contracts', 'arena', 'bounty-ui-duel.clawbounties.v1.json'),
    workerDid: 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    bountyId: null,
    outDir: null,
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--base-url') {
      args.baseUrl = argv[i + 1] ?? args.baseUrl;
      i += 1;
      continue;
    }
    if (arg === '--ui-path') {
      args.uiPath = argv[i + 1] ?? args.uiPath;
      i += 1;
      continue;
    }
    if (arg === '--admin-key') {
      args.adminKey = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--contender-id') {
      args.contenderId = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--contract') {
      args.contractPath = argv[i + 1] ?? args.contractPath;
      i += 1;
      continue;
    }
    if (arg === '--worker-did') {
      args.workerDid = argv[i + 1] ?? args.workerDid;
      i += 1;
      continue;
    }
    if (arg === '--bounty-id') {
      args.bountyId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--out-dir') {
      args.outDir = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
  }

  if (!args.contenderId) {
    throw new Error('Missing contender id. Pass --contender-id.');
  }
  if (!args.dryRun && !args.adminKey) {
    throw new Error('Missing admin key. Pass --admin-key or set BOUNTIES_ADMIN_KEY.');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function defaultOutDir(contenderId) {
  return path.join(
    process.cwd(),
    'artifacts',
    'ops',
    'arena-productization',
    `${nowLabel()}-agp-us-070-ui-duel-evaluator`,
    contenderId,
  );
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

function toRelative(filePath) {
  return path.relative(process.cwd(), filePath) || filePath;
}

function loadContract(contractPath) {
  const raw = readJson(contractPath);
  const weighted = Array.isArray(raw?.objective_profile?.weighted_rubric)
    ? raw.objective_profile.weighted_rubric
    : [];

  const weights = {
    ux_task_success_friction: 35,
    visual_quality_consistency: 20,
    performance: 20,
    accessibility: 15,
    implementation_maintainability: 10,
  };

  for (const item of weighted) {
    if (!item || typeof item !== 'object') continue;
    const id = typeof item.id === 'string' ? item.id.trim() : '';
    const weight = Number(item.weight_percent ?? 0);
    if (!Number.isFinite(weight)) continue;

    if (id === 'ux_task_success_friction') weights.ux_task_success_friction = weight;
    if (id === 'visual_quality_consistency') weights.visual_quality_consistency = weight;
    if (id === 'performance') weights.performance = weight;
    if (id === 'accessibility') weights.accessibility = weight;
    if (id === 'implementation_maintainability') weights.implementation_maintainability = weight;
  }

  return {
    raw,
    weights,
  };
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    stdio: 'pipe',
  });

  if (result.status !== 0) {
    const err = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
    throw new Error(`${command} failed (${result.status}): ${err}`);
  }

  return result.stdout;
}

function ensureHarnessDependencies(harnessDir) {
  const marker = path.join(harnessDir, 'node_modules', '@playwright', 'test');
  if (existsSync(marker)) return;
  run('npm', ['install', '--no-fund', '--no-audit'], harnessDir);
}

function extractMaintainabilitySignals(htmlText) {
  const scripts = [...htmlText.matchAll(/<script[\s\S]*?>[\s\S]*?<\/script>/gi)].map((m) => m[0]);
  const styleBlocks = [...htmlText.matchAll(/<style[\s\S]*?>[\s\S]*?<\/style>/gi)].length;
  const inlineScriptLines = scripts.reduce((sum, block) => sum + block.split(/\r?\n/).length, 0);

  return {
    source_bytes: Buffer.byteLength(htmlText, 'utf8'),
    inline_script_lines: inlineScriptLines,
    inline_style_blocks: styleBlocks,
    dom_node_count: (htmlText.match(/<([a-z][a-z0-9-]*)\b/gi) ?? []).length,
    eval_occurrences: (htmlText.match(/\beval\s*\(/g) ?? []).length,
  };
}

async function fetchUiSource(url) {
  const response = await fetch(url, { headers: { 'cache-control': 'no-cache' } });
  const text = await response.text();

  if (!response.ok) {
    throw new Error(`UI fetch failed (${response.status})`);
  }

  return {
    status: response.status,
    source: text,
  };
}

function buildReviewPaste(input) {
  const gates = input.scores.hard_gates;
  const weighted = input.scores.weighted_scores;

  return [
    `# UI Duel Review — ${input.contenderId}`,
    '',
    `- Contract: ${input.contractId}`,
    `- UI Route: ${input.uiUrl}`,
    `- Final score: ${input.scores.final_score}`,
    `- Hard gate pass: ${input.scores.hard_gate_passed ? 'PASS' : 'FAIL'}`,
    '',
    '## Hard gates',
    `- core_flows_pass: ${gates.core_flows_pass ? 'PASS' : 'FAIL'}`,
    `- no_critical_runtime_errors: ${gates.no_critical_runtime_errors ? 'PASS' : 'FAIL'}`,
    `- no_critical_accessibility_violations: ${gates.no_critical_accessibility_violations ? 'PASS' : 'FAIL'}`,
    '',
    '## Weighted breakdown',
    `- UX task success/friction: ${weighted.ux_task_success_friction}`,
    `- Visual quality consistency: ${weighted.visual_quality_consistency}`,
    `- Performance: ${weighted.performance}`,
    `- Accessibility: ${weighted.accessibility}`,
    `- Maintainability: ${weighted.implementation_maintainability}`,
    '',
    '## Evidence links',
    ...input.evidenceLinks.map((entry) => `- ${entry.label}: ${entry.path}`),
    '',
    '## Reason codes',
    ...(input.scores.reason_codes.length > 0 ? input.scores.reason_codes.map((code) => `- ${code}`) : ['- ARENA_UI_DUEL_HARD_GATES_PASS']),
    '',
  ].join('\n');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const contractPath = path.resolve(args.contractPath);
  const contract = loadContract(contractPath);
  const outDir = args.outDir ? path.resolve(args.outDir) : defaultOutDir(args.contenderId);
  const uiUrl = `${args.baseUrl.replace(/\/$/, '')}${args.uiPath.startsWith('/') ? args.uiPath : `/${args.uiPath}`}`;

  mkdirSync(outDir, { recursive: true });

  if (args.dryRun) {
    const drySummary = {
      ok: true,
      dry_run: true,
      contender_id: args.contenderId,
      contract_id: contract.raw?.contract_id ?? null,
      ui_url: uiUrl,
      weights: contract.weights,
      preview: {
        harness_dir: 'scripts/arena/ui-duel-harness',
        expected_outputs: ['journey.json', 'axe-results.json', 'lighthouse.summary.json', 'summary.json'],
      },
    };

    const outputPath = path.join(outDir, 'summary.json');
    writeFileSync(outputPath, `${JSON.stringify(drySummary, null, 2)}\n`);
    process.stdout.write(`ARENA_UI_DUEL_EVAL_RESULT ${outputPath}\n`);
    process.stdout.write(`${JSON.stringify({ dry_run: true }, null, 2)}\n`);
    return;
  }

  const harnessDir = path.join(process.cwd(), 'scripts', 'arena', 'ui-duel-harness');
  ensureHarnessDependencies(harnessDir);

  const journeyOutDir = path.join(outDir, 'journey');
  mkdirSync(journeyOutDir, { recursive: true });

  const journeyArgs = [
    path.join(harnessDir, 'journey.mjs'),
    '--base-url', args.baseUrl,
    '--ui-path', args.uiPath,
    '--admin-key', args.adminKey,
    '--worker-did', args.workerDid,
    '--output-dir', journeyOutDir,
  ];

  if (args.bountyId) {
    journeyArgs.push('--bounty-id', args.bountyId);
  }

  run('node', journeyArgs, process.cwd());

  const journeyPath = path.join(journeyOutDir, 'journey.json');
  const journey = readJson(journeyPath);

  const lighthouseOutDir = path.join(outDir, 'lighthouse');
  mkdirSync(lighthouseOutDir, { recursive: true });
  run('node', [
    path.join(harnessDir, 'lighthouse-check.mjs'),
    '--url', uiUrl,
    '--output-dir', lighthouseOutDir,
  ], process.cwd());

  const lighthouseSummaryPath = path.join(lighthouseOutDir, 'lighthouse.summary.json');
  const lighthouseSummary = readJson(lighthouseSummaryPath);

  const uiFetch = await fetchUiSource(uiUrl);
  const maintainabilitySignals = extractMaintainabilitySignals(uiFetch.source);
  const maintainabilityScore = computeMaintainabilityScore(maintainabilitySignals);

  const scores = computeUiDuelScores({
    journey,
    lighthouse: lighthouseSummary,
    maintainability: {
      ...maintainabilitySignals,
      inferred_score: maintainabilityScore,
    },
    weights: contract.weights,
  });

  const evidenceLinks = [
    { label: 'journey', path: toRelative(journeyPath) },
    { label: 'axe_raw', path: toRelative(path.join(journeyOutDir, 'axe-results.json')) },
    { label: 'lighthouse_summary', path: toRelative(lighthouseSummaryPath) },
    { label: 'lighthouse_raw', path: toRelative(path.join(lighthouseOutDir, 'lighthouse.raw.json')) },
    { label: 'browse_screenshot', path: toRelative(path.join(journeyOutDir, 'screenshots', '01-browse.png')) },
    { label: 'details_screenshot', path: toRelative(path.join(journeyOutDir, 'screenshots', '02-details.png')) },
    { label: 'claim_screenshot', path: toRelative(path.join(journeyOutDir, 'screenshots', '03-claim.png')) },
    { label: 'submit_screenshot', path: toRelative(path.join(journeyOutDir, 'screenshots', '04-submit.png')) },
    { label: 'journey_video', path: toRelative(path.join(journeyOutDir, 'videos')) },
  ];

  const summary = {
    ok: true,
    dry_run: false,
    schema_version: 'arena_ui_duel_evaluator.v1',
    generated_at: new Date().toISOString(),
    contender_id: args.contenderId,
    contract_id: contract.raw?.contract_id ?? null,
    task_fingerprint: contract.raw?.task_fingerprint ?? null,
    ui_url: uiUrl,
    hard_gates: scores.hard_gates,
    hard_gate_passed: scores.hard_gate_passed,
    weighted_scores: scores.weighted_scores,
    weighted_total: scores.weighted_total,
    final_score: scores.final_score,
    reason_codes: scores.reason_codes,
    diagnostics: {
      ...scores.diagnostics,
      maintainability_signals: maintainabilitySignals,
      maintainability_inferred_score: maintainabilityScore,
      ui_http_status: uiFetch.status,
    },
    artifacts: {
      journey: toRelative(journeyPath),
      lighthouse_summary: toRelative(lighthouseSummaryPath),
      output_dir: toRelative(outDir),
      evidence_links: evidenceLinks,
    },
  };

  const summaryPath = path.join(outDir, 'summary.json');
  writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);

  const managerReview = {
    schema_version: 'arena_manager_review.v1',
    contender_id: args.contenderId,
    recommendation: scores.hard_gate_passed ? 'APPROVE' : 'REJECT',
    confidence: Number((scores.final_score / 100).toFixed(4)),
    reason_codes: scores.reason_codes.length > 0 ? scores.reason_codes : ['ARENA_UI_DUEL_HARD_GATES_PASS'],
    score: {
      final: scores.final_score,
      weighted_total: scores.weighted_total,
      weighted_breakdown: scores.weighted_scores,
    },
    hard_gates: scores.hard_gates,
    evidence_links: evidenceLinks,
    reviewed_at: new Date().toISOString(),
  };

  const managerReviewPath = path.join(outDir, 'manager-review.json');
  writeFileSync(managerReviewPath, `${JSON.stringify(managerReview, null, 2)}\n`);

  const proofPack = {
    schema_version: 'arena_ui_duel_proof_pack.v1',
    contender_id: args.contenderId,
    contract_id: contract.raw?.contract_id ?? null,
    task_fingerprint: contract.raw?.task_fingerprint ?? null,
    generated_at: new Date().toISOString(),
    final_score: scores.final_score,
    hard_gates: scores.hard_gates,
    weighted_scores: scores.weighted_scores,
    reason_codes: scores.reason_codes,
    evidence_links: evidenceLinks,
  };

  const proofPackPath = path.join(outDir, 'proof-pack.v3.json');
  writeFileSync(proofPackPath, `${JSON.stringify(proofPack, null, 2)}\n`);

  const reviewPastePath = path.join(outDir, 'review-paste.md');
  writeFileSync(
    reviewPastePath,
    `${buildReviewPaste({
      contenderId: args.contenderId,
      contractId: contract.raw?.contract_id ?? null,
      uiUrl,
      scores,
      evidenceLinks,
    })}\n`,
  );

  process.stdout.write(`ARENA_UI_DUEL_EVAL_RESULT ${summaryPath}\n`);
  process.stdout.write(
    `${JSON.stringify(
      {
        contender_id: args.contenderId,
        final_score: scores.final_score,
        hard_gate_passed: scores.hard_gate_passed,
        reason_codes: scores.reason_codes,
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
