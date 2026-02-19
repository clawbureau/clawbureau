#!/usr/bin/env node

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { stableJson } from './lib/proof-pack-v3.mjs';

const DEFAULT_OUTPUT_ROOT = 'artifacts/arena';
const DEFAULT_DISPATCH_RETRIES = 1;
const DEFAULT_DISPATCH_TIMEOUT_MS = 15 * 60 * 1000;

function parseArgs(argv) {
  const args = {
    bountyId: null,
    contractPath: null,
    contendersPath: null,
    dispatchConfigPath: null,
    outputRoot: DEFAULT_OUTPUT_ROOT,
    arenaId: null,
    generatedAt: null,
    bountiesBase: 'https://staging.clawbounties.com',
    adminKey: process.env.BOUNTIES_ADMIN_KEY ?? '',
    startIdempotencyKey: null,
    resultIdempotencyKey: null,
    registryPath: null,
    objectiveProfileName: null,
    experimentId: null,
    experimentArm: null,
    prNumber: null,
    postBountyThread: true,
    arenaBaseUrl: '',
    artifactsBaseUrl: '',
    decisionSource: 'arena-launcher',
    dryRun: false,
    dispatchRetries: DEFAULT_DISPATCH_RETRIES,
    dispatchTimeoutMs: DEFAULT_DISPATCH_TIMEOUT_MS,
    gitBaseRef: 'origin/main',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--bounty-id') {
      args.bountyId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--contract') {
      args.contractPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--contenders') {
      args.contendersPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--dispatch-config') {
      args.dispatchConfigPath = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? DEFAULT_OUTPUT_ROOT;
      i += 1;
      continue;
    }
    if (arg === '--arena-id') {
      args.arenaId = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--generated-at') {
      args.generatedAt = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
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
    if (arg === '--start-idempotency-key') {
      args.startIdempotencyKey = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--result-idempotency-key') {
      args.resultIdempotencyKey = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--registry') {
      args.registryPath = argv[i + 1] ?? null;
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
    if (arg === '--pr-number' || arg === '--post-pr-number') {
      args.prNumber = argv[i + 1] ?? null;
      i += 1;
      continue;
    }
    if (arg === '--post-bounty-thread') {
      args.postBountyThread = true;
      continue;
    }
    if (arg === '--no-post-bounty-thread' || arg === '--skip-bounty-thread') {
      args.postBountyThread = false;
      continue;
    }
    if (arg === '--arena-base-url') {
      args.arenaBaseUrl = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--artifacts-base-url') {
      args.artifactsBaseUrl = argv[i + 1] ?? '';
      i += 1;
      continue;
    }
    if (arg === '--decision-source') {
      args.decisionSource = argv[i + 1] ?? 'arena-launcher';
      i += 1;
      continue;
    }
    if (arg === '--dispatch-retries') {
      args.dispatchRetries = Number.parseInt(argv[i + 1] ?? String(DEFAULT_DISPATCH_RETRIES), 10);
      i += 1;
      continue;
    }
    if (arg === '--dispatch-timeout-ms') {
      args.dispatchTimeoutMs = Number.parseInt(argv[i + 1] ?? String(DEFAULT_DISPATCH_TIMEOUT_MS), 10);
      i += 1;
      continue;
    }
    if (arg === '--git-base-ref') {
      args.gitBaseRef = argv[i + 1] ?? 'origin/main';
      i += 1;
      continue;
    }
    if (arg === '--dry-run') {
      args.dryRun = true;
      continue;
    }
  }

  if (!args.bountyId || !args.contractPath || !args.contendersPath || !args.dispatchConfigPath) {
    throw new Error(
      'Usage: node scripts/arena/run-real-contender-dispatch.mjs --bounty-id <bty_...> --contract <json> --contenders <json> --dispatch-config <json> [--registry <json>] [--experiment-id <id>] [--experiment-arm <arm>] [--bounties-base <url>] [--admin-key <key>] [--dry-run]'
    );
  }

  if (!Number.isFinite(args.dispatchRetries) || args.dispatchRetries < 0) {
    throw new Error('--dispatch-retries must be >= 0');
  }

  if (!Number.isFinite(args.dispatchTimeoutMs) || args.dispatchTimeoutMs <= 0) {
    throw new Error('--dispatch-timeout-ms must be > 0');
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function loadJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

function normalizeCategory(value, id) {
  if (typeof value === 'string' && value.trim()) {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'typecheck' || normalized === 'lint' || normalized === 'test' || normalized === 'aux') {
      return normalized;
    }
  }

  const fallback = String(id ?? '').toLowerCase();
  if (fallback.includes('typecheck')) return 'typecheck';
  if (fallback.includes('lint')) return 'lint';
  if (fallback.includes('test')) return 'test';
  return 'aux';
}

function safeFileSegment(value, fallback = 'entry') {
  const normalized = String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');

  return normalized || fallback;
}

function relativePath(filePath) {
  return path.relative(process.cwd(), filePath);
}

function runShellCommand(command, timeoutMs) {
  const started = Date.now();
  const proc = spawnSync('bash', ['-lc', command], {
    encoding: 'utf8',
    timeout: timeoutMs,
    maxBuffer: 10 * 1024 * 1024,
  });
  const duration = Date.now() - started;

  const timedOut = proc.signal === 'SIGTERM' && proc.error && String(proc.error.message || '').toLowerCase().includes('timed out');
  const exitCode = typeof proc.status === 'number' ? proc.status : (timedOut ? 124 : 1);

  return {
    command,
    exit_code: exitCode,
    success: exitCode === 0,
    signal: proc.signal ?? null,
    duration_ms: duration,
    stdout: proc.stdout ?? '',
    stderr: proc.stderr ?? '',
  };
}

function parseTestCounts(text) {
  const value = String(text ?? '');
  let passed = 0;
  let failed = 0;
  let detected = false;

  const patterns = [
    /Tests\s+(\d+)\s+passed[^\n]*/gi,
    /\bpass\s+(\d+)\b/gi,
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(value)) !== null) {
      const n = Number.parseInt(match[1] ?? '', 10);
      if (Number.isFinite(n) && n >= 0) {
        passed += n;
        detected = true;
      }
    }
  }

  const failPatterns = [
    /\bfail\s+(\d+)\b/gi,
    /(\d+)\s+failed/gi,
  ];

  for (const pattern of failPatterns) {
    let match;
    while ((match = pattern.exec(value)) !== null) {
      const n = Number.parseInt(match[1] ?? '', 10);
      if (Number.isFinite(n) && n >= 0) {
        failed += n;
        detected = true;
      }
    }
  }

  return { passed, failed, detected };
}

function parseDiffStats(diffText) {
  const lines = String(diffText ?? '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  let filesChanged = 0;
  let linesAdded = 0;
  let linesDeleted = 0;
  const hotspots = [];

  for (const line of lines) {
    const parts = line.split(/\t+/);
    if (parts.length < 3) continue;

    const addedRaw = parts[0];
    const deletedRaw = parts[1];
    const file = parts.slice(2).join('\t');

    const added = Number.parseInt(addedRaw, 10);
    const deleted = Number.parseInt(deletedRaw, 10);

    const safeAdded = Number.isFinite(added) ? Math.max(0, added) : 0;
    const safeDeleted = Number.isFinite(deleted) ? Math.max(0, deleted) : 0;

    filesChanged += 1;
    linesAdded += safeAdded;
    linesDeleted += safeDeleted;
    hotspots.push({ file, churn: safeAdded + safeDeleted });
  }

  hotspots.sort((a, b) => b.churn - a.churn || a.file.localeCompare(b.file));

  return {
    files_changed: filesChanged,
    lines_added: linesAdded,
    lines_deleted: linesDeleted,
    churn_hotspots: hotspots.slice(0, 5).map((row) => row.file),
  };
}

function loadDispatchConfig(filePath, defaultRetries, defaultTimeoutMs) {
  const input = loadJson(filePath);
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('dispatch config must be an object');
  }

  const contendersRaw = Array.isArray(input.contenders) ? input.contenders : null;
  if (!contendersRaw || contendersRaw.length === 0) {
    throw new Error('dispatch config must include contenders[]');
  }

  const defaultsRaw = input.defaults && typeof input.defaults === 'object' && !Array.isArray(input.defaults)
    ? input.defaults
    : {};

  const defaults = {
    max_retries: Number.isFinite(Number(defaultsRaw.max_retries))
      ? Math.max(0, Math.trunc(Number(defaultsRaw.max_retries)))
      : defaultRetries,
    timeout_ms: Number.isFinite(Number(defaultsRaw.timeout_ms))
      ? Math.max(1, Math.trunc(Number(defaultsRaw.timeout_ms)))
      : defaultTimeoutMs,
  };

  const contenderMap = new Map();

  for (const contenderRaw of contendersRaw) {
    if (!contenderRaw || typeof contenderRaw !== 'object' || Array.isArray(contenderRaw)) {
      throw new Error('dispatch contender entry must be an object');
    }

    const contenderId = typeof contenderRaw.contender_id === 'string'
      ? contenderRaw.contender_id.trim()
      : '';

    if (!contenderId) {
      throw new Error('dispatch contender entry missing contender_id');
    }

    const commandsRaw = Array.isArray(contenderRaw.commands) ? contenderRaw.commands : null;
    if (!commandsRaw || commandsRaw.length === 0) {
      throw new Error(`dispatch contender ${contenderId} missing commands[]`);
    }

    const commands = commandsRaw.map((commandRaw, index) => {
      if (!commandRaw || typeof commandRaw !== 'object' || Array.isArray(commandRaw)) {
        throw new Error(`dispatch command for ${contenderId} must be an object`);
      }

      const id = typeof commandRaw.id === 'string' && commandRaw.id.trim()
        ? commandRaw.id.trim()
        : `cmd_${index + 1}`;

      const run = typeof commandRaw.run === 'string' ? commandRaw.run.trim() : '';
      if (!run) {
        throw new Error(`dispatch command ${id} for ${contenderId} missing run`);
      }

      const retries = Number.isFinite(Number(commandRaw.retries))
        ? Math.max(0, Math.trunc(Number(commandRaw.retries)))
        : defaults.max_retries;

      const timeoutMs = Number.isFinite(Number(commandRaw.timeout_ms))
        ? Math.max(1, Math.trunc(Number(commandRaw.timeout_ms)))
        : defaults.timeout_ms;

      const category = normalizeCategory(commandRaw.category, id);

      return {
        id,
        run,
        retries,
        timeout_ms: timeoutMs,
        category,
      };
    });

    const hasTypecheck = commands.some((row) => row.category === 'typecheck');
    const hasTest = commands.some((row) => row.category === 'test');
    if (!hasTypecheck || !hasTest) {
      throw new Error(`dispatch contender ${contenderId} must include at least one typecheck and one test command (fail-closed evidence requirement)`);
    }

    contenderMap.set(contenderId, {
      contender_id: contenderId,
      commands,
    });
  }

  return {
    schema_version: typeof input.schema_version === 'string' ? input.schema_version : 'arena_real_dispatch.v1',
    defaults,
    contenders: contenderMap,
  };
}

function buildGitDiffArtifact(baseRef, contenderDir) {
  const fallbackCommand = 'git diff --numstat HEAD~1..HEAD';
  const primaryCommand = `git diff --numstat --no-renames ${baseRef}...HEAD`;

  let proc = runShellCommand(primaryCommand, 60_000);
  if (proc.exit_code !== 0) {
    proc = runShellCommand(fallbackCommand, 60_000);
  }

  const diffPath = path.join(contenderDir, 'git-diff.numstat.txt');
  writeFileSync(
    diffPath,
    [
      `# command: ${proc.command}`,
      `# exit_code: ${proc.exit_code}`,
      '',
      proc.stdout,
      proc.stderr ? `\n# stderr\n${proc.stderr}` : '',
    ].join('\n').trimEnd() + '\n'
  );

  const stats = parseDiffStats(proc.stdout);

  return {
    stats,
    artifact_path: relativePath(diffPath),
  };
}

function buildDeliverySummary(contenderId, typecheckPassed, lintPassed, testPassed, testFailed) {
  return [
    `Real contender dispatch executed for ${contenderId} with contract binding checks and deterministic reason code trace capture.`,
    `Live test evidence recorded from command execution: tests_passed=${testPassed}, tests_failed=${testFailed}.`,
    `Static checks: typecheck=${typecheckPassed ? 'pass' : 'fail'}, lint=${lintPassed ? 'pass' : 'fail'}.`,
  ].join(' ');
}

function runContenderDispatch({ contender, spec, outputRoot, gitBaseRef }) {
  const contenderDir = path.join(outputRoot, safeFileSegment(contender.contender_id, 'contender'));
  mkdirSync(contenderDir, { recursive: true });

  const commandSummaries = [];
  let totalLatency = 0;
  let totalAttempts = 0;

  for (const command of spec.commands) {
    const attempts = [];
    let finalAttempt = null;

    for (let attemptIndex = 0; attemptIndex <= command.retries; attemptIndex += 1) {
      const result = runShellCommand(command.run, command.timeout_ms);
      attempts.push(result);
      finalAttempt = result;
      totalLatency += result.duration_ms;
      totalAttempts += 1;

      const logPath = path.join(
        contenderDir,
        `${safeFileSegment(command.id, 'cmd')}.attempt-${attemptIndex + 1}.log`
      );

      writeFileSync(
        logPath,
        [
          `# contender_id: ${contender.contender_id}`,
          `# command_id: ${command.id}`,
          `# category: ${command.category}`,
          `# attempt: ${attemptIndex + 1}/${command.retries + 1}`,
          `# run: ${command.run}`,
          `# exit_code: ${result.exit_code}`,
          `# signal: ${result.signal ?? ''}`,
          `# duration_ms: ${result.duration_ms}`,
          '',
          '# stdout',
          result.stdout,
          '',
          '# stderr',
          result.stderr,
        ].join('\n').trimEnd() + '\n'
      );

      if (result.success) {
        break;
      }
    }

    commandSummaries.push({
      id: command.id,
      category: command.category,
      run: command.run,
      retries_allowed: command.retries,
      attempts: attempts.map((attempt) => ({
        exit_code: attempt.exit_code,
        signal: attempt.signal,
        duration_ms: attempt.duration_ms,
      })),
      final_exit_code: finalAttempt?.exit_code ?? 1,
      success: finalAttempt?.success === true,
      log_path: relativePath(path.join(contenderDir, `${safeFileSegment(command.id, 'cmd')}.attempt-${attempts.length}.log`)),
      stdout: finalAttempt?.stdout ?? '',
      stderr: finalAttempt?.stderr ?? '',
    });
  }

  const typecheckCommands = commandSummaries.filter((row) => row.category === 'typecheck');
  const lintCommands = commandSummaries.filter((row) => row.category === 'lint');
  const testCommands = commandSummaries.filter((row) => row.category === 'test');

  const typecheckPassed = typecheckCommands.every((row) => row.success);
  const lintPassed = lintCommands.length > 0 ? lintCommands.every((row) => row.success) : true;

  let testsPassed = 0;
  let testsFailed = 0;

  for (const row of testCommands) {
    const parsed = parseTestCounts(`${row.stdout}\n${row.stderr}`);
    if (parsed.detected) {
      testsPassed += parsed.passed;
      testsFailed += parsed.failed;
      continue;
    }

    testsPassed += row.success ? 1 : 0;
    testsFailed += row.success ? 0 : 1;
  }

  const retries = totalAttempts - commandSummaries.length;
  const toolCalls = totalAttempts;
  const manualInterventions = 0;

  const gitDiff = buildGitDiffArtifact(gitBaseRef, contenderDir);

  const executionSummary = {
    contender_id: contender.contender_id,
    generated_at: new Date().toISOString(),
    dispatch_runtime: {
      latency_ms: totalLatency,
      tool_calls: toolCalls,
      retries,
      manual_interventions: manualInterventions,
    },
    commands: commandSummaries.map((row) => ({
      id: row.id,
      category: row.category,
      run: row.run,
      retries_allowed: row.retries_allowed,
      success: row.success,
      final_exit_code: row.final_exit_code,
      attempts: row.attempts,
      log_path: row.log_path,
    })),
  };

  const executionSummaryPath = path.join(contenderDir, 'dispatch-summary.json');
  writeFileSync(executionSummaryPath, `${stableJson(executionSummary)}\n`);

  const costUsd = Number(((totalLatency / 1000) * 0.0008 + toolCalls * 0.0015 + retries * 0.0025 + 0.01).toFixed(4));
  const costSummary = {
    contender_id: contender.contender_id,
    computed_at: new Date().toISOString(),
    model: contender.model,
    harness: contender.harness,
    estimate_formula: 'latency_seconds*0.0008 + tool_calls*0.0015 + retries*0.0025 + 0.01',
    latency_ms: totalLatency,
    tool_calls: toolCalls,
    retries,
    estimated_usd: costUsd,
  };

  const costSummaryPath = path.join(contenderDir, 'dispatch-cost-estimate.json');
  writeFileSync(costSummaryPath, `${stableJson(costSummary)}\n`);

  const failedCommandIds = commandSummaries.filter((row) => !row.success).map((row) => row.id);

  const bottlenecks = failedCommandIds.length > 0
    ? failedCommandIds.map((id) => `command_failed:${id}`)
    : ['dispatch completed without command failures'];

  const contractImprovements = failedCommandIds.length > 0
    ? ['tighten acceptance criteria to include mandatory recovery steps for failed command paths']
    : ['encode successful dispatch checklist as explicit acceptance criteria'];

  const nextDelegationHints = failedCommandIds.length > 0
    ? ['route through reviewer checkpoint before acceptance due to command failures']
    : ['eligible for autonomous routing when calibration remains stable'];

  const dispatchRecord = {
    contender_id: contender.contender_id,
    typecheck_passed: typecheckPassed,
    lint_passed: lintPassed,
    tests_passed: testsPassed,
    tests_failed: testsFailed,
    latency_ms: totalLatency,
    tool_calls: toolCalls,
    retries,
    manual_interventions: manualInterventions,
    failed_command_ids: failedCommandIds,
    dispatch_summary_path: relativePath(executionSummaryPath),
    cost_summary_path: relativePath(costSummaryPath),
    git_diff_path: gitDiff.artifact_path,
    command_results: commandSummaries.map((row) => ({
      id: row.id,
      category: row.category,
      success: row.success,
      final_exit_code: row.final_exit_code,
      attempts: row.attempts.length,
      log_path: row.log_path,
    })),
  };

  const ciArtifacts = [];
  const typecheckArtifact = typecheckCommands[0];
  if (typecheckArtifact) {
    ciArtifacts.push({
      label: `Typecheck (${contender.contender_id})`,
      url: typecheckArtifact.log_path,
    });
  }

  const testArtifact = testCommands[0];
  if (testArtifact) {
    ciArtifacts.push({
      label: `Test run (${contender.contender_id})`,
      url: testArtifact.log_path,
    });
  }

  if (ciArtifacts.length === 0) {
    throw new Error(`No CI artifacts captured for ${contender.contender_id}; fail-closed evidence requirement`);
  }

  const deliverySummary = buildDeliverySummary(
    contender.contender_id,
    typecheckPassed,
    lintPassed,
    testsPassed,
    testsFailed,
  );

  const enrichedContender = {
    ...contender,
    delivery_summary: deliverySummary,
    evidence_signals: {
      ci: {
        typecheck_passed: typecheckPassed,
        lint_passed: lintPassed,
        tests_passed: testsPassed,
        tests_failed: testsFailed,
        artifacts: ciArtifacts,
      },
      git: {
        ...gitDiff.stats,
        diff_artifact: {
          label: `Git diff (${contender.contender_id})`,
          url: gitDiff.artifact_path,
        },
      },
      execution: {
        latency_ms: totalLatency,
        tool_calls: toolCalls,
        retries,
        manual_interventions: manualInterventions,
        trace_artifact: {
          label: `Dispatch trace (${contender.contender_id})`,
          url: relativePath(executionSummaryPath),
        },
      },
      cost: {
        usd: costUsd,
        cost_artifact: {
          label: `Dispatch cost estimate (${contender.contender_id})`,
          url: relativePath(costSummaryPath),
        },
      },
    },
    evidence_links: [
      {
        label: 'Dispatch trace',
        url: relativePath(executionSummaryPath),
      },
      {
        label: 'Dispatch cost estimate',
        url: relativePath(costSummaryPath),
      },
      {
        label: 'Dispatch git diff',
        url: gitDiff.artifact_path,
      },
    ],
    bottlenecks,
    contract_improvements: contractImprovements,
    next_delegation_hints: nextDelegationHints,
  };

  return {
    contender: enrichedContender,
    dispatch: dispatchRecord,
  };
}

function runLaunchScript(args) {
  const launchScriptPath = path.resolve('scripts/arena/run-real-bounty-arena.mjs');
  const proc = spawnSync(process.execPath, [launchScriptPath, ...args], {
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  });

  if (proc.status !== 0) {
    throw new Error(`run-real-bounty-arena failed: ${proc.stderr || proc.stdout}`);
  }

  const stdout = String(proc.stdout ?? '').trim();
  if (!stdout) {
    throw new Error('run-real-bounty-arena returned empty stdout');
  }

  try {
    return JSON.parse(stdout);
  } catch {
    const lines = stdout.split(/\r?\n/).map((line) => line.trim()).filter((line) => line.length > 0);
    for (let i = lines.length - 1; i >= 0; i -= 1) {
      try {
        return JSON.parse(lines[i]);
      } catch {
        // continue
      }
    }
  }

  throw new Error('run-real-bounty-arena stdout did not contain JSON payload');
}

function buildLaunchArgs(params) {
  const out = [
    '--bounty-id', params.bountyId,
    '--contract', params.contractPath,
    '--contenders', params.contendersPath,
    '--output-root', params.outputRoot,
    '--arena-id', params.arenaId,
    '--bounties-base', params.bountiesBase,
  ];

  if (params.generatedAt) {
    out.push('--generated-at', params.generatedAt);
  }

  if (params.adminKey) {
    out.push('--admin-key', params.adminKey);
  }

  if (params.startIdempotencyKey) {
    out.push('--start-idempotency-key', params.startIdempotencyKey);
  }

  if (params.resultIdempotencyKey) {
    out.push('--result-idempotency-key', params.resultIdempotencyKey);
  }

  if (params.registryPath) {
    out.push('--registry', params.registryPath);
  }

  if (params.objectiveProfileName) {
    out.push('--objective-profile-name', params.objectiveProfileName);
  }

  if (params.experimentId) {
    out.push('--experiment-id', params.experimentId);
  }

  if (params.experimentArm) {
    out.push('--experiment-arm', params.experimentArm);
  }

  if (params.prNumber) {
    out.push('--pr-number', String(params.prNumber));
  }

  if (params.postBountyThread === false) {
    out.push('--no-post-bounty-thread');
  }

  if (params.arenaBaseUrl) {
    out.push('--arena-base-url', params.arenaBaseUrl);
  }

  if (params.artifactsBaseUrl) {
    out.push('--artifacts-base-url', params.artifactsBaseUrl);
  }

  if (params.decisionSource) {
    out.push('--decision-source', params.decisionSource);
  }

  if (params.dryRun) {
    out.push('--dry-run');
  }

  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.dryRun && (!args.adminKey || !args.adminKey.trim())) {
    throw new Error('admin key is required unless --dry-run is set (provide --admin-key or BOUNTIES_ADMIN_KEY env)');
  }

  const contenders = loadJson(args.contendersPath);
  if (!Array.isArray(contenders) || contenders.length < 2) {
    throw new Error('contenders file must include at least two contenders');
  }

  const dispatchConfig = loadDispatchConfig(
    args.dispatchConfigPath,
    args.dispatchRetries,
    args.dispatchTimeoutMs,
  );

  const arenaId = args.arenaId ?? `arena_${args.bountyId}_${nowLabel()}`;
  const outputDir = path.join(args.outputRoot, arenaId);
  const dispatchRoot = path.join(outputDir, 'dispatch');
  mkdirSync(dispatchRoot, { recursive: true });

  const enrichedContenders = [];
  const dispatchRecords = [];

  for (const contender of contenders) {
    if (!contender || typeof contender !== 'object' || Array.isArray(contender)) {
      throw new Error('contender entry must be an object');
    }

    const contenderId = typeof contender.contender_id === 'string' ? contender.contender_id.trim() : '';
    if (!contenderId) {
      throw new Error('contender entry missing contender_id');
    }

    const spec = dispatchConfig.contenders.get(contenderId);
    if (!spec) {
      throw new Error(`dispatch config missing contender ${contenderId} (fail-closed evidence requirement)`);
    }

    const dispatched = runContenderDispatch({
      contender,
      spec,
      outputRoot: dispatchRoot,
      gitBaseRef: args.gitBaseRef,
    });

    enrichedContenders.push(dispatched.contender);
    dispatchRecords.push(dispatched.dispatch);
  }

  const contendersPath = path.join(outputDir, 'real-dispatch.contenders.json');
  writeFileSync(contendersPath, `${stableJson(enrichedContenders)}\n`);

  const launchArgs = buildLaunchArgs({
    ...args,
    contendersPath,
    arenaId,
  });

  const launchSummary = runLaunchScript(launchArgs);

  const summary = {
    ok: true,
    generated_at: new Date().toISOString(),
    mode: args.dryRun ? 'dry-run' : 'live',
    story: 'AGP-US-053',
    bounty_id: args.bountyId,
    arena_id: arenaId,
    output_dir: outputDir,
    dispatch_config: {
      path: args.dispatchConfigPath,
      schema_version: dispatchConfig.schema_version,
      default_retries: dispatchConfig.defaults.max_retries,
      default_timeout_ms: dispatchConfig.defaults.timeout_ms,
    },
    dispatch: {
      contenders: dispatchRecords,
      executed_contenders: dispatchRecords.length,
      required_contenders_met: dispatchRecords.length >= 3,
      total_latency_ms: dispatchRecords.reduce((sum, row) => sum + row.latency_ms, 0),
      total_retries: dispatchRecords.reduce((sum, row) => sum + row.retries, 0),
      total_tool_calls: dispatchRecords.reduce((sum, row) => sum + row.tool_calls, 0),
    },
    launch_summary_path: relativePath(path.join(outputDir, 'real-bounty-launch.summary.json')),
    launch: launchSummary,
  };

  const summaryPath = path.join(outputDir, 'real-contender-dispatch.summary.json');
  writeFileSync(summaryPath, `${stableJson(summary)}\n`);

  console.log(JSON.stringify(summary, null, 2));
}

main().catch((err) => {
  console.error(JSON.stringify({
    ok: false,
    error: err instanceof Error ? err.message : String(err),
  }, null, 2));
  process.exit(1);
});
