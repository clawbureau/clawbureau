#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

function isoStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

async function writeJson(targetPath, value) {
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.writeFile(targetPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function runCommand(args) {
  const started = Date.now();
  const startedAt = new Date(started).toISOString();

  const result = spawnSync(args.command, args.commandArgs, {
    cwd: args.cwd,
    env: args.env,
    stdio: 'inherit',
  });

  const finished = Date.now();
  const finishedAt = new Date(finished).toISOString();
  const exitCode = result.status ?? (result.error ? 1 : 0);

  return {
    runtime: args.runtime,
    suite: args.suite,
    command: [args.command, ...args.commandArgs].join(' '),
    cwd: path.relative(repoRoot, args.cwd),
    started_at: startedAt,
    finished_at: finishedAt,
    duration_ms: finished - started,
    exit_code: exitCode,
    ok: exitCode === 0,
  };
}

function assertBunAvailable() {
  const check = spawnSync('bun', ['--version'], { stdio: 'pipe' });
  if ((check.status ?? 1) !== 0) {
    throw new Error('bun runtime is required for cross-runtime determinism checks');
  }
}

async function ensureCoreBuild() {
  const distIndex = path.join(repoRoot, 'packages/clawverify-core/dist/index.js');

  try {
    await fs.access(distIndex);
    return;
  } catch {
    // build below
  }

  const result = spawnSync('npm', ['run', 'build'], {
    cwd: path.join(repoRoot, 'packages/clawverify-core'),
    stdio: 'inherit',
    env: process.env,
  });

  if ((result.status ?? 1) !== 0) {
    throw new Error('failed to build packages/clawverify-core before runtime parity check');
  }
}

function normalizeFixtureRows(summary) {
  const rows = Array.isArray(summary?.fixtures) ? summary.fixtures : [];

  return rows.map((row) => {
    const id = typeof row?.id === 'string' ? row.id : '';
    const status = row?.status === 'VALID' || row?.status === 'INVALID' ? row.status : 'INVALID';
    const error_code =
      typeof row?.error_code === 'string' && row.error_code.length > 0
        ? row.error_code
        : status === 'VALID'
          ? 'OK'
          : 'UNKNOWN';

    return {
      id,
      status,
      error_code,
    };
  });
}

async function main() {
  assertBunAvailable();
  await ensureCoreBuild();

  const stamp = isoStamp();
  const outDir = path.join(
    repoRoot,
    'artifacts/ops/causal-cross-runtime-determinism',
    stamp
  );

  const suites = [
    {
      id: 'causal-cldd',
      cwd: path.join(repoRoot, 'services/clawverify'),
      testPath: 'test/firewall-conformance.test.ts',
      summaryEnvKey: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
      extraEnv: {
        CLAWVERIFY_FIREWALL_FIXTURE_SUITE: 'clawverify-causal-cldd',
      },
    },
    {
      id: 'causal-hardening',
      cwd: path.join(repoRoot, 'services/clawverify'),
      testPath: 'test/firewall-conformance.test.ts',
      summaryEnvKey: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
      extraEnv: {
        CLAWVERIFY_FIREWALL_FIXTURE_SUITE: 'clawverify-causal-hardening',
      },
    },
    {
      id: 'causal-connectivity',
      cwd: path.join(repoRoot, 'services/clawverify'),
      testPath: 'test/firewall-conformance.test.ts',
      summaryEnvKey: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
      extraEnv: {
        CLAWVERIFY_FIREWALL_FIXTURE_SUITE: 'clawverify-causal-connectivity',
      },
    },
    {
      id: 'causal-clock',
      cwd: path.join(repoRoot, 'services/clawverify'),
      testPath: 'test/firewall-conformance.test.ts',
      summaryEnvKey: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
      extraEnv: {
        CLAWVERIFY_FIREWALL_FIXTURE_SUITE: 'clawverify-causal-clock',
      },
    },
    {
      id: 'causal-policy-profile',
      cwd: path.join(repoRoot, 'services/clawverify'),
      testPath: 'test/causal-policy-profile-conformance.test.ts',
      summaryEnvKey: 'CLAWVERIFY_POLICY_PROFILE_CONFORMANCE_SUMMARY_PATH',
      extraEnv: {},
    },
    {
      id: 'aggregate-causal',
      cwd: path.join(repoRoot, 'packages/clawverify-cli'),
      testPath: 'test/aggregate-causal-conformance.test.ts',
      summaryEnvKey: 'CLAWVERIFY_AGGREGATE_CAUSAL_CONFORMANCE_SUMMARY_PATH',
      extraEnv: {},
    },
  ];

  const runtimes = [
    { id: 'node', command: 'npm', argsForTest: (testPath) => ['test', '--', '--run', testPath] },
    {
      id: 'bun',
      command: 'bun',
      argsForTest: (testPath) => ['x', 'vitest', 'run', '--run', testPath],
    },
  ];

  const commandRuns = [];
  const runtimeSummaries = {
    node: {},
    bun: {},
  };

  let commandFailure = null;

  for (const runtime of runtimes) {
    for (const suite of suites) {
      const summaryPath = path.join(outDir, `runtime-${runtime.id}`, `${suite.id}.summary.json`);
      const env = {
        ...process.env,
        ...suite.extraEnv,
        [suite.summaryEnvKey]: summaryPath,
      };

      const commandRun = runCommand({
        runtime: runtime.id,
        suite: suite.id,
        command: runtime.command,
        commandArgs: runtime.argsForTest(suite.testPath),
        cwd: suite.cwd,
        env,
      });

      commandRuns.push(commandRun);

      if (!commandRun.ok) {
        commandFailure = commandRun;
        break;
      }

      let parsedSummary = null;
      try {
        parsedSummary = JSON.parse(await fs.readFile(summaryPath, 'utf8'));
      } catch {
        commandFailure = {
          ...commandRun,
          ok: false,
          exit_code: 1,
          error: `missing summary output at ${path.relative(repoRoot, summaryPath)}`,
        };
        break;
      }

      runtimeSummaries[runtime.id][suite.id] = {
        suite: parsedSummary?.suite ?? suite.id,
        summary_path: path.relative(repoRoot, summaryPath),
        fixtures: normalizeFixtureRows(parsedSummary),
      };
    }

    if (commandFailure) break;
  }

  const suiteComparisons = [];

  if (!commandFailure) {
    for (const suite of suites) {
      const nodeSummary = runtimeSummaries.node[suite.id];
      const bunSummary = runtimeSummaries.bun[suite.id];

      const nodeMap = new Map((nodeSummary?.fixtures ?? []).map((f) => [f.id, f]));
      const bunMap = new Map((bunSummary?.fixtures ?? []).map((f) => [f.id, f]));

      const allFixtureIds = [...new Set([...nodeMap.keys(), ...bunMap.keys()])].sort((a, b) =>
        a.localeCompare(b)
      );

      const divergences = [];

      for (const fixtureId of allFixtureIds) {
        const nodeRow = nodeMap.get(fixtureId);
        const bunRow = bunMap.get(fixtureId);

        if (!nodeRow || !bunRow) {
          divergences.push({
            fixture_id: fixtureId,
            node: nodeRow ?? null,
            bun: bunRow ?? null,
            reason: 'fixture_missing_in_runtime_summary',
          });
          continue;
        }

        if (nodeRow.status !== bunRow.status || nodeRow.error_code !== bunRow.error_code) {
          divergences.push({
            fixture_id: fixtureId,
            node: nodeRow,
            bun: bunRow,
            reason: 'status_or_reason_code_mismatch',
          });
        }
      }

      suiteComparisons.push({
        suite_id: suite.id,
        node_fixture_count: nodeSummary?.fixtures?.length ?? 0,
        bun_fixture_count: bunSummary?.fixtures?.length ?? 0,
        divergence_count: divergences.length,
        divergences,
        ok: divergences.length === 0,
      });
    }
  }

  const comparisonFailure = suiteComparisons.find((suite) => !suite.ok) ?? null;

  const summary = {
    ok: !commandFailure && !comparisonFailure,
    checked_at: new Date().toISOString(),
    runtimes: runtimes.map((runtime) => runtime.id),
    suite_count: suites.length,
    command_runs: commandRuns,
    command_failure: commandFailure,
    runtime_summaries: runtimeSummaries,
    suite_comparisons: suiteComparisons,
    comparison_failure_suite: comparisonFailure?.suite_id ?? null,
  };

  const outPath = path.join(outDir, 'summary.json');
  await writeJson(outPath, summary);

  if (!summary.ok) {
    console.error('[clawverify-causal-cross-runtime-determinism] FAIL');
    console.error(
      JSON.stringify(
        {
          ok: false,
          command_failure: commandFailure,
          comparison_failure_suite: summary.comparison_failure_suite,
          outPath: path.relative(repoRoot, outPath),
        },
        null,
        2
      )
    );
    process.exit(1);
  }

  console.log('[clawverify-causal-cross-runtime-determinism] PASS');
  console.log(
    JSON.stringify(
      {
        ok: true,
        suite_count: suites.length,
        outPath: path.relative(repoRoot, outPath),
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error('[clawverify-causal-cross-runtime-determinism] ERROR');
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
