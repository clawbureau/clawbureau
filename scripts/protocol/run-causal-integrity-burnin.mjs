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

function parseArgs(argv) {
  const opts = {
    mode: 'quick',
    mutationSubset: 'quick',
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];

    if (arg === '--mode' && (next === 'quick' || next === 'nightly')) {
      opts.mode = next;
      i += 1;
      continue;
    }

    if (arg.startsWith('--mode=')) {
      const value = arg.slice('--mode='.length);
      if (value === 'quick' || value === 'nightly') {
        opts.mode = value;
      }
      continue;
    }

    if (
      arg === '--mutation-subset' &&
      (next === 'quick' || next === 'full')
    ) {
      opts.mutationSubset = next;
      i += 1;
      continue;
    }

    if (arg.startsWith('--mutation-subset=')) {
      const value = arg.slice('--mutation-subset='.length);
      if (value === 'quick' || value === 'full') {
        opts.mutationSubset = value;
      }
    }
  }

  return opts;
}

function buildSteps(mutationSubset) {
  return [
    {
      id: 'reason-code-parity',
      command: 'node',
      args: ['scripts/protocol/check-reason-code-parity.mjs'],
    },
    {
      id: 'causal-cldd-conformance',
      command: 'node',
      args: ['scripts/protocol/run-clawverify-causal-cldd-conformance.mjs'],
    },
    {
      id: 'causal-hardening-conformance',
      command: 'node',
      args: ['scripts/protocol/run-clawverify-causal-hardening-conformance.mjs'],
    },
    {
      id: 'causal-connectivity-conformance',
      command: 'node',
      args: ['scripts/protocol/run-clawverify-causal-connectivity-conformance.mjs'],
    },
    {
      id: 'causal-clock-conformance',
      command: 'node',
      args: ['scripts/protocol/run-clawverify-causal-clock-conformance.mjs'],
    },
    {
      id: 'service-core-causal-parity',
      command: 'node',
      args: ['scripts/protocol/run-clawverify-service-core-causal-parity.mjs'],
    },
    {
      id: 'aggregate-causal-conformance',
      command: 'node',
      args: ['scripts/protocol/run-clawverify-aggregate-causal-conformance.mjs'],
    },
    {
      id: 'causal-mutation-guardrail',
      command: 'node',
      args: [
        'scripts/protocol/run-clawverify-causal-mutation-guardrail.mjs',
        '--subset',
        mutationSubset,
      ],
    },
  ];
}

async function writeJson(targetPath, value) {
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.writeFile(targetPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const steps = buildSteps(opts.mutationSubset);

  const stepResults = [];
  let ok = true;

  for (const step of steps) {
    const startedAt = new Date().toISOString();
    const started = Date.now();

    const result = spawnSync(step.command, step.args, {
      cwd: repoRoot,
      stdio: 'inherit',
      env: process.env,
    });

    const finishedAt = new Date().toISOString();
    const durationMs = Date.now() - started;
    const exitCode = result.status ?? (result.error ? 1 : 0);

    stepResults.push({
      id: step.id,
      command: [step.command, ...step.args].join(' '),
      started_at: startedAt,
      finished_at: finishedAt,
      duration_ms: durationMs,
      exit_code: exitCode,
      ok: exitCode === 0,
    });

    if (exitCode !== 0) {
      ok = false;
      break;
    }
  }

  const failedStep = stepResults.find((step) => !step.ok) ?? null;

  const summary = {
    ok,
    mode: opts.mode,
    mutation_subset: opts.mutationSubset,
    step_count_expected: steps.length,
    step_count_executed: stepResults.length,
    failed_step_id: failedStep?.id ?? null,
    steps: stepResults,
  };

  const outDir = path.join(
    repoRoot,
    'artifacts/ops/causal-integrity-burnin',
    isoStamp()
  );
  const outPath = path.join(outDir, 'summary.json');
  await writeJson(outPath, summary);

  if (!ok) {
    console.error('[causal-integrity-burnin] FAIL');
    console.error(
      JSON.stringify(
        {
          ok: false,
          mode: opts.mode,
          mutation_subset: opts.mutationSubset,
          failed_step_id: summary.failed_step_id,
          outPath: path.relative(repoRoot, outPath),
        },
        null,
        2
      )
    );
    process.exit(1);
  }

  console.log('[causal-integrity-burnin] PASS');
  console.log(
    JSON.stringify(
      {
        ok: true,
        mode: opts.mode,
        mutation_subset: opts.mutationSubset,
        outPath: path.relative(repoRoot, outPath),
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error('[causal-integrity-burnin] ERROR');
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
