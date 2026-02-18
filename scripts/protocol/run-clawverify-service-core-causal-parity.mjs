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

async function readJson(targetPath) {
  return JSON.parse(await fs.readFile(targetPath, 'utf8'));
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
    throw new Error('failed to build packages/clawverify-core before parity checks');
  }
}

function runNodeScript(scriptRelPath, env) {
  const result = spawnSync('node', [scriptRelPath], {
    cwd: repoRoot,
    env,
    stdio: 'inherit',
  });

  return result.status ?? 1;
}

function indexRows(rows) {
  const out = new Map();
  for (const row of rows) {
    const id = typeof row?.id === 'string' ? row.id : null;
    if (!id) continue;
    out.set(id, {
      status: typeof row?.status === 'string' ? row.status : 'UNKNOWN',
      error_code:
        typeof row?.error_code === 'string' && row.error_code.length > 0
          ? row.error_code
          : 'OK',
    });
  }
  return out;
}

function sortedIds(map) {
  return [...map.keys()].sort((a, b) => a.localeCompare(b));
}

async function main() {
  await ensureCoreBuild();

  const stamp = isoStamp();
  const outDir = path.join(
    repoRoot,
    'artifacts/ops/causal-service-core-parity',
    stamp
  );

  const suites = [
    {
      id: 'clawverify-causal-cldd',
      runner: 'scripts/protocol/run-clawverify-causal-cldd-conformance.mjs',
      summaryEnvKey: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
      verifierEnvKey: 'CLAWVERIFY_FIREWALL_VERIFIER_IMPL',
    },
    {
      id: 'clawverify-causal-hardening',
      runner: 'scripts/protocol/run-clawverify-causal-hardening-conformance.mjs',
      summaryEnvKey: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
      verifierEnvKey: 'CLAWVERIFY_FIREWALL_VERIFIER_IMPL',
    },
    {
      id: 'clawverify-causal-connectivity',
      runner: 'scripts/protocol/run-clawverify-causal-connectivity-conformance.mjs',
      summaryEnvKey: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
      verifierEnvKey: 'CLAWVERIFY_FIREWALL_VERIFIER_IMPL',
    },
    {
      id: 'clawverify-causal-clock',
      runner: 'scripts/protocol/run-clawverify-causal-clock-conformance.mjs',
      summaryEnvKey: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
      verifierEnvKey: 'CLAWVERIFY_FIREWALL_VERIFIER_IMPL',
    },
    {
      id: 'clawverify-causal-policy-profile',
      runner: 'scripts/protocol/run-clawverify-causal-policy-profile-conformance.mjs',
      summaryEnvKey: 'CLAWVERIFY_POLICY_PROFILE_CONFORMANCE_SUMMARY_PATH',
      verifierEnvKey: 'CLAWVERIFY_POLICY_PROFILE_VERIFIER_IMPL',
    },
  ];

  const suiteResults = [];
  let ok = true;

  for (const suite of suites) {
    const serviceSummaryPath = path.join(outDir, `${suite.id}.service.summary.json`);
    const coreSummaryPath = path.join(outDir, `${suite.id}.core.summary.json`);

    const serviceEnv = {
      ...process.env,
      [suite.summaryEnvKey]: serviceSummaryPath,
      [suite.verifierEnvKey]: 'service',
    };

    const serviceExit = runNodeScript(suite.runner, serviceEnv);
    if (serviceExit !== 0) {
      suiteResults.push({
        suite_id: suite.id,
        ok: false,
        service_exit_code: serviceExit,
        core_exit_code: null,
        failures: [
          {
            type: 'service_runner_failed',
            detail: `${suite.runner} exited with code ${serviceExit}`,
          },
        ],
      });
      ok = false;
      break;
    }

    const coreEnv = {
      ...process.env,
      [suite.summaryEnvKey]: coreSummaryPath,
      [suite.verifierEnvKey]: 'core',
    };

    const coreExit = runNodeScript(suite.runner, coreEnv);
    if (coreExit !== 0) {
      suiteResults.push({
        suite_id: suite.id,
        ok: false,
        service_exit_code: serviceExit,
        core_exit_code: coreExit,
        failures: [
          {
            type: 'core_runner_failed',
            detail: `${suite.runner} exited with code ${coreExit} in core mode`,
          },
        ],
      });
      ok = false;
      break;
    }

    let serviceSummary;
    let coreSummary;

    try {
      serviceSummary = await readJson(serviceSummaryPath);
      coreSummary = await readJson(coreSummaryPath);
    } catch (error) {
      suiteResults.push({
        suite_id: suite.id,
        ok: false,
        service_exit_code: serviceExit,
        core_exit_code: coreExit,
        failures: [
          {
            type: 'summary_missing',
            detail:
              error instanceof Error
                ? error.message
                : 'failed to read suite summary outputs',
          },
        ],
      });
      ok = false;
      break;
    }

    const serviceById = indexRows(serviceSummary?.fixtures ?? []);
    const coreById = indexRows(coreSummary?.fixtures ?? []);
    const serviceIds = sortedIds(serviceById);
    const coreIds = sortedIds(coreById);

    const failures = [];

    for (const id of serviceIds) {
      if (!coreById.has(id)) {
        failures.push({
          type: 'fixture_missing_in_core',
          fixture_id: id,
        });
        continue;
      }

      const serviceRow = serviceById.get(id);
      const coreRow = coreById.get(id);

      if (serviceRow.status !== coreRow.status) {
        failures.push({
          type: 'status_mismatch',
          fixture_id: id,
          service_status: serviceRow.status,
          core_status: coreRow.status,
        });
      }

      if (serviceRow.error_code !== coreRow.error_code) {
        failures.push({
          type: 'reason_code_mismatch',
          fixture_id: id,
          service_error_code: serviceRow.error_code,
          core_error_code: coreRow.error_code,
        });
      }
    }

    for (const id of coreIds) {
      if (!serviceById.has(id)) {
        failures.push({
          type: 'fixture_missing_in_service',
          fixture_id: id,
        });
      }
    }

    const suiteOk = failures.length === 0;
    if (!suiteOk) ok = false;

    suiteResults.push({
      suite_id: suite.id,
      fixture_count_service: serviceIds.length,
      fixture_count_core: coreIds.length,
      service_summary_path: path.relative(repoRoot, serviceSummaryPath),
      core_summary_path: path.relative(repoRoot, coreSummaryPath),
      service_exit_code: serviceExit,
      core_exit_code: coreExit,
      ok: suiteOk,
      failures,
    });

    if (!suiteOk) {
      break;
    }
  }

  const failureSuite = suiteResults.find((suite) => !suite.ok) ?? null;

  const summary = {
    ok,
    checked_at: new Date().toISOString(),
    suite_count_expected: suites.length,
    suite_count_executed: suiteResults.length,
    failure_suite_id: failureSuite?.suite_id ?? null,
    suites: suiteResults,
  };

  const outPath = path.join(outDir, 'summary.json');
  await writeJson(outPath, summary);

  if (!ok) {
    console.error('[clawverify-service-core-causal-parity] FAIL');
    console.error(
      JSON.stringify(
        {
          ok: false,
          failure_suite_id: summary.failure_suite_id,
          outPath: path.relative(repoRoot, outPath),
        },
        null,
        2
      )
    );
    process.exit(1);
  }

  console.log('[clawverify-service-core-causal-parity] PASS');
  console.log(
    JSON.stringify(
      {
        ok: true,
        suite_count: suiteResults.length,
        outPath: path.relative(repoRoot, outPath),
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error('[clawverify-service-core-causal-parity] ERROR');
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
