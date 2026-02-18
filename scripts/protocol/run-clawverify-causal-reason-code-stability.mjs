#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

const disallowedGenericCodes = new Set([
  'INVALID',
  'MALFORMED_ENVELOPE',
  'SCHEMA_VALIDATION_FAILED',
  'INTERNAL_ERROR',
  'PARSE_ERROR',
]);

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

function registryCodesFromMarkdown(markdown) {
  return new Set(
    [...markdown.matchAll(/`([A-Z][A-Z0-9_]+)`/g)].map((m) => m[1])
  );
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
    throw new Error('failed to build packages/clawverify-core before reason-code stability checks');
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

async function loadFixtureCases(suiteId) {
  const suiteRoot = path.join(
    repoRoot,
    'packages/schema/fixtures/protocol-conformance',
    suiteId
  );
  const manifest = await readJson(path.join(suiteRoot, 'manifest.v1.json'));
  const caseFiles = Array.isArray(manifest?.cases) ? manifest.cases : [];

  const cases = [];
  for (const caseFile of caseFiles) {
    const doc = await readJson(path.join(suiteRoot, caseFile));
    cases.push({
      file: caseFile,
      id: String(doc?.id ?? caseFile),
      scenario: String(doc?.scenario ?? ''),
      expected_status: String(doc?.expected?.status ?? ''),
      expected_error_code:
        typeof doc?.expected?.error_code === 'string'
          ? doc.expected.error_code
          : doc?.expected?.status === 'VALID'
            ? 'OK'
            : null,
    });
  }

  return {
    manifest_suite: String(manifest?.suite ?? suiteId),
    cases,
  };
}

function indexRows(rows) {
  const out = new Map();
  for (const row of rows) {
    const id = typeof row?.id === 'string' ? row.id : null;
    if (!id) continue;
    out.set(id, {
      status: row?.status,
      error_code: typeof row?.error_code === 'string' ? row.error_code : 'UNKNOWN',
    });
  }
  return out;
}

async function main() {
  await ensureCoreBuild();

  const registryPath = path.join(
    repoRoot,
    'docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md'
  );
  const registryCodes = registryCodesFromMarkdown(
    await fs.readFile(registryPath, 'utf8')
  );

  const stamp = isoStamp();
  const outDir = path.join(
    repoRoot,
    'artifacts/ops/causal-reason-code-stability',
    stamp
  );

  const fixtureContractSummaryPath = path.join(
    outDir,
    'fixture-contract.summary.json'
  );

  const fixtureContractExitCode = runNodeScript(
    'scripts/protocol/check-causal-fixture-contract.mjs',
    {
      ...process.env,
      CAUSAL_FIXTURE_CONTRACT_SUMMARY_PATH: fixtureContractSummaryPath,
    }
  );

  if (fixtureContractExitCode !== 0) {
    const summary = {
      ok: false,
      checked_at: new Date().toISOString(),
      suite_count_expected: 0,
      suite_count_executed: 0,
      failure_suite_id: null,
      fixture_contract_summary_path: path.relative(repoRoot, fixtureContractSummaryPath),
      disallowed_generic_codes: [...disallowedGenericCodes],
      suites: [],
      failures: [
        {
          type: 'fixture_contract_failed',
          detail: `scripts/protocol/check-causal-fixture-contract.mjs exited with code ${fixtureContractExitCode}`,
        },
      ],
    };

    const outPath = path.join(outDir, 'summary.json');
    await writeJson(outPath, summary);

    console.error('[clawverify-causal-reason-code-stability] FAIL');
    console.error(
      JSON.stringify(
        {
          ok: false,
          failure_suite_id: null,
          outPath: path.relative(repoRoot, outPath),
        },
        null,
        2
      )
    );
    process.exit(1);
  }

  const suites = [
    {
      id: 'clawverify-causal-cldd',
      runner: 'scripts/protocol/run-clawverify-causal-cldd-conformance.mjs',
      summary_env_key: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
    },
    {
      id: 'clawverify-causal-hardening',
      runner: 'scripts/protocol/run-clawverify-causal-hardening-conformance.mjs',
      summary_env_key: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
    },
    {
      id: 'clawverify-causal-connectivity',
      runner: 'scripts/protocol/run-clawverify-causal-connectivity-conformance.mjs',
      summary_env_key: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
    },
    {
      id: 'clawverify-causal-clock',
      runner: 'scripts/protocol/run-clawverify-causal-clock-conformance.mjs',
      summary_env_key: 'CLAWVERIFY_FIREWALL_CONFORMANCE_SUMMARY_PATH',
    },
    {
      id: 'clawverify-aggregate-causal',
      runner: 'scripts/protocol/run-clawverify-aggregate-causal-conformance.mjs',
      summary_env_key: 'CLAWVERIFY_AGGREGATE_CAUSAL_CONFORMANCE_SUMMARY_PATH',
    },
  ];

  const suiteResults = [];
  let ok = true;

  for (const suite of suites) {
    const summaryPath = path.join(outDir, `${suite.id}.summary.json`);

    const runEnv = {
      ...process.env,
      [suite.summary_env_key]: summaryPath,
    };

    const exitCode = runNodeScript(suite.runner, runEnv);
    if (exitCode !== 0) {
      suiteResults.push({
        suite_id: suite.id,
        ok: false,
        runner_exit_code: exitCode,
        failures: [
          {
            type: 'runner_failed',
            detail: `${suite.runner} exited with code ${exitCode}`,
          },
        ],
      });
      ok = false;
      break;
    }

    let runtimeSummary;
    try {
      runtimeSummary = await readJson(summaryPath);
    } catch {
      suiteResults.push({
        suite_id: suite.id,
        ok: false,
        runner_exit_code: 1,
        failures: [
          {
            type: 'summary_missing',
            detail: `Expected summary output at ${path.relative(repoRoot, summaryPath)}`,
          },
        ],
      });
      ok = false;
      break;
    }

    const expected = await loadFixtureCases(suite.id);
    const actualById = indexRows(runtimeSummary?.fixtures ?? []);

    const failures = [];
    let invalidChecked = 0;

    for (const spec of expected.cases) {
      const actual = actualById.get(spec.id);
      if (!actual) {
        failures.push({
          type: 'fixture_missing',
          fixture_id: spec.id,
          detail: 'fixture not present in runtime summary',
        });
        continue;
      }

      if (actual.status !== spec.expected_status) {
        failures.push({
          type: 'status_mismatch',
          fixture_id: spec.id,
          expected_status: spec.expected_status,
          actual_status: actual.status,
        });
      }

      if (spec.expected_status !== 'INVALID') {
        continue;
      }

      invalidChecked += 1;

      if (!spec.expected_error_code) {
        failures.push({
          type: 'fixture_missing_expected_code',
          fixture_id: spec.id,
          detail: 'invalid fixture must declare expected.error_code',
        });
        continue;
      }

      if (actual.error_code !== spec.expected_error_code) {
        failures.push({
          type: 'reason_code_mismatch',
          fixture_id: spec.id,
          expected_error_code: spec.expected_error_code,
          actual_error_code: actual.error_code,
        });
      }

      if (disallowedGenericCodes.has(actual.error_code)) {
        failures.push({
          type: 'generic_reason_code_forbidden',
          fixture_id: spec.id,
          actual_error_code: actual.error_code,
        });
      }

      if (!registryCodes.has(actual.error_code)) {
        failures.push({
          type: 'unregistered_reason_code',
          fixture_id: spec.id,
          actual_error_code: actual.error_code,
        });
      }
    }

    for (const id of actualById.keys()) {
      if (!expected.cases.find((spec) => spec.id === id)) {
        failures.push({
          type: 'unexpected_fixture',
          fixture_id: id,
          detail: 'runtime summary includes fixture not present in suite manifest',
        });
      }
    }

    const suiteOk = failures.length === 0;
    if (!suiteOk) ok = false;

    suiteResults.push({
      suite_id: suite.id,
      manifest_suite: expected.manifest_suite,
      fixture_count: expected.cases.length,
      invalid_fixture_count: expected.cases.filter((c) => c.expected_status === 'INVALID').length,
      invalid_fixture_checked_count: invalidChecked,
      summary_path: path.relative(repoRoot, summaryPath),
      runner_exit_code: 0,
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
    fixture_contract_summary_path: path.relative(repoRoot, fixtureContractSummaryPath),
    disallowed_generic_codes: [...disallowedGenericCodes],
    suites: suiteResults,
  };

  const outPath = path.join(outDir, 'summary.json');
  await writeJson(outPath, summary);

  if (!ok) {
    console.error('[clawverify-causal-reason-code-stability] FAIL');
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

  console.log('[clawverify-causal-reason-code-stability] PASS');
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
  console.error('[clawverify-causal-reason-code-stability] ERROR');
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
