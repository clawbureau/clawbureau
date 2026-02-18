#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');
const fixtureRoot = path.join(
  repoRoot,
  'packages/schema/fixtures/protocol-conformance'
);

function isoStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function parseArgs(argv) {
  const opts = {
    summaryOut:
      process.env.CAUSAL_FIXTURE_CONTRACT_SUMMARY_PATH?.trim() || null,
    suites: [],
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];

    if (arg === '--summary-out' && next) {
      opts.summaryOut = next;
      i += 1;
      continue;
    }

    if (arg.startsWith('--summary-out=')) {
      opts.summaryOut = arg.slice('--summary-out='.length);
      continue;
    }

    if (arg === '--suite' && next) {
      opts.suites.push(next);
      i += 1;
      continue;
    }

    if (arg.startsWith('--suite=')) {
      opts.suites.push(arg.slice('--suite='.length));
    }
  }

  return opts;
}

async function readJson(targetPath) {
  return JSON.parse(await fs.readFile(targetPath, 'utf8'));
}

async function writeJson(targetPath, value) {
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.writeFile(targetPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function defaultSummaryPath() {
  return path.join(
    repoRoot,
    'artifacts/ops/causal-fixture-contract',
    isoStamp(),
    'summary.json'
  );
}

async function discoverSuites() {
  const entries = await fs.readdir(fixtureRoot, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .filter(
      (name) =>
        name.startsWith('clawverify-causal-') ||
        name === 'clawverify-aggregate-causal'
    )
    .sort((a, b) => a.localeCompare(b));
}

function toNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
    ? value.trim()
    : null;
}

async function validateSuite(suiteId, globalIds) {
  const suitePath = path.join(fixtureRoot, suiteId);
  const manifestPath = path.join(suitePath, 'manifest.v1.json');

  const suiteFailures = [];
  let manifest;

  try {
    manifest = await readJson(manifestPath);
  } catch (error) {
    suiteFailures.push({
      type: 'manifest_missing_or_invalid',
      detail:
        error instanceof Error
          ? error.message
          : 'failed to read manifest.v1.json',
    });

    return {
      suite_id: suiteId,
      ok: false,
      fixture_count: 0,
      invalid_fixture_count: 0,
      duplicate_fixture_id_count: 0,
      failures: suiteFailures,
    };
  }

  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    suiteFailures.push({
      type: 'manifest_invalid_type',
      detail: 'manifest must be a JSON object',
    });

    return {
      suite_id: suiteId,
      ok: false,
      fixture_count: 0,
      invalid_fixture_count: 0,
      duplicate_fixture_id_count: 0,
      failures: suiteFailures,
    };
  }

  const manifestVersion = toNonEmptyString(manifest.manifest_version);
  const manifestSuite = toNonEmptyString(manifest.suite);
  const manifestCases = Array.isArray(manifest.cases) ? manifest.cases : null;

  if (manifestVersion !== '1') {
    suiteFailures.push({
      type: 'manifest_field_invalid',
      field: 'manifest_version',
      detail: `manifest_version must be "1" (got ${String(manifest.manifest_version)})`,
    });
  }

  if (!manifestSuite) {
    suiteFailures.push({
      type: 'manifest_field_missing',
      field: 'suite',
      detail: 'manifest.suite must be a non-empty string',
    });
  } else if (manifestSuite !== suiteId) {
    suiteFailures.push({
      type: 'manifest_suite_mismatch',
      field: 'suite',
      detail: `manifest.suite must match directory name (${suiteId})`,
    });
  }

  if (!manifestCases) {
    suiteFailures.push({
      type: 'manifest_field_missing',
      field: 'cases',
      detail: 'manifest.cases must be an array',
    });

    return {
      suite_id: suiteId,
      manifest_suite: manifestSuite,
      ok: false,
      fixture_count: 0,
      invalid_fixture_count: 0,
      duplicate_fixture_id_count: 0,
      failures: suiteFailures,
    };
  }

  if (manifestCases.length === 0) {
    suiteFailures.push({
      type: 'manifest_cases_empty',
      detail: 'manifest.cases must include at least one fixture file',
    });
  }

  const manifestCaseSet = new Set();
  for (const caseFile of manifestCases) {
    if (!toNonEmptyString(caseFile)) {
      suiteFailures.push({
        type: 'manifest_case_invalid',
        detail: 'manifest.cases entries must be non-empty strings',
      });
      continue;
    }

    if (manifestCaseSet.has(caseFile)) {
      suiteFailures.push({
        type: 'manifest_case_duplicate',
        case_file: caseFile,
      });
      continue;
    }

    manifestCaseSet.add(caseFile);
  }

  let fixtureCount = 0;
  let invalidFixtureCount = 0;
  let duplicateFixtureIdCount = 0;

  for (const caseFile of manifestCaseSet) {
    const casePath = path.join(suitePath, caseFile);
    let fixture;

    try {
      fixture = await readJson(casePath);
    } catch (error) {
      suiteFailures.push({
        type: 'fixture_missing_or_invalid',
        case_file: caseFile,
        detail:
          error instanceof Error
            ? error.message
            : `failed to read ${caseFile}`,
      });
      continue;
    }

    fixtureCount += 1;

    const fixtureId = toNonEmptyString(fixture?.id);
    const scenario = toNonEmptyString(fixture?.scenario);
    const expected = fixture?.expected;
    const status = toNonEmptyString(expected?.status);
    const errorCode = toNonEmptyString(expected?.error_code);

    if (!fixtureId) {
      suiteFailures.push({
        type: 'fixture_field_missing',
        case_file: caseFile,
        field: 'id',
        detail: 'fixture.id must be a non-empty string',
      });
    } else {
      const firstSeen = globalIds.get(fixtureId);
      if (firstSeen) {
        duplicateFixtureIdCount += 1;
        suiteFailures.push({
          type: 'fixture_id_duplicate',
          fixture_id: fixtureId,
          case_file: caseFile,
          first_seen: `${firstSeen.suite_id}/${firstSeen.case_file}`,
        });
      } else {
        globalIds.set(fixtureId, { suite_id: suiteId, case_file: caseFile });
      }
    }

    if (!scenario) {
      suiteFailures.push({
        type: 'fixture_field_missing',
        case_file: caseFile,
        field: 'scenario',
        detail: 'fixture.scenario must be a non-empty string',
      });
    }

    if (!expected || typeof expected !== 'object' || Array.isArray(expected)) {
      suiteFailures.push({
        type: 'fixture_field_missing',
        case_file: caseFile,
        field: 'expected',
        detail: 'fixture.expected must be an object',
      });
      continue;
    }

    if (status !== 'VALID' && status !== 'INVALID') {
      suiteFailures.push({
        type: 'fixture_expected_status_invalid',
        case_file: caseFile,
        detail: `expected.status must be VALID or INVALID (got ${String(expected.status)})`,
      });
      continue;
    }

    if (status === 'INVALID') {
      invalidFixtureCount += 1;
      if (!errorCode) {
        suiteFailures.push({
          type: 'fixture_expected_error_code_missing',
          case_file: caseFile,
          detail: 'invalid fixtures must define expected.error_code',
        });
      }
    }
  }

  return {
    suite_id: suiteId,
    manifest_suite: manifestSuite,
    ok: suiteFailures.length === 0,
    fixture_count: fixtureCount,
    invalid_fixture_count: invalidFixtureCount,
    duplicate_fixture_id_count: duplicateFixtureIdCount,
    failures: suiteFailures,
  };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const suites =
    opts.suites.length > 0 ? opts.suites.slice().sort((a, b) => a.localeCompare(b)) : await discoverSuites();

  const globalIds = new Map();
  const suiteResults = [];

  for (const suiteId of suites) {
    const result = await validateSuite(suiteId, globalIds);
    suiteResults.push(result);
  }

  const duplicateIds = suiteResults
    .flatMap((suite) =>
      suite.failures
        .filter((failure) => failure.type === 'fixture_id_duplicate')
        .map((failure) => failure.fixture_id)
    )
    .filter((value, idx, arr) => arr.indexOf(value) === idx)
    .sort((a, b) => a.localeCompare(b));

  const ok = suiteResults.every((suite) => suite.ok);
  const summary = {
    ok,
    checked_at: new Date().toISOString(),
    fixture_root: path.relative(repoRoot, fixtureRoot),
    suite_count: suites.length,
    suites_checked: suites,
    fixture_count: suiteResults.reduce((sum, suite) => sum + suite.fixture_count, 0),
    invalid_fixture_count: suiteResults.reduce(
      (sum, suite) => sum + suite.invalid_fixture_count,
      0
    ),
    duplicate_fixture_ids: duplicateIds,
    suites: suiteResults,
  };

  const outPath = path.resolve(repoRoot, opts.summaryOut || defaultSummaryPath());
  await writeJson(outPath, summary);

  if (!ok) {
    console.error('[causal-fixture-contract] FAIL');
    console.error(
      JSON.stringify(
        {
          ok: false,
          suite_count: suites.length,
          duplicate_fixture_ids: duplicateIds,
          outPath: path.relative(repoRoot, outPath),
        },
        null,
        2
      )
    );
    process.exit(1);
  }

  console.log('[causal-fixture-contract] PASS');
  console.log(
    JSON.stringify(
      {
        ok: true,
        suite_count: suites.length,
        fixture_count: summary.fixture_count,
        outPath: path.relative(repoRoot, outPath),
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error('[causal-fixture-contract] ERROR');
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
