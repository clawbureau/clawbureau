#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

const serviceTypesPath = path.join(repoRoot, 'services/clawverify/src/types.ts');
const coreTypesPath = path.join(repoRoot, 'packages/clawverify-core/src/types.ts');
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
      process.env.SERVICE_CORE_CAUSAL_REASON_CODE_PARITY_SUMMARY_PATH?.trim() ||
      null,
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
    }
  }

  return opts;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort((a, b) => a.localeCompare(b));
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
    'artifacts/ops/service-core-causal-reason-code-parity',
    isoStamp(),
    'summary.json'
  );
}

function toNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0
    ? value.trim()
    : null;
}

function extractVerificationErrorCodes(typesSource, label) {
  const match = typesSource.match(
    /export\s+type\s+VerificationErrorCode\s*=([\s\S]*?);\n/
  );

  if (!match) {
    throw new Error(`Could not locate VerificationErrorCode union in ${label}`);
  }

  return uniqueSorted(
    [...match[1].matchAll(/'([A-Z][A-Z0-9_]+)'/g)].map((m) => m[1])
  );
}

async function discoverCausalSuites() {
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

async function collectExpectedCausalCodes(suites) {
  const issues = [];
  const codes = [];
  const suiteSummaries = [];

  for (const suiteId of suites) {
    const suitePath = path.join(fixtureRoot, suiteId);
    const manifestPath = path.join(suitePath, 'manifest.v1.json');

    let manifest;
    try {
      manifest = await readJson(manifestPath);
    } catch (error) {
      issues.push({
        type: 'manifest_missing_or_invalid',
        suite_id: suiteId,
        detail:
          error instanceof Error
            ? error.message
            : 'failed to read manifest.v1.json',
      });
      continue;
    }

    const manifestVersion = toNonEmptyString(manifest?.manifest_version);
    const manifestSuite = toNonEmptyString(manifest?.suite);
    const manifestCases = Array.isArray(manifest?.cases) ? manifest.cases : null;

    if (manifestVersion !== '1') {
      issues.push({
        type: 'manifest_field_invalid',
        suite_id: suiteId,
        field: 'manifest_version',
        detail: `manifest_version must be "1" (got ${String(manifest?.manifest_version)})`,
      });
    }

    if (!manifestSuite) {
      issues.push({
        type: 'manifest_field_missing',
        suite_id: suiteId,
        field: 'suite',
        detail: 'manifest.suite must be a non-empty string',
      });
    } else if (manifestSuite !== suiteId) {
      issues.push({
        type: 'manifest_suite_mismatch',
        suite_id: suiteId,
        detail: `manifest.suite must match directory (${suiteId})`,
      });
    }

    if (!manifestCases) {
      issues.push({
        type: 'manifest_field_missing',
        suite_id: suiteId,
        field: 'cases',
        detail: 'manifest.cases must be an array',
      });
      continue;
    }

    const suiteCodes = [];
    let invalidFixtureCount = 0;

    for (const caseFileRaw of manifestCases) {
      const caseFile = toNonEmptyString(caseFileRaw);
      if (!caseFile) {
        issues.push({
          type: 'manifest_case_invalid',
          suite_id: suiteId,
          detail: 'manifest.cases entries must be non-empty strings',
        });
        continue;
      }

      const casePath = path.join(suitePath, caseFile);
      let fixture;
      try {
        fixture = await readJson(casePath);
      } catch (error) {
        issues.push({
          type: 'fixture_missing_or_invalid',
          suite_id: suiteId,
          case_file: caseFile,
          detail:
            error instanceof Error
              ? error.message
              : `failed to read fixture ${caseFile}`,
        });
        continue;
      }

      const expected = fixture?.expected;
      const status = toNonEmptyString(expected?.status);

      if (status !== 'VALID' && status !== 'INVALID') {
        issues.push({
          type: 'fixture_expected_status_invalid',
          suite_id: suiteId,
          case_file: caseFile,
          detail: `expected.status must be VALID or INVALID (got ${String(expected?.status)})`,
        });
        continue;
      }

      if (status !== 'INVALID') {
        continue;
      }

      invalidFixtureCount += 1;

      const errorCode = toNonEmptyString(expected?.error_code);
      if (!errorCode) {
        issues.push({
          type: 'fixture_expected_error_code_missing',
          suite_id: suiteId,
          case_file: caseFile,
          detail: 'invalid fixtures must define expected.error_code',
        });
        continue;
      }

      suiteCodes.push(errorCode);
      codes.push(errorCode);
    }

    suiteSummaries.push({
      suite_id: suiteId,
      invalid_fixture_count: invalidFixtureCount,
      expected_error_code_count: uniqueSorted(suiteCodes).length,
      expected_error_codes: uniqueSorted(suiteCodes),
    });
  }

  return {
    expectedCodes: uniqueSorted(codes),
    suiteSummaries,
    issues,
  };
}

function difference(from, againstSet) {
  return from.filter((code) => !againstSet.has(code));
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  const [serviceTypesSource, coreTypesSource, suites] = await Promise.all([
    fs.readFile(serviceTypesPath, 'utf8'),
    fs.readFile(coreTypesPath, 'utf8'),
    discoverCausalSuites(),
  ]);

  const serviceCodes = extractVerificationErrorCodes(
    serviceTypesSource,
    'services/clawverify/src/types.ts'
  );
  const coreCodes = extractVerificationErrorCodes(
    coreTypesSource,
    'packages/clawverify-core/src/types.ts'
  );

  const fixtureData = await collectExpectedCausalCodes(suites);

  const expectedCodes = fixtureData.expectedCodes;
  const serviceSet = new Set(serviceCodes);
  const coreSet = new Set(coreCodes);

  const missingInService = difference(expectedCodes, serviceSet);
  const missingInCore = difference(expectedCodes, coreSet);

  const summary = {
    ok:
      fixtureData.issues.length === 0 &&
      missingInService.length === 0 &&
      missingInCore.length === 0,
    checked_at: new Date().toISOString(),
    suite_count: suites.length,
    suites_checked: suites,
    service_code_count: serviceCodes.length,
    core_code_count: coreCodes.length,
    expected_code_count: expectedCodes.length,
    expected_codes: expectedCodes,
    missing_in_service_types: missingInService,
    missing_in_core_types: missingInCore,
    fixture_contract_issues: fixtureData.issues,
    suites_summary: fixtureData.suiteSummaries,
  };

  const outPath = path.resolve(repoRoot, opts.summaryOut || defaultSummaryPath());
  await writeJson(outPath, summary);

  if (!summary.ok) {
    console.error('[service-core-causal-reason-code-parity] FAIL');
    console.error(
      JSON.stringify(
        {
          ok: false,
          missing_in_service_types: missingInService,
          missing_in_core_types: missingInCore,
          fixture_contract_issue_count: fixtureData.issues.length,
          outPath: path.relative(repoRoot, outPath),
        },
        null,
        2
      )
    );
    process.exit(1);
  }

  console.log('[service-core-causal-reason-code-parity] PASS');
  console.log(
    JSON.stringify(
      {
        ok: true,
        expected_code_count: expectedCodes.length,
        outPath: path.relative(repoRoot, outPath),
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error('[service-core-causal-reason-code-parity] ERROR');
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
