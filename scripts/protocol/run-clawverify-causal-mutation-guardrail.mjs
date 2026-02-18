#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

const protocolFixtureRoot = path.join(
  repoRoot,
  'packages/schema/fixtures/protocol-conformance'
);

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

async function fileExists(targetPath) {
  try {
    await fs.access(targetPath);
    return true;
  } catch {
    return false;
  }
}

function parseSubset(argv) {
  const subsetArgIndex = argv.findIndex((arg) => arg === '--subset');
  if (subsetArgIndex >= 0) {
    const value = argv[subsetArgIndex + 1];
    if (value === 'quick' || value === 'full') return value;
  }

  const equalsArg = argv.find((arg) => arg.startsWith('--subset='));
  if (equalsArg) {
    const value = equalsArg.slice('--subset='.length);
    if (value === 'quick' || value === 'full') return value;
  }

  return 'quick';
}

function registryCodesFromMarkdown(markdown) {
  return new Set(
    [...markdown.matchAll(/`([A-Z][A-Z0-9_]+)`/g)].map((m) => m[1])
  );
}

async function writeJson(targetPath, value) {
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.writeFile(targetPath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function main() {
  const subset = parseSubset(process.argv.slice(2));

  const seeds = [
    {
      id: 'seed-connected',
      path: path.join(
        protocolFixtureRoot,
        'clawverify-causal-connectivity/valid-causal-connected.v1.json'
      ),
    },
    {
      id: 'seed-no-replay',
      path: path.join(
        protocolFixtureRoot,
        'clawverify-causal-hardening/valid-causal-no-replay-no-conflict.v1.json'
      ),
    },
    {
      id: 'seed-binding-snake',
      path: path.join(
        protocolFixtureRoot,
        'clawverify-causal-hardening/valid-causal-binding-snake-only.v1.json'
      ),
    },
  ];

  const allMutants = [
    {
      id: 'mut-camel-snake-conflict',
      category: 'camel/snake conflicting duplicates',
      seed_fixture: seeds[2].path,
      scenario: 'invalid_causal_binding_field_conflict',
      expected_error_code: 'CAUSAL_BINDING_FIELD_CONFLICT',
    },
    {
      id: 'mut-unicode-confusable',
      category: 'zero-width/unicode confusable span IDs',
      seed_fixture: seeds[0].path,
      scenario: 'invalid_causal_unicode_confusable_dangling',
      expected_error_code: 'CAUSAL_REFERENCE_DANGLING',
    },
    {
      id: 'mut-span-semantic-drift',
      category: 'span reuse with semantic drift',
      seed_fixture: seeds[1].path,
      scenario: 'invalid_causal_span_reuse_conflict',
      expected_error_code: 'CAUSAL_SPAN_REUSE_CONFLICT',
    },
    {
      id: 'mut-confidence-overclaim',
      category: 'confidence overclaim mutation',
      seed_fixture: seeds[1].path,
      scenario: 'invalid_causal_confidence_overclaim',
      expected_error_code: 'CAUSAL_CONFIDENCE_EVIDENCE_INCONSISTENT',
    },
    {
      id: 'mut-dangling-reference',
      category: 'dangling mutation',
      seed_fixture: seeds[0].path,
      scenario: 'invalid_causal_dangling',
      expected_error_code: 'CAUSAL_REFERENCE_DANGLING',
    },
    {
      id: 'mut-cycle-linkage',
      category: 'cycle mutation',
      seed_fixture: seeds[0].path,
      scenario: 'invalid_causal_cycle',
      expected_error_code: 'CAUSAL_CYCLE_DETECTED',
    },
    {
      id: 'mut-replay-receipt-id',
      category: 'replay-by-receipt-id mutation',
      seed_fixture: seeds[1].path,
      scenario: 'invalid_causal_receipt_replay_detected',
      expected_error_code: 'CAUSAL_RECEIPT_REPLAY_DETECTED',
    },
  ];

  const mutants = subset === 'full' ? allMutants : allMutants.slice(0, 4);

  const registryPath = path.join(
    repoRoot,
    'docs/specs/clawsig-protocol/REASON_CODE_REGISTRY.md'
  );
  const registryCodes = registryCodesFromMarkdown(
    await fs.readFile(registryPath, 'utf8')
  );

  const seedChecks = await Promise.all(
    seeds.map(async (seed) => ({
      id: seed.id,
      path: path.relative(repoRoot, seed.path),
      exists: await fileExists(seed.path),
    }))
  );

  const missingSeeds = seedChecks.filter((seed) => !seed.exists);

  const missingRegistryCodes = mutants
    .map((mutant) => mutant.expected_error_code)
    .filter((code) => !registryCodes.has(code));

  const genericCodes = mutants
    .map((mutant) => mutant.expected_error_code)
    .filter((code) => disallowedGenericCodes.has(code));

  const runStamp = isoStamp();
  const suiteName = `.causal-mutation-guardrail-${runStamp}-${process.pid}`;
  const suiteDir = path.join(protocolFixtureRoot, suiteName);

  await fs.mkdir(suiteDir, { recursive: true });

  const caseFiles = [];
  for (const mutant of mutants) {
    const filename = `${mutant.id}.v1.json`;
    caseFiles.push(filename);

    await writeJson(path.join(suiteDir, filename), {
      id: mutant.id,
      scenario: mutant.scenario,
      expected: {
        status: 'INVALID',
        error_code: mutant.expected_error_code,
      },
    });
  }

  await writeJson(path.join(suiteDir, 'manifest.v1.json'), {
    manifest_version: '1',
    suite: suiteName,
    cases: caseFiles,
  });

  const runTestsAllowed =
    missingSeeds.length === 0 &&
    missingRegistryCodes.length === 0 &&
    genericCodes.length === 0;

  let testExitCode = null;
  if (runTestsAllowed) {
    const result = spawnSync(
      'npm',
      ['test', '--', '--run', 'test/firewall-conformance.test.ts'],
      {
        cwd: path.join(repoRoot, 'services/clawverify'),
        stdio: 'inherit',
        env: {
          ...process.env,
          CLAWVERIFY_FIREWALL_FIXTURE_SUITE: suiteName,
        },
      }
    );

    testExitCode = result.status ?? 1;
  }

  const summary = {
    ok: runTestsAllowed && testExitCode === 0,
    subset,
    generated_fixture_suite: suiteName,
    generated_case_count: mutants.length,
    seed_checks: seedChecks,
    mutants,
    checks: {
      seeds_present: missingSeeds.length === 0,
      expected_codes_registered: missingRegistryCodes.length === 0,
      no_generic_expected_codes: genericCodes.length === 0,
      fixture_suite_passed: runTestsAllowed ? testExitCode === 0 : false,
    },
    failures: {
      missing_seeds: missingSeeds.map((seed) => seed.path),
      missing_registry_codes: [...new Set(missingRegistryCodes)],
      generic_expected_codes: [...new Set(genericCodes)],
      fixture_suite_exit_code: testExitCode,
    },
  };

  const outDir = path.join(
    repoRoot,
    'artifacts/ops/causal-mutation-guardrail',
    runStamp
  );
  const outPath = path.join(outDir, 'summary.json');
  await writeJson(outPath, summary);

  await fs.rm(suiteDir, { recursive: true, force: true });

  if (!summary.ok) {
    console.error('[clawverify-causal-mutation-guardrail] FAIL');
    console.error(JSON.stringify(summary, null, 2));
    process.exit(1);
  }

  console.log('[clawverify-causal-mutation-guardrail] PASS');
  console.log(
    JSON.stringify(
      {
        ok: true,
        subset,
        outPath: path.relative(repoRoot, outPath),
        generated_case_count: mutants.length,
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error('[clawverify-causal-mutation-guardrail] ERROR');
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exit(1);
});
