#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../../..');

function run(command, options = {}) {
  const output = execSync(command, {
    cwd: repoRoot,
    encoding: options.stdio === 'inherit' ? undefined : 'utf8',
    stdio: options.stdio ?? 'pipe',
  });

  if (typeof output === 'string') {
    return output.trim();
  }

  if (output instanceof Buffer) {
    return output.toString('utf8').trim();
  }

  return '';
}

function fail(message) {
  console.error(`\n[clawverify-schema-drift] FAIL: ${message}`);
  process.exit(1);
}

function assertFileContains(filePath, snippet, label) {
  const content = fs.readFileSync(filePath, 'utf8');
  if (!content.includes(snippet)) {
    fail(`${label} missing required snippet: ${snippet}`);
  }
}

function getChangedFiles() {
  const base = process.env.SCHEMA_DRIFT_BASE?.trim();

  if (base) {
    try {
      const out = run(`git diff --name-only --diff-filter=ACMR origin/${base}...HEAD`);
      return out.split('\n').map((s) => s.trim()).filter(Boolean);
    } catch {
      // fall through to local diff
    }
  }

  try {
    const out = run('git diff --name-only --diff-filter=ACMR HEAD~1...HEAD');
    return out.split('\n').map((s) => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

const generatedPath = path.resolve(
  repoRoot,
  'services/clawverify/src/schema-validators.generated.ts'
);
const schemaValidationPath = path.resolve(
  repoRoot,
  'services/clawverify/src/schema-validation.ts'
);
const schemaRegistryPath = path.resolve(
  repoRoot,
  'services/clawverify/src/schema-registry.ts'
);
const contractTestPath = path.resolve(
  repoRoot,
  'services/clawverify/test/schema-runtime-contract.test.ts'
);

const requiredGeneratedValidators = [
  'validateVirV2',
  'validateVirEnvelopeV2',
  'validateWebReceiptEnvelopeV1',
  'validateCoverageAttestationEnvelopeV1',
  'validateBinarySemanticEvidenceEnvelopeV1',
  'validateProofBundleEnvelopeV1',
  'validateToolReceiptV2',
  'validateToolReceiptEnvelopeV2',
  'validateAggregateBundleEnvelopeV1',
];

for (const symbol of requiredGeneratedValidators) {
  assertFileContains(
    generatedPath,
    `export const ${symbol}`,
    'schema-validators.generated.ts'
  );
}

const requiredSchemaValidationExports = [
  'export function validateVirV2',
  'export function validateVirEnvelopeV2',
  'export function validateWebReceiptEnvelopeV1',
  'export function validateCoverageAttestationEnvelopeV1',
  'export function validateBinarySemanticEvidenceEnvelopeV1',
  'export function validateProofBundleEnvelopeV1',
];

for (const symbol of requiredSchemaValidationExports) {
  assertFileContains(schemaValidationPath, symbol, 'schema-validation.ts');
}

const requiredAllowlistEntries = [
  "schema_id: 'vir_receipt'",
  "schema_id: 'web_receipt'",
  "schema_id: 'coverage_attestation'",
  "schema_id: 'binary_semantic_evidence'",
  "schema_id: 'proof_bundle'",
  "schema_id: 'tool_receipt'",
  "schema_id: 'tool_receipt_envelope'",
  "schema_id: 'aggregate_bundle'",
  "schema_id: 'aggregate_bundle_envelope'",
];

for (const snippet of requiredAllowlistEntries) {
  assertFileContains(schemaRegistryPath, snippet, 'schema-registry.ts');
}

if (!fs.existsSync(contractTestPath)) {
  fail('Missing contract test: services/clawverify/test/schema-runtime-contract.test.ts');
}

assertFileContains(contractTestPath, 'web_receipts', 'schema-runtime-contract.test.ts');
assertFileContains(contractTestPath, 'coverage_attestations', 'schema-runtime-contract.test.ts');
assertFileContains(contractTestPath, 'binary_semantic_evidence_attestations', 'schema-runtime-contract.test.ts');
assertFileContains(contractTestPath, 'vir_receipts', 'schema-runtime-contract.test.ts');
assertFileContains(contractTestPath, 'span_id', 'schema-runtime-contract.test.ts');

// Regeneration guard: if running the generator mutates the generated file, fail.
const generatedBefore = fs.readFileSync(generatedPath, 'utf8');
run('node services/clawverify/scripts/generate-schema-validators.mjs', { stdio: 'inherit' });
const generatedAfter = fs.readFileSync(generatedPath, 'utf8');

if (generatedBefore !== generatedAfter) {
  fail(
    'schema-validators.generated.ts is out of date. Run: node services/clawverify/scripts/generate-schema-validators.mjs and commit the result.'
  );
}

// If schema contract files changed (excluding fixture-only updates),
// runtime/tests must also change in the same patch.
const changedFiles = getChangedFiles();
const schemaContractChanged = changedFiles.some(
  (f) =>
    f.startsWith('packages/schema/') &&
    !f.startsWith('packages/schema/fixtures/')
);

if (schemaContractChanged) {
  const runtimeTouched = changedFiles.some(
    (f) =>
      f.startsWith('services/clawverify/src/') ||
      f.startsWith('services/clawverify/test/') ||
      f === 'services/clawverify/scripts/generate-schema-validators.mjs' ||
      f === 'services/clawverify/scripts/check-schema-runtime-sync.mjs' ||
      f === '.github/workflows/clawverify-schema-drift.yml'
  );

  if (!runtimeTouched) {
    fail(
      'Schema contract files changed without corresponding clawverify runtime/test updates. Update schema validation/runtime/tests in the same PR.'
    );
  }
}

console.log('[clawverify-schema-drift] PASS');
