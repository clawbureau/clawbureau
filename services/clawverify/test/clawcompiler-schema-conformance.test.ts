import fs from 'node:fs';
import path from 'node:path';

import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import { describe, expect, it } from 'vitest';

type ConformanceCase = {
  id: string;
  fixture: string;
  schema_id: string;
  expect_valid: boolean;
  expected_error_path?: string;
};

type ConformanceManifest = {
  manifest_version: string;
  suite: string;
  cases: ConformanceCase[];
};

function loadJson(filePath: string): any {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

const repoRoot = path.resolve(process.cwd(), '..', '..');
const schemaRoot = path.join(repoRoot, 'packages', 'schema', 'compliance');
const fixtureRoot = path.join(
  repoRoot,
  'packages',
  'schema',
  'fixtures',
  'protocol-conformance',
  'clawcompiler-compiled-evidence'
);

const narrativeSchema = loadJson(path.join(schemaRoot, 'compiled_evidence_narrative.v1.json'));
const reportSchema = loadJson(path.join(schemaRoot, 'compiled_evidence_report.v1.json'));
const envelopeSchema = loadJson(path.join(schemaRoot, 'compiled_evidence_report_envelope.v1.json'));
const manifest = loadJson(path.join(fixtureRoot, 'manifest.v1.json')) as ConformanceManifest;

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
ajv.addSchema(narrativeSchema);
ajv.addSchema(reportSchema);
ajv.addSchema(envelopeSchema);

describe('clawcompiler schema conformance fixtures', () => {
  it('has expected fixture manifest contract', () => {
    expect(manifest.manifest_version).toBe('1');
    expect(manifest.suite).toBe('clawcompiler-compiled-evidence');
    expect(Array.isArray(manifest.cases)).toBe(true);
    expect(manifest.cases.length).toBeGreaterThanOrEqual(7);
  });

  for (const testCase of manifest.cases) {
    it(testCase.id, () => {
      const validate = ajv.getSchema(testCase.schema_id);
      expect(validate, `Missing schema validator for ${testCase.schema_id}`).toBeTypeOf('function');

      const fixture = loadJson(path.join(fixtureRoot, testCase.fixture));
      const valid = validate!(fixture);
      expect(valid).toBe(testCase.expect_valid);

      if (!testCase.expect_valid) {
        const errors = validate!.errors ?? [];
        expect(errors.length).toBeGreaterThan(0);

        if (testCase.expected_error_path) {
          const hasExpectedPath = errors.some((err) => err.instancePath === testCase.expected_error_path);
          expect(hasExpectedPath).toBe(true);
        }
      }
    });
  }
});
