#!/usr/bin/env node
/**
 * Guardrail: validate real-usecase release evidence summary contract.
 *
 * Required matrix rows:
 * - staging marketplace-settlement
 * - staging marketplace-dispute
 * - prod marketplace-settlement
 * - prod marketplace-dispute
 *
 * For each row:
 * - verify_result.status === PASS
 * - canonical_artifacts.complete === true
 * - tracer.verification_status === PASS
 * - tracer.urm_hash_match === true
 * - required artifact files exist in run_dir
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');

const REQUIRED_SCENARIOS = [
  { env: 'staging', scenario: 'marketplace-settlement' },
  { env: 'staging', scenario: 'marketplace-dispute' },
  { env: 'prod', scenario: 'marketplace-settlement' },
  { env: 'prod', scenario: 'marketplace-dispute' },
];

const REQUIRED_ARTIFACTS = [
  'proof-bundle.json',
  'urm.json',
  'verify.json',
  'smoke.json',
];

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.resolve(ROOT, relativePath), 'utf8'));
}

function parseArgs(argv) {
  const idx = argv.indexOf('--summary');
  const explicitSummary = idx >= 0 ? argv[idx + 1] : null;
  return { explicitSummary };
}

function findLatestSummaryPath() {
  const root = path.resolve(ROOT, 'artifacts/e2e/real-usecases');
  if (!fs.existsSync(root)) {
    return null;
  }

  const entries = fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  const latest = entries.at(-1);
  if (!latest) return null;

  const summaryPath = path.join('artifacts/e2e/real-usecases', latest, 'summary.json');
  return fs.existsSync(path.resolve(ROOT, summaryPath)) ? summaryPath : null;
}

function scenarioKey(row) {
  return `${row.env}:${row.scenario}`;
}

function validate(summaryPath) {
  const summary = readJson(summaryPath);
  const issues = [];

  if (!Array.isArray(summary.matrix)) {
    issues.push('summary.matrix must be an array');
    return { ok: false, issues, summary };
  }

  const byKey = new Map(summary.matrix.map((row) => [scenarioKey(row), row]));

  for (const required of REQUIRED_SCENARIOS) {
    const key = scenarioKey(required);
    const row = byKey.get(key);

    if (!row) {
      issues.push(`missing scenario row: ${key}`);
      continue;
    }

    if (row.verify_result?.status !== 'PASS') {
      issues.push(`${key} verify_result.status must be PASS (got ${row.verify_result?.status ?? 'null'})`);
    }

    if (row.canonical_artifacts?.complete !== true) {
      issues.push(`${key} canonical_artifacts.complete must be true`);
    }

    if (row.tracer?.verification_status !== 'PASS') {
      issues.push(`${key} tracer.verification_status must be PASS`);
    }

    if (row.tracer?.urm_hash_match !== true) {
      issues.push(`${key} tracer.urm_hash_match must be true`);
    }

    const runDir = row.run_dir;
    if (typeof runDir !== 'string' || runDir.length === 0) {
      issues.push(`${key} run_dir must be a non-empty string`);
    } else {
      for (const file of REQUIRED_ARTIFACTS) {
        const full = path.resolve(ROOT, runDir, file);
        if (!fs.existsSync(full)) {
          issues.push(`${key} missing required artifact file: ${path.join(runDir, file)}`);
        }
      }
    }

    const tracePath = row.tracer?.path;
    if (typeof tracePath !== 'string' || !fs.existsSync(path.resolve(ROOT, tracePath))) {
      issues.push(`${key} missing tracer output file: ${tracePath ?? 'null'}`);
    }
  }

  return {
    ok: issues.length === 0,
    issues,
    summary,
  };
}

function run() {
  const { explicitSummary } = parseArgs(process.argv.slice(2));
  const summaryPath = explicitSummary ?? findLatestSummaryPath();

  if (!summaryPath) {
    const result = {
      ok: false,
      summary_path: null,
      issues: ['No real-usecase summary found. Pass --summary <path> or commit artifacts/e2e/real-usecases/<ts>/summary.json'],
    };
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = 1;
    return;
  }

  const validation = validate(summaryPath);

  const result = {
    ok: validation.ok,
    summary_path: summaryPath,
    checked_scenarios: REQUIRED_SCENARIOS.map((s) => scenarioKey(s)),
    issues: validation.issues,
  };

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

  if (!result.ok) {
    process.exitCode = 1;
  }
}

run();
