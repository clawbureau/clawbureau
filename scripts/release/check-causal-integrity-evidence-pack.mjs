#!/usr/bin/env node
/**
 * Guardrail: validate causal-integrity burn-in evidence contract.
 *
 * Contract:
 * - summary exists (explicit --summary or latest under artifacts/ops/causal-integrity-burnin)
 * - summary freshness <= max-age-minutes
 * - summary.ok === true
 * - required mode + mutation_subset match requested values
 * - required burn-in steps are present and PASS (ok=true, exit_code=0)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../..');

const REQUIRED_STEP_IDS = [
  'reason-code-parity',
  'causal-cldd-conformance',
  'causal-hardening-conformance',
  'causal-connectivity-conformance',
  'causal-clock-conformance',
  'aggregate-causal-conformance',
  'causal-mutation-guardrail',
];

function parseArgs(argv) {
  const getValue = (flag) => {
    const idx = argv.indexOf(flag);
    return idx >= 0 ? argv[idx + 1] : undefined;
  };

  const getValueEq = (flag) => {
    const hit = argv.find((arg) => arg.startsWith(`${flag}=`));
    return hit ? hit.slice(flag.length + 1) : undefined;
  };

  const summary = getValue('--summary') ?? getValueEq('--summary');
  const maxAgeRaw =
    getValue('--max-age-minutes') ?? getValueEq('--max-age-minutes');
  const requireMode =
    getValue('--require-mode') ?? getValueEq('--require-mode') ?? 'quick';
  const requireMutationSubset =
    getValue('--require-mutation-subset') ??
    getValueEq('--require-mutation-subset') ??
    'quick';

  const maxAgeMinutes =
    maxAgeRaw !== undefined && Number.isFinite(Number(maxAgeRaw))
      ? Number(maxAgeRaw)
      : 180;

  return {
    summary,
    maxAgeMinutes,
    requireMode,
    requireMutationSubset,
  };
}

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.resolve(ROOT, relativePath), 'utf8'));
}

function findLatestSummaryPath() {
  const root = path.resolve(ROOT, 'artifacts/ops/causal-integrity-burnin');
  if (!fs.existsSync(root)) {
    return null;
  }

  const dirs = fs
    .readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  const latest = dirs.at(-1);
  if (!latest) return null;

  const summaryPath = path.join(
    'artifacts/ops/causal-integrity-burnin',
    latest,
    'summary.json'
  );

  return fs.existsSync(path.resolve(ROOT, summaryPath)) ? summaryPath : null;
}

function validateSummary(summaryPath, opts) {
  const issues = [];
  const summary = readJson(summaryPath);

  const fullSummaryPath = path.resolve(ROOT, summaryPath);
  const stat = fs.statSync(fullSummaryPath);
  const ageMs = Date.now() - stat.mtimeMs;
  const maxAgeMs = opts.maxAgeMinutes * 60_000;

  if (!Number.isFinite(opts.maxAgeMinutes) || opts.maxAgeMinutes <= 0) {
    issues.push('max-age-minutes must be a positive number');
  } else if (ageMs > maxAgeMs) {
    issues.push(
      `summary is stale: age ${Math.round(ageMs / 1000)}s exceeds max ${Math.round(maxAgeMs / 1000)}s`
    );
  }

  if (summary.ok !== true) {
    issues.push(`summary.ok must be true (got ${String(summary.ok)})`);
  }

  if (typeof opts.requireMode === 'string' && opts.requireMode.length > 0) {
    if (summary.mode !== opts.requireMode) {
      issues.push(`summary.mode must be ${opts.requireMode} (got ${String(summary.mode)})`);
    }
  }

  if (
    typeof opts.requireMutationSubset === 'string' &&
    opts.requireMutationSubset.length > 0
  ) {
    if (summary.mutation_subset !== opts.requireMutationSubset) {
      issues.push(
        `summary.mutation_subset must be ${opts.requireMutationSubset} (got ${String(
          summary.mutation_subset
        )})`
      );
    }
  }

  if (!Array.isArray(summary.steps)) {
    issues.push('summary.steps must be an array');
    return {
      ok: false,
      issues,
      summary,
      age_minutes: ageMs / 60_000,
    };
  }

  const byId = new Map(summary.steps.map((step) => [step?.id, step]));

  for (const stepId of REQUIRED_STEP_IDS) {
    const step = byId.get(stepId);
    if (!step) {
      issues.push(`missing required burn-in step: ${stepId}`);
      continue;
    }

    if (step.ok !== true) {
      issues.push(`required step ${stepId} did not pass (ok=${String(step.ok)})`);
    }

    if (step.exit_code !== 0) {
      issues.push(
        `required step ${stepId} exit_code must be 0 (got ${String(step.exit_code)})`
      );
    }
  }

  if (
    typeof summary.step_count_expected === 'number' &&
    summary.step_count_expected < REQUIRED_STEP_IDS.length
  ) {
    issues.push(
      `summary.step_count_expected must be >= ${REQUIRED_STEP_IDS.length} (got ${summary.step_count_expected})`
    );
  }

  return {
    ok: issues.length === 0,
    issues,
    summary,
    age_minutes: ageMs / 60_000,
  };
}

function run() {
  const opts = parseArgs(process.argv.slice(2));
  const summaryPath = opts.summary ?? findLatestSummaryPath();

  if (!summaryPath) {
    const result = {
      ok: false,
      summary_path: null,
      checked_steps: REQUIRED_STEP_IDS,
      issues: [
        'No causal-integrity burn-in summary found. Pass --summary <path> or generate artifacts/ops/causal-integrity-burnin/<timestamp>/summary.json',
      ],
    };
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.exitCode = 1;
    return;
  }

  const validation = validateSummary(summaryPath, opts);

  const result = {
    ok: validation.ok,
    summary_path: summaryPath,
    max_age_minutes: opts.maxAgeMinutes,
    summary_age_minutes: Number(validation.age_minutes.toFixed(2)),
    required_mode: opts.requireMode,
    required_mutation_subset: opts.requireMutationSubset,
    checked_steps: REQUIRED_STEP_IDS,
    issues: validation.issues,
  };

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

  if (!result.ok) {
    process.exitCode = 1;
  }
}

run();
