#!/usr/bin/env node

import { execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '../..');

function run(command) {
  const out = execSync(command, { cwd: repoRoot, encoding: 'utf8' });
  return out.trim();
}

function getChangedFiles() {
  const base = process.env.SMOKE_CONTRACT_BASE?.trim();

  if (base) {
    try {
      const out = run(`git diff --name-only --diff-filter=ACMR origin/${base}...HEAD`);
      return out.split('\n').map((s) => s.trim()).filter(Boolean);
    } catch {
      // fallback below
    }
  }

  try {
    const out = run('git diff --name-only --diff-filter=ACMR HEAD~1...HEAD');
    return out.split('\n').map((s) => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function isSmokeScript(filePath) {
  if (!/^scripts\/poh\/smoke-.*\.mjs$/.test(filePath)) return false;
  if (filePath === 'scripts/poh/smoke-artifact-contract.mjs') return false;
  if (filePath === 'scripts/poh/smoke-artifact-contract.test.mjs') return false;
  return true;
}

function validateSmokeScript(filePath) {
  const full = path.resolve(repoRoot, filePath);
  const text = fs.readFileSync(full, 'utf8');

  const importsContract = text.includes('smoke-artifact-contract.mjs');
  const writesContract = /writeSmokeArtifactContract\s*\(/.test(text);

  const violations = [];
  if (!importsContract) {
    violations.push('missing import for smoke-artifact-contract.mjs');
  }
  if (!writesContract) {
    violations.push('missing writeSmokeArtifactContract(...) call');
  }

  return {
    file: filePath,
    ok: violations.length === 0,
    violations,
  };
}

function main() {
  const changed = getChangedFiles();
  const smokeChanged = changed.filter(isSmokeScript);

  if (smokeChanged.length === 0) {
    const result = {
      ok: true,
      checked: 0,
      message: 'No changed scripts/poh/smoke-*.mjs files in this diff.',
    };
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  const checks = smokeChanged.map(validateSmokeScript);
  const failed = checks.filter((c) => !c.ok);

  const result = {
    ok: failed.length === 0,
    checked: checks.length,
    checks,
  };

  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);

  if (failed.length > 0) {
    process.stderr.write(
      `\n[smoke-artifact-contract] FAIL: ${failed.length} smoke script(s) missing artifact-contract wiring.\n`
    );
    process.exitCode = 1;
  }
}

main();
