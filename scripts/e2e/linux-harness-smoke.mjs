#!/usr/bin/env node

import process from 'node:process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawn } from 'node:child_process';

const ROOT = resolve(new URL('../..', import.meta.url).pathname);

async function runBuild(packageDir) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn('npm', ['run', 'build'], {
      cwd: resolve(ROOT, packageDir),
      stdio: 'inherit',
      env: process.env,
    });

    child.on('error', rejectRun);
    child.on('close', (code) => {
      if (code === 0) resolveRun();
      else rejectRun(new Error(`Build failed for ${packageDir} with exit code ${String(code)}`));
    });
  });
}

async function ensureBuildArtifacts() {
  if (process.env.CLAWSIG_E2E_SKIP_BUILD === '1') {
    return;
  }

  await runBuild('packages/clawverify-cli');
  await runBuild('packages/clawsig-conformance');
}

async function loadHarnessMatrixModule() {
  const distPath = resolve(ROOT, 'packages/clawsig-conformance/dist/harness-matrix.js');
  return import(pathToFileURL(distPath).href);
}

async function main() {
  await ensureBuildArtifacts();

  const {
    runHarnessMatrix,
    formatHarnessMatrixReport,
  } = await loadHarnessMatrixModule();

  const requestedAgents = (process.env.CLAWSIG_E2E_LINUX_AGENTS || 'codex,gemini')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);

  const run = await runHarnessMatrix({
    rootDir: ROOT,
    resultsPath: '.clawsig/e2e-linux-results.json',
    includeLive: false,
    timeoutMs: 60_000,
    prompt: 'Say exactly: hello world',
    agents: requestedAgents,
  });

  process.stdout.write(`${formatHarnessMatrixReport(run)}\n`);
  process.stdout.write(`artifact: ${run.results_path}\n`);

  // Linux lane is currently a smoke/reporting gate.
  // It emits deterministic artifacts and pass/fail counts but does not hard-fail CI yet.
  process.exitCode = 0;
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exitCode = 1;
});
