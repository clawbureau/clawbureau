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

  try {
    return await import(pathToFileURL(distPath).href);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(`Unable to load ${distPath}. Run builds first (or unset CLAWSIG_E2E_SKIP_BUILD). Details: ${detail}`);
  }
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

  // Linux strict lane is proxy-only by contract.
  // Codex base URL override remains opt-in via CLAWSIG_FORCE_BASE_URL_OVERRIDE=1.
  const run = await runHarnessMatrix({
    rootDir: ROOT,
    resultsPath: '.clawsig/e2e-linux-results.json',
    includeLive: false,
    timeoutMs: 60_000,
    prompt: 'Say exactly: hello world',
    agents: requestedAgents,
    layers: ['proxy'],
  });

  process.stdout.write(`${formatHarnessMatrixReport(run)}\n`);
  process.stdout.write(`artifact: ${run.results_path}\n`);

  const byId = new Map(run.results.map((r) => [r.id, r]));
  const requiredCaseIds = requestedAgents.map((agent) => `${agent}:mock:proxy`);

  const strictFailures = requiredCaseIds
    .map((id) => {
      const result = byId.get(id);

      if (!result) {
        return {
          id,
          code: 'AGENT_UNAVAILABLE',
          reason: 'required lane result missing (deterministic matrix contract violated)',
        };
      }

      if (result.status === 'PASS') {
        return null;
      }

      const reason =
        typeof result.reason === 'string' && result.reason.trim().length > 0
          ? result.reason.trim()
          : result.status;

      const code =
        result.status === 'SKIP' || reason.startsWith('AGENT_UNAVAILABLE:')
          ? 'AGENT_UNAVAILABLE'
          : 'PARITY_FAILURE';

      return { id, code, reason };
    })
    .filter(Boolean);

  if (strictFailures.length > 0) {
    process.stdout.write('strict lane failures:\n');
    for (const failure of strictFailures) {
      process.stdout.write(`- ${failure.id}: ${failure.code} (${failure.reason})\n`);
    }
    process.exitCode = 1;
    return;
  }

  process.exitCode = 0;
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exitCode = 1;
});
