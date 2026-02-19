#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const DEFAULT_OUTPUT_ROOT = 'artifacts/ops/clawsig-guarded-deploy';
const DEFAULT_MAX_RUN_REF_AGE_MINUTES = 180;

const SERVICES = {
  ledger: {
    key: 'ledger',
    dir: 'services/clawsig-ledger',
  },
  explorer: {
    key: 'explorer',
    dir: 'services/clawsig-explorer',
  },
};

function parseArgs(argv) {
  const args = {
    outputRoot: DEFAULT_OUTPUT_ROOT,
    maxRunRefAgeMinutes: DEFAULT_MAX_RUN_REF_AGE_MINUTES,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--output-root') {
      args.outputRoot = argv[i + 1] ?? DEFAULT_OUTPUT_ROOT;
      i += 1;
      continue;
    }

    if (arg === '--max-run-ref-age-minutes') {
      const parsed = Number.parseInt(argv[i + 1] ?? '', 10);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        throw new Error('Invalid --max-run-ref-age-minutes value');
      }
      args.maxRunRefAgeMinutes = parsed;
      i += 1;
      continue;
    }
  }

  return args;
}

function nowLabel() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function runCommand({
  name,
  cmd,
  args,
  cwd,
  outputDir,
}) {
  const rendered = [cmd, ...args].join(' ');
  const result = spawnSync(cmd, args, {
    cwd,
    env: process.env,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 20,
  });

  const stdout = result.stdout ?? '';
  const stderr = result.stderr ?? '';
  const exitCode = typeof result.status === 'number' ? result.status : 1;
  const ok = exitCode === 0;
  const logPath = path.join(outputDir, `${name}.log`);

  const logBody = [
    `$ (cwd=${cwd}) ${rendered}`,
    '',
    '--- stdout ---',
    stdout,
    '--- stderr ---',
    stderr,
    `--- exit_code=${exitCode} ---`,
  ].join('\n');

  writeFileSync(logPath, logBody);

  return {
    name,
    ok,
    exit_code: exitCode,
    command: rendered,
    cwd,
    log_path: logPath,
    stdout,
    stderr,
  };
}

function parseCurrentVersionFromDeploymentsJson(raw) {
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) return null;
    const first = parsed[0];
    const version = Array.isArray(first?.versions) ? first.versions[0] : null;
    return typeof version?.version_id === 'string' ? version.version_id : null;
  } catch {
    return null;
  }
}

function parseVersionIdFromDeployOutput(raw) {
  const matches = [...raw.matchAll(/Current Version ID:\s*([0-9a-f-]+)/gi)];
  if (matches.length === 0) return null;
  return matches[matches.length - 1]?.[1] ?? null;
}

function requireStepOk(step, code) {
  if (step.ok) return;
  throw new Error(code);
}

function getCurrentVersion(service, envName, outputDir) {
  const envArgs = envName === 'staging' ? ['--env', 'staging'] : [];
  const step = runCommand({
    name: `${service.key}-${envName}-current-version`,
    cmd: 'npx',
    args: ['wrangler', 'deployments', 'list', '--json', ...envArgs],
    cwd: service.dir,
    outputDir,
  });

  requireStepOk(step, `CURRENT_VERSION_LOOKUP_FAILED_${service.key.toUpperCase()}_${envName.toUpperCase()}`);

  const versionId = parseCurrentVersionFromDeploymentsJson(step.stdout);
  if (!versionId) {
    throw new Error(`CURRENT_VERSION_PARSE_FAILED_${service.key.toUpperCase()}_${envName.toUpperCase()}`);
  }

  return { step, version_id: versionId };
}

function deployService(service, envName, outputDir) {
  const envArgs = envName === 'staging' ? ['--env', 'staging'] : [];
  const step = runCommand({
    name: `${service.key}-${envName}-deploy`,
    cmd: 'npx',
    args: ['wrangler', 'deploy', ...envArgs],
    cwd: service.dir,
    outputDir,
  });

  requireStepOk(step, `DEPLOY_FAILED_${service.key.toUpperCase()}_${envName.toUpperCase()}`);

  const versionId = parseVersionIdFromDeployOutput(`${step.stdout}\n${step.stderr}`);
  if (!versionId) {
    throw new Error(`DEPLOY_VERSION_PARSE_FAILED_${service.key.toUpperCase()}_${envName.toUpperCase()}`);
  }

  return {
    step,
    version_id: versionId,
  };
}

function rollbackService(service, envName, versionId, outputDir) {
  const envArgs = envName === 'staging' ? ['--env', 'staging'] : [];
  return runCommand({
    name: `${service.key}-${envName}-rollback-${versionId}`,
    cmd: 'npx',
    args: ['wrangler', 'rollback', versionId, '-y', ...envArgs],
    cwd: service.dir,
    outputDir,
  });
}

function runSeed(envName, outputDir, tsDir) {
  const seedRoot = path.join(tsDir, `canary-${envName}`);
  return runCommand({
    name: `seed-${envName}`,
    cmd: 'node',
    args: ['scripts/ops/seed-clawsig-canary-run.mjs', '--env', envName, '--output-root', seedRoot],
    cwd: process.cwd(),
    outputDir,
  });
}

function runSmoke(envName, maxRunRefAgeMinutes, outputDir, tsDir) {
  const smokeRoot = path.join(tsDir, `synthetic-${envName}`);
  return runCommand({
    name: `smoke-${envName}`,
    cmd: 'node',
    args: [
      'scripts/ops/smoke-clawsig-surface.mjs',
      '--env', envName,
      '--max-run-ref-age-minutes', String(maxRunRefAgeMinutes),
      '--output-root', smokeRoot,
    ],
    cwd: process.cwd(),
    outputDir,
  });
}

function stepSummary(step) {
  if (!step) return null;
  return {
    ok: step.ok,
    exit_code: step.exit_code,
    command: step.command,
    cwd: step.cwd,
    log_path: step.log_path,
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const ts = nowLabel();
  const outputDir = path.join(args.outputRoot, ts);
  mkdirSync(outputDir, { recursive: true });

  const summary = {
    ok: false,
    generated_at: new Date().toISOString(),
    output_dir: outputDir,
    max_run_ref_age_minutes: args.maxRunRefAgeMinutes,
    baseline_versions: {
      staging: {},
      prod: {},
    },
    deployed_versions: {
      staging: {},
      prod: {},
    },
    staging: {
      deploy: {},
      canary_seed: null,
      synthetic_smoke: null,
    },
    prod: {
      deploy: {},
      canary_seed: null,
      synthetic_smoke: null,
    },
    rollback: {
      attempted: false,
      ok: null,
      reason_code: null,
      steps: [],
      post_rollback_smoke: null,
    },
    failure_reason_code: null,
  };

  let exitCode = 0;

  try {
    for (const [serviceKey, service] of Object.entries(SERVICES)) {
      const stagingCurrent = getCurrentVersion(service, 'staging', outputDir);
      const prodCurrent = getCurrentVersion(service, 'prod', outputDir);
      summary.baseline_versions.staging[serviceKey] = stagingCurrent.version_id;
      summary.baseline_versions.prod[serviceKey] = prodCurrent.version_id;
    }

    for (const [serviceKey, service] of Object.entries(SERVICES)) {
      const deployed = deployService(service, 'staging', outputDir);
      summary.deployed_versions.staging[serviceKey] = deployed.version_id;
      summary.staging.deploy[serviceKey] = stepSummary(deployed.step);
    }

    const stagingSeed = runSeed('staging', outputDir, outputDir);
    summary.staging.canary_seed = stepSummary(stagingSeed);
    requireStepOk(stagingSeed, 'STAGING_CANARY_SEED_FAILED');

    const stagingSmoke = runSmoke('staging', args.maxRunRefAgeMinutes, outputDir, outputDir);
    summary.staging.synthetic_smoke = stepSummary(stagingSmoke);
    requireStepOk(stagingSmoke, 'STAGING_SYNTHETIC_SMOKE_FAILED');

    try {
      for (const [serviceKey, service] of Object.entries(SERVICES)) {
        const deployed = deployService(service, 'prod', outputDir);
        summary.deployed_versions.prod[serviceKey] = deployed.version_id;
        summary.prod.deploy[serviceKey] = stepSummary(deployed.step);
      }
    } catch (error) {
      summary.rollback.attempted = true;
      summary.rollback.reason_code = 'PROD_DEPLOY_FAILED';
      for (const [serviceKey, service] of Object.entries(SERVICES)) {
        const baselineVersion = summary.baseline_versions.prod[serviceKey];
        if (typeof baselineVersion !== 'string' || baselineVersion.length === 0) continue;
        const rollbackStep = rollbackService(service, 'prod', baselineVersion, outputDir);
        summary.rollback.steps.push(stepSummary(rollbackStep));
      }
      const allRollbackOk = summary.rollback.steps.every((step) => step?.ok === true);
      summary.rollback.ok = allRollbackOk;
      throw error;
    }

    const prodSeed = runSeed('prod', outputDir, outputDir);
    summary.prod.canary_seed = stepSummary(prodSeed);
    requireStepOk(prodSeed, 'PROD_CANARY_SEED_FAILED');

    const prodSmoke = runSmoke('prod', args.maxRunRefAgeMinutes, outputDir, outputDir);
    summary.prod.synthetic_smoke = stepSummary(prodSmoke);

    if (!prodSmoke.ok) {
      summary.rollback.attempted = true;
      summary.rollback.reason_code = 'PROD_SYNTHETIC_SMOKE_FAILED';

      for (const [serviceKey, service] of Object.entries(SERVICES)) {
        const baselineVersion = summary.baseline_versions.prod[serviceKey];
        if (typeof baselineVersion !== 'string' || baselineVersion.length === 0) continue;
        const rollbackStep = rollbackService(service, 'prod', baselineVersion, outputDir);
        summary.rollback.steps.push(stepSummary(rollbackStep));
      }

      const postRollbackSmoke = runSmoke('prod', args.maxRunRefAgeMinutes, outputDir, outputDir);
      summary.rollback.post_rollback_smoke = stepSummary(postRollbackSmoke);

      const allRollbackOk = summary.rollback.steps.every((step) => step?.ok === true);
      summary.rollback.ok = allRollbackOk && postRollbackSmoke.ok;
      throw new Error('PROD_SYNTHETIC_SMOKE_FAILED');
    }

    summary.ok = true;
  } catch (error) {
    summary.ok = false;
    summary.failure_reason_code = String(error instanceof Error ? error.message : error);
    exitCode = 1;
  } finally {
    writeFileSync(path.join(outputDir, 'summary.json'), JSON.stringify(summary, null, 2));
    console.log(JSON.stringify(summary, null, 2));
    if (exitCode !== 0) {
      process.exitCode = exitCode;
    }
  }
}

main();
