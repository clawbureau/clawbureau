#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '../../../../');

function base64Url(input) {
  return input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function hashJsonB64u(value) {
  const digest = createHash('sha256').update(JSON.stringify(value)).digest('base64');
  return base64Url(digest);
}

function run(command, args, cwd) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (d) => {
      stdout += String(d);
    });

    child.stderr.on('data', (d) => {
      stderr += String(d);
    });

    child.on('close', (code) => {
      resolve({ code: code ?? 0, stdout, stderr });
    });
  });
}

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function ensureVerifierBuilt() {
  const coreDist = path.join(ROOT, 'packages/clawverify-core/dist/index.js');
  const cliDist = path.join(ROOT, 'packages/clawverify-cli/dist/cli.js');

  if ((await fileExists(coreDist)) && (await fileExists(cliDist))) {
    return;
  }

  const coreDir = path.join(ROOT, 'packages/clawverify-core');
  const cliDir = path.join(ROOT, 'packages/clawverify-cli');

  let step = await run('npm', ['ci'], coreDir);
  if (step.code !== 0) {
    throw new Error(`npm ci failed in packages/clawverify-core: ${step.stderr || step.stdout}`);
  }

  step = await run('npm', ['run', 'build'], coreDir);
  if (step.code !== 0) {
    throw new Error(`npm run build failed in packages/clawverify-core: ${step.stderr || step.stdout}`);
  }

  step = await run('npm', ['ci'], cliDir);
  if (step.code !== 0) {
    throw new Error(`npm ci failed in packages/clawverify-cli: ${step.stderr || step.stdout}`);
  }

  step = await run('npm', ['run', 'build'], cliDir);
  if (step.code !== 0) {
    throw new Error(`npm run build failed in packages/clawverify-cli: ${step.stderr || step.stdout}`);
  }
}

function makeSampleUrm({ packName, proofBundle }) {
  const bundlePayload = proofBundle?.payload ?? {};
  const bundleId = String(bundlePayload.bundle_id ?? `${packName}-bundle`);
  const runId = `run_${packName.replace(/[^a-z0-9]+/gi, '_')}`;
  const issuedAt = new Date().toISOString();

  const urm = {
    urm_version: '1',
    urm_id: `urm_${packName.replace(/[^a-z0-9]+/gi, '_')}`,
    run_id: runId,
    agent_did: String(bundlePayload.agent_did ?? 'did:key:z6MktzmKpfCNcKSUp7qzTrZK3c89QFvhgmK7V1GXxMH9m8XW'),
    issued_at: issuedAt,
    harness: {
      id: `integration-${packName}`,
      version: '1.0.0',
      runtime: `node/${process.version}`,
      metadata: {
        fixture_bundle_id: bundleId,
      },
    },
    inputs: [
      {
        type: 'fixture_bundle',
        uri: `docs/examples/integrations/${packName}`,
      },
    ],
    outputs: [
      {
        type: 'verification_output',
        path: 'verify.json',
      },
    ],
    proof_bundle_hash_b64u: hashJsonB64u(proofBundle),
    metadata: {
      note: 'starter-pack sample URM sidecar',
      applicable: true,
    },
  };

  return urm;
}

export async function runIntegrationPack(options) {
  const {
    packName,
    fixturePath,
    description,
    outputDir = path.join('artifacts', 'examples', 'integrations', packName),
  } = options;

  if (!packName || !fixturePath) {
    throw new Error('packName and fixturePath are required');
  }

  await ensureVerifierBuilt();

  const fixtureFullPath = path.resolve(ROOT, fixturePath);
  const fixtureRaw = await fs.readFile(fixtureFullPath, 'utf8');
  const fixture = JSON.parse(fixtureRaw);

  const outDir = path.resolve(ROOT, outputDir);
  await fs.mkdir(outDir, { recursive: true });

  const proofBundlePath = path.join(outDir, 'proof-bundle.json');
  await fs.writeFile(proofBundlePath, `${JSON.stringify(fixture, null, 2)}\n`, 'utf8');

  const urm = makeSampleUrm({ packName, proofBundle: fixture });
  const urmPath = path.join(outDir, 'urm.json');
  await fs.writeFile(urmPath, `${JSON.stringify(urm, null, 2)}\n`, 'utf8');

  const cliPath = path.join(ROOT, 'packages/clawverify-cli/dist/cli.js');
  const configPath = path.join(
    ROOT,
    'packages/schema/fixtures/protocol-conformance/clawverify.config.conformance.v1.json'
  );

  const verifyRun = await run(
    process.execPath,
    [
      cliPath,
      'verify',
      'proof-bundle',
      '--input',
      proofBundlePath,
      '--config',
      configPath,
      '--urm',
      urmPath,
    ],
    ROOT
  );

  let verifyJson;
  try {
    verifyJson = JSON.parse(verifyRun.stdout);
  } catch {
    verifyJson = {
      status: 'ERROR',
      reason_code: 'PARSE_ERROR',
      reason: 'Could not parse verifier output as JSON',
      stdout: verifyRun.stdout,
      stderr: verifyRun.stderr,
    };
  }

  const verifyPath = path.join(outDir, 'verify.json');
  await fs.writeFile(verifyPath, `${JSON.stringify(verifyJson, null, 2)}\n`, 'utf8');

  const ok = verifyRun.code === 0 && verifyJson?.status === 'PASS';
  const smoke = {
    ok,
    pack: packName,
    description,
    fixture_path: fixturePath,
    command: `node packages/clawverify-cli/dist/cli.js verify proof-bundle --input ${outputDir}/proof-bundle.json --config packages/schema/fixtures/protocol-conformance/clawverify.config.conformance.v1.json --urm ${outputDir}/urm.json`,
    verification: {
      exit_code: verifyRun.code,
      status: verifyJson?.status,
      reason_code: verifyJson?.reason_code,
      reason: verifyJson?.reason,
    },
    generated_at: new Date().toISOString(),
  };

  const smokePath = path.join(outDir, 'smoke.json');
  await fs.writeFile(smokePath, `${JSON.stringify(smoke, null, 2)}\n`, 'utf8');

  process.stdout.write(
    `${JSON.stringify({ ok, out_dir: outDir, files: ['proof-bundle.json', 'urm.json', 'verify.json', 'smoke.json'] }, null, 2)}\n`
  );

  if (!ok) {
    process.exitCode = 1;
  }

  return { ok, outDir, smoke, verifyJson };
}
