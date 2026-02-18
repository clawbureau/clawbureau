#!/usr/bin/env node
/**
 * Clawsig v0.2 package release-prep runner.
 *
 * - packs @clawbureau/schema, @clawbureau/clawverify-core, @clawbureau/clawverify-cli
 * - runs install-from-tarball sanity check in a clean temp project
 * - writes deterministic summary artifact
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

const ROOT = path.resolve(new URL('../..', import.meta.url).pathname);

const TARGETS = [
  {
    name: '@clawbureau/schema',
    dir: 'packages/schema',
    packageJson: 'packages/schema/package.json',
  },
  {
    name: '@clawbureau/clawverify-core',
    dir: 'packages/clawverify-core',
    packageJson: 'packages/clawverify-core/package.json',
  },
  {
    name: '@clawbureau/clawverify-cli',
    dir: 'packages/clawverify-cli',
    packageJson: 'packages/clawverify-cli/package.json',
  },
];

function isoStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function run(command, args, cwd, env = process.env) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
      env,
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

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

async function sha256Hex(filePath) {
  const data = await fs.readFile(filePath);
  return createHash('sha256').update(data).digest('hex');
}

async function packTarget(target, packDir) {
  const pkg = await readJson(path.join(ROOT, target.packageJson));
  const expectedVersion = String(pkg.version ?? '');

  if (pkg?.scripts && typeof pkg.scripts.build === 'string') {
    const buildRun = await run('npm', ['run', 'build'], path.join(ROOT, target.dir));
    if (buildRun.code !== 0) {
      throw new Error(
        `npm run build failed for ${target.name}: ${buildRun.stderr || buildRun.stdout}`,
      );
    }
  }

  const packRun = await run(
    'npm',
    ['pack', '--pack-destination', packDir],
    path.join(ROOT, target.dir),
  );

  if (packRun.code !== 0) {
    throw new Error(
      `npm pack failed for ${target.name}: ${packRun.stderr || packRun.stdout}`,
    );
  }

  const tarballName = packRun.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .at(-1);

  if (!tarballName) {
    throw new Error(`npm pack did not return a tarball name for ${target.name}`);
  }

  const tarballPath = path.join(packDir, tarballName);
  const hash = await sha256Hex(tarballPath);

  return {
    name: target.name,
    expected_version: expectedVersion,
    tarball_name: tarballName,
    tarball_path: tarballPath,
    sha256: hash,
    pack_stdout: packRun.stdout.trim(),
  };
}

async function main() {
  const outDir = path.join(
    ROOT,
    'artifacts/release/clawsig-v0.2-package-prep',
    isoStamp(),
  );
  const packDir = path.join(outDir, 'tarballs');

  await fs.mkdir(packDir, { recursive: true });

  const packed = [];
  for (const target of TARGETS) {
    packed.push(await packTarget(target, packDir));
  }

  const installDir = await fs.mkdtemp(path.join(os.tmpdir(), 'clawsig-v0-2-pack-smoke-'));

  const npmInit = await run('npm', ['init', '-y'], installDir);
  if (npmInit.code !== 0) {
    throw new Error(`npm init failed: ${npmInit.stderr || npmInit.stdout}`);
  }

  const installRun = await run(
    'npm',
    [
      'install',
      ...packed.map((p) => p.tarball_path),
    ],
    installDir,
  );

  if (installRun.code !== 0) {
    throw new Error(`npm install tarballs failed: ${installRun.stderr || installRun.stdout}`);
  }

  const installed = [];
  for (const item of packed) {
    const pkgPath = path.join(
      installDir,
      'node_modules',
      ...item.name.split('/'),
      'package.json',
    );
    const pkg = await readJson(pkgPath);
    installed.push({
      name: item.name,
      expected_version: item.expected_version,
      installed_version: String(pkg.version ?? ''),
      version_match: String(pkg.version ?? '') === item.expected_version,
    });
  }

  const cliVersionRun = await run(
    process.execPath,
    [
      path.join(installDir, 'node_modules', '@clawbureau', 'clawverify-cli', 'dist', 'cli.js'),
      'version',
    ],
    installDir,
  );

  const expectedCliVersion = packed.find((p) => p.name === '@clawbureau/clawverify-cli')?.expected_version ?? '0.2.0';
  const cliVersionOk =
    cliVersionRun.code === 0 &&
    cliVersionRun.stdout.includes(`clawverify ${expectedCliVersion}`);

  const summary = {
    run_at: new Date().toISOString(),
    out_dir: outDir,
    install_dir: installDir,
    package_targets: packed.map((p) => ({
      name: p.name,
      expected_version: p.expected_version,
      tarball_name: p.tarball_name,
      sha256: p.sha256,
    })),
    install_from_tarball: {
      command_ok: installRun.code === 0,
      installed,
    },
    cli_version_check: {
      ok: cliVersionOk,
      exit_code: cliVersionRun.code,
      stdout: cliVersionRun.stdout.trim(),
      stderr: cliVersionRun.stderr.trim(),
    },
  };

  const ok =
    summary.install_from_tarball.command_ok &&
    installed.every((entry) => entry.version_match) &&
    cliVersionOk;

  summary.ok = ok;

  await fs.writeFile(
    path.join(outDir, 'summary.json'),
    `${JSON.stringify(summary, null, 2)}\n`,
    'utf8',
  );

  process.stdout.write(
    `${JSON.stringify({ ok, out_dir: outDir }, null, 2)}\n`,
  );

  if (!ok) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exitCode = 1;
});
