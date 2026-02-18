#!/usr/bin/env node
/**
 * Clawsig Protocol v0.2 quickstart runner.
 *
 * Intended for integrators who want a compact, deterministic verification smoke
 * before running full protocol conformance.
 */

import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { spawn } from 'node:child_process';

const ROOT = path.resolve(new URL('../..', import.meta.url).pathname);

function isoStamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function readJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

function expectedReasonCodes(expected) {
  const reason = expected?.reason_code;
  if (reason === undefined) return null;
  if (typeof reason === 'string') return [reason];
  if (Array.isArray(reason)) return reason.filter((v) => typeof v === 'string');
  return null;
}

function subcommandForKind(kind) {
  if (kind === 'proof_bundle') return 'proof-bundle';
  if (kind === 'aggregate_bundle') return 'aggregate-bundle';
  if (kind === 'export_bundle') return 'export-bundle';
  if (kind === 'commit_sig') return 'commit-sig';
  throw new Error(`Unsupported quickstart vector kind: ${String(kind)}`);
}

function runCli(args, cwd) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, {
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

async function ensureCliBuilt(cliPath) {
  try {
    await fs.access(cliPath);
  } catch {
    throw new Error(
      `Missing ${cliPath}. Build clawverify-cli first: cd packages/clawverify-cli && npm run build`,
    );
  }
}

async function main() {
  const manifestPath = path.join(
    ROOT,
    'packages/schema/fixtures/quickstart/v0.2/manifest.v1.json',
  );
  const configPath = path.join(
    ROOT,
    'packages/schema/fixtures/protocol-conformance/clawverify.config.conformance.v1.json',
  );
  const cliPath = path.join(ROOT, 'packages/clawverify-cli/dist/cli.js');

  await ensureCliBuilt(cliPath);

  const manifest = await readJson(manifestPath);
  if (!isRecord(manifest) || manifest.manifest_version !== '1') {
    throw new Error('Invalid quickstart manifest: expected manifest_version=1');
  }

  const vectors = Array.isArray(manifest.vectors) ? manifest.vectors : [];

  const results = [];

  for (const vector of vectors) {
    const name = String(vector?.name ?? '');
    const kind = String(vector?.kind ?? '');
    const relPath = String(vector?.path ?? '');
    const expected = vector?.expected;

    const inputPath = path.join(ROOT, relPath);
    const subcommand = subcommandForKind(kind);

    const args = [cliPath, 'verify', subcommand, '--input', inputPath];
    if (kind !== 'commit_sig') {
      args.push('--config', configPath);
    }

    const startedAt = new Date().toISOString();
    const run = await runCli(args, ROOT);

    let parsed = null;
    let parseError = null;
    try {
      parsed = JSON.parse(run.stdout);
    } catch (err) {
      parseError = err instanceof Error ? err.message : String(err);
    }

    const expectedValid = Boolean(expected?.valid);
    const expectedCodes = expectedReasonCodes(expected);

    const gotStatus = parsed?.status;
    const gotReasonCode = parsed?.reason_code;
    const gotValid = gotStatus === 'PASS';

    const reasonOk =
      expectedCodes === null || expectedCodes.includes(gotReasonCode);

    const ok =
      parseError === null &&
      run.code === (expectedValid ? 0 : 1) &&
      gotValid === expectedValid &&
      reasonOk;

    results.push({
      name,
      kind,
      input_path: relPath,
      expected: {
        valid: expectedValid,
        reason_code: expectedCodes,
      },
      got: {
        exit_code: run.code,
        status: gotStatus,
        reason_code: gotReasonCode,
      },
      ok,
      started_at: startedAt,
      stderr: run.stderr ? run.stderr.slice(0, 2000) : undefined,
      parse_error: parseError ?? undefined,
    });
  }

  const passed = results.filter((r) => r.ok).length;
  const failed = results.length - passed;

  const summary = {
    manifest: {
      path: 'packages/schema/fixtures/quickstart/v0.2/manifest.v1.json',
      manifest_version: manifest.manifest_version,
      vector_count: results.length,
    },
    cli: {
      path: 'packages/clawverify-cli/dist/cli.js',
    },
    config: {
      path: 'packages/schema/fixtures/protocol-conformance/clawverify.config.conformance.v1.json',
    },
    results: {
      passed,
      failed,
      ok: failed === 0,
    },
    vectors: results,
    finished_at: new Date().toISOString(),
  };

  const outDir = path.join(
    ROOT,
    'artifacts/examples/clawsig-v0.2-quickstart',
    isoStamp(),
  );

  await fs.mkdir(outDir, { recursive: true });
  await fs.writeFile(
    path.join(outDir, 'summary.json'),
    `${JSON.stringify(summary, null, 2)}\n`,
    'utf8',
  );

  process.stdout.write(
    `${JSON.stringify({ ok: summary.results.ok, out_dir: outDir }, null, 2)}\n`,
  );

  if (!summary.results.ok) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exitCode = 1;
});
