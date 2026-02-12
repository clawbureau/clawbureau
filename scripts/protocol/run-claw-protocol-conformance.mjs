#!/usr/bin/env node
/**
 * Claw Protocol conformance runner (offline).
 *
 * Executes the offline verifier CLI against a manifest of vectors and asserts
 * expected PASS/FAIL outcomes + deterministic reason codes.
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

async function readJson(p) {
  return JSON.parse(await fs.readFile(p, 'utf8'));
}

function runCli(args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      ...opts,
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

function expectedReasonCodes(expected) {
  const rc = expected?.reason_code;
  if (rc === undefined) return null;
  if (typeof rc === 'string') return [rc];
  if (Array.isArray(rc)) return rc.filter((x) => typeof x === 'string');
  return null;
}

async function main() {
  const manifestPath = path.join(
    ROOT,
    'packages/schema/fixtures/protocol-conformance/manifest.v1.json'
  );
  const configPath = path.join(
    ROOT,
    'packages/schema/fixtures/protocol-conformance/clawverify.config.conformance.v1.json'
  );
  const cliPath = path.join(ROOT, 'packages/clawverify-cli/dist/cli.js');

  const manifest = await readJson(manifestPath);
  if (!isRecord(manifest) || manifest.manifest_version !== '1') {
    throw new Error('Invalid manifest');
  }

  const vectors = Array.isArray(manifest.vectors) ? manifest.vectors : [];

  const results = [];

  for (const v of vectors) {
    const name = String(v?.name ?? '');
    const kind = String(v?.kind ?? '');
    const relPath = String(v?.path ?? '');
    const expected = v?.expected;

    const inputPath = path.join(ROOT, relPath);

    const sub =
      kind === 'proof_bundle'
        ? 'proof-bundle'
        : kind === 'commit_sig'
          ? 'commit-sig'
          : 'export-bundle';

    const args = [cliPath, 'verify', sub, '--input', inputPath];
    // commit-sig doesn't require a config file
    if (kind !== 'commit_sig') {
      args.push('--config', configPath);
    }

    const startedAt = new Date().toISOString();

    const run = await runCli(args, { cwd: ROOT });

    let parsed = null;
    let parseError = null;
    try {
      parsed = JSON.parse(run.stdout);
    } catch (err) {
      parseError = err instanceof Error ? err.message : String(err);
    }

    const gotStatus = parsed?.status;
    const gotReasonCode = parsed?.reason_code;

    const expectedValid = Boolean(expected?.valid);
    const gotValid = gotStatus === 'PASS';

    const reasonAllowlist = expectedReasonCodes(expected);
    const reasonOk =
      reasonAllowlist === null || reasonAllowlist.includes(gotReasonCode);

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
        reason_code: reasonAllowlist,
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
      path: 'packages/schema/fixtures/protocol-conformance/manifest.v1.json',
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
    'artifacts/conformance/claw-protocol',
    isoStamp()
  );

  await fs.mkdir(outDir, { recursive: true });
  await fs.writeFile(
    path.join(outDir, 'summary.json'),
    `${JSON.stringify(summary, null, 2)}\n`,
    'utf8'
  );

  process.stdout.write(
    `${JSON.stringify({ ok: summary.results.ok, out_dir: outDir }, null, 2)}\n`
  );

  if (!summary.results.ok) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack : String(err)}\n`);
  process.exitCode = 1;
});
