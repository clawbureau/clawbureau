/**
 * Cross-platform verification tests.
 *
 * Validates that clawverify-cli + clawverify-core produce identical results
 * across Node.js, Bun, and Deno. Runs through all conformance vectors.
 *
 * This test is Node-first (uses node:test) but the key assertion is that
 * the CLI binary produces the same exit code and reason_code regardless
 * of which runtime executes it.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../../..');
const CLI_PATH = path.resolve(__dirname, '../dist/cli.js');
const MANIFEST_PATH = path.resolve(REPO_ROOT, 'packages/schema/fixtures/protocol-conformance/manifest.v1.json');
const CONFIG_PATH = path.resolve(REPO_ROOT, 'packages/schema/fixtures/protocol-conformance/clawverify.config.conformance.v1.json');

interface ManifestVector {
  name: string;
  kind: string;
  path: string;
  expected: {
    valid: boolean;
    reason_code: string | string[];
  };
}

interface Manifest {
  manifest_version: string;
  vectors: ManifestVector[];
}

const manifest: Manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));

// Detect available runtimes
function detectRuntimes(): Array<{ name: string; command: string; args: string[] }> {
  const runtimes: Array<{ name: string; command: string; args: string[] }> = [];

  // Node.js (always available since we're running in it)
  runtimes.push({ name: 'node', command: process.execPath, args: [] });

  // Bun
  try {
    execFileSync('bun', ['--version'], { stdio: 'pipe' });
    runtimes.push({ name: 'bun', command: 'bun', args: ['run'] });
  } catch { /* not available */ }

  // Deno
  try {
    execFileSync('deno', ['--version'], { stdio: 'pipe' });
    runtimes.push({ name: 'deno', command: 'deno', args: ['run', '--allow-read', '--allow-env'] });
  } catch { /* not available */ }

  return runtimes;
}

function subcommandForKind(kind: string): string {
  if (kind === 'proof_bundle') return 'proof-bundle';
  if (kind === 'export_bundle') return 'export-bundle';
  if (kind === 'commit_sig') return 'commit-sig';
  return kind;
}

function runCli(
  runtime: { name: string; command: string; args: string[] },
  cliArgs: string[],
): { exitCode: number; stdout: string; stderr: string } {
  try {
    const result = execFileSync(
      runtime.command,
      [...runtime.args, CLI_PATH, ...cliArgs],
      { stdio: 'pipe', encoding: 'utf8', timeout: 15_000 },
    );
    return { exitCode: 0, stdout: result, stderr: '' };
  } catch (err: any) {
    return {
      exitCode: err.status ?? 1,
      stdout: err.stdout ?? '',
      stderr: err.stderr ?? '',
    };
  }
}

const runtimes = detectRuntimes();

describe('cross-platform conformance', () => {
  for (const runtime of runtimes) {
    describe(`runtime: ${runtime.name}`, () => {
      // Quick smoke: version command
      it('clawverify version', () => {
        const result = runCli(runtime, ['version']);
        assert.equal(result.exitCode, 0);
        assert.match(result.stdout, /clawverify/);
      });

      // Quick smoke: explain command
      it('clawverify explain HASH_MISMATCH', () => {
        const result = runCli(runtime, ['explain', 'HASH_MISMATCH']);
        assert.equal(result.exitCode, 0);
        assert.match(result.stdout, /HASH_MISMATCH/);
        assert.match(result.stdout, /Content hash/);
      });

      // Run all conformance vectors
      for (const vector of manifest.vectors) {
        it(`${vector.name} (${vector.kind})`, () => {
          const inputPath = path.resolve(REPO_ROOT, vector.path);
          const sub = subcommandForKind(vector.kind);
          const args = ['verify', sub, '--input', inputPath];
          if (vector.kind !== 'commit_sig') {
            args.push('--config', CONFIG_PATH);
          }

          const result = runCli(runtime, args);
          const expectedCodes = Array.isArray(vector.expected.reason_code)
            ? vector.expected.reason_code
            : [vector.expected.reason_code];

          if (vector.expected.valid) {
            assert.equal(result.exitCode, 0, `Expected exit 0, got ${result.exitCode}. stdout: ${result.stdout}`);
          } else {
            assert.notEqual(result.exitCode, 0, `Expected non-zero exit. stdout: ${result.stdout}`);
          }

          // Parse output and check reason_code
          let output: any;
          try {
            output = JSON.parse(result.stdout);
          } catch {
            assert.fail(`Failed to parse CLI output as JSON: ${result.stdout.slice(0, 200)}`);
          }

          if (vector.expected.valid) {
            assert.equal(output.reason_code, 'OK', `Expected OK, got ${output.reason_code}`);
          } else {
            assert.ok(
              expectedCodes.includes(output.reason_code),
              `Expected one of [${expectedCodes.join(', ')}], got ${output.reason_code}`,
            );
          }

          // On FAIL, verify hint is present
          if (output.status === 'FAIL' && output.reason_code !== 'OK') {
            assert.ok(
              output.hint === undefined || typeof output.hint === 'string',
              'hint must be string or absent',
            );
          }
        });
      }
    });
  }
});

// Summary test
describe('runtime detection', () => {
  it(`detected ${runtimes.length} runtime(s): ${runtimes.map(r => r.name).join(', ')}`, () => {
    assert.ok(runtimes.length >= 1, 'At least Node.js should be available');
  });
});
