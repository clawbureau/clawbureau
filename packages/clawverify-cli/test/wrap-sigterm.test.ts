/**
 * Test: clawsig wrap SIGTERM handling
 *
 * Verifies that when the wrap process receives SIGTERM (e.g. from
 * interactive_shell autoExitOnQuiet, Docker, systemd), the child
 * process is terminated gracefully and the proof bundle is still
 * compiled and written to disk.
 *
 * This is a regression test for the bug where SIGTERM killed the
 * parent process immediately, preventing phase 6 (bundle compilation)
 * from running.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import { readFile, rm, mkdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { randomUUID } from 'node:crypto';

const TIMEOUT = 30_000;

// Resolve the clawsig CLI entry point
function resolveClawsigBin(): string {
  // Use the local package's bin entry
  return join(__dirname, '..', '..', 'clawsig', 'bin', 'clawsig.js');
}

describe('wrap SIGTERM handling', () => {
  let workDir: string;

  beforeEach(async () => {
    workDir = join(tmpdir(), `clawsig-sigterm-test-${randomUUID().slice(0, 8)}`);
    await mkdir(workDir, { recursive: true });
  });

  afterEach(async () => {
    await rm(workDir, { recursive: true, force: true }).catch(() => {});
  });

  it('produces proof bundle when child exits normally', async () => {
    // Baseline: normal exit should always produce a bundle
    const outputPath = join(workDir, 'proof_bundle.json');

    const exitCode = await new Promise<number>((resolve) => {
      const child = spawn(
        process.execPath,
        [resolveClawsigBin(), 'wrap', '--output', outputPath, '--no-publish', '--', 'echo', 'hello'],
        { cwd: workDir, stdio: 'pipe', env: { ...process.env, CLAWSIG_DISABLE_INTERPOSE: '1' } },
      );

      child.on('exit', (code) => resolve(code ?? 1));
      child.on('error', () => resolve(1));
    });

    expect(exitCode).toBe(0);

    const bundleStat = await stat(outputPath).catch(() => null);
    expect(bundleStat).not.toBeNull();
    expect(bundleStat!.size).toBeGreaterThan(100);

    const bundle = JSON.parse(await readFile(outputPath, 'utf-8'));
    expect(bundle.payload.bundle_id).toMatch(/^bundle_/);
    expect(bundle.signer_did).toMatch(/^did:key:/);
  }, TIMEOUT);

  it('produces proof bundle when parent receives SIGTERM during child sleep', async () => {
    // This is the actual regression test.
    // Spawn clawsig wrap with a child that sleeps, then send SIGTERM
    // to the wrap process. The bundle should still be written.
    const outputPath = join(workDir, 'proof_bundle.json');

    const child = spawn(
      process.execPath,
      [
        resolveClawsigBin(), 'wrap',
        '--output', outputPath,
        '--no-publish',
        '--',
        // Child that sleeps for 60s — we'll SIGTERM the parent before it finishes
        'sleep', '60',
      ],
      { cwd: workDir, stdio: 'pipe', env: { ...process.env, CLAWSIG_DISABLE_INTERPOSE: '1' } },
    );

    // Wait for the wrap process to be ready (sentinels started)
    await new Promise<void>((resolve) => {
      let buffer = '';
      child.stderr?.on('data', (chunk: Buffer) => {
        buffer += chunk.toString();
        // Wait until we see the spawn message
        if (buffer.includes('Spawning:')) {
          resolve();
        }
      });
      // Fallback timeout — proceed after 5s even if no stderr
      setTimeout(resolve, 5000);
    });

    // Send SIGTERM to the wrap process (simulating autoExitOnQuiet)
    expect(child.pid).toBeDefined();
    child.kill('SIGTERM');

    // Wait for exit
    const exitCode = await new Promise<number>((resolve) => {
      child.on('exit', (code) => resolve(code ?? 1));
      // Safety timeout
      setTimeout(() => {
        child.kill('SIGKILL');
        resolve(137);
      }, 10_000);
    });

    // The process should have exited (not hung)
    // Exit code may vary (143 for SIGTERM, or child's code)
    expect(typeof exitCode).toBe('number');

    // The proof bundle should exist
    const bundleStat = await stat(outputPath).catch(() => null);
    expect(bundleStat).not.toBeNull();

    if (bundleStat) {
      expect(bundleStat.size).toBeGreaterThan(100);
      const bundle = JSON.parse(await readFile(outputPath, 'utf-8'));
      expect(bundle.payload.bundle_id).toMatch(/^bundle_/);
      expect(bundle.signer_did).toMatch(/^did:key:/);
    }
  }, TIMEOUT);
});
