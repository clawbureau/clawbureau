import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-real-bounty-arena.mjs');
const contractPath = path.resolve('contracts/arena/bounty-contract.sample.v1.json');
const contendersPath = path.resolve('contracts/arena/contenders.sample.v1.json');

test('real bounty launcher dry-run generates summary artifact', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'arena-real-run-'));
  const arenaId = 'arena_test_real_launcher_001';

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounty-id', 'bty_arena_001',
    '--contract', contractPath,
    '--contenders', contendersPath,
    '--output-root', dir,
    '--arena-id', arenaId,
    '--generated-at', '2026-02-19T15:10:00.000Z',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const summaryPath = path.join(dir, arenaId, 'real-bounty-launch.summary.json');
  const summary = JSON.parse(readFileSync(summaryPath, 'utf8'));

  assert.equal(summary.ok, true);
  assert.equal(summary.mode, 'dry-run');
  assert.equal(summary.bounty_id, 'bty_arena_001');
  assert.equal(summary.arena_id, arenaId);
  assert.equal(typeof summary.start_idempotency_key, 'string');
  assert.equal(typeof summary.result_idempotency_key, 'string');

  rmSync(dir, { recursive: true, force: true });
});

test('real bounty launcher fails when bounty id mismatches contract', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'arena-real-run-fail-'));

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounty-id', 'bty_wrong_001',
    '--contract', contractPath,
    '--contenders', contendersPath,
    '--output-root', dir,
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.notEqual(proc.status, 0, 'expected non-zero exit code for mismatch');
  assert.equal((proc.stderr + proc.stdout).includes('does not match --bounty-id'), true);

  rmSync(dir, { recursive: true, force: true });
});
