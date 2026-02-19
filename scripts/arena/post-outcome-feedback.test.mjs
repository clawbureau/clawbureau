import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/post-outcome-feedback.mjs');

test('outcome feedback script dry-run builds payload and endpoint', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounty-id', 'bty_arena_001',
    '--arena-id', 'arena_bty_arena_001',
    '--contender-id', 'contender_codex_pi',
    '--outcome-status', 'ACCEPTED',
    '--review-time-minutes', '22',
    '--time-to-accept-minutes', '75',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const json = JSON.parse(proc.stdout);
  assert.equal(json.ok, true);
  assert.equal(json.mode, 'dry-run');
  assert.equal(json.payload.outcome_status, 'ACCEPTED');
  assert.equal(typeof json.payload.idempotency_key, 'string');
  assert.equal(String(json.endpoint).includes('/v1/bounties/bty_arena_001/arena/outcome'), true);
});

test('outcome feedback script requires override reason for OVERRIDDEN status', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounty-id', 'bty_arena_001',
    '--arena-id', 'arena_bty_arena_001',
    '--outcome-status', 'OVERRIDDEN',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.notEqual(proc.status, 0);
  assert.equal((proc.stderr + proc.stdout).includes('--override-reason-code is required'), true);
});
