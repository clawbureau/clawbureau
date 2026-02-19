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
    '--reviewer-decision', 'approve',
    '--reviewer-rationale', 'All acceptance gates passed with clean evidence.',
    '--decision-tag', 'ui-review',
    '--decision-tag', 'taxonomy-acceptance',
    '--decision-rationale', 'Evidence aligns with policy contract.',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const json = JSON.parse(proc.stdout);
  assert.equal(json.ok, true);
  assert.equal(json.mode, 'dry-run');
  assert.equal(json.payload.outcome_status, 'ACCEPTED');
  assert.equal(json.payload.reviewer_decision, 'approve');
  assert.equal(Array.isArray(json.payload.decision_taxonomy_tags), true);
  assert.equal(json.payload.decision_taxonomy_tags.length, 2);
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

test('outcome feedback script rejects invalid rework-required flag', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounty-id', 'bty_arena_001',
    '--arena-id', 'arena_bty_arena_001',
    '--outcome-status', 'REWORK',
    '--rework-required', 'sometimes',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.notEqual(proc.status, 0);
  assert.equal((proc.stderr + proc.stdout).includes('--rework-required must be true|false|1|0|yes|no'), true);
});
