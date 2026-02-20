import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-autonomous-decision-loop.mjs');

test('autonomous decision loop dry-run writes preview summary', () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'arena-decision-test-'));
  const outputPath = path.join(tempDir, 'summary.json');

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounties-base', 'https://staging.clawbounties.com',
    '--admin-key', 'test-admin-key',
    '--decision-mode', 'mixed',
    '--limit', '80',
    '--target-decisions', '25',
    '--bounty-ids', 'bty_1,bty_2',
    '--allow-unclaimed',
    '--loop-id', 'decision_test_067',
    '--dry-run',
    '--output', outputPath,
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  assert.match(proc.stdout, /ARENA_AUTONOMOUS_DECISION_RESULT/);

  const summary = JSON.parse(readFileSync(outputPath, 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.story, 'AGP-US-067-068');
  assert.equal(summary.dry_run, true);
  assert.equal(summary.request.decision_mode, 'mixed');
  assert.equal(summary.request.limit, 80);
  assert.equal(summary.request.target_decisions, 25);
  assert.deepEqual(summary.request.bounty_ids, ['bty_1', 'bty_2']);
  assert.equal(summary.request.require_claimed, false);
  assert.equal(summary.request.loop_id, 'decision_test_067');
  assert.equal(summary.loop_result.schema_version, 'arena_desk_decision_loop.v1');
  assert.equal(summary.loop_result.preview.endpoint, 'https://staging.clawbounties.com/v1/arena/desk/decision-loop');
});
