import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-self-tuning-rollout.mjs');

test('self-tuning rollout script dry-run writes promoted preview', () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'arena-self-tune-test-'));
  const outputPath = path.join(tempDir, 'summary.json');

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounties-base', 'https://staging.clawbounties.com',
    '--task-fingerprint', 'typescript:worker:api-hardening',
    '--environment', 'staging',
    '--window-hours', '24',
    '--min-confidence', '0.4',
    '--require-promotion',
    '--dry-run',
    '--output', outputPath,
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  assert.match(proc.stdout, /ARENA_SELF_TUNE_RESULT/);

  const summary = JSON.parse(readFileSync(outputPath, 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.dry_run, true);
  assert.equal(summary.rollout_result.payload.schema_version, 'arena_self_tune_rollout.v1');
  assert.equal(summary.rollout_result.payload.rollout_status, 'PROMOTED');
  assert.equal(summary.rollout_result.payload.preview.endpoint, 'https://staging.clawbounties.com/v1/arena/desk/self-tune-rollout');
});
