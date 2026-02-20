import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-roi-dashboard-report.mjs');

test('roi dashboard script dry-run prints endpoint', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--task-fingerprint', 'typescript:worker:api-hardening',
    '--objective-profile-name', 'balanced',
    '--experiment-id', 'exp_api_hardening_live_v1',
    '--experiment-arm', 'LIVE',
    '--min-samples', '8',
    '--limit', '2500',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const json = JSON.parse(proc.stdout);
  assert.equal(json.ok, true);
  assert.equal(json.mode, 'dry-run');
  assert.equal(String(json.endpoint).includes('/v1/arena/roi-dashboard?'), true);
  assert.equal(String(json.endpoint).includes('task_fingerprint=typescript%3Aworker%3Aapi-hardening'), true);
  assert.equal(String(json.endpoint).includes('min_samples=8'), true);
});
