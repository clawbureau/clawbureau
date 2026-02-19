import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/get-manager-coach.mjs');

test('manager coach script dry-run builds request payload', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--task-fingerprint', 'typescript:worker:api-hardening',
    '--objective-profile-name', 'balanced',
    '--mode', 'coach',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const json = JSON.parse(proc.stdout);
  assert.equal(json.ok, true);
  assert.equal(json.mode, 'dry-run');
  assert.equal(json.endpoint, '/v1/arena/manager/coach');
  assert.equal(json.payload.task_fingerprint, 'typescript:worker:api-hardening');
});
