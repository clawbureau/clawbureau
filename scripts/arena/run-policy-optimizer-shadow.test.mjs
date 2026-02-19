import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-policy-optimizer-shadow.mjs');

test('policy optimizer shadow script dry-run prints endpoints and payloads', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--task-fingerprint', 'typescript:worker:api-hardening',
    '--objective-profile-name', 'balanced',
    '--experiment-id', 'exp_live',
    '--experiment-arm', 'A',
    '--environment', 'staging',
    '--max-runs', '120',
    '--min-samples', '8',
    '--min-confidence', '0.71',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const json = JSON.parse(proc.stdout);
  assert.equal(json.ok, true);
  assert.equal(json.mode, 'dry-run');
  assert.equal(String(json.post_endpoint).includes('/v1/arena/policy-optimizer'), true);
  assert.equal(String(json.get_endpoint).includes('/v1/arena/policy-optimizer?'), true);
  assert.equal(String(json.route_endpoint).includes('/v1/arena/manager/route'), true);
  assert.equal(json.post_body.task_fingerprint, 'typescript:worker:api-hardening');
  assert.equal(json.post_body.min_samples, 8);
  assert.equal(json.post_body.min_confidence, 0.71);
  assert.equal(json.route_body.use_active_policy, true);
});
