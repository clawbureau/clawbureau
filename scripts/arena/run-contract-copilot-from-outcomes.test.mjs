import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-contract-copilot-from-outcomes.mjs');

test('contract copilot script dry-run prints endpoints and payload', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--task-fingerprint', 'typescript:worker:api-hardening',
    '--min-outcomes', '10',
    '--min-arenas', '3',
    '--max-suggestions', '6',
    '--limit', '1400',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const json = JSON.parse(proc.stdout);
  assert.equal(json.ok, true);
  assert.equal(json.mode, 'dry-run');
  assert.equal(String(json.post_endpoint).includes('/v1/arena/contract-copilot/generate'), true);
  assert.equal(String(json.get_endpoint).includes('/v1/arena/contract-copilot?'), true);
  assert.equal(json.post_body.task_fingerprint, 'typescript:worker:api-hardening');
  assert.equal(json.post_body.min_outcomes, 10);
  assert.equal(json.post_body.min_arenas, 3);
  assert.equal(json.post_body.max_suggestions, 6);
});
