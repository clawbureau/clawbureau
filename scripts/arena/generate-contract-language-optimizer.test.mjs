import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/generate-contract-language-optimizer.mjs');

test('contract language optimizer script dry-run builds endpoint and payload', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--task-fingerprint', 'typescript:worker:api-hardening',
    '--limit', '220',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const json = JSON.parse(proc.stdout);
  assert.equal(json.ok, true);
  assert.equal(json.mode, 'dry-run');
  assert.equal(String(json.endpoint).includes('/v1/arena/contract-language-optimizer'), true);
  assert.equal(json.body.task_fingerprint, 'typescript:worker:api-hardening');
  assert.equal(json.body.limit, 220);
  assert.equal(typeof json.output_dir, 'string');
});
