import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-historical-backtest.mjs');

test('historical backtest script dry-run builds endpoint and output path', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--task-fingerprint', 'typescript:worker:api-hardening',
    '--limit', '150',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const json = JSON.parse(proc.stdout);
  assert.equal(json.ok, true);
  assert.equal(json.mode, 'dry-run');
  assert.equal(String(json.endpoint).includes('/v1/arena/backtesting?'), true);
  assert.equal(String(json.endpoint).includes('task_fingerprint=typescript%3Aworker%3Aapi-hardening'), true);
  assert.equal(String(json.endpoint).includes('limit=150'), true);
  assert.equal(typeof json.output_dir, 'string');
});
