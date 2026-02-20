import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-autonomous-kpi-recovery-loop.mjs');

test('kpi recovery loop script dry-run writes preview summary', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--window-hours', '24',
    '--limit', '90',
    '--target-submissions', '3',
    '--no-worker-rebind',
    '--no-enforce',
    '--dry-run',
  ], {
    encoding: 'utf8',
    env: {
      ...process.env,
      BOUNTIES_ADMIN_KEY: 'test-admin-key',
    },
  });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const lines = proc.stdout.trim().split('\n');
  const marker = lines.find((line) => line.startsWith('ARENA_KPI_RECOVERY_RESULT '));
  assert.ok(marker, 'expected output marker');

  const tail = JSON.parse(lines[lines.length - 1] ?? '{}');
  assert.equal(tail.dry_run, true);
});
