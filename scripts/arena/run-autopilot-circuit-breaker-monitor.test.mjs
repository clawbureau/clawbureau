import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-autopilot-circuit-breaker-monitor.mjs');

test('autopilot circuit monitor dry-run writes preview summary', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--task-fingerprint', 'AEM-FP-UI-DUEL-V1',
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
  const marker = lines.find((line) => line.startsWith('ARENA_AUTOPILOT_CIRCUIT_MONITOR_RESULT '));
  assert.ok(marker, 'expected output marker');

  const tail = JSON.parse(lines[lines.length - 1] ?? '{}');
  assert.equal(tail.dry_run, true);
});
