import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-autonomous-resolve-loop.mjs');

test('autonomous resolve loop script dry-run writes preview summary', () => {
  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--limit', '120',
    '--target-resolved', '40',
    '--min-pending-age-minutes', '45',
    '--keep-unresolved-pending',
    '--arena-ids', 'arena_alpha,arena_beta',
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
  const totals = JSON.parse(lines[lines.length - 1] ?? '{}');
  assert.equal(totals.dry_run, true);

  const markerLine = lines.find((line) => line.startsWith('ARENA_AUTONOMOUS_RESOLVE_RESULT '));
  assert.ok(markerLine, 'expected output marker');
});
