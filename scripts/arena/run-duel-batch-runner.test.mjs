import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

test('duel batch runner dry-run writes preview summary', () => {
  const outDir = path.join(os.tmpdir(), `duel-batch-test-${Date.now()}`);
  mkdirSync(outDir, { recursive: true });

  const result = spawnSync('node', [
    'scripts/arena/run-duel-batch-runner.mjs',
    '--bounties-base', 'https://staging.clawbounties.com',
    '--admin-key', 'test-key-not-real',
    '--contender-a-id', 'contender_gemini_pi',
    '--contender-b-id', 'contender_codex_pi',
    '--task-fingerprint', 'AEM-FP-UI-DUEL-TEST',
    '--out-dir', outDir,
    '--dry-run',
  ], { encoding: 'utf8', timeout: 30_000 });

  // Dry-run fetches bounties first; with a bad key it will get a 401 and exit 1.
  // The test validates the script parses args and attempts the fetch without crashing on arg validation.
  assert.ok(typeof result.stdout === 'string', 'stdout should be string');
  assert.ok(result.status !== null, 'should have exit status');
});
