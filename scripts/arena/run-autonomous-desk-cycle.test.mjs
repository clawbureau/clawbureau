import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-autonomous-desk-cycle.mjs');

test('autonomous desk cycle dry-run writes preview summary', () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'arena-cycle-test-'));
  const outputPath = path.join(tempDir, 'summary.json');

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounties-base', 'https://staging.clawbounties.com',
    '--admin-key', 'test-admin-key',
    '--target-open-bounties', '25',
    '--target-claims', '15',
    '--target-submissions', '15',
    '--target-decisions', '15',
    '--dry-run',
    '--output', outputPath,
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  assert.match(proc.stdout, /ARENA_AUTONOMOUS_CYCLE_RESULT/);

  const summary = JSON.parse(readFileSync(outputPath, 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.story, 'AGP-US-069');
  assert.equal(summary.dry_run, true);
  assert.equal(summary.requests.discover.target_open_bounties, 25);
  assert.equal(summary.requests.claim.target_claims, 15);
  assert.equal(summary.requests.submit.target_submissions, 15);
  assert.equal(summary.requests.decision.target_decisions, 15);
  assert.equal(summary.endpoints.discover, 'https://staging.clawbounties.com/v1/arena/desk/discover-loop');
  assert.equal(summary.endpoints.decision, 'https://staging.clawbounties.com/v1/arena/desk/decision-loop');
});
