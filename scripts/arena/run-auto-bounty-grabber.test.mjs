import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-auto-bounty-grabber.mjs');

test('auto bounty grabber dry-run writes preview summary', () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'arena-autoclaim-test-'));
  const outputPath = path.join(tempDir, 'summary.json');

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounties-base', 'https://staging.clawbounties.com',
    '--admin-key', 'test-admin-key',
    '--limit', '12',
    '--target-claims', '10',
    '--budget-minor', '120000',
    '--max-fleet-cost-tier', 'medium',
    '--max-fleet-risk-tier', 'medium',
    '--loop-id', 'loop_test_059',
    '--dry-run',
    '--output', outputPath,
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  assert.match(proc.stdout, /AUTO_BOUNTY_GRABBER_RESULT/);

  const summary = JSON.parse(readFileSync(outputPath, 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.dry_run, true);
  assert.equal(summary.request.limit, 12);
  assert.equal(summary.request.target_claims, 10);
  assert.equal(summary.request.max_fleet_cost_tier, 'medium');
  assert.equal(summary.request.max_fleet_risk_tier, 'medium');
  assert.equal(summary.request.loop_id, 'loop_test_059');
  assert.equal(summary.loop_result.schema_version, 'arena_auto_claim_loop.v1');
  assert.equal(summary.loop_result.preview.endpoint, 'https://staging.clawbounties.com/v1/arena/desk/claim-loop');
  assert.equal(summary.claim_locks_snapshot.schema_version, 'arena_auto_claim_locks.v1');
});
