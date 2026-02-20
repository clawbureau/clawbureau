import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-autonomous-discovery-loop.mjs');

test('autonomous discovery loop dry-run writes preview summary', () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'arena-discover-test-'));
  const outputPath = path.join(tempDir, 'summary.json');

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounties-base', 'https://staging.clawbounties.com',
    '--admin-key', 'test-admin-key',
    '--target-open-bounties', '25',
    '--seed-limit', '20',
    '--seed-reward-minor', '30',
    '--seed-requester-dids', 'did:key:zRequesterA,did:key:zRequesterB',
    '--seed-tags', 'arena,seed,test',
    '--discover-id', 'discover_test_064',
    '--dry-run',
    '--output', outputPath,
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  assert.match(proc.stdout, /ARENA_AUTONOMOUS_DISCOVERY_RESULT/);

  const summary = JSON.parse(readFileSync(outputPath, 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.story, 'AGP-US-064');
  assert.equal(summary.dry_run, true);
  assert.equal(summary.request.target_open_bounties, 25);
  assert.equal(summary.request.seed_limit, 20);
  assert.equal(summary.request.seed_reward_minor, '30');
  assert.deepEqual(summary.request.seed_requester_dids, ['did:key:zRequesterA', 'did:key:zRequesterB']);
  assert.deepEqual(summary.request.seed_tags, ['arena', 'seed', 'test']);
  assert.equal(summary.request.discover_id, 'discover_test_064');
  assert.equal(summary.loop_result.schema_version, 'arena_desk_discovery_loop.v1');
  assert.equal(summary.loop_result.preview.endpoint, 'https://staging.clawbounties.com/v1/arena/desk/discover-loop');
});
