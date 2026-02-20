import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-execution-submission-autopilot.mjs');

test('execution+submission autopilot dry-run writes deterministic preview', () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'arena-exec-submit-test-'));
  const outputPath = path.join(tempDir, 'summary.json');
  const bountyIdsPath = path.join(tempDir, 'bounty-ids.txt');

  writeFileSync(
    bountyIdsPath,
    [
      'bty_a1111111-1111-1111-1111-111111111111',
      'bty_b2222222-2222-2222-2222-222222222222',
    ].join('\n') + '\n',
  );

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounties-base', 'https://staging.clawbounties.com',
    '--admin-key', 'test-admin-key',
    '--target-submissions', '2',
    '--limit', '10',
    '--bounty-ids-file', bountyIdsPath,
    '--dry-run',
    '--output', outputPath,
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  assert.match(proc.stdout, /ARENA_EXEC_SUBMISSION_AUTOPILOT_RESULT/);

  const summary = JSON.parse(readFileSync(outputPath, 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.story, 'AGP-US-060');
  assert.equal(summary.dry_run, true);
  assert.equal(summary.endpoint, 'https://staging.clawbounties.com/v1/arena/desk/submit-loop');
  assert.equal(summary.request.worker_did, 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7');
  assert.equal(summary.request.target_submissions, 2);
  assert.deepEqual(summary.request.bounty_ids, [
    'bty_a1111111-1111-1111-1111-111111111111',
    'bty_b2222222-2222-2222-2222-222222222222',
  ]);
  assert.equal(summary.loop_result.schema_version, 'arena_execution_submission_autopilot.v1');
  assert.equal(summary.loop_result.preview.endpoint, 'https://staging.clawbounties.com/v1/arena/desk/submit-loop');
  assert.equal(summary.claims_snapshot.schema_version, 'arena_submissions_snapshot.v1');
});
