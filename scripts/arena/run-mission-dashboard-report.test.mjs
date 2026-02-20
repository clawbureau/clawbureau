import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-mission-dashboard-report.mjs');

test('mission dashboard script dry-run writes preview summary', () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'arena-mission-ui-test-'));
  const outputPath = path.join(tempDir, 'summary.json');

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounties-base', 'https://staging.clawbounties.com',
    '--worker-did', 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    '--window-hours', '48',
    '--dry-run',
    '--output', outputPath,
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  assert.match(proc.stdout, /ARENA_MISSION_REPORT_RESULT/);

  const summary = JSON.parse(readFileSync(outputPath, 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.dry_run, true);
  assert.equal(summary.mission.schema_version, 'arena_mission_summary.v1');
  assert.equal(summary.mission.preview.endpoint, 'https://staging.clawbounties.com/v1/arena/mission?worker_did=did%3Akey%3Az6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7&window_hours=48');
});
