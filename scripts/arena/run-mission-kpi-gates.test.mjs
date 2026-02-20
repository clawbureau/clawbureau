import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-mission-kpi-gates.mjs');

test('mission kpi gate script dry-run writes deterministic preview', () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'arena-kpi-gate-test-'));
  const outputPath = path.join(tempDir, 'summary.json');

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounties-base', 'https://staging.clawbounties.com',
    '--worker-did', 'did:key:z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7',
    '--window-hours', '24',
    '--min-online-workers', '3',
    '--min-claim-success-rate', '0.8',
    '--min-submission-success-rate', '0.8',
    '--min-proof-valid-rate', '0.95',
    '--max-claim-submission-gap', '5',
    '--max-accepted-backlog', '5',
    '--dry-run',
    '--output', outputPath,
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  assert.match(proc.stdout, /ARENA_KPI_GATE_RESULT/);

  const summary = JSON.parse(readFileSync(outputPath, 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.dry_run, true);
  assert.equal(summary.gate_result.payload.schema_version, 'arena_mission_summary.v1');
  assert.equal(summary.gate_result.payload.gate.passed, true);
  assert.equal(summary.gate_result.payload.preview.endpoint, 'https://staging.clawbounties.com/v1/arena/desk/kpi-gate');
});
