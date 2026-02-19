import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/post-decision-paste.mjs');
const arenaReportPath = path.resolve('artifacts/arena/arena_bty_arena_001/arena-report.json');

test('decision paste script emits approve recommendation for winning contender', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'arena-decision-'));
  const outputPath = path.join(dir, 'decision.md');

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--arena-report', arenaReportPath,
    '--output', outputPath,
    '--arena-base-url', 'https://staging.clawsig-explorer.com',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const summary = JSON.parse(proc.stdout);
  assert.equal(summary.recommendation, 'APPROVE');
  assert.equal(summary.contender_id, 'contender_codex_pi');

  const markdown = readFileSync(outputPath, 'utf8');
  assert.equal(markdown.includes('Recommendation: **APPROVE**'), true);
  assert.equal(markdown.includes('One-click links'), true);

  rmSync(dir, { recursive: true, force: true });
});

test('decision paste script maps reject contender to REJECT recommendation', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'arena-decision-reject-'));
  const outputPath = path.join(dir, 'decision.md');

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--arena-report', arenaReportPath,
    '--contender-id', 'contender_gemini_swarm',
    '--output', outputPath,
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const summary = JSON.parse(proc.stdout);
  assert.equal(summary.recommendation, 'REJECT');

  const markdown = readFileSync(outputPath, 'utf8');
  assert.equal(markdown.includes('Recommendation: **REJECT**'), true);

  rmSync(dir, { recursive: true, force: true });
});
