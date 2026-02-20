import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-ui-duel-evaluator.mjs');

test('ui duel evaluator dry-run writes preview summary', () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'ui-duel-eval-test-'));

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--base-url', 'https://staging.clawbounties.com',
    '--ui-path', '/duel',
    '--contender-id', 'contender_gemini_3_1_pro_preview_pi',
    '--contract', 'contracts/arena/bounty-ui-duel.clawbounties.v1.json',
    '--dry-run',
    '--out-dir', tempDir,
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  assert.match(proc.stdout, /ARENA_UI_DUEL_EVAL_RESULT/);

  const summary = JSON.parse(readFileSync(path.join(tempDir, 'summary.json'), 'utf8'));
  assert.equal(summary.ok, true);
  assert.equal(summary.dry_run, true);
  assert.equal(summary.contender_id, 'contender_gemini_3_1_pro_preview_pi');
  assert.equal(summary.contract_id, 'contract_clawbounties_ui_duel_v1');
  assert.equal(summary.ui_url, 'https://staging.clawbounties.com/duel');
  assert.equal(summary.weights.ux_task_success_friction, 35);
  assert.equal(summary.weights.implementation_maintainability, 10);
});
