import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/run-real-contender-dispatch.mjs');

test('real contender dispatch script dry-run executes contenders and launches arena payload', () => {
  const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'arena-dispatch-test-'));
  const contractPath = path.join(tmpDir, 'contract.json');
  const contendersPath = path.join(tmpDir, 'contenders.json');
  const dispatchPath = path.join(tmpDir, 'dispatch.json');
  const outputRoot = path.join(tmpDir, 'out');

  writeFileSync(contractPath, JSON.stringify({
    bounty_id: 'bty_test_dispatch_001',
    contract_id: 'contract_test_dispatch_001',
    task_fingerprint: 'typescript:worker:api-hardening',
    objective_profile: {
      name: 'balanced',
      weights: { quality: 0.35, speed: 0.25, cost: 0.2, safety: 0.2 },
      tie_breakers: ['mandatory_passed', 'quality_score', 'risk_score_low', 'contender_id'],
    },
    acceptance_criteria: [
      {
        id: 'ac_contract_binding',
        required: true,
        rule: { type: 'contains', field: 'delivery_summary', needle: 'contract binding' },
      },
      {
        id: 'ac_reason_codes',
        required: true,
        rule: { type: 'contains', field: 'delivery_summary', needle: 'reason code' },
      },
      {
        id: 'ac_test_coverage',
        required: false,
        rule: { type: 'contains', field: 'delivery_summary', needle: 'test' },
      },
    ],
  }, null, 2));

  writeFileSync(contendersPath, JSON.stringify([
    {
      contender_id: 'contender_alpha',
      label: 'Alpha contender',
      model: 'test-model-a',
      harness: 'test-harness-a',
      tools: ['bash'],
      skills: ['cloudflare'],
      plugins: ['did-work'],
      prompt: 'alpha prompt',
    },
    {
      contender_id: 'contender_beta',
      label: 'Beta contender',
      model: 'test-model-b',
      harness: 'test-harness-b',
      tools: ['bash'],
      skills: ['wrangler'],
      plugins: ['did-work'],
      prompt: 'beta prompt',
    },
  ], null, 2));

  writeFileSync(dispatchPath, JSON.stringify({
    schema_version: 'arena_real_dispatch.v1',
    defaults: {
      max_retries: 0,
      timeout_ms: 60000,
    },
    contenders: [
      {
        contender_id: 'contender_alpha',
        commands: [
          { id: 'alpha-typecheck', category: 'typecheck', run: 'node -e "process.exit(0)"' },
          { id: 'alpha-test', category: 'test', run: 'node -e "console.log(\"pass 3\"); console.log(\"fail 0\")"' },
        ],
      },
      {
        contender_id: 'contender_beta',
        commands: [
          { id: 'beta-typecheck', category: 'typecheck', run: 'node -e "process.exit(0)"' },
          { id: 'beta-test', category: 'test', run: 'node -e "console.log(\"pass 2\"); console.log(\"fail 1\")"' },
        ],
      },
    ],
  }, null, 2));

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--bounty-id', 'bty_test_dispatch_001',
    '--contract', contractPath,
    '--contenders', contendersPath,
    '--dispatch-config', dispatchPath,
    '--output-root', outputRoot,
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const json = JSON.parse(proc.stdout);
  assert.equal(json.ok, true);
  assert.equal(json.mode, 'dry-run');
  assert.equal(json.dispatch.executed_contenders, 2);
  assert.equal(json.dispatch.required_contenders_met, false);
  assert.equal(json.launch.mode, 'dry-run');
  assert.equal(Array.isArray(json.launch.contender_versions), true);
  assert.equal(json.launch.contender_versions.length, 2);
});
