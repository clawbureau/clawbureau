import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

const scriptPath = path.resolve('scripts/arena/register-harness-fleet-workers.mjs');

test('fleet register script dry-run prints register + heartbeat endpoints', () => {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'arena-fleet-test-'));
  const workersPath = path.join(tempDir, 'workers.json');

  writeFileSync(workersPath, JSON.stringify([
    {
      worker_did: 'did:key:z6MkFleetTestWorker0000000000000000000001',
      harness: 'pi',
      model: 'gpt-5.2-codex',
      skills: ['typescript', 'wrangler'],
      tools: ['bash', 'read', 'edit', 'write'],
      objective_profiles: ['balanced'],
      cost_tier: 'medium',
      risk_tier: 'low',
      availability_status: 'online',
    },
  ], null, 2));

  const proc = spawnSync(process.execPath, [
    scriptPath,
    '--workers', workersPath,
    '--bounties-base', 'https://staging.clawbounties.com',
    '--env-label', 'staging',
    '--dry-run',
  ], { encoding: 'utf8' });

  assert.equal(proc.status, 0, proc.stderr || proc.stdout);

  const json = JSON.parse(proc.stdout);
  assert.equal(json.ok, true);
  assert.equal(json.story, 'AGP-US-058');
  assert.equal(json.dry_run, true);
  assert.equal(json.endpoints.register, 'https://staging.clawbounties.com/v1/arena/fleet/workers/register');
  assert.equal(json.endpoints.heartbeat, 'https://staging.clawbounties.com/v1/arena/fleet/workers/heartbeat');
  assert.equal(json.totals.requested_workers, 1);
  assert.equal(Array.isArray(json.events), true);
  assert.equal(json.events.some((entry) => entry.action === 'register'), true);
  assert.equal(json.events.some((entry) => entry.action === 'heartbeat'), true);
});
