import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFileSync } from 'node:fs';
import { loadContenderRegistry, resolveRegistryArenaInput } from './lib/contender-registry.mjs';

const registryPath = path.resolve('contracts/arena/contender-registry.sample.v1.json');
const contendersPath = path.resolve('contracts/arena/contenders.sample.v1.json');

function loadContenders() {
  return JSON.parse(readFileSync(contendersPath, 'utf8'));
}

test('registry resolution honors explicit experiment arm selection', () => {
  const registry = loadContenderRegistry(registryPath);
  const resolved = resolveRegistryArenaInput({
    registry,
    baseContenders: loadContenders(),
    taskFingerprint: 'typescript:worker:api-hardening',
    experimentId: 'exp_api_hardening_ab_v1',
    experimentArm: 'B',
    arenaSeed: 'arena_seed_001',
  });

  const contenderIds = resolved.contenders.map((row) => row.contender_id).sort();
  assert.deepEqual(contenderIds, ['contender_codex_pi', 'contender_gemini_swarm']);
  assert.equal(resolved.registry_context.experiment_id, 'exp_api_hardening_ab_v1');
  assert.equal(resolved.registry_context.experiment_arm, 'B');
  assert.equal(resolved.registry_context.registry_version, '2026-02-19');
  assert.equal(resolved.registry_context.selected_contenders.every((row) => typeof row.version_pin === 'string' && row.version_pin.length > 0), true);
});

test('registry arm allocation is deterministic for identical seeds', () => {
  const registry = loadContenderRegistry(registryPath);

  const first = resolveRegistryArenaInput({
    registry,
    baseContenders: loadContenders(),
    taskFingerprint: 'typescript:worker:api-hardening',
    arenaSeed: 'stable-seed-001',
  });

  const second = resolveRegistryArenaInput({
    registry,
    baseContenders: loadContenders(),
    taskFingerprint: 'typescript:worker:api-hardening',
    arenaSeed: 'stable-seed-001',
  });

  assert.equal(first.registry_context.experiment_arm, second.registry_context.experiment_arm);
  assert.deepEqual(
    first.contenders.map((row) => row.contender_id).sort(),
    second.contenders.map((row) => row.contender_id).sort(),
  );
});
