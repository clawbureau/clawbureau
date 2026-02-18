import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import {
  assertSmokeArtifactContract,
  writeSmokeArtifactContract,
} from './smoke-artifact-contract.mjs';

test('writeSmokeArtifactContract writes canonical files and passes contract check', async () => {
  const artifactDir = await fs.mkdtemp(
    path.join(os.tmpdir(), 'smoke-artifact-contract-pass-')
  );

  const result = await writeSmokeArtifactContract({
    artifactDir,
    proofBundle: { envelope_type: 'proof_bundle', payload: { bundle_id: 'bundle_1' } },
    urm: { urm_id: 'urm_1', run_id: 'run_1' },
    verify: { status: 'PASS', reason_code: 'OK' },
    smoke: { ok: true },
  });

  assert.equal(result.ok, true);
  assert.equal(result.missing.length, 0);

  const verifyText = await fs.readFile(path.join(artifactDir, 'verify.json'), 'utf8');
  const verifyJson = JSON.parse(verifyText);
  assert.equal(verifyJson.status, 'PASS');
});

test('assertSmokeArtifactContract fails when required verify.json is missing', async () => {
  const artifactDir = await fs.mkdtemp(
    path.join(os.tmpdir(), 'smoke-artifact-contract-fail-')
  );

  await fs.writeFile(path.join(artifactDir, 'smoke.json'), '{"ok":false}\n', 'utf8');

  await assert.rejects(
    () =>
      assertSmokeArtifactContract({
        artifactDir,
        requireProofBundle: false,
        requireUrm: false,
        requireVerify: true,
        requireSmoke: true,
      }),
    /missing required files: verify\.json/
  );
});
