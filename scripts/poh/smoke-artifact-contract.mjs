#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function writeJson(filePath, value) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export async function assertSmokeArtifactContract(options) {
  const {
    artifactDir,
    requireProofBundle = true,
    requireUrm = true,
    requireVerify = true,
    requireSmoke = true,
  } = options;

  if (!artifactDir || typeof artifactDir !== 'string') {
    throw new Error('artifactDir is required');
  }

  const required = [];
  if (requireProofBundle) required.push('proof-bundle.json');
  if (requireUrm) required.push('urm.json');
  if (requireVerify) required.push('verify.json');
  if (requireSmoke) required.push('smoke.json');

  const present = [];
  const missing = [];

  for (const file of required) {
    const full = path.resolve(artifactDir, file);
    if (await fileExists(full)) present.push(file);
    else missing.push(file);
  }

  const optional = [];
  if (await fileExists(path.resolve(artifactDir, 'health-snapshot.json'))) {
    optional.push('health-snapshot.json');
  }

  const result = {
    ok: missing.length === 0,
    artifact_dir: artifactDir,
    required,
    present,
    optional,
    missing,
  };

  if (!result.ok) {
    throw new Error(
      `[smoke-artifact-contract] missing required files: ${missing.join(', ')}`
    );
  }

  return result;
}

/**
 * Write canonical smoke artifacts and enforce artifact contract.
 */
export async function writeSmokeArtifactContract(options) {
  const {
    artifactDir,
    proofBundle,
    urm,
    verify,
    smoke,
    healthSnapshot,
    requireProofBundle,
    requireUrm,
  } = options;

  if (!artifactDir || typeof artifactDir !== 'string') {
    throw new Error('artifactDir is required');
  }

  if (verify === undefined) {
    throw new Error('verify artifact is required (verify.json)');
  }

  if (smoke === undefined) {
    throw new Error('smoke artifact is required (smoke.json)');
  }

  await fs.mkdir(artifactDir, { recursive: true });

  if (proofBundle !== undefined) {
    await writeJson(path.resolve(artifactDir, 'proof-bundle.json'), proofBundle);
  }

  if (urm !== undefined) {
    await writeJson(path.resolve(artifactDir, 'urm.json'), urm);
  }

  await writeJson(path.resolve(artifactDir, 'verify.json'), verify);
  await writeJson(path.resolve(artifactDir, 'smoke.json'), smoke);

  if (healthSnapshot !== undefined) {
    await writeJson(path.resolve(artifactDir, 'health-snapshot.json'), healthSnapshot);
  }

  const proofRequired =
    typeof requireProofBundle === 'boolean'
      ? requireProofBundle
      : proofBundle !== undefined;

  const urmRequired =
    typeof requireUrm === 'boolean'
      ? requireUrm
      : proofRequired;

  const contract = await assertSmokeArtifactContract({
    artifactDir,
    requireProofBundle: proofRequired,
    requireUrm: urmRequired,
    requireVerify: true,
    requireSmoke: true,
  });

  return {
    ...contract,
    files: {
      proof_bundle: proofBundle !== undefined ? 'proof-bundle.json' : null,
      urm: urm !== undefined ? 'urm.json' : null,
      verify: 'verify.json',
      smoke: 'smoke.json',
      health_snapshot: healthSnapshot !== undefined ? 'health-snapshot.json' : null,
    },
  };
}
