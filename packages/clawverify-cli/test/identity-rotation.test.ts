import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import crypto from 'node:crypto';

import { generateIdentity, loadIdentity } from '../src/identity.js';
import { rotateIdentity, RotationError } from '../src/identity-rotation.js';
import type { ContinuityProof } from '../src/identity-rotation.js';
import { importKeyPairJWK } from '@clawbureau/clawsig-sdk';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-rotation-test-'));
  delete process.env['CLAWSIG_IDENTITY'];
});

afterEach(async () => {
  delete process.env['CLAWSIG_IDENTITY'];
  await rm(tmpDir, { recursive: true, force: true });
});

function base64UrlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(Buffer.from(padded, 'base64'));
}

async function verifyEd25519(publicKeyJwk: JsonWebKey, message: string, signature: string): Promise<boolean> {
  const pubKey = await crypto.subtle.importKey('jwk', publicKeyJwk, 'Ed25519', true, ['verify']);
  const sigBytes = base64UrlDecode(signature);
  const msgBytes = new TextEncoder().encode(message);
  return crypto.subtle.verify('Ed25519', pubKey, sigBytes, msgBytes);
}

// ---------------------------------------------------------------------------
// rotateIdentity — happy path
// ---------------------------------------------------------------------------

describe('rotateIdentity', () => {
  it('changes the DID after rotation', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const original = await generateIdentity(identityPath);

    const result = await rotateIdentity({ dir: tmpDir });

    expect(result.old_did).toBe(original.did);
    expect(result.new_did).not.toBe(original.did);
    expect(result.new_did).toMatch(/^did:key:z/);

    // On-disk identity should be the new one
    const loaded = await loadIdentity(tmpDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.did).toBe(result.new_did);
  });

  it('creates a continuity proof artifact on disk', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await generateIdentity(identityPath);

    const result = await rotateIdentity({ dir: tmpDir });

    // Proof file should exist
    const proofRaw = await readFile(result.continuity_proof_path, 'utf-8');
    const proof = JSON.parse(proofRaw) as ContinuityProof;

    expect(proof.proof_type).toBe('identity_rotation');
    expect(proof.proof_version).toBe(1);
    expect(proof.old_did).toBe(result.old_did);
    expect(proof.new_did).toBe(result.new_did);
    expect(proof.rotated_at).toBeDefined();
    expect(new Date(proof.rotated_at).toISOString()).toBe(proof.rotated_at);
  });

  it('continuity proof includes valid handoff signature from OLD key', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const original = await generateIdentity(identityPath);

    const result = await rotateIdentity({ dir: tmpDir });
    const proof = result.continuity_proof;

    // Handoff is signed by the OLD key
    const valid = await verifyEd25519(
      original.publicKeyJwk,
      proof.handoff.statement,
      proof.handoff.signature,
    );
    expect(valid).toBe(true);

    // Statement references both DIDs
    expect(proof.handoff.statement).toContain(result.old_did);
    expect(proof.handoff.statement).toContain(result.new_did);
  });

  it('continuity proof includes valid acknowledgment signature from NEW key', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await generateIdentity(identityPath);

    const result = await rotateIdentity({ dir: tmpDir });
    const proof = result.continuity_proof;

    // Read the new identity to get the new public key
    const newIdentity = await loadIdentity(tmpDir);
    expect(newIdentity).not.toBeNull();

    const valid = await verifyEd25519(
      newIdentity!.publicKeyJwk,
      proof.acknowledgment.statement,
      proof.acknowledgment.signature,
    );
    expect(valid).toBe(true);

    // Statement references both DIDs
    expect(proof.acknowledgment.statement).toContain(result.new_did);
    expect(proof.acknowledgment.statement).toContain(result.old_did);
  });

  it('old key signature does NOT verify against new key (distinct keys)', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await generateIdentity(identityPath);

    const result = await rotateIdentity({ dir: tmpDir });
    const proof = result.continuity_proof;

    // Load the new identity
    const newIdentity = await loadIdentity(tmpDir);

    // Handoff signature should NOT verify against new key
    const crossCheck = await verifyEd25519(
      newIdentity!.publicKeyJwk,
      proof.handoff.statement,
      proof.handoff.signature,
    );
    expect(crossCheck).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// rotateIdentity — error cases
// ---------------------------------------------------------------------------

describe('rotateIdentity — error handling', () => {
  it('throws RotationError when no identity exists', async () => {
    const emptyDir = join(tmpDir, 'empty');
    await mkdir(emptyDir, { recursive: true });

    // Point HOME away so global identity is not found
    const originalHome = process.env['HOME'];
    process.env['HOME'] = join(tmpDir, 'no-home');

    try {
      await expect(rotateIdentity({ dir: emptyDir })).rejects.toThrow(RotationError);
      await expect(rotateIdentity({ dir: emptyDir })).rejects.toThrow(/clawsig init/);
    } finally {
      process.env['HOME'] = originalHome;
    }
  });

  it('RotationError has code ROTATION_ERROR', async () => {
    const emptyDir = join(tmpDir, 'empty');
    await mkdir(emptyDir, { recursive: true });

    const originalHome = process.env['HOME'];
    process.env['HOME'] = join(tmpDir, 'no-home');

    try {
      await expect(rotateIdentity({ dir: emptyDir })).rejects.toMatchObject({
        code: 'ROTATION_ERROR',
      });
    } finally {
      process.env['HOME'] = originalHome;
    }
  });
});

// ---------------------------------------------------------------------------
// Multiple rotations
// ---------------------------------------------------------------------------

describe('sequential rotations', () => {
  it('can rotate multiple times with chained proofs', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const original = await generateIdentity(identityPath);

    const r1 = await rotateIdentity({ dir: tmpDir });
    const r2 = await rotateIdentity({ dir: tmpDir });

    // Chain: original -> r1 -> r2
    expect(r1.old_did).toBe(original.did);
    expect(r2.old_did).toBe(r1.new_did);
    expect(r2.new_did).not.toBe(r1.new_did);
    expect(r2.new_did).not.toBe(original.did);

    // Both proof files should exist
    const proof1 = JSON.parse(await readFile(r1.continuity_proof_path, 'utf-8'));
    const proof2 = JSON.parse(await readFile(r2.continuity_proof_path, 'utf-8'));

    expect(proof1.new_did).toBe(proof2.old_did);
  });
});

// ---------------------------------------------------------------------------
// JSON output shape stability
// ---------------------------------------------------------------------------

describe('JSON output shape', () => {
  it('continuity proof has stable schema shape', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await generateIdentity(identityPath);

    const result = await rotateIdentity({ dir: tmpDir });
    const proof = result.continuity_proof;

    // Verify all required fields exist with correct types
    expect(typeof proof.proof_type).toBe('string');
    expect(typeof proof.proof_version).toBe('number');
    expect(typeof proof.old_did).toBe('string');
    expect(typeof proof.new_did).toBe('string');
    expect(typeof proof.rotated_at).toBe('string');

    expect(typeof proof.handoff).toBe('object');
    expect(typeof proof.handoff.statement).toBe('string');
    expect(typeof proof.handoff.signature).toBe('string');

    expect(typeof proof.acknowledgment).toBe('object');
    expect(typeof proof.acknowledgment.statement).toBe('string');
    expect(typeof proof.acknowledgment.signature).toBe('string');

    // Signatures are base64url
    expect(proof.handoff.signature).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(proof.acknowledgment.signature).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('RotationResult has stable shape', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await generateIdentity(identityPath);

    const result = await rotateIdentity({ dir: tmpDir });

    expect(typeof result.old_did).toBe('string');
    expect(typeof result.new_did).toBe('string');
    expect(typeof result.identity_path).toBe('string');
    expect(typeof result.continuity_proof_path).toBe('string');
    expect(typeof result.continuity_proof).toBe('object');
  });
});
