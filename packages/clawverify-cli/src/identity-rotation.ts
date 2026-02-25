/**
 * Identity rotation with continuity proof.
 *
 * Generates a new Ed25519 keypair, atomically replaces the identity file,
 * and produces a cryptographic continuity artifact that proves the handoff
 * from old DID to new DID.
 *
 * Continuity proof contains:
 *  - old_did, new_did, rotated_at
 *  - handoff_statement signed by OLD key (attesting transfer to new)
 *  - acknowledgment_statement signed by NEW key (accepting transfer from old)
 */

import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import {
  generateKeyPair,
  didFromPublicKey,
  exportKeyPairJWK,
  importKeyPairJWK,
} from '@clawbureau/clawsig-sdk';
import type { ClawsigIdentity } from './identity.js';
import { loadIdentity, defaultIdentityPath } from './identity.js';
import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ContinuityProof {
  proof_type: 'identity_rotation';
  proof_version: 1;
  old_did: string;
  new_did: string;
  rotated_at: string;
  handoff: {
    /** Statement signed by the OLD key. */
    statement: string;
    signature: string;
  };
  acknowledgment: {
    /** Statement signed by the NEW key. */
    statement: string;
    signature: string;
  };
}

export interface RotationResult {
  old_did: string;
  new_did: string;
  identity_path: string;
  continuity_proof_path: string;
  continuity_proof: ContinuityProof;
}

export interface RotateIdentityOptions {
  /** Operate on global identity (~/.clawsig/) instead of project-level. */
  global?: boolean;
  /** Explicit project directory (default: cwd). */
  dir?: string;
}

// ---------------------------------------------------------------------------
// Signing helper
// ---------------------------------------------------------------------------

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function signEd25519(privateKey: CryptoKey, message: Uint8Array): Promise<string> {
  const sigBuffer = await crypto.subtle.sign('Ed25519', privateKey, message as Parameters<typeof crypto.subtle.sign>[2]);
  return base64UrlEncode(new Uint8Array(sigBuffer));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Rotate the agent identity: generate new keypair, produce continuity proof,
 * then atomically replace the identity file.
 *
 * Fail-closed: if any signing or write step fails, the old identity is preserved.
 */
export async function rotateIdentity(options: RotateIdentityOptions = {}): Promise<RotationResult> {
  const projectDir = options.dir ?? process.cwd();
  const isGlobal = !!options.global;

  // 1. Load existing identity using standard precedence
  const oldIdentity = await loadIdentity(projectDir);
  if (!oldIdentity) {
    throw new RotationError(
      'No existing identity found. Run `clawsig init` first to create one.',
    );
  }

  // 2. Resolve identity file path (where we will write the replacement)
  const identityPath = defaultIdentityPath(isGlobal, projectDir);

  // Verify the resolved path actually contains an identity we can load
  // (guards against writing to a path that doesn't match what loadIdentity found)
  let fileIdentity: ClawsigIdentity | null = null;
  try {
    const raw = await readFile(identityPath, 'utf-8');
    const parsed = JSON.parse(raw) as { did?: string };
    if (parsed.did === oldIdentity.did) {
      fileIdentity = oldIdentity;
    }
  } catch {
    // File may not exist at the resolved path
  }

  // If the file at our target path doesn't match the loaded identity,
  // the identity was found via a higher-precedence source (env var, etc.).
  // We still allow rotation but target the resolved path.
  const effectiveIdentity = fileIdentity ?? oldIdentity;

  // 3. Import old keypair for signing
  const oldKeyPair = await importKeyPairJWK({
    publicKey: effectiveIdentity.publicKeyJwk,
    privateKey: effectiveIdentity.privateKeyJwk,
  });

  // 4. Generate new keypair
  const newKeyPair = await generateKeyPair();
  const newDid = await didFromPublicKey(newKeyPair.publicKey);
  const newJwk = await exportKeyPairJWK(newKeyPair);
  const rotatedAt = new Date().toISOString();

  // 5. Build and sign continuity proof (fail-closed: both signatures
  //    must succeed before we touch the identity file)
  const handoffStatement = `clawsig:rotate:handoff:${effectiveIdentity.did}:${newDid}:${rotatedAt}`;
  const ackStatement = `clawsig:rotate:ack:${newDid}:${effectiveIdentity.did}:${rotatedAt}`;

  let handoffSig: string;
  let ackSig: string;

  try {
    const encoder = new TextEncoder();
    handoffSig = await signEd25519(oldKeyPair.privateKey, encoder.encode(handoffStatement));
    ackSig = await signEd25519(newKeyPair.privateKey, encoder.encode(ackStatement));
  } catch (err) {
    throw new RotationError(
      `Failed to generate continuity proof signatures: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const continuityProof: ContinuityProof = {
    proof_type: 'identity_rotation',
    proof_version: 1,
    old_did: effectiveIdentity.did,
    new_did: newDid,
    rotated_at: rotatedAt,
    handoff: {
      statement: handoffStatement,
      signature: handoffSig,
    },
    acknowledgment: {
      statement: ackStatement,
      signature: ackSig,
    },
  };

  // 6. Write continuity proof BEFORE replacing identity (fail-closed)
  const proofDir = dirname(identityPath);
  await mkdir(proofDir, { recursive: true });
  const nonce = crypto.randomUUID().slice(0, 8);
  const proofFilename = `rotation-proof-${rotatedAt.replace(/[:.]/g, '-')}-${nonce}.json`;
  const proofPath = join(proofDir, proofFilename);

  try {
    await writeFile(proofPath, JSON.stringify(continuityProof, null, 2) + '\n', {
      encoding: 'utf-8',
      mode: 0o600,
    });
  } catch (err) {
    throw new RotationError(
      `Failed to write continuity proof: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // 7. Atomically replace identity file (write temp, then rename)
  const newIdentityContent = JSON.stringify(
    {
      did: newDid,
      publicKeyJwk: newJwk.publicKey,
      privateKeyJwk: newJwk.privateKey,
      createdAt: rotatedAt,
    },
    null,
    2,
  ) + '\n';

  const tmpPath = identityPath + `.tmp-${Date.now()}`;
  try {
    await writeFile(tmpPath, newIdentityContent, { encoding: 'utf-8', mode: 0o600 });
    await rename(tmpPath, identityPath);
  } catch (err) {
    // Best-effort cleanup of temp file
    try { await import('node:fs/promises').then(fs => fs.unlink(tmpPath)); } catch { /* ignore */ }
    throw new RotationError(
      `Failed to write new identity file: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  return {
    old_did: effectiveIdentity.did,
    new_did: newDid,
    identity_path: identityPath,
    continuity_proof_path: proofPath,
    continuity_proof: continuityProof,
  };
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

export class RotationError extends Error {
  readonly code = 'ROTATION_ERROR';

  constructor(message: string) {
    super(message);
  }
}
