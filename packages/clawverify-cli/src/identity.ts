/**
 * Persistent agent identity for clawsig.
 *
 * Manages Ed25519 keypairs stored as JWK files on disk.
 * Key lookup order:
 *   1. CLAWSIG_IDENTITY env var (explicit path)
 *   2. .clawsig/identity.jwk.json (project-level)
 *   3. ~/.clawsig/identity.jwk.json (global)
 */

import { readFile, writeFile, mkdir, chmod, stat } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { homedir } from 'node:os';
import {
  generateKeyPair,
  didFromPublicKey,
  exportKeyPairJWK,
  importKeyPairJWK,
} from '@clawbureau/clawsig-sdk';
import type { EphemeralDid } from '@clawbureau/clawsig-sdk';
import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Ed25519 signing helper (avoids depending on unexported SDK internals)
// ---------------------------------------------------------------------------

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function signEd25519(privateKey: CryptoKey, message: Uint8Array): Promise<string> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const sigBuffer = await crypto.subtle.sign('Ed25519', privateKey, message as any);
  return base64UrlEncode(new Uint8Array(sigBuffer));
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ClawsigIdentity {
  /** did:key:z6Mk... identifier derived from the public key. */
  did: string;
  /** Ed25519 public key in JWK format. */
  publicKeyJwk: JsonWebKey;
  /** Ed25519 private key in JWK format. */
  privateKeyJwk: JsonWebKey;
  /** ISO 8601 timestamp of when this identity was created. */
  createdAt: string;
}

/** On-disk format of the identity file. */
interface IdentityFile {
  did: string;
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const IDENTITY_FILENAME = 'identity.jwk.json';
const CLAWSIG_DIR = '.clawsig';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a new Ed25519 keypair, derive a did:key, and save to disk.
 *
 * @param outputPath - Absolute path to write the identity JWK file.
 * @returns The generated identity.
 * @throws If the file cannot be written or permissions cannot be set.
 */
export async function generateIdentity(outputPath: string): Promise<ClawsigIdentity> {
  const keyPair = await generateKeyPair();
  const did = await didFromPublicKey(keyPair.publicKey);
  const jwk = await exportKeyPairJWK(keyPair);
  const createdAt = new Date().toISOString();

  const identity: ClawsigIdentity = {
    did,
    publicKeyJwk: jwk.publicKey,
    privateKeyJwk: jwk.privateKey,
    createdAt,
  };

  // Ensure parent directory exists
  await mkdir(dirname(outputPath), { recursive: true });

  // Write with restrictive permissions
  const content = JSON.stringify(
    {
      did: identity.did,
      publicKeyJwk: identity.publicKeyJwk,
      privateKeyJwk: identity.privateKeyJwk,
      createdAt: identity.createdAt,
    } satisfies IdentityFile,
    null,
    2,
  ) + '\n';

  await writeFile(outputPath, content, { encoding: 'utf-8', mode: 0o600 });

  // Verify permissions were set (belt and suspenders)
  try {
    const fileStat = await stat(outputPath);
    const mode = fileStat.mode & 0o777;
    if (mode !== 0o600) {
      // Try to fix permissions explicitly
      await chmod(outputPath, 0o600);
    }
  } catch {
    // On platforms where stat/chmod may not report correctly (e.g., Windows),
    // we accept the best-effort write above.
  }

  return identity;
}

/**
 * Load a persistent identity from disk.
 *
 * Lookup order:
 *   1. CLAWSIG_IDENTITY env var (explicit path to key file)
 *   2. .clawsig/identity.jwk.json in projectDir (or cwd)
 *   3. ~/.clawsig/identity.jwk.json (global)
 *
 * @param projectDir - Project directory to search for project-level identity.
 *                     Defaults to process.cwd().
 * @returns The loaded identity, or null if no identity file is found.
 */
export async function loadIdentity(projectDir?: string): Promise<ClawsigIdentity | null> {
  const candidates: string[] = [];

  // 1. CLAWSIG_IDENTITY env var
  const envPath = process.env['CLAWSIG_IDENTITY'];
  if (envPath) {
    candidates.push(envPath);
  }

  // 2. Project-level
  const dir = projectDir ?? process.cwd();
  candidates.push(join(dir, CLAWSIG_DIR, IDENTITY_FILENAME));

  // 3. Global
  candidates.push(join(homedir(), CLAWSIG_DIR, IDENTITY_FILENAME));

  for (const path of candidates) {
    const identity = await tryLoadIdentityFile(path);
    if (identity) return identity;
  }

  return null;
}

/**
 * Convert a loaded ClawsigIdentity into an EphemeralDid-compatible object
 * that wrap.ts can use as a drop-in replacement.
 */
export async function identityToAgentDid(identity: ClawsigIdentity): Promise<EphemeralDid> {
  const keyPair = await importKeyPairJWK({
    publicKey: identity.publicKeyJwk,
    privateKey: identity.privateKeyJwk,
  });
  const did = identity.did;

  return {
    did,
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    keyPair,
    sign(data: Uint8Array): Promise<string> {
      return signEd25519(keyPair.privateKey, data);
    },
  };
}

/**
 * Resolve the default identity file path.
 *
 * @param global - If true, returns the global path (~/.clawsig/identity.jwk.json).
 *                 Otherwise returns the project-level path.
 * @param projectDir - Project directory (defaults to cwd).
 */
export function defaultIdentityPath(global: boolean, projectDir?: string): string {
  if (global) {
    return join(homedir(), CLAWSIG_DIR, IDENTITY_FILENAME);
  }
  return join(projectDir ?? process.cwd(), CLAWSIG_DIR, IDENTITY_FILENAME);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Try to read and parse an identity file at the given path.
 * Returns null if the file doesn't exist or is invalid.
 */
async function tryLoadIdentityFile(path: string): Promise<ClawsigIdentity | null> {
  try {
    const raw = await readFile(path, 'utf-8');
    const parsed = JSON.parse(raw) as IdentityFile;

    // Validate required fields
    if (
      typeof parsed.did !== 'string' ||
      !parsed.did.startsWith('did:key:z') ||
      !parsed.publicKeyJwk ||
      !parsed.privateKeyJwk ||
      typeof parsed.createdAt !== 'string'
    ) {
      return null;
    }

    return {
      did: parsed.did,
      publicKeyJwk: parsed.publicKeyJwk,
      privateKeyJwk: parsed.privateKeyJwk,
      createdAt: parsed.createdAt,
    };
  } catch {
    return null;
  }
}
