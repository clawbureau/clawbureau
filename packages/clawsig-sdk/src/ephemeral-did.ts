/**
 * Ephemeral DID generator for clawsig wrap.
 *
 * Generates an Ed25519 keypair + did:key in memory.
 * Keys exist only for the lifetime of the process — zero persistence.
 */

import {
  generateKeyPair,
  didFromPublicKey,
  signEd25519,
} from './crypto.js';
import type { Ed25519KeyPair } from './types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Ephemeral DID identity — lives only in memory for a single run. */
export interface EphemeralDid {
  /** The did:key identifier derived from the public key. */
  did: string;
  /** Web Crypto public key handle. */
  publicKey: CryptoKey;
  /** Web Crypto private key handle. */
  privateKey: CryptoKey;
  /** The underlying Ed25519 key pair. */
  keyPair: Ed25519KeyPair;
  /** Sign arbitrary data and return a base64url-encoded Ed25519 signature. */
  sign(data: Uint8Array): Promise<string>;
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/**
 * Generate an ephemeral Ed25519 did:key identity.
 *
 * The keypair is never persisted — it lives only for the duration of the
 * current process. Ideal for `clawsig wrap` where the agent identity is
 * single-use and disposable.
 *
 * @returns An EphemeralDid with the DID string, key handles, and a sign() helper.
 */
export async function generateEphemeralDid(): Promise<EphemeralDid> {
  const keyPair = await generateKeyPair();
  const did = await didFromPublicKey(keyPair.publicKey);

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
