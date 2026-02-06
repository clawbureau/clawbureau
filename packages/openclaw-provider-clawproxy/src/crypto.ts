/**
 * Cryptographic utilities for the harness recorder.
 *
 * Provides Ed25519 key generation, signing, SHA-256 hashing,
 * base64url encoding, base58btc encoding, and DID derivation.
 * Uses the Web Crypto API (available in Node 20+, Deno, Workers).
 */

import type { Ed25519KeyPair } from './types';

// ---------------------------------------------------------------------------
// Base64url
// ---------------------------------------------------------------------------

export function base64UrlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Base58btc (Bitcoin alphabet)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(bytes: Uint8Array): string {
  // Count leading zeros
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }

  // Convert to base58
  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let result = '';
  // Leading '1's for zero bytes
  for (let i = 0; i < leadingZeros; i++) {
    result += '1';
  }
  // Digits in reverse order
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

// ---------------------------------------------------------------------------
// SHA-256 hashing
// ---------------------------------------------------------------------------

/** SHA-256 hash of raw bytes, returned as base64url. */
export async function sha256B64u(data: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

/** SHA-256 hash of a JSON-serializable value (via JSON.stringify), returned as base64url. */
export async function hashJsonB64u(value: unknown): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(value));
  return sha256B64u(data);
}

// ---------------------------------------------------------------------------
// Ed25519 key management
// ---------------------------------------------------------------------------

/** Generate a new Ed25519 key pair. */
export async function generateKeyPair(): Promise<Ed25519KeyPair> {
  const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/** Export the raw public key bytes (32 bytes) from an Ed25519 CryptoKey. */
export async function exportPublicKeyRaw(publicKey: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  return new Uint8Array(raw);
}

/**
 * Derive a did:key DID from an Ed25519 public key.
 * Format: did:key:z<base58btc(0xed01 + publicKeyBytes)>
 */
export async function didFromPublicKey(publicKey: CryptoKey): Promise<string> {
  const pubBytes = await exportPublicKeyRaw(publicKey);
  // Ed25519 multicodec prefix: 0xed 0x01
  const multicodec = new Uint8Array(2 + pubBytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(pubBytes, 2);
  // Multibase prefix 'z' = base58btc
  return `did:key:z${base58Encode(multicodec)}`;
}

// ---------------------------------------------------------------------------
// Ed25519 signing
// ---------------------------------------------------------------------------

/**
 * Sign a message with Ed25519.
 * Returns the signature as base64url.
 */
export async function signEd25519(
  privateKey: CryptoKey,
  message: Uint8Array,
): Promise<string> {
  const sigBuffer = await crypto.subtle.sign('Ed25519', privateKey, message as BufferSource);
  return base64UrlEncode(new Uint8Array(sigBuffer));
}

// ---------------------------------------------------------------------------
// UUID generation
// ---------------------------------------------------------------------------

/** Generate a random UUID v4. */
export function randomUUID(): string {
  return crypto.randomUUID();
}
