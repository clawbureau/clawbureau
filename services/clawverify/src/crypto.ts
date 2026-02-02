/**
 * Cryptographic utilities for signature verification
 */

import type { HashAlgorithm, Algorithm } from './types';

/**
 * Decode base64url to Uint8Array
 */
export function base64UrlDecode(str: string): Uint8Array {
  // Replace base64url chars with base64
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Pad with = if needed
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encode Uint8Array to base64url
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Compute hash of payload using specified algorithm
 */
export async function computeHash(
  payload: unknown,
  algorithm: HashAlgorithm
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(payload));

  if (algorithm === 'SHA-256') {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return base64UrlEncode(new Uint8Array(hashBuffer));
  }

  // BLAKE3 would require a library - for now SHA-256 is primary
  throw new Error(`Hash algorithm not implemented: ${algorithm}`);
}

/**
 * Extract public key bytes from did:key
 * Format: did:key:z<multibase-encoded-public-key>
 */
export function extractPublicKeyFromDidKey(did: string): Uint8Array | null {
  if (!did.startsWith('did:key:z')) {
    return null;
  }

  try {
    // Remove did:key:z prefix and decode multibase (z = base58btc)
    const multibase = did.slice(9);
    const decoded = base58Decode(multibase);

    // Ed25519 multicodec prefix is 0xed01
    if (decoded[0] === 0xed && decoded[1] === 0x01) {
      return decoded.slice(2);
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Base58 Bitcoin alphabet decoder
 */
const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Decode(str: string): Uint8Array {
  const bytes: number[] = [0];

  for (const char of str) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`Invalid base58 character: ${char}`);
    }

    for (let i = 0; i < bytes.length; i++) {
      bytes[i] *= 58;
    }
    bytes[0] += value;

    let carry = 0;
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] += carry;
      carry = bytes[i] >> 8;
      bytes[i] &= 0xff;
    }

    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  // Handle leading zeros
  for (const char of str) {
    if (char !== '1') break;
    bytes.push(0);
  }

  return new Uint8Array(bytes.reverse());
}

/**
 * Verify Ed25519 signature using Web Crypto API
 */
export async function verifySignature(
  algorithm: Algorithm,
  publicKeyBytes: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array
): Promise<boolean> {
  if (algorithm !== 'Ed25519') {
    throw new Error(`Algorithm not supported: ${algorithm}`);
  }

  try {
    // Import the public key
    const publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'Ed25519' },
      false,
      ['verify']
    );

    // Verify the signature
    return await crypto.subtle.verify('Ed25519', publicKey, signature, message);
  } catch {
    return false;
  }
}
