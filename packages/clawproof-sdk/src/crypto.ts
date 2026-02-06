/**
 * Cryptographic utilities for the clawproof SDK.
 *
 * Standalone copy so this package typechecks independently.
 * Uses the Web Crypto API (Node 20+, Deno, Workers).
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
// Hex → bytes / base64url (for bridging clawproxy hex hashes)
// ---------------------------------------------------------------------------

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (normalized.length % 2 !== 0) {
    throw new Error(`Invalid hex string length: ${normalized.length}`);
  }

  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const byte = normalized.slice(i * 2, i * 2 + 2);
    const value = Number.parseInt(byte, 16);
    if (Number.isNaN(value)) {
      throw new Error(`Invalid hex byte: ${byte}`);
    }
    bytes[i] = value;
  }
  return bytes;
}

/**
 * Normalize a SHA-256 hash string into base64url (no padding).
 * Converts clawproxy's hex SHA-256 output (64 chars) when needed.
 */
export function normalizeSha256HashB64u(hash: string): string {
  const normalized = hash.startsWith('0x') ? hash.slice(2) : hash;
  if (/^[a-f0-9]{64}$/i.test(normalized)) {
    return base64UrlEncode(hexToBytes(normalized));
  }
  return hash;
}

// ---------------------------------------------------------------------------
// Base58btc (Bitcoin alphabet)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(bytes: Uint8Array): string {
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }
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
  for (let i = 0; i < leadingZeros; i++) {
    result += '1';
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

// ---------------------------------------------------------------------------
// SHA-256 hashing
// ---------------------------------------------------------------------------

export async function sha256B64u(data: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return base64UrlEncode(new Uint8Array(hashBuffer));
}

export async function hashJsonB64u(value: unknown): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(value));
  return sha256B64u(data);
}

// ---------------------------------------------------------------------------
// Ed25519 key management
// ---------------------------------------------------------------------------

export async function generateKeyPair(): Promise<Ed25519KeyPair> {
  const kp = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export async function exportPublicKeyRaw(publicKey: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  return new Uint8Array(raw);
}

export async function didFromPublicKey(publicKey: CryptoKey): Promise<string> {
  const pubBytes = await exportPublicKeyRaw(publicKey);
  const multicodec = new Uint8Array(2 + pubBytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(pubBytes, 2);
  return `did:key:z${base58Encode(multicodec)}`;
}

export async function signEd25519(
  privateKey: CryptoKey,
  message: Uint8Array,
): Promise<string> {
  const sigBuffer = await crypto.subtle.sign('Ed25519', privateKey, message as BufferSource);
  return base64UrlEncode(new Uint8Array(sigBuffer));
}

export function randomUUID(): string {
  return crypto.randomUUID();
}

// ---------------------------------------------------------------------------
// Key import/export (JWK) for file-based key storage
// ---------------------------------------------------------------------------

export async function exportKeyPairJWK(
  keyPair: Ed25519KeyPair,
): Promise<{ publicKey: JsonWebKey; privateKey: JsonWebKey }> {
  const [publicKey, privateKey] = await Promise.all([
    crypto.subtle.exportKey('jwk', keyPair.publicKey),
    crypto.subtle.exportKey('jwk', keyPair.privateKey),
  ]);
  return { publicKey, privateKey };
}

export async function importKeyPairJWK(jwk: {
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
}): Promise<Ed25519KeyPair> {
  const [publicKey, privateKey] = await Promise.all([
    crypto.subtle.importKey('jwk', jwk.publicKey, 'Ed25519', true, ['verify']),
    crypto.subtle.importKey('jwk', jwk.privateKey, 'Ed25519', true, ['sign']),
  ]);
  return { publicKey, privateKey };
}
