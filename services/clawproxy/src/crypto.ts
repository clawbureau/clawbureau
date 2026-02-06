/**
 * Cryptographic utilities for receipt generation and signing
 */

/**
 * Compute SHA-256 hash of data and return as hex string
 */
export async function sha256(data: string | ArrayBuffer): Promise<string> {
  const buffer = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : data;

  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Compute SHA-256 hash of data and return as base64url (no padding)
 */
export async function sha256B64u(
  data: string | ArrayBuffer | Uint8Array
): Promise<string> {
  const buffer =
    typeof data === 'string'
      ? new TextEncoder().encode(data)
      : data instanceof Uint8Array
        ? data
        : new Uint8Array(data);

  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return base64urlEncode(new Uint8Array(hashBuffer));
}

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

/** Convert a hex-encoded SHA-256 hash to base64url (no padding). */
export function sha256HexToB64u(hashHex: string): string {
  return base64urlEncode(hexToBytes(hashHex));
}

// ---------------------------------------------------------------------------
// Base58btc / did:key
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

  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i]! << 8;
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
    result += BASE58_ALPHABET[digits[i]!];
  }

  return result;
}

/**
 * Derive a did:key DID for an Ed25519 public key.
 * Format: did:key:z<base58btc(0xed01 + rawPublicKeyBytes)>
 */
export function didKeyFromEd25519PublicKeyBytes(publicKeyBytes: Uint8Array): string {
  // Ed25519 multicodec prefix is 0xed 0x01
  const multicodec = new Uint8Array(2 + publicKeyBytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(publicKeyBytes, 2);

  return `did:key:z${base58Encode(multicodec)}`;
}

/**
 * Encode bytes to base64url (RFC 4648)
 */
export function base64urlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode base64url to bytes
 */
export function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(base64 + padding);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

/**
 * Ed25519 key pair for signing operations
 */
export interface Ed25519KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyBytes: Uint8Array;
}

/**
 * Import Ed25519 private key from base64url-encoded raw bytes
 * Returns both private and derived public key
 *
 * Key format: 32 bytes seed (private key) or 64 bytes (seed + public key)
 */
export async function importEd25519Key(base64urlKey: string): Promise<Ed25519KeyPair> {
  const keyBytes = base64urlDecode(base64urlKey);

  // Ed25519 private key can be 32 bytes (seed) or 64 bytes (seed + pubkey)
  if (keyBytes.length !== 32 && keyBytes.length !== 64) {
    throw new Error(`Invalid Ed25519 key length: ${keyBytes.length}. Expected 32 or 64 bytes.`);
  }

  // Use first 32 bytes as seed
  const seed = keyBytes.slice(0, 32);

  // Import as PKCS8 format (required by Web Crypto)
  // Ed25519 PKCS8 format: 48 bytes header + 32 bytes seed
  const pkcs8Header = new Uint8Array([
    0x30, 0x2e, // SEQUENCE, length 46
    0x02, 0x01, 0x00, // INTEGER 0 (version)
    0x30, 0x05, // SEQUENCE, length 5
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x04, 0x22, // OCTET STRING, length 34
    0x04, 0x20, // OCTET STRING, length 32 (wrapped seed)
  ]);

  const pkcs8Key = new Uint8Array(pkcs8Header.length + seed.length);
  pkcs8Key.set(pkcs8Header);
  pkcs8Key.set(seed, pkcs8Header.length);

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8Key,
    { name: 'Ed25519' },
    true,
    ['sign']
  );

  // Export and re-import to get public key
  const jwk = await crypto.subtle.exportKey('jwk', privateKey) as JsonWebKey;
  delete jwk.d; // Remove private component
  jwk.key_ops = ['verify'];

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'Ed25519' },
    true,
    ['verify']
  );

  // Get raw public key bytes for DID
  const publicKeyBytes = base64urlDecode(jwk.x as string);

  return { privateKey, publicKey, publicKeyBytes };
}

/**
 * Sign data using Ed25519 and return base64url signature
 */
export async function signEd25519(
  privateKey: CryptoKey,
  data: string | Uint8Array
): Promise<string> {
  const dataBytes = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : data;

  const signature = await crypto.subtle.sign(
    { name: 'Ed25519' },
    privateKey,
    dataBytes
  );

  return base64urlEncode(new Uint8Array(signature));
}

/**
 * Verify Ed25519 signature
 */
export async function verifyEd25519(
  publicKey: CryptoKey,
  signature: string,
  data: string | Uint8Array
): Promise<boolean> {
  const signatureBytes = base64urlDecode(signature);
  const dataBytes = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : data;

  return crypto.subtle.verify(
    { name: 'Ed25519' },
    publicKey,
    signatureBytes,
    dataBytes
  );
}

/**
 * Compute key ID (kid) from public key bytes
 * Format: SHA-256 hash truncated to first 16 characters
 */
export async function computeKeyId(publicKeyBytes: Uint8Array): Promise<string> {
  const hash = await sha256(publicKeyBytes.buffer as ArrayBuffer);
  return hash.slice(0, 16);
}

/**
 * Import Ed25519 public key from base64url-encoded raw bytes
 * Used for receipt verification
 */
export async function importEd25519PublicKey(base64urlKey: string): Promise<CryptoKey> {
  const publicKeyBytes = base64urlDecode(base64urlKey);

  if (publicKeyBytes.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: ${publicKeyBytes.length}. Expected 32 bytes.`);
  }

  // Import as raw SPKI format
  // Ed25519 SPKI header (12 bytes) + 32 bytes raw public key
  const spkiHeader = new Uint8Array([
    0x30, 0x2a, // SEQUENCE, length 42
    0x30, 0x05, // SEQUENCE, length 5
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x03, 0x21, 0x00, // BIT STRING, length 33, no unused bits
  ]);

  const spkiKey = new Uint8Array(spkiHeader.length + publicKeyBytes.length);
  spkiKey.set(spkiHeader);
  spkiKey.set(publicKeyBytes, spkiHeader.length);

  return crypto.subtle.importKey(
    'spki',
    spkiKey,
    { name: 'Ed25519' },
    true,
    ['verify']
  );
}

/**
 * AES-256-GCM encryption key
 */
export interface AesKey {
  key: CryptoKey;
  keyBytes: Uint8Array;
}

/**
 * Import AES-256 key from base64url-encoded raw bytes
 */
export async function importAesKey(base64urlKey: string): Promise<AesKey> {
  const keyBytes = base64urlDecode(base64urlKey);

  if (keyBytes.length !== 32) {
    throw new Error(`Invalid AES-256 key length: ${keyBytes.length}. Expected 32 bytes.`);
  }

  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );

  return { key, keyBytes };
}

/**
 * Encrypted payload result from AES-256-GCM encryption
 */
export interface AesEncryptedPayload {
  /** Base64url-encoded IV (12 bytes) */
  iv: string;
  /** Base64url-encoded ciphertext */
  ciphertext: string;
  /** Base64url-encoded authentication tag (16 bytes) */
  tag: string;
}

/**
 * Encrypt data using AES-256-GCM
 * Returns IV, ciphertext, and auth tag separately
 */
export async function encryptAes256Gcm(
  key: CryptoKey,
  plaintext: string
): Promise<AesEncryptedPayload> {
  // Generate 12-byte IV (recommended for GCM)
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = new TextEncoder().encode(plaintext);

  // Encrypt with AES-256-GCM (tag is appended to ciphertext by Web Crypto)
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    plaintextBytes
  );

  const encryptedBytes = new Uint8Array(encrypted);

  // Split ciphertext and tag (last 16 bytes is the tag)
  const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
  const tag = encryptedBytes.slice(encryptedBytes.length - 16);

  return {
    iv: base64urlEncode(iv),
    ciphertext: base64urlEncode(ciphertext),
    tag: base64urlEncode(tag),
  };
}

/**
 * Decrypt data using AES-256-GCM
 */
export async function decryptAes256Gcm(
  key: CryptoKey,
  payload: AesEncryptedPayload
): Promise<string> {
  const iv = base64urlDecode(payload.iv);
  const ciphertext = base64urlDecode(payload.ciphertext);
  const tag = base64urlDecode(payload.tag);

  // Combine ciphertext and tag (Web Crypto expects them concatenated)
  const encryptedBytes = new Uint8Array(ciphertext.length + tag.length);
  encryptedBytes.set(ciphertext, 0);
  encryptedBytes.set(tag, ciphertext.length);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    encryptedBytes
  );

  return new TextDecoder().decode(decrypted);
}
