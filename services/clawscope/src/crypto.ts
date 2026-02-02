/**
 * Cryptographic helpers for clawscope (CST issuer)
 */

/**
 * Compute SHA-256 hash of data and return as hex string
 */
export async function sha256(data: string | ArrayBuffer): Promise<string> {
  const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;

  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
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
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
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
 * Import Ed25519 private key from base64url-encoded raw bytes.
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

  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8Key, { name: 'Ed25519' }, true, [
    'sign',
  ]);

  // Export and re-import to get public key
  const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;
  delete jwk.d; // remove private component
  jwk.key_ops = ['verify'];

  const publicKey = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, true, ['verify']);

  // Raw public key is JWK.x
  const publicKeyBytes = base64urlDecode(jwk.x as string);

  return { privateKey, publicKey, publicKeyBytes };
}

/**
 * Sign data using Ed25519 and return base64url signature
 */
export async function signEd25519(privateKey: CryptoKey, data: string): Promise<string> {
  const dataBytes = new TextEncoder().encode(data);

  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, dataBytes);
  return base64urlEncode(new Uint8Array(signature));
}

/**
 * Compute key ID (kid) from public key bytes.
 * Format: SHA-256 hash truncated to first 16 characters.
 */
export async function computeKeyId(publicKeyBytes: Uint8Array): Promise<string> {
  const hash = await sha256(publicKeyBytes.buffer as ArrayBuffer);
  return hash.slice(0, 16);
}
