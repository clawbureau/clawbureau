import bs58 from 'bs58';

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
 * Multicodec prefix for Ed25519 public keys (0xed01 in varint encoding)
 */
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * Extract Ed25519 public key bytes from did:key.
 *
 * Format: did:key:z<base58btc(multicodec_prefix + public_key)>
 */
export function didKeyToEd25519PublicKeyBytes(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error('UNSUPPORTED_DID');
  }

  const encoded = did.slice('did:key:z'.length);
  const decoded = bs58.decode(encoded);

  if (decoded.length < 2) {
    throw new Error('INVALID_DID_KEY');
  }

  if (decoded[0] !== ED25519_MULTICODEC_PREFIX[0] || decoded[1] !== ED25519_MULTICODEC_PREFIX[1]) {
    throw new Error('UNSUPPORTED_KEY_TYPE');
  }

  const publicKey = decoded.slice(2);
  if (publicKey.length !== 32) {
    throw new Error('INVALID_PUBLIC_KEY_LENGTH');
  }

  return publicKey;
}

/**
 * Import Ed25519 public key (raw 32 byte) into WebCrypto.
 */
export async function importEd25519PublicKeyFromBytes(publicKeyBytes: Uint8Array): Promise<CryptoKey> {
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: ${publicKeyBytes.length}. Expected 32 bytes.`);
  }

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

  return crypto.subtle.importKey('spki', spkiKey, { name: 'Ed25519' }, true, ['verify']);
}

/**
 * Verify an Ed25519 signature (base64url) over UTF-8 string data.
 */
export async function verifyEd25519(publicKey: CryptoKey, signatureB64u: string, data: string): Promise<boolean> {
  const signatureBytes = base64urlDecode(signatureB64u);
  const dataBytes = new TextEncoder().encode(data);

  return crypto.subtle.verify({ name: 'Ed25519' }, publicKey, signatureBytes, dataBytes);
}
