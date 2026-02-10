/**
 * Minimal crypto helpers for clawcontrols
 */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  let leadingZeros = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leadingZeros++;
  }

  const digits = [0];
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
  for (let i = 0; i < leadingZeros; i++) result += '1';
  for (let i = digits.length - 1; i >= 0; i--) result += BASE58_ALPHABET[digits[i]!]!;
  return result;
}

export function didKeyFromEd25519PublicKeyBytes(publicKeyBytes: Uint8Array): string {
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKeyBytes.length}`);
  }

  // Ed25519 multicodec prefix is 0xed 0x01
  const multicodec = new Uint8Array(2 + publicKeyBytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(publicKeyBytes, 2);
  return `did:key:z${base58Encode(multicodec)}`;
}

export function base64urlEncode(data: Uint8Array): string {
  // btoa/atob are available in Workers
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(base64 + padding);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export async function sha256B64u(input: string | Uint8Array): Promise<string> {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return base64urlEncode(new Uint8Array(hashBuffer));
}

export interface Ed25519KeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyBytes: Uint8Array;
}

export async function importEd25519Key(base64urlKey: string): Promise<Ed25519KeyPair> {
  const keyBytes = base64urlDecode(base64urlKey);

  if (keyBytes.length !== 32 && keyBytes.length !== 64) {
    throw new Error(`Invalid Ed25519 key length: ${keyBytes.length}. Expected 32 or 64 bytes.`);
  }

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

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    pkcs8Key,
    { name: 'Ed25519' },
    true,
    ['sign'],
  );

  // Export and re-import to get public key
  const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;
  delete (jwk as any).d;
  jwk.key_ops = ['verify'];

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'Ed25519' },
    true,
    ['verify'],
  );

  const publicKeyBytes = base64urlDecode(jwk.x as string);

  return { privateKey, publicKey, publicKeyBytes };
}

export async function signEd25519(privateKey: CryptoKey, data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, bytes);
  return base64urlEncode(new Uint8Array(sig));
}
