const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base64urlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64urlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(base64 + padding);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  const out = await crypto.subtle.digest('SHA-256', input);
  return new Uint8Array(out);
}

export async function sha256B64u(input: Uint8Array | string): Promise<string> {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  return base64urlEncode(await sha256Bytes(bytes));
}

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

  // Ed25519 multicodec prefix: 0xed 0x01
  const multicodec = new Uint8Array(2 + publicKeyBytes.length);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(publicKeyBytes, 2);

  return `did:key:z${base58Encode(multicodec)}`;
}

export interface Ed25519Signer {
  did: string;
  privateKey: CryptoKey;
}

export async function importEd25519Signer(seedB64u: string): Promise<Ed25519Signer> {
  const keyBytes = base64urlDecode(seedB64u);

  if (keyBytes.length !== 32 && keyBytes.length !== 64) {
    throw new Error(`Invalid Ed25519 key length: ${keyBytes.length}. Expected 32 or 64 bytes.`);
  }

  const seed = keyBytes.slice(0, 32);

  // Ed25519 PKCS8 format: 48 bytes header + 32 bytes seed.
  const pkcs8Header = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22,
    0x04, 0x20,
  ]);

  const pkcs8 = new Uint8Array(pkcs8Header.length + seed.length);
  pkcs8.set(pkcs8Header);
  pkcs8.set(seed, pkcs8Header.length);

  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;

  if (!jwk.x || typeof jwk.x !== 'string') {
    throw new Error('Failed to derive Ed25519 public key');
  }

  const did = didKeyFromEd25519PublicKeyBytes(base64urlDecode(jwk.x));
  return { did, privateKey };
}

export async function signEd25519(privateKey: CryptoKey, message: string | Uint8Array): Promise<string> {
  const bytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  const sig = await crypto.subtle.sign('Ed25519', privateKey, bytes);
  return base64urlEncode(new Uint8Array(sig));
}

export function base58Decode(str: string): Uint8Array {
  const bytes: number[] = [0];

  for (const char of str) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) throw new Error(`Invalid base58 character: ${char}`);

    for (let i = 0; i < bytes.length; i++) bytes[i]! *= 58;
    bytes[0]! += value;

    let carry = 0;
    for (let i = 0; i < bytes.length; i++) {
      bytes[i]! += carry;
      carry = bytes[i]! >> 8;
      bytes[i]! &= 0xff;
    }
    while (carry) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  for (const char of str) {
    if (char !== '1') break;
    bytes.push(0);
  }

  return new Uint8Array(bytes.reverse());
}

export function extractPublicKeyFromDidKey(did: string): Uint8Array | null {
  if (!did.startsWith('did:key:z')) return null;

  try {
    const decoded = base58Decode(did.slice(9));
    if (decoded[0] === 0xed && decoded[1] === 0x01) {
      return decoded.slice(2);
    }
    return null;
  } catch {
    return null;
  }
}

export async function verifyEd25519Signature(
  did: string,
  signatureB64u: string,
  message: string | Uint8Array
): Promise<boolean> {
  const publicKeyBytes = extractPublicKeyFromDidKey(did);
  if (!publicKeyBytes) return false;

  try {
    const key = await crypto.subtle.importKey('raw', publicKeyBytes, { name: 'Ed25519' }, false, ['verify']);
    const sig = base64urlDecode(signatureB64u);
    const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    return await crypto.subtle.verify('Ed25519', key, sig, msg);
  } catch {
    return false;
  }
}
