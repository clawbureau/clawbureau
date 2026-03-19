import type { ViewerIdentity } from './inspect-identity.js';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const HKDF_INFO = new TextEncoder().encode('clawsig-epv-002-key-wrap');
const ED25519_P = (1n << 255n) - 19n;

export interface ViewerKeyEntry {
  viewer_did: string;
  ephemeral_public_key_b64u: string;
  wrapped_key_b64u: string;
  wrapped_key_iv_b64u: string;
  wrapped_key_tag_b64u: string;
  role?: 'owner' | 'requester' | 'auditor';
  key_derivation?: 'X25519-HKDF-SHA256';
}

export interface EncryptedPayloadFields {
  ciphertext_b64u: string;
  iv_b64u: string;
  tag_b64u: string;
  plaintext_hash_b64u: string;
}

export interface PublicLayerSummary {
  bundle_version: string;
  schema_version: string | null;
  visibility: string | null;
  agent_did: string | null;
  signer_did: string | null;
  bundle_id: string | null;
  issued_at: string | null;
  has_encrypted_payload: boolean;
  viewer_count: number;
  viewer_dids: string[];
  viewer_roles: Record<string, string>;
}

export type InspectDecryptErrorCode =
  | 'INSPECT_INVALID_BUNDLE'
  | 'INSPECT_V1_NO_DECRYPT'
  | 'INSPECT_NOT_AUTHORIZED'
  | 'INSPECT_CRYPTO_FAILURE'
  | 'INSPECT_INTEGRITY_FAILURE';

export class InspectDecryptError extends Error {
  constructor(
    public readonly code: InspectDecryptErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'InspectDecryptError';
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function fromBase64Url(input: string): Uint8Array {
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase58(input: string): Uint8Array {
  const map = new Map<string, number>();
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    map.set(BASE58_ALPHABET[i]!, i);
  }

  let result = 0n;
  for (const char of input) {
    const value = map.get(char);
    if (value === undefined) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    result = result * 58n + BigInt(value);
  }

  let leadingZeroCount = 0;
  for (const char of input) {
    if (char === '1') {
      leadingZeroCount++;
    } else {
      break;
    }
  }

  const hex = result.toString(16);
  const paddedHex = hex.length % 2 === 0 ? hex : `0${hex}`;
  const payload = paddedHex === '' ? new Uint8Array() : Uint8Array.from((paddedHex.match(/.{1,2}/g) ?? []).map((h) => Number.parseInt(h, 16)));

  const out = new Uint8Array(leadingZeroCount + payload.length);
  out.set(payload, leadingZeroCount);
  return out;
}

function parseDidKeyToEd25519PublicKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error(`Malformed viewer DID: ${did}`);
  }

  const multibase = did.slice('did:key:'.length);
  if (multibase[0] !== 'z') {
    throw new Error('Unsupported did:key multibase prefix');
  }

  const decoded = decodeBase58(multibase.slice(1));
  if (decoded.length < 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error('Malformed did:key Ed25519 multicodec prefix');
  }

  const key = decoded.slice(2);
  if (key.length !== 32) {
    throw new Error('Invalid Ed25519 public key length in did:key');
  }

  return key;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;

  while (e > 0n) {
    if ((e & 1n) === 1n) {
      result = (result * b) % mod;
    }
    e >>= 1n;
    b = (b * b) % mod;
  }

  return result;
}

function modInverse(a: bigint, mod: bigint): bigint {
  return modPow(a, mod - 2n, mod);
}

function ed25519PublicKeyToX25519(edPub: Uint8Array): Uint8Array {
  if (edPub.length !== 32) {
    throw new Error(`Invalid Ed25519 public key length: ${edPub.length}`);
  }

  const yBytes = new Uint8Array(edPub);
  yBytes[31] = yBytes[31]! & 0x7f;

  let y = 0n;
  for (let i = 0; i < 32; i++) {
    y |= BigInt(yBytes[i]!) << BigInt(8 * i);
  }

  const numerator = (1n + y) % ED25519_P;
  const denominator = ((ED25519_P + 1n - y) % ED25519_P + ED25519_P) % ED25519_P;
  if (denominator === 0n) {
    throw new Error('Ed25519->X25519 conversion failed on degenerate key');
  }

  const u = (numerator * modInverse(denominator, ED25519_P)) % ED25519_P;

  const out = new Uint8Array(32);
  let value = u;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }

  return out;
}

async function ed25519SeedToX25519Private(seed: Uint8Array): Promise<Uint8Array> {
  if (seed.length !== 32) {
    throw new Error(`Invalid Ed25519 private seed length: ${seed.length}`);
  }

  const hash = new Uint8Array(await crypto.subtle.digest('SHA-512', seed));
  const scalar = hash.slice(0, 32);

  scalar[0] = scalar[0]! & 248;
  scalar[31] = scalar[31]! & 127;
  scalar[31] = scalar[31]! | 64;

  return scalar;
}

async function createX25519PrivateKeyFromEd25519Jwk(
  privateJwk: JsonWebKey,
  publicJwk: JsonWebKey,
): Promise<CryptoKey> {
  if (typeof privateJwk.d !== 'string' || typeof publicJwk.x !== 'string') {
    throw new Error('Ed25519 JWK missing required fields');
  }

  const seed = fromBase64Url(privateJwk.d);
  const edPublic = fromBase64Url(publicJwk.x);

  const x25519Private = await ed25519SeedToX25519Private(seed);
  const x25519Public = ed25519PublicKeyToX25519(edPublic);

  return crypto.subtle.importKey(
    'jwk',
    {
      kty: 'OKP',
      crv: 'X25519',
      d: toBase64Url(x25519Private),
      x: toBase64Url(x25519Public),
      key_ops: ['deriveBits'],
      ext: false,
    },
    { name: 'X25519' },
    false,
    ['deriveBits'],
  );
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function deriveHkdfSalt(
  senderX25519PublicKey: Uint8Array,
  recipientX25519PublicKey: Uint8Array,
): Promise<Uint8Array> {
  const joined = concatBytes(senderX25519PublicKey, recipientX25519PublicKey);
  const hash = await crypto.subtle.digest('SHA-256', joined);
  return new Uint8Array(hash);
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

async function unwrapContentKey(
  viewerX25519PrivateKey: CryptoKey,
  entry: ViewerKeyEntry,
  viewerX25519PublicKey: Uint8Array,
): Promise<Uint8Array> {
  const ephemeralPublicRaw = fromBase64Url(entry.ephemeral_public_key_b64u);
  const ephemeralPublicKey = await crypto.subtle.importKey(
    'jwk',
    {
      kty: 'OKP',
      crv: 'X25519',
      x: entry.ephemeral_public_key_b64u,
      ext: false,
    },
    { name: 'X25519' },
    false,
    [],
  );

  const sharedSecretBits = await crypto.subtle.deriveBits(
    {
      name: 'X25519',
      // Workers types currently model this as "$public", but runtime expects "public".
      public: ephemeralPublicKey,
    } as unknown as SubtleCryptoDeriveKeyAlgorithm,
    viewerX25519PrivateKey,
    256,
  );

  const hkdfInputKey = await crypto.subtle.importKey(
    'raw',
    sharedSecretBits,
    { name: 'HKDF' },
    false,
    ['deriveBits'],
  );

  const hkdfSalt = await deriveHkdfSalt(ephemeralPublicRaw, viewerX25519PublicKey);

  const wrappingKeyBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: hkdfSalt,
      info: HKDF_INFO,
    },
    hkdfInputKey,
    256,
  );

  const wrappingKey = await crypto.subtle.importKey(
    'raw',
    wrappingKeyBits,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );

  const wrappedKey = fromBase64Url(entry.wrapped_key_b64u);
  const wrappedKeyIv = fromBase64Url(entry.wrapped_key_iv_b64u);
  const wrappedKeyTag = fromBase64Url(entry.wrapped_key_tag_b64u);
  const wrappedCiphertext = concatBytes(wrappedKey, wrappedKeyTag);

  const contentKeyBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: wrappedKeyIv,
      tagLength: 128,
    },
    wrappingKey,
    wrappedCiphertext,
  );

  return new Uint8Array(contentKeyBuffer);
}

async function decryptAndVerifyPayload(
  contentKey: Uint8Array,
  encryptedPayload: EncryptedPayloadFields,
): Promise<Record<string, unknown>> {
  const aesKey = await crypto.subtle.importKey(
    'raw',
    contentKey,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );

  const ciphertext = fromBase64Url(encryptedPayload.ciphertext_b64u);
  const iv = fromBase64Url(encryptedPayload.iv_b64u);
  const tag = fromBase64Url(encryptedPayload.tag_b64u);
  const expectedHash = fromBase64Url(encryptedPayload.plaintext_hash_b64u);

  const cipherWithTag = concatBytes(ciphertext, tag);
  const plaintextBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv,
      tagLength: 128,
    },
    aesKey,
    cipherWithTag,
  );

  const plaintext = new Uint8Array(plaintextBuffer);
  const actualHash = new Uint8Array(await crypto.subtle.digest('SHA-256', plaintext));

  if (!equalBytes(actualHash, expectedHash)) {
    throw new InspectDecryptError(
      'INSPECT_INTEGRITY_FAILURE',
      'Plaintext integrity check failed: SHA-256 hash mismatch after decryption',
    );
  }

  const parsed = JSON.parse(new TextDecoder().decode(plaintext));
  if (!isObject(parsed)) {
    throw new InspectDecryptError('INSPECT_INVALID_BUNDLE', 'Decrypted payload is not a valid object');
  }

  return parsed;
}

export function extractPublicLayer(bundle: Record<string, unknown>): PublicLayerSummary {
  const payload = isObject(bundle.payload) ? bundle.payload : bundle;
  if (!isObject(payload)) {
    throw new InspectDecryptError('INSPECT_INVALID_BUNDLE', 'Bundle missing payload object');
  }

  const viewerKeys = Array.isArray(payload.viewer_keys)
    ? payload.viewer_keys.filter((entry): entry is ViewerKeyEntry => isObject(entry) && typeof entry.viewer_did === 'string')
    : [];

  const viewerRoles: Record<string, string> = {};
  for (const vk of viewerKeys) {
    if (typeof vk.role === 'string') {
      viewerRoles[vk.viewer_did] = vk.role;
    }
  }

  return {
    bundle_version: String(payload.bundle_version ?? '1'),
    schema_version: typeof payload.schema_version === 'string' ? payload.schema_version : null,
    visibility: typeof payload.visibility === 'string' ? payload.visibility : null,
    agent_did: typeof payload.agent_did === 'string' ? payload.agent_did : null,
    signer_did: typeof bundle.signer_did === 'string' ? bundle.signer_did : null,
    bundle_id: typeof payload.bundle_id === 'string' ? payload.bundle_id : null,
    issued_at: typeof bundle.issued_at === 'string' ? bundle.issued_at : null,
    has_encrypted_payload: payload.encrypted_payload !== undefined,
    viewer_count: viewerKeys.length,
    viewer_dids: viewerKeys.map((vk) => vk.viewer_did),
    viewer_roles: viewerRoles,
  };
}

export async function decryptBundleForIdentity(
  bundle: Record<string, unknown>,
  identity: ViewerIdentity,
): Promise<Record<string, unknown>> {
  const payload = isObject(bundle.payload) ? bundle.payload : bundle;
  if (!isObject(payload)) {
    throw new InspectDecryptError('INSPECT_INVALID_BUNDLE', 'Bundle missing payload object');
  }

  const version = String(payload.bundle_version ?? '1');
  if (version !== '2') {
    throw new InspectDecryptError(
      'INSPECT_V1_NO_DECRYPT',
      `Cannot decrypt v${version} bundle. Decryption requires v2 encrypted payload.`,
    );
  }

  const encryptedPayloadRaw = payload.encrypted_payload;
  if (!isObject(encryptedPayloadRaw)) {
    throw new InspectDecryptError('INSPECT_INVALID_BUNDLE', 'v2 bundle missing encrypted_payload');
  }

  if (
    !isNonEmptyString(encryptedPayloadRaw.ciphertext_b64u) ||
    !isNonEmptyString(encryptedPayloadRaw.iv_b64u) ||
    !isNonEmptyString(encryptedPayloadRaw.tag_b64u) ||
    !isNonEmptyString(encryptedPayloadRaw.plaintext_hash_b64u)
  ) {
    throw new InspectDecryptError('INSPECT_INVALID_BUNDLE', 'encrypted_payload missing required fields');
  }

  const encryptedPayload: EncryptedPayloadFields = {
    ciphertext_b64u: encryptedPayloadRaw.ciphertext_b64u,
    iv_b64u: encryptedPayloadRaw.iv_b64u,
    tag_b64u: encryptedPayloadRaw.tag_b64u,
    plaintext_hash_b64u: encryptedPayloadRaw.plaintext_hash_b64u,
  };

  const viewerKeys = Array.isArray(payload.viewer_keys)
    ? payload.viewer_keys.filter((entry): entry is ViewerKeyEntry => isObject(entry) && typeof entry.viewer_did === 'string')
    : [];

  const myEntry = viewerKeys.find((entry) => entry.viewer_did === identity.did);
  if (!myEntry) {
    throw new InspectDecryptError(
      'INSPECT_NOT_AUTHORIZED',
      `Identity DID ${identity.did} is not listed in viewer_keys`,
    );
  }

  if (
    !isNonEmptyString(myEntry.ephemeral_public_key_b64u) ||
    !isNonEmptyString(myEntry.wrapped_key_b64u) ||
    !isNonEmptyString(myEntry.wrapped_key_iv_b64u) ||
    !isNonEmptyString(myEntry.wrapped_key_tag_b64u)
  ) {
    throw new InspectDecryptError('INSPECT_INVALID_BUNDLE', 'viewer_keys entry missing required fields');
  }

  try {
    const didPublicKey = parseDidKeyToEd25519PublicKey(identity.did);
    if (typeof identity.publicKeyJwk.x !== 'string') {
      throw new Error('Identity public JWK missing x field');
    }
    const jwkPublicKey = fromBase64Url(identity.publicKeyJwk.x);
    if (!equalBytes(didPublicKey, jwkPublicKey)) {
      throw new Error('Identity JWK public key does not match DID');
    }

    const viewerPrivateKey = await createX25519PrivateKeyFromEd25519Jwk(
      identity.privateKeyJwk,
      identity.publicKeyJwk,
    );

    const viewerX25519PublicKey = ed25519PublicKeyToX25519(didPublicKey);
    const contentKey = await unwrapContentKey(viewerPrivateKey, myEntry, viewerX25519PublicKey);
    return decryptAndVerifyPayload(contentKey, encryptedPayload);
  } catch (error) {
    if (error instanceof InspectDecryptError) {
      throw error;
    }

    const msg = error instanceof Error ? error.message : String(error);
    throw new InspectDecryptError('INSPECT_CRYPTO_FAILURE', `Failed to decrypt payload: ${msg}`);
  }
}
