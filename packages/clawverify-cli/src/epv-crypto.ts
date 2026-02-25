/**
 * EPV-002: Encrypted Proof Visibility crypto module.
 *
 * Provides:
 * - Visibility mode types and validation
 * - DID parsing (did:key -> raw Ed25519 public key bytes)
 * - Ed25519 -> X25519 public key conversion (Edwards-to-Montgomery birational map)
 * - AES-256-GCM content encryption
 * - X25519 ECDH + HKDF-SHA256 per-viewer key wrapping
 * - High-level applyVisibility() to transform a proof bundle payload
 *
 * Fail-closed: every operation throws on failure. No silent fallback.
 */

import crypto from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type VisibilityMode = 'public' | 'owner' | 'requester' | 'auditor';

export const VALID_VISIBILITY_MODES: readonly VisibilityMode[] = [
  'public', 'owner', 'requester', 'auditor',
] as const;

export interface EncryptedPayloadFields {
  ciphertext_b64u: string;
  iv_b64u: string;
  tag_b64u: string;
  plaintext_hash_b64u: string;
}

export interface ViewerKeyEntry {
  viewer_did: string;
  ephemeral_public_key_b64u: string;
  wrapped_key_b64u: string;
  wrapped_key_iv_b64u: string;
  wrapped_key_tag_b64u: string;
  role: 'owner' | 'requester' | 'auditor';
  key_derivation: 'X25519-HKDF-SHA256';
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Curve25519 field prime: 2^255 - 19. */
const ED25519_P = (1n << 255n) - 19n;

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** HKDF info string for key derivation (unique to EPV-002). */
const HKDF_INFO = 'clawsig-epv-002-key-wrap';

/** HKDF salt: 32 zero bytes (per HKDF spec when no natural salt exists). */
const HKDF_SALT = Buffer.alloc(32);

/**
 * Payload fields that contain sensitive operational details.
 * These are encrypted and removed from the outer bundle in non-public modes.
 */
const SENSITIVE_PAYLOAD_FIELDS = [
  'receipts',
  'event_chain',
  'vir_receipts',
  'web_receipts',
  'tool_receipts',
  'side_effect_receipts',
  'human_approval_receipts',
  'delegation_receipts',
  'execution_receipts',
  'network_receipts',
  'attestations',
  'coverage_attestations',
  'binary_semantic_evidence_attestations',
  'rate_limit_claims',
] as const;

// ---------------------------------------------------------------------------
// Base64url helpers
// ---------------------------------------------------------------------------

function toBase64Url(bytes: Uint8Array | Buffer): string {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function fromBase64Url(str: string): Buffer {
  let padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4;
  if (pad === 2) padded += '==';
  else if (pad === 3) padded += '=';
  return Buffer.from(padded, 'base64');
}

// ---------------------------------------------------------------------------
// Base58btc decoder (for did:key parsing)
// ---------------------------------------------------------------------------

function decodeBase58(input: string): Uint8Array {
  const map = new Map<string, number>();
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    map.set(BASE58_ALPHABET[i]!, i);
  }

  let result = 0n;
  for (const char of input) {
    const val = map.get(char);
    if (val === undefined) {
      throw new Error(`Invalid base58 character: '${char}'`);
    }
    result = result * 58n + BigInt(val);
  }

  // Count leading '1' chars (zero bytes in base58)
  let leadingZeros = 0;
  for (const char of input) {
    if (char === '1') leadingZeros++;
    else break;
  }

  // Convert BigInt to bytes
  const hex = result.toString(16);
  const paddedHex = hex.length % 2 ? '0' + hex : hex;
  const bytes = Buffer.from(paddedHex, 'hex');

  const output = new Uint8Array(leadingZeros + bytes.length);
  output.set(bytes, leadingZeros);
  return output;
}

// ---------------------------------------------------------------------------
// DID parsing
// ---------------------------------------------------------------------------

/**
 * Parse a did:key identifier to extract the raw Ed25519 public key bytes.
 *
 * Expected format: did:key:z6Mk<base58btc-encoded-multicodec-key>
 * Multicodec prefix for Ed25519 public key: 0xed 0x01.
 *
 * @throws Error if the DID format is invalid or not Ed25519.
 */
export function parseDidKeyToEd25519PublicKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw new Error(
      `Malformed viewer DID: expected did:key:z... format, got: ${did}`,
    );
  }

  const multibaseEncoded = did.slice('did:key:'.length);

  // 'z' prefix = base58btc
  if (multibaseEncoded[0] !== 'z') {
    throw new Error(
      `Malformed viewer DID: unsupported multibase prefix '${multibaseEncoded[0]}'`,
    );
  }

  const decoded = decodeBase58(multibaseEncoded.slice(1));

  // Verify Ed25519 multicodec prefix: 0xed 0x01
  if (decoded.length < 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error(
      `Malformed viewer DID: expected Ed25519 multicodec prefix (0xed01), ` +
      `got: 0x${decoded[0]?.toString(16).padStart(2, '0')}${decoded[1]?.toString(16).padStart(2, '0')}`,
    );
  }

  const publicKeyBytes = decoded.slice(2);
  if (publicKeyBytes.length !== 32) {
    throw new Error(
      `Malformed viewer DID: expected 32-byte Ed25519 public key, got ${publicKeyBytes.length} bytes`,
    );
  }

  return publicKeyBytes;
}

// ---------------------------------------------------------------------------
// Ed25519 -> X25519 conversion (birational map)
// ---------------------------------------------------------------------------

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function modInverse(a: bigint, p: bigint): bigint {
  return modPow(a, p - 2n, p);
}

/**
 * Convert a 32-byte Ed25519 public key to a 32-byte X25519 public key.
 *
 * Uses the Edwards-to-Montgomery birational map:
 *   u = (1 + y) / (1 - y) mod p
 *
 * where y is the y-coordinate of the Ed25519 point (little-endian,
 * high sign bit cleared).
 *
 * @throws Error on degenerate points or invalid key length.
 */
export function ed25519PublicKeyToX25519(edPub: Uint8Array): Uint8Array {
  if (edPub.length !== 32) {
    throw new Error(
      `Invalid Ed25519 public key length: ${edPub.length}, expected 32`,
    );
  }

  // Copy and clear the sign bit (high bit of last byte)
  const yBytes = new Uint8Array(edPub);
  yBytes[31] = yBytes[31]! & 0x7f;

  // Read y as little-endian BigInt
  let y = 0n;
  for (let i = 0; i < 32; i++) {
    y |= BigInt(yBytes[i]!) << BigInt(8 * i);
  }

  // u = (1 + y) / (1 - y) mod p
  const numerator = (1n + y) % ED25519_P;
  const denominator = ((ED25519_P + 1n - y) % ED25519_P + ED25519_P) % ED25519_P;

  if (denominator === 0n) {
    throw new Error('Ed25519->X25519 conversion failed: degenerate point (y = 1)');
  }

  const u = (numerator * modInverse(denominator, ED25519_P)) % ED25519_P;

  // Encode u as 32 bytes little-endian
  const result = new Uint8Array(32);
  let val = u;
  for (let i = 0; i < 32; i++) {
    result[i] = Number(val & 0xffn);
    val >>= 8n;
  }

  return result;
}

// ---------------------------------------------------------------------------
// AES-256-GCM encryption
// ---------------------------------------------------------------------------

interface AesGcmResult {
  ciphertext: Buffer;
  iv: Buffer;
  tag: Buffer;
}

function aes256GcmEncrypt(plaintext: Buffer, key: Buffer): AesGcmResult {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, iv, tag };
}

// ---------------------------------------------------------------------------
// X25519 ECDH + HKDF-SHA256 key wrapping
// ---------------------------------------------------------------------------

interface WrapResult {
  ephemeralPublicKey: Buffer;
  wrappedKey: Buffer;
  wrappedKeyIv: Buffer;
  wrappedKeyTag: Buffer;
}

/**
 * Wrap an AES-256 content key for a viewer via X25519 ECDH + HKDF-SHA256.
 *
 * 1. Generate ephemeral X25519 keypair
 * 2. ECDH(ephemeral_private, viewer_x25519_public) -> shared secret
 * 3. HKDF-SHA256(shared_secret, salt, info) -> 32-byte wrapping key
 * 4. AES-256-GCM(wrapping_key, content_key) -> wrapped key + IV + tag
 */
function wrapKeyForViewer(contentKey: Buffer, viewerX25519Public: Uint8Array): WrapResult {
  // Generate ephemeral X25519 keypair
  const ephemeral = crypto.generateKeyPairSync('x25519');

  // Import viewer's X25519 public key from raw bytes via JWK
  const viewerPubJwk = {
    kty: 'OKP' as const,
    crv: 'X25519' as const,
    x: toBase64Url(viewerX25519Public),
  };
  const viewerPublicKey = crypto.createPublicKey({ key: viewerPubJwk, format: 'jwk' });

  // X25519 ECDH -> shared secret
  const sharedSecret = crypto.diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: viewerPublicKey,
  });

  // HKDF-SHA256 -> 32-byte wrapping key
  const wrappingKey = Buffer.from(
    crypto.hkdfSync('sha256', sharedSecret, HKDF_SALT, HKDF_INFO, 32),
  );

  // Wrap content key with AES-256-GCM
  const wrapIv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', wrappingKey, wrapIv);
  const wrappedKey = Buffer.concat([cipher.update(contentKey), cipher.final()]);
  const wrappedKeyTag = cipher.getAuthTag();

  // Export ephemeral public key raw bytes via JWK
  const ephPubJwk = ephemeral.publicKey.export({ format: 'jwk' }) as { x: string };
  const ephemeralPublicKey = fromBase64Url(ephPubJwk.x);

  return { ephemeralPublicKey, wrappedKey, wrappedKeyIv: wrapIv, wrappedKeyTag };
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Validate visibility mode and viewer DIDs. Fail-closed on any error.
 *
 * Resolves the effective viewer DID list:
 * - public: empty (no encryption)
 * - owner: [agentDid]
 * - requester: [agentDid, ...viewerDids]
 * - auditor: [agentDid, ...viewerDids]
 *
 * @throws Error with clear message on validation failure.
 */
export function validateVisibilityArgs(
  visibility: string,
  viewerDids: string[],
  agentDid: string,
): { mode: VisibilityMode; resolvedViewerDids: string[] } {
  if (!VALID_VISIBILITY_MODES.includes(visibility as VisibilityMode)) {
    throw new Error(
      `Invalid --visibility value: '${visibility}'. ` +
      `Allowed values: ${VALID_VISIBILITY_MODES.join(', ')}`,
    );
  }

  const mode = visibility as VisibilityMode;

  if (mode === 'public') {
    return { mode, resolvedViewerDids: [] };
  }

  // Validate all viewer DID formats eagerly (fail-closed)
  for (const did of viewerDids) {
    if (!did.startsWith('did:')) {
      throw new Error(`Malformed viewer DID: must start with 'did:', got: '${did}'`);
    }
    // Parse to verify Ed25519 key format
    parseDidKeyToEd25519PublicKey(did);
  }

  if (mode === 'owner') {
    // Owner mode: agent DID is the sole viewer
    return { mode, resolvedViewerDids: [agentDid] };
  }

  // requester / auditor: require at least one explicit viewer DID
  if (viewerDids.length === 0) {
    throw new Error(
      `--visibility=${mode} requires at least one --viewer-did. ` +
      `Provide the ${mode}'s DID to encrypt the proof bundle for.`,
    );
  }

  // Agent DID + provided viewer DIDs (deduplicated)
  const allDids = [agentDid, ...viewerDids];
  return { mode, resolvedViewerDids: [...new Set(allDids)] };
}

// ---------------------------------------------------------------------------
// High-level: apply visibility to a proof bundle payload
// ---------------------------------------------------------------------------

/**
 * Transform a proof bundle payload for non-public visibility.
 *
 * Extracts sensitive operational fields, encrypts them with AES-256-GCM,
 * wraps the content key for each viewer via X25519 ECDH + HKDF-SHA256,
 * and sets v2 metadata fields on the payload.
 *
 * The payload object is mutated in place.
 *
 * @param payload - The proof bundle payload (mutated in place).
 * @param mode - Non-public visibility mode.
 * @param viewerDids - Resolved list of viewer DIDs (from validateVisibilityArgs).
 * @param agentDid - The agent's own DID (for role assignment).
 * @throws Error on any crypto failure (fail-closed, no silent fallback).
 */
export function applyVisibility(
  payload: Record<string, unknown>,
  mode: VisibilityMode,
  viewerDids: string[],
  agentDid: string,
): void {
  if (mode === 'public') return;

  // 1. Extract sensitive fields into a plaintext object
  const sensitiveData: Record<string, unknown> = {};
  for (const field of SENSITIVE_PAYLOAD_FIELDS) {
    if (payload[field] !== undefined) {
      sensitiveData[field] = payload[field];
    }
  }

  // 2. Serialize plaintext to JSON bytes
  const plaintext = Buffer.from(JSON.stringify(sensitiveData), 'utf-8');

  // 3. SHA-256 hash of plaintext for integrity verification after decryption
  const plaintextHash = crypto.createHash('sha256').update(plaintext).digest();

  // 4. Generate random AES-256 content key (32 bytes)
  const contentKey = crypto.randomBytes(32);

  try {
    // 5. Encrypt with AES-256-GCM
    const { ciphertext, iv, tag } = aes256GcmEncrypt(plaintext, contentKey);

    // 6. Build encrypted_payload
    const encryptedPayload: EncryptedPayloadFields = {
      ciphertext_b64u: toBase64Url(ciphertext),
      iv_b64u: toBase64Url(iv),
      tag_b64u: toBase64Url(tag),
      plaintext_hash_b64u: toBase64Url(plaintextHash),
    };

    // 7. Wrap content key for each viewer
    const viewerKeys: ViewerKeyEntry[] = [];
    for (const viewerDid of viewerDids) {
      const edPub = parseDidKeyToEd25519PublicKey(viewerDid);
      const x25519Pub = ed25519PublicKeyToX25519(edPub);
      const wrapped = wrapKeyForViewer(contentKey, x25519Pub);

      // Role: agent's own DID -> 'owner'; other viewers -> the mode
      const role: ViewerKeyEntry['role'] =
        viewerDid === agentDid ? 'owner' : mode as 'owner' | 'requester' | 'auditor';

      viewerKeys.push({
        viewer_did: viewerDid,
        ephemeral_public_key_b64u: toBase64Url(wrapped.ephemeralPublicKey),
        wrapped_key_b64u: toBase64Url(wrapped.wrappedKey),
        wrapped_key_iv_b64u: toBase64Url(wrapped.wrappedKeyIv),
        wrapped_key_tag_b64u: toBase64Url(wrapped.wrappedKeyTag),
        role,
        key_derivation: 'X25519-HKDF-SHA256',
      });
    }

    // 8. Set v2 metadata on payload
    payload.bundle_version = '2';
    payload.schema_version = 'proof_bundle.v2';
    payload.visibility = mode;
    payload.encrypted_payload = encryptedPayload;
    payload.viewer_keys = viewerKeys;

    // 9. Remove plaintext sensitive fields from outer payload
    for (const field of SENSITIVE_PAYLOAD_FIELDS) {
      delete payload[field];
    }
  } finally {
    // Best-effort key zeroization
    contentKey.fill(0);
  }
}
