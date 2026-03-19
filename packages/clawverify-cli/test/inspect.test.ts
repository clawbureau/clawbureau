import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import crypto from 'node:crypto';

import {
  applyVisibility,
  parseDidKeyToEd25519PublicKey,
  ed25519PublicKeyToX25519,
  ed25519SeedToX25519Private,
  createX25519PrivateKeyFromEd25519Jwk,
  unwrapContentKey,
  decryptAndVerifyPayload,
  toBase64Url,
  fromBase64Url,
} from '../src/epv-crypto.js';
import type {
  EncryptedPayloadFields,
  ViewerKeyEntry,
} from '../src/epv-crypto.js';
import {
  extractPublicLayer,
  decryptBundle,
  InspectError,
} from '../src/inspect-cmd.js';

// Inline the ClawsigIdentity shape to avoid importing identity.ts
// (which transitively depends on @clawbureau/clawsig-sdk).
interface ClawsigIdentity {
  did: string;
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
  createdAt: string;
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function encodeBase58(bytes: Uint8Array): string {
  let num = 0n;
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }
  let result = '';
  while (num > 0n) {
    const remainder = num % 58n;
    result = BASE58_ALPHABET[Number(remainder)]! + result;
    num = num / 58n;
  }
  for (const byte of bytes) {
    if (byte === 0) result = '1' + result;
    else break;
  }
  return result || '1';
}

function jcsCanonicalize(value: unknown): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('Non-finite number not allowed in JCS');
      }
      return JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((entry) => jcsCanonicalize(entry)).join(',')}]`;
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).sort();
      const parts = keys.map((key) => `${JSON.stringify(key)}:${jcsCanonicalize(obj[key])}`);
      return `{${parts.join(',')}}`;
    }
    default:
      throw new Error(`Unsupported value type for JCS: ${typeof value}`);
  }
}

interface TestIdentity {
  did: string;
  publicKeyJwk: JsonWebKey;
  privateKeyJwk: JsonWebKey;
  createdAt: string;
}

/** Generate a full test identity with Ed25519 keypair and did:key. */
function generateTestIdentity(): TestIdentity {
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const publicJwk = keyPair.publicKey.export({ format: 'jwk' }) as JsonWebKey;
  const privateJwk = keyPair.privateKey.export({ format: 'jwk' }) as JsonWebKey;

  const spki = keyPair.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const rawPub = spki.subarray(12);
  const multicodec = new Uint8Array(2 + 32);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(rawPub, 2);
  const did = `did:key:z${encodeBase58(multicodec)}`;

  return { did, publicKeyJwk: publicJwk, privateKeyJwk: privateJwk, createdAt: new Date().toISOString() };
}

/** Create a v1 bundle (public, no encryption). */
function createV1Bundle(agentDid: string): Record<string, unknown> {
  return {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload: {
      bundle_version: '1',
      schema_version: 'proof_bundle.v1',
      bundle_id: 'bundle_test_v1',
      agent_did: agentDid,
      receipts: [{ receipt_id: 'rcpt_1', data: 'test-data' }],
      event_chain: [{ event_id: 'evt_1' }],
    },
    signer_did: agentDid,
    issued_at: new Date().toISOString(),
  };
}

/** Create a v2 bundle encrypted for the given viewer identities. */
function createV2Bundle(
  agentIdentity: TestIdentity,
  viewerDids: string[],
  visibility: 'owner' | 'requester' | 'auditor' = 'owner',
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    bundle_version: '1',
    bundle_id: 'bundle_test_v2',
    agent_did: agentIdentity.did,
    receipts: [
      { receipt_id: 'rcpt_1', data: 'sensitive-receipt-data' },
      { receipt_id: 'rcpt_2', data: 'more-secret-data' },
    ],
    event_chain: [
      { event_id: 'evt_1', data: 'sensitive-chain' },
    ],
    metadata: { harness: { id: 'test', version: '1.0' } },
  };

  const allViewerDids = [...new Set([agentIdentity.did, ...viewerDids])];
  applyVisibility(payload, visibility, allViewerDids, agentIdentity.did);

  return {
    envelope_version: '1',
    envelope_type: 'proof_bundle',
    payload,
    signer_did: agentIdentity.did,
    issued_at: new Date().toISOString(),
  };
}

// Pre-generate identities
let AGENT_IDENTITY: TestIdentity;
let VIEWER_IDENTITY: TestIdentity;
let UNAUTHORIZED_IDENTITY: TestIdentity;

beforeAll(() => {
  AGENT_IDENTITY = generateTestIdentity();
  VIEWER_IDENTITY = generateTestIdentity();
  UNAUTHORIZED_IDENTITY = generateTestIdentity();
});

// ===========================================================================
// Unit: ed25519SeedToX25519Private
// ===========================================================================

describe('ed25519SeedToX25519Private', () => {
  it('produces 32-byte output from 32-byte seed', () => {
    const seed = crypto.randomBytes(32);
    const x25519Priv = ed25519SeedToX25519Private(seed);
    expect(x25519Priv).toBeInstanceOf(Uint8Array);
    expect(x25519Priv.length).toBe(32);
  });

  it('applies clamping: low bits of byte 0 cleared, byte 31 masked', () => {
    const seed = crypto.randomBytes(32);
    const x25519Priv = ed25519SeedToX25519Private(seed);
    expect(x25519Priv[0]! & 0x07).toBe(0);    // low 3 bits clear
    expect(x25519Priv[31]! & 0x80).toBe(0);   // high bit clear
    expect(x25519Priv[31]! & 0x40).toBe(0x40); // bit 6 set
  });

  it('is deterministic', () => {
    const seed = crypto.randomBytes(32);
    const a = ed25519SeedToX25519Private(seed);
    const b = ed25519SeedToX25519Private(seed);
    expect(Buffer.from(a).toString('hex')).toBe(Buffer.from(b).toString('hex'));
  });

  it('rejects wrong-length seed', () => {
    expect(() => ed25519SeedToX25519Private(new Uint8Array(16))).toThrow(/Invalid Ed25519 seed length/);
    expect(() => ed25519SeedToX25519Private(new Uint8Array(64))).toThrow(/Invalid Ed25519 seed length/);
  });
});

// ===========================================================================
// Unit: createX25519PrivateKeyFromEd25519Jwk
// ===========================================================================

describe('createX25519PrivateKeyFromEd25519Jwk', () => {
  it('creates a valid X25519 KeyObject from Ed25519 JWK', () => {
    const identity = generateTestIdentity();
    const key = createX25519PrivateKeyFromEd25519Jwk(
      identity.privateKeyJwk,
      identity.publicKeyJwk,
    );
    expect(key).toBeDefined();
    expect(key.type).toBe('private');
    expect(key.asymmetricKeyType).toBe('x25519');
  });

  it('throws on missing d field', () => {
    const identity = generateTestIdentity();
    const badJwk = { ...identity.privateKeyJwk };
    delete badJwk.d;
    expect(() =>
      createX25519PrivateKeyFromEd25519Jwk(badJwk, identity.publicKeyJwk),
    ).toThrow(/missing private key field/);
  });

  it('throws on missing x field in public JWK', () => {
    const identity = generateTestIdentity();
    const badPubJwk = { ...identity.publicKeyJwk };
    delete badPubJwk.x;
    expect(() =>
      createX25519PrivateKeyFromEd25519Jwk(identity.privateKeyJwk, badPubJwk),
    ).toThrow(/missing public key field/);
  });
});

// ===========================================================================
// Integration: full encrypt -> unwrap -> decrypt round-trip
// ===========================================================================

describe('encrypt -> unwrap -> decrypt round-trip', () => {
  it('successfully round-trips: applyVisibility -> unwrapContentKey -> decryptAndVerifyPayload', () => {
    const identity = generateTestIdentity();
    const originalReceipts = [
      { receipt_id: 'rcpt_1', data: 'sensitive-data' },
      { receipt_id: 'rcpt_2', data: 'more-data' },
    ];

    // Encrypt
    const payload: Record<string, unknown> = {
      bundle_version: '1',
      bundle_id: 'test',
      agent_did: identity.did,
      receipts: JSON.parse(JSON.stringify(originalReceipts)),
    };
    applyVisibility(payload, 'owner', [identity.did], identity.did);

    expect(payload.bundle_version).toBe('2');
    expect(payload.receipts).toBeUndefined();

    // Derive X25519 private key from identity
    const x25519Key = createX25519PrivateKeyFromEd25519Jwk(
      identity.privateKeyJwk,
      identity.publicKeyJwk,
    );

    // Unwrap content key
    const viewerKeys = payload.viewer_keys as ViewerKeyEntry[];
    const myEntry = viewerKeys.find((vk) => vk.viewer_did === identity.did)!;
    const contentKey = unwrapContentKey(x25519Key, myEntry);
    expect(contentKey.length).toBe(32);

    // Decrypt and verify
    const decrypted = decryptAndVerifyPayload(
      contentKey,
      payload.encrypted_payload as EncryptedPayloadFields,
    );

    expect(decrypted.receipts).toEqual(originalReceipts);
  });

  it('works with multiple viewers (requester mode)', () => {
    const agent = generateTestIdentity();
    const viewer = generateTestIdentity();

    const originalReceipts = [{ receipt_id: 'r1' }];
    const payload: Record<string, unknown> = {
      bundle_version: '1',
      bundle_id: 'test-multi',
      agent_did: agent.did,
      receipts: JSON.parse(JSON.stringify(originalReceipts)),
    };
    applyVisibility(payload, 'requester', [agent.did, viewer.did], agent.did);

    const viewerKeys = payload.viewer_keys as ViewerKeyEntry[];
    expect(viewerKeys.length).toBe(2);

    // Both viewers should be able to decrypt
    for (const identity of [agent, viewer]) {
      const x25519Key = createX25519PrivateKeyFromEd25519Jwk(
        identity.privateKeyJwk,
        identity.publicKeyJwk,
      );
      const entry = viewerKeys.find((vk) => vk.viewer_did === identity.did)!;
      const contentKey = unwrapContentKey(x25519Key, entry);
      const decrypted = decryptAndVerifyPayload(
        contentKey,
        payload.encrypted_payload as EncryptedPayloadFields,
      );
      expect(decrypted.receipts).toEqual(originalReceipts);
    }
  });

  it('uses JCS canonicalized plaintext for integrity hash', () => {
    const identity = generateTestIdentity();

    const payloadA: Record<string, unknown> = {
      bundle_version: '1',
      bundle_id: 'test-canonical-a',
      agent_did: identity.did,
      receipts: [{ b: 2, a: 1 }],
      event_chain: [{ z: 'last', a: 'first' }],
    };

    const payloadB: Record<string, unknown> = {
      bundle_version: '1',
      bundle_id: 'test-canonical-b',
      agent_did: identity.did,
      receipts: [{ a: 1, b: 2 }],
      event_chain: [{ a: 'first', z: 'last' }],
    };

    applyVisibility(payloadA, 'owner', [identity.did], identity.did);
    applyVisibility(payloadB, 'owner', [identity.did], identity.did);

    const encryptedA = payloadA.encrypted_payload as EncryptedPayloadFields;
    const encryptedB = payloadB.encrypted_payload as EncryptedPayloadFields;
    expect(encryptedA.plaintext_hash_b64u).toBe(encryptedB.plaintext_hash_b64u);

    const canonicalSensitive = jcsCanonicalize({
      receipts: [{ a: 1, b: 2 }],
      event_chain: [{ a: 'first', z: 'last' }],
    });
    const expectedHash = crypto.createHash('sha256').update(canonicalSensitive, 'utf-8').digest();
    expect(encryptedA.plaintext_hash_b64u).toBe(toBase64Url(expectedHash));
  });

  it('binds HKDF salt to public key context (legacy zero-salt unwrap fails)', () => {
    const identity = generateTestIdentity();
    const payload: Record<string, unknown> = {
      bundle_version: '1',
      bundle_id: 'test-hkdf-salt-binding',
      agent_did: identity.did,
      receipts: [{ receipt_id: 'rcpt_1', data: 'sensitive-data' }],
    };

    applyVisibility(payload, 'owner', [identity.did], identity.did);

    const viewerKeys = payload.viewer_keys as ViewerKeyEntry[];
    const myEntry = viewerKeys.find((vk) => vk.viewer_did === identity.did)!;

    const x25519Key = createX25519PrivateKeyFromEd25519Jwk(
      identity.privateKeyJwk,
      identity.publicKeyJwk,
    );

    const ephemeralPubRaw = fromBase64Url(myEntry.ephemeral_public_key_b64u);
    const ephemeralPubJwk = {
      kty: 'OKP' as const,
      crv: 'X25519' as const,
      x: toBase64Url(ephemeralPubRaw),
    };
    const ephemeralPublicKey = crypto.createPublicKey({ key: ephemeralPubJwk, format: 'jwk' });
    const sharedSecret = crypto.diffieHellman({
      privateKey: x25519Key,
      publicKey: ephemeralPublicKey,
    });

    const viewerEdPublic = parseDidKeyToEd25519PublicKey(identity.did);
    const viewerX25519Public = ed25519PublicKeyToX25519(viewerEdPublic);

    const boundSalt = crypto
      .createHash('sha256')
      .update(ephemeralPubRaw)
      .update(viewerX25519Public)
      .digest();
    const boundWrappingKey = Buffer.from(
      crypto.hkdfSync('sha256', sharedSecret, boundSalt, Buffer.from('clawsig-epv-002-key-wrap'), 32),
    );

    const wrappedKey = fromBase64Url(myEntry.wrapped_key_b64u);
    const wrappedIv = fromBase64Url(myEntry.wrapped_key_iv_b64u);
    const wrappedTag = fromBase64Url(myEntry.wrapped_key_tag_b64u);

    const boundDecipher = crypto.createDecipheriv('aes-256-gcm', boundWrappingKey, wrappedIv);
    boundDecipher.setAuthTag(wrappedTag);
    const manuallyUnwrapped = Buffer.concat([
      boundDecipher.update(wrappedKey),
      boundDecipher.final(),
    ]);

    const unwrappedByApi = unwrapContentKey(x25519Key, myEntry);
    expect(unwrappedByApi.equals(manuallyUnwrapped)).toBe(true);

    const legacyWrappingKey = Buffer.from(
      crypto.hkdfSync(
        'sha256',
        sharedSecret,
        Buffer.alloc(32),
        Buffer.from('clawsig-epv-002-key-wrap'),
        32,
      ),
    );
    expect(() => {
      const legacyDecipher = crypto.createDecipheriv('aes-256-gcm', legacyWrappingKey, wrappedIv);
      legacyDecipher.setAuthTag(wrappedTag);
      legacyDecipher.update(wrappedKey);
      legacyDecipher.final();
    }).toThrow();
  });
});

// ===========================================================================
// Unit: extractPublicLayer
// ===========================================================================

describe('extractPublicLayer', () => {
  it('extracts public layer from v1 bundle', () => {
    const bundle = createV1Bundle(AGENT_IDENTITY.did);
    const pl = extractPublicLayer(bundle);

    expect(pl.bundle_version).toBe('1');
    expect(pl.agent_did).toBe(AGENT_IDENTITY.did);
    expect(pl.signer_did).toBe(AGENT_IDENTITY.did);
    expect(pl.bundle_id).toBe('bundle_test_v1');
    expect(pl.has_encrypted_payload).toBe(false);
    expect(pl.viewer_count).toBe(0);
    expect(pl.viewer_dids).toEqual([]);
    expect(pl.visibility).toBe(null);
  });

  it('extracts public layer from v2 bundle', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, []);
    const pl = extractPublicLayer(bundle);

    expect(pl.bundle_version).toBe('2');
    expect(pl.schema_version).toBe('proof_bundle.v2');
    expect(pl.visibility).toBe('owner');
    expect(pl.has_encrypted_payload).toBe(true);
    expect(pl.viewer_count).toBe(1);
    expect(pl.viewer_dids).toContain(AGENT_IDENTITY.did);
    expect(pl.viewer_roles[AGENT_IDENTITY.did]).toBe('owner');
  });

  it('extracts public layer from v2 bundle with multiple viewers', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, [VIEWER_IDENTITY.did], 'requester');
    const pl = extractPublicLayer(bundle);

    expect(pl.viewer_count).toBe(2);
    expect(pl.viewer_dids).toContain(AGENT_IDENTITY.did);
    expect(pl.viewer_dids).toContain(VIEWER_IDENTITY.did);
    expect(pl.viewer_roles[AGENT_IDENTITY.did]).toBe('owner');
    expect(pl.viewer_roles[VIEWER_IDENTITY.did]).toBe('requester');
  });

  it('throws on missing payload', () => {
    expect(() => extractPublicLayer({} as Record<string, unknown>)).toThrow(InspectError);
    expect(() => extractPublicLayer({} as Record<string, unknown>)).toThrow(/missing payload/);
  });
});

// ===========================================================================
// Unit: decryptBundle
// ===========================================================================

describe('decryptBundle', () => {
  it('decrypts v2 bundle for authorized viewer (owner)', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, []);
    const result = decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity);

    expect(result).toBeDefined();
    expect(result.receipts).toBeDefined();
    expect(Array.isArray(result.receipts)).toBe(true);
    const receipts = result.receipts as Array<{ receipt_id: string }>;
    expect(receipts.length).toBe(2);
    expect(receipts[0]!.receipt_id).toBe('rcpt_1');
    expect(receipts[0]!.data).toBe('sensitive-receipt-data');
  });

  it('decrypts v2 bundle for authorized viewer (requester)', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, [VIEWER_IDENTITY.did], 'requester');
    const result = decryptBundle(bundle, VIEWER_IDENTITY as ClawsigIdentity);

    expect(result).toBeDefined();
    expect(result.receipts).toBeDefined();
  });

  it('fails on v1 bundle with INSPECT_V1_NO_DECRYPT', () => {
    const bundle = createV1Bundle(AGENT_IDENTITY.did);

    expect(() => decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity)).toThrow(InspectError);
    try {
      decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity);
    } catch (err) {
      expect(err).toBeInstanceOf(InspectError);
      expect((err as InspectError).code).toBe('INSPECT_V1_NO_DECRYPT');
    }
  });

  it('fails when DID not in viewer_keys with INSPECT_NOT_AUTHORIZED', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, []);

    expect(() => decryptBundle(bundle, UNAUTHORIZED_IDENTITY as ClawsigIdentity)).toThrow(InspectError);
    try {
      decryptBundle(bundle, UNAUTHORIZED_IDENTITY as ClawsigIdentity);
    } catch (err) {
      expect(err).toBeInstanceOf(InspectError);
      expect((err as InspectError).code).toBe('INSPECT_NOT_AUTHORIZED');
      expect((err as InspectError).message).toContain(UNAUTHORIZED_IDENTITY.did);
    }
  });

  it('fails on tampered ciphertext with INSPECT_CRYPTO_FAILURE', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, []);
    const payload = bundle.payload as Record<string, unknown>;
    const ep = payload.encrypted_payload as EncryptedPayloadFields;

    // Tamper with ciphertext
    const tampered = fromBase64Url(ep.ciphertext_b64u);
    tampered[0] = (tampered[0]! + 1) & 0xff;
    (ep as Record<string, string>).ciphertext_b64u = toBase64Url(tampered);

    expect(() => decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity)).toThrow(InspectError);
    try {
      decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity);
    } catch (err) {
      expect(err).toBeInstanceOf(InspectError);
      // AES-GCM will fail on tampered ciphertext (auth tag check)
      expect((err as InspectError).code).toBe('INSPECT_CRYPTO_FAILURE');
    }
  });

  it('fails on tampered plaintext_hash with INSPECT_INTEGRITY_FAILURE', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, []);
    const payload = bundle.payload as Record<string, unknown>;
    const ep = payload.encrypted_payload as EncryptedPayloadFields;

    // Tamper with the plaintext hash (but leave ciphertext and tag intact)
    const fakeHash = crypto.randomBytes(32);
    (ep as Record<string, string>).plaintext_hash_b64u = toBase64Url(fakeHash);

    expect(() => decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity)).toThrow(InspectError);
    try {
      decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity);
    } catch (err) {
      expect(err).toBeInstanceOf(InspectError);
      expect((err as InspectError).code).toBe('INSPECT_INTEGRITY_FAILURE');
    }
  });

  it('fails on missing encrypted_payload in v2 with INSPECT_INVALID_BUNDLE', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, []);
    const payload = bundle.payload as Record<string, unknown>;
    delete payload.encrypted_payload;

    expect(() => decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity)).toThrow(InspectError);
    try {
      decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity);
    } catch (err) {
      expect(err).toBeInstanceOf(InspectError);
      expect((err as InspectError).code).toBe('INSPECT_INVALID_BUNDLE');
    }
  });
});

// ===========================================================================
// JSON error output contract
// ===========================================================================

describe('InspectError JSON error contract', () => {
  it('INSPECT_V1_NO_DECRYPT has correct code and descriptive message', () => {
    const bundle = createV1Bundle(AGENT_IDENTITY.did);
    try {
      decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(InspectError);
      const ie = err as InspectError;
      expect(ie.code).toBe('INSPECT_V1_NO_DECRYPT');
      expect(ie.message).toMatch(/v1 bundle/i);
      expect(ie.message).toMatch(/v2/);

      // Verify the error can be serialized to JSON (for --json mode)
      const json = JSON.parse(JSON.stringify({ error: true, code: ie.code, message: ie.message }));
      expect(json.error).toBe(true);
      expect(json.code).toBe('INSPECT_V1_NO_DECRYPT');
      expect(typeof json.message).toBe('string');
    }
  });

  it('INSPECT_NOT_AUTHORIZED has correct code and includes DID', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, []);
    try {
      decryptBundle(bundle, UNAUTHORIZED_IDENTITY as ClawsigIdentity);
      expect.unreachable('should have thrown');
    } catch (err) {
      const ie = err as InspectError;
      expect(ie.code).toBe('INSPECT_NOT_AUTHORIZED');
      expect(ie.message).toContain(UNAUTHORIZED_IDENTITY.did);

      const json = JSON.parse(JSON.stringify({ error: true, code: ie.code, message: ie.message }));
      expect(json.error).toBe(true);
      expect(json.code).toBe('INSPECT_NOT_AUTHORIZED');
    }
  });

  it('INSPECT_CRYPTO_FAILURE has correct code', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, []);
    const payload = bundle.payload as Record<string, unknown>;
    const ep = payload.encrypted_payload as Record<string, string>;
    const tampered = fromBase64Url(ep.ciphertext_b64u!);
    tampered[0] = (tampered[0]! + 1) & 0xff;
    ep.ciphertext_b64u = toBase64Url(tampered);

    try {
      decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity);
      expect.unreachable('should have thrown');
    } catch (err) {
      const ie = err as InspectError;
      expect(ie.code).toBe('INSPECT_CRYPTO_FAILURE');

      const json = JSON.parse(JSON.stringify({ error: true, code: ie.code, message: ie.message }));
      expect(json.error).toBe(true);
      expect(json.code).toBe('INSPECT_CRYPTO_FAILURE');
    }
  });

  it('INSPECT_INTEGRITY_FAILURE has correct code', () => {
    const bundle = createV2Bundle(AGENT_IDENTITY, []);
    const payload = bundle.payload as Record<string, unknown>;
    const ep = payload.encrypted_payload as Record<string, string>;
    ep.plaintext_hash_b64u = toBase64Url(crypto.randomBytes(32));

    try {
      decryptBundle(bundle, AGENT_IDENTITY as ClawsigIdentity);
      expect.unreachable('should have thrown');
    } catch (err) {
      const ie = err as InspectError;
      expect(ie.code).toBe('INSPECT_INTEGRITY_FAILURE');

      const json = JSON.parse(JSON.stringify({ error: true, code: ie.code, message: ie.message }));
      expect(json.error).toBe(true);
      expect(json.code).toBe('INSPECT_INTEGRITY_FAILURE');
    }
  });

  it('all error codes are distinct strings', () => {
    const codes: string[] = [
      'INSPECT_FILE_NOT_FOUND',
      'INSPECT_INVALID_BUNDLE',
      'INSPECT_V1_NO_DECRYPT',
      'INSPECT_NO_IDENTITY',
      'INSPECT_NOT_AUTHORIZED',
      'INSPECT_CRYPTO_FAILURE',
      'INSPECT_INTEGRITY_FAILURE',
    ];
    const unique = new Set(codes);
    expect(unique.size).toBe(codes.length);
  });
});
