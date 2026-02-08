import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import {
  base58Decode,
  extractPublicKeyFromDidKey,
  verifySignature,
} from '../src/crypto';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function base64ToBytes(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function jcsCanonicalize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Non-finite number not allowed');
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);

  if (Array.isArray(value)) {
    return `[${value.map(jcsCanonicalize).join(',')}]`;
  }

  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      parts.push(`${JSON.stringify(k)}:${jcsCanonicalize(obj[k])}`);
    }
    return `{${parts.join(',')}}`;
  }

  throw new Error(`Unsupported JSON value type: ${typeof value}`);
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return bytesToHex(new Uint8Array(hash));
}

describe('Protocol M golden vector (fixtures/protocol-m-golden-vector.v1.json)', () => {
  it('verifies did:key derivation + JCS canonical string + Ed25519 signature', async () => {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);

    const fixturePath = path.resolve(
      __dirname,
      '../../../packages/schema/fixtures/protocol-m-golden-vector.v1.json'
    );

    const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as any;

    // 1) did:key → pubkey extraction
    const pub = extractPublicKeyFromDidKey(fixture.did);
    expect(pub).toBeTruthy();
    expect(bytesToHex(pub!)).toBe(fixture.public_key_hex);

    // 2) did:key multicodec prefix check (0xed01)
    const multibase = fixture.did.slice('did:key:z'.length);
    const decoded = base58Decode(multibase);
    expect(bytesToHex(decoded.slice(0, 2))).toBe(fixture.did_derivation.multicodec_prefix);
    expect(bytesToHex(decoded.slice(2))).toBe(fixture.public_key_hex);

    // 3) artifact SHA-256
    const artifactBytes = new TextEncoder().encode(
      fixture.test_artifact.file_bytes_utf8
    );
    expect(artifactBytes.length).toBe(fixture.test_artifact.file_size);

    const artifactSha = await sha256Hex(artifactBytes);
    expect(artifactSha).toBe(fixture.test_artifact.sha256_hex);
    expect(artifactSha).toBe(fixture.signature_envelope.hash.value);

    // 4) JCS canonicalization check
    const canonical = jcsCanonicalize(fixture.signature_envelope);
    expect(canonical).toBe(fixture.canonical_jcs);

    // 5) signature decode consistency
    const sigBytes = base64ToBytes(fixture.signature_base64);
    expect(bytesToHex(sigBytes)).toBe(fixture.signature_hex);

    // 6) verify signature over canonical UTF-8 bytes
    const msgBytes = new TextEncoder().encode(canonical);
    const ok = await verifySignature('Ed25519', pub!, sigBytes, msgBytes);
    expect(ok).toBe(true);

    // 7) tamper check
    const tampered = new TextEncoder().encode(`${canonical} `);
    const ok2 = await verifySignature('Ed25519', pub!, sigBytes, tampered);
    expect(ok2).toBe(false);
  });

  it('fails closed on unsupported values in JCS canonicalizer (sanity)', () => {
    expect(() => jcsCanonicalize(undefined)).toThrow();
    expect(() => jcsCanonicalize(() => 1)).toThrow();
    expect(() => jcsCanonicalize(Number.NaN)).toThrow();
    expect(() => jcsCanonicalize(Number.POSITIVE_INFINITY)).toThrow();
  });
});
