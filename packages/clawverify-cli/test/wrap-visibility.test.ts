import { describe, it, expect, beforeAll } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, mkdir, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import crypto from 'node:crypto';

import {
  parseDidKeyToEd25519PublicKey,
  ed25519PublicKeyToX25519,
  validateVisibilityArgs,
  applyVisibility,
  VALID_VISIBILITY_MODES,
} from '../src/epv-crypto.js';
import type { VisibilityMode } from '../src/epv-crypto.js';

const execFileAsync = promisify(execFile);

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const CLI_PATH = resolve(__dirname, '../dist/cli.js');

// ---------------------------------------------------------------------------
// Test DID helpers
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

/** Generate a valid did:key from a fresh Ed25519 keypair. */
function generateTestDid(): string {
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const spki = keyPair.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  // SPKI DER for Ed25519: 30 2a 30 05 06 03 2b 65 70 03 21 00 <32 bytes>
  const rawPub = spki.subarray(12);
  const multicodec = new Uint8Array(2 + 32);
  multicodec[0] = 0xed;
  multicodec[1] = 0x01;
  multicodec.set(rawPub, 2);
  return `did:key:z${encodeBase58(multicodec)}`;
}

// Pre-generate test DIDs
let TEST_AGENT_DID: string;
let TEST_VIEWER_DID: string;

beforeAll(() => {
  TEST_AGENT_DID = generateTestDid();
  TEST_VIEWER_DID = generateTestDid();
});

// ---------------------------------------------------------------------------
// CLI integration helper
// ---------------------------------------------------------------------------

async function runWrap(
  workdir: string,
  extraFlags: string[] = [],
): Promise<{ stderr: string; stdout: string; exitCode: number; bundlePath: string }> {
  const args = [
    CLI_PATH,
    'wrap',
    '--no-publish',
    ...extraFlags,
    '--',
    process.execPath,
    '-e',
    "console.log('epv-test')",
  ];

  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, args, {
      cwd: workdir,
      env: {
        ...process.env,
        CLAWSIG_DISABLE_INTERPOSE: '1',
      },
      timeout: 60_000,
    });

    return {
      stderr,
      stdout,
      exitCode: 0,
      bundlePath: join(workdir, '.clawsig', 'proof_bundle.json'),
    };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; code?: number; status?: number };
    return {
      stderr: e.stderr ?? '',
      stdout: e.stdout ?? '',
      exitCode: e.status ?? e.code ?? 1,
      bundlePath: join(workdir, '.clawsig', 'proof_bundle.json'),
    };
  }
}

// ===========================================================================
// Unit tests: parseDidKeyToEd25519PublicKey
// ===========================================================================

describe('parseDidKeyToEd25519PublicKey', () => {
  it('parses a valid Ed25519 did:key to 32 bytes', () => {
    const did = generateTestDid();
    const pubKey = parseDidKeyToEd25519PublicKey(did);
    expect(pubKey).toBeInstanceOf(Uint8Array);
    expect(pubKey.length).toBe(32);
  });

  it('round-trips: generated DID parses back to same public key', () => {
    const keyPair = crypto.generateKeyPairSync('ed25519');
    const spki = keyPair.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    const rawPub = new Uint8Array(spki.subarray(12));

    const multicodec = new Uint8Array(2 + 32);
    multicodec[0] = 0xed;
    multicodec[1] = 0x01;
    multicodec.set(rawPub, 2);
    const did = `did:key:z${encodeBase58(multicodec)}`;

    const parsed = parseDidKeyToEd25519PublicKey(did);
    expect(Buffer.from(parsed).toString('hex')).toBe(Buffer.from(rawPub).toString('hex'));
  });

  it('rejects non-did:key format', () => {
    expect(() => parseDidKeyToEd25519PublicKey('did:web:example.com')).toThrow(
      /Malformed viewer DID/,
    );
  });

  it('rejects empty string', () => {
    expect(() => parseDidKeyToEd25519PublicKey('')).toThrow(/Malformed viewer DID/);
  });

  it('rejects did:key with wrong multicodec prefix', () => {
    // Use a non-Ed25519 multicodec prefix (0x0012 = sha2-256)
    const fakeKey = new Uint8Array(34);
    fakeKey[0] = 0x00;
    fakeKey[1] = 0x12;
    const did = `did:key:z${encodeBase58(fakeKey)}`;
    expect(() => parseDidKeyToEd25519PublicKey(did)).toThrow(/multicodec prefix/);
  });
});

// ===========================================================================
// Unit tests: ed25519PublicKeyToX25519
// ===========================================================================

describe('ed25519PublicKeyToX25519', () => {
  it('converts a 32-byte Ed25519 key to a 32-byte X25519 key', () => {
    const did = generateTestDid();
    const edPub = parseDidKeyToEd25519PublicKey(did);
    const x25519Pub = ed25519PublicKeyToX25519(edPub);
    expect(x25519Pub).toBeInstanceOf(Uint8Array);
    expect(x25519Pub.length).toBe(32);
  });

  it('produces non-zero output', () => {
    const did = generateTestDid();
    const edPub = parseDidKeyToEd25519PublicKey(did);
    const x25519Pub = ed25519PublicKeyToX25519(edPub);
    const allZero = x25519Pub.every((b) => b === 0);
    expect(allZero).toBe(false);
  });

  it('rejects wrong-length input', () => {
    expect(() => ed25519PublicKeyToX25519(new Uint8Array(16))).toThrow(
      /Invalid Ed25519 public key length/,
    );
  });

  it('deterministic: same input produces same output', () => {
    const did = generateTestDid();
    const edPub = parseDidKeyToEd25519PublicKey(did);
    const x1 = ed25519PublicKeyToX25519(edPub);
    const x2 = ed25519PublicKeyToX25519(edPub);
    expect(Buffer.from(x1).toString('hex')).toBe(Buffer.from(x2).toString('hex'));
  });
});

// ===========================================================================
// Unit tests: validateVisibilityArgs
// ===========================================================================

describe('validateVisibilityArgs', () => {
  it('accepts public mode with no viewer DIDs', () => {
    const result = validateVisibilityArgs('public', [], TEST_AGENT_DID);
    expect(result.mode).toBe('public');
    expect(result.resolvedViewerDids).toEqual([]);
  });

  it('accepts owner mode with no explicit viewer DIDs (uses agent DID)', () => {
    const result = validateVisibilityArgs('owner', [], TEST_AGENT_DID);
    expect(result.mode).toBe('owner');
    expect(result.resolvedViewerDids).toEqual([TEST_AGENT_DID]);
  });

  it('accepts requester mode with a viewer DID', () => {
    const result = validateVisibilityArgs('requester', [TEST_VIEWER_DID], TEST_AGENT_DID);
    expect(result.mode).toBe('requester');
    expect(result.resolvedViewerDids).toContain(TEST_AGENT_DID);
    expect(result.resolvedViewerDids).toContain(TEST_VIEWER_DID);
  });

  it('accepts auditor mode with a viewer DID', () => {
    const result = validateVisibilityArgs('auditor', [TEST_VIEWER_DID], TEST_AGENT_DID);
    expect(result.mode).toBe('auditor');
    expect(result.resolvedViewerDids).toContain(TEST_AGENT_DID);
    expect(result.resolvedViewerDids).toContain(TEST_VIEWER_DID);
  });

  it('deduplicates agent DID when also passed as viewer DID', () => {
    const result = validateVisibilityArgs('requester', [TEST_AGENT_DID, TEST_VIEWER_DID], TEST_AGENT_DID);
    const agentCount = result.resolvedViewerDids.filter((d) => d === TEST_AGENT_DID).length;
    expect(agentCount).toBe(1);
  });

  it('rejects invalid visibility mode', () => {
    expect(() => validateVisibilityArgs('secret', [], TEST_AGENT_DID)).toThrow(
      /Invalid --visibility value/,
    );
  });

  it('rejects requester mode without viewer DID', () => {
    expect(() => validateVisibilityArgs('requester', [], TEST_AGENT_DID)).toThrow(
      /requires at least one --viewer-did/,
    );
  });

  it('rejects auditor mode without viewer DID', () => {
    expect(() => validateVisibilityArgs('auditor', [], TEST_AGENT_DID)).toThrow(
      /requires at least one --viewer-did/,
    );
  });

  it('rejects malformed viewer DID (not did: prefix)', () => {
    expect(() =>
      validateVisibilityArgs('requester', ['not-a-did'], TEST_AGENT_DID),
    ).toThrow(/Malformed viewer DID/);
  });

  it('rejects malformed viewer DID (did:web, not did:key)', () => {
    expect(() =>
      validateVisibilityArgs('requester', ['did:web:example.com'], TEST_AGENT_DID),
    ).toThrow(/Malformed viewer DID/);
  });
});

// ===========================================================================
// Unit tests: applyVisibility
// ===========================================================================

describe('applyVisibility', () => {
  function makeMockPayload(): Record<string, unknown> {
    return {
      bundle_version: '1',
      bundle_id: 'bundle_test_123',
      agent_did: TEST_AGENT_DID,
      receipts: [{ receipt_id: 'rcpt_1', data: 'sensitive' }],
      event_chain: [{ event_id: 'evt_1', data: 'sensitive' }],
      metadata: { harness: { id: 'test', version: '1.0' } },
    };
  }

  it('does nothing for public mode', () => {
    const payload = makeMockPayload();
    const original = JSON.parse(JSON.stringify(payload));
    applyVisibility(payload, 'public', [], TEST_AGENT_DID);
    expect(payload).toEqual(original);
  });

  it('sets bundle_version to "2" for owner mode', () => {
    const payload = makeMockPayload();
    applyVisibility(payload, 'owner', [TEST_AGENT_DID], TEST_AGENT_DID);
    expect(payload.bundle_version).toBe('2');
  });

  it('sets schema_version to "proof_bundle.v2"', () => {
    const payload = makeMockPayload();
    applyVisibility(payload, 'owner', [TEST_AGENT_DID], TEST_AGENT_DID);
    expect(payload.schema_version).toBe('proof_bundle.v2');
  });

  it('sets visibility field to selected mode', () => {
    const payload = makeMockPayload();
    applyVisibility(payload, 'requester', [TEST_AGENT_DID, TEST_VIEWER_DID], TEST_AGENT_DID);
    expect(payload.visibility).toBe('requester');
  });

  it('includes encrypted_payload with required fields', () => {
    const payload = makeMockPayload();
    applyVisibility(payload, 'owner', [TEST_AGENT_DID], TEST_AGENT_DID);

    const ep = payload.encrypted_payload as Record<string, string>;
    expect(ep).toBeDefined();
    expect(ep.ciphertext_b64u).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(ep.iv_b64u).toMatch(/^[A-Za-z0-9_-]{16}$/);
    expect(ep.tag_b64u).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(ep.plaintext_hash_b64u).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('includes viewer_keys with correct structure', () => {
    const payload = makeMockPayload();
    applyVisibility(payload, 'owner', [TEST_AGENT_DID], TEST_AGENT_DID);

    const vk = payload.viewer_keys as Array<Record<string, string>>;
    expect(vk).toBeDefined();
    expect(vk.length).toBe(1);
    expect(vk[0]!.viewer_did).toBe(TEST_AGENT_DID);
    expect(vk[0]!.ephemeral_public_key_b64u).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(vk[0]!.wrapped_key_b64u).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(vk[0]!.wrapped_key_iv_b64u).toMatch(/^[A-Za-z0-9_-]{16}$/);
    expect(vk[0]!.wrapped_key_tag_b64u).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(vk[0]!.key_derivation).toBe('X25519-HKDF-SHA256');
  });

  it('assigns owner role to agent DID in requester mode', () => {
    const payload = makeMockPayload();
    applyVisibility(payload, 'requester', [TEST_AGENT_DID, TEST_VIEWER_DID], TEST_AGENT_DID);

    const vk = payload.viewer_keys as Array<Record<string, string>>;
    const agentEntry = vk.find((k) => k.viewer_did === TEST_AGENT_DID);
    const viewerEntry = vk.find((k) => k.viewer_did === TEST_VIEWER_DID);
    expect(agentEntry!.role).toBe('owner');
    expect(viewerEntry!.role).toBe('requester');
  });

  it('removes sensitive plaintext fields from outer payload', () => {
    const payload = makeMockPayload();
    applyVisibility(payload, 'owner', [TEST_AGENT_DID], TEST_AGENT_DID);

    expect(payload.receipts).toBeUndefined();
    expect(payload.event_chain).toBeUndefined();
  });

  it('preserves non-sensitive fields (metadata, agent_did, bundle_id)', () => {
    const payload = makeMockPayload();
    applyVisibility(payload, 'owner', [TEST_AGENT_DID], TEST_AGENT_DID);

    expect(payload.agent_did).toBe(TEST_AGENT_DID);
    expect(payload.bundle_id).toBe('bundle_test_123');
    expect(payload.metadata).toBeDefined();
  });

  it('creates one viewer_key per viewer DID', () => {
    const extraDid = generateTestDid();
    const payload = makeMockPayload();
    applyVisibility(
      payload,
      'auditor',
      [TEST_AGENT_DID, TEST_VIEWER_DID, extraDid],
      TEST_AGENT_DID,
    );

    const vk = payload.viewer_keys as Array<Record<string, string>>;
    expect(vk.length).toBe(3);
    const dids = vk.map((k) => k.viewer_did);
    expect(dids).toContain(TEST_AGENT_DID);
    expect(dids).toContain(TEST_VIEWER_DID);
    expect(dids).toContain(extraDid);
  });
});

// ===========================================================================
// CLI integration tests: --visibility flag parsing + validation
// ===========================================================================

describe('clawsig wrap --visibility (CLI integration)', () => {
  it('default (no --visibility) produces v1 bundle (public)', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'epv-pub-'));
    try {
      const { exitCode, bundlePath } = await runWrap(workdir);
      expect(exitCode).toBe(0);

      const raw = await readFile(bundlePath, 'utf-8');
      const bundle = JSON.parse(raw) as Record<string, unknown>;
      const payload = bundle.payload as Record<string, unknown>;

      expect(payload.bundle_version).toBe('1');
      expect(payload.visibility).toBeUndefined();
      expect(payload.encrypted_payload).toBeUndefined();
      expect(payload.viewer_keys).toBeUndefined();
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('--visibility public produces v1 bundle (unchanged)', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'epv-pub-'));
    try {
      const { exitCode, bundlePath } = await runWrap(workdir, ['--visibility', 'public']);
      expect(exitCode).toBe(0);

      const raw = await readFile(bundlePath, 'utf-8');
      const bundle = JSON.parse(raw) as Record<string, unknown>;
      const payload = bundle.payload as Record<string, unknown>;

      expect(payload.bundle_version).toBe('1');
      expect(payload.encrypted_payload).toBeUndefined();
      expect(payload.viewer_keys).toBeUndefined();
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('--visibility owner produces v2 bundle with encrypted_payload', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'epv-owner-'));
    try {
      const { exitCode, bundlePath } = await runWrap(workdir, ['--visibility', 'owner']);
      expect(exitCode).toBe(0);

      const raw = await readFile(bundlePath, 'utf-8');
      const bundle = JSON.parse(raw) as Record<string, unknown>;
      const payload = bundle.payload as Record<string, unknown>;

      expect(payload.bundle_version).toBe('2');
      expect(payload.schema_version).toBe('proof_bundle.v2');
      expect(payload.visibility).toBe('owner');
      expect(payload.encrypted_payload).toBeDefined();
      expect(payload.viewer_keys).toBeDefined();

      const vk = payload.viewer_keys as Array<Record<string, string>>;
      expect(vk.length).toBe(1);
      expect(vk[0]!.role).toBe('owner');
      expect(vk[0]!.key_derivation).toBe('X25519-HKDF-SHA256');

      // Sensitive fields should be removed from outer payload
      expect(payload.receipts).toBeUndefined();
      expect(payload.event_chain).toBeUndefined();
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('--visibility requester with --viewer-did produces v2 bundle', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'epv-req-'));
    const viewerDid = generateTestDid();
    try {
      const { exitCode, bundlePath } = await runWrap(workdir, [
        '--visibility', 'requester',
        '--viewer-did', viewerDid,
      ]);
      expect(exitCode).toBe(0);

      const raw = await readFile(bundlePath, 'utf-8');
      const bundle = JSON.parse(raw) as Record<string, unknown>;
      const payload = bundle.payload as Record<string, unknown>;

      expect(payload.bundle_version).toBe('2');
      expect(payload.visibility).toBe('requester');

      const vk = payload.viewer_keys as Array<Record<string, string>>;
      // Should have 2 entries: agent (owner) + viewer (requester)
      expect(vk.length).toBe(2);
      const roles = vk.map((k) => k.role).sort();
      expect(roles).toEqual(['owner', 'requester']);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  // -----------------------------------------------------------------------
  // Fail-closed tests
  // -----------------------------------------------------------------------

  it('--visibility invalid exits non-zero', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'epv-invalid-'));
    try {
      const { exitCode, stdout, stderr } = await runWrap(workdir, ['--visibility', 'secret']);
      expect(exitCode).not.toBe(0);
      // Error may go to stdout (via output()) or stderr depending on handler
      const combined = stdout + stderr;
      expect(combined).toMatch(/Invalid --visibility value/);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('--visibility requester without --viewer-did exits non-zero', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'epv-noid-'));
    try {
      const { exitCode, stdout, stderr } = await runWrap(workdir, ['--visibility', 'requester']);
      expect(exitCode).not.toBe(0);
      const combined = stdout + stderr;
      expect(combined).toMatch(/requires at least one --viewer-did/);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('--visibility auditor without --viewer-did exits non-zero', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'epv-noid-'));
    try {
      const { exitCode, stdout, stderr } = await runWrap(workdir, ['--visibility', 'auditor']);
      expect(exitCode).not.toBe(0);
      const combined = stdout + stderr;
      expect(combined).toMatch(/requires at least one --viewer-did/);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });

  it('malformed --viewer-did exits non-zero', async () => {
    const workdir = await mkdtemp(join(tmpdir(), 'epv-baddid-'));
    try {
      const { exitCode, stdout, stderr } = await runWrap(workdir, [
        '--visibility', 'requester',
        '--viewer-did', 'not-a-valid-did',
      ]);
      expect(exitCode).not.toBe(0);
      const combined = stdout + stderr;
      expect(combined).toMatch(/Malformed viewer DID|EPV error/);
    } finally {
      await rm(workdir, { recursive: true, force: true });
    }
  });
});
