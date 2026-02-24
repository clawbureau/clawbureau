import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, stat, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  generateIdentity,
  loadIdentity,
  identityToAgentDid,
  defaultIdentityPath,
} from '../src/identity.js';
import { runInit } from '../src/init.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-identity-test-'));
  // Clear env var to avoid interference
  delete process.env['CLAWSIG_IDENTITY'];
});

afterEach(async () => {
  delete process.env['CLAWSIG_IDENTITY'];
  await rm(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// generateIdentity
// ---------------------------------------------------------------------------

describe('generateIdentity', () => {
  it('creates a valid JWK file with correct structure', async () => {
    const outputPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const identity = await generateIdentity(outputPath);

    // Verify file was written
    const raw = await readFile(outputPath, 'utf-8');
    const parsed = JSON.parse(raw);

    expect(parsed.did).toBe(identity.did);
    expect(parsed.publicKeyJwk).toBeDefined();
    expect(parsed.privateKeyJwk).toBeDefined();
    expect(parsed.createdAt).toBeDefined();

    // Verify DID format
    expect(identity.did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);

    // Verify JWK structure
    expect(parsed.publicKeyJwk.kty).toBe('OKP');
    expect(parsed.publicKeyJwk.crv).toBe('Ed25519');
    expect(parsed.publicKeyJwk.x).toBeDefined();
    expect(parsed.privateKeyJwk.kty).toBe('OKP');
    expect(parsed.privateKeyJwk.crv).toBe('Ed25519');
    expect(parsed.privateKeyJwk.d).toBeDefined();

    // Verify ISO 8601 timestamp
    expect(new Date(identity.createdAt).toISOString()).toBe(identity.createdAt);
  });

  it('sets file permissions to 0o600', async () => {
    const outputPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await generateIdentity(outputPath);

    const fileStat = await stat(outputPath);
    const mode = fileStat.mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('creates parent directories if they do not exist', async () => {
    const outputPath = join(tmpDir, 'deep', 'nested', 'dir', 'identity.jwk.json');
    const identity = await generateIdentity(outputPath);

    expect(identity.did).toMatch(/^did:key:z/);
    const raw = await readFile(outputPath, 'utf-8');
    expect(JSON.parse(raw).did).toBe(identity.did);
  });
});

// ---------------------------------------------------------------------------
// loadIdentity
// ---------------------------------------------------------------------------

describe('loadIdentity', () => {
  it('discovers project-level identity', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const generated = await generateIdentity(identityPath);

    const loaded = await loadIdentity(tmpDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.did).toBe(generated.did);
    expect(loaded!.createdAt).toBe(generated.createdAt);
  });

  it('discovers global identity via CLAWSIG_IDENTITY env var', async () => {
    // Use CLAWSIG_IDENTITY to simulate global-like resolution
    // (os.homedir() behavior in test environments is unreliable)
    const globalDir = join(tmpDir, 'fakehome');
    const identityPath = join(globalDir, '.clawsig', 'identity.jwk.json');
    const generated = await generateIdentity(identityPath);

    // Point CLAWSIG_IDENTITY to the "global" identity
    process.env['CLAWSIG_IDENTITY'] = identityPath;

    try {
      // Use a project dir that does NOT have an identity
      const emptyProjectDir = join(tmpDir, 'empty-project');
      await mkdir(emptyProjectDir, { recursive: true });

      const loaded = await loadIdentity(emptyProjectDir);
      expect(loaded).not.toBeNull();
      expect(loaded!.did).toBe(generated.did);
    } finally {
      delete process.env['CLAWSIG_IDENTITY'];
    }
  });

  it('discovers global identity at ~/.clawsig/', async () => {
    const globalDir = join(tmpDir, 'fakehome');
    const identityPath = join(globalDir, '.clawsig', 'identity.jwk.json');
    const generated = await generateIdentity(identityPath);

    const originalHome = process.env['HOME'];
    process.env['HOME'] = globalDir;

    try {
      const { homedir } = await import('node:os');
      // Verify env var took effect for this runtime
      if (homedir() !== globalDir) {
        // Skip on platforms where HOME override doesn't work
        return;
      }

      const emptyProjectDir = join(tmpDir, 'empty-project');
      await mkdir(emptyProjectDir, { recursive: true });

      const loaded = await loadIdentity(emptyProjectDir);
      expect(loaded).not.toBeNull();
      expect(loaded!.did).toBe(generated.did);
    } finally {
      process.env['HOME'] = originalHome;
    }
  });

  it('prefers env var > project', async () => {
    const envPath = join(tmpDir, 'env-identity.jwk.json');
    const projectPath = join(tmpDir, '.clawsig', 'identity.jwk.json');

    const envIdentity = await generateIdentity(envPath);
    const projectIdentity = await generateIdentity(projectPath);

    // Both env and project exist — env var should win
    process.env['CLAWSIG_IDENTITY'] = envPath;
    let loaded = await loadIdentity(tmpDir);
    expect(loaded!.did).toBe(envIdentity.did);

    // Remove env var — project should win
    delete process.env['CLAWSIG_IDENTITY'];
    loaded = await loadIdentity(tmpDir);
    expect(loaded!.did).toBe(projectIdentity.did);
  });

  it('falls back from project to global when project identity is removed', async () => {
    const projectPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const globalDir = join(tmpDir, 'fakehome');
    const globalPath = join(globalDir, '.clawsig', 'identity.jwk.json');

    const projectIdentity = await generateIdentity(projectPath);
    const globalIdentity = await generateIdentity(globalPath);

    const originalHome = process.env['HOME'];
    process.env['HOME'] = globalDir;

    try {
      const { homedir } = await import('node:os');
      if (homedir() !== globalDir) return; // skip if HOME override fails

      // Project exists — should win over global
      let loaded = await loadIdentity(tmpDir);
      expect(loaded!.did).toBe(projectIdentity.did);

      // Remove project file — global should win
      await rm(projectPath);
      loaded = await loadIdentity(tmpDir);
      expect(loaded).not.toBeNull();
      expect(loaded!.did).toBe(globalIdentity.did);
    } finally {
      process.env['HOME'] = originalHome;
    }
  });

  it('returns null when no identity file exists', async () => {
    const emptyDir = join(tmpDir, 'empty');
    await mkdir(emptyDir, { recursive: true });

    // Point HOME to a nonexistent global dir to avoid finding a real one
    const originalHome = process.env['HOME'];
    process.env['HOME'] = join(tmpDir, 'no-home-here');

    try {
      const loaded = await loadIdentity(emptyDir);
      expect(loaded).toBeNull();
    } finally {
      process.env['HOME'] = originalHome;
    }
  });

  it('returns null for malformed identity files', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await mkdir(join(tmpDir, '.clawsig'), { recursive: true });
    await writeFile(identityPath, '{"not": "an identity"}', 'utf-8');

    // Point HOME to a nonexistent global dir
    const originalHome = process.env['HOME'];
    process.env['HOME'] = join(tmpDir, 'no-home-here');

    try {
      const loaded = await loadIdentity(tmpDir);
      expect(loaded).toBeNull();
    } finally {
      process.env['HOME'] = originalHome;
    }
  });
});

// ---------------------------------------------------------------------------
// DID stability
// ---------------------------------------------------------------------------

describe('DID stability', () => {
  it('same key produces the same DID across calls', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const identity = await generateIdentity(identityPath);

    // Load and convert to agent DID twice
    const loaded1 = await loadIdentity(tmpDir);
    const loaded2 = await loadIdentity(tmpDir);

    expect(loaded1!.did).toBe(identity.did);
    expect(loaded2!.did).toBe(identity.did);

    // Also verify through identityToAgentDid
    const agentDid1 = await identityToAgentDid(loaded1!);
    const agentDid2 = await identityToAgentDid(loaded2!);

    expect(agentDid1.did).toBe(identity.did);
    expect(agentDid2.did).toBe(identity.did);
  });

  it('different keys produce different DIDs', async () => {
    const path1 = join(tmpDir, 'id1.jwk.json');
    const path2 = join(tmpDir, 'id2.jwk.json');

    const id1 = await generateIdentity(path1);
    const id2 = await generateIdentity(path2);

    expect(id1.did).not.toBe(id2.did);
  });
});

// ---------------------------------------------------------------------------
// identityToAgentDid
// ---------------------------------------------------------------------------

describe('identityToAgentDid', () => {
  it('produces a working signer', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const identity = await generateIdentity(identityPath);
    const agentDid = await identityToAgentDid(identity);

    expect(agentDid.did).toBe(identity.did);
    expect(agentDid.publicKey).toBeDefined();
    expect(agentDid.privateKey).toBeDefined();

    // sign() should produce a non-empty base64url string
    const sig = await agentDid.sign(new TextEncoder().encode('test message'));
    expect(typeof sig).toBe('string');
    expect(sig.length).toBeGreaterThan(0);
    // base64url: no +, /, or = characters
    expect(sig).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

// ---------------------------------------------------------------------------
// defaultIdentityPath
// ---------------------------------------------------------------------------

describe('defaultIdentityPath', () => {
  it('returns project-level path by default', () => {
    const path = defaultIdentityPath(false, '/some/project');
    expect(path).toBe('/some/project/.clawsig/identity.jwk.json');
  });

  it('returns global path when global=true', () => {
    const path = defaultIdentityPath(true);
    expect(path).toContain('.clawsig/identity.jwk.json');
    // Should be under home directory, not cwd
    expect(path).not.toContain(process.cwd());
  });
});

// ---------------------------------------------------------------------------
// init integration
// ---------------------------------------------------------------------------

describe('runInit with identity', () => {
  it('creates identity file if missing', async () => {
    const result = await runInit({ targetDir: tmpDir });

    expect(result.created).toContain('identity.jwk.json');
    expect(result.did).toBeDefined();
    expect(result.did).toMatch(/^did:key:z/);

    // Verify file exists
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const raw = await readFile(identityPath, 'utf-8');
    const parsed = JSON.parse(raw);
    expect(parsed.did).toBe(result.did);
  });

  it('skips identity if it already exists', async () => {
    // First init
    const first = await runInit({ targetDir: tmpDir });
    expect(first.created).toContain('identity.jwk.json');

    // Second init without --force
    const second = await runInit({ targetDir: tmpDir });
    expect(second.skipped).toContain('identity.jwk.json');
    expect(second.did).toBe(first.did);
  });

  it('regenerates identity with --force', async () => {
    const first = await runInit({ targetDir: tmpDir });
    const firstDid = first.did;

    const second = await runInit({ targetDir: tmpDir, force: true });
    expect(second.created).toContain('identity.jwk.json');
    expect(second.did).toBeDefined();
    // New keypair = new DID (extremely unlikely to collide)
    expect(second.did).not.toBe(firstDid);
  });

  it('still creates policy.json and README.md', async () => {
    const result = await runInit({ targetDir: tmpDir });

    expect(result.created).toContain('policy.json');
    expect(result.created).toContain('README.md');
    expect(result.created).toContain('identity.jwk.json');
  });
});
