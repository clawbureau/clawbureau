import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { generateIdentity } from '../src/identity.js';
import {
  loadWorkConfig,
  saveWorkConfig,
  workConfigPath,
  workConfigExists,
  DEFAULT_MARKETPLACE_URL,
} from '../src/work-config.js';
import type { WorkConfig } from '../src/work-config.js';
import { registerWorker, __setFetch } from '../src/work-api.js';
import { saveRuntimeConfig } from '../src/runtime-config.js';
import { runWorkInit } from '../src/work-cmd.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

let tmpDir: string;

async function quietAsync<T>(fn: () => Promise<T>): Promise<T> {
  const origOut = process.stdout.write;
  const origErr = process.stderr.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    return await fn();
  } finally {
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
}

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-work-test-'));
  delete process.env['CLAWSIG_IDENTITY'];
});

afterEach(async () => {
  delete process.env['CLAWSIG_IDENTITY'];
  process.exitCode = undefined;
  await rm(tmpDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// work-config: saveWorkConfig + loadWorkConfig round-trip
// ---------------------------------------------------------------------------

describe('work-config', () => {
  it('saves and loads config round-trip', async () => {
    const config: WorkConfig = {
      configVersion: '1',
      workerDid: 'did:key:z6MkTest123',
      marketplaceUrl: 'https://example.com',
      createdAt: '2025-01-01T00:00:00.000Z',
    };

    const path = await saveWorkConfig(config, tmpDir);
    expect(existsSync(path)).toBe(true);

    const loaded = await loadWorkConfig(tmpDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.configVersion).toBe('1');
    expect(loaded!.workerDid).toBe('did:key:z6MkTest123');
    expect(loaded!.marketplaceUrl).toBe('https://example.com');
    expect(loaded!.createdAt).toBe('2025-01-01T00:00:00.000Z');
  });

  it('saves config with registration metadata', async () => {
    const config: WorkConfig = {
      configVersion: '1',
      workerDid: 'did:key:z6MkTest123',
      marketplaceUrl: 'https://example.com',
      createdAt: '2025-01-01T00:00:00.000Z',
      registration: {
        workerId: 'w-abc123',
        registeredAt: '2025-01-01T00:00:01.000Z',
      },
    };

    await saveWorkConfig(config, tmpDir);
    const loaded = await loadWorkConfig(tmpDir);
    expect(loaded!.registration).toBeDefined();
    expect(loaded!.registration!.workerId).toBe('w-abc123');
    expect(loaded!.registration!.registeredAt).toBe('2025-01-01T00:00:01.000Z');
  });

  it('returns null for missing config', async () => {
    const loaded = await loadWorkConfig(tmpDir);
    expect(loaded).toBeNull();
  });

  it('returns null for invalid JSON', async () => {
    const dir = join(tmpDir, '.clawsig');
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'work.json'), 'not json', 'utf-8');
    const loaded = await loadWorkConfig(tmpDir);
    expect(loaded).toBeNull();
  });

  it('returns null for wrong schema version', async () => {
    const dir = join(tmpDir, '.clawsig');
    await mkdir(dir, { recursive: true });
    await writeFile(
      join(dir, 'work.json'),
      JSON.stringify({ configVersion: '99', workerDid: 'x', marketplaceUrl: 'x', createdAt: 'x' }),
      'utf-8',
    );
    const loaded = await loadWorkConfig(tmpDir);
    expect(loaded).toBeNull();
  });

  it('workConfigExists returns correct value', async () => {
    expect(workConfigExists(tmpDir)).toBe(false);

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: 'did:key:z6MkTest123',
      marketplaceUrl: 'https://example.com',
      createdAt: '2025-01-01T00:00:00.000Z',
    };
    await saveWorkConfig(config, tmpDir);
    expect(workConfigExists(tmpDir)).toBe(true);
  });

  it('workConfigPath returns expected path', () => {
    const path = workConfigPath('/some/project');
    expect(path).toBe('/some/project/.clawsig/work.json');
  });
});

// ---------------------------------------------------------------------------
// work-api: registerWorker (mocked fetch)
// ---------------------------------------------------------------------------

describe('work-api: registerWorker', () => {
  it('succeeds with valid response', async () => {
    const restore = __setFetch(async () =>
      new Response(
        JSON.stringify({
          worker_id: 'w-abc123',
          registered_at: '2025-01-01T00:00:00.000Z',
          tier: 'basic',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    try {
      const result = await registerWorker('https://example.com', {
        workerDid: 'did:key:z6MkTest',
      });
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.registration.workerId).toBe('w-abc123');
        expect(result.registration.registeredAt).toBe('2025-01-01T00:00:00.000Z');
        // Extra fields preserved.
        expect(result.registration['tier']).toBe('basic');
      }
    } finally {
      restore();
    }
  });

  it('returns error on HTTP 500', async () => {
    const restore = __setFetch(async () =>
      new Response('Internal Server Error', { status: 500 }),
    );

    try {
      const result = await registerWorker('https://example.com', {
        workerDid: 'did:key:z6MkTest',
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe('REGISTRATION_FAILED');
        expect(result.message).toContain('500');
      }
    } finally {
      restore();
    }
  });

  it('returns error on network failure', async () => {
    const restore = __setFetch(async () => {
      throw new Error('connection refused');
    });

    try {
      const result = await registerWorker('https://example.com', {
        workerDid: 'did:key:z6MkTest',
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe('NETWORK_ERROR');
        expect(result.message).toContain('connection refused');
      }
    } finally {
      restore();
    }
  });

  it('returns error on unparseable response', async () => {
    const restore = __setFetch(async () =>
      new Response('not json at all', {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
      }),
    );

    try {
      const result = await registerWorker('https://example.com', {
        workerDid: 'did:key:z6MkTest',
      });
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe('REGISTRATION_PARSE_ERROR');
      }
    } finally {
      restore();
    }
  });

  it('strips trailing slash from marketplace URL', async () => {
    let requestedUrl = '';
    const restore = __setFetch(async (input: RequestInfo | URL) => {
      requestedUrl = input.toString();
      return new Response(
        JSON.stringify({ worker_id: 'w-1', registered_at: '2025-01-01T00:00:00Z' }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    });

    try {
      await registerWorker('https://example.com/', { workerDid: 'did:key:z6MkTest' });
      expect(requestedUrl).toBe('https://example.com/v1/workers/register');
    } finally {
      restore();
    }
  });
});

// ---------------------------------------------------------------------------
// work-cmd: runWorkInit (integration-level, mocked where needed)
// ---------------------------------------------------------------------------

describe('runWorkInit', () => {
  it('fails with IDENTITY_MISSING when no identity exists', async () => {
    const result = await quietAsync(() =>
      runWorkInit({ json: true, projectDir: tmpDir }),
    );
    expect(result.status).toBe('error');
    expect(result.error?.code).toBe('IDENTITY_MISSING');
    expect(process.exitCode).toBe(2);
  });

  it('creates work config in offline mode (no --register)', async () => {
    // Generate identity first.
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const identity = await generateIdentity(identityPath);

    const result = await quietAsync(() =>
      runWorkInit({ projectDir: tmpDir }),
    );
    expect(result.status).toBe('ok');
    expect(result.workerDid).toBe(identity.did);
    expect(result.registered).toBe(false);

    // Config should be on disk.
    const loaded = await loadWorkConfig(tmpDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.workerDid).toBe(identity.did);
    expect(loaded!.marketplaceUrl).toBe(DEFAULT_MARKETPLACE_URL);
    expect(loaded!.configVersion).toBe('1');
    expect(loaded!.registration).toBeUndefined();
  });

  it('uses custom marketplace URL', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await generateIdentity(identityPath);

    const result = await quietAsync(() =>
      runWorkInit({ marketplace: 'https://custom.example.com', projectDir: tmpDir }),
    );
    expect(result.status).toBe('ok');

    const loaded = await loadWorkConfig(tmpDir);
    expect(loaded!.marketplaceUrl).toBe('https://custom.example.com');
  });

  it('registers with marketplace when --register is set', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const identity = await generateIdentity(identityPath);

    const restore = __setFetch(async () =>
      new Response(
        JSON.stringify({
          worker_id: 'w-registered',
          registered_at: '2025-06-01T00:00:00.000Z',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    try {
      const result = await quietAsync(() =>
        runWorkInit({ register: true, projectDir: tmpDir }),
      );
      expect(result.status).toBe('ok');
      expect(result.registered).toBe(true);

      const loaded = await loadWorkConfig(tmpDir);
      expect(loaded!.registration).toBeDefined();
      expect(loaded!.registration!.workerId).toBe('w-registered');
    } finally {
      restore();
    }
  });

  it('skips registration when marketplace is disabled in runtime config', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await generateIdentity(identityPath);
    await saveRuntimeConfig(
      {
        configVersion: '1',
        marketplace: { enabled: false },
      },
      tmpDir,
    );

    let fetchCalled = false;
    const restore = __setFetch(async () => {
      fetchCalled = true;
      return new Response('{}', { status: 200 });
    });

    try {
      const result = await quietAsync(() =>
        runWorkInit({ register: true, projectDir: tmpDir }),
      );
      expect(result.status).toBe('ok');
      expect(result.registered).toBe(false);
      expect(result.warning?.code).toBe('MARKETPLACE_DISABLED');
      expect(fetchCalled).toBe(false);

      const loaded = await loadWorkConfig(tmpDir);
      expect(loaded).not.toBeNull();
      expect(loaded!.registration).toBeUndefined();
    } finally {
      restore();
    }
  });

  it('saves config even when registration fails', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await generateIdentity(identityPath);

    const restore = __setFetch(async () =>
      new Response('Service Unavailable', { status: 503 }),
    );

    try {
      const result = await quietAsync(() =>
        runWorkInit({ register: true, json: true, projectDir: tmpDir }),
      );
      expect(result.status).toBe('error');
      expect(result.registered).toBe(false);
      expect(result.error?.code).toBe('REGISTRATION_FAILED');
      expect(process.exitCode).toBe(1);

      // Config should still exist on disk (offline fallback).
      const loaded = await loadWorkConfig(tmpDir);
      expect(loaded).not.toBeNull();
      expect(loaded!.registration).toBeUndefined();
    } finally {
      restore();
    }
  });

  it('preserves existing registration on re-init without --register', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    await generateIdentity(identityPath);

    // Pre-populate work config with a registration.
    const existing: WorkConfig = {
      configVersion: '1',
      workerDid: 'did:key:z6MkOld',
      marketplaceUrl: 'https://old.example.com',
      createdAt: '2025-01-01T00:00:00.000Z',
      registration: {
        workerId: 'w-existing',
        registeredAt: '2025-01-01T00:00:01.000Z',
      },
    };
    await saveWorkConfig(existing, tmpDir);

    const result = await quietAsync(() =>
      runWorkInit({ projectDir: tmpDir }),
    );
    expect(result.status).toBe('ok');
    expect(result.registered).toBe(false);

    // Registration from previous config should be preserved.
    const loaded = await loadWorkConfig(tmpDir);
    expect(loaded!.registration).toBeDefined();
    expect(loaded!.registration!.workerId).toBe('w-existing');
  });

  it('produces parseable JSON output', async () => {
    const identityPath = join(tmpDir, '.clawsig', 'identity.jwk.json');
    const identity = await generateIdentity(identityPath);

    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: string) => {
      chunks.push(chunk);
      return true;
    }) as typeof process.stdout.write;

    // Suppress stderr.
    const origErr = process.stderr.write;
    process.stderr.write = (() => true) as typeof process.stderr.write;

    try {
      await runWorkInit({ json: true, projectDir: tmpDir });
    } finally {
      process.stdout.write = origWrite;
      process.stderr.write = origErr;
    }

    const output = chunks.join('');
    const parsed = JSON.parse(output);
    expect(parsed.status).toBe('ok');
    expect(parsed.worker_did).toBe(identity.did);
    expect(parsed.marketplace_url).toBe(DEFAULT_MARKETPLACE_URL);
    expect(parsed.registered).toBe(false);
    expect(typeof parsed.config_path).toBe('string');
    expect(typeof parsed.created_at).toBe('string');
  });
});
