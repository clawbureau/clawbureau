import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { runConfigSet } from '../src/config-cmd.js';
import {
  isMarketplaceEnabled,
  loadRuntimeConfig,
  runtimeConfigPath,
  saveRuntimeConfig,
} from '../src/runtime-config.js';

let tmpDir: string;
let originalXdgConfigHome: string | undefined;
let originalRuntimeConfigEnv: string | undefined;

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
  tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-runtime-test-'));
  originalXdgConfigHome = process.env['XDG_CONFIG_HOME'];
  originalRuntimeConfigEnv = process.env['CLAWSIG_RUNTIME_CONFIG'];
  delete process.env['XDG_CONFIG_HOME'];
  delete process.env['CLAWSIG_RUNTIME_CONFIG'];
});

afterEach(async () => {
  if (originalXdgConfigHome === undefined) {
    delete process.env['XDG_CONFIG_HOME'];
  } else {
    process.env['XDG_CONFIG_HOME'] = originalXdgConfigHome;
  }

  if (originalRuntimeConfigEnv === undefined) {
    delete process.env['CLAWSIG_RUNTIME_CONFIG'];
  } else {
    process.env['CLAWSIG_RUNTIME_CONFIG'] = originalRuntimeConfigEnv;
  }

  process.exitCode = undefined;
  await rm(tmpDir, { recursive: true, force: true });
});

describe('runtime-config', () => {
  it('writes runtime config to .clawsig/runtime.json', () => {
    expect(runtimeConfigPath(tmpDir)).toBe(join(tmpDir, '.clawsig', 'runtime.json'));
  });

  it('loads global XDG runtime config when project config is absent', async () => {
    const xdgConfigHome = join(tmpDir, 'xdg-config');
    process.env['XDG_CONFIG_HOME'] = xdgConfigHome;

    await mkdir(join(xdgConfigHome, 'clawsig'), { recursive: true });
    await writeFile(
      join(xdgConfigHome, 'clawsig', 'runtime.json'),
      JSON.stringify({
        configVersion: '1',
        marketplace: { enabled: false },
      }) + '\n',
      'utf-8',
    );

    const loaded = await loadRuntimeConfig(tmpDir);
    expect(loaded).toEqual({
      configVersion: '1',
      marketplace: { enabled: false },
    });
  });

  it('keeps verifier config.json separate from runtime config', async () => {
    const clawsigDir = join(tmpDir, '.clawsig');
    await mkdir(clawsigDir, { recursive: true });
    await writeFile(
      join(clawsigDir, 'config.json'),
      JSON.stringify({
        config_version: '1',
        allowlists: {
          gateway_receipt_signer_dids: ['did:key:z6MkVerifier'],
        },
      }) + '\n',
      'utf-8',
    );

    expect(await loadRuntimeConfig(tmpDir)).toBeNull();
    expect(await isMarketplaceEnabled(tmpDir)).toBe(true);
  });

  it('loads legacy runtime config from .clawsig/config.json when present', async () => {
    const clawsigDir = join(tmpDir, '.clawsig');
    await mkdir(clawsigDir, { recursive: true });
    await writeFile(
      join(clawsigDir, 'config.json'),
      JSON.stringify({
        configVersion: '1',
        marketplace: { enabled: false },
      }) + '\n',
      'utf-8',
    );

    const loaded = await loadRuntimeConfig(tmpDir);
    expect(loaded).toEqual({
      configVersion: '1',
      marketplace: { enabled: false },
    });
  });

  it('runConfigSet writes marketplace.enabled to runtime.json', async () => {
    const result = await quietAsync(() =>
      runConfigSet({
        key: 'marketplace.enabled',
        value: 'false',
        json: true,
        projectDir: tmpDir,
      }),
    );

    expect(result.status).toBe('ok');
    expect(result.configPath).toBe(join(tmpDir, '.clawsig', 'runtime.json'));
    expect(await loadRuntimeConfig(tmpDir)).toEqual({
      configVersion: '1',
      marketplace: { enabled: false },
    });
  });

  it('writes runtime config with restrictive permissions on POSIX', async () => {
    const path = await saveRuntimeConfig(
      {
        configVersion: '1',
        marketplace: { enabled: false },
      },
      tmpDir,
    );

    if (process.platform !== 'win32') {
      const fileStat = await stat(path);
      expect(fileStat.mode & 0o777).toBe(0o600);
    }
  });
});
