import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

const CLAWSIG_DIR = '.clawsig';
const LEGACY_RUNTIME_CONFIG_FILENAME = 'config.json';
const RUNTIME_CONFIG_FILENAME = 'runtime.json';
const XDG_CONFIG_DIR = 'clawsig';
const RUNTIME_CONFIG_ENV = 'CLAWSIG_RUNTIME_CONFIG';

export interface ClawsigRuntimeConfig {
  configVersion: '1';
  marketplace: {
    enabled: boolean;
  };
}

export const DEFAULT_RUNTIME_CONFIG: ClawsigRuntimeConfig = {
  configVersion: '1',
  marketplace: {
    enabled: true,
  },
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function cloneDefaultRuntimeConfig(): ClawsigRuntimeConfig {
  return {
    configVersion: DEFAULT_RUNTIME_CONFIG.configVersion,
    marketplace: {
      enabled: DEFAULT_RUNTIME_CONFIG.marketplace.enabled,
    },
  };
}

function parseRuntimeConfig(raw: string): ClawsigRuntimeConfig | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (!isRecord(parsed)) return null;
  if (parsed.configVersion !== '1') return null;

  const marketplaceRaw = parsed.marketplace;
  if (!isRecord(marketplaceRaw)) return null;
  if (typeof marketplaceRaw.enabled !== 'boolean') return null;

  return {
    configVersion: '1',
    marketplace: {
      enabled: marketplaceRaw.enabled,
    },
  };
}

function trimPath(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : null;
}

function xdgConfigHome(): string {
  return trimPath(process.env['XDG_CONFIG_HOME']) ?? join(homedir(), '.config');
}

function legacyRuntimeConfigPath(projectDir?: string): string {
  const dir = projectDir ?? process.cwd();
  return join(dir, CLAWSIG_DIR, LEGACY_RUNTIME_CONFIG_FILENAME);
}

export function runtimeConfigPath(projectDir?: string): string {
  const dir = projectDir ?? process.cwd();
  return join(dir, CLAWSIG_DIR, RUNTIME_CONFIG_FILENAME);
}

function globalRuntimeConfigCandidatePaths(): string[] {
  return [
    join(xdgConfigHome(), XDG_CONFIG_DIR, RUNTIME_CONFIG_FILENAME),
    join(homedir(), CLAWSIG_DIR, RUNTIME_CONFIG_FILENAME),
    join(homedir(), CLAWSIG_DIR, LEGACY_RUNTIME_CONFIG_FILENAME),
  ];
}

async function loadRuntimeConfigFromPath(path: string): Promise<ClawsigRuntimeConfig | null> {
  try {
    const raw = await readFile(path, 'utf-8');
    return parseRuntimeConfig(raw);
  } catch {
    return null;
  }
}

export async function loadRuntimeConfig(projectDir?: string): Promise<ClawsigRuntimeConfig | null> {
  const overridePath = trimPath(process.env[RUNTIME_CONFIG_ENV]);
  if (overridePath) {
    return loadRuntimeConfigFromPath(overridePath);
  }

  const candidates = [
    runtimeConfigPath(projectDir),
    legacyRuntimeConfigPath(projectDir),
    ...globalRuntimeConfigCandidatePaths(),
  ];

  for (const path of candidates) {
    const config = await loadRuntimeConfigFromPath(path);
    if (config) {
      return config;
    }
  }

  return null;
}

export async function resolveRuntimeConfig(projectDir?: string): Promise<ClawsigRuntimeConfig> {
  const loaded = await loadRuntimeConfig(projectDir);
  if (loaded) return loaded;
  return cloneDefaultRuntimeConfig();
}

export async function saveRuntimeConfig(
  config: ClawsigRuntimeConfig,
  projectDir?: string,
): Promise<string> {
  const path = runtimeConfigPath(projectDir);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, JSON.stringify(config, null, 2) + '\n', {
    encoding: 'utf-8',
    mode: 0o600,
  });
  await chmod(path, 0o600).catch(() => {});
  return path;
}

export async function isMarketplaceEnabled(projectDir?: string): Promise<boolean> {
  const config = await loadRuntimeConfig(projectDir);
  if (!config) return true;
  return config.marketplace.enabled;
}
