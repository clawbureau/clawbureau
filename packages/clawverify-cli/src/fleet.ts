import { existsSync } from 'node:fs';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import { generateIdentity } from './identity.js';
import type { ClawsigIdentity } from './identity.js';

const CLAWSIG_DIR = '.clawsig';
const FLEET_DIRNAME = 'fleet';
const REGISTRY_FILENAME = 'registry.json';
const IDENTITY_FILENAME = 'identity.jwk.json';
const FLEET_NAME_PATTERN = /^[A-Za-z0-9._-]+$/;

export type FleetAgentStatus = 'active' | 'revoked';

interface FleetRegistryEntry {
  name: string;
  did: string;
  status: FleetAgentStatus;
  key_file: string;
  created_at: string;
  revoked_at?: string;
}

interface FleetRegistryFile {
  version: 1;
  updated_at: string;
  agents: FleetRegistryEntry[];
}

interface FleetLocation {
  scope: 'project' | 'global';
  fleetDir: string;
  registryPath: string;
}

export interface FleetAgentRecord {
  name: string;
  did: string;
  status: FleetAgentStatus;
  keyPath: string;
  createdAt: string;
  revokedAt?: string;
}

export interface FleetAddResult {
  name: string;
  did: string;
  status: 'active';
  keyPath: string;
  registryPath: string;
}

export interface FleetRevokeResult {
  name: string;
  did: string;
  status: 'revoked';
  keyPath: string;
  registryPath: string;
  revokedAt: string;
}

export interface WrapIdentitySelection {
  identity: ClawsigIdentity;
  source: 'identity' | 'fleet';
  fleetName?: string;
}

export class FleetError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function addFleetAgent(
  name: string,
  projectDir = process.cwd(),
): Promise<FleetAddResult> {
  assertValidFleetName(name);

  const existing = await listFleetAgents(projectDir);
  if (existing.some((entry) => entry.name === name)) {
    throw new FleetError('FLEET_AGENT_EXISTS', `Fleet agent '${name}' already exists.`);
  }

  const location = selectFleetWriteLocation(projectDir);
  const registry = await loadFleetRegistry(location.registryPath);
  if (registry.agents.some((entry) => entry.name === name)) {
    throw new FleetError('FLEET_AGENT_EXISTS', `Fleet agent '${name}' already exists.`);
  }

  const keyFile = keyFileForName(name);
  const keyPath = join(location.fleetDir, keyFile);
  if (await fileExists(keyPath)) {
    throw new FleetError('FLEET_KEY_EXISTS', `Fleet key file already exists: ${keyPath}`);
  }

  const identity = await generateIdentity(keyPath);
  const createdAt = new Date().toISOString();

  registry.agents.push({
    name,
    did: identity.did,
    status: 'active',
    key_file: keyFile,
    created_at: createdAt,
  });
  registry.updated_at = createdAt;

  await saveFleetRegistry(location, registry);

  return {
    name,
    did: identity.did,
    status: 'active',
    keyPath,
    registryPath: location.registryPath,
  };
}

export async function listFleetAgents(projectDir = process.cwd()): Promise<FleetAgentRecord[]> {
  const entries = await listFleetAgentsByPrecedence(projectDir);
  return entries.sort((a, b) => a.name.localeCompare(b.name));
}

async function listFleetAgentsByPrecedence(projectDir: string): Promise<FleetAgentRecord[]> {
  const merged = new Map<string, FleetAgentRecord>();

  for (const location of fleetLocations(projectDir)) {
    const registry = await loadFleetRegistry(location.registryPath);
    for (const entry of registry.agents) {
      if (merged.has(entry.name)) continue;
      merged.set(entry.name, {
        name: entry.name,
        did: entry.did,
        status: entry.status,
        keyPath: join(location.fleetDir, entry.key_file),
        createdAt: entry.created_at,
        ...(entry.revoked_at ? { revokedAt: entry.revoked_at } : {}),
      });
    }
  }

  return Array.from(merged.values());
}

export async function revokeFleetAgent(
  name: string,
  projectDir = process.cwd(),
): Promise<FleetRevokeResult> {
  assertValidFleetName(name);

  for (const location of fleetLocations(projectDir)) {
    const registry = await loadFleetRegistry(location.registryPath);
    const entry = registry.agents.find((candidate) => candidate.name === name);
    if (!entry) continue;

    if (entry.status === 'revoked' && entry.revoked_at) {
      return {
        name: entry.name,
        did: entry.did,
        status: 'revoked',
        keyPath: join(location.fleetDir, entry.key_file),
        registryPath: location.registryPath,
        revokedAt: entry.revoked_at,
      };
    }

    const revokedAt = new Date().toISOString();
    entry.status = 'revoked';
    entry.revoked_at = revokedAt;
    registry.updated_at = revokedAt;

    await saveFleetRegistry(location, registry);

    return {
      name: entry.name,
      did: entry.did,
      status: 'revoked',
      keyPath: join(location.fleetDir, entry.key_file),
      registryPath: location.registryPath,
      revokedAt,
    };
  }

  throw new FleetError('FLEET_AGENT_NOT_FOUND', `Fleet agent '${name}' was not found.`);
}

export async function loadIdentityForWrap(
  projectDir = process.cwd(),
): Promise<WrapIdentitySelection | null> {
  const revokedPaths = await revokedFleetKeyPaths(projectDir);

  const identityCandidates = [
    process.env['CLAWSIG_IDENTITY'],
    join(projectDir, CLAWSIG_DIR, IDENTITY_FILENAME),
    join(homedir(), CLAWSIG_DIR, IDENTITY_FILENAME),
  ].filter((value): value is string => typeof value === 'string' && value.length > 0);

  for (const candidatePath of identityCandidates) {
    const resolvedCandidate = resolve(candidatePath);
    if (revokedPaths.has(resolvedCandidate)) {
      continue;
    }

    const identity = await tryLoadIdentityFromPath(resolvedCandidate);
    if (identity) {
      return {
        identity,
        source: 'identity',
      };
    }
  }

  const fleetEntries = await listFleetAgentsByPrecedence(projectDir);
  for (const entry of fleetEntries) {
    if (entry.status !== 'active') continue;

    const resolvedKeyPath = resolve(entry.keyPath);
    if (revokedPaths.has(resolvedKeyPath)) {
      continue;
    }

    const identity = await tryLoadIdentityFromPath(resolvedKeyPath);
    if (!identity) continue;
    if (identity.did !== entry.did) continue;

    return {
      identity,
      source: 'fleet',
      fleetName: entry.name,
    };
  }

  return null;
}

function assertValidFleetName(name: string): void {
  if (!name || !FLEET_NAME_PATTERN.test(name)) {
    throw new FleetError(
      'FLEET_NAME_INVALID',
      "Fleet name must match /^[A-Za-z0-9._-]+$/ and cannot be empty.",
    );
  }
}

function keyFileForName(name: string): string {
  return `${name}.jwk.json`;
}

function projectFleetLocation(projectDir: string): FleetLocation {
  const fleetDir = join(projectDir, CLAWSIG_DIR, FLEET_DIRNAME);
  return {
    scope: 'project',
    fleetDir,
    registryPath: join(fleetDir, REGISTRY_FILENAME),
  };
}

function globalFleetLocation(): FleetLocation {
  const fleetDir = join(homedir(), CLAWSIG_DIR, FLEET_DIRNAME);
  return {
    scope: 'global',
    fleetDir,
    registryPath: join(fleetDir, REGISTRY_FILENAME),
  };
}

function fleetLocations(projectDir: string): FleetLocation[] {
  return [projectFleetLocation(projectDir), globalFleetLocation()];
}

function selectFleetWriteLocation(projectDir: string): FleetLocation {
  const projectClawsigDir = join(projectDir, CLAWSIG_DIR);
  if (existsSync(projectClawsigDir)) {
    return projectFleetLocation(projectDir);
  }
  return globalFleetLocation();
}

function defaultRegistry(): FleetRegistryFile {
  const now = new Date().toISOString();
  return {
    version: 1,
    updated_at: now,
    agents: [],
  };
}

async function loadFleetRegistry(registryPath: string): Promise<FleetRegistryFile> {
  try {
    const raw = await readFile(registryPath, 'utf-8');
    const parsed = JSON.parse(raw) as Partial<FleetRegistryFile>;

    if (
      parsed.version !== 1 ||
      !Array.isArray(parsed.agents) ||
      typeof parsed.updated_at !== 'string'
    ) {
      throw new FleetError(
        'FLEET_REGISTRY_INVALID',
        `Invalid fleet registry format: ${registryPath}`,
      );
    }

    const agents: FleetRegistryEntry[] = [];
    for (const entry of parsed.agents as FleetRegistryEntry[]) {
      if (
        typeof entry?.name !== 'string' ||
        typeof entry?.did !== 'string' ||
        (entry?.status !== 'active' && entry?.status !== 'revoked') ||
        typeof entry?.key_file !== 'string' ||
        typeof entry?.created_at !== 'string'
      ) {
        throw new FleetError(
          'FLEET_REGISTRY_INVALID',
          `Invalid fleet registry entry: ${registryPath}`,
        );
      }

      agents.push({
        name: entry.name,
        did: entry.did,
        status: entry.status,
        key_file: entry.key_file,
        created_at: entry.created_at,
        ...(typeof entry.revoked_at === 'string' ? { revoked_at: entry.revoked_at } : {}),
      });
    }

    return {
      version: 1,
      updated_at: parsed.updated_at,
      agents,
    };
  } catch (err) {
    if (err instanceof FleetError) {
      throw err;
    }

    if (isNotFoundError(err)) {
      return defaultRegistry();
    }

    throw new FleetError(
      'FLEET_REGISTRY_READ_ERROR',
      `Failed to read fleet registry: ${registryPath}`,
    );
  }
}

async function saveFleetRegistry(location: FleetLocation, registry: FleetRegistryFile): Promise<void> {
  await mkdir(location.fleetDir, { recursive: true });
  await writeFile(location.registryPath, JSON.stringify(registry, null, 2) + '\n', {
    encoding: 'utf-8',
    mode: 0o600,
  });
}

async function revokedFleetKeyPaths(projectDir: string): Promise<Set<string>> {
  const revokedPaths = new Set<string>();

  for (const location of fleetLocations(projectDir)) {
    const registry = await loadFleetRegistry(location.registryPath);
    for (const entry of registry.agents) {
      if (entry.status !== 'revoked') continue;
      revokedPaths.add(resolve(join(location.fleetDir, entry.key_file)));
    }
  }

  return revokedPaths;
}

async function tryLoadIdentityFromPath(path: string): Promise<ClawsigIdentity | null> {
  try {
    const raw = await readFile(path, 'utf-8');
    const parsed = JSON.parse(raw) as {
      did?: string;
      publicKeyJwk?: JsonWebKey;
      privateKeyJwk?: JsonWebKey;
      createdAt?: string;
    };

    if (
      typeof parsed.did !== 'string' ||
      !parsed.did.startsWith('did:key:z') ||
      !parsed.publicKeyJwk ||
      !parsed.privateKeyJwk ||
      typeof parsed.createdAt !== 'string'
    ) {
      return null;
    }

    return {
      did: parsed.did,
      publicKeyJwk: parsed.publicKeyJwk,
      privateKeyJwk: parsed.privateKeyJwk,
      createdAt: parsed.createdAt,
    };
  } catch {
    return null;
  }
}

function isNotFoundError(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code?: string }).code === 'ENOENT'
  );
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}
