import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir, tmpdir } from 'node:os';

import {
  addFleetAgent,
  listFleetAgents,
  revokeFleetAgent,
  loadIdentityForWrap,
} from '../src/fleet.js';

let tmpRoot: string;

beforeEach(async () => {
  tmpRoot = await mkdtemp(join(tmpdir(), 'clawsig-fleet-test-'));
  delete process.env['CLAWSIG_IDENTITY'];
});

afterEach(async () => {
  delete process.env['CLAWSIG_IDENTITY'];
  await rm(tmpRoot, { recursive: true, force: true });
});

describe('fleet registry', () => {
  it('adds and lists fleet agents with active status', async () => {
    await mkdir(join(tmpRoot, '.clawsig'), { recursive: true });

    const added = await addFleetAgent('agent-alpha', tmpRoot);

    expect(added.name).toBe('agent-alpha');
    expect(added.did).toMatch(/^did:key:z/);
    expect(added.status).toBe('active');
    expect(added.keyPath).toBe(join(tmpRoot, '.clawsig', 'fleet', 'agent-alpha.jwk.json'));
    expect(added.registryPath).toBe(join(tmpRoot, '.clawsig', 'fleet', 'registry.json'));

    const listed = await listFleetAgents(tmpRoot);
    const alpha = listed.find((entry) => entry.name === 'agent-alpha');
    expect(alpha).toBeDefined();
    expect(alpha?.did).toBe(added.did);
    expect(alpha?.status).toBe('active');
  });

  it('revoke marks agent as revoked and keeps key discoverable in list', async () => {
    await mkdir(join(tmpRoot, '.clawsig'), { recursive: true });

    const added = await addFleetAgent('agent-bravo', tmpRoot);
    const revoked = await revokeFleetAgent('agent-bravo', tmpRoot);

    expect(revoked.name).toBe('agent-bravo');
    expect(revoked.did).toBe(added.did);
    expect(revoked.status).toBe('revoked');
    expect(typeof revoked.revokedAt).toBe('string');

    const listed = await listFleetAgents(tmpRoot);
    const bravo = listed.find((entry) => entry.name === 'agent-bravo');
    expect(bravo).toBeDefined();
    expect(bravo?.status).toBe('revoked');
  });

  it('stores fleet registry under global ~/.clawsig/fleet when project .clawsig is absent', async () => {
    const fakeHome = join(tmpRoot, 'fake-home');
    await mkdir(fakeHome, { recursive: true });

    const originalHome = process.env['HOME'];
    process.env['HOME'] = fakeHome;

    try {
      if (homedir() !== fakeHome) {
        return;
      }
      const added = await addFleetAgent('agent-global', tmpRoot);
      expect(added.keyPath).toBe(join(fakeHome, '.clawsig', 'fleet', 'agent-global.jwk.json'));
      expect(added.registryPath).toBe(join(fakeHome, '.clawsig', 'fleet', 'registry.json'));
    } finally {
      process.env['HOME'] = originalHome;
    }
  });
});

describe('wrap identity discovery', () => {
  it('discovers active fleet key and excludes revoked fleet key', async () => {
    await mkdir(join(tmpRoot, '.clawsig'), { recursive: true });

    const added = await addFleetAgent('agent-wrap', tmpRoot);
    const selectedActive = await loadIdentityForWrap(tmpRoot);

    expect(selectedActive).not.toBeNull();
    expect(selectedActive?.source).toBe('fleet');
    expect(selectedActive?.fleetName).toBe('agent-wrap');
    expect(selectedActive?.identity.did).toBe(added.did);

    await revokeFleetAgent('agent-wrap', tmpRoot);
    const selectedRevoked = await loadIdentityForWrap(tmpRoot);
    if (selectedRevoked) {
      expect(selectedRevoked.identity.did).not.toBe(added.did);
    } else {
      expect(selectedRevoked).toBeNull();
    }
  });

  it('does not load a revoked fleet key via CLAWSIG_IDENTITY', async () => {
    await mkdir(join(tmpRoot, '.clawsig'), { recursive: true });

    const added = await addFleetAgent('agent-env', tmpRoot);
    await revokeFleetAgent('agent-env', tmpRoot);

    process.env['CLAWSIG_IDENTITY'] = added.keyPath;

    const selected = await loadIdentityForWrap(tmpRoot);
    if (selected) {
      expect(selected.identity.did).not.toBe(added.did);
    } else {
      expect(selected).toBeNull();
    }
  });
});
