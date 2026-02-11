import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';

import plugin, {
  classifyAirlockPath,
  partitionBootstrapFilesForAirlock,
} from '../dist/openclaw.js';

test('classifyAirlockPath classifies trusted/untrusted/unknown paths', () => {
  const identityRoots = ['/identity'];
  const jobRoots = ['/job'];

  assert.equal(
    classifyAirlockPath('/identity/bootstrap/AGENTS.md', identityRoots, jobRoots),
    'trusted',
  );

  assert.equal(
    classifyAirlockPath('/job/repo/AGENTS.md', identityRoots, jobRoots),
    'untrusted',
  );

  assert.equal(
    classifyAirlockPath('/tmp/random/AGENTS.md', identityRoots, jobRoots),
    'unknown',
  );
});

test('partitionBootstrapFilesForAirlock partitions by IdentityRoot/JobRoot', () => {
  const partition = partitionBootstrapFilesForAirlock(
    [
      { path: '/identity/bootstrap/AGENTS.md', content: 'ok' },
      { path: '/job/repo/AGENTS.md', content: 'bad' },
      { path: '/elsewhere/SYSTEM.md', content: 'unknown' },
    ],
    {
      enabled: true,
      identityRoots: ['/identity'],
      jobRoots: ['/job'],
      requireTrustedBootstrap: true,
    },
  );

  assert.equal(partition.trustedFiles.length, 1);
  assert.equal(partition.untrustedFiles.length, 1);
  assert.equal(partition.unknownFiles.length, 1);
});

test('plugin fails closed on untrusted bootstrap files when airlock is enabled', async () => {
  const tmpRoot = await mkdtemp(path.join(os.tmpdir(), 'openclaw-airlock-test-'));
  const stateDir = path.join(tmpRoot, 'state');

  try {
    const internalHooks = new Map();
    const hooks = new Map();

    const api = {
      id: 'provider-clawproxy',
      version: '0.1.0-test',
      pluginConfig: {
        baseUrl: 'https://clawproxy.test',
        mode: 'enforce',
        includePromptPack: true,
        includeToolEvents: false,
        airlock: {
          enabled: true,
          identityRoots: ['/identity'],
          jobRoots: ['/job'],
          requireTrustedBootstrap: true,
        },
      },
      config: {},
      runtime: {
        version: 'openclaw-test',
        state: {
          resolveStateDir: () => stateDir,
        },
      },
      logger: {
        info: () => {},
        warn: () => {},
        error: () => {},
        debug: () => {},
      },
      resolvePath: (input) => input,
      registerHook: (event, handler) => {
        internalHooks.set(event, handler);
      },
      on: (hookName, handler) => {
        hooks.set(hookName, handler);
      },
    };

    plugin.register(api);

    const bootstrapHandler = internalHooks.get('agent:bootstrap');
    const beforeAgentStart = hooks.get('before_agent_start');

    assert.equal(typeof bootstrapHandler, 'function');
    assert.equal(typeof beforeAgentStart, 'function');

    const sessionKey = 'agent:main:test:airlock';

    await bootstrapHandler({
      type: 'agent',
      action: 'bootstrap',
      sessionKey,
      context: {
        sessionKey,
        bootstrapFiles: [
          {
            name: 'AGENTS.md',
            path: '/job/repo/AGENTS.md',
            content: 'buyer-controlled',
          },
        ],
      },
    });

    await assert.rejects(
      () =>
        beforeAgentStart(
          { prompt: 'hello', messages: [] },
          { agentId: 'main', sessionKey, workspaceDir: tmpRoot },
        ),
      /AIRLOCK_BOOTSTRAP_VIOLATION/,
    );
  } finally {
    await rm(tmpRoot, { recursive: true, force: true });
  }
});
