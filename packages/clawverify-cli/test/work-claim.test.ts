import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { generateIdentity } from '../src/identity.js';
import { saveWorkConfig, loadWorkConfig, DEFAULT_MARKETPLACE_URL } from '../src/work-config.js';
import type { WorkConfig } from '../src/work-config.js';
import { activeBountyPath } from '../src/active-bounty.js';
import { __setFetch } from '../src/work-api.js';
import { saveRuntimeConfig } from '../src/runtime-config.js';
import { runWorkClaim } from '../src/work-claim.js';

let tmpDir: string;
const validTaskSpec = {
  version: '1',
  objective: 'Implement structured schema integration',
  repo: 'clawbureau/clawverify-cli',
  base_ref: 'main',
  files_hint: ['src/work-submit.ts', 'src/work-claim.ts'],
  validation: {
    commands: ['pnpm typecheck', 'pnpm test'],
    timeout_seconds: 300,
  },
  constraints: {
    max_files_changed: 20,
    forbidden_patterns: ['rm -rf', 'force push'],
    required_proof_tier: 'gateway',
  },
  deliverables: ['pr', 'proof_bundle', 'did_signature'],
} as const;

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
  tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-claim-test-'));
  delete process.env['CLAWSIG_IDENTITY'];
});

afterEach(async () => {
  delete process.env['CLAWSIG_IDENTITY'];
  process.exitCode = undefined;
  await rm(tmpDir, { recursive: true, force: true });
});

describe('runWorkClaim', () => {
  it('fails with IDENTITY_MISSING when no identity exists', async () => {
    const result = await quietAsync(() =>
      runWorkClaim({
        bountyId: 'bty_test',
        json: true,
        projectDir: tmpDir,
      }),
    );

    expect(result.status).toBe('error');
    expect(result.error?.code).toBe('IDENTITY_MISSING');
    expect(process.exitCode).toBe(2);
  });

  it('fails with WORK_CONFIG_MISSING when work config is absent', async () => {
    await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));

    const result = await quietAsync(() =>
      runWorkClaim({
        bountyId: 'bty_test',
        json: true,
        projectDir: tmpDir,
      }),
    );

    expect(result.status).toBe('error');
    expect(result.error?.code).toBe('WORK_CONFIG_MISSING');
    expect(process.exitCode).toBe(2);
  });

  it('fails with WORKER_AUTH_MISSING when registration token is not present', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: DEFAULT_MARKETPLACE_URL,
      createdAt: '2025-01-01T00:00:00Z',
    };
    await saveWorkConfig(config, tmpDir);

    const result = await quietAsync(() =>
      runWorkClaim({
        bountyId: 'bty_test',
        json: true,
        projectDir: tmpDir,
      }),
    );

    expect(result.status).toBe('error');
    expect(result.error?.code).toBe('WORKER_AUTH_MISSING');
    expect(process.exitCode).toBe(2);
  });

  it('blocks marketplace calls when runtime config disables marketplace', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));
    await saveRuntimeConfig(
      {
        configVersion: '1',
        marketplace: { enabled: false },
      },
      tmpDir,
    );

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: DEFAULT_MARKETPLACE_URL,
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: {
          mode: 'token',
          token: 'tok_abc123',
        },
      },
    };
    await saveWorkConfig(config, tmpDir);

    let fetchCalled = false;
    const restore = __setFetch(async () => {
      fetchCalled = true;
      return new Response('{}', { status: 200 });
    });

    try {
      const result = await quietAsync(() =>
        runWorkClaim({
          bountyId: 'bty_test',
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('error');
      expect(result.error?.code).toBe('MARKETPLACE_DISABLED');
      expect(process.exitCode).toBe(2);
      expect(fetchCalled).toBe(false);
    } finally {
      restore();
    }
  });

  it('claims bounty and persists activeBounty context', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://market.example.com',
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: {
          mode: 'token',
          token: 'tok_abc123',
        },
      },
    };
    await saveWorkConfig(config, tmpDir);

    let capturedUrl = '';
    let capturedHeaders: Record<string, string> = {};
    let capturedBody: Record<string, unknown> = {};

    const restore = __setFetch(async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = input.toString();
      capturedHeaders = (init?.headers ?? {}) as Record<string, string>;
      capturedBody = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;

      return new Response(
        JSON.stringify({
          bounty_id: 'bty_test',
          escrow_id: 'esc_001',
          status: 'accepted',
          worker_did: identity.did,
          accepted_at: '2025-02-20T00:00:00.000Z',
          fee_policy_version: 'cuts_v1',
          payout: { worker_net_minor: '120', currency: 'USD' },
          task_spec: validTaskSpec,
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } },
      );
    });

    try {
      const result = await quietAsync(() =>
        runWorkClaim({
          bountyId: 'bty_test',
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('ok');
      expect(result.claim?.bounty_id).toBe('bty_test');
      expect(capturedUrl).toBe('https://market.example.com/v1/bounties/bty_test/accept');
      expect(capturedHeaders.Authorization).toBe('Bearer tok_abc123');
      expect(capturedBody.worker_did).toBe(identity.did);
      expect(capturedBody.idempotency_key).toBe(`claim:bty_test:${identity.did}`);

      const updated = await loadWorkConfig(tmpDir);
      expect(updated?.activeBounty).toBeDefined();
      expect(updated?.activeBounty?.bountyId).toBe('bty_test');
      expect(updated?.activeBounty?.workerDid).toBe(identity.did);
      expect(updated?.activeBounty?.idempotencyKey).toBe(`claim:bty_test:${identity.did}`);
      expect(updated?.activeBounty?.taskSpec?.version).toBe('1');

      const activeFile = await readFile(activeBountyPath(tmpDir), 'utf-8');
      const activeFromDisk = JSON.parse(activeFile) as Record<string, unknown>;
      expect(activeFromDisk['bounty_id']).toBe('bty_test');
      expect((activeFromDisk['task_spec'] as Record<string, unknown>)['version']).toBe('1');
      expect(result.taskSpec?.deliverables).toEqual(['pr', 'proof_bundle', 'did_signature']);
    } finally {
      restore();
    }
  });

  it('fails when claim response task_spec is invalid', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://market.example.com',
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: {
          mode: 'token',
          token: 'tok_abc123',
        },
      },
    };
    await saveWorkConfig(config, tmpDir);

    const restore = __setFetch(async () =>
      new Response(
        JSON.stringify({
          bounty_id: 'bty_test',
          escrow_id: 'esc_001',
          status: 'accepted',
          worker_did: identity.did,
          accepted_at: '2025-02-20T00:00:00.000Z',
          task_spec: {
            version: '1',
            objective: '',
          },
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    try {
      const result = await quietAsync(() =>
        runWorkClaim({
          bountyId: 'bty_test',
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('error');
      expect(result.error?.code).toBe('TASK_SPEC_INVALID');
      expect(process.exitCode).toBe(1);
    } finally {
      restore();
    }
  });

  it('surfaces API error codes from marketplace', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://market.example.com',
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: {
          mode: 'token',
          token: 'tok_abc123',
        },
      },
    };
    await saveWorkConfig(config, tmpDir);

    const restore = __setFetch(async () =>
      new Response(
        JSON.stringify({
          error: 'BOUNTY_ALREADY_ACCEPTED',
          message: 'Bounty already accepted',
          details: { worker_did: 'did:key:someone-else' },
        }),
        { status: 409, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    try {
      const result = await quietAsync(() =>
        runWorkClaim({
          bountyId: 'bty_test',
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('error');
      expect(result.error?.code).toBe('BOUNTY_ALREADY_ACCEPTED');
      expect(result.error?.message).toContain('Bounty already accepted');
      expect(process.exitCode).toBe(1);
    } finally {
      restore();
    }
  });
});
