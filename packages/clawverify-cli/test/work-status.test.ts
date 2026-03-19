import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';

import { generateIdentity } from '../src/identity.js';
import { saveWorkConfig, DEFAULT_MARKETPLACE_URL } from '../src/work-config.js';
import type { WorkConfig } from '../src/work-config.js';
import { __setFetch } from '../src/work-api.js';
import { runWorkStatus } from '../src/work-status.js';

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

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(value, null, 2), 'utf-8');
}

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-status-test-'));
  delete process.env['CLAWSIG_IDENTITY'];
});

afterEach(async () => {
  delete process.env['CLAWSIG_IDENTITY'];
  process.exitCode = undefined;
  await rm(tmpDir, { recursive: true, force: true });
});

describe('runWorkStatus', () => {
  it('fails with IDENTITY_MISSING when no identity exists', async () => {
    const result = await quietAsync(() =>
      runWorkStatus({
        submissionId: 'sub_test',
        json: true,
        projectDir: tmpDir,
      }),
    );

    expect(result.status).toBe('error');
    expect(result.error?.code).toBe('IDENTITY_MISSING');
    expect(process.exitCode).toBe(2);
  });

  it('fails with SUBMISSION_MISSING when no submission id can be resolved', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));
    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: DEFAULT_MARKETPLACE_URL,
      createdAt: '2025-01-01T00:00:00Z',
    };
    await saveWorkConfig(config, tmpDir);

    const result = await quietAsync(() =>
      runWorkStatus({
        json: true,
        projectDir: tmpDir,
      }),
    );

    expect(result.status).toBe('error');
    expect(result.error?.code).toBe('SUBMISSION_MISSING');
    expect(process.exitCode).toBe(2);
  });

  it('auto-discovers submission_id from .clawsig/active-bounty.json', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://config.example.com',
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: { mode: 'token', token: 'tok_abc' },
      },
      activeBounty: {
        bountyId: 'bty_test',
        workerDid: identity.did,
        marketplaceUrl: 'https://config.example.com',
        status: 'pending_review',
        claimedAt: '2025-01-01T00:00:02Z',
        idempotencyKey: 'claim:bty_test',
        submissionId: 'sub_from_work_json',
      },
    };
    await saveWorkConfig(config, tmpDir);

    await writeJson(join(tmpDir, '.clawsig', 'active-bounty.json'), {
      submission_id: 'sub_from_active_file',
      marketplace_url: 'https://active.example.com',
    });

    let capturedUrl = '';
    let capturedHeaders: Record<string, string> = {};
    const restore = __setFetch(async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = input.toString();
      capturedHeaders = (init?.headers ?? {}) as Record<string, string>;
      return new Response(
        JSON.stringify({
          submission_id: 'sub_from_active_file',
          status: 'pending_review',
          verification_result: {
            status: 'pass',
            reason_codes: ['VR_CODE'],
          },
          approval_status: 'pending',
          payout: {
            amount_minor: '123',
            currency: 'USD',
          },
          reason_codes: ['TOP_LEVEL_CODE'],
          next_actions: ['wait for requester decision'],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    });

    try {
      const result = await quietAsync(() =>
        runWorkStatus({
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('ok');
      expect(result.submissionId).toBe('sub_from_active_file');
      expect(capturedUrl).toBe('https://active.example.com/v1/submissions/sub_from_active_file');
      expect(capturedHeaders['X-Worker-DID']).toBe(identity.did);
      expect(capturedHeaders.Authorization).toBe('Bearer tok_abc');
      expect(result.reasonCodes).toContain('VR_CODE');
      expect(result.reasonCodes).toContain('TOP_LEVEL_CODE');
    } finally {
      restore();
    }
  });

  it('uses explicit submission id when provided', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://market.example.com',
      createdAt: '2025-01-01T00:00:00Z',
    };
    await saveWorkConfig(config, tmpDir);

    await writeJson(join(tmpDir, '.clawsig', 'active-bounty.json'), {
      submission_id: 'sub_from_active_file',
    });

    let capturedUrl = '';
    const restore = __setFetch(async (input: RequestInfo | URL) => {
      capturedUrl = input.toString();
      return new Response(
        JSON.stringify({
          submission_id: 'sub_explicit',
          status: 'approved',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    });

    try {
      const result = await quietAsync(() =>
        runWorkStatus({
          submissionId: 'sub_explicit',
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('ok');
      expect(capturedUrl).toBe('https://market.example.com/v1/submissions/sub_explicit');
      expect(result.submissionId).toBe('sub_explicit');
    } finally {
      restore();
    }
  });

  it('supports watch polling with configurable interval', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://market.example.com',
      createdAt: '2025-01-01T00:00:00Z',
    };
    await saveWorkConfig(config, tmpDir);

    let pollCount = 0;
    const restore = __setFetch(async () => {
      pollCount += 1;
      return new Response(
        JSON.stringify({
          submission_id: 'sub_watch',
          status: 'pending_review',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      );
    });

    try {
      const result = await quietAsync(() =>
        runWorkStatus({
          submissionId: 'sub_watch',
          watch: true,
          intervalSeconds: 0.01,
          maxPolls: 2,
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('ok');
      expect(pollCount).toBe(2);
      expect(result.watch).toBe(true);
      expect(result.intervalSeconds).toBe(0.01);
    } finally {
      restore();
    }
  });
});
