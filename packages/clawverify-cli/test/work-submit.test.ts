import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';

import { generateIdentity } from '../src/identity.js';
import { saveWorkConfig, loadWorkConfig, DEFAULT_MARKETPLACE_URL } from '../src/work-config.js';
import type { WorkConfig } from '../src/work-config.js';
import { __setFetch } from '../src/work-api.js';
import { saveRuntimeConfig } from '../src/runtime-config.js';
import { runWorkSubmit } from '../src/work-submit.js';

let tmpDir: string;
const validTaskSpec = {
  version: '1',
  objective: 'Ship structured task spec integration',
  repo: 'clawbureau/clawverify-cli',
  base_ref: 'main',
  files_hint: ['src/work-submit.ts'],
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

function isRecord(input: unknown): input is Record<string, unknown> {
  return !!input && typeof input === 'object' && !Array.isArray(input);
}

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
  tmpDir = await mkdtemp(join(tmpdir(), 'clawsig-submit-test-'));
  delete process.env['CLAWSIG_IDENTITY'];
});

afterEach(async () => {
  delete process.env['CLAWSIG_IDENTITY'];
  process.exitCode = undefined;
  await rm(tmpDir, { recursive: true, force: true });
});

describe('runWorkSubmit', () => {
  it('fails with IDENTITY_MISSING when no identity exists', async () => {
    const proofPath = join(tmpDir, 'bundle.json');
    await writeJson(proofPath, { agent_did: 'did:key:z6MkFake' });

    const result = await quietAsync(() =>
      runWorkSubmit({
        proofBundlePath: proofPath,
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
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));
    const proofPath = join(tmpDir, 'bundle.json');
    await writeJson(proofPath, { agent_did: identity.did });

    const result = await quietAsync(() =>
      runWorkSubmit({
        proofBundlePath: proofPath,
        bountyId: 'bty_test',
        json: true,
        projectDir: tmpDir,
      }),
    );

    expect(result.status).toBe('error');
    expect(result.error?.code).toBe('WORK_CONFIG_MISSING');
    expect(process.exitCode).toBe(2);
  });

  it('requires bounty id when no active claim context exists', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: DEFAULT_MARKETPLACE_URL,
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: { mode: 'token', token: 'tok_abc' },
      },
    };
    await saveWorkConfig(config, tmpDir);

    const proofPath = join(tmpDir, 'bundle.json');
    await writeJson(proofPath, { agent_did: identity.did });

    const result = await quietAsync(() =>
      runWorkSubmit({
        proofBundlePath: proofPath,
        json: true,
        projectDir: tmpDir,
      }),
    );

    expect(result.status).toBe('error');
    expect(result.error?.code).toBe('BOUNTY_MISSING');
    expect(process.exitCode).toBe(2);
  });

  it('fails fast when proof bundle agent_did does not match worker DID', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: DEFAULT_MARKETPLACE_URL,
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: { mode: 'token', token: 'tok_abc' },
      },
      activeBounty: {
        bountyId: 'bty_test',
        workerDid: identity.did,
        marketplaceUrl: DEFAULT_MARKETPLACE_URL,
        status: 'accepted',
        claimedAt: '2025-01-01T00:00:02Z',
        idempotencyKey: 'claim:bty_test',
      },
    };
    await saveWorkConfig(config, tmpDir);

    const proofPath = join(tmpDir, 'bundle.json');
    await writeJson(proofPath, { agent_did: 'did:key:z6MkDifferent' });

    const result = await quietAsync(() =>
      runWorkSubmit({
        proofBundlePath: proofPath,
        json: true,
        projectDir: tmpDir,
      }),
    );

    expect(result.status).toBe('error');
    expect(result.error?.code).toBe('PROOF_AGENT_DID_MISMATCH');
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
        auth: { mode: 'token', token: 'tok_abc' },
      },
      activeBounty: {
        bountyId: 'bty_test',
        workerDid: identity.did,
        marketplaceUrl: DEFAULT_MARKETPLACE_URL,
        status: 'accepted',
        claimedAt: '2025-01-01T00:00:02Z',
        idempotencyKey: 'claim:bty_test',
      },
    };
    await saveWorkConfig(config, tmpDir);

    const proofPath = join(tmpDir, 'bundle.json');
    await writeJson(proofPath, { payload: { agent_did: identity.did } });

    let fetchCalled = false;
    const restore = __setFetch(async () => {
      fetchCalled = true;
      return new Response('{}', { status: 200 });
    });

    try {
      const result = await quietAsync(() =>
        runWorkSubmit({
          proofBundlePath: proofPath,
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

  it('submits successfully, forwards auth header, and updates active context', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));
    const requesterDid = 'did:key:z6MkrRequester000000000000000000000000000001';

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://market.example.com',
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: { mode: 'token', token: 'tok_abc' },
      },
      activeBounty: {
        bountyId: 'bty_test',
        workerDid: identity.did,
        marketplaceUrl: 'https://market.example.com',
        status: 'accepted',
        claimedAt: '2025-01-01T00:00:02Z',
        idempotencyKey: 'claim:bty_test',
        requesterDid,
      },
    };
    await saveWorkConfig(config, tmpDir);

    const proofPath = join(tmpDir, 'bundle.json');
    await writeJson(proofPath, {
      payload: {
        agent_did: identity.did,
        visibility: 'requester',
        encrypted_payload: {
          ciphertext_b64u: 'abc',
          iv_b64u: 'abc',
          tag_b64u: 'abc',
          plaintext_hash_b64u: 'abc',
        },
        viewer_keys: [
          { viewer_did: identity.did, role: 'owner' },
          { viewer_did: requesterDid, role: 'requester' },
        ],
        receipts: [
          {
            payload: {
              binding: {
                mission_id: 'bty_test',
              },
            },
          },
        ],
      },
    });

    let capturedUrl = '';
    let capturedHeaders: Record<string, string> = {};
    let capturedBody: Record<string, unknown> = {};

    const restore = __setFetch(async (input: RequestInfo | URL, init?: RequestInit) => {
      capturedUrl = input.toString();
      capturedHeaders = (init?.headers ?? {}) as Record<string, string>;
      capturedBody = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;

      return new Response(
        JSON.stringify({
          submission_id: 'sub_001',
          bounty_id: 'bty_test',
          status: 'pending_review',
          verification: {
            proof_bundle: { status: 'valid', tier: 'gateway' },
          },
          next_actions: ['wait for requester decision'],
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } },
      );
    });

    try {
      const result = await quietAsync(() =>
        runWorkSubmit({
          proofBundlePath: proofPath,
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('ok');
      expect(result.submission?.submission_id).toBe('sub_001');
      expect(result.submission?.status).toBe('pending_review');
      expect(result.nextActions).toContain('wait for requester decision');
      expect(capturedUrl).toBe('https://market.example.com/v1/bounties/bty_test/submit');
      expect(capturedHeaders.Authorization).toBe('Bearer tok_abc');
      expect(capturedBody.worker_did).toBe(identity.did);
      const envelope = capturedBody.proof_bundle_envelope as Record<string, unknown>;
      const payload = isRecord(envelope.payload) ? envelope.payload : envelope;
      expect(payload.agent_did).toBe(identity.did);
      expect(payload.visibility).toBe('requester');

      const updated = await loadWorkConfig(tmpDir);
      expect(updated?.activeBounty?.bountyId).toBe('bty_test');
      expect(updated?.activeBounty?.submissionId).toBe('sub_001');
      expect(updated?.activeBounty?.status).toBe('pending_review');
      expect(updated?.activeBounty?.submittedAt).toBeDefined();
      expect(updated?.activeBounty?.requesterDid).toBe(requesterDid);
    } finally {
      restore();
    }
  });

  it('accepts wrapped proof bundles with payload fields under envelope.payload', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));
  it('fails before submit when task_spec requires did_signature but --commit-proof is missing', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));
    const requesterDid = 'did:key:z6MkrRequester000000000000000000000000000001';

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://market.example.com',
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: { mode: 'token', token: 'tok_abc' },
      },
      activeBounty: {
        bountyId: 'bty_test',
        workerDid: identity.did,
        marketplaceUrl: 'https://market.example.com',
        status: 'accepted',
        claimedAt: '2025-01-01T00:00:02Z',
        idempotencyKey: 'claim:bty_test',
        requesterDid,
        taskSpec: validTaskSpec,
      },
    };
    await saveWorkConfig(config, tmpDir);

    const proofPath = join(tmpDir, 'wrapped-bundle.json');
    await writeJson(proofPath, {
      envelope: {
        payload: {
          agent_did: identity.did,
          receipts: [
            {
              payload: {
                binding: {
                  mission_id: 'bty_test',
                },
              },
            },
          ],
        },
      },
    });

    let capturedBody: Record<string, unknown> = {};
    const restore = __setFetch(async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedBody = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
      return new Response(
        JSON.stringify({
          submission_id: 'sub_wrapped',
          bounty_id: 'bty_test',
          status: 'pending_review',
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } },
      );
    });
    const proofPath = join(tmpDir, 'bundle.json');
    await writeJson(proofPath, {
      payload: {
        agent_did: identity.did,
        visibility: 'requester',
        encrypted_payload: {
          ciphertext_b64u: 'abc',
          iv_b64u: 'abc',
          tag_b64u: 'abc',
          plaintext_hash_b64u: 'abc',
        },
        viewer_keys: [
          { viewer_did: identity.did, role: 'owner' },
          { viewer_did: requesterDid, role: 'requester' },
        ],
        receipts: [
          {
            payload: {
              binding: {
                mission_id: 'bty_test',
              },
            },
          },
        ],
      },
    });

    const restore = __setFetch(async () =>
      new Response(
        JSON.stringify({ error: 'SHOULD_NOT_BE_CALLED' }),
        { status: 500, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    try {
      const result = await quietAsync(() =>
        runWorkSubmit({
          proofBundlePath: proofPath,
          resultSummary: 'PR: https://github.com/clawbureau/clawverify-cli/pull/123',
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('error');
      expect(result.error?.code).toBe('TASK_SPEC_DELIVERABLES_MISSING');
      expect(process.exitCode).toBe(2);
    } finally {
      restore();
    }
  });

  it('passes deliverable validation when commit proof and PR summary are provided', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));
    const requesterDid = 'did:key:z6MkrRequester000000000000000000000000000001';

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://market.example.com',
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: { mode: 'token', token: 'tok_abc' },
      },
      activeBounty: {
        bountyId: 'bty_test',
        workerDid: identity.did,
        marketplaceUrl: 'https://market.example.com',
        status: 'accepted',
        claimedAt: '2025-01-01T00:00:02Z',
        idempotencyKey: 'claim:bty_test',
        requesterDid,
        taskSpec: validTaskSpec,
      },
    };
    await saveWorkConfig(config, tmpDir);

    const proofPath = join(tmpDir, 'bundle.json');
    await writeJson(proofPath, {
      payload: {
        agent_did: identity.did,
        visibility: 'requester',
        encrypted_payload: {
          ciphertext_b64u: 'abc',
          iv_b64u: 'abc',
          tag_b64u: 'abc',
          plaintext_hash_b64u: 'abc',
        },
        viewer_keys: [
          { viewer_did: identity.did, role: 'owner' },
          { viewer_did: requesterDid, role: 'requester' },
        ],
        receipts: [
          {
            payload: {
              binding: {
                mission_id: 'bty_test',
              },
            },
          },
        ],
      },
    });

    const commitProofPath = join(tmpDir, 'commit.sig.json');
    await writeJson(commitProofPath, {
      envelope_version: '1',
      envelope_type: 'commit_proof',
      payload: {
        version: '1',
      },
    });

    const restore = __setFetch(async () =>
      new Response(
        JSON.stringify({
          submission_id: 'sub_002',
          bounty_id: 'bty_test',
          status: 'pending_review',
          verification: {
            proof_bundle: { status: 'valid', tier: 'gateway' },
          },
        }),
        { status: 201, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    try {
      const result = await quietAsync(() =>
        runWorkSubmit({
          proofBundlePath: proofPath,
          commitProofPath,
          resultSummary: 'PR: https://github.com/clawbureau/clawverify-cli/pull/123',
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('ok');
      const submittedEnvelope = capturedBody.proof_bundle_envelope as Record<string, unknown>;
      expect(isRecord(submittedEnvelope)).toBe(true);
      expect((submittedEnvelope.payload as Record<string, unknown>).agent_did).toBe(identity.did);
      expect(result.taskSpec?.version).toBe('1');
      expect(result.validatedDeliverables).toEqual(['pr', 'proof_bundle', 'did_signature']);
    } finally {
      restore();
    }
  });

  it('fails requester visibility submit when requester DID is missing from viewer_keys', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));
    const requesterDid = 'did:key:z6MkrRequester000000000000000000000000000001';

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://market.example.com',
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: { mode: 'token', token: 'tok_abc' },
      },
      activeBounty: {
        bountyId: 'bty_test',
        workerDid: identity.did,
        marketplaceUrl: 'https://market.example.com',
        status: 'accepted',
        claimedAt: '2025-01-01T00:00:02Z',
        idempotencyKey: 'claim:bty_test',
        requesterDid,
      },
    };
    await saveWorkConfig(config, tmpDir);

    const proofPath = join(tmpDir, 'bundle.json');
    await writeJson(proofPath, {
      payload: {
        agent_did: identity.did,
        visibility: 'requester',
        encrypted_payload: {
          ciphertext_b64u: 'abc',
          iv_b64u: 'abc',
          tag_b64u: 'abc',
          plaintext_hash_b64u: 'abc',
        },
        viewer_keys: [
          { viewer_did: identity.did, role: 'owner' },
        ],
        receipts: [
          {
            payload: {
              binding: {
                mission_id: 'bty_test',
              },
            },
          },
        ],
      },
    });

    const restore = __setFetch(async () =>
      new Response(
        JSON.stringify({ error: 'SHOULD_NOT_BE_CALLED' }),
        { status: 500, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    try {
      const result = await quietAsync(() =>
        runWorkSubmit({
          proofBundlePath: proofPath,
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('error');
      expect(result.error?.code).toBe('PROOF_BUNDLE_REQUESTER_VIEWER_MISSING');
      expect(process.exitCode).toBe(2);
    } finally {
      restore();
    }
  });

  it('fails requester visibility submit when requester DID cannot be resolved from active context', async () => {
    const identity = await generateIdentity(join(tmpDir, '.clawsig', 'identity.jwk.json'));
    const explicitRequesterDid = 'did:key:z6MkrRequester000000000000000000000000000002';

    const config: WorkConfig = {
      configVersion: '1',
      workerDid: identity.did,
      marketplaceUrl: 'https://market.example.com',
      createdAt: '2025-01-01T00:00:00Z',
      registration: {
        workerId: 'w-123',
        registeredAt: '2025-01-01T00:00:01Z',
        auth: { mode: 'token', token: 'tok_abc' },
      },
      activeBounty: {
        bountyId: 'bty_test',
        workerDid: identity.did,
        marketplaceUrl: 'https://market.example.com',
        status: 'accepted',
        claimedAt: '2025-01-01T00:00:02Z',
        idempotencyKey: 'claim:bty_test',
      },
    };
    await saveWorkConfig(config, tmpDir);

    const proofPath = join(tmpDir, 'bundle.json');
    await writeJson(proofPath, {
      payload: {
        agent_did: identity.did,
        visibility: 'requester',
        encrypted_payload: {
          ciphertext_b64u: 'abc',
          iv_b64u: 'abc',
          tag_b64u: 'abc',
          plaintext_hash_b64u: 'abc',
        },
        viewer_keys: [
          { viewer_did: identity.did, role: 'owner' },
          { viewer_did: explicitRequesterDid, role: 'requester' },
        ],
        receipts: [
          {
            payload: {
              binding: {
                mission_id: 'bty_test',
              },
            },
          },
        ],
      },
    });

    const restore = __setFetch(async () =>
      new Response(
        JSON.stringify({ error: 'SHOULD_NOT_BE_CALLED' }),
        { status: 500, headers: { 'Content-Type': 'application/json' } },
      ),
    );

    try {
      const result = await quietAsync(() =>
        runWorkSubmit({
          proofBundlePath: proofPath,
          json: true,
          projectDir: tmpDir,
        }),
      );

      expect(result.status).toBe('error');
      expect(result.error?.code).toBe('PROOF_BUNDLE_REQUESTER_DID_UNKNOWN');
      expect(process.exitCode).toBe(2);
    } finally {
      restore();
    }
  });
});
