import { execFileSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { normalizeCommitProofEnvelope } from '../src/commit-proof.js';
import { generateIdentity } from '../src/identity.js';

let repoDir: string;

function initGitRepo(dir: string): void {
  execFileSync('git', ['init'], { cwd: dir, stdio: 'ignore' });
  execFileSync('git', ['checkout', '-b', 'feature/commit-proof'], {
    cwd: dir,
    stdio: 'ignore',
  });
  execFileSync('git', ['remote', 'add', 'origin', 'git@github.com:clawbureau/clawverify-cli.git'], {
    cwd: dir,
    stdio: 'ignore',
  });
}

beforeEach(async () => {
  repoDir = await mkdtemp(join(tmpdir(), 'clawsig-commit-proof-repo-'));
  initGitRepo(repoDir);
  delete process.env.CLAWSIG_IDENTITY;
});

afterEach(async () => {
  delete process.env.CLAWSIG_IDENTITY;
  process.exitCode = undefined;
  await rm(repoDir, { recursive: true, force: true });
});

describe('commit proof normalization', () => {
  it('upgrades legacy commit_proof envelopes to the repo-bound payload schema', async () => {
    const identity = await generateIdentity(join(repoDir, '.clawsig', 'identity.jwk.json'));
    const legacyEnvelope = {
      envelope_version: '1',
      envelope_type: 'commit_proof',
      payload: {
        type: 'commit_proof',
        commit_sha: 'ABCDEF1',
        agent_did: identity.did,
        timestamp: '2026-03-20T00:00:00.000Z',
      },
      payload_hash_b64u: 'legacyhash',
      hash_algorithm: 'SHA-256',
      signature_b64u: 'legacysig',
      algorithm: 'Ed25519',
      signer_did: identity.did,
      issued_at: '2026-03-20T00:00:00.000Z',
    } satisfies Record<string, unknown>;

    const normalized = await normalizeCommitProofEnvelope(legacyEnvelope, identity, {
      projectDir: repoDir,
    });

    expect(normalized.payload).toMatchObject({
      proof_version: '1',
      commit_sha: 'abcdef1',
      repository: 'clawbureau/clawverify-cli',
      branch: 'feature/commit-proof',
    });
    expect(normalized.payload.repo_claim_id).toMatch(/^claim_[a-f0-9]{32}$/);
    expect(normalized.signer_did).toBe(identity.did);
  });

  it('upgrades legacy message signatures using the provided projectDir context', async () => {
    const identity = await generateIdentity(join(repoDir, '.clawsig', 'identity.jwk.json'));
    const legacyMessageSignature = {
      type: 'message_signature',
      message: 'commit:1234567',
      did: identity.did,
    } satisfies Record<string, unknown>;

    const normalized = await normalizeCommitProofEnvelope(legacyMessageSignature, identity, {
      projectDir: repoDir,
    });

    expect(normalized.payload).toMatchObject({
      proof_version: '1',
      commit_sha: '1234567',
      repository: 'clawbureau/clawverify-cli',
      branch: 'feature/commit-proof',
    });
    expect(normalized.payload.repo_claim_id).toMatch(/^claim_[a-f0-9]{32}$/);
  });
});
