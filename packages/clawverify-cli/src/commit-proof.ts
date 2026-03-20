import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';

import { hashJsonB64u } from '@clawbureau/clawsig-sdk';

import { identityToAgentDid, loadIdentity, type ClawsigIdentity } from './identity.js';

const COMMIT_SHA_RE = /^[a-f0-9]{7,64}$/i;
const REPOSITORY_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const execFileAsync = promisify(execFile);

export interface CommitProofEnvelopePayload {
  proof_version: '1';
  repo_claim_id: string;
  commit_sha: string;
  repository: string;
  branch?: string;
}

export interface CommitProofEnvelope {
  envelope_version: '1';
  envelope_type: 'commit_proof';
  payload: CommitProofEnvelopePayload;
  payload_hash_b64u: string;
  hash_algorithm: 'SHA-256';
  signature_b64u: string;
  algorithm: 'Ed25519';
  signer_did: string;
  issued_at: string;
}

function normalizeCommitSha(commitSha: string): string {
  const normalized = commitSha.trim();
  if (!COMMIT_SHA_RE.test(normalized)) {
    throw new Error('commit SHA must be 7-64 hex characters');
  }
  return normalized.toLowerCase();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isCommitProofEnvelopePayload(value: unknown): value is CommitProofEnvelopePayload {
  if (!isRecord(value)) return false;

  return (
    value.proof_version === '1' &&
    typeof value.repo_claim_id === 'string' &&
    value.repo_claim_id.trim().length > 0 &&
    typeof value.commit_sha === 'string' &&
    COMMIT_SHA_RE.test(value.commit_sha) &&
    typeof value.repository === 'string' &&
    value.repository.trim().length > 0 &&
    (value.branch === undefined || typeof value.branch === 'string')
  );
}

export function isCommitProofEnvelope(value: unknown): value is CommitProofEnvelope {
  if (!isRecord(value)) return false;

  return (
    value.envelope_version === '1' &&
    value.envelope_type === 'commit_proof' &&
    value.hash_algorithm === 'SHA-256' &&
    value.algorithm === 'Ed25519' &&
    typeof value.payload_hash_b64u === 'string' &&
    typeof value.signature_b64u === 'string' &&
    typeof value.signer_did === 'string' &&
    typeof value.issued_at === 'string' &&
    isCommitProofEnvelopePayload(value.payload)
  );
}

function extractCommitShaFromLegacyMessageSignature(
  value: Record<string, unknown>,
): string | null {
  const type = value.type;
  const message = value.message;

  if (type !== 'message_signature' || typeof message !== 'string') {
    return null;
  }

  const match = message.trim().match(/^commit:([a-f0-9]{7,64})$/i);
  if (!match) return null;
  return match[1]!.toLowerCase();
}

function extractCommitShaFromLegacyCommitProofEnvelope(
  value: Record<string, unknown>,
): string | null {
  if (value.envelope_type !== 'commit_proof' || !isRecord(value.payload)) {
    return null;
  }

  const commitSha = value.payload.commit_sha;
  if (typeof commitSha !== 'string') {
    return null;
  }

  const normalized = commitSha.trim();
  if (!COMMIT_SHA_RE.test(normalized)) {
    return null;
  }

  return normalized.toLowerCase();
}

function extractLegacySignerDid(value: Record<string, unknown>): string {
  const payload = isRecord(value.payload) ? value.payload : null;
  const candidates = [
    typeof value.did === 'string' ? value.did : '',
    typeof value.signer_did === 'string' ? value.signer_did : '',
    typeof payload?.agent_did === 'string' ? payload.agent_did : '',
  ];

  for (const candidate of candidates) {
    const normalized = candidate.trim();
    if (normalized.length > 0) {
      return normalized;
    }
  }

  return '';
}

async function gitOutput(args: string[], projectDir?: string): Promise<string> {
  const { stdout } = await execFileAsync('git', args, {
    cwd: projectDir,
    encoding: 'utf8',
  });
  return stdout.trim();
}

function parseRepositoryFromRemote(remoteUrl: string): string | null {
  const trimmed = remoteUrl.trim();
  if (!trimmed) return null;

  const simple = trimmed.replace(/\.git$/i, '');
  if (REPOSITORY_RE.test(simple)) return simple;

  const scpMatch = trimmed.match(/^[^@]+@[^:]+:(.+)$/);
  if (scpMatch?.[1]) {
    const pathParts = scpMatch[1]
      .replace(/\.git$/i, '')
      .split('/')
      .filter((part) => part.length > 0);
    if (pathParts.length >= 2) {
      return `${pathParts[pathParts.length - 2]}/${pathParts[pathParts.length - 1]}`;
    }
  }

  try {
    const parsed = new URL(trimmed);
    const pathParts = parsed.pathname
      .replace(/^\/+/, '')
      .replace(/\.git$/i, '')
      .split('/')
      .filter((part) => part.length > 0);
    if (pathParts.length >= 2) {
      return `${pathParts[pathParts.length - 2]}/${pathParts[pathParts.length - 1]}`;
    }
  } catch {
    return null;
  }

  return null;
}

function normalizeRepoClaimId(repoClaimId: string): string {
  const normalized = repoClaimId.trim();
  if (normalized.length === 0) {
    throw new Error('--repo-claim-id cannot be empty');
  }
  return normalized;
}

function deriveRepoClaimId(repository: string): string {
  const digest = createHash('sha256')
    .update(repository.toLowerCase())
    .digest('hex')
    .slice(0, 32);
  return `claim_${digest}`;
}

async function resolveRepositoryAndBranch(projectDir?: string): Promise<{
  repository: string;
  branch?: string;
}> {
  let repository = '';
  try {
    const remoteUrl = await gitOutput(['config', '--get', 'remote.origin.url'], projectDir);
    const parsedRepository = parseRepositoryFromRemote(remoteUrl);
    if (parsedRepository) {
      repository = parsedRepository;
    }
  } catch {
    // Fallback to CI metadata below.
  }

  if (!repository && process.env.GITHUB_REPOSITORY) {
    const envRepository = process.env.GITHUB_REPOSITORY.trim();
    if (REPOSITORY_RE.test(envRepository)) {
      repository = envRepository;
    }
  }

  if (!repository) {
    throw new Error(
      'Could not resolve repository from git remote origin. Set remote.origin.url or run in a git checkout.',
    );
  }

  let branch: string | undefined;
  try {
    const currentBranch = await gitOutput(['branch', '--show-current'], projectDir);
    if (currentBranch.length > 0) {
      branch = currentBranch;
    }
  } catch {
    // Detached HEAD or unavailable git metadata is non-fatal.
  }

  return { repository, branch };
}

export interface SignCommitProofOptions {
  repoClaimId?: string;
  projectDir?: string;
}

export async function signCommitProofEnvelope(
  commitSha: string,
  identity: ClawsigIdentity,
  options: SignCommitProofOptions = {},
): Promise<CommitProofEnvelope> {
  const normalizedCommitSha = normalizeCommitSha(commitSha);
  const issuedAt = new Date().toISOString();
  const { repository, branch } = await resolveRepositoryAndBranch(options.projectDir);
  const repoClaimId = options.repoClaimId
    ? normalizeRepoClaimId(options.repoClaimId)
    : deriveRepoClaimId(repository);

  const payload: CommitProofEnvelopePayload = {
    proof_version: '1',
    repo_claim_id: repoClaimId,
    commit_sha: normalizedCommitSha,
    repository,
    ...(branch ? { branch } : {}),
  };

  const payloadHashB64u = await hashJsonB64u(payload);
  const signer = await identityToAgentDid(identity);
  const signature = await signer.sign(new TextEncoder().encode(payloadHashB64u));

  return {
    envelope_version: '1',
    envelope_type: 'commit_proof',
    payload,
    payload_hash_b64u: payloadHashB64u,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: identity.did,
    issued_at: issuedAt,
  };
}

export async function normalizeCommitProofEnvelope(
  value: Record<string, unknown>,
  identity: ClawsigIdentity,
  options: SignCommitProofOptions = {},
): Promise<CommitProofEnvelope> {
  if (isCommitProofEnvelope(value)) {
    return value;
  }

  const commitSha =
    extractCommitShaFromLegacyMessageSignature(value) ??
    extractCommitShaFromLegacyCommitProofEnvelope(value);
  if (!commitSha) {
    throw new Error(
      'commit proof must be a schema-valid commit_proof envelope, a legacy commit_proof envelope, or a legacy message_signature with "commit:<sha>"',
    );
  }

  const signerDid = extractLegacySignerDid(value);
  if (signerDid && signerDid !== identity.did) {
    throw new Error(
      `legacy commit proof DID (${signerDid}) does not match current identity DID (${identity.did})`,
    );
  }

  return signCommitProofEnvelope(commitSha, identity, options);
}

export async function signCommitProofEnvelopeForCurrentIdentity(
  commitSha: string,
  projectDir?: string,
  options: Omit<SignCommitProofOptions, 'projectDir'> = {},
): Promise<CommitProofEnvelope> {
  const identity = await loadIdentity(projectDir);
  if (!identity) {
    throw new Error('No persistent identity found. Run `clawsig init` first.');
  }
  return signCommitProofEnvelope(commitSha, identity, {
    ...options,
    projectDir,
  });
}
