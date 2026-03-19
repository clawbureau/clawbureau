import { hashJsonB64u } from '@clawbureau/clawsig-sdk';

import { identityToAgentDid, loadIdentity, type ClawsigIdentity } from './identity.js';

const COMMIT_SHA_RE = /^[a-f0-9]{7,64}$/i;

export interface CommitProofEnvelopePayload {
  type: 'commit_proof';
  commit_sha: string;
  agent_did: string;
  timestamp: string;
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
    isRecord(value.payload)
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

export async function signCommitProofEnvelope(
  commitSha: string,
  identity: ClawsigIdentity,
): Promise<CommitProofEnvelope> {
  const normalizedCommitSha = normalizeCommitSha(commitSha);
  const timestamp = new Date().toISOString();

  const payload: CommitProofEnvelopePayload = {
    type: 'commit_proof',
    commit_sha: normalizedCommitSha,
    agent_did: identity.did,
    timestamp,
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
    issued_at: timestamp,
  };
}

export async function normalizeCommitProofEnvelope(
  value: Record<string, unknown>,
  identity: ClawsigIdentity,
): Promise<CommitProofEnvelope> {
  if (isCommitProofEnvelope(value)) {
    return value;
  }

  const commitSha = extractCommitShaFromLegacyMessageSignature(value);
  if (!commitSha) {
    throw new Error(
      'commit proof must be a commit_proof signed envelope or a legacy message_signature with "commit:<sha>"',
    );
  }

  const signerDid = typeof value.did === 'string' ? value.did.trim() : '';
  if (signerDid && signerDid !== identity.did) {
    throw new Error(
      `legacy commit signature DID (${signerDid}) does not match current identity DID (${identity.did})`,
    );
  }

  return signCommitProofEnvelope(commitSha, identity);
}

export async function signCommitProofEnvelopeForCurrentIdentity(
  commitSha: string,
  projectDir?: string,
): Promise<CommitProofEnvelope> {
  const identity = await loadIdentity(projectDir);
  if (!identity) {
    throw new Error('No persistent identity found. Run `clawsig init` first.');
  }
  return signCommitProofEnvelope(commitSha, identity);
}
