import type { VerificationError } from './types';
import {
  base64UrlDecode,
  base64UrlEncode,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto';
import { isValidDidFormat, isValidIsoDate } from './schema-registry';
import { validateLogInclusionProofV1 } from './schema-validation';

interface LogInclusionProofLike {
  proof_version: '1';
  log_id: string;
  tree_size: number;
  leaf_hash_b64u: string;
  root_hash_b64u: string;
  audit_path: string[];
  root_published_at: string;
  root_signature: {
    signer_did: string;
    sig_b64u: string;
  };
  metadata?: Record<string, unknown>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(digest);
}

function expectedAuditPathLength(treeSize: number): number {
  let n = treeSize;
  let len = 0;
  while (n > 1) {
    n = Math.floor((n + 1) / 2);
    len += 1;
  }
  return len;
}

function decodeLeafIndex(metadata: unknown): number | null {
  if (!isRecord(metadata)) return null;
  const index = metadata.leaf_index;
  if (!Number.isInteger(index) || (index as number) < 0) return null;
  return index as number;
}

export interface InclusionProofVerification {
  valid: boolean;
  error?: VerificationError;
  reason?: string;
}

/**
 * Verify `log_inclusion_proof.v1`.
 *
 * Fail-closed expectations:
 * - strict schema
 * - valid did:key root signature over root_hash_b64u
 * - valid Merkle path (sha256(left||right), duplicate-last at generation time)
 */
export async function verifyLogInclusionProof(
  proof: unknown,
): Promise<InclusionProofVerification> {
  const schemaResult = validateLogInclusionProofV1(proof);
  if (!schemaResult.valid) {
    return {
      valid: false,
      reason: schemaResult.message,
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: schemaResult.message,
        field: schemaResult.field,
      },
    };
  }

  const p = proof as LogInclusionProofLike;

  if (!isValidIsoDate(p.root_published_at)) {
    return {
      valid: false,
      reason: 'Invalid root_published_at date format',
      error: {
        code: 'INCLUSION_PROOF_INVALID',
        message: 'root_published_at must be a valid ISO 8601 date',
        field: 'root_published_at',
      },
    };
  }

  const leafIndex = decodeLeafIndex(p.metadata);
  if (leafIndex === null) {
    return {
      valid: false,
      reason: 'Missing metadata.leaf_index required for ordered Merkle verification',
      error: {
        code: 'INCLUSION_PROOF_INVALID',
        message:
          'inclusion_proof.metadata.leaf_index (integer) is required for ordered Merkle verification',
        field: 'metadata.leaf_index',
      },
    };
  }

  if (!Number.isInteger(p.tree_size) || p.tree_size <= 0) {
    return {
      valid: false,
      reason: 'tree_size must be a positive integer',
      error: {
        code: 'INCLUSION_PROOF_INVALID',
        message: 'tree_size must be a positive integer for inclusion proofs',
        field: 'tree_size',
      },
    };
  }

  if (leafIndex >= p.tree_size) {
    return {
      valid: false,
      reason: 'leaf_index out of bounds',
      error: {
        code: 'INCLUSION_PROOF_INVALID',
        message: 'metadata.leaf_index must be less than tree_size',
        field: 'metadata.leaf_index',
      },
    };
  }

  const expectedPathLen = expectedAuditPathLength(p.tree_size);
  if (p.audit_path.length !== expectedPathLen) {
    return {
      valid: false,
      reason: 'audit_path length does not match tree_size',
      error: {
        code: 'INCLUSION_PROOF_INVALID',
        message: `audit_path length must be ${expectedPathLen} for tree_size=${p.tree_size}`,
        field: 'audit_path',
      },
    };
  }

  // Verify root signature first.
  if (!isValidDidFormat(p.root_signature.signer_did)) {
    return {
      valid: false,
      reason: 'Invalid root signature DID format',
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'root_signature.signer_did must be a valid DID',
        field: 'root_signature.signer_did',
      },
    };
  }

  const publicKeyBytes = extractPublicKeyFromDidKey(p.root_signature.signer_did);
  if (!publicKeyBytes) {
    return {
      valid: false,
      reason: 'Could not extract public key from root signature DID',
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'root_signature.signer_did must be did:key with Ed25519 multicodec',
        field: 'root_signature.signer_did',
      },
    };
  }

  try {
    const sigBytes = base64UrlDecode(p.root_signature.sig_b64u);
    const msgBytes = new TextEncoder().encode(p.root_hash_b64u);

    const ok = await verifySignature('Ed25519', publicKeyBytes, sigBytes, msgBytes);
    if (!ok) {
      return {
        valid: false,
        reason: 'Root signature verification failed',
        error: {
          code: 'SIGNATURE_INVALID',
          message: 'root_signature.sig_b64u does not verify root_hash_b64u',
          field: 'root_signature.sig_b64u',
        },
      };
    }
  } catch {
    return {
      valid: false,
      reason: 'Root signature verification error',
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'Failed to verify root_signature.sig_b64u',
        field: 'root_signature.sig_b64u',
      },
    };
  }

  // Verify Merkle inclusion path.
  let current: Uint8Array;
  try {
    current = base64UrlDecode(p.leaf_hash_b64u);
  } catch {
    return {
      valid: false,
      reason: 'Invalid leaf hash encoding',
      error: {
        code: 'INCLUSION_PROOF_INVALID',
        message: 'leaf_hash_b64u is not valid base64url',
        field: 'leaf_hash_b64u',
      },
    };
  }

  let index = leafIndex;
  for (const siblingHash of p.audit_path) {
    let sibling: Uint8Array;
    try {
      sibling = base64UrlDecode(siblingHash);
    } catch {
      return {
        valid: false,
        reason: 'Invalid sibling hash encoding in audit_path',
        error: {
          code: 'INCLUSION_PROOF_INVALID',
          message: 'audit_path entries must be valid base64url strings',
          field: 'audit_path',
        },
      };
    }

    current =
      index % 2 === 0
        ? await sha256(concatBytes(current, sibling))
        : await sha256(concatBytes(sibling, current));

    index = Math.floor(index / 2);
  }

  const computedRoot = base64UrlEncode(current);
  if (computedRoot !== p.root_hash_b64u) {
    return {
      valid: false,
      reason: 'Computed Merkle root does not match proof root',
      error: {
        code: 'INCLUSION_PROOF_INVALID',
        message: 'Merkle audit path does not resolve to root_hash_b64u',
      },
    };
  }

  return { valid: true, reason: 'Inclusion proof verified successfully' };
}
