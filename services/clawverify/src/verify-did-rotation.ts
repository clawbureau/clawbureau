/**
 * DID Rotation Certificate Verification
 *
 * Verifies a rotation certificate signed by both the old and new did:key.
 *
 * Signing rule:
 * - Canonicalize the certificate via RFC 8785 JCS with both signature fields set
 *   to the empty string.
 * - Both old and new keys must sign the canonical UTF-8 bytes.
 */

import type {
  DidRotationCertificate,
  VerificationError,
  VerificationResult,
} from './types';
import { isValidBase64Url, isValidIsoDate } from './schema-registry';
import {
  base64UrlDecode,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto';
import { jcsCanonicalize } from './jcs';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function validateNoUnknownKeys(
  obj: Record<string, unknown>,
  allowedKeys: readonly string[]
): boolean {
  const allowed = new Set(allowedKeys);
  return Object.keys(obj).every((k) => allowed.has(k));
}

function validateDidRotationCertificate(
  certificate: unknown
): certificate is DidRotationCertificate {
  if (!isPlainObject(certificate)) return false;

  const allowedKeys = [
    'rotation_version',
    'rotation_id',
    'old_did',
    'new_did',
    'issued_at',
    'reason',
    'signature_old_b64u',
    'signature_new_b64u',
    'metadata',
  ] as const;

  if (!validateNoUnknownKeys(certificate, allowedKeys)) return false;

  if (certificate.rotation_version !== '1') return false;
  if (!isNonEmptyString(certificate.rotation_id)) return false;
  if (!isNonEmptyString(certificate.old_did)) return false;
  if (!isNonEmptyString(certificate.new_did)) return false;
  if (!isValidIsoDate(certificate.issued_at)) return false;
  if (!isNonEmptyString(certificate.reason)) return false;
  if (!isValidBase64Url(certificate.signature_old_b64u)) return false;
  if (!isValidBase64Url(certificate.signature_new_b64u)) return false;

  if ('metadata' in certificate) {
    if (certificate.metadata !== undefined && !isPlainObject(certificate.metadata)) {
      return false;
    }
  }

  return true;
}

export async function verifyDidRotation(
  certificate: unknown
): Promise<{
  result: VerificationResult;
  rotation_id?: string;
  old_did?: string;
  new_did?: string;
  issued_at?: string;
  reason?: string;
  error?: VerificationError;
}> {
  const now = new Date().toISOString();

  // 1) Structural validation (fail-closed)
  if (!validateDidRotationCertificate(certificate)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Malformed did_rotation certificate: missing required fields or invalid structure',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message:
          'Certificate must match did_rotation.v1 shape (rotation_version=1, required fields present, no unknown fields).',
      },
    };
  }

  // 2) Semantic checks
  if (certificate.old_did === certificate.new_did) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Rotation must change DID: old_did and new_did are identical',
        verified_at: now,
      },
      rotation_id: certificate.rotation_id,
      old_did: certificate.old_did,
      new_did: certificate.new_did,
      issued_at: certificate.issued_at,
      reason: certificate.reason,
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'old_did and new_did must be different',
        field: 'new_did',
      },
    };
  }

  // 3) Extract public keys (did:key only)
  const oldPub = extractPublicKeyFromDidKey(certificate.old_did);
  if (!oldPub) {
    return {
      result: {
        status: 'INVALID',
        reason: `Invalid old_did format (expected did:key with Ed25519 multicodec prefix): ${certificate.old_did}`,
        verified_at: now,
      },
      rotation_id: certificate.rotation_id,
      old_did: certificate.old_did,
      new_did: certificate.new_did,
      issued_at: certificate.issued_at,
      reason: certificate.reason,
      error: {
        code: 'INVALID_DID_FORMAT',
        message:
          'old_did must be a did:key that encodes an Ed25519 public key (multicodec 0xed01).',
        field: 'old_did',
      },
    };
  }

  const newPub = extractPublicKeyFromDidKey(certificate.new_did);
  if (!newPub) {
    return {
      result: {
        status: 'INVALID',
        reason: `Invalid new_did format (expected did:key with Ed25519 multicodec prefix): ${certificate.new_did}`,
        verified_at: now,
      },
      rotation_id: certificate.rotation_id,
      old_did: certificate.old_did,
      new_did: certificate.new_did,
      issued_at: certificate.issued_at,
      reason: certificate.reason,
      error: {
        code: 'INVALID_DID_FORMAT',
        message:
          'new_did must be a did:key that encodes an Ed25519 public key (multicodec 0xed01).',
        field: 'new_did',
      },
    };
  }

  // 4) Canonicalize with signatures blanked
  let canonical: string;
  try {
    const canonicalObject: DidRotationCertificate = {
      ...certificate,
      signature_old_b64u: '',
      signature_new_b64u: '',
    };

    canonical = jcsCanonicalize(canonicalObject);
  } catch (err) {
    return {
      result: {
        status: 'INVALID',
        reason: `Canonicalization failed: ${err instanceof Error ? err.message : 'unknown error'}`,
        verified_at: now,
      },
      rotation_id: certificate.rotation_id,
      old_did: certificate.old_did,
      new_did: certificate.new_did,
      issued_at: certificate.issued_at,
      reason: certificate.reason,
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'Failed to canonicalize certificate via JCS',
      },
    };
  }

  const messageBytes = new TextEncoder().encode(canonical);

  // 5) Verify both signatures
  try {
    const sigOld = base64UrlDecode(certificate.signature_old_b64u);
    const sigNew = base64UrlDecode(certificate.signature_new_b64u);

    if (sigOld.length !== 64) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Invalid signature_old_b64u length (expected 64 bytes for Ed25519)',
          verified_at: now,
        },
        rotation_id: certificate.rotation_id,
        old_did: certificate.old_did,
        new_did: certificate.new_did,
        issued_at: certificate.issued_at,
        reason: certificate.reason,
        error: {
          code: 'SIGNATURE_INVALID',
          message: 'Ed25519 signatures must be 64 bytes',
          field: 'signature_old_b64u',
        },
      };
    }

    if (sigNew.length !== 64) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Invalid signature_new_b64u length (expected 64 bytes for Ed25519)',
          verified_at: now,
        },
        rotation_id: certificate.rotation_id,
        old_did: certificate.old_did,
        new_did: certificate.new_did,
        issued_at: certificate.issued_at,
        reason: certificate.reason,
        error: {
          code: 'SIGNATURE_INVALID',
          message: 'Ed25519 signatures must be 64 bytes',
          field: 'signature_new_b64u',
        },
      };
    }

    const okOld = await verifySignature('Ed25519', oldPub, sigOld, messageBytes);
    const okNew = await verifySignature('Ed25519', newPub, sigNew, messageBytes);

    if (!okOld || !okNew) {
      return {
        result: {
          status: 'INVALID',
          reason: 'Rotation certificate signature verification failed',
          verified_at: now,
        },
        rotation_id: certificate.rotation_id,
        old_did: certificate.old_did,
        new_did: certificate.new_did,
        issued_at: certificate.issued_at,
        reason: certificate.reason,
        error: {
          code: 'SIGNATURE_INVALID',
          message: 'Either old signature or new signature did not verify',
        },
      };
    }
  } catch (err) {
    return {
      result: {
        status: 'INVALID',
        reason: `Signature verification error: ${err instanceof Error ? err.message : 'unknown error'}`,
        verified_at: now,
      },
      rotation_id: certificate.rotation_id,
      old_did: certificate.old_did,
      new_did: certificate.new_did,
      issued_at: certificate.issued_at,
      reason: certificate.reason,
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'Failed to decode or verify one of the signatures',
      },
    };
  }

  // 6) Valid
  return {
    result: {
      status: 'VALID',
      reason: 'DID rotation certificate verified successfully',
      verified_at: now,
    },
    rotation_id: certificate.rotation_id,
    old_did: certificate.old_did,
    new_did: certificate.new_did,
    issued_at: certificate.issued_at,
    reason: certificate.reason,
  };
}
