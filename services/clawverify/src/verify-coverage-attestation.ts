/**
 * Coverage Attestation Verification
 * CVF-US-057: Verify coverage_attestation envelopes for runtime binding.
 */

import type {
  SignedEnvelope,
  CoverageAttestationPayload,
  VerificationResult,
  VerificationError,
} from './types';
import {
  isAllowedVersion,
  isAllowedType,
  isAllowedAlgorithm,
  isAllowedHashAlgorithm,
  isValidDidFormat,
  isValidBase64Url,
  isValidIsoDate,
} from './schema-registry';
import {
  computeHash,
  base64UrlDecode,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto';
import { validateCoverageAttestationEnvelopeV1 } from './schema-validation';

export interface CoverageAttestationVerifierOptions {
  /**
   * Allowlisted signer DIDs (did:key:...).
   * Fail-closed: if empty or missing, coverage attestations are INVALID.
   */
  allowlistedSignerDids?: readonly string[];
}

function validateEnvelopeStructure(
  envelope: unknown,
): envelope is SignedEnvelope<CoverageAttestationPayload> {
  if (typeof envelope !== 'object' || envelope === null) return false;
  const e = envelope as Record<string, unknown>;

  return (
    'envelope_version' in e &&
    'envelope_type' in e &&
    'payload' in e &&
    'payload_hash_b64u' in e &&
    'hash_algorithm' in e &&
    'signature_b64u' in e &&
    'algorithm' in e &&
    'signer_did' in e &&
    'issued_at' in e
  );
}

function validatePayload(payload: unknown): payload is CoverageAttestationPayload {
  if (typeof payload !== 'object' || payload === null) return false;
  const p = payload as Record<string, unknown>;

  if (p.attestation_version !== '1') return false;
  if (typeof p.attestation_id !== 'string' || p.attestation_id.trim().length === 0) return false;
  if (typeof p.run_id !== 'string' || p.run_id.trim().length === 0) return false;
  if (!isValidDidFormat(p.agent_did)) return false;
  if (!isValidDidFormat(p.sentinel_did)) return false;
  if (!isValidIsoDate(p.issued_at)) return false;

  const binding = p.binding as Record<string, unknown> | undefined;
  if (!binding || typeof binding !== 'object') return false;

  const eventChainRoot = binding.event_chain_root_hash_b64u;
  if (
    typeof eventChainRoot !== 'string' ||
    eventChainRoot.trim().length < 8 ||
    !isValidBase64Url(eventChainRoot)
  ) {
    return false;
  }

  const metrics = p.metrics as Record<string, unknown> | undefined;
  if (!metrics || typeof metrics !== 'object') return false;

  const lineage = metrics.lineage as Record<string, unknown> | undefined;
  const egress = metrics.egress as Record<string, unknown> | undefined;
  const liveness = metrics.liveness as Record<string, unknown> | undefined;
  if (!lineage || !egress || !liveness) return false;

  const rootPid = lineage.root_pid;
  const tracked = lineage.processes_tracked;
  const unmonitored = lineage.unmonitored_spawns;
  if (
    typeof rootPid !== 'number' || !Number.isInteger(rootPid) || rootPid < 1 ||
    typeof tracked !== 'number' || !Number.isInteger(tracked) || tracked < 0 ||
    typeof unmonitored !== 'number' || !Number.isInteger(unmonitored) || unmonitored < 0 ||
    typeof lineage.escapes_suspected !== 'boolean'
  ) {
    return false;
  }

  const connectionsTotal = egress.connections_total;
  const unmediated = egress.unmediated_connections;
  if (
    typeof connectionsTotal !== 'number' || !Number.isInteger(connectionsTotal) || connectionsTotal < 0 ||
    typeof unmediated !== 'number' || !Number.isInteger(unmediated) || unmediated < 0
  ) {
    return false;
  }

  const livenessStatus = liveness.status;
  const uptimeMs = liveness.uptime_ms;
  const heartbeatIntervalMs = liveness.heartbeat_interval_ms;
  const maxGapMs = liveness.max_gap_ms;
  if (
    (livenessStatus !== 'continuous' && livenessStatus !== 'interrupted') ||
    typeof uptimeMs !== 'number' || !Number.isInteger(uptimeMs) || uptimeMs < 0 ||
    typeof heartbeatIntervalMs !== 'number' || !Number.isInteger(heartbeatIntervalMs) || heartbeatIntervalMs < 1 ||
    typeof maxGapMs !== 'number' || !Number.isInteger(maxGapMs) || maxGapMs < 0
  ) {
    return false;
  }

  return true;
}

export async function verifyCoverageAttestation(
  envelope: unknown,
  options: CoverageAttestationVerifierOptions = {},
): Promise<{
  result: VerificationResult;
  attestation_id?: string;
  run_id?: string;
  agent_did?: string;
  sentinel_did?: string;
  event_chain_root_hash_b64u?: string;
  metrics?: CoverageAttestationPayload['metrics'];
  signer_did?: string;
  allowlisted?: boolean;
  error?: VerificationError;
}> {
  const now = new Date().toISOString();

  if (!validateEnvelopeStructure(envelope)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Malformed envelope: missing required fields',
        verified_at: now,
      },
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'Envelope is missing required fields or has invalid structure',
      },
    };
  }

  if (!isAllowedVersion(envelope.envelope_version)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown envelope version: ${envelope.envelope_version}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_VERSION',
        message: `Envelope version "${envelope.envelope_version}" is not in the allowlist`,
        field: 'envelope_version',
      },
    };
  }

  if (!isAllowedType(envelope.envelope_type)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown envelope type: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: `Envelope type "${envelope.envelope_type}" is not in the allowlist`,
        field: 'envelope_type',
      },
    };
  }

  if (envelope.envelope_type !== 'coverage_attestation') {
    return {
      result: {
        status: 'INVALID',
        reason: `Expected coverage_attestation envelope, got: ${envelope.envelope_type}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ENVELOPE_TYPE',
        message: 'This verifier only accepts coverage_attestation envelopes',
        field: 'envelope_type',
      },
    };
  }

  if (!isAllowedAlgorithm(envelope.algorithm)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown signature algorithm: ${envelope.algorithm}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_ALGORITHM',
        message: `Signature algorithm "${envelope.algorithm}" is not in the allowlist`,
        field: 'algorithm',
      },
    };
  }

  if (!isAllowedHashAlgorithm(envelope.hash_algorithm)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Unknown hash algorithm: ${envelope.hash_algorithm}`,
        verified_at: now,
      },
      error: {
        code: 'UNKNOWN_HASH_ALGORITHM',
        message: `Hash algorithm "${envelope.hash_algorithm}" is not in the allowlist`,
        field: 'hash_algorithm',
      },
    };
  }

  const schemaResult = validateCoverageAttestationEnvelopeV1(envelope);
  if (!schemaResult.valid) {
    return {
      result: {
        status: 'INVALID',
        reason: schemaResult.message,
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      error: {
        code: 'SCHEMA_VALIDATION_FAILED',
        message: schemaResult.message,
        field: schemaResult.field,
      },
    };
  }

  if (!isValidDidFormat(envelope.signer_did)) {
    return {
      result: {
        status: 'INVALID',
        reason: `Invalid DID format: ${envelope.signer_did}`,
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      error: {
        code: 'INVALID_DID_FORMAT',
        message: 'Signer DID does not match expected format (did:key:... or did:web:...)',
        field: 'signer_did',
      },
    };
  }

  if (!options.allowlistedSignerDids || options.allowlistedSignerDids.length === 0) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Coverage attestation signer allowlist not configured',
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted: false,
      error: {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message:
          'Coverage attestation signer allowlist is not configured. Set COVERAGE_ATTESTATION_SIGNER_DIDS to enable verification.',
        field: 'env.COVERAGE_ATTESTATION_SIGNER_DIDS',
      },
    };
  }

  const allowlisted = options.allowlistedSignerDids.includes(envelope.signer_did);
  if (!allowlisted) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Coverage attestation signer DID is not allowlisted',
        envelope_type: envelope.envelope_type,
        signer_did: envelope.signer_did,
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'CLAIM_NOT_FOUND',
        message: `Signer DID '${envelope.signer_did}' is not in the allowlisted coverage attestation signer list`,
        field: 'signer_did',
      },
    };
  }

  if (!isValidIsoDate(envelope.issued_at)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid issued_at date format',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'issued_at must be a valid ISO 8601 date string',
        field: 'issued_at',
      },
    };
  }

  if (
    !isValidBase64Url(envelope.payload_hash_b64u) ||
    envelope.payload_hash_b64u.length < 8
  ) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid payload_hash_b64u format',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'payload_hash_b64u must be base64url and at least 8 chars',
        field: 'payload_hash_b64u',
      },
    };
  }

  if (
    !isValidBase64Url(envelope.signature_b64u) ||
    envelope.signature_b64u.length < 8
  ) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid signature_b64u format',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'MALFORMED_ENVELOPE',
        message: 'signature_b64u must be base64url and at least 8 chars',
        field: 'signature_b64u',
      },
    };
  }

  if (!validatePayload(envelope.payload)) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Invalid coverage attestation payload fields',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'MALFORMED_ENVELOPE',
        message:
          'Coverage attestation payload is malformed or missing required semantic fields',
        field: 'payload',
      },
    };
  }

  let computedHash: string;
  try {
    computedHash = await computeHash(envelope.payload, envelope.hash_algorithm);
  } catch (err) {
    return {
      result: {
        status: 'INVALID',
        reason: `Hash computation failed: ${err instanceof Error ? err.message : 'unknown error'}`,
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'HASH_MISMATCH',
        message: 'Failed to recompute payload hash',
      },
    };
  }

  if (computedHash !== envelope.payload_hash_b64u) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Payload hash mismatch',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'HASH_MISMATCH',
        message: 'Computed payload hash does not match envelope payload_hash_b64u',
        field: 'payload_hash_b64u',
      },
    };
  }

  const publicKeyBytes = extractPublicKeyFromDidKey(envelope.signer_did);
  if (!publicKeyBytes) {
    return {
      result: {
        status: 'INVALID',
        reason: `Could not extract public key from DID: ${envelope.signer_did}`,
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'INVALID_DID_FORMAT',
        message:
          'Unable to extract Ed25519 public key from did:key. Ensure the DID uses the Ed25519 multicodec prefix.',
        field: 'signer_did',
      },
    };
  }

  let signatureValid = false;
  try {
    const signatureBytes = base64UrlDecode(envelope.signature_b64u);
    const messageBytes = new TextEncoder().encode(envelope.payload_hash_b64u);

    signatureValid = await verifySignature(
      envelope.algorithm,
      publicKeyBytes,
      signatureBytes,
      messageBytes,
    );
  } catch (err) {
    return {
      result: {
        status: 'INVALID',
        reason: `Signature verification error: ${err instanceof Error ? err.message : 'unknown error'}`,
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'Failed to verify signature',
      },
    };
  }

  if (!signatureValid) {
    return {
      result: {
        status: 'INVALID',
        reason: 'Signature verification failed',
        verified_at: now,
      },
      signer_did: envelope.signer_did,
      allowlisted,
      error: {
        code: 'SIGNATURE_INVALID',
        message: 'The Ed25519 signature does not match the payload hash',
      },
    };
  }

  return {
    result: {
      status: 'VALID',
      reason: 'Coverage attestation verified successfully',
      envelope_type: envelope.envelope_type,
      signer_did: envelope.signer_did,
      verified_at: now,
    },
    attestation_id: envelope.payload.attestation_id,
    run_id: envelope.payload.run_id,
    agent_did: envelope.payload.agent_did,
    sentinel_did: envelope.payload.sentinel_did,
    event_chain_root_hash_b64u: envelope.payload.binding.event_chain_root_hash_b64u,
    metrics: envelope.payload.metrics,
    signer_did: envelope.signer_did,
    allowlisted,
  };
}
