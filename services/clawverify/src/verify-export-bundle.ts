/**
 * Export Bundle Verification
 * POHVN-US-007: Audit-ready export bundles (offline verifiability)
 */

import type {
  ExportBundlePayload,
  ExportBundleManifestEntry,
  VerifyExportBundleResponse,
  VerificationError,
} from './types';
import { isValidDidFormat, isValidIsoDate } from './schema-registry';
import {
  base64UrlDecode,
  base64UrlEncode,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto';
import { validateExportBundleV1 } from './schema-validation';
import { verifyProofBundle } from './verify-proof-bundle';
import { verifyExecutionAttestation } from './verify-execution-attestation';
import { verifyDerivationAttestation } from './verify-derivation-attestation';
import { verifyAuditResultAttestation } from './verify-audit-result-attestation';
import { jcsCanonicalize } from './jcs';

export interface VerifyExportBundleOptions {
  allowlistedReceiptSignerDids?: readonly string[];
  allowlistedAttesterDids?: readonly string[];
  allowlistedExecutionAttestationSignerDids?: readonly string[];
  allowlistedDerivationAttestationSignerDids?: readonly string[];
  allowlistedAuditResultAttestationSignerDids?: readonly string[];
}

function utf8Bytes(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

async function sha256B64u(input: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', input);
  return base64UrlEncode(new Uint8Array(digest));
}

function manifestPathFor(kind: string, index?: number): string {
  if (index === undefined) return `artifacts/${kind}.json`;
  return `artifacts/${kind}/${index}.json`;
}

async function manifestEntry(path: string, value: unknown): Promise<ExportBundleManifestEntry> {
  const canonical = jcsCanonicalize(value);
  const bytes = utf8Bytes(canonical);

  return {
    path,
    sha256_b64u: await sha256B64u(bytes),
    content_type: 'application/json',
    size_bytes: bytes.byteLength,
  };
}

async function computeExpectedManifestEntries(bundle: ExportBundlePayload): Promise<ExportBundleManifestEntry[]> {
  const entries: ExportBundleManifestEntry[] = [];

  entries.push(
    await manifestEntry(
      manifestPathFor('proof_bundle_envelope'),
      bundle.artifacts.proof_bundle_envelope,
    ),
  );

  const execution = bundle.artifacts.execution_attestation_envelopes ?? [];
  for (let i = 0; i < execution.length; i++) {
    entries.push(await manifestEntry(manifestPathFor('execution_attestation_envelopes', i), execution[i]));
  }

  const derivation = bundle.artifacts.derivation_attestation_envelopes ?? [];
  for (let i = 0; i < derivation.length; i++) {
    entries.push(await manifestEntry(manifestPathFor('derivation_attestation_envelopes', i), derivation[i]));
  }

  const audit = bundle.artifacts.audit_result_attestation_envelopes ?? [];
  for (let i = 0; i < audit.length; i++) {
    entries.push(await manifestEntry(manifestPathFor('audit_result_attestation_envelopes', i), audit[i]));
  }

  return entries.sort((a, b) => a.path.localeCompare(b.path));
}

function normalizeManifestEntries(entries: ExportBundleManifestEntry[]): ExportBundleManifestEntry[] {
  return [...entries].sort((a, b) => a.path.localeCompare(b.path));
}

function firstRunIdFromProofBundle(bundle: ExportBundlePayload): string | null {
  const events = bundle.artifacts.proof_bundle_envelope?.payload?.event_chain;
  if (!Array.isArray(events) || events.length === 0) return null;

  const runId = events[0]?.run_id;
  return typeof runId === 'string' && runId.length > 0 ? runId : null;
}

function signableBundleView(bundle: ExportBundlePayload): Record<string, unknown> {
  const out: Record<string, unknown> = {
    export_version: bundle.export_version,
    export_id: bundle.export_id,
    created_at: bundle.created_at,
    issuer_did: bundle.issuer_did,
    manifest: bundle.manifest,
    artifacts: bundle.artifacts,
    issued_at: bundle.issued_at,
  };

  if (bundle.metadata !== undefined) {
    out.metadata = bundle.metadata;
  }

  return out;
}

function invalid(
  now: string,
  reason: string,
  error: VerificationError,
  extras: Partial<VerifyExportBundleResponse> = {},
): VerifyExportBundleResponse {
  return {
    result: {
      status: 'INVALID',
      reason,
      envelope_type: 'export_bundle',
      verified_at: now,
    },
    error,
    ...extras,
  };
}

function valid(
  now: string,
  bundle: ExportBundlePayload,
  extras: Partial<VerifyExportBundleResponse> = {},
): VerifyExportBundleResponse {
  return {
    result: {
      status: 'VALID',
      reason: 'Export bundle verified successfully',
      envelope_type: 'export_bundle',
      signer_did: bundle.issuer_did,
      verified_at: now,
    },
    export_id: bundle.export_id,
    bundle_hash_b64u: bundle.bundle_hash_b64u,
    ...extras,
  };
}

export async function verifyExportBundle(
  bundleInput: unknown,
  options: VerifyExportBundleOptions = {},
): Promise<VerifyExportBundleResponse> {
  const now = new Date().toISOString();

  const schemaResult = validateExportBundleV1(bundleInput);
  if (!schemaResult.valid) {
    return invalid(now, schemaResult.message, {
      code: 'SCHEMA_VALIDATION_FAILED',
      message: schemaResult.message,
      field: schemaResult.field,
    });
  }

  const bundle = bundleInput as ExportBundlePayload;

  if (!isValidDidFormat(bundle.issuer_did)) {
    return invalid(now, 'Invalid issuer DID format', {
      code: 'INVALID_DID_FORMAT',
      message: 'issuer_did must be a valid DID string',
      field: 'issuer_did',
    });
  }

  if (!isValidIsoDate(bundle.created_at) || !isValidIsoDate(bundle.issued_at)) {
    return invalid(now, 'Invalid date fields', {
      code: 'MALFORMED_ENVELOPE',
      message: 'created_at and issued_at must be valid ISO 8601 strings',
      field: !isValidIsoDate(bundle.created_at) ? 'created_at' : 'issued_at',
    });
  }

  // 1) Verify manifest hashes/content-addressing against included artifacts.
  const providedEntries = normalizeManifestEntries(bundle.manifest.entries);
  const expectedEntries = await computeExpectedManifestEntries(bundle);

  const pathSet = new Set<string>();
  for (const e of providedEntries) {
    if (pathSet.has(e.path)) {
      return invalid(now, 'Manifest contains duplicate path entries', {
        code: 'MALFORMED_ENVELOPE',
        message: `Duplicate manifest path: ${e.path}`,
        field: 'manifest.entries.path',
      });
    }
    pathSet.add(e.path);
  }

  if (providedEntries.length !== expectedEntries.length) {
    return invalid(now, 'Manifest entry count mismatch', {
      code: 'MISSING_REQUIRED_FIELD',
      message: `manifest.entries count (${providedEntries.length}) does not match expected artifact count (${expectedEntries.length})`,
      field: 'manifest.entries',
    });
  }

  const providedMap = new Map(providedEntries.map((e) => [e.path, e]));
  for (const expected of expectedEntries) {
    const actual = providedMap.get(expected.path);
    if (!actual) {
      return invalid(now, 'Manifest missing expected artifact path', {
        code: 'MISSING_REQUIRED_FIELD',
        message: `manifest is missing expected path ${expected.path}`,
        field: 'manifest.entries.path',
      });
    }

    if (actual.sha256_b64u !== expected.sha256_b64u) {
      return invalid(now, 'Manifest hash mismatch', {
        code: 'HASH_MISMATCH',
        message: `manifest hash mismatch for ${expected.path}`,
        field: `manifest.entries[${expected.path}].sha256_b64u`,
      });
    }

    if (actual.content_type !== expected.content_type) {
      return invalid(now, 'Manifest content type mismatch', {
        code: 'MALFORMED_ENVELOPE',
        message: `manifest content_type mismatch for ${expected.path}`,
        field: `manifest.entries[${expected.path}].content_type`,
      });
    }

    if (actual.size_bytes !== expected.size_bytes) {
      return invalid(now, 'Manifest size mismatch', {
        code: 'HASH_MISMATCH',
        message: `manifest size_bytes mismatch for ${expected.path}`,
        field: `manifest.entries[${expected.path}].size_bytes`,
      });
    }
  }

  // 2) Verify export bundle hash + signature.
  const computedBundleHash = await sha256B64u(utf8Bytes(jcsCanonicalize(signableBundleView(bundle))));
  if (computedBundleHash !== bundle.bundle_hash_b64u) {
    return invalid(now, 'Export bundle hash mismatch', {
      code: 'HASH_MISMATCH',
      message: 'Computed bundle hash does not match bundle_hash_b64u',
      field: 'bundle_hash_b64u',
    });
  }

  const exportPublicKey = extractPublicKeyFromDidKey(bundle.issuer_did);
  if (!exportPublicKey) {
    return invalid(now, 'Could not extract public key from issuer DID', {
      code: 'INVALID_DID_FORMAT',
      message: 'issuer_did must be did:key with Ed25519 multicodec key',
      field: 'issuer_did',
    });
  }

  let bundleSigBytes: Uint8Array;
  try {
    bundleSigBytes = base64UrlDecode(bundle.signature_b64u);
  } catch {
    return invalid(now, 'Invalid export bundle signature encoding', {
      code: 'MALFORMED_ENVELOPE',
      message: 'signature_b64u is not valid base64url',
      field: 'signature_b64u',
    });
  }

  const bundleSigOk = await verifySignature(
    'Ed25519',
    exportPublicKey,
    bundleSigBytes,
    utf8Bytes(bundle.bundle_hash_b64u),
  );

  if (!bundleSigOk) {
    return invalid(now, 'Export bundle signature verification failed', {
      code: 'SIGNATURE_INVALID',
      message: 'signature_b64u does not verify bundle_hash_b64u using issuer_did key',
      field: 'signature_b64u',
    });
  }

  // 3) Verify included envelopes with existing verifiers (offline, no network calls).
  const proofBundleOut = await verifyProofBundle(bundle.artifacts.proof_bundle_envelope, {
    allowlistedReceiptSignerDids: options.allowlistedReceiptSignerDids,
    allowlistedAttesterDids: options.allowlistedAttesterDids,
  });

  if (proofBundleOut.result.status !== 'VALID') {
    return invalid(
      now,
      `Proof bundle verification failed: ${proofBundleOut.result.reason}`,
      proofBundleOut.error ?? {
        code: 'MALFORMED_ENVELOPE',
        message: 'proof_bundle_envelope failed verification',
        field: 'artifacts.proof_bundle_envelope',
      },
      {
        export_id: bundle.export_id,
        bundle_hash_b64u: bundle.bundle_hash_b64u,
      },
    );
  }

  const expectedProofBundleHash = bundle.artifacts.proof_bundle_envelope.payload_hash_b64u;
  const expectedRunId = firstRunIdFromProofBundle(bundle);
  const expectedAgentDid = bundle.artifacts.proof_bundle_envelope.payload.agent_did;

  const execution = bundle.artifacts.execution_attestation_envelopes ?? [];
  for (let i = 0; i < execution.length; i++) {
    const out = await verifyExecutionAttestation(execution[i], {
      allowlistedSignerDids: options.allowlistedExecutionAttestationSignerDids,
    });

    if (out.result.status !== 'VALID') {
      return invalid(
        now,
        `Execution attestation verification failed (index ${i})`,
        out.error ?? {
          code: 'MALFORMED_ENVELOPE',
          message: 'execution_attestation_envelope failed verification',
          field: `artifacts.execution_attestation_envelopes[${i}]`,
        },
      );
    }

    if (out.proof_bundle_hash_b64u !== expectedProofBundleHash) {
      return invalid(now, 'Execution attestation proof bundle hash mismatch', {
        code: 'HASH_MISMATCH',
        message: `execution_attestation proof_bundle_hash_b64u mismatch at index ${i}`,
        field: `artifacts.execution_attestation_envelopes[${i}].payload.proof_bundle_hash_b64u`,
      });
    }

    if (expectedRunId && out.run_id !== expectedRunId) {
      return invalid(now, 'Execution attestation run_id mismatch', {
        code: 'HASH_MISMATCH',
        message: `execution_attestation run_id mismatch at index ${i}`,
        field: `artifacts.execution_attestation_envelopes[${i}].payload.run_id`,
      });
    }

    if (out.agent_did !== expectedAgentDid) {
      return invalid(now, 'Execution attestation agent_did mismatch', {
        code: 'HASH_MISMATCH',
        message: `execution_attestation agent_did mismatch at index ${i}`,
        field: `artifacts.execution_attestation_envelopes[${i}].payload.agent_did`,
      });
    }
  }

  const derivations = bundle.artifacts.derivation_attestation_envelopes ?? [];
  for (let i = 0; i < derivations.length; i++) {
    const out = await verifyDerivationAttestation(derivations[i], {
      allowlistedSignerDids: options.allowlistedDerivationAttestationSignerDids,
    });

    if (out.result.status !== 'VALID') {
      return invalid(
        now,
        `Derivation attestation verification failed (index ${i})`,
        out.error ?? {
          code: 'MALFORMED_ENVELOPE',
          message: 'derivation_attestation_envelope failed verification',
          field: `artifacts.derivation_attestation_envelopes[${i}]`,
        },
      );
    }
  }

  const audits = bundle.artifacts.audit_result_attestation_envelopes ?? [];
  for (let i = 0; i < audits.length; i++) {
    const out = await verifyAuditResultAttestation(audits[i], {
      allowlistedSignerDids: options.allowlistedAuditResultAttestationSignerDids,
    });

    if (out.result.status !== 'VALID') {
      return invalid(
        now,
        `Audit-result attestation verification failed (index ${i})`,
        out.error ?? {
          code: 'MALFORMED_ENVELOPE',
          message: 'audit_result_attestation_envelope failed verification',
          field: `artifacts.audit_result_attestation_envelopes[${i}]`,
        },
      );
    }
  }

  return valid(now, bundle, {
    manifest_entries_verified: expectedEntries.length,
    verified_components: {
      proof_bundle_valid: true,
      execution_attestations_verified: execution.length,
      derivation_attestations_verified: derivations.length,
      audit_result_attestations_verified: audits.length,
    },
    proof_tier: proofBundleOut.result.proof_tier,
    model_identity_tier: proofBundleOut.result.model_identity_tier,
  });
}
