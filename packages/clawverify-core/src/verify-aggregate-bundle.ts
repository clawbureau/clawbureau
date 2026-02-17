/**
 * Aggregate Bundle Verification (R49)
 *
 * Deterministic, fail-closed verifier for aggregate_bundle_envelope.v1.
 */

import type {
  AggregateBundleEnvelope,
  AggregateBundleMember,
  ExportBundleManifestEntry,
  ExportBundlePayload,
  ModelIdentityTier,
  ProofBundlePayload,
  ProofTier,
  RateLimitClaim,
  SignedEnvelope,
  VerificationError,
  VerifyAggregateBundleResponse,
} from './types.js';
import { isValidDidFormat, isValidIsoDate } from './schema-registry.js';
import {
  base64UrlDecode,
  base64UrlEncode,
  computeHash,
  extractPublicKeyFromDidKey,
  verifySignature,
} from './crypto.js';
import { jcsCanonicalize } from './jcs.js';
import { validateAggregateBundleEnvelopeV1 } from './schema-validation.js';
import { verifyProofBundle } from './verify-proof-bundle.js';
import { verifyExportBundle } from './verify-export-bundle.js';

export interface VerifyAggregateBundleOptions {
  allowlistedReceiptSignerDids?: readonly string[];
  allowlistedAttesterDids?: readonly string[];
  allowlistedExecutionAttestationSignerDids?: readonly string[];
  allowlistedDerivationAttestationSignerDids?: readonly string[];
  allowlistedAuditResultAttestationSignerDids?: readonly string[];
  /** Deterministic verification-time override (ISO-8601). */
  verifyAt?: string;
  /** Temporal skew allowance in ms. Default: 300000 (5 minutes). */
  ttlSkewMs?: number;
}

const DEFAULT_TTL_SKEW_MS = 300_000;

const PROOF_TIER_RANK: Record<ProofTier, number> = {
  unknown: 0,
  self: 1,
  gateway: 2,
  sandbox: 3,
  tee: 4,
  witnessed_web: 5,
};

const MODEL_TIER_RANK: Record<ModelIdentityTier, number> = {
  unknown: 0,
  closed_opaque: 1,
  closed_provider_manifest: 2,
  openweights_hashable: 3,
  tee_measured: 4,
};

function utf8Bytes(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

async function sha256B64u(input: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    input.buffer.slice(
      input.byteOffset,
      input.byteOffset + input.byteLength
    ) as ArrayBuffer
  );
  return base64UrlEncode(new Uint8Array(digest));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function manifestPathForMember(index: number): string {
  return `artifacts/member_bundles/${index}.json`;
}

async function manifestEntryForMember(
  index: number,
  value: unknown
): Promise<ExportBundleManifestEntry> {
  const canonical = jcsCanonicalize(value);
  const bytes = utf8Bytes(canonical);
  return {
    path: manifestPathForMember(index),
    sha256_b64u: await sha256B64u(bytes),
    content_type: 'application/json',
    size_bytes: bytes.byteLength,
  };
}

function normalizeManifestEntries(
  entries: ExportBundleManifestEntry[]
): ExportBundleManifestEntry[] {
  return [...entries].sort((a, b) => a.path.localeCompare(b.path));
}

function invalid(
  now: string,
  reason: string,
  error: VerificationError,
  extras: Partial<VerifyAggregateBundleResponse> = {}
): VerifyAggregateBundleResponse {
  return {
    result: {
      status: 'INVALID',
      reason,
      envelope_type: 'aggregate_bundle',
      verified_at: now,
    },
    error,
    ...extras,
  };
}

function valid(
  now: string,
  envelope: AggregateBundleEnvelope,
  extras: Partial<VerifyAggregateBundleResponse> = {}
): VerifyAggregateBundleResponse {
  return {
    result: {
      status: 'VALID',
      reason: 'Aggregate bundle verified successfully',
      envelope_type: 'aggregate_bundle',
      signer_did: envelope.signer_did,
      verified_at: now,
    },
    aggregate_id: envelope.payload.aggregate_id,
    signer_did: envelope.signer_did,
    ...extras,
  };
}

function resolveVerificationTime(
  now: string,
  verifyAt?: string
):
  | { ok: true; verifyAtIso: string; verifyAtMs: number }
  | { ok: false; message: string } {
  const verifyAtIso = verifyAt ?? now;
  if (!isValidIsoDate(verifyAtIso)) {
    return {
      ok: false,
      message: 'verifyAt must be a valid ISO-8601 date-time string',
    };
  }

  return {
    ok: true,
    verifyAtIso,
    verifyAtMs: Date.parse(verifyAtIso),
  };
}

function proofTierMin(a: ProofTier, b: ProofTier): ProofTier {
  return PROOF_TIER_RANK[a] <= PROOF_TIER_RANK[b] ? a : b;
}

function modelTierMin(a: ModelIdentityTier, b: ModelIdentityTier): ModelIdentityTier {
  return MODEL_TIER_RANK[a] <= MODEL_TIER_RANK[b] ? a : b;
}

function isProofBundleMember(
  member: AggregateBundleMember
): member is SignedEnvelope<ProofBundlePayload> {
  return isRecord(member) && member.envelope_type === 'proof_bundle';
}

function isExportBundleMember(
  member: AggregateBundleMember
): member is ExportBundlePayload {
  return isRecord(member) && member.export_version === '1';
}

function extractRunIdFromProofEnvelope(
  proofEnvelope: SignedEnvelope<ProofBundlePayload>
): { ok: true; runId: string } | { ok: false; reason: string } {
  const events = proofEnvelope.payload.event_chain;
  if (!Array.isArray(events) || events.length === 0) {
    return {
      ok: false,
      reason: 'proof bundle member must contain a non-empty event_chain',
    };
  }

  let expectedRunId: string | null = null;
  for (let i = 0; i < events.length; i++) {
    const runId = events[i]?.run_id;
    if (typeof runId !== 'string' || runId.length === 0) {
      return {
        ok: false,
        reason: `event_chain[${i}].run_id must be a non-empty string`,
      };
    }

    if (expectedRunId === null) {
      expectedRunId = runId;
    } else if (runId !== expectedRunId) {
      return {
        ok: false,
        reason: `event_chain[${i}].run_id is inconsistent within member`,
      };
    }
  }

  if (expectedRunId === null) {
    return {
      ok: false,
      reason: 'proof bundle member is missing run_id evidence',
    };
  }

  return { ok: true, runId: expectedRunId };
}

function parseExpiresAtMs(
  value: unknown
): { ok: true; ms: number | null } | { ok: false } {
  if (value === undefined) return { ok: true, ms: null };
  if (typeof value !== 'string' || !isValidIsoDate(value)) return { ok: false };
  return { ok: true, ms: Date.parse(value) };
}

function rateClaimKey(agentDid: string, claim: RateLimitClaim): string {
  return [
    agentDid,
    claim.scope,
    claim.scope_key,
    claim.window_start,
    claim.window_end,
  ].join('|');
}

function optionalLimitEqual(
  a: number | undefined,
  b: number | undefined
): boolean {
  return a === b;
}

export async function verifyAggregateBundle(
  envelopeInput: unknown,
  options: VerifyAggregateBundleOptions = {}
): Promise<VerifyAggregateBundleResponse> {
  const now = new Date().toISOString();

  const schemaResult = validateAggregateBundleEnvelopeV1(envelopeInput);
  if (!schemaResult.valid) {
    return invalid(now, schemaResult.message, {
      code: 'SCHEMA_VALIDATION_FAILED',
      message: schemaResult.message,
      field: schemaResult.field,
    });
  }

  const envelope = envelopeInput as AggregateBundleEnvelope;
  const payload = envelope.payload;

  const verifyTime = resolveVerificationTime(now, options.verifyAt);
  if (!verifyTime.ok) {
    return invalid(now, verifyTime.message, {
      code: 'MALFORMED_ENVELOPE',
      message: verifyTime.message,
      field: 'verifyAt',
    });
  }

  const ttlSkewMs = Number.isFinite(options.ttlSkewMs)
    ? Math.max(0, Math.trunc(options.ttlSkewMs as number))
    : DEFAULT_TTL_SKEW_MS;

  if (!isValidDidFormat(envelope.signer_did) || !isValidDidFormat(payload.issuer_did)) {
    return invalid(now, 'Invalid signer or issuer DID format', {
      code: 'INVALID_DID_FORMAT',
      message: 'signer_did and payload.issuer_did must be valid DIDs',
      field: !isValidDidFormat(envelope.signer_did)
        ? 'signer_did'
        : 'payload.issuer_did',
    });
  }

  if (envelope.signer_did !== payload.issuer_did) {
    return invalid(now, 'Aggregate signer does not match payload issuer', {
      code: 'AGGREGATE_SIGNER_MISMATCH',
      message: 'envelope.signer_did must equal payload.issuer_did',
      field: 'signer_did',
    });
  }

  if (!isValidIsoDate(payload.created_at) || !isValidIsoDate(envelope.issued_at)) {
    return invalid(now, 'Invalid created_at or issued_at timestamp', {
      code: 'MALFORMED_ENVELOPE',
      message: 'payload.created_at and envelope.issued_at must be valid ISO-8601 date-time strings',
      field: !isValidIsoDate(payload.created_at)
        ? 'payload.created_at'
        : 'issued_at',
    });
  }

  const payloadExpires = parseExpiresAtMs(payload.expires_at);
  const envelopeExpires = parseExpiresAtMs(envelope.expires_at);
  if (!payloadExpires.ok || !envelopeExpires.ok) {
    return invalid(now, 'Invalid expires_at timestamp', {
      code: 'MALFORMED_ENVELOPE',
      message: 'expires_at must be valid ISO-8601 date-time when provided',
      field: !payloadExpires.ok ? 'payload.expires_at' : 'expires_at',
    });
  }

  const createdAtMs = Date.parse(payload.created_at);
  const issuedAtMs = Date.parse(envelope.issued_at);

  if (createdAtMs > issuedAtMs) {
    return invalid(now, 'Aggregate clock causality violated', {
      code: 'CAUSAL_CLOCK_CONTRADICTION',
      message: 'payload.created_at must be less than or equal to envelope.issued_at',
      field: 'payload.created_at',
    });
  }

  if (issuedAtMs > verifyTime.verifyAtMs + ttlSkewMs) {
    return invalid(now, 'Aggregate issued_at is in the future beyond skew allowance', {
      code: 'FUTURE_TIMESTAMP_POISONING',
      message: 'envelope.issued_at exceeds verifyAt + ttlSkewMs',
      field: 'issued_at',
    });
  }

  if (
    payloadExpires.ms !== null &&
    verifyTime.verifyAtMs > payloadExpires.ms + ttlSkewMs
  ) {
    return invalid(now, 'Aggregate payload has expired', {
      code: 'EXPIRED_TTL',
      message: 'payload.expires_at is in the past for verifyAt',
      field: 'payload.expires_at',
    });
  }

  if (
    envelopeExpires.ms !== null &&
    verifyTime.verifyAtMs > envelopeExpires.ms + ttlSkewMs
  ) {
    return invalid(now, 'Aggregate envelope has expired', {
      code: 'EXPIRED_TTL',
      message: 'envelope.expires_at is in the past for verifyAt',
      field: 'expires_at',
    });
  }

  let computedPayloadHash: string;
  try {
    computedPayloadHash = await computeHash(payload, envelope.hash_algorithm);
  } catch {
    return invalid(now, 'Unknown aggregate hash algorithm', {
      code: 'UNKNOWN_HASH_ALGORITHM',
      message: `Unsupported hash algorithm: ${envelope.hash_algorithm}`,
      field: 'hash_algorithm',
    });
  }

  if (computedPayloadHash !== envelope.payload_hash_b64u) {
    return invalid(now, 'Aggregate payload hash mismatch', {
      code: 'HASH_MISMATCH',
      message: 'Computed payload hash does not match payload_hash_b64u',
      field: 'payload_hash_b64u',
    });
  }

  const signerPublicKey = extractPublicKeyFromDidKey(envelope.signer_did);
  if (!signerPublicKey) {
    return invalid(now, 'Could not extract signer key from DID', {
      code: 'INVALID_DID_FORMAT',
      message: 'signer_did must be a did:key Ed25519 DID',
      field: 'signer_did',
    });
  }

  let signatureBytes: Uint8Array;
  try {
    signatureBytes = base64UrlDecode(envelope.signature_b64u);
  } catch {
    return invalid(now, 'Invalid aggregate signature encoding', {
      code: 'MALFORMED_ENVELOPE',
      message: 'signature_b64u is not valid base64url',
      field: 'signature_b64u',
    });
  }

  const signatureValid = await verifySignature(
    envelope.algorithm,
    signerPublicKey,
    signatureBytes,
    utf8Bytes(envelope.payload_hash_b64u)
  );

  if (!signatureValid) {
    return invalid(now, 'Aggregate envelope signature verification failed', {
      code: 'SIGNATURE_INVALID',
      message: 'signature_b64u does not verify payload_hash_b64u with signer_did key',
      field: 'signature_b64u',
    });
  }

  const members = payload.artifacts.member_bundles;

  const expectedManifestEntries: ExportBundleManifestEntry[] = [];

  let previousHash: string | null = null;
  const seenHashes = new Set<string>();

  for (let i = 0; i < members.length; i++) {
    const entry = await manifestEntryForMember(i, members[i]);
    expectedManifestEntries.push(entry);

    const memberHash = entry.sha256_b64u;
    if (previousHash !== null && memberHash < previousHash) {
      return invalid(now, 'member_bundles must be lexicographically sorted by canonical hash', {
        code: 'UNSORTED_MEMBER_ARRAY',
        message: `member_bundles[${i}] hash is out of order`,
        field: `payload.artifacts.member_bundles[${i}]`,
      });
    }
    previousHash = memberHash;

    if (seenHashes.has(memberHash)) {
      return invalid(now, 'Duplicate aggregate member hash detected', {
        code: 'AGGREGATE_DUPLICATE_MEMBER',
        message: `Duplicate canonical member hash at index ${i}`,
        field: `payload.artifacts.member_bundles[${i}]`,
      });
    }
    seenHashes.add(memberHash);
  }

  const providedEntries = normalizeManifestEntries(payload.manifest.entries);
  const expectedEntries = normalizeManifestEntries(expectedManifestEntries);

  const pathSet = new Set<string>();
  for (const e of providedEntries) {
    if (pathSet.has(e.path)) {
      return invalid(now, 'Aggregate manifest has duplicate paths', {
        code: 'AGGREGATE_BUNDLE_INVALID',
        message: `Duplicate manifest path: ${e.path}`,
        field: 'payload.manifest.entries.path',
      });
    }
    pathSet.add(e.path);
  }

  if (providedEntries.length !== expectedEntries.length) {
    return invalid(now, 'Aggregate manifest entry count mismatch', {
      code: 'HASH_MISMATCH',
      message: `manifest.entries count (${providedEntries.length}) does not match members (${expectedEntries.length})`,
      field: 'payload.manifest.entries',
    });
  }

  const providedMap = new Map(providedEntries.map((e) => [e.path, e]));
  for (const expected of expectedEntries) {
    const actual = providedMap.get(expected.path);
    if (!actual) {
      return invalid(now, 'Aggregate manifest missing expected path', {
        code: 'HASH_MISMATCH',
        message: `manifest is missing ${expected.path}`,
        field: 'payload.manifest.entries.path',
      });
    }

    if (actual.sha256_b64u !== expected.sha256_b64u) {
      return invalid(now, 'Aggregate manifest hash mismatch', {
        code: 'HASH_MISMATCH',
        message: `manifest hash mismatch for ${expected.path}`,
        field: `payload.manifest.entries[${expected.path}].sha256_b64u`,
      });
    }

    if (actual.content_type !== expected.content_type) {
      return invalid(now, 'Aggregate manifest content_type mismatch', {
        code: 'AGGREGATE_BUNDLE_INVALID',
        message: `manifest content_type mismatch for ${expected.path}`,
        field: `payload.manifest.entries[${expected.path}].content_type`,
      });
    }

    if (actual.size_bytes !== expected.size_bytes) {
      return invalid(now, 'Aggregate manifest size mismatch', {
        code: 'HASH_MISMATCH',
        message: `manifest size_bytes mismatch for ${expected.path}`,
        field: `payload.manifest.entries[${expected.path}].size_bytes`,
      });
    }
  }

  const seenBundleIds = new Set<string>();
  const seenRunIds = new Set<string>();
  const uniqueAgents = new Set<string>();
  const aggregatedRateClaims = new Map<
    string,
    {
      max_requests: number;
      observed_requests: number;
      max_tokens_input?: number;
      observed_tokens_input: number;
      max_tokens_output?: number;
      observed_tokens_output: number;
      firstField: string;
    }
  >();

  let fleetProofTier: ProofTier = 'witnessed_web';
  let fleetModelTier: ModelIdentityTier = 'tee_measured';

  for (let i = 0; i < members.length; i++) {
    const member = members[i];

    let memberBundleId: string;
    let memberRunId: string;
    let memberAgentDid: string;
    let memberExpiresAtMs: number | null = null;
    let childProofTier: ProofTier = 'unknown';
    let childModelTier: ModelIdentityTier = 'unknown';
    let memberRateClaims: RateLimitClaim[] = [];
    let memberRateClaimsField = `payload.artifacts.member_bundles[${i}]`;

    if (isProofBundleMember(member)) {
      memberBundleId = member.payload.bundle_id;
      memberAgentDid = member.payload.agent_did;
      memberRateClaims = member.payload.rate_limit_claims ?? [];
      memberRateClaimsField =
        `payload.artifacts.member_bundles[${i}].payload.rate_limit_claims`;

      const runInfo = extractRunIdFromProofEnvelope(member);
      if (!runInfo.ok) {
        return invalid(now, 'Aggregate member contains inconsistent run_id evidence', {
          code: 'INCONSISTENT_RUN_ID',
          message: `member[${i}] ${runInfo.reason}`,
          field: `payload.artifacts.member_bundles[${i}]`,
        });
      }
      memberRunId = runInfo.runId;

      const expires = parseExpiresAtMs(member.expires_at);
      if (!expires.ok) {
        return invalid(now, 'Aggregate member has invalid expires_at', {
          code: 'AGGREGATE_BUNDLE_INVALID',
          message: `member[${i}] expires_at is invalid`,
          field: `payload.artifacts.member_bundles[${i}].expires_at`,
        });
      }
      memberExpiresAtMs = expires.ms;

      const proofOut = await verifyProofBundle(member, {
        allowlistedReceiptSignerDids: options.allowlistedReceiptSignerDids,
        allowlistedAttesterDids: options.allowlistedAttesterDids,
        verificationTime: verifyTime.verifyAtIso,
        ttlSkewMs,
      });

      if (proofOut.result.status !== 'VALID') {
        return invalid(now, 'Aggregate member proof bundle failed verification', {
          code: 'AGGREGATE_MEMBER_INVALID',
          message:
            `member[${i}] failed verification: ${proofOut.error?.code ?? 'INVALID'} ${proofOut.error?.message ?? proofOut.result.reason}`,
          field: `payload.artifacts.member_bundles[${i}]`,
        });
      }

      childProofTier = proofOut.result.proof_tier ?? 'unknown';
      childModelTier = proofOut.result.model_identity_tier ?? 'unknown';
    } else if (isExportBundleMember(member)) {
      const nestedProof = member.artifacts.proof_bundle_envelope;
      memberBundleId = nestedProof.payload.bundle_id;
      memberAgentDid = nestedProof.payload.agent_did;
      memberRateClaims = nestedProof.payload.rate_limit_claims ?? [];
      memberRateClaimsField =
        `payload.artifacts.member_bundles[${i}].artifacts.proof_bundle_envelope.payload.rate_limit_claims`;

      const runInfo = extractRunIdFromProofEnvelope(nestedProof);
      if (!runInfo.ok) {
        return invalid(now, 'Aggregate export member has inconsistent run_id evidence', {
          code: 'INCONSISTENT_RUN_ID',
          message: `member[${i}] ${runInfo.reason}`,
          field: `payload.artifacts.member_bundles[${i}].artifacts.proof_bundle_envelope.payload.event_chain`,
        });
      }
      memberRunId = runInfo.runId;

      const expires = parseExpiresAtMs(member.expires_at);
      if (!expires.ok) {
        return invalid(now, 'Aggregate export member has invalid expires_at', {
          code: 'AGGREGATE_BUNDLE_INVALID',
          message: `member[${i}] expires_at is invalid`,
          field: `payload.artifacts.member_bundles[${i}].expires_at`,
        });
      }
      memberExpiresAtMs = expires.ms;

      const exportOut = await verifyExportBundle(member, {
        allowlistedReceiptSignerDids: options.allowlistedReceiptSignerDids,
        allowlistedAttesterDids: options.allowlistedAttesterDids,
        allowlistedExecutionAttestationSignerDids:
          options.allowlistedExecutionAttestationSignerDids,
        allowlistedDerivationAttestationSignerDids:
          options.allowlistedDerivationAttestationSignerDids,
        allowlistedAuditResultAttestationSignerDids:
          options.allowlistedAuditResultAttestationSignerDids,
        verifyAt: verifyTime.verifyAtIso,
        ttlSkewMs,
      });

      if (exportOut.result.status !== 'VALID') {
        return invalid(now, 'Aggregate member export bundle failed verification', {
          code: 'AGGREGATE_MEMBER_INVALID',
          message:
            `member[${i}] failed verification: ${exportOut.error?.code ?? 'INVALID'} ${exportOut.error?.message ?? exportOut.result.reason}`,
          field: `payload.artifacts.member_bundles[${i}]`,
        });
      }

      childProofTier = exportOut.proof_tier ?? 'unknown';
      childModelTier = exportOut.model_identity_tier ?? 'unknown';
    } else {
      return invalid(now, 'Aggregate member type is unsupported', {
        code: 'AGGREGATE_BUNDLE_INVALID',
        message: `member[${i}] is neither proof_bundle_envelope.v1 nor export_bundle.v1`,
        field: `payload.artifacts.member_bundles[${i}]`,
      });
    }

    if (memberAgentDid === payload.issuer_did) {
      return invalid(now, 'Aggregate issuer conflicts with member agent identity', {
        code: 'IDENTITY_CONFLICT',
        message: `member[${i}] agent_did must not equal aggregate payload.issuer_did`,
        field: `payload.artifacts.member_bundles[${i}]`,
      });
    }

    if (
      payloadExpires.ms !== null &&
      memberExpiresAtMs !== null &&
      payloadExpires.ms > memberExpiresAtMs
    ) {
      return invalid(now, 'Aggregate TTL exceeds member TTL', {
        code: 'AGGREGATE_TTL_EXCEEDS_MEMBER',
        message: `member[${i}] expires earlier than aggregate payload expires_at`,
        field: `payload.artifacts.member_bundles[${i}].expires_at`,
      });
    }

    if (
      memberExpiresAtMs !== null &&
      verifyTime.verifyAtMs > memberExpiresAtMs + ttlSkewMs
    ) {
      return invalid(now, 'Aggregate member has expired', {
        code: 'AGGREGATE_MEMBER_INVALID',
        message: `member[${i}] expired before verifyAt`,
        field: `payload.artifacts.member_bundles[${i}].expires_at`,
      });
    }

    if (seenBundleIds.has(memberBundleId)) {
      return invalid(now, 'Duplicate member bundle_id detected', {
        code: 'AGGREGATE_DUPLICATE_BUNDLE_ID',
        message: `Duplicate member bundle_id: ${memberBundleId}`,
        field: `payload.artifacts.member_bundles[${i}]`,
      });
    }
    seenBundleIds.add(memberBundleId);

    if (seenRunIds.has(memberRunId)) {
      return invalid(now, 'Duplicate member run_id detected', {
        code: 'AGGREGATE_DUPLICATE_RUN_ID',
        message: `Duplicate member run_id: ${memberRunId}`,
        field: `payload.artifacts.member_bundles[${i}]`,
      });
    }
    seenRunIds.add(memberRunId);

    for (let claimIndex = 0; claimIndex < memberRateClaims.length; claimIndex++) {
      const claim = memberRateClaims[claimIndex];
      const claimField = `${memberRateClaimsField}[${claimIndex}]`;

      const windowStartMs = Date.parse(claim.window_start);
      const windowEndMs = Date.parse(claim.window_end);
      if (!Number.isFinite(windowStartMs) || !Number.isFinite(windowEndMs)) {
        return invalid(now, 'Invalid rate-limit claim window timestamps', {
          code: 'RATE_LIMIT_CLAIM_INCONSISTENT',
          message: 'rate_limit_claim window_start/window_end must be valid ISO-8601 timestamps',
          field: claimField,
        });
      }

      if (windowStartMs > windowEndMs) {
        return invalid(now, 'Rate-limit claim window is invalid', {
          code: 'RATE_LIMIT_WINDOW_INVALID',
          message: 'rate_limit_claim window_start must be <= window_end',
          field: `${claimField}.window_start`,
        });
      }

      if (
        !Number.isFinite(claim.max_requests) ||
        claim.max_requests < 0 ||
        !Number.isFinite(claim.observed_requests) ||
        claim.observed_requests < 0
      ) {
        return invalid(now, 'Invalid rate-limit claim numeric values', {
          code: 'RATE_LIMIT_CLAIM_INCONSISTENT',
          message: 'rate_limit_claim max_requests/observed_requests must be finite non-negative numbers',
          field: claimField,
        });
      }

      const maxInputSet = claim.max_tokens_input !== undefined;
      const observedInputSet = claim.observed_tokens_input !== undefined;
      const maxOutputSet = claim.max_tokens_output !== undefined;
      const observedOutputSet = claim.observed_tokens_output !== undefined;

      if (maxInputSet !== observedInputSet || maxOutputSet !== observedOutputSet) {
        return invalid(now, 'Incomplete rate-limit token claim fields', {
          code: 'RATE_LIMIT_CLAIM_INCONSISTENT',
          message: 'rate_limit_claim max_tokens_* and observed_tokens_* must be provided together',
          field: claimField,
        });
      }

      if (
        (maxInputSet && (!Number.isFinite(claim.max_tokens_input) || claim.max_tokens_input! < 0)) ||
        (observedInputSet && (!Number.isFinite(claim.observed_tokens_input) || claim.observed_tokens_input! < 0)) ||
        (maxOutputSet && (!Number.isFinite(claim.max_tokens_output) || claim.max_tokens_output! < 0)) ||
        (observedOutputSet && (!Number.isFinite(claim.observed_tokens_output) || claim.observed_tokens_output! < 0))
      ) {
        return invalid(now, 'Invalid rate-limit token claim values', {
          code: 'RATE_LIMIT_CLAIM_INCONSISTENT',
          message: 'rate_limit_claim token limits/observations must be finite non-negative numbers',
          field: claimField,
        });
      }

      const key = rateClaimKey(memberAgentDid, claim);
      const existing = aggregatedRateClaims.get(key);
      if (!existing) {
        aggregatedRateClaims.set(key, {
          max_requests: claim.max_requests,
          observed_requests: claim.observed_requests,
          max_tokens_input: claim.max_tokens_input,
          observed_tokens_input: claim.observed_tokens_input ?? 0,
          max_tokens_output: claim.max_tokens_output,
          observed_tokens_output: claim.observed_tokens_output ?? 0,
          firstField: claimField,
        });
      } else {
        if (
          existing.max_requests !== claim.max_requests ||
          !optionalLimitEqual(existing.max_tokens_input, claim.max_tokens_input) ||
          !optionalLimitEqual(existing.max_tokens_output, claim.max_tokens_output)
        ) {
          return invalid(now, 'Rate-limit claim is inconsistent across bundles', {
            code: 'RATE_LIMIT_CLAIM_INCONSISTENT',
            message: 'Conflicting max limits detected for the same agent/scope/window rate-limit claim',
            field: claimField,
          });
        }

        existing.observed_requests += claim.observed_requests;
        existing.observed_tokens_input += claim.observed_tokens_input ?? 0;
        existing.observed_tokens_output += claim.observed_tokens_output ?? 0;
      }
    }

    uniqueAgents.add(memberAgentDid);
    fleetProofTier = proofTierMin(fleetProofTier, childProofTier);
    fleetModelTier = modelTierMin(fleetModelTier, childModelTier);
  }

  for (const [claimKey, agg] of aggregatedRateClaims) {
    if (agg.observed_requests > agg.max_requests) {
      return invalid(now, 'Aggregated rate-limit request count exceeded', {
        code: 'RATE_LIMIT_EXCEEDED',
        message: `Aggregated observed_requests exceeds max_requests for claim ${claimKey}`,
        field: agg.firstField,
      });
    }

    if (
      agg.max_tokens_input !== undefined &&
      agg.observed_tokens_input > agg.max_tokens_input
    ) {
      return invalid(now, 'Aggregated rate-limit input token count exceeded', {
        code: 'RATE_LIMIT_EXCEEDED',
        message:
          `Aggregated observed_tokens_input exceeds max_tokens_input for claim ${claimKey}`,
        field: agg.firstField,
      });
    }

    if (
      agg.max_tokens_output !== undefined &&
      agg.observed_tokens_output > agg.max_tokens_output
    ) {
      return invalid(now, 'Aggregated rate-limit output token count exceeded', {
        code: 'RATE_LIMIT_EXCEEDED',
        message:
          `Aggregated observed_tokens_output exceeds max_tokens_output for claim ${claimKey}`,
        field: agg.firstField,
      });
    }
  }

  const summary = payload.metadata.fleet_summary;
  if (summary.total_members !== members.length) {
    return invalid(now, 'Fleet summary total_members mismatch', {
      code: 'FLEET_SUMMARY_MISMATCH',
      message:
        `fleet_summary.total_members=${summary.total_members} but computed=${members.length}`,
      field: 'payload.metadata.fleet_summary.total_members',
    });
  }

  if (summary.unique_agents !== uniqueAgents.size) {
    return invalid(now, 'Fleet summary unique_agents mismatch', {
      code: 'FLEET_SUMMARY_MISMATCH',
      message:
        `fleet_summary.unique_agents=${summary.unique_agents} but computed=${uniqueAgents.size}`,
      field: 'payload.metadata.fleet_summary.unique_agents',
    });
  }

  if (summary.total_runs !== seenRunIds.size) {
    return invalid(now, 'Fleet summary total_runs mismatch', {
      code: 'FLEET_SUMMARY_MISMATCH',
      message: `fleet_summary.total_runs=${summary.total_runs} but computed=${seenRunIds.size}`,
      field: 'payload.metadata.fleet_summary.total_runs',
    });
  }

  if (
    summary.fleet_proof_tier !== undefined &&
    summary.fleet_proof_tier !== fleetProofTier
  ) {
    return invalid(now, 'Fleet summary fleet_proof_tier mismatch', {
      code: 'FLEET_SUMMARY_MISMATCH',
      message:
        `fleet_summary.fleet_proof_tier=${summary.fleet_proof_tier} but computed=${fleetProofTier}`,
      field: 'payload.metadata.fleet_summary.fleet_proof_tier',
    });
  }

  return valid(now, envelope, {
    manifest_entries_verified: expectedEntries.length,
    member_count: members.length,
    unique_agents: uniqueAgents.size,
    total_runs: seenRunIds.size,
    proof_tier: fleetProofTier,
    model_identity_tier: fleetModelTier,
  });
}
