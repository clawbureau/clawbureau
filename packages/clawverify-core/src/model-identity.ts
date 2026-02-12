/**
 * CVF-US-016 — Model identity extraction + verification.
 *
 * Model identity is an orthogonal axis to PoH tiers:
 * - PoH (`proof_tier` / `poh_tier`) describes execution provenance.
 * - `model_identity_tier` describes what we can honestly claim about the model identity.
 *
 * This module intentionally fail-closes *only* the model identity axis.
 * Receipt signature/binding validity is handled elsewhere.
 */

import type { GatewayReceiptPayload, ModelIdentityTier, SignedEnvelope } from './types.js';
import { base64UrlEncode } from './crypto.js';
import { jcsCanonicalize } from './jcs.js';
import { isValidBase64Url } from './schema-registry.js';
import { validateModelIdentityV1 } from './schema-validation.js';

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

async function sha256B64uUtf8(s: string): Promise<string> {
  const bytes = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

export async function computeModelIdentityHashB64u(identity: unknown): Promise<string> {
  return sha256B64uUtf8(jcsCanonicalize(identity));
}

const TIER_STRENGTH: Record<ModelIdentityTier, number> = {
  unknown: 0,
  closed_opaque: 1,
  closed_provider_manifest: 2,
  openweights_hashable: 3,
  tee_measured: 4,
};

function normalizeTier(tier: unknown): ModelIdentityTier {
  if (tier === 'closed_opaque') return 'closed_opaque';
  if (tier === 'closed_provider_manifest') return 'closed_provider_manifest';
  if (tier === 'openweights_hashable') return 'openweights_hashable';
  if (tier === 'tee_measured') return 'tee_measured';
  return 'unknown';
}

function requireString(obj: Record<string, unknown>, key: string): string | null {
  const v = obj[key];
  return typeof v === 'string' && v.trim().length > 0 ? v : null;
}

function hasProviderManifestEvidence(identity: Record<string, unknown>): boolean {
  const artifacts = identity.artifacts;
  if (!isRecord(artifacts)) return false;
  const pm = artifacts.provider_manifest;
  if (!isRecord(pm)) return false;
  const h = pm.hash_b64u;
  return typeof h === 'string' && isValidBase64Url(h) && h.length >= 8;
}

function hasOpenweightsEvidence(identity: Record<string, unknown>): boolean {
  const artifacts = identity.artifacts;
  if (!isRecord(artifacts)) return false;
  const ow = artifacts.openweights;
  if (!isRecord(ow)) return false;
  const weights = ow.weights;
  if (!Array.isArray(weights) || weights.length === 0) return false;
  for (const w of weights) {
    if (!isRecord(w)) return false;
    const h = w.hash_b64u;
    if (typeof h !== 'string' || !isValidBase64Url(h) || h.length < 8) return false;
  }
  return true;
}

function hasTeeEvidence(identity: Record<string, unknown>): boolean {
  const artifacts = identity.artifacts;
  if (!isRecord(artifacts)) return false;
  const tm = artifacts.tee_measurement;
  if (!isRecord(tm)) return false;
  const ref = tm.attestation_report_ref;
  if (!isRecord(ref)) return false;
  const h = ref.resource_hash_b64u;
  return typeof h === 'string' && isValidBase64Url(h) && h.length >= 8;
}

export interface ModelIdentityVerificationResult {
  /** Whether the model identity claim itself verified (schema + hash + consistency). */
  valid: boolean;
  tier: ModelIdentityTier;
  /** Deterministic risk flags (non-normative). */
  risk_flags: string[];
  computed_hash_b64u?: string;
}

/**
 * Verify model identity for a single receipt payload.
 *
 * Returns:
 * - `valid=false` only means model identity cannot be trusted. Receipt may still be cryptographically valid.
 */
export async function verifyModelIdentityFromReceiptPayload(
  payload: GatewayReceiptPayload
): Promise<ModelIdentityVerificationResult> {
  const risk = new Set<string>();

  const metadata = isRecord(payload.metadata) ? payload.metadata : null;

  const providedIdentity = metadata?.model_identity;
  const providedHash = typeof metadata?.model_identity_hash_b64u === 'string' ? metadata.model_identity_hash_b64u : null;

  let identity: unknown;

  if (providedIdentity === undefined) {
    // Back-compat: older receipts may not include model identity metadata.
    // Default is still "closed_opaque" for closed providers.
    risk.add('MODEL_IDENTITY_MISSING_DEFAULTED');
    identity = {
      model_identity_version: '1',
      tier: 'closed_opaque',
      model: {
        provider: payload.provider,
        name: payload.model,
      },
    };
  } else {
    // Strict schema validate when present.
    const v = validateModelIdentityV1(providedIdentity);
    if (!v.valid) {
      risk.add('MODEL_IDENTITY_SCHEMA_INVALID');
      return { valid: false, tier: 'unknown', risk_flags: [...risk].sort() };
    }
    identity = providedIdentity;
  }

  // Ensure the identity model label matches the receipt payload model label.
  if (!isRecord(identity)) {
    risk.add('MODEL_IDENTITY_SCHEMA_INVALID');
    return { valid: false, tier: 'unknown', risk_flags: [...risk].sort() };
  }

  const model = identity.model;
  if (!isRecord(model)) {
    risk.add('MODEL_IDENTITY_SCHEMA_INVALID');
    return { valid: false, tier: 'unknown', risk_flags: [...risk].sort() };
  }

  const identityProvider = requireString(model, 'provider');
  const identityName = requireString(model, 'name');

  if (!identityProvider || !identityName) {
    risk.add('MODEL_IDENTITY_SCHEMA_INVALID');
    return { valid: false, tier: 'unknown', risk_flags: [...risk].sort() };
  }

  if (identityProvider !== payload.provider || identityName !== payload.model) {
    risk.add('MODEL_IDENTITY_MODEL_MISMATCH');
    return { valid: false, tier: 'unknown', risk_flags: [...risk].sort() };
  }

  // Validate hash (if present) against sha256_b64u(JCS(model_identity)).
  let computedHash: string;
  try {
    computedHash = await computeModelIdentityHashB64u(identity);
  } catch {
    risk.add('MODEL_IDENTITY_HASH_COMPUTE_FAILED');
    return { valid: false, tier: 'unknown', risk_flags: [...risk].sort() };
  }

  if (providedHash) {
    if (!isValidBase64Url(providedHash)) {
      risk.add('MODEL_IDENTITY_HASH_INVALID');
      return { valid: false, tier: 'unknown', risk_flags: [...risk].sort(), computed_hash_b64u: computedHash };
    }

    if (providedHash !== computedHash) {
      risk.add('MODEL_IDENTITY_HASH_MISMATCH');
      return { valid: false, tier: 'unknown', risk_flags: [...risk].sort(), computed_hash_b64u: computedHash };
    }
  } else {
    risk.add('MODEL_IDENTITY_HASH_MISSING');
  }

  // Validate tier semantics (fail-closed on stronger tiers without evidence).
  const tier = normalizeTier(identity.tier);

  if (tier === 'unknown') {
    risk.add('MODEL_IDENTITY_TIER_INVALID');
    return { valid: false, tier: 'unknown', risk_flags: [...risk].sort(), computed_hash_b64u: computedHash };
  }

  if (tier === 'closed_provider_manifest' && !hasProviderManifestEvidence(identity)) {
    risk.add('MODEL_IDENTITY_EVIDENCE_MISSING');
    return { valid: false, tier: 'unknown', risk_flags: [...risk].sort(), computed_hash_b64u: computedHash };
  }

  if (tier === 'openweights_hashable' && !hasOpenweightsEvidence(identity)) {
    risk.add('MODEL_IDENTITY_EVIDENCE_MISSING');
    return { valid: false, tier: 'unknown', risk_flags: [...risk].sort(), computed_hash_b64u: computedHash };
  }

  if (tier === 'tee_measured' && !hasTeeEvidence(identity)) {
    risk.add('MODEL_IDENTITY_EVIDENCE_MISSING');
    return { valid: false, tier: 'unknown', risk_flags: [...risk].sort(), computed_hash_b64u: computedHash };
  }

  if (tier === 'closed_opaque') {
    // Not an error: this is the expected posture for closed providers.
    risk.add('MODEL_IDENTITY_OPAQUE');
  }

  return {
    valid: true,
    tier,
    risk_flags: [...risk].sort(),
    computed_hash_b64u: computedHash,
  };
}

export interface ReceiptVerificationForModelIdentity {
  signature_valid?: boolean;
  binding_valid?: boolean;
  valid?: boolean;
}

/**
 * Compute a single model_identity_tier for a set of receipts.
 *
 * Policy/gating-friendly semantics: the overall tier is the *minimum* tier
 * across all receipts that have signature-valid envelopes.
 */
export async function computeModelIdentityTierFromReceipts(input: {
  receipts: SignedEnvelope<GatewayReceiptPayload>[];
  receiptResults?: ReceiptVerificationForModelIdentity[] | null;
}): Promise<{ model_identity_tier: ModelIdentityTier; risk_flags: string[] }> {
  const risk = new Set<string>();

  const tiers: ModelIdentityTier[] = [];

  for (let i = 0; i < input.receipts.length; i++) {
    const r = input.receipts[i];
    const vr = input.receiptResults?.[i];

    // Only consider receipts whose envelope signature+payload hash were verified.
    // If we have no per-receipt verification results, assume caller already filtered.
    if (vr && vr.signature_valid === false) continue;

    const out = await verifyModelIdentityFromReceiptPayload(r.payload);
    for (const f of out.risk_flags) risk.add(f);

    tiers.push(out.tier);
  }

  if (tiers.length === 0) {
    risk.add('MODEL_IDENTITY_NO_SIGNATURE_VERIFIED_RECEIPTS');
    return { model_identity_tier: 'unknown', risk_flags: [...risk].sort() };
  }

  let minTier: ModelIdentityTier = tiers[0];
  for (const t of tiers) {
    if (TIER_STRENGTH[t] < TIER_STRENGTH[minTier]) minTier = t;
  }

  const distinct = new Set(tiers);
  if (distinct.size > 1) risk.add('MODEL_IDENTITY_HETEROGENEOUS');

  return {
    model_identity_tier: minTier,
    risk_flags: [...risk].sort(),
  };
}
