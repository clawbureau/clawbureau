import type { Env, Provider, ReceiptPrivacyMode } from './types';
import {
  base64urlEncode,
  extractEd25519PublicKeyFromDidKey,
  importEd25519PublicKey,
  sha256B64u,
  verifyEd25519,
} from './crypto';
import { jcsCanonicalize } from './jcs';

export type RedactionRule = {
  path: string;
  action: 'remove' | 'hash' | 'mask';
};

/**
 * Work Policy Contract (WPC) v1
 *
 * Hashing (policy_hash_b64u):
 *   sha256( JCS(policy) ) as base64url (no padding)
 */
export type WorkPolicyContractV1 = {
  policy_version: '1';
  policy_id: string;
  issuer_did: string;

  // Constraints
  allowed_providers?: Provider[];
  allowed_models?: string[];

  /**
   * Optional minimum required model identity tier (orthogonal to PoH tiers).
   * Gateways MUST fail closed when only a weaker tier is available.
   */
  minimum_model_identity_tier?: 'closed_opaque' | 'closed_provider_manifest' | 'openweights_hashable' | 'tee_measured';

  /**
   * Optional required audit packs by deterministic audit_pack_hash_b64u (see ADR 0001).
   * Used for policy gating (verify-under-policy / procurement requirements).
   */
  required_audit_packs?: string[];

  // Privacy / DLP controls
  redaction_rules?: RedactionRule[];
  receipt_privacy_mode?: ReceiptPrivacyMode;

  // Future: egress mediation
  egress_allowlist?: string[];

  // Free-form metadata (hash-bound)
  metadata?: Record<string, unknown>;
};

export type WorkPolicyContractEnvelopeV1 = {
  envelope_version: '1';
  envelope_type: 'work_policy_contract';
  payload: WorkPolicyContractV1;
  payload_hash_b64u: string;
  hash_algorithm: 'SHA-256';
  signature_b64u: string;
  algorithm: 'Ed25519';
  signer_did: string;
  issued_at: string;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function isNonEmptyString(value: unknown, opts?: { maxLen?: number }): value is string {
  if (typeof value !== 'string') return false;
  const s = value.trim();
  if (s.length === 0) return false;
  if (opts?.maxLen && s.length > opts.maxLen) return false;
  return true;
}

const B64U_RE = /^[A-Za-z0-9_-]+$/;

function isB64uString(
  value: unknown,
  opts?: { minLen?: number; maxLen?: number }
): value is string {
  if (typeof value !== 'string') return false;
  const s = value.trim();
  if (s.length === 0) return false;
  if (opts?.minLen && s.length < opts.minLen) return false;
  if (opts?.maxLen && s.length > opts.maxLen) return false;
  return B64U_RE.test(s);
}

function isB64uStringArray(
  value: unknown,
  opts?: { maxItems?: number; minLen?: number; maxLen?: number }
): value is string[] {
  if (!Array.isArray(value)) return false;
  if (opts?.maxItems && value.length > opts.maxItems) return false;
  return value.every((v) => isB64uString(v, { minLen: opts?.minLen, maxLen: opts?.maxLen }));
}

function isStringArray(value: unknown, opts?: { maxItems?: number; maxLen?: number }): value is string[] {
  if (!Array.isArray(value)) return false;
  if (opts?.maxItems && value.length > opts.maxItems) return false;
  return value.every((v) => isNonEmptyString(v, { maxLen: opts?.maxLen }));
}

function isProviderArray(value: unknown, opts?: { maxItems?: number }): value is Provider[] {
  if (!Array.isArray(value)) return false;
  if (opts?.maxItems && value.length > opts.maxItems) return false;
  return value.every((v) => v === 'openai' || v === 'anthropic' || v === 'google');
}

function isModelIdentityTier(value: unknown): boolean {
  return (
    value === 'closed_opaque' ||
    value === 'closed_provider_manifest' ||
    value === 'openweights_hashable' ||
    value === 'tee_measured'
  );
}

function isRedactionRules(value: unknown): value is RedactionRule[] {
  if (!Array.isArray(value)) return false;
  if (value.length > 256) return false;

  for (const r of value) {
    const o = asRecord(r);
    if (!o) return false;

    const keys = Object.keys(o);
    for (const k of keys) {
      if (k !== 'path' && k !== 'action') return false;
    }

    if (!isNonEmptyString(o.path, { maxLen: 512 })) return false;
    if (o.action !== 'remove' && o.action !== 'hash' && o.action !== 'mask') return false;
  }

  return true;
}

export function isWorkPolicyContractV1(value: unknown): value is WorkPolicyContractV1 {
  const obj = asRecord(value);
  if (!obj) return false;

  const allowedKeys = new Set([
    'policy_version',
    'policy_id',
    'issuer_did',
    'allowed_providers',
    'allowed_models',
    'minimum_model_identity_tier',
    'required_audit_packs',
    'redaction_rules',
    'receipt_privacy_mode',
    'egress_allowlist',
    'metadata',
  ]);

  for (const k of Object.keys(obj)) {
    if (!allowedKeys.has(k)) return false;
  }

  if (obj.policy_version !== '1') return false;
  if (!isNonEmptyString(obj.policy_id, { maxLen: 128 })) return false;

  if (!isNonEmptyString(obj.issuer_did, { maxLen: 256 })) return false;
  if (!String(obj.issuer_did).startsWith('did:')) return false;

  if (obj.allowed_providers !== undefined && !isProviderArray(obj.allowed_providers, { maxItems: 16 })) {
    return false;
  }

  if (obj.allowed_models !== undefined && !isStringArray(obj.allowed_models, { maxItems: 256, maxLen: 256 })) {
    return false;
  }

  if (obj.minimum_model_identity_tier !== undefined && !isModelIdentityTier(obj.minimum_model_identity_tier)) {
    return false;
  }

  if (obj.required_audit_packs !== undefined && !isB64uStringArray(obj.required_audit_packs, { maxItems: 64, minLen: 8, maxLen: 128 })) {
    return false;
  }

  if (obj.redaction_rules !== undefined && !isRedactionRules(obj.redaction_rules)) {
    return false;
  }

  if (obj.receipt_privacy_mode !== undefined) {
    if (obj.receipt_privacy_mode !== 'hash_only' && obj.receipt_privacy_mode !== 'encrypted') return false;
  }

  if (obj.egress_allowlist !== undefined && !isStringArray(obj.egress_allowlist, { maxItems: 256, maxLen: 256 })) {
    return false;
  }

  if (obj.metadata !== undefined) {
    const md = asRecord(obj.metadata);
    if (!md) return false;
  }

  return true;
}

export function isWorkPolicyContractEnvelopeV1(value: unknown): value is WorkPolicyContractEnvelopeV1 {
  const obj = asRecord(value);
  if (!obj) return false;

  const allowedKeys = new Set([
    'envelope_version',
    'envelope_type',
    'payload',
    'payload_hash_b64u',
    'hash_algorithm',
    'signature_b64u',
    'algorithm',
    'signer_did',
    'issued_at',
  ]);

  for (const k of Object.keys(obj)) {
    if (!allowedKeys.has(k)) return false;
  }

  if (obj.envelope_version !== '1') return false;
  if (obj.envelope_type !== 'work_policy_contract') return false;
  if (obj.hash_algorithm !== 'SHA-256') return false;
  if (obj.algorithm !== 'Ed25519') return false;

  if (!isNonEmptyString(obj.payload_hash_b64u, { maxLen: 128 })) return false;
  if (!isNonEmptyString(obj.signature_b64u, { maxLen: 2048 })) return false;
  if (!isNonEmptyString(obj.signer_did, { maxLen: 256 })) return false;
  if (!String(obj.signer_did).startsWith('did:')) return false;

  if (!isNonEmptyString(obj.issued_at, { maxLen: 64 })) return false;

  if (!isWorkPolicyContractV1(obj.payload)) return false;

  return true;
}

const WPC_HASH_RE = /^[A-Za-z0-9_-]{43}$/;

export function isWpcHashB64u(value: string): boolean {
  return WPC_HASH_RE.test(value);
}

export async function computeWpcHashB64u(payload: WorkPolicyContractV1): Promise<string> {
  const canonical = jcsCanonicalize(payload);
  return sha256B64u(canonical);
}

function parseSignerAllowlist(env: Env): Set<string> | null {
  const raw = env.WPC_SIGNER_DIDS;
  if (typeof raw !== 'string' || raw.trim().length === 0) return null;

  const parts = raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  if (parts.length === 0) return null;
  return new Set(parts);
}

export type FetchWpcResult =
  | {
      ok: true;
      policy_hash_b64u: string;
      envelope: WorkPolicyContractEnvelopeV1;
      policy: WorkPolicyContractV1;
      cache: 'hit' | 'miss';
    }
  | {
      ok: false;
      errorCode: string;
      error: string;
      status: number;
    };

const WPC_CACHE_TTL_MS = 60_000;
const WPC_CACHE_MAX = 512;

const wpcCache: Map<
  string,
  {
    expiresAtMs: number;
    value: Extract<FetchWpcResult, { ok: true }>;
  }
> = new Map();

async function verifyWpcEnvelope(
  env: Env,
  policyHashB64u: string,
  envelope: WorkPolicyContractEnvelopeV1
): Promise<{ ok: true; policy: WorkPolicyContractV1 } | { ok: false; errorCode: string; error: string; status: number }> {
  if (envelope.payload_hash_b64u !== policyHashB64u) {
    return {
      ok: false,
      errorCode: 'WPC_HASH_MISMATCH',
      error: `WPC payload_hash_b64u mismatch (expected ${policyHashB64u}, got ${envelope.payload_hash_b64u})`,
      status: 400,
    };
  }

  const computed = await computeWpcHashB64u(envelope.payload);
  if (computed !== envelope.payload_hash_b64u) {
    return {
      ok: false,
      errorCode: 'WPC_HASH_INVALID',
      error: `WPC payload hash is invalid (computed ${computed}, envelope ${envelope.payload_hash_b64u})`,
      status: 400,
    };
  }

  const allowlist = parseSignerAllowlist(env);
  if (allowlist && !allowlist.has(envelope.signer_did)) {
    return {
      ok: false,
      errorCode: 'WPC_SIGNER_NOT_ALLOWED',
      error: `WPC signer_did not allowlisted (${envelope.signer_did})`,
      status: 403,
    };
  }

  const publicKeyBytes = extractEd25519PublicKeyFromDidKey(envelope.signer_did);
  if (!publicKeyBytes) {
    return {
      ok: false,
      errorCode: 'WPC_SIGNER_DID_UNSUPPORTED',
      error: 'Unsupported signer_did format (expected did:key with Ed25519 multicodec)',
      status: 400,
    };
  }

  const publicKeyB64u = base64urlEncode(publicKeyBytes);
  const publicKey = await importEd25519PublicKey(publicKeyB64u);

  const ok = await verifyEd25519(publicKey, envelope.signature_b64u, envelope.payload_hash_b64u);
  if (!ok) {
    return {
      ok: false,
      errorCode: 'WPC_SIGNATURE_INVALID',
      error: 'WPC signature verification failed',
      status: 403,
    };
  }

  return { ok: true, policy: envelope.payload };
}

export async function fetchWpcFromRegistry(env: Env, policyHashB64u: string): Promise<FetchWpcResult> {
  const now = Date.now();

  const cached = wpcCache.get(policyHashB64u);
  if (cached && cached.expiresAtMs > now) {
    return { ...cached.value, cache: 'hit' };
  }

  const baseUrl = typeof env.WPC_REGISTRY_BASE_URL === 'string' && env.WPC_REGISTRY_BASE_URL.trim().length > 0
    ? env.WPC_REGISTRY_BASE_URL.trim()
    : 'https://clawcontrols.com';

  let url: URL;
  try {
    url = new URL(`/v1/wpc/${policyHashB64u}`, baseUrl);
  } catch {
    return {
      ok: false,
      errorCode: 'WPC_REGISTRY_BASE_URL_INVALID',
      error: 'Invalid WPC_REGISTRY_BASE_URL',
      status: 500,
    };
  }

  if (url.protocol !== 'https:') {
    return {
      ok: false,
      errorCode: 'WPC_REGISTRY_BASE_URL_INSECURE',
      error: 'WPC_REGISTRY_BASE_URL must be https',
      status: 500,
    };
  }

  let resp: Response;
  try {
    resp = await fetch(url.toString(), { method: 'GET' });
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'unknown error';
    return {
      ok: false,
      errorCode: 'WPC_REGISTRY_FETCH_FAILED',
      error: `Failed to fetch WPC from registry: ${msg}`,
      status: 503,
    };
  }

  if (!resp.ok) {
    const status = resp.status;

    if (status === 404) {
      return {
        ok: false,
        errorCode: 'WPC_NOT_FOUND',
        error: `WPC not found for hash: ${policyHashB64u}`,
        status: 404,
      };
    }

    let detail = '';
    try {
      detail = await resp.text();
    } catch {
      // ignore
    }

    return {
      ok: false,
      errorCode: 'WPC_REGISTRY_ERROR',
      error: `WPC registry returned HTTP ${status}${detail ? `: ${detail}` : ''}`,
      status: 503,
    };
  }

  let json: unknown;
  try {
    json = await resp.json();
  } catch {
    return {
      ok: false,
      errorCode: 'WPC_REGISTRY_BAD_JSON',
      error: 'WPC registry returned invalid JSON',
      status: 502,
    };
  }

  const obj = asRecord(json);
  if (!obj) {
    return {
      ok: false,
      errorCode: 'WPC_REGISTRY_BAD_RESPONSE',
      error: 'WPC registry returned invalid response shape',
      status: 502,
    };
  }

  const envelope = obj.envelope;
  if (!isWorkPolicyContractEnvelopeV1(envelope)) {
    return {
      ok: false,
      errorCode: 'WPC_ENVELOPE_INVALID',
      error: 'WPC registry returned invalid envelope',
      status: 502,
    };
  }

  const verify = await verifyWpcEnvelope(env, policyHashB64u, envelope);
  if (!verify.ok) return verify;

  const value: Extract<FetchWpcResult, { ok: true }> = {
    ok: true,
    policy_hash_b64u: policyHashB64u,
    envelope,
    policy: verify.policy,
    cache: 'miss',
  };

  // Cache (best-effort)
  try {
    if (wpcCache.size >= WPC_CACHE_MAX) {
      wpcCache.clear();
    }
    wpcCache.set(policyHashB64u, { expiresAtMs: now + WPC_CACHE_TTL_MS, value });
  } catch {
    // ignore
  }

  return value;
}
