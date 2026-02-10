import type { Provider, ReceiptPrivacyMode } from './types';

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

  // Privacy / DLP controls
  redaction_rules?: RedactionRule[];
  receipt_privacy_mode?: ReceiptPrivacyMode;

  // Future: egress mediation
  egress_allowlist?: string[];

  // Free-form metadata (hash-bound)
  metadata?: Record<string, unknown>;
};

export type SignedEnvelope<T> = {
  envelope_version: '1';
  envelope_type: 'work_policy_contract';
  payload: T;
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
