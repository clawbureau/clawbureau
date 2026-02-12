/**
 * Redaction utilities for PoH artifacts.
 *
 * IMPORTANT: This runs BEFORE hashing event payloads / URM metadata.
 * Secrets that enter the immutable event chain (even as hashed JSON) can still
 * become toxic when payloads are materialized for debugging or future tooling.
 *
 * This module is intentionally conservative and regex-based.
 * Ported from /Users/gfw/code/agentlog/redact.py (+ supplemental patterns).
 */

// Order matters: redact large structures first, then smaller patterns.

const PRIVATE_KEY_BLOCK_RE =
  /-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]+?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----/gm;

const JWT_RE = /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g;

const BEARER_RE = /\bBearer\s+([A-Za-z0-9\-._~+/]+=*)/gi;

// Common API key shapes
const OPENAI_SK_RE = /\bsk-[A-Za-z0-9]{20,}\b/g;
const ANTHROPIC_SK_RE = /\bsk-ant-[A-Za-z0-9\-]{20,}\b/g;
const GITHUB_TOKEN_RE = /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g;
const GITHUB_PAT_RE = /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g;
const GOOGLE_API_KEY_RE = /\bAIza[0-9A-Za-z\-_]{20,}\b/g;

// Agent ecosystem examples
const MOLTBOOK_SK_RE = /\bmoltbook_sk_[A-Za-z0-9\-_]{10,}\b/g;
const MOLTBOOK_CLAIM_RE = /\bmoltbook_claim_[A-Za-z0-9\-_]+\b/g;

// Generic key/value leakage in JSON or env snippets
const KV_SECRET_RE =
  /(\b(?:api[_-]?key|token|secret|password|authorization)\b\s*[:=]\s*)(['"]?)([^\s'"\n]{8,})(\2)/gi;

const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

const FORMATTED_ADDRESS_JSON_RE =
  /("formatted_address"\s*:\s*")[^"]+(\")/gi;
const ADDRESS_JSON_RE = /("address"\s*:\s*")[^"]+(\")/gi;

// URL query params that often contain secrets
const URL_SECRET_PARAM_RE =
  /([?&](?:token|api_key|apikey|key|secret|signature|sig|access_token)=)([^&#\s]+)/gi;

// Supplemental patterns for natural-language leaks
const PROSE_SECRET_RE =
  /\b(token|key|secret|password|credential)([^"']{0,20})(["'])([A-Za-z0-9\-_./+=]{16,})(\3)/gi;

const HEX_TOKEN_RE = /\b[0-9a-f]{32,}\b/gi;

function truncate(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  return text.slice(0, Math.max(0, maxChars - 20)) + '\n… [TRUNCATED]';
}

export function redactText(text: string): string {
  if (!text) return '';

  let out = String(text);

  // 1) Private keys
  out = out.replace(PRIVATE_KEY_BLOCK_RE, '[REDACTED:private_key]');

  // 2) JWTs
  out = out.replace(JWT_RE, '[REDACTED:jwt]');

  // 3) Bearer tokens
  out = out.replace(BEARER_RE, 'Bearer [REDACTED:bearer]');

  // 4) Known key formats
  out = out.replace(ANTHROPIC_SK_RE, '[REDACTED:api_key]');
  out = out.replace(OPENAI_SK_RE, '[REDACTED:api_key]');
  out = out.replace(GITHUB_PAT_RE, '[REDACTED:api_key]');
  out = out.replace(GITHUB_TOKEN_RE, '[REDACTED:api_key]');
  out = out.replace(GOOGLE_API_KEY_RE, '[REDACTED:api_key]');
  out = out.replace(MOLTBOOK_SK_RE, '[REDACTED:api_key]');

  // 5) Claim URLs / opaque claim strings
  out = out.replace(MOLTBOOK_CLAIM_RE, '[REDACTED:claim]');

  // 6) Secret-ish key/value pairs (JSON/env dumps)
  out = out.replace(KV_SECRET_RE, (_m, prefix, quote, _value, closing) => {
    const q = typeof quote === 'string' ? quote : '';
    const c = typeof closing === 'string' && closing.length > 0 ? closing : q;
    return `${prefix}${q}[REDACTED:secret]${c}`;
  });

  // 7) URL secret params
  out = out.replace(URL_SECRET_PARAM_RE, '$1[REDACTED:secret]');

  // 8) Emails
  out = out.replace(EMAIL_RE, '[REDACTED:email]');

  // 9) Addresses in JSON-ish payloads
  out = out.replace(FORMATTED_ADDRESS_JSON_RE, '$1[REDACTED:address]$2');
  out = out.replace(ADDRESS_JSON_RE, '$1[REDACTED:address]$2');

  // 10) Natural-language secret disclosures
  out = out.replace(PROSE_SECRET_RE, (_m, kind, mid, quote, _value) => {
    const k = String(kind);
    const m = typeof mid === 'string' ? mid : '';
    const q = typeof quote === 'string' ? quote : '"';
    return `${k}${m}${q}[REDACTED:secret]${q}`;
  });

  // 11) Long hex strings (often tokens)
  out = out.replace(HEX_TOKEN_RE, '[REDACTED:hex_token]');

  return out;
}

export function jsonByteSize(value: unknown): number {
  const json = JSON.stringify(value);
  return new TextEncoder().encode(json).byteLength;
}

export interface RedactDeepOptions {
  /** Per-string max length (applied before redaction). */
  maxStringLength?: number;
  /** When true, unknown non-JSON-ish values are stringified. */
  coerceUnknownToString?: boolean;
}

/**
 * Deep-redact a JSON-ish value.
 *
 * - redacts every string value
 * - truncates long strings
 * - preserves object key order
 */
export function redactDeep(value: unknown, options?: RedactDeepOptions): unknown {
  const maxStringLength = options?.maxStringLength ?? 10_000;
  const coerceUnknownToString = options?.coerceUnknownToString ?? true;

  const seen = new WeakSet<object>();

  const walk = (v: unknown): unknown => {
    if (v === null || v === undefined) return v;

    const t = typeof v;
    if (t === 'string') {
      return redactText(truncate(v as string, maxStringLength));
    }
    if (t === 'number' || t === 'boolean') return v;
    if (t === 'bigint') return String(v);

    if (Array.isArray(v)) {
      return v.map(walk);
    }

    if (t === 'object') {
      const obj = v as Record<string, unknown>;

      if (seen.has(obj)) {
        return '[REDACTED:cycle]';
      }
      seen.add(obj);

      // Date handling (best-effort)
      if (v instanceof Date) {
        return v.toISOString();
      }

      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(obj)) {
        out[k] = walk(val);
      }
      return out;
    }

    // symbol/function/etc
    return coerceUnknownToString ? redactText(String(v)) : v;
  };

  return walk(value);
}
