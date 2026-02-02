/**
 * Scoped Token (CST) validation
 *
 * Validates JWT (JWS compact serialization) signed with Ed25519 (alg=EdDSA).
 * Token claims follow packages/schema/auth/scoped_token_claims.v1.json.
 */

import type { Env } from './types';
import { sha256, base64urlDecode, importEd25519PublicKey, verifyEd25519 } from './crypto';

export interface ScopedTokenClaims {
  token_version: '1';
  sub: string;
  aud: string | string[];
  scope: string[];
  iat: number;
  exp: number;
  owner_ref?: string;
  policy_hash_b64u?: string;
  token_scope_hash_b64u?: string;
  spend_cap?: number;
  mission_id?: string;
  jti?: string;
  nonce?: string;
}

export interface ScopedTokenValidationOk {
  valid: true;
  claims: ScopedTokenClaims;
  token_hash: string;
}

export interface ScopedTokenValidationError {
  valid: false;
  status: number;
  code: string;
  message: string;
}

let cachedIssuerPublicKey: CryptoKey | null = null;
let cachedIssuerKeyRaw: string | null = null;

async function getIssuerPublicKey(env: Env): Promise<CryptoKey | null> {
  if (!env.CST_ISSUER_PUBLIC_KEY) return null;

  if (cachedIssuerPublicKey && cachedIssuerKeyRaw === env.CST_ISSUER_PUBLIC_KEY) {
    return cachedIssuerPublicKey;
  }

  const key = await importEd25519PublicKey(env.CST_ISSUER_PUBLIC_KEY);
  cachedIssuerPublicKey = key;
  cachedIssuerKeyRaw = env.CST_ISSUER_PUBLIC_KEY;
  return key;
}

function decodeJsonSegment(segmentB64u: string): unknown {
  const bytes = base64urlDecode(segmentB64u);
  const json = new TextDecoder().decode(bytes);
  return JSON.parse(json) as unknown;
}

function isNonEmptyStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((s) => typeof s === 'string' && s.length > 0)
  );
}

function normalizeAudience(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value) && value.every((v) => typeof v === 'string')) {
    return value as string[];
  }
  return [];
}

function audMatches(aud: string | string[], expectedAudiences: string[]): boolean {
  const audList = typeof aud === 'string' ? [aud] : aud;
  return audList.some((a) => expectedAudiences.includes(a));
}

function hasRequiredScope(
  scopes: string[],
  provider: string,
  requiredScopes: string[]
): boolean {
  // Global wildcards
  if (scopes.includes('*') || scopes.includes('proxy:*') || scopes.includes('clawproxy:*')) {
    return true;
  }

  // Explicit required scopes
  for (const req of requiredScopes) {
    if (scopes.includes(req)) return true;
  }

  // Provider-granular scopes (future-friendly)
  if (scopes.includes(`proxy:provider:${provider}`)) return true;
  if (scopes.includes(`proxy:call:${provider}`)) return true;
  if (scopes.includes(`clawproxy:provider:${provider}`)) return true;
  if (scopes.includes(`clawproxy:call:${provider}`)) return true;

  return false;
}

function validateClaimsShape(payload: unknown): payload is ScopedTokenClaims {
  if (typeof payload !== 'object' || payload === null) return false;
  const p = payload as Record<string, unknown>;

  if (p.token_version !== '1') return false;
  if (typeof p.sub !== 'string') return false;
  if (normalizeAudience(p.aud).length === 0) return false;
  if (!isNonEmptyStringArray(p.scope)) return false;
  if (typeof p.iat !== 'number' || !Number.isFinite(p.iat)) return false;
  if (typeof p.exp !== 'number' || !Number.isFinite(p.exp)) return false;

  return true;
}

/**
 * Validate a CST token.
 *
 * - Requires EdDSA (Ed25519) signature
 * - Validates audience, expiry, and required scope
 */
export async function validateScopedToken(options: {
  token: string;
  env: Env;
  expectedAudiences: string[];
  provider: string;
  requiredScopes: string[];
}): Promise<ScopedTokenValidationOk | ScopedTokenValidationError> {
  const { token, env, expectedAudiences, provider, requiredScopes } = options;

  const token_hash = await sha256(token);

  const parts = token.split('.');
  if (parts.length !== 3) {
    return {
      valid: false,
      status: 401,
      code: 'TOKEN_MALFORMED',
      message: 'CST token must be a JWT (header.payload.signature)',
    };
  }

  const headerB64u = parts[0]!;
  const payloadB64u = parts[1]!;
  const signatureB64u = parts[2]!;

  // Decode header
  let header: unknown;
  try {
    header = decodeJsonSegment(headerB64u);
  } catch {
    return {
      valid: false,
      status: 401,
      code: 'TOKEN_MALFORMED',
      message: 'Invalid JWT header encoding',
    };
  }

  if (typeof header !== 'object' || header === null) {
    return {
      valid: false,
      status: 401,
      code: 'TOKEN_MALFORMED',
      message: 'Invalid JWT header',
    };
  }

  const h = header as Record<string, unknown>;
  if (h.alg !== 'EdDSA') {
    return {
      valid: false,
      status: 401,
      code: 'TOKEN_UNSUPPORTED_ALG',
      message: 'Unsupported token algorithm (expected EdDSA)',
    };
  }

  // Decode payload
  let payload: unknown;
  try {
    payload = decodeJsonSegment(payloadB64u);
  } catch {
    return {
      valid: false,
      status: 401,
      code: 'TOKEN_MALFORMED',
      message: 'Invalid JWT payload encoding',
    };
  }

  if (!validateClaimsShape(payload)) {
    return {
      valid: false,
      status: 401,
      code: 'TOKEN_INVALID_CLAIMS',
      message: 'Token claims do not match scoped_token_claims.v1 schema',
    };
  }

  // Validate audience
  if (!audMatches(payload.aud, expectedAudiences)) {
    return {
      valid: false,
      status: 403,
      code: 'TOKEN_BAD_AUDIENCE',
      message: `Token audience not allowed (expected one of: ${expectedAudiences.join(', ')})`,
    };
  }

  // Validate expiry
  const nowSec = Math.floor(Date.now() / 1000);
  if (payload.exp <= nowSec) {
    return {
      valid: false,
      status: 401,
      code: 'TOKEN_EXPIRED',
      message: 'Token has expired',
    };
  }

  // Validate scope
  if (!hasRequiredScope(payload.scope, provider, requiredScopes)) {
    return {
      valid: false,
      status: 403,
      code: 'TOKEN_INSUFFICIENT_SCOPE',
      message: 'Token does not grant required scope for this operation',
    };
  }

  // Verify signature (fail closed if key missing)
  const issuerKey = await getIssuerPublicKey(env);
  if (!issuerKey) {
    return {
      valid: false,
      status: 503,
      code: 'TOKEN_VERIFICATION_KEY_MISSING',
      message: 'CST issuer public key is not configured (CST_ISSUER_PUBLIC_KEY)',
    };
  }

  const signingInput = `${headerB64u}.${payloadB64u}`;
  let signatureValid: boolean;
  try {
    signatureValid = await verifyEd25519(issuerKey, signatureB64u, signingInput);
  } catch {
    return {
      valid: false,
      status: 401,
      code: 'TOKEN_SIGNATURE_INVALID',
      message: 'Token signature verification failed',
    };
  }

  if (!signatureValid) {
    return {
      valid: false,
      status: 401,
      code: 'TOKEN_SIGNATURE_INVALID',
      message: 'Token signature verification failed',
    };
  }

  return {
    valid: true,
    claims: payload,
    token_hash,
  };
}
