/**
 * Scoped Token (CST) validation
 *
 * Validates JWT (JWS compact serialization) signed with Ed25519 (alg=EdDSA).
 * Token claims follow packages/schema/auth/scoped_token_claims.v1.json.
 */

import {
  hasRequiredScope,
  normalizeAudience,
  type ScopedTokenClaimsV1,
  validateScopedTokenClaimsShape,
} from '../../../packages/identity-auth/src/index';
import type { Env } from './types';
import { sha256, base64urlDecode, importEd25519PublicKey, verifyEd25519 } from './crypto';

export type ScopedTokenClaims = ScopedTokenClaimsV1;

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

function audMatches(aud: string | string[], expectedAudiences: string[]): boolean {
  const normalizedAud = normalizeAudience(aud);
  return normalizedAud.some((value) => expectedAudiences.includes(value));
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

  if (!validateScopedTokenClaimsShape(payload)) {
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
  if (!hasRequiredScope(payload.scope, requiredScopes, provider)) {
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
