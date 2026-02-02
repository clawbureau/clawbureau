/**
 * Schema Registry
 * Fail-closed validation: reject any unknown version/type/algorithm
 */

import {
  ENVELOPE_VERSIONS,
  ENVELOPE_TYPES,
  ALGORITHMS,
  HASH_ALGORITHMS,
  type EnvelopeVersion,
  type EnvelopeType,
  type Algorithm,
  type HashAlgorithm,
} from './types';

/**
 * Check if an envelope version is allowlisted
 */
export function isAllowedVersion(version: unknown): version is EnvelopeVersion {
  return (
    typeof version === 'string' &&
    (ENVELOPE_VERSIONS as readonly string[]).includes(version)
  );
}

/**
 * Check if an envelope type is allowlisted
 */
export function isAllowedType(type: unknown): type is EnvelopeType {
  return (
    typeof type === 'string' &&
    (ENVELOPE_TYPES as readonly string[]).includes(type)
  );
}

/**
 * Check if a signature algorithm is allowlisted
 */
export function isAllowedAlgorithm(algorithm: unknown): algorithm is Algorithm {
  return (
    typeof algorithm === 'string' &&
    (ALGORITHMS as readonly string[]).includes(algorithm)
  );
}

/**
 * Check if a hash algorithm is allowlisted
 */
export function isAllowedHashAlgorithm(
  hashAlgorithm: unknown
): hashAlgorithm is HashAlgorithm {
  return (
    typeof hashAlgorithm === 'string' &&
    (HASH_ALGORITHMS as readonly string[]).includes(hashAlgorithm)
  );
}

/**
 * Validate DID format (did:key:... or did:web:...)
 */
export function isValidDidFormat(did: unknown): did is string {
  if (typeof did !== 'string') return false;
  // Basic DID format validation
  return /^did:(key|web):[a-zA-Z0-9._%-]+$/.test(did);
}

/**
 * Validate ISO 8601 date format
 */
export function isValidIsoDate(date: unknown): date is string {
  if (typeof date !== 'string') return false;
  const parsed = Date.parse(date);
  return !isNaN(parsed);
}

/**
 * Validate base64url string format
 */
export function isValidBase64Url(str: unknown): str is string {
  if (typeof str !== 'string') return false;
  // Base64url uses A-Z, a-z, 0-9, -, _
  return /^[A-Za-z0-9_-]+$/.test(str);
}
