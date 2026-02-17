/**
 * Schema Registry
 * Fail-closed validation: reject any unknown version/type/algorithm
 * CVF-US-009: Schema registry allowlist for deterministic validation
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
 * Schema allowlist entry - defines an allowed schema ID with its version
 */
export interface SchemaAllowlistEntry {
  /** Schema identifier (e.g., 'artifact_signature') */
  schema_id: string;
  /** Current active version */
  version: string;
  /** All supported versions for this schema */
  supported_versions: string[];
  /** Schema status */
  status: 'active' | 'deprecated';
  /** When this schema was added to the allowlist */
  added_at: string;
  /** Optional deprecation date for deprecated schemas */
  deprecated_at?: string;
}

/**
 * Allowlisted schema IDs and their versions
 * This is the authoritative list - any schema not in this list is rejected
 */
export const SCHEMA_ALLOWLIST: readonly SchemaAllowlistEntry[] = [
  {
    schema_id: 'artifact_signature',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-01-01T00:00:00Z',
  },
  {
    schema_id: 'message_signature',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-01-01T00:00:00Z',
  },
  {
    schema_id: 'gateway_receipt',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-01-01T00:00:00Z',
  },
  {
    schema_id: 'tool_receipt',
    version: '2',
    supported_versions: ['1', '2'],
    status: 'active',
    added_at: '2026-02-17T00:00:00Z',
  },
  {
    schema_id: 'tool_receipt_envelope',
    version: '2',
    supported_versions: ['1', '2'],
    status: 'active',
    added_at: '2026-02-17T00:00:00Z',
  },
  {
    schema_id: 'co_signature',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-17T00:00:00Z',
  },
  {
    schema_id: 'selective_disclosure',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-17T00:00:00Z',
  },
  {
    schema_id: 'aggregate_bundle',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-17T00:00:00Z',
  },
  {
    schema_id: 'aggregate_bundle_envelope',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-17T00:00:00Z',
  },
  {
    schema_id: 'vir_receipt',
    version: '2',
    supported_versions: ['1', '2'],
    status: 'active',
    added_at: '2026-02-15T00:00:00Z',
  },
  {
    schema_id: 'coverage_attestation',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-17T00:00:00Z',
  },
  {
    schema_id: 'binary_semantic_evidence',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-17T00:00:00Z',
  },
  {
    schema_id: 'web_receipt',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-11T00:00:00Z',
  },
  {
    schema_id: 'proof_bundle',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-01-01T00:00:00Z',
  },
  {
    schema_id: 'event_chain',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-01-01T00:00:00Z',
  },
  {
    schema_id: 'owner_attestation',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-01-01T00:00:00Z',
  },
  {
    schema_id: 'commit_proof',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-01-01T00:00:00Z',
  },
  {
    schema_id: 'execution_attestation',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-01-01T00:00:00Z',
  },
  {
    schema_id: 'prompt_pack',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-09T00:00:00Z',
  },
  {
    schema_id: 'system_prompt_report',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-09T00:00:00Z',
  },
  {
    schema_id: 'derivation_attestation',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-11T00:00:00Z',
  },
  {
    schema_id: 'audit_result_attestation',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-11T00:00:00Z',
  },
  {
    schema_id: 'export_bundle',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-02-11T00:00:00Z',
  },
  {
    schema_id: 'scoped_token',
    version: '1',
    supported_versions: ['1'],
    status: 'active',
    added_at: '2026-01-01T00:00:00Z',
  },
] as const;

/**
 * Map of schema_id to allowlist entry for O(1) lookup
 */
const SCHEMA_ALLOWLIST_MAP: Map<string, SchemaAllowlistEntry> = new Map(
  SCHEMA_ALLOWLIST.map((entry) => [entry.schema_id, entry])
);

/**
 * Canonical schema URI mapping for resolver normalization.
 *
 * Policy:
 * - Fully-qualified URI IDs only
 * - Explicit finite alias map for legacy v1 tool schema URIs
 * - Unknown schema URI => fail-closed (UNKNOWN_SCHEMA_ID)
 */
const CANONICAL_SCHEMA_URI_TO_ALLOWLIST_ID: Readonly<Record<string, string>> = {
  'https://schemas.clawbureau.com/poh/tool_receipt.v1.json': 'tool_receipt',
  'https://schemas.clawbureau.com/poh/tool_receipt_envelope.v1.json': 'tool_receipt_envelope',
  'https://schemas.clawbureau.org/claw.poh.tool_receipt.v2.json': 'tool_receipt',
  'https://schemas.clawbureau.org/claw.poh.tool_receipt_envelope.v2.json': 'tool_receipt_envelope',
  'https://schemas.clawbureau.org/claw.poh.co_signature.v1.json': 'co_signature',
  'https://schemas.clawbureau.org/claw.poh.selective_disclosure.v1.json': 'selective_disclosure',
  'https://schemas.clawbureau.org/claw.poh.aggregate_bundle.v1.json': 'aggregate_bundle',
  'https://schemas.clawbureau.org/claw.poh.aggregate_bundle_envelope.v1.json': 'aggregate_bundle_envelope',
};

const SCHEMA_URI_ALIAS_TO_CANONICAL: Readonly<Record<string, string>> = {
  'https://schemas.clawbureau.org/claw.poh.tool_receipt.v1.json':
    'https://schemas.clawbureau.com/poh/tool_receipt.v1.json',
  'https://schemas.clawbureau.org/claw.poh.tool_receipt_envelope.v1.json':
    'https://schemas.clawbureau.com/poh/tool_receipt_envelope.v1.json',
};

export function canonicalizeSchemaUri(schemaUri: unknown): string | null {
  if (typeof schemaUri !== 'string') return null;
  if (schemaUri in SCHEMA_URI_ALIAS_TO_CANONICAL) {
    return SCHEMA_URI_ALIAS_TO_CANONICAL[schemaUri]!;
  }
  if (schemaUri in CANONICAL_SCHEMA_URI_TO_ALLOWLIST_ID) {
    return schemaUri;
  }
  return null;
}

function resolveAllowlistSchemaId(schemaIdOrUri: string): string | null {
  if (/^https?:\/\//.test(schemaIdOrUri)) {
    const canonical = canonicalizeSchemaUri(schemaIdOrUri);
    if (!canonical) return null;
    return CANONICAL_SCHEMA_URI_TO_ALLOWLIST_ID[canonical] ?? null;
  }
  return schemaIdOrUri;
}

/**
 * Check if a schema ID is in the allowlist
 * @param schemaId - The schema ID to check
 * @returns true if the schema ID is allowlisted, false otherwise
 */
export function isAllowlistedSchemaId(schemaId: unknown): schemaId is string {
  if (typeof schemaId !== 'string') return false;
  const resolved = resolveAllowlistSchemaId(schemaId);
  return typeof resolved === 'string' && SCHEMA_ALLOWLIST_MAP.has(resolved);
}

/**
 * Check if a schema ID + version combination is allowlisted
 * @param schemaId - The schema ID to check
 * @param version - The version to check
 * @returns true if the combination is allowlisted, false otherwise
 */
export function isAllowlistedSchemaVersion(
  schemaId: string,
  version: string
): boolean {
  const entry = SCHEMA_ALLOWLIST_MAP.get(schemaId);
  if (!entry) return false;
  return entry.supported_versions.includes(version);
}

/**
 * Get the allowlist entry for a schema ID
 * @param schemaId - The schema ID to look up
 * @returns The allowlist entry or undefined if not found
 */
export function getSchemaAllowlistEntry(
  schemaId: string
): SchemaAllowlistEntry | undefined {
  return SCHEMA_ALLOWLIST_MAP.get(schemaId);
}

/**
 * Get all allowlisted schema IDs
 * @returns Array of all allowlisted schema IDs
 */
export function getAllowlistedSchemaIds(): string[] {
  return Array.from(SCHEMA_ALLOWLIST_MAP.keys());
}

/**
 * Validate schema ID and version against the allowlist
 * Returns detailed error information for fail-closed behavior
 */
export interface SchemaValidationResult {
  valid: boolean;
  schema_id?: string;
  version?: string;
  error_code?: 'UNKNOWN_SCHEMA_ID' | 'UNKNOWN_SCHEMA_VERSION' | 'DEPRECATED_SCHEMA';
  error_message?: string;
}

/**
 * Validate a schema ID and version against the allowlist
 * @param schemaId - The schema ID to validate
 * @param version - The version to validate (optional, defaults to checking if ID exists)
 * @returns Validation result with error details if invalid
 */
export function validateSchemaAllowlist(
  schemaId: string,
  version?: string
): SchemaValidationResult {
  const resolvedSchemaId = resolveAllowlistSchemaId(schemaId);

  // Check if schema ID is allowlisted
  if (!resolvedSchemaId || !SCHEMA_ALLOWLIST_MAP.has(resolvedSchemaId)) {
    return {
      valid: false,
      schema_id: schemaId,
      error_code: 'UNKNOWN_SCHEMA_ID',
      error_message: `Schema ID '${schemaId}' is not in the allowlist. Allowlisted schemas: ${getAllowlistedSchemaIds().join(', ')}`,
    };
  }

  const entry = getSchemaAllowlistEntry(resolvedSchemaId)!;

  // Check if version is provided and valid
  if (version !== undefined) {
    if (!entry.supported_versions.includes(version)) {
      return {
        valid: false,
        schema_id: resolvedSchemaId,
        version: version,
        error_code: 'UNKNOWN_SCHEMA_VERSION',
        error_message: `Version '${version}' is not supported for schema '${schemaId}'. Supported versions: ${entry.supported_versions.join(', ')}`,
      };
    }
  }

  // Check if schema is deprecated (warning, but still valid)
  if (entry.status === 'deprecated') {
    return {
      valid: true,
      schema_id: resolvedSchemaId,
      version: version ?? entry.version,
      error_code: 'DEPRECATED_SCHEMA',
      error_message: `Schema '${schemaId}' is deprecated as of ${entry.deprecated_at}`,
    };
  }

  return {
    valid: true,
    schema_id: resolvedSchemaId,
    version: version ?? entry.version,
  };
}

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
