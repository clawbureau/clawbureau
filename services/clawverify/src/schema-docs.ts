/**
 * Schema Documentation
 * CVF-US-006: Public docs and schema registry for developer integration
 *
 * This module provides:
 * - Schema definitions for all supported envelope types
 * - Example payloads for testing and integration
 * - Fail-closed validation rules
 */

import {
  ENVELOPE_VERSIONS,
  ENVELOPE_TYPES,
  ALGORITHMS,
  HASH_ALGORITHMS,
  type SignedEnvelope,
  type ArtifactPayload,
  type MessagePayload,
  type GatewayReceiptPayload,
} from './types';

/**
 * Schema field definition
 */
export interface SchemaField {
  name: string;
  type: string;
  required: boolean;
  description: string;
  allowedValues?: readonly string[];
}

/**
 * Schema definition with documentation
 */
export interface SchemaDefinition {
  id: string;
  name: string;
  description: string;
  version: string;
  status: 'active' | 'deprecated';
  fields: {
    envelope: SchemaField[];
    payload: SchemaField[];
  };
  failClosedRules: string[];
  example: unknown;
}

/**
 * Schema registry response
 */
export interface SchemaRegistryResponse {
  version: string;
  schemas: SchemaDefinition[];
  globalRules: {
    failClosedBehavior: string[];
    allowedVersions: readonly string[];
    allowedAlgorithms: readonly string[];
    allowedHashAlgorithms: readonly string[];
  };
}

/**
 * Individual schema response
 */
export interface SchemaDetailResponse {
  found: boolean;
  schema?: SchemaDefinition;
}

/**
 * Common envelope fields shared by all signed envelopes
 */
const COMMON_ENVELOPE_FIELDS: SchemaField[] = [
  {
    name: 'envelope_version',
    type: 'string',
    required: true,
    description: 'Version of the envelope format',
    allowedValues: ENVELOPE_VERSIONS,
  },
  {
    name: 'envelope_type',
    type: 'string',
    required: true,
    description: 'Type of the signed payload',
    allowedValues: ENVELOPE_TYPES,
  },
  {
    name: 'payload',
    type: 'object',
    required: true,
    description: 'The payload being signed (structure varies by envelope_type)',
  },
  {
    name: 'payload_hash_b64u',
    type: 'string',
    required: true,
    description: 'Base64url-encoded hash of JSON.stringify(payload)',
  },
  {
    name: 'hash_algorithm',
    type: 'string',
    required: true,
    description: 'Hash algorithm used for payload_hash_b64u',
    allowedValues: HASH_ALGORITHMS,
  },
  {
    name: 'signature_b64u',
    type: 'string',
    required: true,
    description: 'Base64url-encoded signature over payload_hash_b64u string',
  },
  {
    name: 'algorithm',
    type: 'string',
    required: true,
    description: 'Signature algorithm used',
    allowedValues: ALGORITHMS,
  },
  {
    name: 'signer_did',
    type: 'string',
    required: true,
    description: 'DID of the signer (did:key:... or did:web:...)',
  },
  {
    name: 'issued_at',
    type: 'string',
    required: true,
    description: 'ISO 8601 timestamp when the envelope was signed',
  },
];

/**
 * Global fail-closed rules that apply to all verification
 */
const GLOBAL_FAIL_CLOSED_RULES: string[] = [
  'Unknown envelope_version: REJECTED (code: UNKNOWN_ENVELOPE_VERSION)',
  'Unknown envelope_type: REJECTED (code: UNKNOWN_ENVELOPE_TYPE)',
  'Unknown algorithm: REJECTED (code: UNKNOWN_ALGORITHM)',
  'Unknown hash_algorithm: REJECTED (code: UNKNOWN_HASH_ALGORITHM)',
  'Invalid DID format: REJECTED (code: INVALID_DID_FORMAT)',
  'Malformed JSON: REJECTED (code: PARSE_ERROR)',
  'Missing required field: REJECTED (code: MISSING_REQUIRED_FIELD)',
  'Hash mismatch: REJECTED (code: HASH_MISMATCH)',
  'Signature verification failure: REJECTED (code: SIGNATURE_INVALID)',
];

/**
 * Example artifact envelope for documentation
 */
const ARTIFACT_EXAMPLE: SignedEnvelope<ArtifactPayload> = {
  envelope_version: '1',
  envelope_type: 'artifact_signature',
  payload: {
    artifact_version: '1',
    artifact_id: 'artifact_abc123xyz',
    artifact_type: 'code_review',
    content_hash_b64u: 'LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564',
    content_type: 'application/json',
    content_size_bytes: 2048,
    metadata: {
      repository: 'github.com/example/repo',
      commit_sha: 'abc123def456',
    },
  },
  payload_hash_b64u: 'kXB8aXqUzZl3rJ6N4mAhK9dVqXYnB2cF7pL0sT1wM5E',
  hash_algorithm: 'SHA-256',
  signature_b64u:
    'MEUCIQDxE2o_9nKr8LvnM4NnXqPbH8cJ2fK1aL3mY6pQ7sT0VwIgYkB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4',
  algorithm: 'Ed25519',
  signer_did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  issued_at: '2026-02-02T12:00:00Z',
};

/**
 * Example message envelope for documentation
 */
const MESSAGE_EXAMPLE: SignedEnvelope<MessagePayload> = {
  envelope_version: '1',
  envelope_type: 'message_signature',
  payload: {
    message_version: '1',
    message_type: 'account_binding',
    message: 'I authorize binding DID did:key:z6Mk... to account user@example.com',
    nonce: 'nonce_xyz789abc',
    audience: 'https://clawbureau.example.com',
    expires_at: '2026-02-02T13:00:00Z',
  },
  payload_hash_b64u: 'pQr8sT0uV1wX2yZ3aB4cD5eF6gH7iJ8kL9mN0oP1qR2',
  hash_algorithm: 'SHA-256',
  signature_b64u:
    'MEQCIH8jK9lM2nO3pQ4rS5tU6vW7xY8zA9bC0dE1fG2hI3jKAiB4lM5nO6pQ7rS8tU9vW0xY1zA2bC3dE4fG5hI6jK7lM8',
  algorithm: 'Ed25519',
  signer_did: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  issued_at: '2026-02-02T12:00:00Z',
};

/**
 * Example gateway receipt envelope for documentation
 */
const RECEIPT_EXAMPLE: SignedEnvelope<GatewayReceiptPayload> = {
  envelope_version: '1',
  envelope_type: 'gateway_receipt',
  payload: {
    receipt_version: '1',
    receipt_id: 'rcpt_abc123xyz789',
    gateway_id: 'gw_clawgateway_prod',
    provider: 'anthropic',
    model: 'claude-sonnet-4-20250514',
    request_hash_b64u: 'aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4c',
    response_hash_b64u: 'xY9zA0bC1dE2fG3hI4jK5lM6nO7pQ8rS9tU0vW1xY2z',
    tokens_input: 150,
    tokens_output: 500,
    latency_ms: 1234,
    timestamp: '2026-02-02T12:00:00Z',
    metadata: {
      client_id: 'agent_xyz',
      session_id: 'sess_abc123',
    },
  },
  payload_hash_b64u: 'zZ9yY8xX7wW6vV5uU4tT3sS2rR1qQ0pP9oO8nN7mM6l',
  hash_algorithm: 'SHA-256',
  signature_b64u:
    'MEUCIQCnN8oO9pP0qQ1rR2sS3tT4uU5vV6wW7xX8yY9zZ0aABwIgbB1cC2dD3eE4fF5gG6hH7iI8jJ9kK0lL1mM2nN3oO4p',
  algorithm: 'Ed25519',
  signer_did: 'did:key:z6MkrGQzLbqWwFzjg8S9T0vU1wX2yZ3aB4cD5eF6gH7iJ8kL',
  issued_at: '2026-02-02T12:00:00Z',
};

/**
 * Schema definitions for all supported envelope types
 */
const SCHEMA_DEFINITIONS: SchemaDefinition[] = [
  {
    id: 'artifact_signature',
    name: 'Artifact Signature',
    description:
      'Signed envelope for work artifacts (code, documents, media). Proves authorship and content integrity.',
    version: '1',
    status: 'active',
    fields: {
      envelope: COMMON_ENVELOPE_FIELDS,
      payload: [
        {
          name: 'artifact_version',
          type: 'string',
          required: true,
          description: 'Version of the artifact payload format',
          allowedValues: ['1'],
        },
        {
          name: 'artifact_id',
          type: 'string',
          required: true,
          description: 'Unique identifier for the artifact',
        },
        {
          name: 'artifact_type',
          type: 'string',
          required: true,
          description: 'Type of artifact (e.g., code_review, document, image)',
        },
        {
          name: 'content_hash_b64u',
          type: 'string',
          required: true,
          description: 'Base64url-encoded hash of the artifact content',
        },
        {
          name: 'content_type',
          type: 'string',
          required: true,
          description: 'MIME type of the artifact content',
        },
        {
          name: 'content_size_bytes',
          type: 'number',
          required: true,
          description: 'Size of the artifact content in bytes',
        },
        {
          name: 'metadata',
          type: 'object',
          required: false,
          description: 'Optional metadata about the artifact',
        },
      ],
    },
    failClosedRules: [
      ...GLOBAL_FAIL_CLOSED_RULES,
      'Invalid artifact_version: REJECTED',
      'Missing artifact_id: REJECTED',
      'Non-positive content_size_bytes: REJECTED',
    ],
    example: ARTIFACT_EXAMPLE,
  },
  {
    id: 'message_signature',
    name: 'Message Signature',
    description:
      'Signed message for DID binding and ownership proof. Used to bind DIDs to accounts or respond to challenges.',
    version: '1',
    status: 'active',
    fields: {
      envelope: COMMON_ENVELOPE_FIELDS,
      payload: [
        {
          name: 'message_version',
          type: 'string',
          required: true,
          description: 'Version of the message payload format',
          allowedValues: ['1'],
        },
        {
          name: 'message_type',
          type: 'string',
          required: true,
          description: 'Type of message being signed',
          allowedValues: ['account_binding', 'ownership_proof', 'challenge_response'],
        },
        {
          name: 'message',
          type: 'string',
          required: true,
          description: 'The message content being signed',
        },
        {
          name: 'nonce',
          type: 'string',
          required: true,
          description: 'Unique nonce to prevent replay attacks',
        },
        {
          name: 'audience',
          type: 'string',
          required: false,
          description: 'Intended audience for the message (e.g., service URL)',
        },
        {
          name: 'expires_at',
          type: 'string',
          required: false,
          description: 'ISO 8601 expiration timestamp for time-limited messages',
        },
      ],
    },
    failClosedRules: [
      ...GLOBAL_FAIL_CLOSED_RULES,
      'Invalid message_version: REJECTED',
      'Unknown message_type: REJECTED',
      'Missing nonce: REJECTED',
      'Expired (expires_at in past): REJECTED (code: EXPIRED)',
    ],
    example: MESSAGE_EXAMPLE,
  },
  {
    id: 'gateway_receipt',
    name: 'Gateway Receipt',
    description:
      'Proof-of-harness receipt from AI proxy gateways. Validates that requests were routed through a trusted gateway.',
    version: '1',
    status: 'active',
    fields: {
      envelope: COMMON_ENVELOPE_FIELDS,
      payload: [
        {
          name: 'receipt_version',
          type: 'string',
          required: true,
          description: 'Version of the receipt payload format',
          allowedValues: ['1'],
        },
        {
          name: 'receipt_id',
          type: 'string',
          required: true,
          description: 'Unique identifier for the receipt',
        },
        {
          name: 'gateway_id',
          type: 'string',
          required: true,
          description: 'Identifier of the gateway that issued the receipt',
        },
        {
          name: 'provider',
          type: 'string',
          required: true,
          description: 'AI provider (e.g., anthropic, openai)',
        },
        {
          name: 'model',
          type: 'string',
          required: true,
          description: 'Model identifier used for the request',
        },
        {
          name: 'request_hash_b64u',
          type: 'string',
          required: true,
          description: 'Base64url-encoded hash of the request',
        },
        {
          name: 'response_hash_b64u',
          type: 'string',
          required: true,
          description: 'Base64url-encoded hash of the response',
        },
        {
          name: 'tokens_input',
          type: 'number',
          required: true,
          description: 'Number of input tokens',
        },
        {
          name: 'tokens_output',
          type: 'number',
          required: true,
          description: 'Number of output tokens',
        },
        {
          name: 'latency_ms',
          type: 'number',
          required: true,
          description: 'Request latency in milliseconds',
        },
        {
          name: 'timestamp',
          type: 'string',
          required: true,
          description: 'ISO 8601 timestamp of the request',
        },
        {
          name: 'metadata',
          type: 'object',
          required: false,
          description: 'Optional metadata about the request',
        },
      ],
    },
    failClosedRules: [
      ...GLOBAL_FAIL_CLOSED_RULES,
      'Invalid receipt_version: REJECTED',
      'Missing receipt_id: REJECTED',
      'Missing gateway_id: REJECTED',
      'Negative tokens_input: REJECTED',
      'Negative tokens_output: REJECTED',
      'Negative latency_ms: REJECTED',
      'Invalid request_hash_b64u format: REJECTED',
      'Invalid response_hash_b64u format: REJECTED',
    ],
    example: RECEIPT_EXAMPLE,
  },
  {
    id: 'proof_bundle',
    name: 'Proof Bundle',
    description:
      'Composite proof containing URM, event chains, receipts, and attestations for trust tier computation.',
    version: '1',
    status: 'active',
    fields: {
      envelope: COMMON_ENVELOPE_FIELDS,
      payload: [
        {
          name: 'bundle_version',
          type: 'string',
          required: true,
          description: 'Version of the proof bundle format',
          allowedValues: ['1'],
        },
        {
          name: 'bundle_id',
          type: 'string',
          required: true,
          description: 'Unique identifier for the bundle',
        },
        {
          name: 'urm',
          type: 'object',
          required: false,
          description: 'Universal Resource Manifest (if present)',
        },
        {
          name: 'event_chain',
          type: 'array',
          required: false,
          description: 'Hash-chained event log entries',
        },
        {
          name: 'receipts',
          type: 'array',
          required: false,
          description: 'Gateway receipts for proof-of-harness',
        },
        {
          name: 'attestations',
          type: 'array',
          required: false,
          description: 'Owner and third-party attestations',
        },
      ],
    },
    failClosedRules: [
      ...GLOBAL_FAIL_CLOSED_RULES,
      'Invalid bundle_version: REJECTED',
      'Missing bundle_id: REJECTED',
      'At least one of urm, event_chain, receipts, or attestations required',
    ],
    example: {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload: {
        bundle_version: '1',
        bundle_id: 'bundle_abc123',
        event_chain: [],
        receipts: [],
      },
      payload_hash_b64u: 'example_hash',
      hash_algorithm: 'SHA-256',
      signature_b64u: 'example_signature',
      algorithm: 'Ed25519',
      signer_did: 'did:key:example',
      issued_at: '2026-02-02T12:00:00Z',
    },
  },
  {
    id: 'event_chain',
    name: 'Event Chain',
    description:
      'Hash-chained event log for tamper-evident audit trails. Enforces run_id consistency.',
    version: '1',
    status: 'active',
    fields: {
      envelope: COMMON_ENVELOPE_FIELDS,
      payload: [
        {
          name: 'chain_version',
          type: 'string',
          required: true,
          description: 'Version of the event chain format',
          allowedValues: ['1'],
        },
        {
          name: 'run_id',
          type: 'string',
          required: true,
          description: 'Unique identifier for the run/session',
        },
        {
          name: 'events',
          type: 'array',
          required: true,
          description: 'Array of hash-chained events',
        },
        {
          name: 'chain_root_hash_b64u',
          type: 'string',
          required: true,
          description: 'Root hash of the event chain',
        },
      ],
    },
    failClosedRules: [
      ...GLOBAL_FAIL_CLOSED_RULES,
      'Invalid chain_version: REJECTED',
      'Missing run_id: REJECTED',
      'Empty events array: REJECTED',
      'Hash chain break detected: REJECTED',
      'Inconsistent run_id in events: REJECTED',
    ],
    example: {
      envelope_version: '1',
      envelope_type: 'event_chain',
      payload: {
        chain_version: '1',
        run_id: 'run_abc123',
        events: [],
        chain_root_hash_b64u: 'example_root_hash',
      },
      payload_hash_b64u: 'example_hash',
      hash_algorithm: 'SHA-256',
      signature_b64u: 'example_signature',
      algorithm: 'Ed25519',
      signer_did: 'did:key:example',
      issued_at: '2026-02-02T12:00:00Z',
    },
  },
  {
    id: 'owner_attestation',
    name: 'Owner Attestation',
    description:
      'Attestation from an owner/operator binding identity to a DID. Used for sybil resistance.',
    version: '1',
    status: 'active',
    fields: {
      envelope: COMMON_ENVELOPE_FIELDS,
      payload: [
        {
          name: 'attestation_version',
          type: 'string',
          required: true,
          description: 'Version of the attestation format',
          allowedValues: ['1'],
        },
        {
          name: 'attestation_id',
          type: 'string',
          required: true,
          description: 'Unique identifier for the attestation',
        },
        {
          name: 'subject_did',
          type: 'string',
          required: true,
          description: 'DID of the subject being attested',
        },
        {
          name: 'provider_ref',
          type: 'string',
          required: false,
          description: 'Reference to identity provider',
        },
        {
          name: 'expires_at',
          type: 'string',
          required: false,
          description: 'ISO 8601 expiration timestamp',
        },
      ],
    },
    failClosedRules: [
      ...GLOBAL_FAIL_CLOSED_RULES,
      'Invalid attestation_version: REJECTED',
      'Missing attestation_id: REJECTED',
      'Invalid subject_did format: REJECTED',
      'Expired (expires_at in past): REJECTED (code: EXPIRED)',
    ],
    example: {
      envelope_version: '1',
      envelope_type: 'owner_attestation',
      payload: {
        attestation_version: '1',
        attestation_id: 'attest_abc123',
        subject_did: 'did:key:z6MkSubject...',
        provider_ref: 'github.com/example-user',
        expires_at: '2027-02-02T12:00:00Z',
      },
      payload_hash_b64u: 'example_hash',
      hash_algorithm: 'SHA-256',
      signature_b64u: 'example_signature',
      algorithm: 'Ed25519',
      signer_did: 'did:key:example',
      issued_at: '2026-02-02T12:00:00Z',
    },
  },
  {
    id: 'commit_proof',
    name: 'Commit Proof',
    description:
      'Proof that a commit was made by a specific DID. Used to verify agent work in repositories.',
    version: '1',
    status: 'active',
    fields: {
      envelope: COMMON_ENVELOPE_FIELDS,
      payload: [
        {
          name: 'proof_version',
          type: 'string',
          required: true,
          description: 'Version of the commit proof format',
          allowedValues: ['1'],
        },
        {
          name: 'repo_claim_id',
          type: 'string',
          required: true,
          description: 'Reference to clawclaim repo claim',
        },
        {
          name: 'commit_sha',
          type: 'string',
          required: true,
          description: 'Git commit SHA',
        },
        {
          name: 'repository',
          type: 'string',
          required: true,
          description: 'Repository identifier (e.g., github.com/org/repo)',
        },
        {
          name: 'branch',
          type: 'string',
          required: false,
          description: 'Branch name',
        },
      ],
    },
    failClosedRules: [
      ...GLOBAL_FAIL_CLOSED_RULES,
      'Invalid proof_version: REJECTED',
      'Missing repo_claim_id: REJECTED',
      'Invalid commit_sha format: REJECTED',
      'Repo claim not found in clawclaim: REJECTED',
    ],
    example: {
      envelope_version: '1',
      envelope_type: 'commit_proof',
      payload: {
        proof_version: '1',
        repo_claim_id: 'claim_abc123',
        commit_sha: 'abc123def456789',
        repository: 'github.com/example/repo',
        branch: 'main',
      },
      payload_hash_b64u: 'example_hash',
      hash_algorithm: 'SHA-256',
      signature_b64u: 'example_signature',
      algorithm: 'Ed25519',
      signer_did: 'did:key:example',
      issued_at: '2026-02-02T12:00:00Z',
    },
  },
  {
    id: 'scoped_token',
    name: 'Scoped Token',
    description:
      'Signed token with specific scopes and audience for authorization. Used for service-to-service auth.',
    version: '1',
    status: 'active',
    fields: {
      envelope: COMMON_ENVELOPE_FIELDS,
      payload: [
        {
          name: 'token_version',
          type: 'string',
          required: true,
          description: 'Version of the token format',
          allowedValues: ['1'],
        },
        {
          name: 'token_id',
          type: 'string',
          required: true,
          description: 'Unique identifier for the token',
        },
        {
          name: 'scope',
          type: 'array',
          required: true,
          description: 'Array of permission scopes',
        },
        {
          name: 'audience',
          type: 'string',
          required: true,
          description: 'Intended audience for the token',
        },
        {
          name: 'owner_ref',
          type: 'string',
          required: false,
          description: 'Reference to the token owner',
        },
        {
          name: 'expires_at',
          type: 'string',
          required: true,
          description: 'ISO 8601 expiration timestamp',
        },
      ],
    },
    failClosedRules: [
      ...GLOBAL_FAIL_CLOSED_RULES,
      'Invalid token_version: REJECTED',
      'Missing token_id: REJECTED',
      'Empty scope array: REJECTED',
      'Missing audience: REJECTED',
      'Missing expires_at: REJECTED',
      'Expired (expires_at in past): REJECTED (code: EXPIRED)',
    ],
    example: {
      envelope_version: '1',
      envelope_type: 'scoped_token',
      payload: {
        token_version: '1',
        token_id: 'tok_abc123',
        scope: ['read:artifacts', 'write:artifacts'],
        audience: 'https://api.clawbureau.example.com',
        owner_ref: 'user_xyz789',
        expires_at: '2026-02-02T13:00:00Z',
      },
      payload_hash_b64u: 'example_hash',
      hash_algorithm: 'SHA-256',
      signature_b64u: 'example_signature',
      algorithm: 'Ed25519',
      signer_did: 'did:key:example',
      issued_at: '2026-02-02T12:00:00Z',
    },
  },
];

/**
 * Get the full schema registry
 */
export function getSchemaRegistry(): SchemaRegistryResponse {
  return {
    version: '1',
    schemas: SCHEMA_DEFINITIONS,
    globalRules: {
      failClosedBehavior: GLOBAL_FAIL_CLOSED_RULES,
      allowedVersions: ENVELOPE_VERSIONS,
      allowedAlgorithms: ALGORITHMS,
      allowedHashAlgorithms: HASH_ALGORITHMS,
    },
  };
}

/**
 * Get a single schema by ID
 */
export function getSchemaById(schemaId: string): SchemaDetailResponse {
  const schema = SCHEMA_DEFINITIONS.find((s) => s.id === schemaId);
  if (!schema) {
    return { found: false };
  }
  return { found: true, schema };
}

/**
 * Get list of all schema IDs
 */
export function getSchemaIds(): string[] {
  return SCHEMA_DEFINITIONS.map((s) => s.id);
}

/**
 * Schema allowlist response with examples
 * CVF-US-009: Schema registry allowlist
 */
export interface SchemaAllowlistResponse {
  /** API version */
  version: string;
  /** When the allowlist was last updated */
  updated_at: string;
  /** Total number of allowlisted schemas */
  total_schemas: number;
  /** Allowlisted schema entries with examples */
  schemas: SchemaAllowlistWithExample[];
  /** Fail-closed validation rules */
  validation_rules: string[];
}

/**
 * Schema allowlist entry with example payload
 */
export interface SchemaAllowlistWithExample {
  /** Schema identifier */
  schema_id: string;
  /** Human-readable name */
  name: string;
  /** Schema description */
  description: string;
  /** Current active version */
  current_version: string;
  /** All supported versions */
  supported_versions: string[];
  /** Schema status */
  status: 'active' | 'deprecated';
  /** Example payload for this schema */
  example: unknown;
  /** Fail-closed rules specific to this schema */
  fail_closed_rules: string[];
}

/**
 * Get the schema allowlist with examples for each schema
 * This is the authoritative list for deterministic validation
 */
export function getSchemaAllowlist(): SchemaAllowlistResponse {
  const schemasWithExamples: SchemaAllowlistWithExample[] = SCHEMA_DEFINITIONS.map((schema) => ({
    schema_id: schema.id,
    name: schema.name,
    description: schema.description,
    current_version: schema.version,
    supported_versions: [schema.version], // Currently only version 1 is supported
    status: schema.status,
    example: schema.example,
    fail_closed_rules: schema.failClosedRules,
  }));

  return {
    version: '1',
    updated_at: '2026-02-02T00:00:00Z',
    total_schemas: schemasWithExamples.length,
    schemas: schemasWithExamples,
    validation_rules: [
      'Unknown schema_id: REJECTED (code: UNKNOWN_SCHEMA_ID)',
      'Unknown schema version: REJECTED (code: UNKNOWN_SCHEMA_VERSION)',
      'Deprecated schema: ACCEPTED with warning (code: DEPRECATED_SCHEMA)',
      'Missing required envelope fields: REJECTED (code: MISSING_REQUIRED_FIELD)',
      'Invalid payload structure: REJECTED (code: MALFORMED_ENVELOPE)',
    ],
  };
}

/**
 * Get example payload for a specific schema ID
 * @param schemaId - The schema ID to get example for
 * @returns Example payload or undefined if not found
 */
export function getSchemaExample(schemaId: string): unknown | undefined {
  const schema = SCHEMA_DEFINITIONS.find((s) => s.id === schemaId);
  return schema?.example;
}
