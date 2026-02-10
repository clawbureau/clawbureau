/**
 * Work Policy Contract (WPC) enforcement
 *
 * WPCs define enterprise policy constraints for confidential runs:
 * - Provider/model allowlists
 * - Field redaction rules
 * - Confidentiality mode requirements
 */

import type { Env, Provider, ReceiptPrivacyMode } from './types';
import type { RedactionRule, WorkPolicyContractV1 } from './wpc';
import { fetchWpcFromRegistry, isWpcHashB64u } from './wpc';

/**
 * Policy header for Work Policy Contract
 */
export const POLICY_HEADER = 'X-Policy-Hash';
export const CONFIDENTIAL_MODE_HEADER = 'X-Confidential-Mode';
export const PRIVACY_MODE_HEADER = 'X-Receipt-Privacy-Mode';

/**
 * Result of policy extraction from request
 */
export interface PolicyExtractionResult {
  /** Whether confidential mode is enabled */
  confidentialMode: boolean;
  /** Policy hash if provided */
  policyHash?: string;
  /** Parsed policy (fetched/verified from registry) */
  policy?: WorkPolicyContractV1;

  /** Error if policy is invalid or missing when required */
  error?: string;
  /** Structured error code (for HTTP responses) */
  errorCode?: string;
  /** HTTP status to return when failing closed */
  errorStatus?: number;

  /** Receipt privacy mode requested/effective (defaults to hash_only) */
  privacyMode: ReceiptPrivacyMode;
}

/**
 * Result of policy enforcement check
 */
export interface PolicyEnforcementResult {
  /** Whether the request is allowed under the policy */
  allowed: boolean;
  /** Error message if not allowed */
  error?: string;
  /** Error code for structured responses */
  errorCode?: string;
}

/**
 * In-memory policy store (demo purposes)
 * In production, policies are fetched from clawcontrols (WPC registry).
 */
const DEMO_POLICIES: Map<string, WorkPolicyContractV1> = new Map();

/**
 * Register a demo policy for testing.
 */
export function registerDemoPolicy(policyHashB64u: string, policy: WorkPolicyContractV1): void {
  DEMO_POLICIES.set(policyHashB64u, policy);
}

function resolvePrivacyMode(
  request: Request,
  confidentialMode: boolean,
  policy?: WorkPolicyContractV1
): ReceiptPrivacyMode {
  const header = request.headers.get(PRIVACY_MODE_HEADER);

  const headerMode: ReceiptPrivacyMode | null =
    header === 'hash_only' || header === 'encrypted' ? header : null;

  const policyMode: ReceiptPrivacyMode | null =
    policy?.receipt_privacy_mode === 'hash_only' || policy?.receipt_privacy_mode === 'encrypted'
      ? policy.receipt_privacy_mode
      : null;

  // Default to hash_only (most private)
  let effective: ReceiptPrivacyMode = headerMode ?? policyMode ?? 'hash_only';

  // If policy explicitly forces hash_only, do not allow encrypted.
  if (policyMode === 'hash_only' && effective === 'encrypted') {
    effective = 'hash_only';
  }

  // In confidential mode, encrypted payloads are not allowed.
  // This ensures prompts are never stored in recoverable form.
  if (confidentialMode && effective === 'encrypted') {
    effective = 'hash_only';
  }

  return effective;
}

/**
 * Extract policy information from request headers.
 */
export async function extractPolicyFromHeaders(
  request: Request,
  env: Env,
  options?: { policyHashOverride?: string }
): Promise<PolicyExtractionResult> {
  const confidentialModeHeader = request.headers.get(CONFIDENTIAL_MODE_HEADER);
  const policyHashHeader = request.headers.get(POLICY_HEADER) ?? undefined;

  // Confidential mode is enabled if header is present and truthy
  const confidentialMode = confidentialModeHeader === 'true' || confidentialModeHeader === '1';

  const headerPolicyHash =
    typeof policyHashHeader === 'string' && policyHashHeader.trim().length > 0
      ? policyHashHeader.trim()
      : undefined;

  const overridePolicyHash =
    typeof options?.policyHashOverride === 'string' && options.policyHashOverride.trim().length > 0
      ? options.policyHashOverride.trim()
      : undefined;

  // If a policy hash is pinned into the CST, treat it as authoritative.
  // If the caller also supplies X-Policy-Hash, it must match.
  if (overridePolicyHash && headerPolicyHash && headerPolicyHash !== overridePolicyHash) {
    return {
      confidentialMode,
      policyHash: overridePolicyHash,
      privacyMode: resolvePrivacyMode(request, confidentialMode, undefined),
      errorCode: 'POLICY_HASH_MISMATCH',
      errorStatus: 403,
      error: 'X-Policy-Hash does not match CST policy_hash_b64u',
    };
  }

  const policyHash = overridePolicyHash ?? headerPolicyHash;

  // No policy requested.
  if (!policyHash) {
    const privacyMode = resolvePrivacyMode(request, confidentialMode, undefined);

    // Fail closed in confidential mode if no policy hash was provided.
    if (confidentialMode) {
      return {
        confidentialMode: true,
        privacyMode,
        errorCode: 'POLICY_REQUIRED',
        errorStatus: 400,
        error: 'Confidential mode requires a policy hash (X-Policy-Hash or CST policy_hash_b64u)',
      };
    }

    return { confidentialMode: false, privacyMode };
  }

  if (!isWpcHashB64u(policyHash)) {
    return {
      confidentialMode,
      policyHash,
      privacyMode: resolvePrivacyMode(request, confidentialMode, undefined),
      errorCode: 'POLICY_HASH_INVALID',
      errorStatus: 400,
      error: 'X-Policy-Hash must be a SHA-256 base64url hash (length 43)',
    };
  }

  // Load policy (demo store first, otherwise policy registry).
  let policy = DEMO_POLICIES.get(policyHash);

  if (!policy) {
    const fetched = await fetchWpcFromRegistry(env, policyHash);
    if (!fetched.ok) {
      return {
        confidentialMode,
        policyHash,
        privacyMode: resolvePrivacyMode(request, confidentialMode, undefined),
        errorCode: fetched.errorCode,
        errorStatus: fetched.status,
        error: fetched.error,
      };
    }

    policy = fetched.policy;
  }

  const privacyMode = resolvePrivacyMode(request, confidentialMode, policy);

  return {
    confidentialMode,
    policyHash,
    policy,
    privacyMode,
  };
}

/**
 * Check if a model matches an allowlist pattern
 * Supports simple glob patterns: * matches any characters
 */
function matchesModelPattern(model: string | undefined, pattern: string): boolean {
  if (!model) return false;

  // Convert glob pattern to regex
  const regexPattern = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&') // Escape special regex chars
    .replace(/\*/g, '.*'); // Convert * to .*

  const regex = new RegExp(`^${regexPattern}$`, 'i');
  return regex.test(model);
}

/**
 * Enforce provider/model allowlist from policy
 */
export function enforceProviderAllowlist(
  provider: Provider,
  model: string | undefined,
  policy: WorkPolicyContractV1
): PolicyEnforcementResult {
  // Check provider allowlist
  if (policy.allowed_providers && policy.allowed_providers.length > 0) {
    if (!policy.allowed_providers.includes(provider)) {
      return {
        allowed: false,
        error: `Provider '${provider}' is not allowed by policy. Allowed providers: ${policy.allowed_providers.join(', ')}`,
        errorCode: 'POLICY_PROVIDER_NOT_ALLOWED',
      };
    }
  }

  // Check model allowlist
  if (policy.allowed_models && policy.allowed_models.length > 0) {
    if (!model) {
      return {
        allowed: false,
        error: 'Model is required when policy specifies model allowlist',
        errorCode: 'POLICY_MODEL_REQUIRED',
      };
    }

    const modelAllowed = policy.allowed_models.some((pattern) =>
      matchesModelPattern(model, pattern)
    );

    if (!modelAllowed) {
      return {
        allowed: false,
        error: `Model '${model}' is not allowed by policy. Allowed patterns: ${policy.allowed_models.join(', ')}`,
        errorCode: 'POLICY_MODEL_NOT_ALLOWED',
      };
    }
  }

  return { allowed: true };
}

/**
 * Apply redaction rules to a JSON object
 * Returns a new object with redacted fields
 */
export function applyRedactionRules(data: unknown, rules: RedactionRule[]): unknown {
  if (!rules || rules.length === 0) {
    return data;
  }

  // Deep clone to avoid mutating original
  let result = JSON.parse(JSON.stringify(data));

  for (const rule of rules) {
    result = applyRedactionRule(result, rule);
  }

  return result;
}

/**
 * Apply a single redaction rule to an object
 * Supports simplified JSON path patterns:
 * - $.field - top-level field
 * - $.nested.field - nested field
 * - $.array[*].field - field in array items
 */
function applyRedactionRule(obj: unknown, rule: RedactionRule): unknown {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const path = rule.path;

  // Remove leading $. if present
  const normalizedPath = path.startsWith('$.') ? path.slice(2) : path;

  return redactPath(obj, normalizedPath.split('.'), rule.action);
}

/**
 * Recursively redact a path in an object
 */
function redactPath(
  obj: unknown,
  pathParts: string[],
  action: RedactionRule['action']
): unknown {
  if (typeof obj !== 'object' || obj === null || pathParts.length === 0) {
    return obj;
  }

  const [current, ...rest] = pathParts;
  const result = Array.isArray(obj) ? [...obj] : { ...obj };

  // Handle array wildcard: field[*]
  const arrayMatch = current?.match(/^([^[]+)\[\*\]$/);
  if (arrayMatch) {
    const fieldName = arrayMatch[1] as string;
    const fieldValue = (result as Record<string, unknown>)[fieldName];

    if (Array.isArray(fieldValue)) {
      (result as Record<string, unknown>)[fieldName] = fieldValue.map((item) =>
        rest.length === 0 ? applyAction(item, action) : redactPath(item, rest, action)
      );
    }
  } else if (current) {
    // Regular field access
    const fieldValue = (result as Record<string, unknown>)[current];

    if (fieldValue !== undefined) {
      if (rest.length === 0) {
        // End of path - apply action
        (result as Record<string, unknown>)[current] = applyAction(fieldValue, action);
      } else {
        // Continue recursion
        (result as Record<string, unknown>)[current] = redactPath(fieldValue, rest, action);
      }
    }
  }

  return result;
}

/**
 * Apply redaction action to a value
 */
function applyAction(value: unknown, action: RedactionRule['action']): unknown {
  switch (action) {
    case 'remove':
      return undefined; // Will be stripped during JSON serialization
    case 'mask':
      if (typeof value === 'string') {
        return '[REDACTED]';
      }
      return '[REDACTED]';
    case 'hash':
      // For sync operation, we use a marker that indicates hashing needed
      // In production, this would be an async SHA-256 hash
      return `[HASH:${typeof value}]`;
    default:
      return value;
  }
}

/**
 * Strip undefined values from an object (cleanup after redaction)
 */
export function stripUndefined(obj: unknown): unknown {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  if (Array.isArray(obj)) {
    return obj
      .filter((item) => item !== undefined)
      .map((item) => stripUndefined(item));
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value !== undefined) {
      result[key] = stripUndefined(value);
    }
  }
  return result;
}
