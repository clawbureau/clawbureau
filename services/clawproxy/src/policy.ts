/**
 * Work Policy Contract (WPC) enforcement
 *
 * WPCs define enterprise policy constraints for confidential runs:
 * - Provider/model allowlists
 * - Field redaction rules
 * - Confidentiality mode requirements
 */


import type { Provider, ReceiptPrivacyMode } from './types';

/**
 * Policy header for Work Policy Contract
 */
export const POLICY_HEADER = 'X-Policy-Hash';
export const CONFIDENTIAL_MODE_HEADER = 'X-Confidential-Mode';
export const PRIVACY_MODE_HEADER = 'X-Receipt-Privacy-Mode';

/**
 * Redaction rule for stripping fields from requests/responses
 */
export interface RedactionRule {
  /** JSON path pattern to match (e.g., "$.messages[*].content", "$.metadata") */
  path: string;
  /** Action to take when field matches */
  action: 'remove' | 'hash' | 'mask';
}

/**
 * Work Policy Contract definition
 * Defines constraints for confidential enterprise runs
 */
export interface WorkPolicyContract {
  /** WPC version for compatibility */
  version: '1.0';
  /** SHA-256 hash of the policy content (computed, not stored in policy) */
  policyHash?: string;
  /** Allowed providers (if empty, all supported providers allowed) */
  allowedProviders?: Provider[];
  /** Allowed model patterns (glob-style, e.g., "claude-3-*", "gpt-4*") */
  allowedModels?: string[];
  /** Field redaction rules for privacy */
  redactionRules?: RedactionRule[];
  /** Whether to enforce hash-only receipts (no plaintext in logs) */
  hashOnlyReceipts?: boolean;
}

/**
 * Result of policy extraction from request
 */
export interface PolicyExtractionResult {
  /** Whether confidential mode is enabled */
  confidentialMode: boolean;
  /** Policy hash if provided */
  policyHash?: string;
  /** Parsed policy (in production, would be fetched from policy store) */
  policy?: WorkPolicyContract;
  /** Error if policy is invalid or missing when required */
  error?: string;
  /** Receipt privacy mode requested (defaults to hash_only) */
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
 * In production, policies would be fetched from a secure policy registry
 */
const DEMO_POLICIES: Map<string, WorkPolicyContract> = new Map();

/**
 * Register a demo policy for testing
 * In production, policies would be managed externally
 */
export function registerDemoPolicy(policyHash: string, policy: WorkPolicyContract): void {
  DEMO_POLICIES.set(policyHash, { ...policy, policyHash });
}

/**
 * Extract privacy mode from request header
 * In confidential mode, only hash_only is allowed (encrypted is blocked)
 */
function extractPrivacyMode(request: Request, confidentialMode: boolean): ReceiptPrivacyMode {
  const privacyModeHeader = request.headers.get(PRIVACY_MODE_HEADER);

  // Default to hash_only (most private)
  if (!privacyModeHeader) {
    return 'hash_only';
  }

  // Validate privacy mode header value
  if (privacyModeHeader !== 'hash_only' && privacyModeHeader !== 'encrypted') {
    // Invalid value, default to hash_only
    return 'hash_only';
  }

  // In confidential mode, encrypted payloads are not allowed
  // This ensures prompts are never stored in recoverable form
  if (confidentialMode && privacyModeHeader === 'encrypted') {
    return 'hash_only';
  }

  return privacyModeHeader;
}

/**
 * Extract policy information from request headers
 */
export function extractPolicyFromHeaders(request: Request): PolicyExtractionResult {
  const confidentialModeHeader = request.headers.get(CONFIDENTIAL_MODE_HEADER);
  const policyHash = request.headers.get(POLICY_HEADER) ?? undefined;

  // Confidential mode is enabled if header is present and truthy
  const confidentialMode = confidentialModeHeader === 'true' || confidentialModeHeader === '1';

  // Extract privacy mode (respects confidential mode restrictions)
  const privacyMode = extractPrivacyMode(request, confidentialMode);

  // If confidential mode but no policy hash, that's an error
  if (confidentialMode && !policyHash) {
    return {
      confidentialMode: true,
      privacyMode,
      error: 'Confidential mode requires X-Policy-Hash header',
    };
  }

  // If policy hash is provided, try to load the policy
  if (policyHash) {
    const policy = DEMO_POLICIES.get(policyHash);
    if (!policy) {
      // Policy not found - in confidential mode this is an error
      if (confidentialMode) {
        return {
          confidentialMode: true,
          policyHash,
          privacyMode,
          error: `Policy not found for hash: ${policyHash}`,
        };
      }
      // In non-confidential mode, unknown policy is a warning but allowed
      return {
        confidentialMode: false,
        policyHash,
        privacyMode,
      };
    }

    return {
      confidentialMode,
      policyHash,
      policy,
      privacyMode,
    };
  }

  return { confidentialMode: false, privacyMode };
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
  policy: WorkPolicyContract
): PolicyEnforcementResult {
  // Check provider allowlist
  if (policy.allowedProviders && policy.allowedProviders.length > 0) {
    if (!policy.allowedProviders.includes(provider)) {
      return {
        allowed: false,
        error: `Provider '${provider}' is not allowed by policy. Allowed providers: ${policy.allowedProviders.join(', ')}`,
        errorCode: 'POLICY_PROVIDER_NOT_ALLOWED',
      };
    }
  }

  // Check model allowlist
  if (policy.allowedModels && policy.allowedModels.length > 0) {
    if (!model) {
      return {
        allowed: false,
        error: 'Model is required when policy specifies model allowlist',
        errorCode: 'POLICY_MODEL_REQUIRED',
      };
    }

    const modelAllowed = policy.allowedModels.some(pattern =>
      matchesModelPattern(model, pattern)
    );

    if (!modelAllowed) {
      return {
        allowed: false,
        error: `Model '${model}' is not allowed by policy. Allowed patterns: ${policy.allowedModels.join(', ')}`,
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
export function applyRedactionRules(
  data: unknown,
  rules: RedactionRule[]
): unknown {
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
      (result as Record<string, unknown>)[fieldName] = fieldValue.map(item =>
        rest.length === 0
          ? applyAction(item, action)
          : redactPath(item, rest, action)
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
      .filter(item => item !== undefined)
      .map(item => stripUndefined(item));
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value !== undefined) {
      result[key] = stripUndefined(value);
    }
  }
  return result;
}
