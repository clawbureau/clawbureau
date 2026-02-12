/**
 * WPC v2 Policy Evaluator — IAM-style policy engine.
 *
 * Evaluation rules (matching AWS IAM semantics):
 * 1. Default deny: if no statement explicitly allows, the action is denied.
 * 2. Explicit Deny always wins over Allow.
 * 3. Strict Intersection: when `inherits` is set, parent AND child must both allow.
 *
 * Pure TypeScript, zero external dependencies, deterministic, offline.
 * Designed to run in Cloudflare Workers (<5ms for 20 statements).
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** WPC v1 schema (for backward compatibility). */
export interface WPCv1 {
  policy_version: '1';
  policy_id: string;
  issuer_did: string;
  allowed_providers?: string[];
  allowed_models?: string[];
  minimum_model_identity_tier?: string;
  egress_allowlist?: string[];
  redaction_rules?: unknown[];
  receipt_privacy_mode?: string;
  required_audit_packs?: string[];
  metadata?: Record<string, unknown>;
}

/** Condition operator map: context-key -> expected value. */
export type ConditionMap = Record<string, string>;

/** Condition operators supported by the evaluator. */
export interface PolicyConditions {
  StringEquals?: ConditionMap;
  StringNotEquals?: ConditionMap;
  StringLike?: ConditionMap;
  StringNotLike?: ConditionMap;
  NumericEquals?: ConditionMap;
  NumericLessThan?: ConditionMap;
  NumericGreaterThan?: ConditionMap;
  Bool?: ConditionMap;
  IpAddress?: ConditionMap;
}

/** A single IAM-style policy statement. */
export interface PolicyStatement {
  sid: string;
  effect: 'Allow' | 'Deny';
  actions: string[];
  resources: string[];
  conditions?: PolicyConditions;
}

/** WPC v2 schema. */
export interface WPCv2 {
  policy_version: '2';
  policy_id: string;
  issuer_did: string;
  inherits?: string;
  statements: PolicyStatement[];
  metadata?: Record<string, unknown>;
}

/** Union type for any WPC version. */
export type WPC = WPCv1 | WPCv2;

/** Context keys available during policy evaluation. */
export interface PolicyContext {
  /** Agent's DID (Agent:DID) */
  'Agent:DID'?: string;
  /** Model provider (Model:Provider) */
  'Model:Provider'?: string;
  /** Model name (Model:Name) */
  'Model:Name'?: string;
  /** Proof tier from receipt (Receipt:ProofTier) */
  'Receipt:ProofTier'?: string;
  /** Whether human approval was obtained (Request:HasHumanApproval) */
  'Request:HasHumanApproval'?: string;
  /** Target domain for network egress (SideEffect:TargetDomain) */
  'SideEffect:TargetDomain'?: string;
  /** Tool name being invoked (Tool:Name) */
  'Tool:Name'?: string;
  /** Hour of day 0-23 (Context:Hour) */
  'Context:Hour'?: string;
  /** Allow additional context keys. */
  [key: string]: string | undefined;
}

export type PolicyDecisionEffect = 'ALLOW' | 'DENY';

/** Result of evaluating a policy against an action + context. */
export interface PolicyDecision {
  effect: PolicyDecisionEffect;
  /** Human-readable reason for the decision. */
  reason: string;
  /** Statement IDs that contributed to the decision. */
  matched_statements: string[];
}

/** Resolver for parent policies (used in Strict Intersection). */
export type PolicyResolver = (policyId: string) => WPCv2 | WPC | null;

// ---------------------------------------------------------------------------
// Glob matching (minimal, no dependencies)
// ---------------------------------------------------------------------------

/**
 * Match a value against a glob pattern.
 * Supports:
 * - '*' matches any sequence of characters (non-greedy per segment)
 * - '**' matches any sequence including path separators
 * - '?' matches exactly one character
 */
function globMatch(pattern: string, value: string): boolean {
  // Fast-path: exact wildcard
  if (pattern === '*' || pattern === '**') return true;

  // Convert glob to regex
  let regex = '^';
  let i = 0;
  while (i < pattern.length) {
    const ch = pattern[i];
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        // ** matches everything including /
        regex += '.*';
        i += 2;
        // Skip trailing / after **
        if (pattern[i] === '/') i++;
      } else {
        // * matches everything except /
        regex += '[^/]*';
        i++;
      }
    } else if (ch === '?') {
      regex += '[^/]';
      i++;
    } else {
      // Escape regex special chars
      regex += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
      i++;
    }
  }
  regex += '$';

  return new RegExp(regex).test(value);
}

// ---------------------------------------------------------------------------
// CIDR matching (IPv4 only, sufficient for policy evaluation)
// ---------------------------------------------------------------------------

function ipToNumber(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    const n = parseInt(part, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    num = (num << 8) | n;
  }
  // Convert to unsigned 32-bit
  return num >>> 0;
}

function cidrMatch(cidr: string, ip: string): boolean {
  const [network, prefixStr] = cidr.split('/');
  const prefix = prefixStr !== undefined ? parseInt(prefixStr, 10) : 32;
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return false;

  const networkNum = ipToNumber(network);
  const ipNum = ipToNumber(ip);
  if (networkNum === null || ipNum === null) return false;

  if (prefix === 0) return true;
  const mask = (~0 << (32 - prefix)) >>> 0;
  return (networkNum & mask) === (ipNum & mask);
}

// ---------------------------------------------------------------------------
// Condition evaluation
// ---------------------------------------------------------------------------

function evaluateConditionOperator(
  operator: string,
  conditionMap: ConditionMap,
  context: PolicyContext,
): boolean {
  for (const [key, expected] of Object.entries(conditionMap)) {
    const actual = context[key];

    switch (operator) {
      case 'StringEquals':
        if (actual !== expected) return false;
        break;

      case 'StringNotEquals':
        if (actual === expected) return false;
        break;

      case 'StringLike':
        if (actual === undefined || !globMatch(expected, actual)) return false;
        break;

      case 'StringNotLike':
        if (actual !== undefined && globMatch(expected, actual)) return false;
        break;

      case 'NumericEquals': {
        if (actual === undefined) return false;
        const numActual = parseFloat(actual);
        const numExpected = parseFloat(expected);
        if (isNaN(numActual) || isNaN(numExpected)) return false;
        if (numActual !== numExpected) return false;
        break;
      }

      case 'NumericLessThan': {
        if (actual === undefined) return false;
        const numActual = parseFloat(actual);
        const numExpected = parseFloat(expected);
        if (isNaN(numActual) || isNaN(numExpected)) return false;
        if (numActual >= numExpected) return false;
        break;
      }

      case 'NumericGreaterThan': {
        if (actual === undefined) return false;
        const numActual = parseFloat(actual);
        const numExpected = parseFloat(expected);
        if (isNaN(numActual) || isNaN(numExpected)) return false;
        if (numActual <= numExpected) return false;
        break;
      }

      case 'Bool': {
        if (actual === undefined) return false;
        const boolExpected = expected.toLowerCase() === 'true';
        const boolActual = actual.toLowerCase() === 'true';
        if (boolActual !== boolExpected) return false;
        break;
      }

      case 'IpAddress': {
        if (actual === undefined) return false;
        if (!cidrMatch(expected, actual)) return false;
        break;
      }

      default:
        // Unknown operator: fail-closed
        return false;
    }
  }
  return true;
}

function evaluateConditions(
  conditions: PolicyConditions | undefined,
  context: PolicyContext,
): boolean {
  if (!conditions) return true;

  // All condition operators must pass (AND logic)
  for (const [operator, conditionMap] of Object.entries(conditions)) {
    if (!conditionMap || typeof conditionMap !== 'object') continue;
    if (!evaluateConditionOperator(operator, conditionMap as ConditionMap, context)) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// Statement matching
// ---------------------------------------------------------------------------

function actionMatches(statementActions: string[], requestedAction: string): boolean {
  return statementActions.some((pattern) => globMatch(pattern, requestedAction));
}

function resourceMatches(statementResources: string[], requestedResource: string): boolean {
  return statementResources.some((pattern) => globMatch(pattern, requestedResource));
}

// ---------------------------------------------------------------------------
// v1 -> v2 conversion (inline, for backward compat evaluation)
// ---------------------------------------------------------------------------

/**
 * Convert a WPC v1 to v2 statements for evaluation.
 * This mirrors the logic in the migration helper but is kept inline
 * to avoid circular deps.
 */
export function convertV1toV2(v1: WPCv1): WPCv2 {
  const statements: PolicyStatement[] = [];
  let sid = 0;

  // allowed_providers -> model:invoke with StringEquals on Model:Provider
  if (v1.allowed_providers && v1.allowed_providers.length > 0) {
    for (const provider of v1.allowed_providers) {
      statements.push({
        sid: `v1-provider-${++sid}`,
        effect: 'Allow',
        actions: ['model:invoke'],
        resources: ['*'],
        conditions: {
          StringEquals: { 'Model:Provider': provider },
        },
      });
    }
  } else {
    // No provider restriction -> allow all model invocations
    statements.push({
      sid: `v1-model-allow-all-${++sid}`,
      effect: 'Allow',
      actions: ['model:invoke'],
      resources: ['*'],
    });
  }

  // allowed_models -> model:invoke with StringLike on Model:Name
  if (v1.allowed_models && v1.allowed_models.length > 0) {
    // If allowed_models is set, deny all models first, then allow the listed ones
    statements.push({
      sid: `v1-model-deny-unlisted-${++sid}`,
      effect: 'Deny',
      actions: ['model:invoke'],
      resources: ['*'],
      conditions: {
        // This deny applies when Model:Name does NOT match any allowed pattern.
        // Since we can't express OR in a single condition, we add individual Allow
        // statements for each model. The default deny covers the rest.
      },
    });
    // Actually, for v1 compat we just allow specific models.
    // Remove the deny (default deny handles unlisted).
    statements.pop();
    // Remove the blanket model allow we added above
    const blanketIdx = statements.findIndex((s) =>
      s.sid.startsWith('v1-model-allow-all-'),
    );
    if (blanketIdx >= 0) {
      statements.splice(blanketIdx, 1);
    }
    // Also remove provider-specific allows and replace with model+provider combo
    const providerIdxs: number[] = [];
    statements.forEach((s, i) => {
      if (s.sid.startsWith('v1-provider-')) providerIdxs.push(i);
    });
    // Keep provider statements AND add model-specific ones
    for (const model of v1.allowed_models) {
      statements.push({
        sid: `v1-model-${++sid}`,
        effect: 'Allow',
        actions: ['model:invoke'],
        resources: ['*'],
        conditions: {
          StringLike: { 'Model:Name': model },
        },
      });
    }
  }

  // egress_allowlist -> side_effect:network_egress
  if (v1.egress_allowlist && v1.egress_allowlist.length > 0) {
    for (const domain of v1.egress_allowlist) {
      statements.push({
        sid: `v1-egress-${++sid}`,
        effect: 'Allow',
        actions: ['side_effect:network_egress'],
        resources: ['*'],
        conditions: {
          StringLike: { 'SideEffect:TargetDomain': domain },
        },
      });
    }
  } else {
    // No egress restriction -> allow all
    statements.push({
      sid: `v1-egress-allow-all-${++sid}`,
      effect: 'Allow',
      actions: ['side_effect:network_egress'],
      resources: ['*'],
    });
  }

  // Allow all tool execution and filesystem operations by default (v1 had no tool/fs restrictions)
  statements.push({
    sid: `v1-tools-allow-all-${++sid}`,
    effect: 'Allow',
    actions: ['tool:*', 'side_effect:filesystem_read', 'side_effect:filesystem_write'],
    resources: ['*'],
  });

  // Ensure at least one statement exists
  if (statements.length === 0) {
    statements.push({
      sid: 'v1-default-allow-all',
      effect: 'Allow',
      actions: ['*'],
      resources: ['*'],
    });
  }

  return {
    policy_version: '2',
    policy_id: v1.policy_id,
    issuer_did: v1.issuer_did,
    statements,
    metadata: {
      ...v1.metadata,
      _migrated_from: 'v1',
      _original_policy_version: '1',
    },
  };
}

// ---------------------------------------------------------------------------
// Core evaluator
// ---------------------------------------------------------------------------

/**
 * Evaluate a single WPC v2 policy (no inheritance resolution).
 */
function evaluateStatements(
  statements: PolicyStatement[],
  action: string,
  resource: string,
  context: PolicyContext,
): { effect: PolicyDecisionEffect; matchedSids: string[] } {
  let hasAllow = false;
  const matchedAllowSids: string[] = [];
  const matchedDenySids: string[] = [];

  for (const stmt of statements) {
    // Check action match
    if (!actionMatches(stmt.actions, action)) continue;

    // Check resource match
    if (!resourceMatches(stmt.resources, resource)) continue;

    // Check conditions
    if (!evaluateConditions(stmt.conditions, context)) continue;

    // Statement matches
    if (stmt.effect === 'Deny') {
      // Explicit Deny always wins — short circuit
      matchedDenySids.push(stmt.sid);
    } else {
      hasAllow = true;
      matchedAllowSids.push(stmt.sid);
    }
  }

  // Deny wins over Allow (IAM semantics)
  if (matchedDenySids.length > 0) {
    return { effect: 'DENY', matchedSids: matchedDenySids };
  }

  if (hasAllow) {
    return { effect: 'ALLOW', matchedSids: matchedAllowSids };
  }

  // Default deny
  return { effect: 'DENY', matchedSids: [] };
}

/**
 * Normalize a WPC (v1 or v2) to v2 for evaluation.
 */
function normalizeToV2(policy: WPC): WPCv2 {
  if (policy.policy_version === '2') return policy as WPCv2;
  if (policy.policy_version === '1') return convertV1toV2(policy as WPCv1);
  // Unknown version: fail-closed with empty statements (deny all)
  return {
    policy_version: '2',
    policy_id: (policy as Record<string, string>).policy_id ?? 'unknown',
    issuer_did: (policy as Record<string, string>).issuer_did ?? 'unknown',
    statements: [],
  };
}

/**
 * Evaluate a WPC policy against an action, resource, and context.
 *
 * Supports both WPC v1 (auto-converted) and v2 policies.
 * When `inherits` is set and a `resolver` is provided, performs
 * Strict Intersection (parent AND child must both allow).
 *
 * @param policy - The WPC policy (v1 or v2)
 * @param action - The action being requested (e.g., "model:invoke")
 * @param resource - The resource being acted upon (e.g., "src/index.ts")
 * @param context - Context keys from the proof bundle / runtime
 * @param resolver - Optional resolver for parent policies (Strict Intersection)
 */
export function evaluatePolicy(
  policy: WPC,
  action: string,
  resource: string,
  context: PolicyContext,
  resolver?: PolicyResolver,
): PolicyDecision {
  const v2 = normalizeToV2(policy);
  const childResult = evaluateStatements(v2.statements, action, resource, context);

  // If no inheritance, return child result directly
  if (!v2.inherits || !resolver) {
    return {
      effect: childResult.effect,
      reason:
        childResult.effect === 'ALLOW'
          ? `Allowed by statement(s): ${childResult.matchedSids.join(', ') || 'none'}`
          : childResult.matchedSids.length > 0
            ? `Explicitly denied by statement(s): ${childResult.matchedSids.join(', ')}`
            : `No statement allows action '${action}' on resource '${resource}' (default deny)`,
      matched_statements: childResult.matchedSids,
    };
  }

  // Strict Intersection: resolve parent and evaluate
  const parentRaw = resolver(v2.inherits);
  if (!parentRaw) {
    // Cannot resolve parent: fail-closed
    return {
      effect: 'DENY',
      reason: `Cannot resolve parent policy '${v2.inherits}' (fail-closed)`,
      matched_statements: [],
    };
  }

  const parent = normalizeToV2(parentRaw);
  const parentResult = evaluateStatements(parent.statements, action, resource, context);

  // Both must allow (Strict Intersection)
  if (parentResult.effect === 'DENY') {
    return {
      effect: 'DENY',
      reason:
        parentResult.matchedSids.length > 0
          ? `Parent policy '${v2.inherits}' explicitly denied by: ${parentResult.matchedSids.join(', ')}`
          : `Parent policy '${v2.inherits}' has no statement allowing action '${action}' on '${resource}'`,
      matched_statements: parentResult.matchedSids,
    };
  }

  if (childResult.effect === 'DENY') {
    return {
      effect: 'DENY',
      reason:
        childResult.matchedSids.length > 0
          ? `Explicitly denied by child statement(s): ${childResult.matchedSids.join(', ')}`
          : `No child statement allows action '${action}' on resource '${resource}' (default deny)`,
      matched_statements: childResult.matchedSids,
    };
  }

  // Both allow
  const allSids = [...parentResult.matchedSids, ...childResult.matchedSids];
  return {
    effect: 'ALLOW',
    reason: `Allowed by parent (${parentResult.matchedSids.join(', ')}) AND child (${childResult.matchedSids.join(', ')})`,
    matched_statements: allSids,
  };
}

/**
 * Convenience: evaluate multiple actions against a policy.
 * Returns a map of action -> PolicyDecision.
 */
export function evaluatePolicyBatch(
  policy: WPC,
  requests: Array<{ action: string; resource: string }>,
  context: PolicyContext,
  resolver?: PolicyResolver,
): Map<string, PolicyDecision> {
  const results = new Map<string, PolicyDecision>();
  for (const { action, resource } of requests) {
    const key = `${action}::${resource}`;
    results.set(key, evaluatePolicy(policy, action, resource, context, resolver));
  }
  return results;
}
