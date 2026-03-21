/**
 * Local interceptor proxy for clawsig wrap.
 *
 * Starts a lightweight HTTP server on a random port that intercepts
 * OpenAI-compatible and Anthropic-compatible API requests, rewrites
 * auth headers, forwards them through clawproxy, and collects
 * gateway receipts for proof bundle compilation.
 *
 * Uses only `node:http` — zero external dependencies.
 */

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { hashJsonB64u, sha256B64u, base64UrlEncode, base64UrlDecode } from './crypto.js';
import type { EphemeralDid } from './ephemeral-did.js';
import type { SignedEnvelope, GatewayReceiptPayload, ProofBundlePayload, EventChainEntry } from './types.js';
import { CausalSieve, type LocalPolicy, type PolicyViolation } from './causal-sieve.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Options for starting the local interceptor proxy. */
export interface ProxyOptions {
  /** Ephemeral DID identity for this run. */
  agentDid: EphemeralDid;
  /** Unique run identifier. */
  runId: string;
  /** Upstream clawproxy URL (default: https://clawproxy.com). */
  clawproxyUrl?: string;
  /** Optional clawproxy CST / scoped token (forwarded as X-CST). */
  proxyToken?: string;
  /** Provider API key for OpenAI (passed through to clawproxy). */
  providerApiKey?: string;
  /** Local WPC policy for the TCP Guillotine. */
  policy?: LocalPolicy | null;
  /** Working directory for git diff operations. */
  cwd?: string;
  /** Callback when a policy violation is detected in the stream. */
  onViolation?: (violation: PolicyViolation) => void;
  /**
   * Passthrough mode: forward directly to upstream provider APIs
   * instead of routing through clawproxy.com.
   *
   * In passthrough mode:
   * - Requests go straight to api.anthropic.com / api.openai.com
   * - Original auth headers are preserved
   * - No gateway receipts are generated (no clawproxy)
   * - The Causal Sieve still parses tool_calls/tool_results
   * - Git diff still detects file mutations
   *
   * Use this when the agent has its own API auth (OAuth, API keys)
   * that clawproxy doesn't support.
   */
  passthrough?: boolean;
  /**
   * Enforce deny-by-default outbound egress host policy.
   * When enabled, requests to destinations not in `egressAllowlist` are blocked.
   */
  enforceEgressAllowlist?: boolean;
  /** Explicit outbound egress host allowlist (hostnames, optional `*.` wildcard). */
  egressAllowlist?: string[];
  /** Effective signed-policy hash resolved by wrap for proofed policy-bound controls. */
  effectivePolicyHashB64u?: string;
}

/** A running local proxy instance. */
export interface LocalProxy {
  /** The port the proxy is listening on. */
  port: number;
  /** Stop the proxy server. */
  stop(): Promise<void>;
  /** Compile all collected receipts into a signed proof bundle. */
  compileProofBundle(): Promise<SignedEnvelope<ProofBundlePayload>>;
  /** Number of receipts collected so far. */
  receiptCount: number;
  /** Number of tool receipts synthesized by the Causal Sieve. */
  toolReceiptCount: number;
  /** Number of side-effect receipts synthesized by the Causal Sieve. */
  sideEffectReceiptCount: number;
  /** Number of policy violations detected by the TCP Guillotine. */
  violationCount: number;
  /** Per-run privacy salt (base64url-encoded, 16 bytes). Needed by verifiers. */
  runSaltB64u: string;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface CollectedReceipt {
  envelope: SignedEnvelope<GatewayReceiptPayload>;
  collectedAt: string;
  provider: string;
  model: string;
  eventChainEntry: EventChainEntry;
}

interface EgressPolicy {
  enforce: boolean;
  allowlist: string[];
}

interface ProcessorPolicy {
  enforce: boolean;
  policy_version: '1';
  profile_id: string;
  allowed_providers: string[];
  allowed_models: string[];
  allowed_regions: string[];
  allowed_retention_profiles: string[];
  default_region: string;
  default_retention_profile: string;
}

interface ProcessorPolicyConstraints {
  allowed_providers: string[];
  allowed_models: string[];
  allowed_regions: string[];
  allowed_retention_profiles: string[];
  default_region: string;
  default_retention_profile: string;
}

interface ProcessorRouteClaims {
  provider: string;
  model: string;
  region: string;
  retention_profile: string;
}

interface ProcessorPolicyDecision {
  allowed: boolean;
  route: ProcessorRouteClaims;
  reason_code?: string;
}

interface ProcessorPolicyState {
  allowed_count: number;
  denied_count: number;
  used_processors: Map<string, { route: ProcessorRouteClaims; count: number }>;
  blocked_attempts: Array<{
    route: ProcessorRouteClaims;
    reason_code: string;
    timestamp: string;
  }>;
}

type DataHandlingAction = 'allow' | 'redact' | 'block' | 'require_approval';
type DataHandlingEnforcementMode = 'enforced' | 'simulated';
type DataHandlingRedactionStrategy = 'none' | 'text_regex' | 'json_structured';

type DataHandlingClassId = string;
type DataHandlingRuleSource = 'builtin' | 'custom';

interface DataHandlingPolicyEvidence {
  taxonomy_version: 'prv.dlp.taxonomy.v2';
  ruleset_hash_b64u: string;
  built_in_rule_count: number;
  custom_rule_count: number;
}

interface DataHandlingRule {
  source: DataHandlingRuleSource;
  class_id: DataHandlingClassId;
  rule_id: string;
  action: DataHandlingAction;
  pattern: RegExp;
  pattern_source: string;
  pattern_flags: string;
  redaction_token?: string;
}

interface DataHandlingClassMatch {
  class_id: DataHandlingClassId;
  rule_id: string;
  action: DataHandlingAction;
  match_count: number;
}

interface DataHandlingRedactionOperation {
  class_id: DataHandlingClassId;
  rule_id: string;
  path: string;
  match_count: number;
  redaction_token: string;
}

interface DataHandlingDecision {
  action: DataHandlingAction;
  reason_code: string;
  enforcement_mode: DataHandlingEnforcementMode;
  would_action: DataHandlingAction;
  would_reason_code: string;
  classes: DataHandlingClassMatch[];
  policy: DataHandlingPolicyEvidence | null;
  approval_required: boolean;
  approval_satisfied: boolean;
  approval_scope_hash_b64u: string | null;
  approval_receipt_hash_b64u: string | null;
  approval_receipt_signer_did: string | null;
  approval_receipt_envelope: SignedEnvelope<HumanApprovalReceiptPayload> | null;
  redaction_applied: boolean;
  redaction_strategy: DataHandlingRedactionStrategy;
  redaction_operations: DataHandlingRedactionOperation[];
  outboundBody: Buffer;
  original_payload_hash_b64u: string;
  outbound_payload_hash_b64u: string | null;
}

interface HumanApprovalReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  approval_type: 'explicit_approve' | 'auto_approve';
  approver_subject: string;
  approver_method?: 'ui_click' | 'cli_confirm' | 'api_call' | 'policy_auto';
  agent_did: string;
  scope_hash_b64u: string;
  scope_summary?: string;
  policy_hash_b64u: string;
  minted_capability_ttl_seconds: number;
  hash_algorithm: 'SHA-256';
  timestamp: string;
  binding?: {
    run_id?: string;
    event_hash_b64u?: string;
    nonce?: string;
    policy_hash?: string;
  };
}

interface DataHandlingReceiptPayload {
  receipt_version: '1';
  receipt_id: string;
  policy_version: 'prv.dlp.v1';
  effective_policy_hash_b64u: string;
  policy?: DataHandlingPolicyEvidence;
  run_id: string;
  provider: string;
  action: DataHandlingAction;
  reason_code: string;
  classes: DataHandlingClassMatch[];
  enforcement: {
    mode: DataHandlingEnforcementMode;
    would_action: DataHandlingAction;
    would_reason_code: string;
    would_block: boolean;
    would_require_approval: boolean;
    would_redact: boolean;
  };
  approval: {
    required: boolean;
    satisfied: boolean;
    mechanism: 'signed_receipt';
    scope_hash_b64u: string | null;
    receipt_hash_b64u: string | null;
    receipt_signer_did: string | null;
    receipt_envelope: SignedEnvelope<HumanApprovalReceiptPayload> | null;
  };
  redaction: {
    applied: boolean;
    original_payload_hash_b64u: string;
    outbound_payload_hash_b64u: string | null;
    strategy: DataHandlingRedactionStrategy;
    operations: DataHandlingRedactionOperation[];
  };
  timestamp: string;
}

class EgressPolicyError extends Error {
  readonly code = 'PRV_EGRESS_DENIED';
  readonly destination: string;

  constructor(destination: string) {
    super(`Outbound destination is not allowlisted: ${destination}`);
    this.name = 'EgressPolicyError';
    this.destination = destination;
  }
}

class ProcessorPolicyError extends Error {
  readonly code = 'PRV_PROCESSOR_POLICY_DENIED';
  readonly reasonCode: string;
  readonly route: ProcessorRouteClaims;

  constructor(reasonCode: string, route: ProcessorRouteClaims) {
    super(`Processor policy denied route (${reasonCode})`);
    this.name = 'ProcessorPolicyError';
    this.reasonCode = reasonCode;
    this.route = route;
  }
}

function parseBooleanEnv(value: string | undefined): boolean {
  if (!value) return false;
  const normalized = value.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'y';
}

function normalizePolicyToken(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase();
  return trimmed.length > 0 ? trimmed : null;
}

function parsePolicyTokenList(raw: string | undefined): string[] {
  if (!raw || raw.trim().length === 0) return [];
  const out = new Set<string>();
  for (const token of raw.split(',')) {
    const normalized = normalizePolicyToken(token);
    if (normalized) out.add(normalized);
  }
  return [...out];
}

function normalizePolicyModel(model: string): string {
  return model.trim().toLowerCase();
}

function matchesWildcardPattern(value: string, pattern: string): boolean {
  if (pattern === '*') return true;
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`).test(value);
}

function valueMatchesAllowlist(value: string, allowlist: string[]): boolean {
  if (allowlist.length === 0) return false;
  const normalized = value.trim().toLowerCase();
  for (const entry of allowlist) {
    if (entry === '*') return true;
    if (matchesWildcardPattern(normalized, entry)) return true;
  }
  return false;
}

function canonicalizeJson(value: unknown): string {
  if (value === null) return 'null';

  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalizeJson(entry)).join(',')}]`;
  }

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) {
        throw new Error('Cannot canonicalize non-finite number');
      }
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'object': {
      const record = value as Record<string, unknown>;
      const keys = Object.keys(record).sort((a, b) => a.localeCompare(b));
      return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalizeJson(record[key])}`).join(',')}}`;
    }
    default:
      throw new Error(`Cannot canonicalize JSON value of type ${typeof value}`);
  }
}

function buildProcessorPolicyConstraints(policy: ProcessorPolicy): ProcessorPolicyConstraints {
  return {
    allowed_providers: [...policy.allowed_providers],
    allowed_models: [...policy.allowed_models],
    allowed_regions: [...policy.allowed_regions],
    allowed_retention_profiles: [...policy.allowed_retention_profiles],
    default_region: policy.default_region,
    default_retention_profile: policy.default_retention_profile,
  };
}

async function hashProcessorPolicyCanonicalB64u(policy: ProcessorPolicy): Promise<string> {
  const canonical = canonicalizeJson({
    policy_version: policy.policy_version,
    profile_id: policy.profile_id,
    enforce: policy.enforce,
    ...buildProcessorPolicyConstraints(policy),
  });
  return sha256B64u(new TextEncoder().encode(canonical));
}

function readHeaderValue(
  headers: Record<string, string | string[] | undefined>,
  names: string[],
): string | undefined {
  for (const name of names) {
    const direct = headers[name];
    if (typeof direct === 'string' && direct.trim().length > 0) return direct.trim();
    if (Array.isArray(direct) && direct.length > 0 && direct[0]?.trim()) return direct[0].trim();

    const lower = headers[name.toLowerCase()];
    if (typeof lower === 'string' && lower.trim().length > 0) return lower.trim();
    if (Array.isArray(lower) && lower.length > 0 && lower[0]?.trim()) return lower[0].trim();
  }
  return undefined;
}

function parseJsonBodyRecord(bodyBuffer: Buffer): Record<string, unknown> | null {
  if (bodyBuffer.length === 0) return null;
  try {
    const parsed = JSON.parse(bodyBuffer.toString('utf-8'));
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function readStringField(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function resolveProcessorModel(
  provider: string,
  body: Record<string, unknown> | null,
): string | null {
  const direct = body ? readStringField(body.model) : undefined;
  if (direct) return normalizePolicyModel(direct);

  if (provider === 'google' && body) {
    const nestedModel = readStringField(body['model_name']);
    if (nestedModel) return normalizePolicyModel(nestedModel);
  }

  return null;
}

function resolveProcessorRegion(
  body: Record<string, unknown> | null,
  headers: Record<string, string | string[] | undefined>,
  fallbackRegion: string,
): string {
  const fromHeader = readHeaderValue(headers, ['x-clawsig-region']);
  if (fromHeader) return normalizePolicyModel(fromHeader);

  const direct = body ? readStringField(body.region) : undefined;
  if (direct) return normalizePolicyModel(direct);

  const metadata = body && typeof body.metadata === 'object' && body.metadata !== null && !Array.isArray(body.metadata)
    ? (body.metadata as Record<string, unknown>)
    : null;
  const nested = metadata ? readStringField(metadata.region) : undefined;
  if (nested) return normalizePolicyModel(nested);

  return fallbackRegion;
}

function resolveRetentionProfile(
  body: Record<string, unknown> | null,
  headers: Record<string, string | string[] | undefined>,
  fallbackRetentionProfile: string,
): string {
  const fromHeader = readHeaderValue(headers, ['x-clawsig-retention-profile']);
  if (fromHeader) return normalizePolicyModel(fromHeader);

  const fromSnake = body ? readStringField(body.retention_profile) : undefined;
  if (fromSnake) return normalizePolicyModel(fromSnake);

  const fromCamel = body ? readStringField(body.retentionProfile) : undefined;
  if (fromCamel) return normalizePolicyModel(fromCamel);

  const fromPromptCache = body ? readStringField(body.prompt_cache_retention) : undefined;
  if (fromPromptCache) return normalizePolicyModel(fromPromptCache);

  if (body && typeof body.store === 'boolean') {
    return body.store ? 'provider_default' : 'no_store';
  }

  return fallbackRetentionProfile;
}

function buildProcessorRouteClaims(args: {
  provider: string;
  bodyBuffer: Buffer;
  headers: Record<string, string | string[] | undefined>;
  policy: ProcessorPolicy;
}): ProcessorRouteClaims | null {
  const provider = normalizePolicyModel(args.provider);
  const body = parseJsonBodyRecord(args.bodyBuffer);
  const model = resolveProcessorModel(provider, body);
  if (!model) return null;

  return {
    provider,
    model,
    region: resolveProcessorRegion(body, args.headers, args.policy.default_region),
    retention_profile: resolveRetentionProfile(
      body,
      args.headers,
      args.policy.default_retention_profile,
    ),
  };
}

function resolveProcessorPolicy(proofedMode: boolean): ProcessorPolicy {
  const enforceRequested = parseBooleanEnv(process.env['CLAWSIG_PROCESSOR_POLICY_ENFORCE']);
  const enforce = proofedMode && (enforceRequested || process.env['CLAWSIG_PROCESSOR_POLICY_ENFORCE'] === undefined);

  const allowedProviders = parsePolicyTokenList(process.env['CLAWSIG_PROCESSOR_ALLOWED_PROVIDERS']);
  const allowedModels = parsePolicyTokenList(process.env['CLAWSIG_PROCESSOR_ALLOWED_MODELS']);
  const allowedRegions = parsePolicyTokenList(process.env['CLAWSIG_PROCESSOR_ALLOWED_REGIONS']);
  const allowedRetentionProfiles = parsePolicyTokenList(
    process.env['CLAWSIG_PROCESSOR_ALLOWED_RETENTION_PROFILES'],
  );

  const defaultRegionRaw =
    process.env['CLAWSIG_PROCESSOR_DEFAULT_REGION']?.trim() ||
    process.env['CLAWSIG_PROCESSOR_REGION']?.trim();
  const defaultRetentionRaw =
    process.env['CLAWSIG_PROCESSOR_DEFAULT_RETENTION_PROFILE']?.trim() ||
    process.env['CLAWSIG_PROCESSOR_RETENTION_PROFILE']?.trim();

  const defaultRegion = normalizePolicyModel(defaultRegionRaw ?? 'unspecified');
  const defaultRetentionProfile = normalizePolicyModel(defaultRetentionRaw ?? 'unspecified');

  return {
    enforce,
    policy_version: '1',
    profile_id:
      process.env['CLAWSIG_PROCESSOR_POLICY_PROFILE']?.trim() ||
      process.env['CLAWSIG_PROCESSOR_POLICY_PROFILE_ID']?.trim() ||
      'prv.pol.v1.default',
    allowed_providers:
      allowedProviders.length > 0 ? allowedProviders : ['openai', 'anthropic', 'google'],
    allowed_models: allowedModels.length > 0 ? allowedModels : ['*'],
    allowed_regions: allowedRegions.length > 0 ? allowedRegions : [defaultRegion],
    allowed_retention_profiles:
      allowedRetentionProfiles.length > 0 ? allowedRetentionProfiles : [defaultRetentionProfile],
    default_region: defaultRegion,
    default_retention_profile: defaultRetentionProfile,
  };
}

function evaluateProcessorPolicy(
  policy: ProcessorPolicy,
  route: ProcessorRouteClaims | null,
): ProcessorPolicyDecision {
  if (!policy.enforce) {
    return {
      allowed: true,
      route: route ?? {
        provider: 'unknown',
        model: 'unknown',
        region: policy.default_region,
        retention_profile: policy.default_retention_profile,
      },
    };
  }

  if (!route) {
    return {
      allowed: false,
      route: {
        provider: 'unknown',
        model: 'unknown',
        region: policy.default_region,
        retention_profile: policy.default_retention_profile,
      },
      reason_code: 'PRV_PROCESSOR_MODEL_MISSING',
    };
  }

  if (!valueMatchesAllowlist(route.provider, policy.allowed_providers)) {
    return { allowed: false, route, reason_code: 'PRV_PROCESSOR_PROVIDER_DENIED' };
  }

  if (!valueMatchesAllowlist(route.model, policy.allowed_models)) {
    return { allowed: false, route, reason_code: 'PRV_PROCESSOR_MODEL_DENIED' };
  }

  if (!valueMatchesAllowlist(route.region, policy.allowed_regions)) {
    return { allowed: false, route, reason_code: 'PRV_PROCESSOR_REGION_DENIED' };
  }

  if (!valueMatchesAllowlist(route.retention_profile, policy.allowed_retention_profiles)) {
    return { allowed: false, route, reason_code: 'PRV_PROCESSOR_RETENTION_DENIED' };
  }

  return { allowed: true, route };
}

function recordProcessorPolicyDecision(
  state: ProcessorPolicyState,
  decision: ProcessorPolicyDecision,
  timestamp: string,
): void {
  const route = decision.route;
  if (decision.allowed) {
    state.allowed_count += 1;
    const key = `${route.provider}|${route.model}|${route.region}|${route.retention_profile}`;
    const existing = state.used_processors.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      state.used_processors.set(key, { route, count: 1 });
    }
    return;
  }

  state.denied_count += 1;
  if (decision.reason_code) {
    state.blocked_attempts.push({
      route,
      reason_code: decision.reason_code,
      timestamp,
    });
    if (state.blocked_attempts.length > 25) {
      state.blocked_attempts.splice(0, state.blocked_attempts.length - 25);
    }
  }
}

function normalizeEgressAllowlistEntry(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) return null;

  const wildcard = trimmed.startsWith('*.');
  const candidate = wildcard ? trimmed.slice(2) : trimmed;

  let host = candidate;
  try {
    if (candidate.includes('://')) {
      host = new URL(candidate).hostname.toLowerCase();
    } else {
      host = candidate.split('/')[0]?.split(':')[0] ?? '';
    }
  } catch {
    return null;
  }

  if (!host) return null;
  return wildcard ? `*.${host}` : host;
}

function normalizeEgressAllowlist(entries: string[] | undefined): string[] {
  if (!entries || entries.length === 0) return [];
  const out = new Set<string>();
  for (const entry of entries) {
    const normalized = normalizeEgressAllowlistEntry(entry);
    if (normalized) out.add(normalized);
  }
  return [...out];
}

function hostIsAllowlisted(hostname: string, allowlist: string[]): boolean {
  const host = hostname.toLowerCase();
  for (const allowed of allowlist) {
    if (allowed.startsWith('*.')) {
      const suffix = allowed.slice(2);
      if (host === suffix || host.endsWith(`.${suffix}`)) return true;
      continue;
    }
    if (host === allowed) return true;
  }
  return false;
}

function enforceEgressPolicy(targetUrl: string, policy: EgressPolicy | undefined): void {
  if (!policy?.enforce) return;

  let host = '';
  try {
    host = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    throw new EgressPolicyError(targetUrl);
  }

  if (!hostIsAllowlisted(host, policy.allowlist)) {
    throw new EgressPolicyError(host);
  }
}

function randomUUID(): string {
  return crypto.randomUUID();
}

const DLP_POLICY_VERSION = 'prv.dlp.v1' as const;
const DLP_TAXONOMY_VERSION = 'prv.dlp.taxonomy.v2' as const;
const DLP_APPROVAL_HEADER = 'x-clawsig-approval-receipt';
const DLP_APPROVER_DIDS_ENV = 'CLAWSIG_DLP_APPROVER_DIDS';
const DLP_APPROVER_DID_ENV = 'CLAWSIG_DLP_APPROVER_DID';
const DLP_CUSTOM_RULES_ENV = 'CLAWSIG_DLP_CUSTOM_RULES_JSON';
const DLP_APPROVAL_SCOPE_VERSION = 'prv.dlp.approval_scope.v1';
const DLP_MODE_ENV = 'CLAWSIG_DLP_MODE';
const DLP_SIMULATE_ENV = 'CLAWSIG_DLP_SIMULATE';
const DLP_SIMULATION_ALLOW_REASON_CODE = 'PRV_DLP_SIMULATION_ALLOW';

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

interface DataHandlingRuleDefinition {
  class_id: string;
  rule_id: string;
  action: DataHandlingAction;
  pattern: string;
  flags: string;
  redaction_token?: string;
}

interface DataHandlingCustomRuleInput {
  class_id: string;
  action: DataHandlingAction;
  pattern: string;
  flags?: string;
  redaction_token?: string;
  rule_id?: string;
}

interface DataHandlingPolicyConfig extends DataHandlingPolicyEvidence {
  policy_version: typeof DLP_POLICY_VERSION;
  rules: readonly DataHandlingRule[];
}

function resolveDataHandlingEnforcementMode(
  proofedMode: boolean,
): DataHandlingEnforcementMode {
  if (!proofedMode) return 'enforced';

  const normalizedMode = process.env[DLP_MODE_ENV]?.trim().toLowerCase();
  if (
    normalizedMode === 'simulate' ||
    normalizedMode === 'simulated' ||
    normalizedMode === 'preview'
  ) {
    return 'simulated';
  }

  if (parseBooleanEnv(process.env[DLP_SIMULATE_ENV])) {
    return 'simulated';
  }

  return 'enforced';
}

function isDataHandlingAction(value: unknown): value is DataHandlingAction {
  return (
    value === 'allow' ||
    value === 'redact' ||
    value === 'block' ||
    value === 'require_approval'
  );
}

const DLP_CLASS_ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const DLP_CUSTOM_RULE_ID_PATTERN = /^prv\.dlp\.custom\.[a-z0-9._-]+\.[A-Za-z0-9_-]{8,}\.v[0-9]+$/;
const DLP_RULE_ID_PATTERN = /^[A-Za-z0-9._:-]+$/;
const DLP_ALLOWED_REGEX_FLAGS = ['g', 'i', 'm', 's', 'u', 'y'] as const;

const DLP_BUILTIN_RULE_DEFINITIONS: readonly DataHandlingRuleDefinition[] = [
  {
    class_id: 'secret.api_key',
    rule_id: 'prv.dlp.secret.api_key.v1',
    action: 'redact',
    pattern: '\\b(sk-(?:proj-)?[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,})\\b',
    flags: 'g',
    redaction_token: '[REDACTED_SECRET]',
  },
  {
    class_id: 'secret.private_key',
    rule_id: 'prv.dlp.secret.private_key.v1',
    action: 'block',
    pattern: '-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----',
    flags: 'g',
  },
  {
    class_id: 'credential.password',
    rule_id: 'prv.dlp.credential.password.inline.v1',
    action: 'require_approval',
    pattern: '"(password|passwd|pwd|api[_-]?key|token|secret)"\\s*:\\s*"[^"]+"',
    flags: 'gi',
  },
  {
    class_id: 'credential.session_token',
    rule_id: 'prv.dlp.credential.session_token.v1',
    action: 'require_approval',
    pattern:
      '"(session[_-]?token|access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?id)"\\s*:\\s*"[^"]+"',
    flags: 'gi',
  },
  {
    class_id: 'pii.email',
    rule_id: 'prv.dlp.pii.email.v1',
    action: 'allow',
    pattern: '\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b',
    flags: 'gi',
  },
  {
    class_id: 'pii.phone',
    rule_id: 'prv.dlp.pii.phone.v1',
    action: 'allow',
    pattern:
      '\\b(?:\\+?[1-9][0-9]{0,2}[ -]?)?(?:\\([0-9]{3}\\)|[0-9]{3})[ -]?[0-9]{3}[ -]?[0-9]{4}\\b',
    flags: 'g',
  },
  {
    class_id: 'financial.card_pan',
    rule_id: 'prv.dlp.financial.card_pan.v1',
    action: 'redact',
    pattern: '\\b(?:\\d[ -]*?){13,19}\\b',
    flags: 'g',
    redaction_token: '[REDACTED_CARD_PAN]',
  },
  {
    class_id: 'customer.restricted',
    rule_id: 'prv.dlp.customer.restricted.v1',
    action: 'block',
    pattern: '\\b(customer[_-]restricted|customer[_-]confidential|nda[_-]?restricted)\\b',
    flags: 'gi',
  },
] as const;

function normalizeDataHandlingClassId(raw: string, fieldPath: string): string {
  const normalized = raw.trim().toLowerCase();
  if (!DLP_CLASS_ID_PATTERN.test(normalized)) {
    throw new Error(`${fieldPath} must match ${DLP_CLASS_ID_PATTERN.source}.`);
  }
  return normalized;
}

function normalizeRegexFlags(rawFlags: string | undefined, fieldPath: string): string {
  const source = (rawFlags ?? '').trim();
  const seen = new Set<string>();
  for (const flag of source) {
    if (!DLP_ALLOWED_REGEX_FLAGS.includes(flag as (typeof DLP_ALLOWED_REGEX_FLAGS)[number])) {
      throw new Error(`${fieldPath} includes unsupported regex flag "${flag}".`);
    }
    seen.add(flag);
  }
  seen.add('g');
  return DLP_ALLOWED_REGEX_FLAGS.filter((flag) => seen.has(flag)).join('');
}

function buildDataHandlingRule(args: {
  source: DataHandlingRuleSource;
  class_id: string;
  rule_id: string;
  action: DataHandlingAction;
  pattern: string;
  flags: string;
  redaction_token?: string;
}): DataHandlingRule {
  const classId = normalizeDataHandlingClassId(args.class_id, `${args.source}.class_id`);
  const ruleId = args.rule_id.trim();
  if (!DLP_RULE_ID_PATTERN.test(ruleId)) {
    throw new Error(`${args.source}.rule_id contains unsupported characters.`);
  }
  const flags = normalizeRegexFlags(args.flags, `${args.source}.flags`);

  let regex: RegExp;
  try {
    regex = new RegExp(args.pattern, flags);
  } catch (err) {
    throw new Error(
      `${args.source}.pattern failed to compile: ${
        err instanceof Error ? err.message : 'unknown error'
      }`,
    );
  }

  return {
    source: args.source,
    class_id: classId,
    rule_id: ruleId,
    action: args.action,
    pattern: regex,
    pattern_source: args.pattern,
    pattern_flags: flags,
    ...(args.redaction_token ? { redaction_token: args.redaction_token } : {}),
  };
}

async function computeDeterministicCustomRuleId(args: {
  class_id: string;
  action: DataHandlingAction;
  pattern: string;
  flags: string;
  redaction_token?: string;
}): Promise<string> {
  const canonical = canonicalizeJson({
    class_id: args.class_id,
    action: args.action,
    pattern: args.pattern,
    flags: args.flags,
    redaction_token: args.redaction_token ?? null,
  });
  const digest = await sha256B64u(new TextEncoder().encode(canonical));
  return `prv.dlp.custom.${args.class_id}.${digest.slice(0, 16)}.v1`;
}

async function parseCustomDataHandlingRules(raw: string | undefined): Promise<DataHandlingRule[]> {
  if (!raw || raw.trim().length === 0) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `${DLP_CUSTOM_RULES_ENV} must be valid JSON: ${
        err instanceof Error ? err.message : 'unknown error'
      }`,
    );
  }

  if (!Array.isArray(parsed)) {
    throw new Error(`${DLP_CUSTOM_RULES_ENV} must be a JSON array of custom rules.`);
  }

  const customRules: DataHandlingRule[] = [];
  for (let i = 0; i < parsed.length; i++) {
    const item = parsed[i];
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      throw new Error(`${DLP_CUSTOM_RULES_ENV}[${i}] must be an object.`);
    }

    const candidate = item as Partial<DataHandlingCustomRuleInput>;
    if (typeof candidate.class_id !== 'string' || candidate.class_id.trim().length === 0) {
      throw new Error(`${DLP_CUSTOM_RULES_ENV}[${i}].class_id must be a non-empty string.`);
    }
    if (!isDataHandlingAction(candidate.action)) {
      throw new Error(`${DLP_CUSTOM_RULES_ENV}[${i}].action is invalid.`);
    }
    if (typeof candidate.pattern !== 'string' || candidate.pattern.length === 0) {
      throw new Error(`${DLP_CUSTOM_RULES_ENV}[${i}].pattern must be a non-empty string.`);
    }

    const classId = normalizeDataHandlingClassId(
      candidate.class_id,
      `${DLP_CUSTOM_RULES_ENV}[${i}].class_id`,
    );
    const flags = normalizeRegexFlags(
      candidate.flags,
      `${DLP_CUSTOM_RULES_ENV}[${i}].flags`,
    );
    const deterministicRuleId = await computeDeterministicCustomRuleId({
      class_id: classId,
      action: candidate.action,
      pattern: candidate.pattern,
      flags,
      redaction_token: candidate.redaction_token,
    });
    if (!DLP_CUSTOM_RULE_ID_PATTERN.test(deterministicRuleId)) {
      throw new Error(
        `${DLP_CUSTOM_RULES_ENV}[${i}] computed deterministic rule id is invalid: ${deterministicRuleId}.`,
      );
    }

    if (candidate.rule_id !== undefined) {
      const providedRuleId = candidate.rule_id.trim();
      if (!DLP_RULE_ID_PATTERN.test(providedRuleId)) {
        throw new Error(`${DLP_CUSTOM_RULES_ENV}[${i}].rule_id contains unsupported characters.`);
      }
      if (providedRuleId !== deterministicRuleId) {
        throw new Error(
          `${DLP_CUSTOM_RULES_ENV}[${i}].rule_id must equal deterministic id ${deterministicRuleId}.`,
        );
      }
    }

    customRules.push(
      buildDataHandlingRule({
        source: 'custom',
        class_id: classId,
        rule_id: deterministicRuleId,
        action: candidate.action,
        pattern: candidate.pattern,
        flags,
        redaction_token: candidate.redaction_token,
      }),
    );
  }

  customRules.sort((a, b) => a.rule_id.localeCompare(b.rule_id));
  const duplicateRuleIds = new Set<string>();
  for (const rule of customRules) {
    if (duplicateRuleIds.has(rule.rule_id)) {
      throw new Error(
        `${DLP_CUSTOM_RULES_ENV} includes duplicate deterministic rule_id: ${rule.rule_id}.`,
      );
    }
    duplicateRuleIds.add(rule.rule_id);
  }

  return customRules;
}

async function computeDataHandlingRulesetHash(rules: readonly DataHandlingRule[]): Promise<string> {
  const canonical = canonicalizeJson(
    [...rules]
      .map((rule) => ({
        source: rule.source,
        class_id: rule.class_id,
        rule_id: rule.rule_id,
        action: rule.action,
        pattern: rule.pattern_source,
        flags: rule.pattern_flags,
        redaction_token: rule.redaction_token ?? null,
      }))
      .sort((a, b) => a.rule_id.localeCompare(b.rule_id)),
  );
  return sha256B64u(new TextEncoder().encode(canonical));
}

async function resolveDataHandlingPolicyConfig(): Promise<DataHandlingPolicyConfig> {
  const builtinRules = DLP_BUILTIN_RULE_DEFINITIONS.map((rule) =>
    buildDataHandlingRule({
      source: 'builtin',
      class_id: rule.class_id,
      rule_id: rule.rule_id,
      action: rule.action,
      pattern: rule.pattern,
      flags: rule.flags,
      redaction_token: rule.redaction_token,
    }),
  );

  const customRules = await parseCustomDataHandlingRules(process.env[DLP_CUSTOM_RULES_ENV]);
  const rules = [...builtinRules, ...customRules];
  const rulesetHash = await computeDataHandlingRulesetHash(rules);

  return {
    policy_version: DLP_POLICY_VERSION,
    taxonomy_version: DLP_TAXONOMY_VERSION,
    ruleset_hash_b64u: rulesetHash,
    built_in_rule_count: builtinRules.length,
    custom_rule_count: customRules.length,
    rules,
  };
}

function cloneRegex(regex: RegExp): RegExp {
  return new RegExp(regex.source, regex.flags);
}

function cloneRegexForGlobalScan(regex: RegExp): RegExp {
  return regex.flags.includes('g')
    ? cloneRegex(regex)
    : new RegExp(regex.source, `${regex.flags}g`);
}

function countMatches(text: string, pattern: RegExp): number {
  const matcher = cloneRegexForGlobalScan(pattern);
  let count = 0;
  let result: RegExpExecArray | null;

  while ((result = matcher.exec(text)) !== null) {
    count += 1;
    if (result[0].length === 0) {
      matcher.lastIndex += 1;
    }
  }

  return count;
}

function redactionOperationComparator(
  left: DataHandlingRedactionOperation,
  right: DataHandlingRedactionOperation,
): number {
  const classOrder = left.class_id.localeCompare(right.class_id);
  if (classOrder !== 0) return classOrder;
  const ruleOrder = left.rule_id.localeCompare(right.rule_id);
  if (ruleOrder !== 0) return ruleOrder;
  return left.path.localeCompare(right.path);
}

function escapeJsonPathSegment(segment: string): string {
  if (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(segment)) return `.${segment}`;
  return `[${JSON.stringify(segment)}]`;
}

function applyRegexRedaction(args: {
  originalText: string;
  redactionRules: readonly DataHandlingRule[];
}): {
  text: string;
  strategy: DataHandlingRedactionStrategy;
  operations: DataHandlingRedactionOperation[];
} {
  let redactedText = args.originalText;
  const operations: DataHandlingRedactionOperation[] = [];

  for (const rule of args.redactionRules) {
    const replacement = rule.redaction_token ?? '[REDACTED]';
    const matchCount = countMatches(redactedText, rule.pattern);
    if (matchCount === 0) continue;
    redactedText = redactedText.replace(
      cloneRegexForGlobalScan(rule.pattern),
      replacement,
    );
    operations.push({
      class_id: rule.class_id,
      rule_id: rule.rule_id,
      path: '$',
      match_count: matchCount,
      redaction_token: replacement,
    });
  }

  operations.sort(redactionOperationComparator);
  return {
    text: redactedText,
    strategy: operations.length > 0 ? 'text_regex' : 'none',
    operations,
  };
}

function tryApplyStructuredJsonRedaction(args: {
  originalText: string;
  redactionRules: readonly DataHandlingRule[];
}): {
  text: string;
  strategy: DataHandlingRedactionStrategy;
  operations: DataHandlingRedactionOperation[];
} | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(args.originalText);
  } catch {
    return null;
  }

  const operations: DataHandlingRedactionOperation[] = [];
  const sortedRules = [...args.redactionRules].sort((a, b) =>
    a.rule_id.localeCompare(b.rule_id),
  );

  const redactNode = (value: unknown, path: string): unknown => {
    if (typeof value === 'string') {
      let next = value;
      for (const rule of sortedRules) {
        const matchCount = countMatches(next, rule.pattern);
        if (matchCount === 0) continue;
        const replacement = rule.redaction_token ?? '[REDACTED]';
        next = next.replace(cloneRegexForGlobalScan(rule.pattern), replacement);
        operations.push({
          class_id: rule.class_id,
          rule_id: rule.rule_id,
          path,
          match_count: matchCount,
          redaction_token: replacement,
        });
      }
      return next;
    }

    if (Array.isArray(value)) {
      return value.map((entry, index) => redactNode(entry, `${path}[${index}]`));
    }

    if (value !== null && typeof value === 'object') {
      const input = value as Record<string, unknown>;
      const output: Record<string, unknown> = {};
      for (const key of Object.keys(input).sort((a, b) => a.localeCompare(b))) {
        output[key] = redactNode(input[key], `${path}${escapeJsonPathSegment(key)}`);
      }
      return output;
    }

    return value;
  };

  const redacted = redactNode(parsed, '$');
  operations.sort(redactionOperationComparator);
  return {
    text: JSON.stringify(redacted),
    strategy: operations.length > 0 ? 'json_structured' : 'none',
    operations,
  };
}

function readSingleHeader(
  headers: Record<string, string | string[] | undefined>,
  key: string,
): string | undefined {
  const wanted = key.toLowerCase();
  for (const [headerKey, value] of Object.entries(headers)) {
    if (headerKey.toLowerCase() !== wanted || value === undefined) continue;
    if (Array.isArray(value)) return value[0]?.trim();
    return value.trim();
  }
  return undefined;
}

function buildDataHandlingReasonCode(args: {
  action: DataHandlingAction;
  approval_required: boolean;
  approval_satisfied: boolean;
}): string {
  if (args.action === 'block') return 'PRV_DLP_BLOCKED';
  if (args.action === 'redact') return 'PRV_DLP_REDACTED';
  if (args.action === 'require_approval') return 'PRV_DLP_APPROVAL_REQUIRED';
  if (args.approval_required && args.approval_satisfied) return 'PRV_DLP_APPROVAL_GRANTED';
  return 'PRV_DLP_ALLOW';
}

function parseDidAllowlist(raw: string | undefined): Set<string> {
  if (!raw || raw.trim().length === 0) return new Set<string>();
  const dids = new Set<string>();
  for (const part of raw.split(',')) {
    const normalized = part.trim();
    if (normalized.length > 0) dids.add(normalized);
  }
  return dids;
}

function parseHeaderJsonObject(value: string): Record<string, unknown> | null {
  const trimmed = value.trim();
  if (trimmed.length === 0) return null;

  if (trimmed.startsWith('{')) {
    try {
      const parsed = JSON.parse(trimmed);
      return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : null;
    } catch {
      return null;
    }
  }

  try {
    const decoded = new TextDecoder().decode(base64UrlDecode(trimmed));
    const parsed = JSON.parse(decoded);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function base58Decode(input: string): Uint8Array {
  const bytes: number[] = [0];
  for (const char of input) {
    const value = BASE58_ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`invalid base58 character: ${char}`);
    }
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] *= 58;
    }
    bytes[0] += value;
    let carry = 0;
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] += carry;
      carry = bytes[i] >> 8;
      bytes[i] &= 0xff;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of input) {
    if (char !== '1') break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

function decodeDidKeyPublicKey(did: string): Uint8Array | null {
  if (!did.startsWith('did:key:z')) return null;
  try {
    const decoded = base58Decode(did.slice('did:key:z'.length));
    if (decoded.length < 3) return null;
    if (decoded[0] !== 0xed || decoded[1] !== 0x01) return null;
    return decoded.slice(2);
  } catch {
    return null;
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const src = bytes.buffer;
  if (src instanceof ArrayBuffer) {
    return src.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }

  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function verifyEd25519DidKeySignature(args: {
  signerDid: string;
  signatureB64u: string;
  payloadHashB64u: string;
}): Promise<boolean> {
  const publicKeyRaw = decodeDidKeyPublicKey(args.signerDid);
  if (!publicKeyRaw) return false;
  const verifyKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(publicKeyRaw),
    'Ed25519',
    false,
    ['verify'],
  );
  return await crypto.subtle.verify(
    'Ed25519',
    verifyKey,
    toArrayBuffer(base64UrlDecode(args.signatureB64u)),
    toArrayBuffer(new TextEncoder().encode(args.payloadHashB64u)),
  );
}

async function computeApprovalScopeHashB64u(args: {
  provider: string;
  classes: DataHandlingClassMatch[];
  effectivePolicyHashB64u: string;
}): Promise<string> {
  const approvalClassIds = [...new Set(
    args.classes
      .filter((entry) => entry.action === 'require_approval')
      .map((entry) => entry.class_id),
  )].sort((a, b) => a.localeCompare(b));
  const scope = {
    scope_version: DLP_APPROVAL_SCOPE_VERSION,
    provider: normalizePolicyModel(args.provider),
    policy_version: DLP_POLICY_VERSION,
    effective_policy_hash_b64u: args.effectivePolicyHashB64u,
    class_ids: approvalClassIds,
  };
  const canonical = canonicalizeJson(scope);
  return await sha256B64u(new TextEncoder().encode(canonical));
}

function parseApprovalReceiptFromHeader(
  value: string | undefined,
): SignedEnvelope<HumanApprovalReceiptPayload> | null {
  if (!value) return null;
  const parsed = parseHeaderJsonObject(value);
  if (!parsed) return null;
  if (
    parsed.envelope_version !== '1' ||
    parsed.envelope_type !== 'human_approval_receipt' ||
    parsed.hash_algorithm !== 'SHA-256' ||
    parsed.algorithm !== 'Ed25519' ||
    typeof parsed.payload_hash_b64u !== 'string' ||
    typeof parsed.signature_b64u !== 'string' ||
    typeof parsed.signer_did !== 'string' ||
    typeof parsed.issued_at !== 'string' ||
    typeof parsed.payload !== 'object' ||
    parsed.payload === null ||
    Array.isArray(parsed.payload)
  ) {
    return null;
  }
  return parsed as unknown as SignedEnvelope<HumanApprovalReceiptPayload>;
}

interface ApprovalReceiptValidationResult {
  valid: boolean;
  reason?: string;
  receiptEnvelope: SignedEnvelope<HumanApprovalReceiptPayload> | null;
  receiptHashB64u: string | null;
  receiptSignerDid: string | null;
  scopeHashB64u: string | null;
}

async function validateApprovalReceipt(args: {
  approvalReceiptHeader: string | undefined;
  expectedAgentDid: string;
  expectedRunId: string;
  expectedEventHashB64u: string;
  expectedPolicyHashB64u: string | null;
  expectedScopeHashB64u: string | null;
  approverDidAllowlist: Set<string>;
  decisionTimestampMs: number;
}): Promise<ApprovalReceiptValidationResult> {
  const receiptEnvelope = parseApprovalReceiptFromHeader(args.approvalReceiptHeader);
  if (!receiptEnvelope) {
    return {
      valid: false,
      reason: 'approval_receipt_missing_or_malformed',
      receiptEnvelope: null,
      receiptHashB64u: null,
      receiptSignerDid: null,
      scopeHashB64u: args.expectedScopeHashB64u,
    };
  }

  if (
    args.approverDidAllowlist.size === 0 ||
    !args.approverDidAllowlist.has(receiptEnvelope.signer_did)
  ) {
    return {
      valid: false,
      reason: 'approval_receipt_signer_not_allowlisted',
      receiptEnvelope: null,
      receiptHashB64u: null,
      receiptSignerDid: null,
      scopeHashB64u: args.expectedScopeHashB64u,
    };
  }

  const payload = receiptEnvelope.payload as unknown as Record<string, unknown>;
  if (
    payload.receipt_version !== '1' ||
    (payload.approval_type !== 'explicit_approve' && payload.approval_type !== 'auto_approve') ||
    typeof payload.approver_subject !== 'string' ||
    payload.approver_subject.trim().length === 0 ||
    typeof payload.agent_did !== 'string' ||
    payload.agent_did !== args.expectedAgentDid ||
    typeof payload.scope_hash_b64u !== 'string' ||
    typeof payload.policy_hash_b64u !== 'string' ||
    typeof payload.timestamp !== 'string' ||
    typeof payload.minted_capability_ttl_seconds !== 'number' ||
    !Number.isInteger(payload.minted_capability_ttl_seconds) ||
    payload.minted_capability_ttl_seconds <= 0 ||
    payload.hash_algorithm !== 'SHA-256'
  ) {
    return {
      valid: false,
      reason: 'approval_receipt_payload_invalid',
      receiptEnvelope: null,
      receiptHashB64u: null,
      receiptSignerDid: null,
      scopeHashB64u: args.expectedScopeHashB64u,
    };
  }

  if (
    !args.expectedPolicyHashB64u ||
    !args.expectedScopeHashB64u ||
    payload.policy_hash_b64u !== args.expectedPolicyHashB64u ||
    payload.scope_hash_b64u !== args.expectedScopeHashB64u
  ) {
    return {
      valid: false,
      reason: 'approval_receipt_policy_scope_mismatch',
      receiptEnvelope: null,
      receiptHashB64u: null,
      receiptSignerDid: null,
      scopeHashB64u: args.expectedScopeHashB64u,
    };
  }

  const receiptTimestampMs = Date.parse(payload.timestamp);
  if (!Number.isFinite(receiptTimestampMs)) {
    return {
      valid: false,
      reason: 'approval_receipt_timestamp_invalid',
      receiptEnvelope: null,
      receiptHashB64u: null,
      receiptSignerDid: null,
      scopeHashB64u: args.expectedScopeHashB64u,
    };
  }

  const expiresAtMs =
    receiptTimestampMs + (payload.minted_capability_ttl_seconds as number) * 1000;
  if (args.decisionTimestampMs < receiptTimestampMs || args.decisionTimestampMs > expiresAtMs) {
    return {
      valid: false,
      reason: 'approval_receipt_expired_or_not_yet_valid',
      receiptEnvelope: null,
      receiptHashB64u: null,
      receiptSignerDid: null,
      scopeHashB64u: args.expectedScopeHashB64u,
    };
  }

  const binding =
    typeof payload.binding === 'object' &&
    payload.binding !== null &&
    !Array.isArray(payload.binding)
      ? (payload.binding as Record<string, unknown>)
      : null;
  if (binding) {
    if (
      binding.run_id !== undefined &&
      (typeof binding.run_id !== 'string' || binding.run_id !== args.expectedRunId)
    ) {
      return {
        valid: false,
        reason: 'approval_receipt_run_binding_mismatch',
        receiptEnvelope: null,
        receiptHashB64u: null,
        receiptSignerDid: null,
        scopeHashB64u: args.expectedScopeHashB64u,
      };
    }
    if (
      binding.event_hash_b64u !== undefined &&
      (typeof binding.event_hash_b64u !== 'string' || binding.event_hash_b64u !== args.expectedEventHashB64u)
    ) {
      return {
        valid: false,
        reason: 'approval_receipt_event_binding_mismatch',
        receiptEnvelope: null,
        receiptHashB64u: null,
        receiptSignerDid: null,
        scopeHashB64u: args.expectedScopeHashB64u,
      };
    }
  }

  const computedPayloadHash = await hashJsonB64u(receiptEnvelope.payload);
  if (computedPayloadHash !== receiptEnvelope.payload_hash_b64u) {
    return {
      valid: false,
      reason: 'approval_receipt_payload_hash_mismatch',
      receiptEnvelope: null,
      receiptHashB64u: null,
      receiptSignerDid: null,
      scopeHashB64u: args.expectedScopeHashB64u,
    };
  }

  const signatureValid = await verifyEd25519DidKeySignature({
    signerDid: receiptEnvelope.signer_did,
    signatureB64u: receiptEnvelope.signature_b64u,
    payloadHashB64u: receiptEnvelope.payload_hash_b64u,
  });
  if (!signatureValid) {
    return {
      valid: false,
      reason: 'approval_receipt_signature_invalid',
      receiptEnvelope: null,
      receiptHashB64u: null,
      receiptSignerDid: null,
      scopeHashB64u: args.expectedScopeHashB64u,
    };
  }

  return {
    valid: true,
    receiptEnvelope,
    receiptHashB64u: receiptEnvelope.payload_hash_b64u,
    receiptSignerDid: receiptEnvelope.signer_did,
    scopeHashB64u: args.expectedScopeHashB64u,
  };
}

async function evaluateDataHandlingPolicy(args: {
  bodyBuffer: Buffer;
  policyConfig: DataHandlingPolicyConfig;
  enforcementMode: DataHandlingEnforcementMode;
  provider: string;
  runId: string;
  eventHashB64u: string;
  agentDid: string;
  effectivePolicyHashB64u: string | null;
  approvalReceiptHeader: string | undefined;
  approverDidAllowlist: Set<string>;
  decisionTimestampMs: number;
}): Promise<DataHandlingDecision> {
  const originalText = args.bodyBuffer.toString('utf-8');
  const classes: DataHandlingClassMatch[] = [];

  for (const rule of args.policyConfig.rules) {
    const matchCount = countMatches(originalText, rule.pattern);
    if (matchCount === 0) continue;

    classes.push({
      class_id: rule.class_id,
      rule_id: rule.rule_id,
      action: rule.action,
      match_count: matchCount,
    });
  }

  classes.sort((a, b) => {
    const classOrder = a.class_id.localeCompare(b.class_id);
    if (classOrder !== 0) return classOrder;
    return a.rule_id.localeCompare(b.rule_id);
  });

  const approvalRequired = classes.some((c) => c.action === 'require_approval');
  const approvalScopeHashB64u =
    approvalRequired && args.effectivePolicyHashB64u
      ? await computeApprovalScopeHashB64u({
          provider: args.provider,
          classes,
          effectivePolicyHashB64u: args.effectivePolicyHashB64u,
        })
      : null;

  const approvalReceiptValidation =
    approvalRequired
      ? await validateApprovalReceipt({
          approvalReceiptHeader: args.approvalReceiptHeader,
          expectedAgentDid: args.agentDid,
          expectedRunId: args.runId,
          expectedEventHashB64u: args.eventHashB64u,
          expectedPolicyHashB64u: args.effectivePolicyHashB64u,
          expectedScopeHashB64u: approvalScopeHashB64u,
          approverDidAllowlist: args.approverDidAllowlist,
          decisionTimestampMs: args.decisionTimestampMs,
        })
      : {
          valid: false,
          receiptEnvelope: null,
          receiptHashB64u: null,
          receiptSignerDid: null,
          scopeHashB64u: null,
        };
  const approvalSatisfied = approvalRequired && approvalReceiptValidation.valid;

  let wouldAction: DataHandlingAction = 'allow';
  if (classes.some((c) => c.action === 'block')) {
    wouldAction = 'block';
  } else if (approvalRequired && !approvalSatisfied) {
    wouldAction = 'require_approval';
  } else if (classes.some((c) => c.action === 'redact')) {
    wouldAction = 'redact';
  }

  if (
    approvalRequired &&
    approvalScopeHashB64u === null &&
    wouldAction !== 'block'
  ) {
    wouldAction = 'require_approval';
  }

  const redactionRules = args.policyConfig.rules
    .filter((rule) => rule.action === 'redact')
    .sort((a, b) => a.rule_id.localeCompare(b.rule_id));
  const redactionResult =
    redactionRules.length > 0
      ? tryApplyStructuredJsonRedaction({
          originalText,
          redactionRules,
        }) ??
        applyRegexRedaction({
          originalText,
          redactionRules,
        })
      : {
          text: originalText,
          strategy: 'none' as const,
          operations: [] as DataHandlingRedactionOperation[],
        };

  const wouldReasonCode = buildDataHandlingReasonCode({
    action: wouldAction,
    approval_required: approvalRequired,
    approval_satisfied: approvalSatisfied,
  });

  const isSimulation = args.enforcementMode === 'simulated';
  const action: DataHandlingAction = isSimulation ? 'allow' : wouldAction;
  const reasonCode = isSimulation
    ? DLP_SIMULATION_ALLOW_REASON_CODE
    : wouldReasonCode;

  const outboundBody =
    isSimulation
      ? args.bodyBuffer
      : action === 'redact'
        ? Buffer.from(redactionResult.text, 'utf-8')
        : args.bodyBuffer;
  const redactionApplied =
    !isSimulation &&
    action === 'redact' &&
    outboundBody.toString('utf-8') !== originalText;
  const originalHash = await sha256B64u(new Uint8Array(args.bodyBuffer));
  const outboundHash =
    action === 'block' || action === 'require_approval'
      ? null
      : await sha256B64u(new Uint8Array(outboundBody));

  const redactionStrategy: DataHandlingRedactionStrategy =
    isSimulation ? 'none' : redactionResult.strategy;
  const redactionOperations =
    isSimulation ? [] : redactionResult.operations;

  return {
    action,
    reason_code: reasonCode,
    enforcement_mode: args.enforcementMode,
    would_action: wouldAction,
    would_reason_code: wouldReasonCode,
    classes,
    policy: {
      taxonomy_version: args.policyConfig.taxonomy_version,
      ruleset_hash_b64u: args.policyConfig.ruleset_hash_b64u,
      built_in_rule_count: args.policyConfig.built_in_rule_count,
      custom_rule_count: args.policyConfig.custom_rule_count,
    },
    approval_required: approvalRequired,
    approval_satisfied: approvalSatisfied,
    approval_scope_hash_b64u: approvalScopeHashB64u,
    approval_receipt_hash_b64u: approvalReceiptValidation.receiptHashB64u,
    approval_receipt_signer_did: approvalReceiptValidation.receiptSignerDid,
    approval_receipt_envelope: approvalReceiptValidation.receiptEnvelope,
    redaction_applied: redactionApplied,
    redaction_strategy: redactionStrategy,
    redaction_operations: redactionOperations,
    outboundBody,
    original_payload_hash_b64u: originalHash,
    outbound_payload_hash_b64u: outboundHash,
  };
}

async function buildFallbackDataHandlingReceiptPayload(args: {
  runId: string;
  provider: string;
  classifierTimestamp: string;
  bodyBuffer: Buffer;
  effectivePolicyHashB64u: string | null;
  policyConfig: DataHandlingPolicyConfig | null;
  enforcementMode: DataHandlingEnforcementMode;
}): Promise<DataHandlingReceiptPayload> {
  const originalPayloadHash = await sha256B64u(new Uint8Array(args.bodyBuffer));
  const isSimulation = args.enforcementMode === 'simulated';
  const fallbackScopeHash =
    args.effectivePolicyHashB64u
      ? await computeApprovalScopeHashB64u({
          provider: args.provider,
          classes: [],
          effectivePolicyHashB64u: args.effectivePolicyHashB64u,
        })
      : null;
  return {
    receipt_version: '1',
    receipt_id: `dhr_${randomUUID()}`,
    policy_version: DLP_POLICY_VERSION,
    effective_policy_hash_b64u: args.effectivePolicyHashB64u ?? 'unknown_policy_hash',
    ...(args.policyConfig
      ? {
          policy: {
            taxonomy_version: args.policyConfig.taxonomy_version,
            ruleset_hash_b64u: args.policyConfig.ruleset_hash_b64u,
            built_in_rule_count: args.policyConfig.built_in_rule_count,
            custom_rule_count: args.policyConfig.custom_rule_count,
          },
        }
      : {}),
    run_id: args.runId,
    provider: args.provider,
    action: isSimulation ? 'allow' : 'require_approval',
    reason_code: isSimulation
      ? DLP_SIMULATION_ALLOW_REASON_CODE
      : 'PRV_DLP_CLASSIFIER_ERROR',
    classes: [],
    enforcement: {
      mode: args.enforcementMode,
      would_action: 'require_approval',
      would_reason_code: 'PRV_DLP_CLASSIFIER_ERROR',
      would_block: false,
      would_require_approval: true,
      would_redact: false,
    },
    approval: {
      required: true,
      satisfied: false,
      mechanism: 'signed_receipt',
      scope_hash_b64u: fallbackScopeHash,
      receipt_hash_b64u: null,
      receipt_signer_did: null,
      receipt_envelope: null,
    },
    redaction: {
      applied: false,
      original_payload_hash_b64u: originalPayloadHash,
      outbound_payload_hash_b64u: isSimulation ? originalPayloadHash : null,
      strategy: 'none',
      operations: [],
    },
    timestamp: args.classifierTimestamp,
  };
}

async function signDataHandlingReceipt(
  payload: DataHandlingReceiptPayload,
  signer: { did: string; sign(data: Uint8Array): Promise<string> },
): Promise<SignedEnvelope<DataHandlingReceiptPayload>> {
  const payloadHash = await hashJsonB64u(payload);
  const signature = await signer.sign(new TextEncoder().encode(payloadHash));
  return {
    envelope_version: '1',
    envelope_type: 'data_handling_receipt',
    payload,
    payload_hash_b64u: payloadHash,
    hash_algorithm: 'SHA-256',
    signature_b64u: signature,
    algorithm: 'Ed25519',
    signer_did: signer.did,
    issued_at: payload.timestamp,
  };
}

/**
 * Read the full request body from an IncomingMessage.
 */
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Resolve provider + upstream path from incoming local-proxy route.
 *
 * Supported patterns:
 *   /v1/proxy/<provider>[/...]  -> provider + mapped upstream path
 *   /v1/chat/completions        -> openai /v1/chat/completions
 *   /v1/responses               -> openai /v1/responses
 *   /v1/messages                -> anthropic /v1/messages
 */
interface ProxyRoute {
  provider: string;
  upstreamPath: string;
}

function parseProxyRoute(pathname: string): ProxyRoute | null {
  if (pathname.startsWith('/v1/proxy/')) {
    const rest = pathname.slice('/v1/proxy/'.length);
    const slash = rest.indexOf('/');
    const provider = slash === -1 ? rest : rest.slice(0, slash);
    if (!provider) return null;

    const suffix = slash === -1 ? '' : rest.slice(slash); // e.g. /models
    const defaultPath = UPSTREAM_PATHS[provider] ?? '/v1/chat/completions';
    const upstreamPath = !suffix
      ? defaultPath
      : (suffix.startsWith('/v1/') ? suffix : `/v1${suffix}`);

    return { provider, upstreamPath };
  }

  if (pathname === '/v1/chat/completions') {
    return { provider: 'openai', upstreamPath: '/v1/chat/completions' };
  }
  if (pathname === '/v1/responses') {
    return { provider: 'openai', upstreamPath: '/v1/responses' };
  }
  if (pathname === '/v1/messages') {
    return { provider: 'anthropic', upstreamPath: '/v1/messages' };
  }

  return null;
}

/**
 * Extract provider API key from incoming request headers.
 * Checks X-Provider-API-Key first, then Authorization: Bearer.
 */
function extractProviderKey(headers: Record<string, string | string[] | undefined>): string | undefined {
  const explicit = headers['x-provider-api-key'];
  if (typeof explicit === 'string' && explicit.trim().length > 0) {
    return explicit.trim();
  }

  const auth = headers['authorization'];
  if (typeof auth === 'string') {
    const match = auth.match(/^Bearer\s+(.+)/i);
    if (match?.[1]) return match[1].trim();
  }

  return undefined;
}

/**
 * Copy incoming request headers for upstream forwarding while stripping hop-by-hop headers.
 *
 * Important for Codex compatibility:
 * - Preserve Content-Encoding when clients send compressed JSON bodies.
 * - Preserve provider-specific headers (OpenAI-Beta, Anthropic-Version, etc).
 */
function buildUpstreamRequestHeaders(
  incomingHeaders: Record<string, string | string[] | undefined>,
  bodyBuffer: Buffer,
): Record<string, string> {
  const headers: Record<string, string> = {};
  const hopByHop = new Set([
    'host',
    'content-length',
    'connection',
    'transfer-encoding',
    'proxy-connection',
    'keep-alive',
    DLP_APPROVAL_HEADER,
  ]);

  for (const [key, value] of Object.entries(incomingHeaders)) {
    if (!value) continue;
    const lower = key.toLowerCase();
    if (hopByHop.has(lower)) continue;
    headers[key] = Array.isArray(value) ? value.join(', ') : value;
  }

  // Sensible default when caller omitted content-type on non-empty body.
  if (bodyBuffer.length > 0 && !Object.keys(headers).some(k => k.toLowerCase() === 'content-type')) {
    headers['Content-Type'] = 'application/json';
  }

  return headers;
}

/**
 * ZlibError fix: Node/Bun fetch auto-decompresses payloads but leaves compression
 * headers intact. We rigorously strip them here to prevent double-decompression.
 */
function extractSafeHeaders(rawHeaders: Headers): Record<string, string> {
  const safeHeaders: Record<string, string> = {};
  rawHeaders.forEach((value, key) => {
    const lower = key.toLowerCase();
    if (lower === 'content-encoding' ||
        lower === 'content-length' ||
        lower === 'transfer-encoding' ||
        lower === 'connection') {
      return;
    }
    safeHeaders[key] = value;
  });
  return safeHeaders;
}

/**
 * Forward a request to clawproxy with receipt-binding headers.
 * Returns a ReadableStream for SSE responses (true streaming passthrough)
 * and a Buffer for non-streaming responses.
 */
async function forwardToClawproxy(
  provider: string,
  upstreamPathWithQuery: string,
  method: string,
  bodyBuffer: Buffer,
  incomingHeaders: Record<string, string | string[] | undefined>,
  providerApiKey: string | undefined,
  proxyToken: string | undefined,
  clawproxyUrl: string,
  runId: string,
  agentDid: string,
  idempotencyKey: string,
  eventHash: string,
  egressPolicy: EgressPolicy | undefined,
): Promise<{ status: number; headers: Record<string, string>; body: Buffer; isStream: boolean; stream?: ReadableStream<Uint8Array> | null }> {
  // clawproxy exposes a single canonical POST /v1/proxy/:provider endpoint.
  // Do not forward SDK-specific suffixes like /chat/completions or /messages,
  // or clawproxy will return NOT_FOUND and we will silently fall back to
  // unsigned preload receipts instead of collecting signed gateway receipts.
  const queryIndex = upstreamPathWithQuery.indexOf('?');
  const query = queryIndex === -1 ? '' : upstreamPathWithQuery.slice(queryIndex);
  const targetUrl = `${clawproxyUrl}/v1/proxy/${provider}${query}`;
  enforceEgressPolicy(targetUrl, egressPolicy);

  let forwardedBodyBuffer = bodyBuffer;
  if (provider === 'google' && bodyBuffer.length > 0) {
    try {
      const parsed = JSON.parse(bodyBuffer.toString('utf-8')) as Record<string, unknown>;
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        delete parsed['store'];
        delete parsed['prompt_cache_key'];
        delete parsed['prompt_cache_retention'];
        delete parsed['service_tier'];
        delete parsed['reasoning'];
        delete parsed['include'];
        forwardedBodyBuffer = Buffer.from(JSON.stringify(parsed), 'utf-8');
      }
    } catch {
      // Non-JSON payloads are forwarded unchanged.
    }
  }

  const headers = buildUpstreamRequestHeaders(incomingHeaders, forwardedBodyBuffer);
  delete headers['authorization'];
  delete headers['Authorization'];
  delete headers['x-goog-api-key'];
  delete headers['X-Goog-Api-Key'];
  delete headers['api-key'];
  delete headers['Api-Key'];
  delete headers['x-api-key'];
  delete headers['X-Api-Key'];
  headers['X-Run-Id'] = runId;
  headers['X-Event-Hash'] = eventHash;
  headers['X-Idempotency-Key'] = idempotencyKey;
  headers['X-Agent-DID'] = agentDid;

  if (providerApiKey) {
    headers['X-Provider-API-Key'] = providerApiKey;
  }
  if (proxyToken && proxyToken.trim().length > 0) {
    headers['X-CST'] = proxyToken.trim();
  }

  const upperMethod = method.toUpperCase();
  const hasBody = upperMethod !== 'GET' && upperMethod !== 'HEAD' && forwardedBodyBuffer.length > 0;

  const res = await fetch(targetUrl, {
    method: upperMethod,
    headers,
    ...(hasBody ? { body: new Uint8Array(forwardedBodyBuffer) } : {}),
  });

  const contentType = res.headers.get('content-type') ?? '';
  const isStream = contentType.includes('text/event-stream');
  const safeHeaders = extractSafeHeaders(res.headers);

  // For SSE: return the ReadableStream directly for true streaming passthrough.
  // Buffering entire SSE streams wastes memory on long agent sessions.
  if (isStream && res.body) {
    return { status: res.status, headers: safeHeaders, stream: res.body, isStream: true, body: Buffer.alloc(0) };
  } else {
    const responseBuffer = Buffer.from(await res.arrayBuffer());
    return { status: res.status, headers: safeHeaders, stream: null, isStream: false, body: responseBuffer };
  }
}

/** Map provider name to upstream API base URL. */
const UPSTREAM_URLS: Record<string, string> = {
  openai: 'https://api.openai.com',
  anthropic: 'https://api.anthropic.com',
  google: 'https://generativelanguage.googleapis.com',
};

/** Map provider to the expected API path. */
const UPSTREAM_PATHS: Record<string, string> = {
  openai: '/v1/chat/completions',
  anthropic: '/v1/messages',
};

/**
 * Forward a request directly to the upstream provider (passthrough mode).
 * Preserves original request method/path/headers for maximal client compatibility.
 * Returns a ReadableStream for SSE responses (true streaming passthrough).
 */
async function forwardToUpstream(
  provider: string,
  upstreamPathWithQuery: string,
  method: string,
  bodyBuffer: Buffer,
  incomingHeaders: Record<string, string | string[] | undefined>,
  egressPolicy: EgressPolicy | undefined,
): Promise<{ status: number; headers: Record<string, string>; body: Buffer; isStream: boolean; stream?: ReadableStream<Uint8Array> | null }> {
  const baseUrl = UPSTREAM_URLS[provider] ?? `https://api.${provider}.com`;
  const targetUrl = `${baseUrl}${upstreamPathWithQuery}`;
  enforceEgressPolicy(targetUrl, egressPolicy);

  const headers = buildUpstreamRequestHeaders(incomingHeaders, bodyBuffer);
  const upperMethod = method.toUpperCase();
  const hasBody = upperMethod !== 'GET' && upperMethod !== 'HEAD' && bodyBuffer.length > 0;

  const res = await fetch(targetUrl, {
    method: upperMethod,
    headers,
    ...(hasBody ? { body: new Uint8Array(bodyBuffer) } : {}),
  });

  const contentType = res.headers.get('content-type') ?? '';
  const isStream = contentType.includes('text/event-stream');
  const safeHeaders = extractSafeHeaders(res.headers);

  if (isStream && res.body) {
    return { status: res.status, headers: safeHeaders, stream: res.body, isStream: true, body: Buffer.alloc(0) };
  } else {
    const responseBuffer = Buffer.from(await res.arrayBuffer());
    return { status: res.status, headers: safeHeaders, body: responseBuffer, isStream: false, stream: null };
  }
}

/**
 * Extract receipt envelope from a clawproxy JSON response.
 */
function isSignedGatewayReceiptEnvelope(
  value: unknown,
): value is SignedEnvelope<GatewayReceiptPayload> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  return (
    candidate['envelope_version'] === '1' &&
    candidate['envelope_type'] === 'gateway_receipt' &&
    typeof candidate['payload'] === 'object' &&
    candidate['payload'] !== null &&
    !Array.isArray(candidate['payload']) &&
    typeof candidate['payload_hash_b64u'] === 'string' &&
    candidate['payload_hash_b64u'].length > 0 &&
    typeof candidate['signature_b64u'] === 'string' &&
    candidate['signature_b64u'].length > 0 &&
    typeof candidate['signer_did'] === 'string' &&
    candidate['signer_did'].length > 0 &&
    typeof candidate['issued_at'] === 'string' &&
    candidate['issued_at'].length > 0
  );
}

function extractReceiptFromResponse(body: Buffer): {
  envelope?: SignedEnvelope<GatewayReceiptPayload>;
  provider: string;
  model: string;
} {
  try {
    const parsed = JSON.parse(body.toString('utf-8')) as Record<string, unknown>;
    const maybeEnvelope = parsed['_receipt_envelope'];
    const envelope = isSignedGatewayReceiptEnvelope(maybeEnvelope)
      ? maybeEnvelope
      : undefined;

    // Extract provider/model from envelope payload or legacy receipt
    let provider = 'unknown';
    let model = 'unknown';

    if (envelope?.payload) {
      provider = envelope.payload.provider ?? 'unknown';
      model = envelope.payload.model ?? 'unknown';
    } else {
      const legacyReceipt = parsed['_receipt'] as Record<string, unknown> | undefined;
      if (legacyReceipt) {
        provider = (legacyReceipt['provider'] as string) ?? 'unknown';
        model = (legacyReceipt['model'] as string) ?? 'unknown';
      }
    }

    return { envelope, provider, model };
  } catch {
    return { provider: 'unknown', model: 'unknown' };
  }
}

/**
 * Extract receipt from a streaming (SSE) response.
 * Clawproxy appends the receipt as a final SSE event.
 */
function extractReceiptFromStream(body: Buffer): {
  envelope?: SignedEnvelope<GatewayReceiptPayload>;
  provider: string;
  model: string;
} {
  const text = body.toString('utf-8');
  const lines = text.split('\n');

  const parseCommentEnvelope = (value: string): SignedEnvelope<GatewayReceiptPayload> | undefined => {
    try {
      const normalized = value.trim().replace(/-/g, '+').replace(/_/g, '/');
      const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
      const decoded = Buffer.from(padded, 'base64').toString('utf-8');
      const parsed = JSON.parse(decoded) as unknown;
      if (isSignedGatewayReceiptEnvelope(parsed)) return parsed;
    } catch {
      // ignore malformed trailer comments
    }
    return undefined;
  };

  // Look for receipt event in SSE stream
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;

    if (line.startsWith(':clawproxy_receipt_envelope_b64u=')) {
      const envelope = parseCommentEnvelope(
        line.slice(':clawproxy_receipt_envelope_b64u='.length),
      );
      if (envelope) {
        return {
          envelope,
          provider: envelope.payload?.provider ?? 'unknown',
          model: envelope.payload?.model ?? 'unknown',
        };
      }
      continue;
    }

    // Look for data lines that might contain receipt
    if (line.startsWith('data: ')) {
      const data = line.slice(6).trim();
      if (data === '[DONE]') continue;
      try {
        const parsed = JSON.parse(data) as Record<string, unknown>;
        if (parsed['_receipt_envelope']) {
          const maybeEnvelope = parsed['_receipt_envelope'];
          if (isSignedGatewayReceiptEnvelope(maybeEnvelope)) {
            return {
              envelope: maybeEnvelope,
              provider: maybeEnvelope.payload?.provider ?? 'unknown',
              model: maybeEnvelope.payload?.model ?? 'unknown',
            };
          }
        }
      } catch {
        // Not JSON, skip
      }
    }
  }

  return { provider: 'unknown', model: 'unknown' };
}

function sanitizeSpanSeed(seed: string): string {
  const normalized = seed
    .replace(/[^A-Za-z0-9_-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '');

  return normalized.length > 0 ? normalized.slice(0, 64) : randomUUID().replace(/-/g, '');
}

function deriveGatewaySpanId(
  envelope: SignedEnvelope<GatewayReceiptPayload> | undefined,
  fallbackSeed: string,
): string {
  const explicit = envelope?.payload?.binding?.span_id;
  if (typeof explicit === 'string' && explicit.trim().length > 0) {
    return explicit;
  }

  const fromReceiptId = envelope?.payload?.receipt_id;
  if (typeof fromReceiptId === 'string' && fromReceiptId.trim().length > 0) {
    return `span_gateway_${sanitizeSpanSeed(fromReceiptId)}`;
  }

  return `span_gateway_${sanitizeSpanSeed(fallbackSeed)}`;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Start a local HTTP interceptor proxy.
 *
 * The proxy listens on a random port and intercepts LLM API calls,
 * forwarding them through clawproxy with proper receipt-binding headers.
 *
 * Supported routes:
 *   * /v1/proxy/openai[/...]      (method-preserving passthrough)
 *   * /v1/proxy/anthropic[/...]   (method-preserving passthrough)
 *   POST /v1/chat/completions     (alias for openai)
 *   POST /v1/responses            (alias for openai)
 *   POST /v1/messages             (alias for anthropic)
 *   GET  /health
 */
export async function startLocalProxy(options: ProxyOptions): Promise<LocalProxy> {
  const {
    agentDid,
    runId,
    clawproxyUrl = 'https://clawproxy.com',
    proxyToken,
    providerApiKey,
    policy = null,
    cwd,
    onViolation,
    passthrough = false,
    enforceEgressAllowlist = false,
    egressAllowlist = [],
    effectivePolicyHashB64u,
  } = options;

  const normalizedUrl = clawproxyUrl.replace(/\/+$/, '');
  const normalizedEgressAllowlist = normalizeEgressAllowlist(egressAllowlist);
  const egressPolicy: EgressPolicy | undefined = enforceEgressAllowlist
    ? { enforce: true, allowlist: normalizedEgressAllowlist }
    : undefined;
  const proofedMode = parseBooleanEnv(process.env['CLAWSIG_PROOFED']);
  const dataHandlingEnforcementMode =
    resolveDataHandlingEnforcementMode(proofedMode);
  const processorPolicy = resolveProcessorPolicy(proofedMode);
  const processorPolicyState: ProcessorPolicyState = {
    allowed_count: 0,
    denied_count: 0,
    used_processors: new Map(),
    blocked_attempts: [],
  };
  const eventChainEntries: EventChainEntry[] = [];
  const receipts: CollectedReceipt[] = [];
  const dataHandlingReceipts: SignedEnvelope<DataHandlingReceiptPayload>[] = [];
  let plannedPrevHash: string | null = null;
  let dataHandlingPolicyConfig: DataHandlingPolicyConfig | null = null;
  let dataHandlingPolicyConfigError: string | null = null;
  try {
    dataHandlingPolicyConfig = await resolveDataHandlingPolicyConfig();
  } catch (err) {
    dataHandlingPolicyConfigError = `Data handling policy config invalid: ${
      err instanceof Error ? err.message : 'unknown error'
    }`;
  }
  const approverDidAllowlist = parseDidAllowlist(
    process.env[DLP_APPROVER_DIDS_ENV] ?? process.env[DLP_APPROVER_DID_ENV],
  );
  const normalizedEffectivePolicyHash =
    typeof effectivePolicyHashB64u === 'string' && effectivePolicyHashB64u.trim().length > 0
      ? effectivePolicyHashB64u.trim()
      : null;

  // RED TEAM FIX #7: Ephemeral run salt for privacy.
  // Generate a 16-byte random salt per run.
  const runSaltBytes = randomBytes(16);
  const runSaltB64u = base64UrlEncode(runSaltBytes);

  // CAUSAL SIEVE: Initialize tool observability.
  // Parses LLM HTTP traffic to extract tool_calls/tool_results,
  // runs git diff between tool boundaries to detect file mutations.
  const sieve = new CausalSieve({
    agentDid,
    runId,
    cwd,
    policy,
    onViolation,
  });
  await sieve.initialize();

  const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', `http://127.0.0.1`);
    const pathname = url.pathname;

    // Health check
    if (req.method === 'GET' && pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', runId, receipts: receipts.length }));
      return;
    }

    const method = (req.method ?? 'GET').toUpperCase();
    const allowedMethods = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']);
    if (!allowedMethods.has(method)) {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'METHOD_NOT_ALLOWED', message: `Method ${method} is not supported` }));
      return;
    }

    const route = parseProxyRoute(pathname);
    if (!route) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'NOT_FOUND', message: `Unknown route: ${pathname}` }));
      return;
    }

    const provider = route.provider;
    const upstreamPathWithQuery = `${route.upstreamPath}${url.search}`;

    try {
      const bodyBuffer = (method === 'GET' || method === 'HEAD')
        ? Buffer.alloc(0)
        : await readBody(req);
      const idempotencyKey = randomUUID();
      const eventId = `evt_${randomUUID()}`;
      const eventTimestamp = new Date().toISOString();
      const payloadHashB64u = await hashJsonB64u({
        provider,
        method,
        nonce: idempotencyKey,
      });
      const plannedEventHeader: Omit<EventChainEntry, 'event_hash_b64u'> = {
        event_id: eventId,
        run_id: runId,
        event_type: 'llm_call',
        timestamp: eventTimestamp,
        payload_hash_b64u: payloadHashB64u,
        prev_hash_b64u: plannedPrevHash,
      };
      const eventHash = await hashJsonB64u(plannedEventHeader);
      const eventChainEntry: EventChainEntry = {
        ...plannedEventHeader,
        event_hash_b64u: eventHash,
      };
      plannedPrevHash = eventHash;
      eventChainEntries.push(eventChainEntry);

      // Extract provider key from the incoming request, fall back to constructor option
      const reqHeaders = req.headers as Record<string, string | string[] | undefined>;
      const incomingKey = extractProviderKey(reqHeaders) ?? providerApiKey;
      let outboundBodyBuffer = bodyBuffer;
      let simulationPreview:
        | {
            wouldAction: DataHandlingAction;
            wouldReasonCode: string;
          }
        | null = null;

      if (egressPolicy?.enforce) {
        const approvalReceiptHeader = readSingleHeader(reqHeaders, DLP_APPROVAL_HEADER);
        const contentEncoding = readSingleHeader(reqHeaders, 'content-encoding');
        const classifierTimestamp = new Date().toISOString();
        const classifierTimestampMs = Date.parse(classifierTimestamp);

        try {
          if (
            bodyBuffer.length > 0 &&
            contentEncoding !== undefined &&
            contentEncoding.trim().length > 0 &&
            contentEncoding.trim().toLowerCase() !== 'identity'
          ) {
            throw new Error(
              `Data handling classifier does not support content-encoding=${contentEncoding}.`,
            );
          }

          if (dataHandlingPolicyConfigError) {
            throw new Error(dataHandlingPolicyConfigError);
          }
          if (!dataHandlingPolicyConfig) {
            throw new Error('Data handling policy config unavailable.');
          }

          const decision = await evaluateDataHandlingPolicy({
            bodyBuffer,
            policyConfig: dataHandlingPolicyConfig,
            enforcementMode: dataHandlingEnforcementMode,
            provider,
            runId,
            eventHashB64u: eventHash,
            agentDid: agentDid.did,
            effectivePolicyHashB64u: normalizedEffectivePolicyHash,
            approvalReceiptHeader,
            approverDidAllowlist,
            decisionTimestampMs:
              Number.isFinite(classifierTimestampMs) ? classifierTimestampMs : Date.now(),
          });
          outboundBodyBuffer = decision.outboundBody;
          if (decision.enforcement_mode === 'simulated') {
            simulationPreview = {
              wouldAction: decision.would_action,
              wouldReasonCode: decision.would_reason_code,
            };
          }

          const receiptPayload: DataHandlingReceiptPayload = {
            receipt_version: '1',
            receipt_id: `dhr_${randomUUID()}`,
            policy_version: DLP_POLICY_VERSION,
            effective_policy_hash_b64u:
              normalizedEffectivePolicyHash ?? 'unknown_policy_hash',
            ...(decision.policy ? { policy: decision.policy } : {}),
            run_id: runId,
            provider,
            action: decision.action,
            reason_code: decision.reason_code,
            classes: decision.classes,
            enforcement: {
              mode: decision.enforcement_mode,
              would_action: decision.would_action,
              would_reason_code: decision.would_reason_code,
              would_block: decision.would_action === 'block',
              would_require_approval:
                decision.would_action === 'require_approval',
              would_redact: decision.would_action === 'redact',
            },
            approval: {
              required: decision.approval_required,
              satisfied: decision.approval_satisfied,
              mechanism: 'signed_receipt',
              scope_hash_b64u: decision.approval_scope_hash_b64u,
              receipt_hash_b64u: decision.approval_receipt_hash_b64u,
              receipt_signer_did: decision.approval_receipt_signer_did,
              receipt_envelope: decision.approval_receipt_envelope,
            },
            redaction: {
              applied: decision.redaction_applied,
              original_payload_hash_b64u: decision.original_payload_hash_b64u,
              outbound_payload_hash_b64u: decision.outbound_payload_hash_b64u,
              strategy: decision.redaction_strategy,
              operations: decision.redaction_operations,
            },
            timestamp: classifierTimestamp,
          };

          dataHandlingReceipts.push(
            await signDataHandlingReceipt(receiptPayload, {
              did: agentDid.did,
              sign: (data) => agentDid.sign(data),
            }),
          );

          if (decision.action === 'block' || decision.action === 'require_approval') {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: decision.reason_code,
              reason_code: decision.reason_code,
              action: decision.action,
              classes: decision.classes,
              message:
                decision.action === 'block'
                  ? 'Outbound payload blocked by data handling policy.'
                  : 'Outbound payload requires explicit approval and no valid signed approval receipt was provided.',
            }));
            return;
          }
        } catch (err) {
          const fallbackPayload = await buildFallbackDataHandlingReceiptPayload({
            runId,
            provider,
            classifierTimestamp,
            bodyBuffer,
            effectivePolicyHashB64u: normalizedEffectivePolicyHash,
            policyConfig: dataHandlingPolicyConfig,
            enforcementMode: dataHandlingEnforcementMode,
          });

          try {
            dataHandlingReceipts.push(
              await signDataHandlingReceipt(fallbackPayload, {
                did: agentDid.did,
                sign: (data) => agentDid.sign(data),
              }),
            );
          } catch {
            // best effort; return fail-closed even if nested receipt signing fails
          }

          if (dataHandlingEnforcementMode === 'simulated') {
            simulationPreview = {
              wouldAction: 'require_approval',
              wouldReasonCode: 'PRV_DLP_CLASSIFIER_ERROR',
            };
            outboundBodyBuffer = bodyBuffer;
          } else {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'PRV_DLP_CLASSIFIER_ERROR',
              reason_code: 'PRV_DLP_CLASSIFIER_ERROR',
              action: 'require_approval',
              message: err instanceof Error ? err.message : 'Data handling classifier failed closed.',
            }));
            return;
          }
        }
      }

      const processorRoute = buildProcessorRouteClaims({
        provider,
        bodyBuffer: outboundBodyBuffer,
        headers: reqHeaders,
        policy: processorPolicy,
      });
      const processorDecision = evaluateProcessorPolicy(processorPolicy, processorRoute);
      recordProcessorPolicyDecision(processorPolicyState, processorDecision, eventTimestamp);
      if (!processorDecision.allowed) {
        throw new ProcessorPolicyError(
          processorDecision.reason_code ?? 'PRV_PROCESSOR_POLICY_DENIED',
          processorDecision.route,
        );
      }

      // CAUSAL SIEVE: Process outgoing request for tool_results.
      // This detects when the agent sends tool execution results back
      // to the LLM, which means a tool just finished executing.
      // We run git diff to capture file mutations from that tool.
      const providerType = (provider === 'anthropic' ? 'anthropic' : 'openai') as 'openai' | 'anthropic';
      if (outboundBodyBuffer.length > 0) {
        try {
          await sieve.processAgentRequest(providerType, outboundBodyBuffer.toString('utf-8'));
        } catch {
          // Sieve errors must not break the proxy pipeline
        }
      }

      // Forward request: passthrough goes direct to provider, otherwise through clawproxy
      const upstream = passthrough
        ? await forwardToUpstream(
            provider,
            upstreamPathWithQuery,
            method,
            outboundBodyBuffer,
            reqHeaders,
            egressPolicy,
          )
        : await forwardToClawproxy(
            provider,
            upstreamPathWithQuery,
            method,
            outboundBodyBuffer,
            reqHeaders,
            incomingKey,
            proxyToken,
            normalizedUrl,
            runId,
            agentDid.did,
            idempotencyKey,
            eventHash,
            egressPolicy,
          );

      // Force explicit content-length to match exact decompressed payload size.
      // This is crucial to prevent the consumer from expecting chunked boundaries.
      if (!upstream.isStream) {
        upstream.headers['content-length'] = String(upstream.body.length);
      }
      if (simulationPreview) {
        upstream.headers['x-clawsig-dlp-mode'] = 'simulated';
        upstream.headers['x-clawsig-dlp-would-action'] =
          simulationPreview.wouldAction;
        upstream.headers['x-clawsig-dlp-would-reason'] =
          simulationPreview.wouldReasonCode;
      }

      res.writeHead(upstream.status, upstream.headers);

      // Web Stream -> node.js stream passthrough for SSE.
      // Uses getReader() loop to flush chunks to the client immediately
      // instead of buffering the entire SSE stream in memory.
      if (upstream.isStream && upstream.stream) {
        const reader = upstream.stream.getReader();
        const chunks: Buffer[] = [];
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value) {
              const buf = Buffer.from(value);
              chunks.push(buf);
              res.write(buf); // Flush to consumer immediately
            }
          }
        } finally {
          res.end();
          reader.releaseLock();
        }
        // Reassemble for receipt extraction + Sieve processing
        upstream.body = Buffer.concat(chunks);
      } else {
        res.end(upstream.body);
      }

      // Collect receipt from response
      const receiptInfo = upstream.isStream
        ? extractReceiptFromStream(upstream.body)
        : extractReceiptFromResponse(upstream.body);

      if (receiptInfo.envelope) {
        receipts.push({
          envelope: receiptInfo.envelope,
          collectedAt: eventTimestamp,
          provider: receiptInfo.provider,
          model: receiptInfo.model,
          eventChainEntry,
        });
      }

      const gatewaySpanId = deriveGatewaySpanId(
        receiptInfo.envelope,
        `${provider}:${idempotencyKey}`,
      );

      // CAUSAL SIEVE: Process LLM response for tool_calls.
      // The TCP Guillotine evaluates these against the local WPC policy.
      let guillotineViolations: PolicyViolation[] = [];
      try {
        guillotineViolations = sieve.processLLMResponse(
          providerType,
          upstream.body.toString('utf-8'),
          { gatewaySpanId },
        );
      } catch {
        // Sieve errors must not break the proxy pipeline
      }

      if (guillotineViolations.length > 0) {
        for (const v of guillotineViolations) {
          process.stderr.write(
            `\x1b[31m[clawsig:guillotine]\x1b[0m BLOCKED: ${v.reason}\n`,
          );
        }
      }
    } catch (err) {
      if (err instanceof EgressPolicyError) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: err.code,
          reason_code: err.code,
          destination: err.destination,
          message: err.message,
        }));
        return;
      }

      if (err instanceof ProcessorPolicyError) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: err.code,
          reason_code: err.reasonCode,
          route: err.route,
          message: err.message,
        }));
        return;
      }

      const message = err instanceof Error ? err.message : 'Proxy forwarding failed';
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'PROXY_ERROR', message }));
    }
  });

  // Listen on a random available port
  const port = await new Promise<number>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (addr && typeof addr === 'object') {
        resolve(addr.port);
      } else {
        reject(new Error('Failed to bind local proxy'));
      }
    });
    server.on('error', reject);
  });

  async function stop(): Promise<void> {
    // Finalize the Causal Sieve: sweep for remaining file mutations
    try {
      await sieve.finalize();
    } catch {
      // Finalization errors must not prevent shutdown
    }

    return new Promise((resolve, reject) => {
      server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  /** Compute salted SHA-256: SHA256(salt || content). Red Team Fix #7. */
  async function saltedHashB64u(content: Uint8Array): Promise<string> {
    const combined = new Uint8Array(runSaltBytes.length + content.length);
    combined.set(runSaltBytes, 0);
    combined.set(content, runSaltBytes.length);
    return sha256B64u(combined);
  }
  void saltedHashB64u;

  async function compileProofBundle(): Promise<SignedEnvelope<ProofBundlePayload>> {
    const encoder = new TextEncoder();

    // Build the event chain from the precomputed request headers used for
    // receipt binding. The event_hash_b64u must match the exact X-Event-Hash
    // sent to clawproxy, otherwise downstream binding verification will fail.
    const eventChain: EventChainEntry[] = [...eventChainEntries];

    const envelopes = receipts.map((r) => r.envelope);

    // Assemble proof bundle payload
    const bundleId = `bundle_${randomUUID()}`;
    const payload: ProofBundlePayload = {
      bundle_version: '1',
      bundle_id: bundleId,
      agent_did: agentDid.did,
      event_chain: eventChain,
      metadata: {
        harness: {
          id: 'clawsig-wrap',
          version: '1.0.0',
          runtime: `node/${process.versions.node}`,
        },
        // RED TEAM FIX #7: Per-run ephemeral salt for privacy.
        run_salt_b64u: runSaltB64u,
      },
    };

    if (eventChain.length > 0) {
      payload.event_chain = eventChain;
    }

    const processorPolicyHash = await hashProcessorPolicyCanonicalB64u(processorPolicy);
    const processorPolicyConstraints = buildProcessorPolicyConstraints(processorPolicy);
    const eventChainRootHash = eventChain.length > 0 ? eventChain[0].event_hash_b64u : undefined;

    const usedProcessors = [...processorPolicyState.used_processors.values()]
      .sort((a, b) => {
        const aKey = `${a.route.provider}|${a.route.model}|${a.route.region}|${a.route.retention_profile}`;
        const bKey = `${b.route.provider}|${b.route.model}|${b.route.region}|${b.route.retention_profile}`;
        return aKey.localeCompare(bKey);
      })
      .map((entry) => ({
        ...entry.route,
        count: entry.count,
      }));

    payload.metadata = {
      ...payload.metadata,
      processor_policy: {
        receipt_version: '1',
        receipt_type: 'processor_policy',
        policy_version: processorPolicy.policy_version,
        profile_id: processorPolicy.profile_id,
        policy_hash_b64u: processorPolicyHash,
        enforce: processorPolicy.enforce,
        binding: {
          run_id: runId,
          ...(eventChainRootHash ? { event_chain_root_hash_b64u: eventChainRootHash } : {}),
        },
        constraints: processorPolicyConstraints,
        counters: {
          allowed_routes: processorPolicyState.allowed_count,
          denied_routes: processorPolicyState.denied_count,
        },
        used_processors: usedProcessors,
        blocked_attempts: processorPolicyState.blocked_attempts.map((attempt) => ({
          route: { ...attempt.route },
          reason_code: attempt.reason_code,
          timestamp: attempt.timestamp,
        })),
      },
    };

    if (envelopes.length > 0) {
      payload.receipts = envelopes;
    }

    if (dataHandlingReceipts.length > 0) {
      const simulatedReceiptCount = dataHandlingReceipts.filter(
        (receipt) => receipt.payload.enforcement.mode === 'simulated',
      ).length;
      const enforcedReceiptCount = dataHandlingReceipts.length - simulatedReceiptCount;
      const metadataMode =
        simulatedReceiptCount === 0
          ? 'enforced'
          : enforcedReceiptCount === 0
            ? 'simulated'
            : 'mixed';
      payload.metadata = {
        ...payload.metadata,
        data_handling: {
          policy_version: DLP_POLICY_VERSION,
          enforcement_mode: metadataMode,
          simulated_receipt_count: simulatedReceiptCount,
          enforced_receipt_count: enforcedReceiptCount,
          ...(dataHandlingPolicyConfig
            ? {
                taxonomy_version: dataHandlingPolicyConfig.taxonomy_version,
                ruleset_hash_b64u: dataHandlingPolicyConfig.ruleset_hash_b64u,
                built_in_rule_count: dataHandlingPolicyConfig.built_in_rule_count,
                custom_rule_count: dataHandlingPolicyConfig.custom_rule_count,
              }
            : {}),
          ...(dataHandlingPolicyConfigError
            ? { policy_error: dataHandlingPolicyConfigError }
            : {}),
          ...(normalizedEffectivePolicyHash
            ? { effective_policy_hash_b64u: normalizedEffectivePolicyHash }
            : {}),
          receipts: dataHandlingReceipts,
        },
      };
    }

    // CAUSAL SIEVE: Include synthesized tool and side-effect receipts.
    // These are auto-generated from parsing the LLM HTTP stream
    // and running git diff between tool execution boundaries.
    if (sieve.toolReceipts.length > 0) {
      payload.tool_receipts = sieve.toolReceipts.map(e => e.payload);
    }
    if (sieve.sideEffectReceipts.length > 0) {
      payload.side_effect_receipts = sieve.sideEffectReceipts.map(e => e.payload);
    }

    // Sign the bundle
    const payloadHashB64u = await hashJsonB64u(payload);
    const signatureB64u = await agentDid.sign(encoder.encode(payloadHashB64u));

    const envelope: SignedEnvelope<ProofBundlePayload> = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHashB64u,
      hash_algorithm: 'SHA-256',
      signature_b64u: signatureB64u,
      algorithm: 'Ed25519',
      signer_did: agentDid.did,
      issued_at: new Date().toISOString(),
    };

    return envelope;
  }

  return {
    port,
    stop,
    compileProofBundle,
    get receiptCount() {
      return receipts.length;
    },
    get toolReceiptCount() {
      return sieve.toolReceipts.length;
    },
    get sideEffectReceiptCount() {
      return sieve.sideEffectReceipts.length;
    },
    get violationCount() {
      return sieve.violations.length;
    },
    runSaltB64u,
  };
}
