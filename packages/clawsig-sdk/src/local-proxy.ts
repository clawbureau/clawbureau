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
import { hashJsonB64u, sha256B64u, base64UrlEncode } from './crypto.js';
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
function extractReceiptFromResponse(body: Buffer): {
  envelope?: SignedEnvelope<GatewayReceiptPayload>;
  provider: string;
  model: string;
} {
  try {
    const parsed = JSON.parse(body.toString('utf-8')) as Record<string, unknown>;
    const envelope = parsed['_receipt_envelope'] as SignedEnvelope<GatewayReceiptPayload> | undefined;

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
      const parsed = JSON.parse(decoded) as SignedEnvelope<GatewayReceiptPayload>;
      if (parsed?.envelope_type === 'gateway_receipt') return parsed;
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
          const envelope = parsed['_receipt_envelope'] as SignedEnvelope<GatewayReceiptPayload>;
          return {
            envelope,
            provider: envelope.payload?.provider ?? 'unknown',
            model: envelope.payload?.model ?? 'unknown',
          };
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
  } = options;

  const normalizedUrl = clawproxyUrl.replace(/\/+$/, '');
  const normalizedEgressAllowlist = normalizeEgressAllowlist(egressAllowlist);
  const egressPolicy: EgressPolicy | undefined = enforceEgressAllowlist
    ? { enforce: true, allowlist: normalizedEgressAllowlist }
    : undefined;
  const proofedMode = parseBooleanEnv(process.env['CLAWSIG_PROOFED']);
  const processorPolicy = resolveProcessorPolicy(proofedMode);
  const processorPolicyState: ProcessorPolicyState = {
    allowed_count: 0,
    denied_count: 0,
    used_processors: new Map(),
    blocked_attempts: [],
  };
  const eventChainEntries: EventChainEntry[] = [];
  const receipts: CollectedReceipt[] = [];
  let plannedPrevHash: string | null = null;

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

      const processorRoute = buildProcessorRouteClaims({
        provider,
        bodyBuffer,
        headers: req.headers as Record<string, string | string[] | undefined>,
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

      // Extract provider key from the incoming request, fall back to constructor option
      const reqHeaders = req.headers as Record<string, string | string[] | undefined>;
      const incomingKey = extractProviderKey(reqHeaders) ?? providerApiKey;

      // CAUSAL SIEVE: Process outgoing request for tool_results.
      // This detects when the agent sends tool execution results back
      // to the LLM, which means a tool just finished executing.
      // We run git diff to capture file mutations from that tool.
      const providerType = (provider === 'anthropic' ? 'anthropic' : 'openai') as 'openai' | 'anthropic';
      if (bodyBuffer.length > 0) {
        try {
          await sieve.processAgentRequest(providerType, bodyBuffer.toString('utf-8'));
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
            bodyBuffer,
            reqHeaders,
            egressPolicy,
          )
        : await forwardToClawproxy(
            provider,
            upstreamPathWithQuery,
            method,
            bodyBuffer,
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
