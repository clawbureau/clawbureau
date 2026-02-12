export interface ScopedTokenClaimsV1 {
  token_version: '1';
  sub: string;
  aud: string | string[];
  scope: string[];
  iat: number;
  exp: number;
  owner_ref?: string;
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  policy_hash_b64u?: string;
  control_plane_policy_hash_b64u?: string;
  token_scope_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
  delegation_id?: string;
  delegator_did?: string;
  delegate_did?: string;
  delegation_policy_hash_b64u?: string;
  delegation_spend_cap_minor?: string;
  delegation_expires_at?: number;
  token_lane?: 'legacy' | 'canonical';
  jti?: string;
  nonce?: string;
}

export interface CanonicalChainValidation {
  ok: boolean;
  code?:
    | 'TOKEN_CONTROL_CHAIN_MISSING'
    | 'CONTROL_CHAIN_CONTEXT_MISMATCH'
    | 'TOKEN_CONTROL_SUBJECT_MISMATCH';
  message?: string;
}

export interface TokenScopeHashInputV1 {
  token_version: '1';
  sub: string;
  aud: string[];
  scope: string[];
  owner_ref?: string;
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  policy_hash_b64u?: string;
  control_plane_policy_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
  delegation_id?: string;
  delegator_did?: string;
  delegate_did?: string;
  delegation_policy_hash_b64u?: string;
  delegation_spend_cap_minor?: string;
  delegation_expires_at?: number;
}

export interface TransitionMatrixEntry {
  allowed: boolean;
  reason_code: string;
  reason: string;
}

export interface TransitionMatrixResponse {
  active?: boolean;
  revoked?: boolean;
  matrix?: Record<string, TransitionMatrixEntry>;
  error?: string;
  message?: string;
}

export interface RevalidateTransitionsInput {
  scopeBaseUrl: string;
  token: string;
  requiredTransitions: string[];
  timeoutMs?: number;
  fetcher?: typeof fetch;
}

export type RevalidateTransitionsResult =
  | {
      ok: true;
      matrix: Record<string, TransitionMatrixEntry>;
      denied: string[];
    }
  | {
      ok: false;
      status: number;
      code: 'DEPENDENCY_NOT_CONFIGURED' | 'TOKEN_CONTROL_TRANSITION_FORBIDDEN' | 'PARSE_ERROR';
      message: string;
      matrix?: Record<string, TransitionMatrixEntry>;
      denied?: string[];
    };

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

export function isDid(value: string): boolean {
  return /^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$/i.test(value);
}

function uniqueSorted(values: string[]): string[] {
  return Array.from(new Set(values.map((v) => v.trim()).filter((v) => v.length > 0))).sort();
}

export function normalizeAudience(value: string | string[]): string[] {
  if (typeof value === 'string') return uniqueSorted([value]);
  return uniqueSorted(value);
}

export function normalizeScope(value: string[]): string[] {
  return uniqueSorted(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function isSha256B64u(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value);
}

export function validateScopedTokenClaimsShape(payload: unknown): payload is ScopedTokenClaimsV1 {
  if (typeof payload !== 'object' || payload === null) return false;

  const p = payload as Record<string, unknown>;

  if (p.token_version !== '1') return false;
  if (!isNonEmptyString(p.sub)) return false;
  if (!isStringArray(p.scope) || p.scope.length === 0) return false;
  if (typeof p.iat !== 'number' || !Number.isFinite(p.iat)) return false;
  if (typeof p.exp !== 'number' || !Number.isFinite(p.exp)) return false;

  if (typeof p.aud !== 'string' && !isStringArray(p.aud)) return false;
  if (normalizeAudience(p.aud as string | string[]).length === 0) return false;

  if (p.owner_ref !== undefined && !isNonEmptyString(p.owner_ref)) return false;

  if (p.owner_did !== undefined) {
    if (!isNonEmptyString(p.owner_did) || !isDid(p.owner_did.trim())) return false;
  }

  if (p.controller_did !== undefined) {
    if (!isNonEmptyString(p.controller_did) || !isDid(p.controller_did.trim())) return false;
  }

  if (p.agent_did !== undefined) {
    if (!isNonEmptyString(p.agent_did) || !isDid(p.agent_did.trim())) return false;
  }

  if (p.policy_hash_b64u !== undefined) {
    if (!isNonEmptyString(p.policy_hash_b64u) || !isSha256B64u(p.policy_hash_b64u.trim())) return false;
  }

  if (p.control_plane_policy_hash_b64u !== undefined) {
    if (
      !isNonEmptyString(p.control_plane_policy_hash_b64u) ||
      !isSha256B64u(p.control_plane_policy_hash_b64u.trim())
    ) {
      return false;
    }
  }

  if (p.token_scope_hash_b64u !== undefined) {
    if (!isNonEmptyString(p.token_scope_hash_b64u) || !isSha256B64u(p.token_scope_hash_b64u.trim())) {
      return false;
    }
  }

  if (p.payment_account_did !== undefined) {
    if (!isNonEmptyString(p.payment_account_did)) return false;
  }

  if (p.spend_cap !== undefined) {
    if (typeof p.spend_cap !== 'number' || !Number.isFinite(p.spend_cap) || p.spend_cap < 0) return false;
  }

  if (p.mission_id !== undefined && !isNonEmptyString(p.mission_id)) return false;

  if (p.delegation_id !== undefined && !isNonEmptyString(p.delegation_id)) return false;

  if (p.delegator_did !== undefined) {
    if (!isNonEmptyString(p.delegator_did) || !isDid(p.delegator_did.trim())) return false;
  }

  if (p.delegate_did !== undefined) {
    if (!isNonEmptyString(p.delegate_did) || !isDid(p.delegate_did.trim())) return false;
  }

  if (p.delegation_policy_hash_b64u !== undefined) {
    if (!isNonEmptyString(p.delegation_policy_hash_b64u) || !isSha256B64u(p.delegation_policy_hash_b64u.trim())) {
      return false;
    }
  }

  if (p.delegation_spend_cap_minor !== undefined) {
    if (!isNonEmptyString(p.delegation_spend_cap_minor) || !/^[0-9]+$/.test(p.delegation_spend_cap_minor.trim())) {
      return false;
    }
  }

  if (p.delegation_expires_at !== undefined) {
    if (typeof p.delegation_expires_at !== 'number' || !Number.isFinite(p.delegation_expires_at)) return false;
  }

  if (p.token_lane !== undefined && p.token_lane !== 'legacy' && p.token_lane !== 'canonical') {
    return false;
  }

  return true;
}

export function hasRequiredScope(
  tokenScopes: string[],
  requiredScopes: string[],
  provider?: string
): boolean {
  const normalizedScopes = new Set(normalizeScope(tokenScopes));

  if (
    normalizedScopes.has('*') ||
    normalizedScopes.has('proxy:*') ||
    normalizedScopes.has('clawproxy:*') ||
    normalizedScopes.has('control:*')
  ) {
    return true;
  }

  for (const required of normalizeScope(requiredScopes)) {
    if (normalizedScopes.has(required)) return true;
  }

  if (provider && provider.trim().length > 0) {
    const p = provider.trim();
    const providerScopes = [
      `proxy:provider:${p}`,
      `proxy:call:${p}`,
      `clawproxy:provider:${p}`,
      `clawproxy:call:${p}`,
    ];

    if (providerScopes.some((scope) => normalizedScopes.has(scope))) {
      return true;
    }
  }

  return false;
}

function base64urlEncode(bytes: Uint8Array): string {
  const b64 = btoa(String.fromCharCode(...bytes));
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function canonicalize(value: unknown): string {
  if (value === null) return 'null';

  const valueType = typeof value;
  if (valueType === 'string') return JSON.stringify(value);
  if (valueType === 'number') {
    if (!Number.isFinite(value as number)) throw new Error('Cannot canonicalize non-finite number');
    return JSON.stringify(value);
  }
  if (valueType === 'boolean') return value ? 'true' : 'false';

  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalize(entry)).join(',')}]`;
  }

  if (valueType === 'object') {
    const objectValue = value as Record<string, unknown>;
    const keys = Object.keys(objectValue)
      .filter((key) => objectValue[key] !== undefined)
      .sort();

    return `{${keys
      .map((key) => `${JSON.stringify(key)}:${canonicalize(objectValue[key])}`)
      .join(',')}}`;
  }

  throw new Error(`Unsupported value type for canonicalization: ${valueType}`);
}

export function buildTokenScopeHashInput(input: {
  sub: string;
  aud: string | string[];
  scope: string[];
  owner_ref?: string;
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  policy_hash_b64u?: string;
  control_plane_policy_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
  delegation_id?: string;
  delegator_did?: string;
  delegate_did?: string;
  delegation_policy_hash_b64u?: string;
  delegation_spend_cap_minor?: string;
  delegation_expires_at?: number;
}): TokenScopeHashInputV1 {
  const out: TokenScopeHashInputV1 = {
    token_version: '1',
    sub: input.sub.trim(),
    aud: normalizeAudience(input.aud),
    scope: normalizeScope(input.scope),
  };

  if (isNonEmptyString(input.owner_ref)) out.owner_ref = input.owner_ref.trim();
  if (isNonEmptyString(input.owner_did)) out.owner_did = input.owner_did.trim();
  if (isNonEmptyString(input.controller_did)) out.controller_did = input.controller_did.trim();
  if (isNonEmptyString(input.agent_did)) out.agent_did = input.agent_did.trim();
  if (isNonEmptyString(input.policy_hash_b64u)) out.policy_hash_b64u = input.policy_hash_b64u.trim();
  if (isNonEmptyString(input.control_plane_policy_hash_b64u)) {
    out.control_plane_policy_hash_b64u = input.control_plane_policy_hash_b64u.trim();
  }
  if (isNonEmptyString(input.payment_account_did)) out.payment_account_did = input.payment_account_did.trim();
  if (typeof input.spend_cap === 'number' && Number.isFinite(input.spend_cap) && input.spend_cap >= 0) {
    out.spend_cap = input.spend_cap;
  }
  if (isNonEmptyString(input.mission_id)) out.mission_id = input.mission_id.trim();
  if (isNonEmptyString(input.delegation_id)) out.delegation_id = input.delegation_id.trim();
  if (isNonEmptyString(input.delegator_did)) out.delegator_did = input.delegator_did.trim();
  if (isNonEmptyString(input.delegate_did)) out.delegate_did = input.delegate_did.trim();
  if (isNonEmptyString(input.delegation_policy_hash_b64u)) {
    out.delegation_policy_hash_b64u = input.delegation_policy_hash_b64u.trim();
  }
  if (isNonEmptyString(input.delegation_spend_cap_minor) && /^[0-9]+$/.test(input.delegation_spend_cap_minor.trim())) {
    out.delegation_spend_cap_minor = input.delegation_spend_cap_minor.trim();
  }
  if (
    typeof input.delegation_expires_at === 'number' &&
    Number.isFinite(input.delegation_expires_at) &&
    input.delegation_expires_at > 0
  ) {
    out.delegation_expires_at = Math.floor(input.delegation_expires_at);
  }

  return out;
}

export async function computeTokenScopeHashB64u(input: {
  sub: string;
  aud: string | string[];
  scope: string[];
  owner_ref?: string;
  owner_did?: string;
  controller_did?: string;
  agent_did?: string;
  policy_hash_b64u?: string;
  control_plane_policy_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
  delegation_id?: string;
  delegator_did?: string;
  delegate_did?: string;
  delegation_policy_hash_b64u?: string;
  delegation_spend_cap_minor?: string;
  delegation_expires_at?: number;
}): Promise<string> {
  const payload = buildTokenScopeHashInput(input);
  const canonical = canonicalize(payload);
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return base64urlEncode(new Uint8Array(digest));
}

export function validateCanonicalControlContext(
  claims: Pick<
    ScopedTokenClaimsV1,
    'owner_did' | 'controller_did' | 'agent_did' | 'token_lane'
  >,
  expected?: {
    owner_did?: string;
    controller_did?: string;
    agent_did?: string;
  }
): CanonicalChainValidation {
  if (
    !isNonEmptyString(claims.owner_did) ||
    !isNonEmptyString(claims.controller_did) ||
    !isNonEmptyString(claims.agent_did) ||
    claims.token_lane !== 'canonical'
  ) {
    return {
      ok: false,
      code: 'TOKEN_CONTROL_CHAIN_MISSING',
      message:
        'Canonical chain claims are required: owner_did, controller_did, agent_did, token_lane=canonical',
    };
  }

  if (expected?.owner_did && expected.owner_did.trim() !== claims.owner_did.trim()) {
    return {
      ok: false,
      code: 'CONTROL_CHAIN_CONTEXT_MISMATCH',
      message: 'owner_did claim mismatch',
    };
  }

  if (
    expected?.controller_did &&
    expected.controller_did.trim() !== claims.controller_did.trim()
  ) {
    return {
      ok: false,
      code: 'CONTROL_CHAIN_CONTEXT_MISMATCH',
      message: 'controller_did claim mismatch',
    };
  }

  if (expected?.agent_did && expected.agent_did.trim() !== claims.agent_did.trim()) {
    return {
      ok: false,
      code: 'TOKEN_CONTROL_SUBJECT_MISMATCH',
      message: 'agent_did claim mismatch',
    };
  }

  return { ok: true };
}

function parseJsonResponse(text: string): unknown {
  try {
    return text.length > 0 ? (JSON.parse(text) as unknown) : null;
  } catch {
    return null;
  }
}

export async function revalidateSensitiveTransitions(
  input: RevalidateTransitionsInput
): Promise<RevalidateTransitionsResult> {
  const requiredTransitions = normalizeScope(input.requiredTransitions);
  if (requiredTransitions.length === 0) {
    return { ok: true, matrix: {}, denied: [] };
  }

  const fetcher = input.fetcher ?? fetch;
  const timeoutMs = Number.isFinite(input.timeoutMs) ? Math.max(200, Number(input.timeoutMs)) : 5000;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetcher(`${input.scopeBaseUrl.replace(/\/$/, '')}/v1/tokens/introspect/matrix`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify({ token: input.token }),
      signal: controller.signal,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      ok: false,
      status: 503,
      code: 'DEPENDENCY_NOT_CONFIGURED',
      message: `Failed to query transition matrix endpoint: ${message}`,
    };
  } finally {
    clearTimeout(timeout);
  }

  const text = await response.text();
  const payload = parseJsonResponse(text) as TransitionMatrixResponse | null;

  if (!response.ok || !payload) {
    return {
      ok: false,
      status: response.status,
      code: response.status >= 500 ? 'DEPENDENCY_NOT_CONFIGURED' : 'PARSE_ERROR',
      message:
        (payload && typeof payload.message === 'string' && payload.message.trim().length > 0
          ? payload.message
          : null) ?? `Transition matrix request failed with status ${response.status}`,
    };
  }

  const matrix = payload.matrix ?? {};
  const denied = requiredTransitions.filter((transition) => matrix[transition]?.allowed !== true);

  if (denied.length > 0) {
    return {
      ok: false,
      status: 403,
      code: 'TOKEN_CONTROL_TRANSITION_FORBIDDEN',
      message: `Transition(s) denied by matrix: ${denied.join(', ')}`,
      matrix,
      denied,
    };
  }

  return {
    ok: true,
    matrix,
    denied: [],
  };
}
