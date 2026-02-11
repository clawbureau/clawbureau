import type {
  RemediationHint,
  VerificationError,
  VerifyTokenControlRequest,
  VerifyTokenControlResponse,
} from './types';
import { base64UrlEncode } from './crypto';
import { jcsCanonicalize } from './jcs';
import { isValidDidFormat } from './schema-registry';

interface VerifyTokenControlOptions {
  clawscopeBaseUrl?: string;
  timeoutMs?: number;
  fetcher?: typeof fetch;
}

interface IntrospectionResponse {
  active: boolean;
  revoked?: boolean;
  token_hash: string;
  sub: string;
  aud: string | string[];
  scope: string[];
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
  token_lane?: 'legacy' | 'canonical';
  iat?: number;
  exp?: number;
}

interface MatrixResponse {
  active: boolean;
  revoked: boolean;
  matrix?: Record<
    string,
    {
      allowed: boolean;
      reason_code: string;
      reason: string;
    }
  >;
}

interface JsonResponse {
  status: number;
  ok: boolean;
  json: unknown;
}

function hint(code: RemediationHint['code'], message: string, action: string): RemediationHint {
  return { code, message, action };
}

function uniqueStrings(values: string[]): string[] {
  return Array.from(new Set(values.map((v) => v.trim()).filter((v) => v.length > 0))).sort();
}

function normalizeAudience(value: string | string[]): string[] {
  if (Array.isArray(value)) {
    return uniqueStrings(value.filter((v) => typeof v === 'string'));
  }

  if (typeof value === 'string' && value.trim().length > 0) {
    return [value.trim()];
  }

  return [];
}

function buildInvalidResponse(
  now: string,
  reason: string,
  error: VerificationError,
  partial: Partial<VerifyTokenControlResponse> = {},
  remediation_hints: RemediationHint[] = []
): VerifyTokenControlResponse {
  return {
    result: {
      status: 'INVALID',
      reason,
      verified_at: now,
    },
    ...partial,
    remediation_hints,
    error,
  };
}

async function postJson(
  fetcher: typeof fetch,
  url: string,
  payload: Record<string, unknown>,
  timeoutMs: number
): Promise<JsonResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetcher(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    const text = await response.text();
    let json: unknown = null;
    try {
      json = text ? (JSON.parse(text) as unknown) : null;
    } catch {
      json = null;
    }

    return {
      status: response.status,
      ok: response.ok,
      json,
    };
  } finally {
    clearTimeout(timer);
  }
}

function getUpstreamErrorMessage(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  if (typeof p.message === 'string' && p.message.trim().length > 0) return p.message;
  if (typeof p.error === 'string' && p.error.trim().length > 0) return p.error;
  return null;
}

function getUpstreamErrorCode(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null;
  const p = payload as Record<string, unknown>;
  if (typeof p.error === 'string' && p.error.trim().length > 0) return p.error.trim();
  if (typeof p.code === 'string' && p.code.trim().length > 0) return p.code.trim();
  return null;
}

function validateRequest(
  body: unknown,
  now: string
): { ok: true; req: VerifyTokenControlRequest } | { ok: false; response: VerifyTokenControlResponse } {
  if (!body || typeof body !== 'object') {
    return {
      ok: false,
      response: buildInvalidResponse(
        now,
        'Request must be a JSON object',
        {
          code: 'PARSE_ERROR',
          message: 'Request body must be a JSON object',
        },
        {},
        [
          hint(
            'CHECK_CONTROL_CHAIN_CONFIG',
            'Token-control verification expects a structured request body',
            'Provide token and optional expected_* constraints as JSON'
          ),
        ]
      ),
    };
  }

  const req = body as Partial<VerifyTokenControlRequest>;
  const token = typeof req.token === 'string' ? req.token.trim() : '';

  if (!token) {
    return {
      ok: false,
      response: buildInvalidResponse(
        now,
        'Missing required token field',
        {
          code: 'MISSING_REQUIRED_FIELD',
          message: 'token is required',
          field: 'token',
        },
        {},
        [
          hint(
            'REISSUE_TOKEN',
            'Token value is required for verification',
            'Pass the canonical CST token in token field'
          ),
        ]
      ),
    };
  }

  const normalized: VerifyTokenControlRequest = { token };

  if (typeof req.expected_owner_did === 'string' && req.expected_owner_did.trim().length > 0) {
    normalized.expected_owner_did = req.expected_owner_did.trim();
  }
  if (
    typeof req.expected_controller_did === 'string' &&
    req.expected_controller_did.trim().length > 0
  ) {
    normalized.expected_controller_did = req.expected_controller_did.trim();
  }
  if (typeof req.expected_agent_did === 'string' && req.expected_agent_did.trim().length > 0) {
    normalized.expected_agent_did = req.expected_agent_did.trim();
  }

  if (
    normalized.expected_owner_did &&
    !isValidDidFormat(normalized.expected_owner_did)
  ) {
    return {
      ok: false,
      response: buildInvalidResponse(
        now,
        'expected_owner_did is malformed',
        {
          code: 'INVALID_DID_FORMAT',
          message: 'expected_owner_did must be a valid DID',
          field: 'expected_owner_did',
        },
        {},
        [
          hint(
            'CHECK_CONTROL_CHAIN_CONFIG',
            'expected_owner_did is not a valid DID',
            'Fix expected_owner_did and retry'
          ),
        ]
      ),
    };
  }

  if (
    normalized.expected_controller_did &&
    !isValidDidFormat(normalized.expected_controller_did)
  ) {
    return {
      ok: false,
      response: buildInvalidResponse(
        now,
        'expected_controller_did is malformed',
        {
          code: 'INVALID_DID_FORMAT',
          message: 'expected_controller_did must be a valid DID',
          field: 'expected_controller_did',
        },
        {},
        [
          hint(
            'CHECK_CONTROL_CHAIN_CONFIG',
            'expected_controller_did is not a valid DID',
            'Fix expected_controller_did and retry'
          ),
        ]
      ),
    };
  }

  if (
    normalized.expected_agent_did &&
    !isValidDidFormat(normalized.expected_agent_did)
  ) {
    return {
      ok: false,
      response: buildInvalidResponse(
        now,
        'expected_agent_did is malformed',
        {
          code: 'INVALID_DID_FORMAT',
          message: 'expected_agent_did must be a valid DID',
          field: 'expected_agent_did',
        },
        {},
        [
          hint(
            'CHECK_CONTROL_CHAIN_CONFIG',
            'expected_agent_did is not a valid DID',
            'Fix expected_agent_did and retry'
          ),
        ]
      ),
    };
  }

  if (typeof req.required_audience === 'string') {
    normalized.required_audience = req.required_audience.trim();
  } else if (Array.isArray(req.required_audience)) {
    normalized.required_audience = uniqueStrings(
      req.required_audience.filter((v) => typeof v === 'string')
    );
  }

  if (Array.isArray(req.required_scope)) {
    normalized.required_scope = uniqueStrings(req.required_scope.filter((v) => typeof v === 'string'));
  }

  if (Array.isArray(req.required_transitions)) {
    normalized.required_transitions = uniqueStrings(
      req.required_transitions.filter((v) => typeof v === 'string')
    );
  }

  return {
    ok: true,
    req: normalized,
  };
}

async function computeTokenScopeHashB64u(introspection: IntrospectionResponse): Promise<string> {
  const canonical: Record<string, unknown> = {
    token_version: '1',
    sub: introspection.sub,
    aud: normalizeAudience(introspection.aud),
    scope: uniqueStrings(introspection.scope ?? []),
  };

  if (typeof introspection.owner_ref === 'string' && introspection.owner_ref.trim().length > 0) {
    canonical.owner_ref = introspection.owner_ref.trim();
  }
  if (typeof introspection.owner_did === 'string' && introspection.owner_did.trim().length > 0) {
    canonical.owner_did = introspection.owner_did.trim();
  }
  if (
    typeof introspection.controller_did === 'string' &&
    introspection.controller_did.trim().length > 0
  ) {
    canonical.controller_did = introspection.controller_did.trim();
  }
  if (typeof introspection.agent_did === 'string' && introspection.agent_did.trim().length > 0) {
    canonical.agent_did = introspection.agent_did.trim();
  }
  if (
    typeof introspection.policy_hash_b64u === 'string' &&
    introspection.policy_hash_b64u.trim().length > 0
  ) {
    canonical.policy_hash_b64u = introspection.policy_hash_b64u.trim();
  }
  if (
    typeof introspection.control_plane_policy_hash_b64u === 'string' &&
    introspection.control_plane_policy_hash_b64u.trim().length > 0
  ) {
    canonical.control_plane_policy_hash_b64u = introspection.control_plane_policy_hash_b64u.trim();
  }
  if (
    typeof introspection.payment_account_did === 'string' &&
    introspection.payment_account_did.trim().length > 0
  ) {
    canonical.payment_account_did = introspection.payment_account_did.trim();
  }
  if (typeof introspection.spend_cap === 'number' && Number.isFinite(introspection.spend_cap)) {
    canonical.spend_cap = introspection.spend_cap;
  }
  if (typeof introspection.mission_id === 'string' && introspection.mission_id.trim().length > 0) {
    canonical.mission_id = introspection.mission_id.trim();
  }

  const bytes = new TextEncoder().encode(jcsCanonicalize(canonical));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return base64UrlEncode(new Uint8Array(digest));
}

export async function verifyTokenControl(
  body: unknown,
  options: VerifyTokenControlOptions = {}
): Promise<VerifyTokenControlResponse> {
  const now = new Date().toISOString();

  const validated = validateRequest(body, now);
  if (!validated.ok) {
    return validated.response;
  }

  const req = validated.req;
  const fetcher = options.fetcher ?? fetch;
  const timeoutMs = options.timeoutMs && Number.isFinite(options.timeoutMs) ? options.timeoutMs : 5000;
  const baseUrl = options.clawscopeBaseUrl?.trim();

  if (!baseUrl) {
    return buildInvalidResponse(
      now,
      'clawscope base URL is not configured',
      {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message: 'CLAWSCOPE_BASE_URL is required for token-control verification',
      },
      {},
      [
        hint(
          'CHECK_CONTROL_CHAIN_CONFIG',
          'Token-control dependency is not configured',
          'Set CLAWSCOPE_BASE_URL in clawverify environment'
        ),
      ]
    );
  }

  let introspectResponse: JsonResponse;
  try {
    introspectResponse = await postJson(
      fetcher,
      `${baseUrl.replace(/\/$/, '')}/v1/tokens/introspect`,
      { token: req.token },
      timeoutMs
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return buildInvalidResponse(
      now,
      'Failed to query clawscope introspection endpoint',
      {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message,
      },
      {},
      [
        hint(
          'CHECK_CONTROL_CHAIN_CONFIG',
          'Could not reach clawscope introspection endpoint',
          'Verify CLAWSCOPE_BASE_URL and clawscope deployment health'
        ),
      ]
    );
  }

  if (introspectResponse.status !== 200 || !introspectResponse.json) {
    const upstreamCode = getUpstreamErrorCode(introspectResponse.json);
    const upstreamMessage =
      getUpstreamErrorMessage(introspectResponse.json) ??
      `clawscope introspection failed with status ${introspectResponse.status}`;

    if (upstreamCode === 'TOKEN_UNKNOWN_KID') {
      return buildInvalidResponse(
        now,
        'Token kid is not accepted by clawscope key contract',
        {
          code: 'TOKEN_CONTROL_KEY_UNKNOWN',
          message: upstreamMessage,
          field: 'token',
        },
        {},
        [
          hint(
            'REISSUE_TOKEN',
            'Token was issued under a kid that is not present in the active overlap window',
            'Reissue the token using current canonical keyset'
          ),
          hint(
            'SYNC_REVOCATION_STREAM',
            'Control-plane consumers must use synchronized accepted_kids during overlap',
            'Refresh /v1/keys/rotation-contract and /v1/jwks before retrying'
          ),
        ]
      );
    }

    if (upstreamCode === 'TOKEN_KID_EXPIRED') {
      return buildInvalidResponse(
        now,
        'Token kid overlap window has expired',
        {
          code: 'TOKEN_CONTROL_KEY_EXPIRED',
          message: upstreamMessage,
          field: 'token',
        },
        {},
        [
          hint(
            'REISSUE_TOKEN',
            'Token uses an expired overlap key',
            'Reissue token with the current active key'
          ),
        ]
      );
    }

    return buildInvalidResponse(
      now,
      'clawscope introspection rejected token',
      {
        code: introspectResponse.status >= 500 ? 'DEPENDENCY_NOT_CONFIGURED' : 'PARSE_ERROR',
        message: upstreamMessage,
      },
      {},
      [
        hint(
          'REISSUE_TOKEN',
          'Token could not be introspected successfully',
          'Reissue token in canonical lane and retry verification'
        ),
      ]
    );
  }

  const introspection = introspectResponse.json as IntrospectionResponse;
  const tokenHash = introspection.token_hash;
  const tokenLane = introspection.token_lane;

  if (introspection.active !== true) {
    return buildInvalidResponse(
      now,
      introspection.revoked ? 'Token is revoked' : 'Token is inactive',
      {
        code: introspection.revoked ? 'REVOKED' : 'CLAIM_NOT_FOUND',
        message: introspection.revoked
          ? 'Token has been revoked in clawscope revocation stream'
          : 'Token is not active',
      },
      {
        token_hash: tokenHash,
        active: false,
        revoked: introspection.revoked === true,
        token_lane: tokenLane,
        owner_did: introspection.owner_did,
        controller_did: introspection.controller_did,
        agent_did: introspection.agent_did,
      },
      [
        hint(
          'REISSUE_TOKEN',
          introspection.revoked
            ? 'Revoked tokens cannot authorize control transitions'
            : 'Inactive token cannot authorize control transitions',
          'Issue a fresh canonical token and distribute it to control callers'
        ),
        hint(
          'SYNC_REVOCATION_STREAM',
          'Ensure verifiers consume latest revocation stream entries',
          'Sync from clawscope /v1/revocations/stream before retries'
        ),
      ]
    );
  }

  if (
    !introspection.owner_did ||
    !introspection.controller_did ||
    !introspection.agent_did ||
    tokenLane !== 'canonical'
  ) {
    return buildInvalidResponse(
      now,
      'Token is not bound to canonical owner/controller/agent chain',
      {
        code: 'TOKEN_CONTROL_CHAIN_MISSING',
        message: 'Canonical chain claims are required: owner_did, controller_did, agent_did, token_lane=canonical',
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
        owner_did: introspection.owner_did,
        controller_did: introspection.controller_did,
        agent_did: introspection.agent_did,
      },
      [
        hint(
          'USE_CANONICAL_CST_LANE',
          'Legacy CST lane cannot satisfy strict control-plane verification',
          'Issue via /v1/tokens/issue/canonical with chain-bound claims'
        ),
      ]
    );
  }

  if (req.expected_owner_did && req.expected_owner_did !== introspection.owner_did) {
    return buildInvalidResponse(
      now,
      'Token owner_did does not match expected_owner_did',
      {
        code: 'CONTROL_CHAIN_CONTEXT_MISMATCH',
        message: 'owner_did claim mismatch',
        field: 'expected_owner_did',
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
        owner_did: introspection.owner_did,
        controller_did: introspection.controller_did,
        agent_did: introspection.agent_did,
      },
      [
        hint(
          'REGISTER_OWNER_BINDING',
          'Token owner does not match requested owner context',
          'Issue token for the intended owner/controller/agent chain'
        ),
      ]
    );
  }

  if (req.expected_controller_did && req.expected_controller_did !== introspection.controller_did) {
    return buildInvalidResponse(
      now,
      'Token controller_did does not match expected_controller_did',
      {
        code: 'CONTROL_CHAIN_CONTEXT_MISMATCH',
        message: 'controller_did claim mismatch',
        field: 'expected_controller_did',
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
        owner_did: introspection.owner_did,
        controller_did: introspection.controller_did,
        agent_did: introspection.agent_did,
      },
      [
        hint(
          'REGISTER_CONTROLLER',
          'Token controller does not match expected control context',
          'Issue token for the expected controller DID'
        ),
      ]
    );
  }

  if (req.expected_agent_did && req.expected_agent_did !== introspection.agent_did) {
    return buildInvalidResponse(
      now,
      'Token agent_did does not match expected_agent_did',
      {
        code: 'TOKEN_CONTROL_SUBJECT_MISMATCH',
        message: 'agent_did claim mismatch',
        field: 'expected_agent_did',
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
        owner_did: introspection.owner_did,
        controller_did: introspection.controller_did,
        agent_did: introspection.agent_did,
      },
      [
        hint(
          'REGISTER_AGENT_UNDER_CONTROLLER',
          'Token agent does not match expected execution subject',
          'Issue token for the expected agent DID'
        ),
      ]
    );
  }

  const calculatedScopeHash = await computeTokenScopeHashB64u(introspection);
  if (
    !introspection.token_scope_hash_b64u ||
    introspection.token_scope_hash_b64u !== calculatedScopeHash
  ) {
    return buildInvalidResponse(
      now,
      'token_scope_hash_b64u does not match recomputed claim hash',
      {
        code: 'TOKEN_CONTROL_SCOPE_HASH_MISMATCH',
        message: 'token_scope_hash_b64u mismatch',
        field: 'token_scope_hash_b64u',
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
        owner_did: introspection.owner_did,
        controller_did: introspection.controller_did,
        agent_did: introspection.agent_did,
        token_scope_hash_b64u: introspection.token_scope_hash_b64u,
      },
      [
        hint(
          'REISSUE_TOKEN',
          'Token claim hash drift indicates stale or malformed token claims',
          'Reissue canonical token to restore deterministic scope hash binding'
        ),
      ]
    );
  }

  const tokenScopeSet = new Set(uniqueStrings(introspection.scope ?? []));
  const requiredScope = uniqueStrings(req.required_scope ?? []);
  const missingScope = requiredScope.filter((scope) => !tokenScopeSet.has(scope));
  if (missingScope.length > 0) {
    return buildInvalidResponse(
      now,
      `Token is missing required scope(s): ${missingScope.join(', ')}`,
      {
        code: 'TOKEN_CONTROL_SCOPE_MISSING',
        message: `Missing required scope(s): ${missingScope.join(', ')}`,
        field: 'required_scope',
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
        owner_did: introspection.owner_did,
        controller_did: introspection.controller_did,
        agent_did: introspection.agent_did,
        scope: introspection.scope,
        aud: introspection.aud,
        token_scope_hash_b64u: introspection.token_scope_hash_b64u,
      },
      [
        hint(
          'REQUEST_REQUIRED_SCOPE',
          'Token does not include required transition scope set',
          `Request token with scope(s): ${missingScope.join(', ')}`
        ),
        hint(
          'UPDATE_SENSITIVE_POLICY',
          'Required sensitive scope may not be enabled in controller policy',
          'Update controller sensitive policy to allow missing scopes, then reissue token'
        ),
      ]
    );
  }

  const requiredAudience = Array.isArray(req.required_audience)
    ? uniqueStrings(req.required_audience)
    : typeof req.required_audience === 'string' && req.required_audience.trim().length > 0
      ? [req.required_audience.trim()]
      : [];

  const tokenAudience = new Set(normalizeAudience(introspection.aud));
  const missingAudience = requiredAudience.filter((aud) => !tokenAudience.has(aud));
  if (missingAudience.length > 0) {
    return buildInvalidResponse(
      now,
      `Token is missing required audience(s): ${missingAudience.join(', ')}`,
      {
        code: 'TOKEN_CONTROL_AUDIENCE_MISMATCH',
        message: `Missing required audience(s): ${missingAudience.join(', ')}`,
        field: 'required_audience',
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
        owner_did: introspection.owner_did,
        controller_did: introspection.controller_did,
        agent_did: introspection.agent_did,
        scope: introspection.scope,
        aud: introspection.aud,
        token_scope_hash_b64u: introspection.token_scope_hash_b64u,
      },
      [
        hint(
          'REQUEST_REQUIRED_AUDIENCE',
          'Token audience binding does not include required target(s)',
          `Request token with audience(s): ${missingAudience.join(', ')}`
        ),
      ]
    );
  }

  let transitionMatrix: MatrixResponse['matrix'] | undefined;
  const requiredTransitions = uniqueStrings(req.required_transitions ?? []);
  if (requiredTransitions.length > 0) {
    let matrixResponse: JsonResponse;
    try {
      matrixResponse = await postJson(
        fetcher,
        `${baseUrl.replace(/\/$/, '')}/v1/tokens/introspect/matrix`,
        { token: req.token },
        timeoutMs
      );
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return buildInvalidResponse(
        now,
        'Failed to query clawscope transition matrix endpoint',
        {
          code: 'DEPENDENCY_NOT_CONFIGURED',
          message,
        },
        {
          token_hash: tokenHash,
          active: true,
          revoked: false,
          token_lane: tokenLane,
          owner_did: introspection.owner_did,
          controller_did: introspection.controller_did,
          agent_did: introspection.agent_did,
        },
        [
          hint(
            'CHECK_CONTROL_CHAIN_CONFIG',
            'Transition matrix endpoint unavailable',
            'Check clawscope /v1/tokens/introspect/matrix availability'
          ),
        ]
      );
    }

    if (matrixResponse.status !== 200 || !matrixResponse.json) {
      return buildInvalidResponse(
        now,
        'clawscope transition matrix request failed',
        {
          code: matrixResponse.status >= 500 ? 'DEPENDENCY_NOT_CONFIGURED' : 'PARSE_ERROR',
          message:
            getUpstreamErrorMessage(matrixResponse.json) ??
            `clawscope transition matrix failed with status ${matrixResponse.status}`,
        },
        {
          token_hash: tokenHash,
          active: true,
          revoked: false,
          token_lane: tokenLane,
          owner_did: introspection.owner_did,
          controller_did: introspection.controller_did,
          agent_did: introspection.agent_did,
        },
        [
          hint(
            'CHECK_CONTROL_CHAIN_CONFIG',
            'Could not evaluate sensitive transition matrix',
            'Check clawscope matrix endpoint and payload contract'
          ),
        ]
      );
    }

    const matrixPayload = matrixResponse.json as MatrixResponse;
    transitionMatrix = matrixPayload.matrix ?? {};

    const deniedTransitions = requiredTransitions.filter((transition) => {
      const entry = transitionMatrix?.[transition];
      return !entry || entry.allowed !== true;
    });

    if (deniedTransitions.length > 0) {
      return buildInvalidResponse(
        now,
        `Token is not authorized for transition(s): ${deniedTransitions.join(', ')}`,
        {
          code: 'TOKEN_CONTROL_TRANSITION_FORBIDDEN',
          message: `Transition(s) denied by matrix: ${deniedTransitions.join(', ')}`,
          field: 'required_transitions',
        },
        {
          token_hash: tokenHash,
          active: true,
          revoked: false,
          token_lane: tokenLane,
          owner_did: introspection.owner_did,
          controller_did: introspection.controller_did,
          agent_did: introspection.agent_did,
          scope: introspection.scope,
          aud: introspection.aud,
          token_scope_hash_b64u: introspection.token_scope_hash_b64u,
          transition_matrix: transitionMatrix,
        },
        [
          hint(
            'UPDATE_SENSITIVE_POLICY',
            'Transition matrix denied one or more requested sensitive transitions',
            'Update controller sensitive policy and reissue token'
          ),
          hint(
            'USE_CANONICAL_CST_LANE',
            'Sensitive transitions require canonical chain-bound CST lane',
            'Use /v1/tokens/issue/canonical in clawscope'
          ),
        ]
      );
    }
  }

  return {
    result: {
      status: 'VALID',
      reason: 'Token satisfies control-chain, audience, scope, and transition requirements',
      verified_at: now,
    },
    token_hash: tokenHash,
    active: true,
    revoked: false,
    token_lane: tokenLane,
    owner_did: introspection.owner_did,
    controller_did: introspection.controller_did,
    agent_did: introspection.agent_did,
    aud: introspection.aud,
    scope: introspection.scope,
    token_scope_hash_b64u: introspection.token_scope_hash_b64u,
    transition_matrix: transitionMatrix,
    remediation_hints: [],
  };
}
