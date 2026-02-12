import {
  computeTokenScopeHashB64u,
  normalizeAudience,
  normalizeScope,
  revalidateSensitiveTransitions,
  validateCanonicalControlContext,
} from '../../../packages/identity-auth/src/index';
import type {
  RemediationHint,
  VerificationError,
  VerifyTokenControlRequest,
  VerifyTokenControlResponse,
} from './types';
import { isValidDidFormat } from './schema-registry';

interface VerifyTokenControlOptions {
  clawscopeBaseUrl?: string;
  timeoutMs?: number;
  transparencyMaxAgeSeconds?: number;
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
  kid?: string;
  kid_source?: string;
  iat?: number;
  exp?: number;
}

interface KeyTransparencySnapshot {
  snapshot_id?: string;
  generated_at?: number;
  generated_at_iso?: string;
  active_kid?: string;
  accepted_kids?: string[];
  expiring_kids?: Array<{ kid: string; not_after_unix: number }>;
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

async function getJson(
  fetcher: typeof fetch,
  url: string,
  timeoutMs: number
): Promise<JsonResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetcher(url, {
      method: 'GET',
      headers: {
        accept: 'application/json',
      },
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

  if (normalized.expected_owner_did && !isValidDidFormat(normalized.expected_owner_did)) {
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

  if (normalized.expected_controller_did && !isValidDidFormat(normalized.expected_controller_did)) {
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

  if (normalized.expected_agent_did && !isValidDidFormat(normalized.expected_agent_did)) {
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
    normalized.required_scope = normalizeScope(req.required_scope.filter((v) => typeof v === 'string'));
  }

  if (Array.isArray(req.required_transitions)) {
    normalized.required_transitions = normalizeScope(
      req.required_transitions.filter((v) => typeof v === 'string')
    );
  }

  return {
    ok: true,
    req: normalized,
  };
}

function normalizeRequiredAudience(value: VerifyTokenControlRequest['required_audience']): string[] {
  if (Array.isArray(value)) {
    return uniqueStrings(value);
  }

  if (typeof value === 'string' && value.trim().length > 0) {
    return [value.trim()];
  }

  return [];
}

async function fetchTransparencySnapshot(
  fetcher: typeof fetch,
  baseUrl: string,
  timeoutMs: number
): Promise<JsonResponse> {
  return getJson(fetcher, `${baseUrl.replace(/\/$/, '')}/v1/keys/transparency/latest`, timeoutMs);
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
  const transparencyMaxAgeSeconds =
    options.transparencyMaxAgeSeconds && Number.isFinite(options.transparencyMaxAgeSeconds)
      ? Math.max(60, Math.floor(options.transparencyMaxAgeSeconds))
      : 60 * 60;
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
          hint('REISSUE_TOKEN', 'Token uses an expired overlap key', 'Reissue token with the current active key'),
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

  const canonicalContext = validateCanonicalControlContext(
    {
      owner_did: introspection.owner_did,
      controller_did: introspection.controller_did,
      agent_did: introspection.agent_did,
      token_lane: introspection.token_lane,
    },
    {
      owner_did: req.expected_owner_did,
      controller_did: req.expected_controller_did,
      agent_did: req.expected_agent_did,
    }
  );

  if (!canonicalContext.ok) {
    return buildInvalidResponse(
      now,
      canonicalContext.message ?? 'Token control context mismatch',
      {
        code: canonicalContext.code ?? 'TOKEN_CONTROL_CHAIN_MISSING',
        message: canonicalContext.message ?? 'Token control context mismatch',
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
          canonicalContext.code === 'TOKEN_CONTROL_CHAIN_MISSING'
            ? 'USE_CANONICAL_CST_LANE'
            : canonicalContext.code === 'TOKEN_CONTROL_SUBJECT_MISMATCH'
              ? 'REGISTER_AGENT_UNDER_CONTROLLER'
              : 'CHECK_CONTROL_CHAIN_CONFIG',
          'Token claims do not satisfy canonical control-chain constraints',
          'Issue a canonical token for the expected owner/controller/agent context and retry'
        ),
      ]
    );
  }

  const calculatedScopeHash = await computeTokenScopeHashB64u({
    sub: introspection.sub,
    aud: introspection.aud,
    scope: introspection.scope,
    owner_ref: introspection.owner_ref,
    owner_did: introspection.owner_did,
    controller_did: introspection.controller_did,
    agent_did: introspection.agent_did,
    policy_hash_b64u: introspection.policy_hash_b64u,
    control_plane_policy_hash_b64u: introspection.control_plane_policy_hash_b64u,
    payment_account_did: introspection.payment_account_did,
    spend_cap: introspection.spend_cap,
    mission_id: introspection.mission_id,
  });

  if (!introspection.token_scope_hash_b64u || introspection.token_scope_hash_b64u !== calculatedScopeHash) {
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

  const tokenScopeSet = new Set(normalizeScope(introspection.scope ?? []));
  const requiredScope = normalizeScope(req.required_scope ?? []);
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

  const requiredAudience = normalizeRequiredAudience(req.required_audience);
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

  let transparencySnapshot: KeyTransparencySnapshot | undefined;
  try {
    const snapshotResponse = await fetchTransparencySnapshot(fetcher, baseUrl, timeoutMs);
    if (snapshotResponse.status !== 200 || !snapshotResponse.json) {
      return buildInvalidResponse(
        now,
        'Failed to read key transparency snapshot',
        {
          code: 'DEPENDENCY_NOT_CONFIGURED',
          message:
            getUpstreamErrorMessage(snapshotResponse.json) ??
            `Key transparency endpoint failed with status ${snapshotResponse.status}`,
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
            'SYNC_REVOCATION_STREAM',
            'Key transparency snapshot is unavailable',
            'Restore clawscope key transparency endpoint and retry'
          ),
        ]
      );
    }

    transparencySnapshot = snapshotResponse.json as KeyTransparencySnapshot;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return buildInvalidResponse(
      now,
      'Failed to query key transparency snapshot',
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
          'Key transparency dependency is unavailable',
          'Verify clawscope /v1/keys/transparency/latest health'
        ),
      ]
    );
  }

  if (!transparencySnapshot || typeof transparencySnapshot.generated_at !== 'number') {
    return buildInvalidResponse(
      now,
      'Key transparency snapshot payload is invalid',
      {
        code: 'DEPENDENCY_NOT_CONFIGURED',
        message: 'generated_at is required in transparency snapshot',
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
      }
    );
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const snapshotAge = nowSec - transparencySnapshot.generated_at;
  if (snapshotAge > transparencyMaxAgeSeconds) {
    return buildInvalidResponse(
      now,
      'Key transparency snapshot is stale',
      {
        code: 'TOKEN_CONTROL_TRANSPARENCY_STALE',
        message: `Snapshot age ${snapshotAge}s exceeds max allowed ${transparencyMaxAgeSeconds}s`,
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
        transparency_snapshot: {
          snapshot_id: transparencySnapshot.snapshot_id,
          generated_at: transparencySnapshot.generated_at,
          generated_at_iso: transparencySnapshot.generated_at_iso,
          active_kid: transparencySnapshot.active_kid,
          accepted_kids: transparencySnapshot.accepted_kids,
          kid_observed: introspection.kid,
        },
      },
      [
        hint(
          'SYNC_REVOCATION_STREAM',
          'Verification requires fresh key transparency snapshots',
          'Regenerate key transparency snapshot in clawscope and retry'
        ),
      ]
    );
  }

  const acceptedKids = Array.isArray(transparencySnapshot.accepted_kids)
    ? uniqueStrings(transparencySnapshot.accepted_kids.filter((entry) => typeof entry === 'string'))
    : [];

  if (!introspection.kid || !acceptedKids.includes(introspection.kid)) {
    return buildInvalidResponse(
      now,
      'Token kid is not included in accepted transparency snapshot window',
      {
        code: 'TOKEN_CONTROL_TRANSPARENCY_KID_UNKNOWN',
        message: 'Observed token kid is not in snapshot accepted_kids',
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
        transparency_snapshot: {
          snapshot_id: transparencySnapshot.snapshot_id,
          generated_at: transparencySnapshot.generated_at,
          generated_at_iso: transparencySnapshot.generated_at_iso,
          active_kid: transparencySnapshot.active_kid,
          accepted_kids: acceptedKids,
          kid_observed: introspection.kid,
        },
      },
      [
        hint(
          'REISSUE_TOKEN',
          'Token kid is outside accepted overlap window',
          'Reissue token against current active keyset'
        ),
      ]
    );
  }

  const expiringEntry = (transparencySnapshot.expiring_kids ?? []).find(
    (entry) => entry && entry.kid === introspection.kid
  );
  if (
    expiringEntry &&
    typeof expiringEntry.not_after_unix === 'number' &&
    nowSec > expiringEntry.not_after_unix
  ) {
    return buildInvalidResponse(
      now,
      'Token kid overlap window has expired according to transparency snapshot',
      {
        code: 'TOKEN_CONTROL_TRANSPARENCY_KID_EXPIRED',
        message: `kid ${introspection.kid} expired at ${expiringEntry.not_after_unix}`,
      },
      {
        token_hash: tokenHash,
        active: true,
        revoked: false,
        token_lane: tokenLane,
        transparency_snapshot: {
          snapshot_id: transparencySnapshot.snapshot_id,
          generated_at: transparencySnapshot.generated_at,
          generated_at_iso: transparencySnapshot.generated_at_iso,
          active_kid: transparencySnapshot.active_kid,
          accepted_kids: acceptedKids,
          kid_observed: introspection.kid,
        },
      },
      [
        hint(
          'REISSUE_TOKEN',
          'Token kid overlap has expired',
          'Reissue token with currently active kid and retry'
        ),
      ]
    );
  }

  let transitionMatrix: VerifyTokenControlResponse['transition_matrix'] | undefined;
  const requiredTransitions = normalizeScope(req.required_transitions ?? []);
  if (requiredTransitions.length > 0) {
    const transitionResult = await revalidateSensitiveTransitions({
      scopeBaseUrl: baseUrl,
      token: req.token,
      requiredTransitions,
      timeoutMs,
      fetcher,
    });

    if (!transitionResult.ok) {
      if (transitionResult.code === 'TOKEN_CONTROL_TRANSITION_FORBIDDEN') {
        return buildInvalidResponse(
          now,
          transitionResult.message,
          {
            code: 'TOKEN_CONTROL_TRANSITION_FORBIDDEN',
            message: transitionResult.message,
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
            transition_matrix: transitionResult.matrix,
            transparency_snapshot: {
              snapshot_id: transparencySnapshot.snapshot_id,
              generated_at: transparencySnapshot.generated_at,
              generated_at_iso: transparencySnapshot.generated_at_iso,
              active_kid: transparencySnapshot.active_kid,
              accepted_kids: acceptedKids,
              kid_observed: introspection.kid,
            },
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

      return buildInvalidResponse(
        now,
        'Failed to evaluate sensitive transition matrix',
        {
          code: transitionResult.code === 'PARSE_ERROR' ? 'PARSE_ERROR' : 'DEPENDENCY_NOT_CONFIGURED',
          message: transitionResult.message,
        },
        {
          token_hash: tokenHash,
          active: true,
          revoked: false,
          token_lane: tokenLane,
          owner_did: introspection.owner_did,
          controller_did: introspection.controller_did,
          agent_did: introspection.agent_did,
          transparency_snapshot: {
            snapshot_id: transparencySnapshot.snapshot_id,
            generated_at: transparencySnapshot.generated_at,
            generated_at_iso: transparencySnapshot.generated_at_iso,
            active_kid: transparencySnapshot.active_kid,
            accepted_kids: acceptedKids,
            kid_observed: introspection.kid,
          },
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

    transitionMatrix = transitionResult.matrix;
  }

  return {
    result: {
      status: 'VALID',
      reason:
        'Token satisfies control-chain, audience, scope, transition requirements, and key transparency policy',
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
    transparency_snapshot: {
      snapshot_id: transparencySnapshot.snapshot_id,
      generated_at: transparencySnapshot.generated_at,
      generated_at_iso: transparencySnapshot.generated_at_iso,
      active_kid: transparencySnapshot.active_kid,
      accepted_kids: acceptedKids,
      kid_observed: introspection.kid,
    },
    remediation_hints: [],
  };
}
