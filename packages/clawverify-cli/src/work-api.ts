/**
 * Clawbounties marketplace API client.
 *
 * Handles worker registration, listing, and claim/submit interactions.
 * All network errors are surfaced as structured results (never thrown)
 * so callers can produce clean JSON output.
 */

import type { WorkerRegistration } from './work-config.js';
import type { AssuranceRequirementsV1, TaskSpecV1 } from './task-spec.generated.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RegisterWorkerRequest {
  workerDid: string;
}

export type RegisterWorkerResult =
  | { ok: true; registration: WorkerRegistration }
  | { ok: false; code: string; message: string };

/** A single bounty as returned by GET /v1/bounties. */
export interface Bounty {
  id: string;
  title: string;
  repo?: string;
  skills?: string[];
  budget?: number;
  currency?: string;
  status?: string;
  created_at?: string;
  assurance_requirements?: AssuranceRequirementsV1;
  /** Catch-all for extra marketplace fields. */
  [key: string]: unknown;
}

export type ListBountiesResult =
  | { ok: true; bounties: Bounty[] }
  | { ok: false; code: string; message: string };

export interface AcceptBountyRequest {
  workerDid: string;
  idempotencyKey: string;
  authToken: string;
  cwcWorkerEnvelope?: Record<string, unknown>;
}

export interface AcceptBountyResponse {
  bounty_id: string;
  escrow_id: string;
  status: string;
  worker_did: string;
  accepted_at: string;
  fee_policy_version?: string;
  payout?: {
    worker_net_minor?: string;
    currency?: string;
    [key: string]: unknown;
  };
  assurance_requirements?: AssuranceRequirementsV1;
  task_spec?: TaskSpecV1;
  [key: string]: unknown;
}

export type AcceptBountyResult =
  | { ok: true; claim: AcceptBountyResponse }
  | { ok: false; code: string; message: string; details?: unknown };

export interface SubmitBountyRequest {
  workerDid: string;
  authToken: string;
  proofBundleEnvelope: Record<string, unknown>;
  idempotencyKey?: string;
  urm?: Record<string, unknown>;
  commitProofEnvelope?: Record<string, unknown>;
  artifacts?: unknown[];
  agentPack?: Record<string, unknown>;
  resultSummary?: string;
  trustPulse?: Record<string, unknown>;
  executionAttestations?: Record<string, unknown>[];
}

export interface SubmitBountyResponse {
  submission_id: string;
  bounty_id: string;
  status: string;
  verification?: {
    proof_bundle?: {
      status?: string;
      reason?: string;
      verified_at?: string;
      tier?: string | null;
      [key: string]: unknown;
    };
    commit_proof?: {
      status?: string;
      reason?: string;
      verified_at?: string;
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  next_actions?: string[];
  [key: string]: unknown;
}

export type SubmitBountyResult =
  | { ok: true; submission: SubmitBountyResponse }
  | { ok: false; code: string; message: string; details?: unknown };

export interface GetSubmissionStatusRequest {
  workerDid: string;
  authToken?: string;
}

export interface SubmissionStatusResponse {
  submission_id: string;
  status: string;
  verification_result?: unknown;
  approval_status?: string;
  payout?: Record<string, unknown>;
  reason_codes?: string[];
  next_actions?: string[];
  [key: string]: unknown;
}

export type GetSubmissionStatusResult =
  | { ok: true; submission: SubmissionStatusResponse }
  | { ok: false; code: string; message: string; details?: unknown };

// ---------------------------------------------------------------------------
// Internal: pluggable fetch for testability
// ---------------------------------------------------------------------------

type FetchFn = typeof globalThis.fetch;

let _fetch: FetchFn = globalThis.fetch;

/**
 * Override the fetch implementation (for testing).
 * Returns a restore function.
 */
export function __setFetch(fn: FetchFn): () => void {
  const prev = _fetch;
  _fetch = fn;
  return () => {
    _fetch = prev;
  };
}

function toRecord(input: unknown): Record<string, unknown> | null {
  return input && typeof input === 'object' ? (input as Record<string, unknown>) : null;
}

const ASSURANCE_REQUIRED_LEVELS = new Set(['none', 'gateway', 'sandbox']);
const ASSURANCE_PRIVACY_POSTURES = new Set(['good', 'caution', 'action']);
const ASSURANCE_APPROVAL_POLICIES = new Set(['none', 'human_approval_receipt']);
const ASSURANCE_REQUIRED_PROCESSOR_RE = /^[a-z0-9][a-z0-9._:-]{0,119}$/;

function normalizeAssuranceRequirements(
  input: unknown,
): { ok: true; value: AssuranceRequirementsV1 } | { ok: false; message: string } {
  const raw = toRecord(input);
  if (!raw) {
    return { ok: false, message: 'must be an object' };
  }

  const allowedKeys = new Set([
    'version',
    'required_assurance_level',
    'required_privacy_posture',
    'required_processors',
    'approval_policy',
  ]);
  for (const key of Object.keys(raw)) {
    if (!allowedKeys.has(key)) {
      return { ok: false, message: `unexpected property: ${key}` };
    }
  }

  if (raw.version !== '1') {
    return { ok: false, message: 'version must be "1"' };
  }

  let requiredAssuranceLevel: AssuranceRequirementsV1['required_assurance_level'];
  if (raw.required_assurance_level !== undefined) {
    if (typeof raw.required_assurance_level !== 'string') {
      return { ok: false, message: 'required_assurance_level must be a string' };
    }
    if (!ASSURANCE_REQUIRED_LEVELS.has(raw.required_assurance_level)) {
      return { ok: false, message: 'required_assurance_level must be one of: none, gateway, sandbox' };
    }
    requiredAssuranceLevel = raw.required_assurance_level as AssuranceRequirementsV1['required_assurance_level'];
  }

  let requiredPrivacyPosture: AssuranceRequirementsV1['required_privacy_posture'];
  if (raw.required_privacy_posture !== undefined) {
    if (typeof raw.required_privacy_posture !== 'string') {
      return { ok: false, message: 'required_privacy_posture must be a string' };
    }
    if (!ASSURANCE_PRIVACY_POSTURES.has(raw.required_privacy_posture)) {
      return { ok: false, message: 'required_privacy_posture must be one of: good, caution, action' };
    }
    requiredPrivacyPosture = raw.required_privacy_posture as AssuranceRequirementsV1['required_privacy_posture'];
  }

  let requiredProcessors: string[] | undefined;
  if (raw.required_processors !== undefined) {
    if (!Array.isArray(raw.required_processors)) {
      return { ok: false, message: 'required_processors must be an array' };
    }
    if (raw.required_processors.length === 0) {
      return { ok: false, message: 'required_processors must have at least 1 item' };
    }
    if (raw.required_processors.length > 32) {
      return { ok: false, message: 'required_processors must have at most 32 items' };
    }

    const seen = new Set<string>();
    const parsed: string[] = [];
    for (const entry of raw.required_processors) {
      if (typeof entry !== 'string') {
        return { ok: false, message: 'required_processors entries must be strings' };
      }
      const trimmed = entry.trim();
      if (!trimmed) {
        return { ok: false, message: 'required_processors entries must be non-empty strings' };
      }
      if (!ASSURANCE_REQUIRED_PROCESSOR_RE.test(trimmed)) {
        return {
          ok: false,
          message: `required_processors entry "${trimmed}" must match ^[a-z0-9][a-z0-9._:-]{0,119}$`,
        };
      }
      if (seen.has(trimmed)) {
        return { ok: false, message: `required_processors contains duplicate entry "${trimmed}"` };
      }
      seen.add(trimmed);
      parsed.push(trimmed);
    }
    requiredProcessors = parsed;
  }

  let approvalPolicy: AssuranceRequirementsV1['approval_policy'];
  if (raw.approval_policy !== undefined) {
    if (typeof raw.approval_policy !== 'string') {
      return { ok: false, message: 'approval_policy must be a string' };
    }
    if (!ASSURANCE_APPROVAL_POLICIES.has(raw.approval_policy)) {
      return { ok: false, message: 'approval_policy must be one of: none, human_approval_receipt' };
    }
    approvalPolicy = raw.approval_policy as AssuranceRequirementsV1['approval_policy'];
  }

  if (
    requiredAssuranceLevel === undefined
    && requiredPrivacyPosture === undefined
    && requiredProcessors === undefined
    && approvalPolicy === undefined
  ) {
    return {
      ok: false,
      message:
        'must declare at least one requirement: required_assurance_level, required_privacy_posture, required_processors, approval_policy',
    };
  }

  return {
    ok: true,
    value: {
      version: '1',
      ...(requiredAssuranceLevel ? { required_assurance_level: requiredAssuranceLevel } : {}),
      ...(requiredPrivacyPosture ? { required_privacy_posture: requiredPrivacyPosture } : {}),
      ...(requiredProcessors ? { required_processors: requiredProcessors } : {}),
      ...(approvalPolicy ? { approval_policy: approvalPolicy } : {}),
    },
  };
}

function extractAssuranceRequirements(
  body: Record<string, unknown>,
): { ok: true; value?: AssuranceRequirementsV1 } | { ok: false; message: string } {
  const fromRoot = body.assurance_requirements;
  const fromMetadata = toRecord(body.metadata)?.assurance_requirements;
  const source = fromRoot !== undefined ? fromRoot : fromMetadata;
  if (source === undefined || source === null) {
    return { ok: true };
  }
  const normalized = normalizeAssuranceRequirements(source);
  if (!normalized.ok) {
    return normalized;
  }
  return { ok: true, value: normalized.value };
}

function extractReward(
  body: Record<string, unknown>,
): { budget?: number; currency?: string } {
  const reward = toRecord(body.reward);
  const amountMinor =
    typeof body.amount_minor === 'string'
      ? body.amount_minor
      : typeof reward?.amount_minor === 'string'
        ? reward.amount_minor
        : undefined;
  const currency =
    typeof body.currency === 'string'
      ? body.currency
      : typeof reward?.currency === 'string'
        ? reward.currency
        : undefined;

  return {
    ...(amountMinor && /^\d+$/.test(amountMinor) ? { budget: Number(amountMinor) } : {}),
    ...(currency ? { currency } : {}),
  };
}

function normalizeRegistrationAuth(input: unknown): { mode: string; token: string } | null {
  const auth = toRecord(input);
  if (!auth) return null;

  const token = typeof auth.token === 'string' ? auth.token.trim() : '';
  if (!token) return null;

  const mode = typeof auth.mode === 'string' && auth.mode.trim().length > 0
    ? auth.mode.trim()
    : 'token';

  return { mode, token };
}

async function parseApiError(
  response: Response,
  fallbackCode: string,
): Promise<{ code: string; message: string; details?: unknown }> {
  let bodyText = '';
  try {
    bodyText = await response.text();
  } catch {
    bodyText = '';
  }

  if (bodyText.length > 0) {
    try {
      const parsed = JSON.parse(bodyText) as unknown;
      const r = toRecord(parsed);
      if (r) {
        const code = typeof r.error === 'string' && r.error.trim().length > 0
          ? r.error.trim()
          : fallbackCode;

        const message = typeof r.message === 'string' && r.message.trim().length > 0
          ? r.message.trim()
          : `HTTP ${response.status}`;

        return {
          code,
          message,
          ...(r.details !== undefined ? { details: r.details } : {}),
        };
      }
    } catch {
      // ignore parse failure, handled below
    }
  }

  return {
    code: fallbackCode,
    message: `HTTP ${response.status}${bodyText ? ': ' + bodyText.slice(0, 500) : ''}`,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * List bounties from the clawbounties marketplace.
 *
 * GET {marketplaceUrl}/v1/bounties
 *
 * Optional headers:
 *   X-Worker-DID: <did>            (when identity is available)
 *   Authorization: Bearer <token>  (when worker registration token is available)
 *
 * Expected success response (200):
 *   { "bounties": [ ... ] }  or  [ ... ]
 */
export async function listBounties(
  marketplaceUrl: string,
  workerDid?: string,
  authToken?: string,
): Promise<ListBountiesResult> {
  const url = `${marketplaceUrl.replace(/\/+$/, '')}/v1/bounties`;

  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  if (workerDid) {
    headers['X-Worker-DID'] = workerDid;
  }
  if (authToken) {
    headers.Authorization = `Bearer ${authToken}`;
  }

  let response: Response;
  try {
    response = await _fetch(url, { method: 'GET', headers });
  } catch (err) {
    return {
      ok: false,
      code: 'NETWORK_ERROR',
      message: err instanceof Error ? err.message : 'fetch failed',
    };
  }

  if (!response.ok) {
    let detail = '';
    try {
      const body = await response.text();
      detail = body.slice(0, 500);
    } catch {
      // ignore read errors
    }
    return {
      ok: false,
      code: 'LIST_FAILED',
      message: `HTTP ${response.status}${detail ? ': ' + detail : ''}`,
    };
  }

  try {
    const body = await response.json();
    // Accept both { bounties: [...] } and bare array.
    const raw: unknown[] = Array.isArray(body)
      ? body
      : Array.isArray((body as Record<string, unknown>).bounties)
        ? (body as Record<string, unknown>).bounties as unknown[]
        : [];

    const bounties: Bounty[] = [];
    for (const item of raw) {
      const r = (item && typeof item === 'object' ? item : {}) as Record<string, unknown>;
      const assurance = extractAssuranceRequirements(r);
      if (!assurance.ok) {
        const bountyId = typeof r.bounty_id === 'string'
          ? r.bounty_id
          : typeof r.id === 'string'
            ? r.id
            : '(unknown)';
        return {
          ok: false,
          code: 'UNSUPPORTED_ASSURANCE_REQUIREMENTS',
          message: `Bounty ${bountyId} returned unsupported assurance_requirements: ${assurance.message}`,
        };
      }

      bounties.push({
        id: typeof r.id === 'string'
          ? r.id
          : typeof r.bounty_id === 'string'
            ? r.bounty_id
            : '',
        title: typeof r.title === 'string' ? r.title : '',
        ...(typeof r.repo === 'string' ? { repo: r.repo } : {}),
        ...(Array.isArray(r.skills) ? { skills: r.skills.filter((s: unknown) => typeof s === 'string') as string[] } : {}),
        ...(typeof r.budget === 'number' ? { budget: r.budget } : extractReward(r)),
        ...(typeof r.status === 'string' ? { status: r.status } : {}),
        ...(typeof r.created_at === 'string' ? { created_at: r.created_at } : {}),
        ...(typeof r.min_proof_tier === 'string' ? { min_proof_tier: r.min_proof_tier } : {}),
        ...(typeof r.minimum_proof_tier === 'string' ? { minimum_proof_tier: r.minimum_proof_tier } : {}),
        ...(assurance.value ? { assurance_requirements: assurance.value } : {}),
      } satisfies Bounty);
    }

    return { ok: true, bounties };
  } catch {
    return {
      ok: false,
      code: 'LIST_PARSE_ERROR',
      message: 'Could not parse bounty list response as JSON',
    };
  }
}

/**
 * Register a worker DID with the clawbounties marketplace.
 *
 * POST {marketplaceUrl}/v1/workers/register
 * Body: { "worker_did": "<did>" }
 *
 * Expected success response (200):
 *   { "worker_id": "...", "registered_at": "...", ... }
 */
export async function registerWorker(
  marketplaceUrl: string,
  request: RegisterWorkerRequest,
): Promise<RegisterWorkerResult> {
  const url = `${marketplaceUrl.replace(/\/+$/, '')}/v1/workers/register`;

  let response: Response;
  try {
    response = await _fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ worker_did: request.workerDid }),
    });
  } catch (err) {
    return {
      ok: false,
      code: 'NETWORK_ERROR',
      message: err instanceof Error ? err.message : 'fetch failed',
    };
  }

  if (!response.ok) {
    let detail = '';
    try {
      const body = await response.text();
      detail = body.slice(0, 500);
    } catch {
      // ignore read errors
    }
    return {
      ok: false,
      code: 'REGISTRATION_FAILED',
      message: `HTTP ${response.status}${detail ? ': ' + detail : ''}`,
    };
  }

  try {
    const body = (await response.json()) as Record<string, unknown>;
    const registration: WorkerRegistration = {
      workerId: (body.worker_id as string) ?? '',
      registeredAt: (body.registered_at as string) ?? new Date().toISOString(),
    };

    const normalizedAuth = normalizeRegistrationAuth(body.auth);
    if (normalizedAuth) {
      registration.auth = normalizedAuth;
    } else {
      const fallbackTokenKeys = ['token', 'auth_token', 'worker_token', 'worker_auth_token'] as const;
      for (const key of fallbackTokenKeys) {
        const value = body[key];
        if (typeof value === 'string' && value.trim().length > 0) {
          registration.auth = { mode: 'token', token: value.trim() };
          break;
        }
      }
    }

    // Preserve any extra fields the marketplace returns.
    for (const [k, v] of Object.entries(body)) {
      if (k !== 'worker_id' && k !== 'registered_at' && k !== 'auth') {
        registration[k] = v;
      }
    }

    return { ok: true, registration };
  } catch {
    return {
      ok: false,
      code: 'REGISTRATION_PARSE_ERROR',
      message: 'Could not parse registration response as JSON',
    };
  }
}

/**
 * Claim a bounty as the authenticated worker.
 *
 * POST {marketplaceUrl}/v1/bounties/{bounty_id}/accept
 * Authorization: Bearer <worker token>
 * Body: { worker_did, idempotency_key, cwc_worker_envelope? }
 */
export async function acceptBounty(
  marketplaceUrl: string,
  bountyId: string,
  request: AcceptBountyRequest,
): Promise<AcceptBountyResult> {
  const url = `${marketplaceUrl.replace(/\/+$/, '')}/v1/bounties/${encodeURIComponent(bountyId)}/accept`;

  const body: Record<string, unknown> = {
    worker_did: request.workerDid,
    idempotency_key: request.idempotencyKey,
  };

  if (request.cwcWorkerEnvelope) {
    body.cwc_worker_envelope = request.cwcWorkerEnvelope;
  }

  let response: Response;
  try {
    response = await _fetch(url, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${request.authToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
  } catch (err) {
    return {
      ok: false,
      code: 'NETWORK_ERROR',
      message: err instanceof Error ? err.message : 'fetch failed',
    };
  }

  if (!response.ok) {
    const parsed = await parseApiError(response, 'CLAIM_FAILED');
    return {
      ok: false,
      code: parsed.code,
      message: parsed.message,
      ...(parsed.details !== undefined ? { details: parsed.details } : {}),
    };
  }

  try {
    const bodyRaw = (await response.json()) as Record<string, unknown>;
    const assurance = extractAssuranceRequirements(bodyRaw);
    if (!assurance.ok) {
      return {
        ok: false,
        code: 'UNSUPPORTED_ASSURANCE_REQUIREMENTS',
        message: `Claim response returned unsupported assurance_requirements: ${assurance.message}`,
      };
    }

    const claim: AcceptBountyResponse = {
      bounty_id: typeof bodyRaw.bounty_id === 'string' ? bodyRaw.bounty_id : bountyId,
      escrow_id: typeof bodyRaw.escrow_id === 'string' ? bodyRaw.escrow_id : '',
      status: typeof bodyRaw.status === 'string' ? bodyRaw.status : 'accepted',
      worker_did: typeof bodyRaw.worker_did === 'string' ? bodyRaw.worker_did : request.workerDid,
      accepted_at: typeof bodyRaw.accepted_at === 'string' ? bodyRaw.accepted_at : new Date().toISOString(),
      ...(typeof bodyRaw.fee_policy_version === 'string' ? { fee_policy_version: bodyRaw.fee_policy_version } : {}),
      ...(toRecord(bodyRaw.payout) ? { payout: bodyRaw.payout as AcceptBountyResponse['payout'] } : {}),
      ...(assurance.value ? { assurance_requirements: assurance.value } : {}),
    };

    for (const [k, v] of Object.entries(bodyRaw)) {
      if (!(k in claim)) {
        claim[k] = v;
      }
    }

    return { ok: true, claim };
  } catch {
    return {
      ok: false,
      code: 'CLAIM_PARSE_ERROR',
      message: 'Could not parse claim response as JSON',
    };
  }
}

/**
 * Submit completed bounty work.
 *
 * POST {marketplaceUrl}/v1/bounties/{bounty_id}/submit
 * Authorization: Bearer <worker token>
 */
export async function submitBounty(
  marketplaceUrl: string,
  bountyId: string,
  request: SubmitBountyRequest,
): Promise<SubmitBountyResult> {
  const url = `${marketplaceUrl.replace(/\/+$/, '')}/v1/bounties/${encodeURIComponent(bountyId)}/submit`;

  const body: Record<string, unknown> = {
    worker_did: request.workerDid,
    proof_bundle_envelope: request.proofBundleEnvelope,
  };

  if (request.idempotencyKey) body.idempotency_key = request.idempotencyKey;
  if (request.urm) body.urm = request.urm;
  if (request.commitProofEnvelope) body.commit_proof_envelope = request.commitProofEnvelope;
  if (request.artifacts) body.artifacts = request.artifacts;
  if (request.agentPack) body.agent_pack = request.agentPack;
  if (request.resultSummary) body.result_summary = request.resultSummary;
  if (request.trustPulse) body.trust_pulse = request.trustPulse;
  if (request.executionAttestations) body.execution_attestations = request.executionAttestations;

  let response: Response;
  try {
    response = await _fetch(url, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${request.authToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });
  } catch (err) {
    return {
      ok: false,
      code: 'NETWORK_ERROR',
      message: err instanceof Error ? err.message : 'fetch failed',
    };
  }

  if (!response.ok) {
    const parsed = await parseApiError(response, 'SUBMIT_FAILED');
    return {
      ok: false,
      code: parsed.code,
      message: parsed.message,
      ...(parsed.details !== undefined ? { details: parsed.details } : {}),
    };
  }

  try {
    const bodyRaw = (await response.json()) as Record<string, unknown>;
    const submission: SubmitBountyResponse = {
      submission_id: typeof bodyRaw.submission_id === 'string' ? bodyRaw.submission_id : '',
      bounty_id: typeof bodyRaw.bounty_id === 'string' ? bodyRaw.bounty_id : bountyId,
      status: typeof bodyRaw.status === 'string' ? bodyRaw.status : 'pending_review',
    };

    if (toRecord(bodyRaw.verification)) {
      submission.verification = bodyRaw.verification as SubmitBountyResponse['verification'];
    }

    if (Array.isArray(bodyRaw.next_actions)) {
      const nextActions = bodyRaw.next_actions
        .filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
        .map((v) => v.trim());
      if (nextActions.length > 0) {
        submission.next_actions = nextActions;
      }
    }

    for (const [k, v] of Object.entries(bodyRaw)) {
      if (!(k in submission)) {
        submission[k] = v;
      }
    }

    return { ok: true, submission };
  } catch {
    return {
      ok: false,
      code: 'SUBMIT_PARSE_ERROR',
      message: 'Could not parse submit response as JSON',
    };
  }
}

/**
 * Fetch current submission status.
 *
 * GET {marketplaceUrl}/v1/submissions/{submission_id}
 * X-Worker-DID: <did>
 * Authorization: Bearer <worker token> (optional)
 */
export async function getSubmissionStatus(
  marketplaceUrl: string,
  submissionId: string,
  request: GetSubmissionStatusRequest,
): Promise<GetSubmissionStatusResult> {
  const url = `${marketplaceUrl.replace(/\/+$/, '')}/v1/submissions/${encodeURIComponent(submissionId)}`;

  const headers: Record<string, string> = {
    Accept: 'application/json',
    'X-Worker-DID': request.workerDid,
  };
  if (request.authToken && request.authToken.trim().length > 0) {
    headers.Authorization = `Bearer ${request.authToken}`;
  }

  let response: Response;
  try {
    response = await _fetch(url, { method: 'GET', headers });
  } catch (err) {
    return {
      ok: false,
      code: 'NETWORK_ERROR',
      message: err instanceof Error ? err.message : 'fetch failed',
    };
  }

  if (!response.ok) {
    const parsed = await parseApiError(response, 'SUBMISSION_STATUS_FAILED');
    return {
      ok: false,
      code: parsed.code,
      message: parsed.message,
      ...(parsed.details !== undefined ? { details: parsed.details } : {}),
    };
  }

  try {
    const bodyRaw = (await response.json()) as Record<string, unknown>;
    const submission: SubmissionStatusResponse = {
      submission_id: typeof bodyRaw.submission_id === 'string' ? bodyRaw.submission_id : submissionId,
      status: typeof bodyRaw.status === 'string' ? bodyRaw.status : '',
    };

    if (bodyRaw.verification_result !== undefined) {
      submission.verification_result = bodyRaw.verification_result;
    }

    if (typeof bodyRaw.approval_status === 'string') {
      submission.approval_status = bodyRaw.approval_status;
    }

    if (toRecord(bodyRaw.payout)) {
      submission.payout = bodyRaw.payout as Record<string, unknown>;
    }

    if (Array.isArray(bodyRaw.reason_codes)) {
      const reasonCodes = bodyRaw.reason_codes
        .filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
        .map((entry) => entry.trim());
      if (reasonCodes.length > 0) {
        submission.reason_codes = reasonCodes;
      }
    }

    if (Array.isArray(bodyRaw.next_actions)) {
      const nextActions = bodyRaw.next_actions
        .filter((entry): entry is string => typeof entry === 'string' && entry.trim().length > 0)
        .map((entry) => entry.trim());
      if (nextActions.length > 0) {
        submission.next_actions = nextActions;
      }
    }

    for (const [k, v] of Object.entries(bodyRaw)) {
      if (!(k in submission)) {
        submission[k] = v;
      }
    }

    return { ok: true, submission };
  } catch {
    return {
      ok: false,
      code: 'SUBMISSION_STATUS_PARSE_ERROR',
      message: 'Could not parse submission status response as JSON',
    };
  }
}
