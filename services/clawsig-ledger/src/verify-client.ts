import type { Env } from './types';

type VerifyStatus = 'VALID' | 'INVALID';

type FailureClass = 'none' | 'upstream_unavailable' | 'upstream_malformed';

interface UpstreamResultShape {
  status?: unknown;
  proof_tier?: unknown;
  agent_did?: unknown;
}

interface UpstreamErrorShape {
  code?: unknown;
  message?: unknown;
}

interface ParsedUpstreamVerification {
  status: VerifyStatus;
  proof_tier: string;
  agent_did?: string;
  error_code?: string;
  error_message?: string;
}

export interface VerifyProofBundleOutcome {
  status: VerifyStatus;
  proof_tier: string;
  agent_did?: string;
  reason_code: string;
  failure_class: FailureClass;
}

const DEFAULT_CLAWVERIFY_API_URL = 'https://clawverify.com';
const VERIFY_BUNDLE_PATH = '/v1/verify/bundle';

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object'
    ? (value as Record<string, unknown>)
    : null;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0
    ? value
    : undefined;
}

function normalizeReasonCode(raw: string | undefined, fallback: string): string {
  if (!raw) return fallback;

  const sanitized = raw
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');

  return sanitized.length > 0 ? sanitized : fallback;
}

function getVerifyBaseUrl(env: Pick<Env, 'CLAWVERIFY_API_URL'>): string {
  const configured = env.CLAWVERIFY_API_URL?.trim() || DEFAULT_CLAWVERIFY_API_URL;
  return configured.replace(/\/+$/, '');
}

function parseUpstreamVerification(payload: unknown): ParsedUpstreamVerification | null {
  const doc = asRecord(payload);
  if (!doc) return null;

  const result = asRecord(doc.result) as UpstreamResultShape | null;
  const error = asRecord(doc.error) as UpstreamErrorShape | null;

  const statusRaw = asString(result?.status);
  if (statusRaw !== 'VALID' && statusRaw !== 'INVALID') {
    return null;
  }

  const proofTier =
    asString(result?.proof_tier) ||
    asString(doc.proof_tier) ||
    'unknown';

  return {
    status: statusRaw,
    proof_tier: proofTier,
    agent_did: asString(result?.agent_did),
    error_code: asString(error?.code),
    error_message: asString(error?.message),
  };
}

async function parseResponseJson(response: Response): Promise<unknown | null> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

export async function verifyProofBundleViaApi(
  proofBundle: unknown,
  env: Pick<Env, 'CLAWVERIFY_API_URL' | 'CLAWVERIFY_API_TOKEN'>
): Promise<VerifyProofBundleOutcome> {
  const url = `${getVerifyBaseUrl(env)}${VERIFY_BUNDLE_PATH}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (env.CLAWVERIFY_API_TOKEN?.trim()) {
    headers.Authorization = `Bearer ${env.CLAWVERIFY_API_TOKEN.trim()}`;
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ envelope: proofBundle }),
    });
  } catch {
    return {
      status: 'INVALID',
      proof_tier: 'unknown',
      reason_code: 'VERIFIER_UNAVAILABLE',
      failure_class: 'upstream_unavailable',
    };
  }

  const payload = await parseResponseJson(response);
  const parsed = parseUpstreamVerification(payload);

  if (!parsed) {
    return {
      status: 'INVALID',
      proof_tier: 'unknown',
      reason_code: 'VERIFIER_MALFORMED_RESPONSE',
      failure_class: 'upstream_malformed',
    };
  }

  if (response.status >= 500) {
    return {
      status: 'INVALID',
      proof_tier: parsed.proof_tier,
      agent_did: parsed.agent_did,
      reason_code: 'VERIFIER_UNAVAILABLE',
      failure_class: 'upstream_unavailable',
    };
  }

  if (parsed.status === 'VALID') {
    return {
      status: 'VALID',
      proof_tier: parsed.proof_tier,
      agent_did: parsed.agent_did,
      reason_code: 'OK',
      failure_class: 'none',
    };
  }

  return {
    status: 'INVALID',
    proof_tier: parsed.proof_tier,
    agent_did: parsed.agent_did,
    reason_code: normalizeReasonCode(parsed.error_code, 'VERIFICATION_FAILED'),
    failure_class: 'none',
  };
}
