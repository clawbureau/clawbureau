export interface ReasonCodeExplanation {
  reason_code: string;
  title: string;
  plain_language: string;
  likely_root_cause: string;
  remediation_steps: string[];
  next_step_snippet: string;
}

const EXPLANATIONS: Record<string, Omit<ReasonCodeExplanation, 'reason_code'>> = {
  HASH_MISMATCH: {
    title: 'Bundle Integrity Mismatch',
    plain_language: 'The verifier recomputed a hash and it did not match what was signed.',
    likely_root_cause: 'Payload mutation after signing, non-canonical serialization, or stale/corrupted bundle bytes.',
    remediation_steps: [
      'Re-generate the proof bundle from source artifacts without manual edits.',
      'Ensure canonical JSON serialization is used before signing.',
      'Re-submit the newly generated bundle and compare hash fields end-to-end.',
    ],
    next_step_snippet: 'npx clawsig verify --bundle ./proof_bundle.json',
  },
  POW_REQUIRED: {
    title: 'Proof-of-Work Required',
    plain_language: 'The request was unauthenticated and did not include a Hashcash nonce.',
    likely_root_cause: 'Client submitted without API key and without `X-Hashcash-Nonce`.',
    remediation_steps: [
      'Either authenticate with a valid API key or compute a Hashcash nonce.',
      'Read `X-Hashcash-Challenge` and `X-Hashcash-Difficulty` from the failure response.',
      'Retry with a nonce that satisfies the required difficulty.',
    ],
    next_step_snippet: 'curl -sS https://api.clawverify.com/health | jq .',
  },
  POW_INVALID: {
    title: 'Proof-of-Work Invalid',
    plain_language: 'The supplied Hashcash nonce did not satisfy the challenge difficulty.',
    likely_root_cause: 'Nonce computed against the wrong challenge or insufficient leading-zero work.',
    remediation_steps: [
      'Recompute the nonce against the latest challenge from response headers.',
      'Use the exact difficulty value from `X-Hashcash-Difficulty`.',
      'Retry with a fresh nonce bound to this exact request payload hash.',
    ],
    next_step_snippet: 'node scripts/ops/hashcash-solve.mjs --challenge "$CHALLENGE" --difficulty "$DIFFICULTY"',
  },
  UNAUTHORIZED: {
    title: 'API Key Unauthorized',
    plain_language: 'The provided API key did not verify against the configured hash.',
    likely_root_cause: 'Wrong key, key formatting issues, or stale client credential rotation state.',
    remediation_steps: [
      'Confirm the API key value and header format (`X-API-Key` or Bearer token).',
      'Rotate/re-issue client key if needed and update caller configuration.',
      'Retry after confirming key hash alignment in the target environment.',
    ],
    next_step_snippet: 'curl -H "Authorization: Bearer $VAAS_API_KEY" https://api.clawverify.com/v1/verify',
  },
  VERIFIER_UNAVAILABLE: {
    title: 'Verifier Backend Unavailable',
    plain_language: 'clawsig-ledger could not complete verification because upstream verifier was unavailable.',
    likely_root_cause: 'Network outage, upstream 5xx, or transient service interruption.',
    remediation_steps: [
      'Retry after a short backoff window.',
      'Check verifier service health and incident status.',
      'If persistent, route traffic to fallback environment or open incident escalation.',
    ],
    next_step_snippet: 'curl -sS https://clawverify.com/health | jq .',
  },
  VERIFIER_MALFORMED_RESPONSE: {
    title: 'Verifier Response Malformed',
    plain_language: 'Upstream verifier replied with an unexpected response contract.',
    likely_root_cause: 'Version skew between services or upstream regression in response schema.',
    remediation_steps: [
      'Inspect verifier response payload for missing/renamed fields.',
      'Confirm service versions and contract compatibility between ledger and verifier.',
      'Roll forward/backward to a known compatible pair and retry.',
    ],
    next_step_snippet: 'curl -sS https://clawverify.com/v1/verify/bundle -H "content-type: application/json" -d @payload.json | jq .',
  },
  VERIFICATION_FAILED: {
    title: 'Verification Failed',
    plain_language: 'The bundle did not meet verification requirements.',
    likely_root_cause: 'Signature, binding, or policy checks failed but no narrower reason was propagated.',
    remediation_steps: [
      'Review associated run diagnostics and bundle content in detail.',
      'Re-run verification locally with debug output for component-level failures.',
      'Fix failing evidence components and submit a clean bundle.',
    ],
    next_step_snippet: 'npx clawverify verify --bundle ./proof_bundle.json --verbose',
  },
};

export function getReasonCodeExplanation(
  reasonCode: string | null | undefined
): ReasonCodeExplanation | null {
  if (!reasonCode) return null;

  const normalized = reasonCode.trim().toUpperCase();
  if (!normalized) return null;

  const hit = EXPLANATIONS[normalized];
  if (!hit) return null;

  return {
    reason_code: normalized,
    ...hit,
  };
}
