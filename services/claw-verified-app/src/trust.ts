/**
 * Trusted Gateway DID Allowlist.
 *
 * Per Gemini Deep Think Problem 2 (Round 1):
 * The GitHub App maintains a hardcoded, open-source allowlist of trusted Gateway DIDs.
 * Gateway receipts from unknown DIDs = verification FAIL.
 *
 * Why: You cannot trust an agent to run its own gateway. The gateway signature is the
 * only proof that an LLM actually generated the response and consumed tokens.
 */

/**
 * Trusted gateway DIDs. Gateway receipts signed by DIDs NOT in this list
 * will cause verification to fail with UNTRUSTED_GATEWAY.
 *
 * To add a new gateway: submit a PR adding the DID here with evidence of
 * the gateway operator's identity and signing key provenance.
 */
export const TRUSTED_GATEWAY_DIDS: readonly string[] = [
  // clawproxy.com production gateway
  'did:key:z6MkjvBkt8ETnxXGBFPSGgYKb43q68BHMYGDQEBEvJcLG5wv',
  // clawproxy.com staging gateway
  'did:key:z6Mkw1Mpfejq2R76AsQo2qJoAVBMoVQBYBWXBLagzGFMEJQE',
] as const;

/**
 * Check if a gateway DID is in the trusted allowlist.
 */
export function isGatewayTrusted(did: string): boolean {
  return TRUSTED_GATEWAY_DIDS.includes(did);
}

/**
 * Proof tier numeric values for comparison.
 */
export const PROOF_TIER_VALUES: Record<string, number> = {
  unknown: 0,
  self: 1,
  gateway: 2,
  sandbox: 3,
} as const;

/**
 * Check if a proof tier meets the minimum requirement.
 */
export function meetsTierRequirement(
  actual: string,
  minimum: string,
): boolean {
  const actualVal = PROOF_TIER_VALUES[actual] ?? 0;
  const minVal = PROOF_TIER_VALUES[minimum] ?? 0;
  return actualVal >= minVal;
}
