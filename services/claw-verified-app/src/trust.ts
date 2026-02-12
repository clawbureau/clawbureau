/**
 * Gateway Allowlist — Trusted Gateway DIDs
 *
 * Per Gemini Deep Think Decision (Problem 2):
 * The GitHub App maintains a hardcoded, open-source allowlist of trusted
 * Gateway DIDs. Gateway receipts from unknown DIDs = verification FAIL.
 *
 * The gateway signature is the only proof that an LLM actually generated
 * the response. We cannot trust an agent to run its own gateway.
 *
 * Update this list when clawproxy.com rotates its signing key or when
 * additional trusted gateways are onboarded.
 */

/**
 * Trusted Gateway DIDs that may sign gateway receipts.
 *
 * Currently: clawproxy.com production gateway.
 * These DIDs correspond to the Ed25519 keys used by clawproxy to sign
 * gateway_receipt envelopes.
 *
 * To add a gateway:
 * 1. Verify the gateway operator's identity and security posture
 * 2. Obtain their Ed25519 public key as did:key
 * 3. Add to this array
 * 4. PR + review + merge (the allowlist IS the trust anchor)
 */
export const TRUSTED_GATEWAY_DIDS: string[] = [
  // clawproxy.com production signing key
  // TODO: Replace with actual production DID once clawproxy receipt signing is configured
  // 'did:key:z6Mk...',
];

/**
 * Check whether a DID is in the trusted gateway allowlist.
 */
export function isGatewayTrusted(did: string): boolean {
  return TRUSTED_GATEWAY_DIDS.includes(did);
}

/**
 * Trusted attester DIDs for execution attestations (sandbox tier).
 * Currently empty — will be populated when clawea sandbox fleet ships.
 */
export const TRUSTED_ATTESTER_DIDS: string[] = [];
