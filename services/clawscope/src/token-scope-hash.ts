import {
  buildTokenScopeHashInput,
  computeTokenScopeHashB64u as computeSharedTokenScopeHashB64u,
  normalizeAudience as normalizeSharedAudience,
  normalizeScope as normalizeSharedScope,
  type TokenScopeHashInputV1,
} from '../../../packages/identity-auth/src/index';

export type { TokenScopeHashInputV1 };

export function normalizeAud(aud: string | string[]): string[] {
  return normalizeSharedAudience(aud);
}

export function normalizeScope(scope: string[]): string[] {
  return normalizeSharedScope(scope);
}

/**
 * Deterministic token_scope_hash_b64u (v1).
 *
 * Shared implementation lives in packages/identity-auth.
 */
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
  const normalized = buildTokenScopeHashInput(input);
  return computeSharedTokenScopeHashB64u(normalized);
}
