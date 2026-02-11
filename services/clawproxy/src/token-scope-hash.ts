import { sha256B64u } from './crypto';
import { jcsCanonicalize } from './jcs';

export type TokenScopeHashInputV1 = {
  token_version: '1';
  sub: string;
  aud: string[];
  scope: string[];

  owner_ref?: string;
  policy_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
};

function normalizeStringList(values: string[]): string[] {
  const out: string[] = [];

  for (const v of values) {
    const s = v.trim();
    if (s.length === 0) continue;
    out.push(s);
  }

  // Deduplicate + stable sort
  return Array.from(new Set(out)).sort();
}

export function normalizeAud(aud: string | string[]): string[] {
  const raw = typeof aud === 'string' ? [aud] : aud;
  return normalizeStringList(raw);
}

export function normalizeScope(scope: string[]): string[] {
  return normalizeStringList(scope);
}

/**
 * Deterministic token_scope_hash_b64u (v1).
 *
 * Algorithm:
 *   token_scope_hash_b64u = sha256_b64u( JCS({
 *     token_version, sub, aud[], scope[], owner_ref?, policy_hash_b64u?, payment_account_did?, spend_cap?, mission_id?
 *   }) )
 *
 * Notes:
 * - aud and scope are normalized as sorted unique arrays.
 * - iat/exp/jti/nonce are intentionally excluded to keep the hash stable across re-issuance.
 */
export async function computeTokenScopeHashB64uV1(input: {
  sub: string;
  aud: string | string[];
  scope: string[];
  owner_ref?: string;
  policy_hash_b64u?: string;
  payment_account_did?: string;
  spend_cap?: number;
  mission_id?: string;
}): Promise<string> {
  const aud = normalizeAud(input.aud);
  const scope = normalizeScope(input.scope);

  const out: TokenScopeHashInputV1 = {
    token_version: '1',
    sub: input.sub.trim(),
    aud,
    scope,
  };

  if (typeof input.owner_ref === 'string' && input.owner_ref.trim().length > 0) {
    out.owner_ref = input.owner_ref.trim();
  }

  if (typeof input.policy_hash_b64u === 'string' && input.policy_hash_b64u.trim().length > 0) {
    out.policy_hash_b64u = input.policy_hash_b64u.trim();
  }

  if (typeof input.payment_account_did === 'string' && input.payment_account_did.trim().length > 0) {
    out.payment_account_did = input.payment_account_did.trim();
  }

  if (typeof input.spend_cap === 'number' && Number.isFinite(input.spend_cap) && input.spend_cap >= 0) {
    out.spend_cap = input.spend_cap;
  }

  if (typeof input.mission_id === 'string' && input.mission_id.trim().length > 0) {
    out.mission_id = input.mission_id.trim();
  }

  const canonical = jcsCanonicalize(out);
  return sha256B64u(canonical);
}
