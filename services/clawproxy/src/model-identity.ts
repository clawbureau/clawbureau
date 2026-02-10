/**
 * CPX-US-016 — Model identity (tiered) in gateway receipts.
 *
 * This module is intentionally conservative:
 * - Closed-provider API calls default to tier = closed_opaque.
 * - We avoid per-call timestamps inside model_identity so model_identity_hash_b64u is stable
 *   for the same {tier, provider, model}.
 */

import type { Provider } from './types';
import { sha256B64u } from './crypto';
import { jcsCanonicalize } from './jcs';

export type ModelIdentityTier =
  | 'closed_opaque'
  | 'closed_provider_manifest'
  | 'openweights_hashable'
  | 'tee_measured';

export interface ModelIdentityV1 {
  model_identity_version: '1';
  tier: ModelIdentityTier;
  model: {
    provider: string;
    name: string;
    family?: string;
    endpoint?: string;
    region?: string;
    deployment_id?: string;
    revision?: string;
  };
}

export function buildModelIdentityV1(input: {
  provider: Provider;
  model: string;
  tier?: ModelIdentityTier;
}): ModelIdentityV1 {
  return {
    model_identity_version: '1',
    tier: input.tier ?? 'closed_opaque',
    model: {
      provider: input.provider,
      name: input.model,
    },
  };
}

export async function computeModelIdentityHashB64u(identity: ModelIdentityV1): Promise<string> {
  return sha256B64u(jcsCanonicalize(identity));
}

/**
 * Merge the provided metadata with model identity fields.
 *
 * Writes:
 * - metadata.model_identity
 * - metadata.model_identity_hash_b64u
 */
export async function buildReceiptMetadataWithModelIdentity(input: {
  provider: Provider;
  model: string;
  existing?: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const modelIdentity = buildModelIdentityV1({ provider: input.provider, model: input.model });
  const modelIdentityHash = await computeModelIdentityHashB64u(modelIdentity);

  return {
    ...(input.existing ?? {}),
    model_identity: modelIdentity,
    model_identity_hash_b64u: modelIdentityHash,
  };
}
