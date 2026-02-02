/**
 * Compute reserve assets
 * CLD-US-011: Record Gemini/FAL credit balances as reserve assets with conservative haircuts.
 *
 * This is intentionally simple/deterministic: balances are supplied by an operator/system caller
 * and stored into the reserve asset registry using stable asset IDs.
 */

import type { Env, ReserveAsset, Timestamp } from './types';
import { ReserveAssetService } from './reserve-assets';

export interface ComputeReservesUpsertRequest {
  /** Gemini credit balance (bigint string, same unit as ledger credits) */
  gemini_amount: string;
  /** FAL credit balance (bigint string, same unit as ledger credits) */
  fal_amount: string;
  /** Optional as-of timestamp (ISO string). Defaults to now. */
  as_of?: Timestamp;
}

export interface ComputeReservesUpsertResponse {
  assets: ReserveAsset[];
}

const COMPUTE_ASSET_TYPE = 'compute_credits';
const COMPUTE_CURRENCY = 'USD';

const DEFAULT_HAIRCUT_BPS_BY_PROVIDER: Record<string, number> = {
  // Conservative by default: these are not cash, they are provider credits.
  // Values represent the *eligible* portion after haircut.
  gemini: 7000, // 30% haircut
  fal: 6000, // 40% haircut
};

function stableAssetId(provider: 'gemini' | 'fal'): string {
  return `ras_compute_${provider}_${COMPUTE_CURRENCY.toLowerCase()}`;
}

function parseBigintString(value: string, field: string): bigint {
  try {
    return BigInt(value);
  } catch {
    throw new Error(`Invalid ${field}: must be a bigint string`);
  }
}

export class ComputeReserveService {
  private reserveAssets: ReserveAssetService;

  constructor(private env: Env) {
    this.reserveAssets = new ReserveAssetService(env);
  }

  async upsertComputeReserves(
    req: ComputeReservesUpsertRequest
  ): Promise<ComputeReservesUpsertResponse> {
    // Validate amounts
    const geminiAmount = parseBigintString(req.gemini_amount, 'gemini_amount');
    const falAmount = parseBigintString(req.fal_amount, 'fal_amount');

    // Fail closed on negative amounts
    if (geminiAmount < 0n) {
      throw new Error('Invalid gemini_amount: must be non-negative');
    }
    if (falAmount < 0n) {
      throw new Error('Invalid fal_amount: must be non-negative');
    }

    const asOf = req.as_of ?? (new Date().toISOString() as Timestamp);

    const assets: ReserveAsset[] = [];

    // Gemini
    assets.push(
      (
        await this.reserveAssets.upsertAsset({
          asset_id: stableAssetId('gemini'),
          provider: 'gemini',
          asset_type: COMPUTE_ASSET_TYPE,
          currency: COMPUTE_CURRENCY,
          amount: req.gemini_amount,
          haircut_bps: DEFAULT_HAIRCUT_BPS_BY_PROVIDER.gemini,
          eligible: true,
          as_of: asOf,
          metadata: {
            category: 'compute_reserve',
            provider: 'gemini',
            note: 'Operator-reported compute credit balance (subject to haircut)',
          },
        })
      ).asset
    );

    // FAL
    assets.push(
      (
        await this.reserveAssets.upsertAsset({
          asset_id: stableAssetId('fal'),
          provider: 'fal',
          asset_type: COMPUTE_ASSET_TYPE,
          currency: COMPUTE_CURRENCY,
          amount: req.fal_amount,
          haircut_bps: DEFAULT_HAIRCUT_BPS_BY_PROVIDER.fal,
          eligible: true,
          as_of: asOf,
          metadata: {
            category: 'compute_reserve',
            provider: 'fal',
            note: 'Operator-reported compute credit balance (subject to haircut)',
          },
        })
      ).asset
    );

    return { assets };
  }
}
