/**
 * Reserve Asset Registry
 * CLD-US-010: Store reserve assets with haircuts and eligibility.
 */

import type { Env, ReserveAsset, ReserveAssetUpsertRequest, ReserveAssetUpsertResponse, ReserveAssetsListResponse, Timestamp } from './types';

function generateReserveAssetId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `ras_${timestamp}_${random}`;
}

function parseMetadata(metadataJson: string | null): Record<string, unknown> | undefined {
  if (!metadataJson) return undefined;
  try {
    const parsed = JSON.parse(metadataJson) as unknown;
    if (typeof parsed === 'object' && parsed !== null) {
      return parsed as Record<string, unknown>;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

function toBool(value: unknown): boolean {
  return value === 1 || value === true || value === '1' || value === 'true';
}

function parseReserveAssetRow(row: Record<string, unknown>): ReserveAsset {
  return {
    asset_id: row.asset_id as string,
    provider: row.provider as string,
    asset_type: row.asset_type as string,
    currency: row.currency as string,
    amount: row.amount as string,
    haircut_bps: Number(row.haircut_bps ?? 10000),
    eligible: toBool(row.eligible),
    as_of: row.as_of as Timestamp,
    created_at: row.created_at as Timestamp,
    updated_at: row.updated_at as Timestamp,
    metadata: parseMetadata((row.metadata_json as string | null) ?? null),
  };
}

export class ReserveAssetRepository {
  constructor(private db: D1Database) {}

  async upsert(input: {
    asset_id: string;
    provider: string;
    asset_type: string;
    currency: string;
    amount: string;
    haircut_bps: number;
    eligible: boolean;
    as_of: string;
    metadata_json: string | null;
  }): Promise<ReserveAsset> {
    const now = new Date().toISOString();

    await this.db
      .prepare(
        `INSERT INTO reserve_assets (
          asset_id, provider, asset_type, currency, amount,
          haircut_bps, eligible, as_of, metadata_json,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(asset_id) DO UPDATE SET
          provider=excluded.provider,
          asset_type=excluded.asset_type,
          currency=excluded.currency,
          amount=excluded.amount,
          haircut_bps=excluded.haircut_bps,
          eligible=excluded.eligible,
          as_of=excluded.as_of,
          metadata_json=excluded.metadata_json,
          updated_at=excluded.updated_at`
      )
      .bind(
        input.asset_id,
        input.provider,
        input.asset_type,
        input.currency,
        input.amount,
        input.haircut_bps,
        input.eligible ? 1 : 0,
        input.as_of,
        input.metadata_json,
        now,
        now
      )
      .run();

    const row = await this.db
      .prepare(
        `SELECT asset_id, provider, asset_type, currency, amount,
                haircut_bps, eligible, as_of, metadata_json,
                created_at, updated_at
         FROM reserve_assets
         WHERE asset_id = ?`
      )
      .bind(input.asset_id)
      .first();

    if (!row) {
      throw new Error('Failed to upsert reserve asset');
    }

    return parseReserveAssetRow(row);
  }

  async list(): Promise<ReserveAsset[]> {
    const result = await this.db
      .prepare(
        `SELECT asset_id, provider, asset_type, currency, amount,
                haircut_bps, eligible, as_of, metadata_json,
                created_at, updated_at
         FROM reserve_assets
         ORDER BY provider ASC, asset_id ASC`
      )
      .all();

    return (result.results || []).map((r) => parseReserveAssetRow(r as Record<string, unknown>));
  }
}

export class ReserveAssetService {
  private repo: ReserveAssetRepository;

  constructor(env: Env) {
    this.repo = new ReserveAssetRepository(env.DB);
  }

  async upsertAsset(req: ReserveAssetUpsertRequest): Promise<ReserveAssetUpsertResponse> {
    // Validate amount as bigint string
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const _amount = BigInt(req.amount);
    } catch {
      throw new Error('Invalid amount: must be a bigint string');
    }

    const haircut_bps = req.haircut_bps ?? 10000;
    if (!Number.isInteger(haircut_bps) || haircut_bps < 0 || haircut_bps > 10000) {
      throw new Error('Invalid haircut_bps: must be an integer between 0 and 10000');
    }

    const assetId = req.asset_id ?? generateReserveAssetId();
    const asOf = req.as_of ?? (new Date().toISOString() as Timestamp);
    const metadataJson = req.metadata ? JSON.stringify(req.metadata) : null;

    const asset = await this.repo.upsert({
      asset_id: assetId,
      provider: req.provider,
      asset_type: req.asset_type,
      currency: req.currency,
      amount: req.amount,
      haircut_bps,
      eligible: req.eligible ?? true,
      as_of: asOf,
      metadata_json: metadataJson,
    });

    return { asset };
  }

  async listAssets(): Promise<ReserveAssetsListResponse> {
    const assets = await this.repo.list();
    return { assets, total: assets.length };
  }
}
