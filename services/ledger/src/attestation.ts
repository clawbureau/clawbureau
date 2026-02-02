/**
 * Reserve attestation for ClawLedger
 * Computes reserve coverage reports and generates signed attestations
 */

import type {
  Env,
  ReserveAttestation,
  ReserveAttestationResponse,
  ReserveAssetBreakdown,
  Timestamp,
} from './types';

/**
 * Generate a unique attestation ID
 */
function generateAttestationId(): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 10);
  return `att_${timestamp}_${random}`;
}

/**
 * Compute SHA-256 hash of data
 */
async function computeHash(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

function formatRatio(numerator: bigint, denominator: bigint, decimals = 4): string {
  if (denominator === 0n) {
    return numerator === 0n ? '1.0' : 'Infinity';
  }

  const scale = 10n ** BigInt(decimals);
  const scaled = (numerator * scale) / denominator;
  const s = scaled.toString();

  if (decimals === 0) return s;
  if (s.length <= decimals) {
    return `0.${s.padStart(decimals, '0')}`;
  }

  return `${s.slice(0, -decimals)}.${s.slice(-decimals)}`;
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

/**
 * Account balance summary for attestation calculation
 */
interface AccountBalanceSummary {
  accountId: string;
  available: bigint;
  held: bigint;
  bonded: bigint;
  feePool: bigint;
  promo: bigint;
  total: bigint;
}

interface ReserveAssetRow {
  asset_id: string;
  provider: string;
  asset_type: string;
  currency: string;
  amount: bigint;
  haircut_bps: number;
  eligible: boolean;
  as_of: Timestamp;
  created_at: Timestamp;
  updated_at: Timestamp;
  metadata?: Record<string, unknown>;
}

/**
 * Repository for reserve attestation data queries
 */
class AttestationRepository {
  constructor(private db: D1Database) {}

  /**
   * Get all account balances for reserve calculation
   */
  async getAllAccountBalances(): Promise<AccountBalanceSummary[]> {
    const results = await this.db
      .prepare(
        `SELECT id, balance_available, balance_held, balance_bonded,
                balance_fee_pool, balance_promo
         FROM accounts
         ORDER BY id`
      )
      .all();

    return (results.results || []).map((row) => {
      const available = BigInt((row.balance_available as string) || '0');
      const held = BigInt((row.balance_held as string) || '0');
      const bonded = BigInt((row.balance_bonded as string) || '0');
      const feePool = BigInt((row.balance_fee_pool as string) || '0');
      const promo = BigInt((row.balance_promo as string) || '0');

      return {
        accountId: row.id as string,
        available,
        held,
        bonded,
        feePool,
        promo,
        total: available + held + bonded + feePool + promo,
      };
    });
  }

  /**
   * Get reserve assets from the registry
   */
  async getReserveAssets(): Promise<ReserveAssetRow[]> {
    const result = await this.db
      .prepare(
        `SELECT asset_id, provider, asset_type, currency, amount,
                haircut_bps, eligible, as_of, metadata_json,
                created_at, updated_at
         FROM reserve_assets
         ORDER BY provider ASC, asset_id ASC`
      )
      .all();

    return (result.results || []).map((row) => {
      const r = row as Record<string, unknown>;
      return {
        asset_id: r.asset_id as string,
        provider: r.provider as string,
        asset_type: r.asset_type as string,
        currency: r.currency as string,
        amount: BigInt((r.amount as string) || '0'),
        haircut_bps: Number(r.haircut_bps ?? 10000),
        eligible: (r.eligible as number) === 1,
        as_of: r.as_of as Timestamp,
        created_at: r.created_at as Timestamp,
        updated_at: r.updated_at as Timestamp,
        metadata: parseMetadata((r.metadata_json as string | null) ?? null),
      };
    });
  }

  /**
   * Get the latest event hash
   */
  async getLatestEventHash(): Promise<string> {
    const result = await this.db
      .prepare(
        `SELECT event_hash FROM events ORDER BY created_at DESC, id DESC LIMIT 1`
      )
      .first();

    if (!result) {
      return '0'.repeat(64); // Genesis hash
    }

    return result.event_hash as string;
  }
}

/**
 * Service for computing reserve attestations
 */
export class ReserveAttestationService {
  private repository: AttestationRepository;

  constructor(private env: Env) {
    this.repository = new AttestationRepository(env.DB);
  }

  /**
   * Generate a signed reserve attestation
   * Computes total outstanding liabilities, reserve coverage, and signs the attestation
   */
  async generateAttestation(): Promise<ReserveAttestationResponse> {
    const now = new Date().toISOString() as Timestamp;
    const attestationId = generateAttestationId();

    // Get all account balances
    const accounts = await this.repository.getAllAccountBalances();

    // Compute totals by bucket
    const totals = {
      available: 0n,
      held: 0n,
      bonded: 0n,
      feePool: 0n,
      promo: 0n,
    };

    for (const account of accounts) {
      totals.available += account.available;
      totals.held += account.held;
      totals.bonded += account.bonded;
      totals.feePool += account.feePool;
      totals.promo += account.promo;
    }

    const totalOutstanding =
      totals.available + totals.held + totals.bonded + totals.feePool + totals.promo;

    // Reserves are computed from the reserve asset registry (eligible assets only, after haircuts)
    const reserveAssets = await this.repository.getReserveAssets();

    let totalReservesReported = 0n;
    let totalReservesEligibleGross = 0n;
    let totalReservesEligible = 0n;

    const reserveBreakdown: ReserveAssetBreakdown[] = reserveAssets.map((a) => {
      totalReservesReported += a.amount;

      let eligibleAmount = 0n;
      if (a.eligible) {
        totalReservesEligibleGross += a.amount;
        eligibleAmount = (a.amount * BigInt(a.haircut_bps)) / 10000n;
        totalReservesEligible += eligibleAmount;
      }

      return {
        asset_id: a.asset_id,
        provider: a.provider,
        asset_type: a.asset_type,
        currency: a.currency,
        amount: a.amount.toString(),
        haircut_bps: a.haircut_bps,
        eligible: a.eligible,
        as_of: a.as_of,
        created_at: a.created_at,
        updated_at: a.updated_at,
        metadata: a.metadata,
        eligible_amount: eligibleAmount.toString(),
      };
    });

    // Hash reserve assets for signing
    const reserveAssetData = reserveBreakdown
      .map(
        (a) =>
          `${a.asset_id}:${a.provider}:${a.asset_type}:${a.currency}:${a.amount}:${a.haircut_bps}:${a.eligible ? 1 : 0}:${a.as_of}`
      )
      .join('|');
    const reserveAssetsHash = await computeHash(reserveAssetData);

    // Compute coverage ratio using eligible reserves only (after haircut)
    const coverageRatio = formatRatio(totalReservesEligible, totalOutstanding, 4);
    const isFullyBacked = totalReservesEligible >= totalOutstanding;

    // Compute hash of all account balances for verification
    const balanceData = accounts
      .map(
        (a) =>
          `${a.accountId}:${a.available}:${a.held}:${a.bonded}:${a.feePool}:${a.promo}`
      )
      .join('|');
    const balanceHash = await computeHash(balanceData);

    // Get latest event hash
    const latestEventHash = await this.repository.getLatestEventHash();

    // Create attestation data for signing
    const attestationData = [
      attestationId,
      now,
      totalOutstanding.toString(),
      totalReservesEligible.toString(),
      totalReservesReported.toString(),
      totalReservesEligibleGross.toString(),
      reserveAssetsHash,
      coverageRatio,
      accounts.length.toString(),
      balanceHash,
      latestEventHash,
    ].join('|');

    // Sign the attestation (in production, use a proper signing key)
    // For now, we use a deterministic hash-based signature
    const signature = await computeHash(`sign:${attestationData}`);

    const attestation: ReserveAttestation = {
      id: attestationId,
      timestamp: now,
      totalOutstanding: totalOutstanding.toString(),
      outstandingByBucket: {
        available: totals.available.toString(),
        held: totals.held.toString(),
        bonded: totals.bonded.toString(),
        feePool: totals.feePool.toString(),
        promo: totals.promo.toString(),
      },
      totalReserves: totalReservesEligible.toString(),
      totalReservesReported: totalReservesReported.toString(),
      totalReservesEligibleGross: totalReservesEligibleGross.toString(),
      reserveAssetsHash,
      reserveAssets: reserveBreakdown,
      coverageRatio,
      isFullyBacked,
      accountCount: accounts.length,
      balanceHash,
      signature,
      version: '1.1.0',
    };

    // Create human-readable summary
    const summary = this.formatSummary(attestation);

    return {
      attestation,
      latestEventHash,
      summary,
    };
  }

  /**
   * Format a human-readable summary of the attestation
   */
  private formatSummary(attestation: ReserveAttestation): string {
    const status = attestation.isFullyBacked
      ? 'FULLY BACKED'
      : 'UNDERCOLLATERALIZED';
    return (
      `Reserve Attestation ${attestation.id}\n` +
      `Generated: ${attestation.timestamp}\n` +
      `Status: ${status}\n` +
      `Coverage Ratio: ${attestation.coverageRatio}\n` +
      `Total Outstanding: ${attestation.totalOutstanding}\n` +
      `Eligible Reserves (after haircut): ${attestation.totalReserves}\n` +
      `Reported Reserves (gross): ${attestation.totalReservesReported}\n` +
      `Reserve Assets: ${attestation.reserveAssets.length}\n` +
      `Accounts: ${attestation.accountCount}`
    );
  }

  /**
   * Verify an attestation signature
   */
  async verifyAttestation(
    attestation: ReserveAttestation,
    latestEventHash: string
  ): Promise<boolean> {
    const attestationData = [
      attestation.id,
      attestation.timestamp,
      attestation.totalOutstanding,
      attestation.totalReserves,
      attestation.totalReservesReported,
      attestation.totalReservesEligibleGross,
      attestation.reserveAssetsHash,
      attestation.coverageRatio,
      attestation.accountCount.toString(),
      attestation.balanceHash,
      latestEventHash,
    ].join('|');

    const expectedSignature = await computeHash(`sign:${attestationData}`);
    return attestation.signature === expectedSignature;
  }
}
