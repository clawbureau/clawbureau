/**
 * Reserve attestation for ClawLedger
 * Computes reserve coverage reports and generates signed attestations
 */

import type {
  Env,
  ReserveAttestation,
  ReserveAttestationResponse,
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

  /**
   * Get total minted minus burned for reserve calculation
   * This represents the theoretical reserve requirement
   */
  async computeNetMinted(): Promise<bigint> {
    // Sum of all mint events
    const mintResult = await this.db
      .prepare(
        `SELECT COALESCE(SUM(CAST(amount AS INTEGER)), 0) as total
         FROM events WHERE event_type = 'mint'`
      )
      .first();
    const totalMinted = BigInt((mintResult?.total as number) || 0);

    // Sum of all burn events
    const burnResult = await this.db
      .prepare(
        `SELECT COALESCE(SUM(CAST(amount AS INTEGER)), 0) as total
         FROM events WHERE event_type = 'burn'`
      )
      .first();
    const totalBurned = BigInt((burnResult?.total as number) || 0);

    return totalMinted - totalBurned;
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

    // Get total reserves (net minted = theoretical reserve backing)
    const totalReserves = await this.repository.computeNetMinted();

    // Compute coverage ratio (handle division by zero)
    let coverageRatio: string;
    let isFullyBacked: boolean;

    if (totalOutstanding === 0n) {
      coverageRatio = totalReserves === 0n ? '1.0' : 'Infinity';
      isFullyBacked = true;
    } else {
      // Compute ratio with 4 decimal precision
      // ratio = reserves / outstanding
      const scaledRatio = (totalReserves * 10000n) / totalOutstanding;
      coverageRatio = (Number(scaledRatio) / 10000).toFixed(4);
      isFullyBacked = totalReserves >= totalOutstanding;
    }

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
      totalReserves.toString(),
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
      totalReserves: totalReserves.toString(),
      coverageRatio,
      isFullyBacked,
      accountCount: accounts.length,
      balanceHash,
      signature,
      version: '1.0.0',
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
    const status = attestation.isFullyBacked ? 'FULLY BACKED' : 'UNDERCOLLATERALIZED';
    return (
      `Reserve Attestation ${attestation.id}\n` +
      `Generated: ${attestation.timestamp}\n` +
      `Status: ${status}\n` +
      `Coverage Ratio: ${attestation.coverageRatio}\n` +
      `Total Outstanding: ${attestation.totalOutstanding}\n` +
      `Total Reserves: ${attestation.totalReserves}\n` +
      `Accounts: ${attestation.accountCount}`
    );
  }

  /**
   * Verify an attestation signature
   */
  async verifyAttestation(attestation: ReserveAttestation, latestEventHash: string): Promise<boolean> {
    // Reconstruct attestation data
    const attestationData = [
      attestation.id,
      attestation.timestamp,
      attestation.totalOutstanding,
      attestation.totalReserves,
      attestation.coverageRatio,
      attestation.accountCount.toString(),
      attestation.balanceHash,
      latestEventHash,
    ].join('|');

    // Verify signature
    const expectedSignature = await computeHash(`sign:${attestationData}`);
    return attestation.signature === expectedSignature;
  }
}
