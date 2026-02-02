import {
  StakeService,
  CalculateStakeRequest,
  CalculateStakeResponse,
  LockStakeRequest,
  LockStakeResponse,
  LockStakeResponseSchema,
  ReleaseStakeRequest,
  ReleaseStakeResponse,
  ReleaseStakeResponseSchema,
  SlashStakeRequest,
  SlashStakeResponse,
  SlashStakeResponseSchema,
  calculateStakeAmount,
} from "../types/stake.js";
import { EligibilityService } from "../types/eligibility.js";

/**
 * Configuration for the stake client
 */
export interface StakeClientConfig {
  /** Base URL for the ledger service */
  baseUrl: string;
  /** Request timeout in milliseconds */
  timeout?: number;
}

/**
 * HTTP client for ledger bonded bucket stake operations
 *
 * Implements the StakeService interface for locking, releasing,
 * and slashing stakes in the ledger bonded bucket.
 */
export class StakeClient implements StakeService {
  private readonly baseUrl: string;
  private readonly timeout: number;
  private eligibilityService?: EligibilityService;

  constructor(config: StakeClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.timeout = config.timeout ?? 30000;
  }

  /**
   * Set the eligibility service for trust tier lookups
   */
  setEligibilityService(service: EligibilityService): void {
    this.eligibilityService = service;
  }

  /**
   * Calculate required stake based on trust tier and bounty size
   *
   * Uses clawtrust to look up the party's trust tier, then applies
   * stake rules based on role and tier.
   */
  async calculateStake(request: CalculateStakeRequest): Promise<CalculateStakeResponse> {
    // Look up trust tier if eligibility service is available
    let trustTier = 0;
    if (this.eligibilityService) {
      try {
        const eligibility = await this.eligibilityService.checkEligibility({
          agent_did: request.did,
          required_poh_tier: 0, // Just looking up tier, not checking eligibility
        });
        trustTier = eligibility.current_poh_tier;
      } catch {
        // Default to tier 0 if lookup fails
        trustTier = 0;
      }
    }

    const { amount, percentage } = calculateStakeAmount(
      request.role,
      trustTier,
      request.bounty_amount,
      request.currency
    );

    return {
      schema_version: "1",
      requirement: {
        role: request.role,
        trust_tier: trustTier,
        bounty_amount: request.bounty_amount,
        currency: request.currency,
        stake_amount: amount,
        stake_percentage: percentage,
      },
      trust_tier: trustTier,
      calculated_at: new Date().toISOString(),
    };
  }

  /**
   * Lock stake in ledger bonded bucket
   */
  async lockStake(request: LockStakeRequest): Promise<LockStakeResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/bonded/lock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.text();
        return {
          stake_id: "",
          ledger_tx_id: "",
          status: "locked",
          amount_locked: 0,
          currency: request.currency,
          locked_at: new Date().toISOString(),
          error: `HTTP ${response.status}: ${errorBody}`,
        };
      }

      const data = await response.json();
      const parsed = LockStakeResponseSchema.safeParse(data);

      if (!parsed.success) {
        return {
          stake_id: "",
          ledger_tx_id: "",
          status: "locked",
          amount_locked: 0,
          currency: request.currency,
          locked_at: new Date().toISOString(),
          error: `Invalid response from ledger service: ${parsed.error.message}`,
        };
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);

      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      return {
        stake_id: "",
        ledger_tx_id: "",
        status: "locked",
        amount_locked: 0,
        currency: request.currency,
        locked_at: new Date().toISOString(),
        error: `Ledger service error: ${errorMessage}`,
      };
    }
  }

  /**
   * Release stake from ledger bonded bucket
   */
  async releaseStake(request: ReleaseStakeRequest): Promise<ReleaseStakeResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/bonded/release`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.text();
        return {
          stake_id: request.stake_id,
          status: "locked",
          amount_released: 0,
          amount_slashed: 0,
          currency: "CLAW",
          ledger_tx_id: "",
          released_at: new Date().toISOString(),
          error: `HTTP ${response.status}: ${errorBody}`,
        };
      }

      const data = await response.json();
      const parsed = ReleaseStakeResponseSchema.safeParse(data);

      if (!parsed.success) {
        return {
          stake_id: request.stake_id,
          status: "locked",
          amount_released: 0,
          amount_slashed: 0,
          currency: "CLAW",
          ledger_tx_id: "",
          released_at: new Date().toISOString(),
          error: `Invalid response from ledger service: ${parsed.error.message}`,
        };
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);

      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      return {
        stake_id: request.stake_id,
        status: "locked",
        amount_released: 0,
        amount_slashed: 0,
        currency: "CLAW",
        ledger_tx_id: "",
        released_at: new Date().toISOString(),
        error: `Ledger service error: ${errorMessage}`,
      };
    }
  }

  /**
   * Slash stake based on trial outcome
   */
  async slashStake(request: SlashStakeRequest): Promise<SlashStakeResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/bonded/slash`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.text();
        return {
          stake_id: request.stake_id,
          status: "locked",
          amount_slashed: 0,
          amount_released: 0,
          currency: "CLAW",
          ledger_tx_id: "",
          slashed_at: new Date().toISOString(),
          error: `HTTP ${response.status}: ${errorBody}`,
        };
      }

      const data = await response.json();
      const parsed = SlashStakeResponseSchema.safeParse(data);

      if (!parsed.success) {
        return {
          stake_id: request.stake_id,
          status: "locked",
          amount_slashed: 0,
          amount_released: 0,
          currency: "CLAW",
          ledger_tx_id: "",
          slashed_at: new Date().toISOString(),
          error: `Invalid response from ledger service: ${parsed.error.message}`,
        };
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);

      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      return {
        stake_id: request.stake_id,
        status: "locked",
        amount_slashed: 0,
        amount_released: 0,
        currency: "CLAW",
        ledger_tx_id: "",
        slashed_at: new Date().toISOString(),
        error: `Ledger service error: ${errorMessage}`,
      };
    }
  }
}

/**
 * Create a stake client with the given configuration
 */
export function createStakeClient(config: StakeClientConfig): StakeClient {
  return new StakeClient(config);
}
