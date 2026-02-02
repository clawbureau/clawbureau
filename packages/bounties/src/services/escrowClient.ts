import {
  EscrowService,
  EscrowHoldRequest,
  EscrowHoldResponse,
  EscrowHoldResponseSchema,
  EscrowFreezeRequest,
  EscrowFreezeResponse,
  EscrowFreezeResponseSchema,
} from "../types/escrow.js";

/**
 * Configuration for the escrow client
 */
export interface EscrowClientConfig {
  baseUrl: string;
  timeout?: number;
}

/**
 * HTTP client for clawescrow service
 *
 * Implements the EscrowService interface for creating escrow holds
 */
export class EscrowClient implements EscrowService {
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(config: EscrowClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.timeout = config.timeout ?? 30000;
  }

  async createHold(request: EscrowHoldRequest): Promise<EscrowHoldResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/escrow/hold`, {
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
          escrow_id: "",
          status: "failed",
          amount_held: 0,
          currency: request.currency,
          created_at: new Date().toISOString(),
          error: `HTTP ${response.status}: ${errorBody}`,
        };
      }

      const data = await response.json();
      const parsed = EscrowHoldResponseSchema.safeParse(data);

      if (!parsed.success) {
        return {
          escrow_id: "",
          status: "failed",
          amount_held: 0,
          currency: request.currency,
          created_at: new Date().toISOString(),
          error: `Invalid response from escrow service: ${parsed.error.message}`,
        };
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);

      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      return {
        escrow_id: "",
        status: "failed",
        amount_held: 0,
        currency: request.currency,
        created_at: new Date().toISOString(),
        error: `Escrow service error: ${errorMessage}`,
      };
    }
  }

  async freezeHold(request: EscrowFreezeRequest): Promise<EscrowFreezeResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/escrow/freeze`, {
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
          escrow_id: request.escrow_id,
          dispute_id: request.dispute_id,
          frozen: false,
          frozen_at: new Date().toISOString(),
          error: `HTTP ${response.status}: ${errorBody}`,
        };
      }

      const data = await response.json();
      const parsed = EscrowFreezeResponseSchema.safeParse(data);

      if (!parsed.success) {
        return {
          escrow_id: request.escrow_id,
          dispute_id: request.dispute_id,
          frozen: false,
          frozen_at: new Date().toISOString(),
          error: `Invalid response from escrow service: ${parsed.error.message}`,
        };
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);

      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      return {
        escrow_id: request.escrow_id,
        dispute_id: request.dispute_id,
        frozen: false,
        frozen_at: new Date().toISOString(),
        error: `Escrow service error: ${errorMessage}`,
      };
    }
  }
}

/**
 * Create an escrow client with the given configuration
 */
export function createEscrowClient(config: EscrowClientConfig): EscrowService {
  return new EscrowClient(config);
}
