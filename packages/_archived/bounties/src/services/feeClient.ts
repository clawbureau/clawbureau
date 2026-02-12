import {
  FeeService,
  FeeCalculationRequest,
  FeeCalculationResponse,
  FeeCalculationResponseSchema,
} from "../types/fees.js";

/**
 * Configuration for the fee client
 */
export interface FeeClientConfig {
  baseUrl: string;
  timeout?: number;
}

/**
 * Error thrown when fee calculation fails
 */
export class FeeCalculationError extends Error {
  constructor(
    message: string,
    public readonly code: string
  ) {
    super(message);
    this.name = "FeeCalculationError";
  }
}

/**
 * HTTP client for clawcuts fee service
 *
 * Implements the FeeService interface for calculating fees
 */
export class FeeClient implements FeeService {
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(config: FeeClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.timeout = config.timeout ?? 30000;
  }

  async calculateFees(
    request: FeeCalculationRequest
  ): Promise<FeeCalculationResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/fees/calculate`, {
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
        throw new FeeCalculationError(
          `HTTP ${response.status}: ${errorBody}`,
          "HTTP_ERROR"
        );
      }

      const data = await response.json();
      const parsed = FeeCalculationResponseSchema.safeParse(data);

      if (!parsed.success) {
        throw new FeeCalculationError(
          `Invalid response from fee service: ${parsed.error.message}`,
          "PARSE_ERROR"
        );
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof FeeCalculationError) {
        throw error;
      }

      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";
      throw new FeeCalculationError(
        `Fee service error: ${errorMessage}`,
        "NETWORK_ERROR"
      );
    }
  }
}

/**
 * Create a fee client with the given configuration
 */
export function createFeeClient(config: FeeClientConfig): FeeService {
  return new FeeClient(config);
}
