import {
  EligibilityService,
  EligibilityCheckRequest,
  EligibilityCheckResponse,
  EligibilityCheckResponseSchema,
} from "../types/eligibility.js";

/**
 * Configuration for the eligibility client
 */
export interface EligibilityClientConfig {
  baseUrl: string;
  timeout?: number;
}

/**
 * Error thrown when eligibility check fails
 */
export class EligibilityClientError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "EligibilityClientError";
  }
}

/**
 * HTTP client for clawtrust eligibility service
 *
 * Implements the EligibilityService interface for checking PoH tier eligibility
 */
export class EligibilityClient implements EligibilityService {
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(config: EligibilityClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.timeout = config.timeout ?? 30000;
  }

  async checkEligibility(
    request: EligibilityCheckRequest
  ): Promise<EligibilityCheckResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/eligibility/check`, {
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
        throw new EligibilityClientError(
          `HTTP ${response.status}: ${errorBody}`,
          "HTTP_ERROR",
          { status: response.status, body: errorBody }
        );
      }

      const data = await response.json();
      const parsed = EligibilityCheckResponseSchema.safeParse(data);

      if (!parsed.success) {
        throw new EligibilityClientError(
          `Invalid response from eligibility service: ${parsed.error.message}`,
          "PARSE_ERROR",
          { errors: parsed.error.issues }
        );
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof EligibilityClientError) {
        throw error;
      }

      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      throw new EligibilityClientError(
        `Eligibility service error: ${errorMessage}`,
        "SERVICE_ERROR",
        { originalError: errorMessage }
      );
    }
  }
}

/**
 * Create an eligibility client with the given configuration
 */
export function createEligibilityClient(
  config: EligibilityClientConfig
): EligibilityService {
  return new EligibilityClient(config);
}
