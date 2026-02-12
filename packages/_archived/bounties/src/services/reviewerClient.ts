import {
  ReviewerService,
  SelectReviewersRequest,
  SelectReviewersResponse,
  SelectReviewersResponseSchema,
  ReviewerInfo,
  ReviewerInfoSchema,
} from "../types/quorum.js";

/**
 * Configuration for the reviewer client
 */
export interface ReviewerClientConfig {
  baseUrl: string;
  timeout?: number;
}

/**
 * Error thrown when reviewer service fails
 */
export class ReviewerClientError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "ReviewerClientError";
  }
}

/**
 * HTTP client for clawrep reviewer service
 *
 * Implements the ReviewerService interface for selecting reviewers by reputation
 */
export class ReviewerClient implements ReviewerService {
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(config: ReviewerClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.timeout = config.timeout ?? 30000;
  }

  async selectReviewers(
    request: SelectReviewersRequest
  ): Promise<SelectReviewersResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/reviewers/select`, {
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
        throw new ReviewerClientError(
          `HTTP ${response.status}: ${errorBody}`,
          "HTTP_ERROR",
          { status: response.status, body: errorBody }
        );
      }

      const data = await response.json();
      const parsed = SelectReviewersResponseSchema.safeParse(data);

      if (!parsed.success) {
        throw new ReviewerClientError(
          `Invalid response from reviewer service: ${parsed.error.message}`,
          "PARSE_ERROR",
          { errors: parsed.error.issues }
        );
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof ReviewerClientError) {
        throw error;
      }

      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      throw new ReviewerClientError(
        `Reviewer service error: ${errorMessage}`,
        "SERVICE_ERROR",
        { originalError: errorMessage }
      );
    }
  }

  async getReviewerInfo(reviewerDid: string): Promise<ReviewerInfo | null> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(
        `${this.baseUrl}/v1/reviewers/${encodeURIComponent(reviewerDid)}`,
        {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
          },
          signal: controller.signal,
        }
      );

      clearTimeout(timeoutId);

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        const errorBody = await response.text();
        throw new ReviewerClientError(
          `HTTP ${response.status}: ${errorBody}`,
          "HTTP_ERROR",
          { status: response.status, body: errorBody }
        );
      }

      const data = await response.json();
      const parsed = ReviewerInfoSchema.safeParse(data);

      if (!parsed.success) {
        throw new ReviewerClientError(
          `Invalid response from reviewer service: ${parsed.error.message}`,
          "PARSE_ERROR",
          { errors: parsed.error.issues }
        );
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error instanceof ReviewerClientError) {
        throw error;
      }

      const errorMessage =
        error instanceof Error ? error.message : "Unknown error";

      throw new ReviewerClientError(
        `Reviewer service error: ${errorMessage}`,
        "SERVICE_ERROR",
        { originalError: errorMessage }
      );
    }
  }
}

/**
 * Create a reviewer client with the given configuration
 */
export function createReviewerClient(
  config: ReviewerClientConfig
): ReviewerService {
  return new ReviewerClient(config);
}
