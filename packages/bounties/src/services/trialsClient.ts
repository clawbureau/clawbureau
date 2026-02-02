import {
  TrialsService,
  CreateTrialCaseRequest,
  CreateTrialCaseResponse,
  CreateTrialCaseResponseSchema,
  TrialCaseInfo,
  TrialCaseInfoSchema,
} from "../types/dispute.js";

/**
 * Configuration for the trials client
 */
export interface TrialsClientConfig {
  baseUrl: string;
  timeout?: number;
}

/**
 * HTTP client for clawtrial service
 *
 * Implements the TrialsService interface for routing disputes to trials
 */
export class TrialsClient implements TrialsService {
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(config: TrialsClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.timeout = config.timeout ?? 30000;
  }

  async createCase(request: CreateTrialCaseRequest): Promise<CreateTrialCaseResponse> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/trials/cases`, {
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
        throw new Error(`HTTP ${response.status}: ${errorBody}`);
      }

      const data = await response.json();
      const parsed = CreateTrialCaseResponseSchema.safeParse(data);

      if (!parsed.success) {
        throw new Error(`Invalid response from trials service: ${parsed.error.message}`);
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }

  async getCaseStatus(trialCaseId: string): Promise<TrialCaseInfo | null> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}/v1/trials/cases/${trialCaseId}`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
        },
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.status === 404) {
        return null;
      }

      if (!response.ok) {
        const errorBody = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorBody}`);
      }

      const data = await response.json();
      const parsed = TrialCaseInfoSchema.safeParse(data);

      if (!parsed.success) {
        throw new Error(`Invalid response from trials service: ${parsed.error.message}`);
      }

      return parsed.data;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }
}

/**
 * Create a trials client with the given configuration
 */
export function createTrialsClient(config: TrialsClientConfig): TrialsService {
  return new TrialsClient(config);
}
