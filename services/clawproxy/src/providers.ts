/**
 * LLM Provider configurations and routing
 */

import type { Provider, ProviderConfig } from './types';

/**
 * Known provider endpoint configurations
 * Only these providers/endpoints are allowed (SSRF prevention)
 */
export const PROVIDERS: Record<Provider, ProviderConfig> = {
  anthropic: {
    baseUrl: 'https://api.anthropic.com/v1/messages',
    authHeader: 'x-api-key',
    contentType: 'application/json',
  },
  openai: {
    baseUrl: 'https://api.openai.com/v1/chat/completions',
    authHeader: 'Authorization',
    contentType: 'application/json',
  },
};

/**
 * Check if a provider is supported
 */
export function isValidProvider(provider: string): provider is Provider {
  return provider in PROVIDERS;
}

/**
 * Get provider config or throw
 */
export function getProviderConfig(provider: string): ProviderConfig {
  if (!isValidProvider(provider)) {
    throw new Error(`Unknown provider: ${provider}`);
  }
  return PROVIDERS[provider];
}

/**
 * Build the Authorization/API key header for a provider
 */
export function buildAuthHeader(
  provider: Provider,
  apiKey: string
): Record<string, string> {
  const config = PROVIDERS[provider];

  if (provider === 'openai') {
    // OpenAI uses Bearer token format
    return { [config.authHeader]: `Bearer ${apiKey}` };
  }

  // Anthropic and others use direct API key
  return { [config.authHeader]: apiKey };
}

/**
 * Extract model from request body based on provider
 */
export function extractModel(provider: Provider, body: unknown): string | undefined {
  if (typeof body !== 'object' || body === null) {
    return undefined;
  }

  const obj = body as Record<string, unknown>;
  return typeof obj['model'] === 'string' ? obj['model'] : undefined;
}
