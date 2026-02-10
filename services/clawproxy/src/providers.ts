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
    // Base URL for OpenAI APIs. The final path is selected by buildProviderUrl().
    baseUrl: 'https://api.openai.com/v1',
    authHeader: 'Authorization',
    contentType: 'application/json',
  },
  google: {
    // Gemini API via OpenAI compatibility endpoints.
    // Base URL format: https://generativelanguage.googleapis.com/v1beta/openai/{endpoint}
    // Example: POST https://generativelanguage.googleapis.com/v1beta/openai/chat/completions
    //
    // This matches the request shape used by OpenAI SDKs ({ model, messages, ... }) and
    // avoids format translation in the gateway.
    baseUrl: 'https://generativelanguage.googleapis.com/v1beta/openai',
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
 * Get list of supported provider names
 */
export function getSupportedProviders(): string[] {
  return Object.keys(PROVIDERS);
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

  // Providers that expect Bearer tokens in Authorization.
  if (provider === 'openai' || provider === 'google') {
    return { [config.authHeader]: `Bearer ${apiKey}` };
  }

  // Anthropic and other direct-key providers.
  return { [config.authHeader]: apiKey };
}

/**
 * OpenAI upstream API selection.
 *
 * - chat_completions → POST /v1/chat/completions
 * - responses → POST /v1/responses
 */
export type OpenAIUpstreamApi = 'chat_completions' | 'responses';

/**
 * Build the full provider URL.
 *
 * Most providers use a static URL, but:
 * - Google Gemini requires the model in the path
 * - OpenAI has multiple top-level endpoints (chat completions vs responses)
 */
export function buildProviderUrl(
  provider: Provider,
  model?: string,
  opts?: { openaiApi?: OpenAIUpstreamApi }
): string {
  const config = PROVIDERS[provider];

  if (provider === 'google') {
    // Model is still required for receipts + policy enforcement, even though the OpenAI
    // compatibility endpoint does not include the model in the URL.
    if (!model) {
      throw new Error('Model is required for Google Gemini API');
    }

    const api = opts?.openaiApi ?? 'chat_completions';
    if (api === 'responses') {
      return `${config.baseUrl}/responses`;
    }
    return `${config.baseUrl}/chat/completions`;
  }

  if (provider === 'openai') {
    const api = opts?.openaiApi ?? 'chat_completions';
    if (api === 'responses') {
      return `${config.baseUrl}/responses`;
    }
    return `${config.baseUrl}/chat/completions`;
  }

  return config.baseUrl;
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

// ---------------------------------------------------------------------------
// fal OpenRouter upstream (OpenAI-compatible)
// ---------------------------------------------------------------------------

/**
 * fal OpenRouter router (OpenAI-compatible) upstream.
 *
 * Upstream auth: `Authorization: Key <FAL_KEY>` (NOT Bearer).
 */
export const FAL_OPENROUTER_BASE_URL = 'https://fal.run/openrouter/router/openai/v1';

/**
 * Routing selector: treat `model=openrouter/...` as a signal to route OpenAI requests
 * to fal's OpenRouter router instead of api.openai.com.
 */
export function isFalOpenrouterModel(model: string | undefined): boolean {
  return typeof model === 'string' && model.trim().toLowerCase().startsWith('openrouter/');
}

/**
 * OpenRouter model IDs in OpenClaw are typically encoded as:
 *   openrouter/<upstream-provider>/<model>
 *
 * The OpenRouter upstream expects the model WITHOUT the leading `openrouter/` prefix.
 */
export function stripOpenrouterModelPrefix(model: string): string {
  const trimmed = model.trim();
  if (!trimmed) return trimmed;

  const m = trimmed.match(/^openrouter\//i);
  return m ? trimmed.slice(m[0].length).trim() : trimmed;
}

export function buildFalOpenrouterUrl(opts?: { openaiApi?: OpenAIUpstreamApi }): string {
  const api = opts?.openaiApi ?? 'chat_completions';
  if (api === 'responses') return `${FAL_OPENROUTER_BASE_URL}/responses`;
  return `${FAL_OPENROUTER_BASE_URL}/chat/completions`;
}

function stripKeyPrefix(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return trimmed;

  const m = trimmed.match(/^Key\s+/i);
  return m ? trimmed.slice(m[0].length).trim() : trimmed;
}

/**
 * Build the upstream authorization header for fal OpenRouter router.
 *
 * Accepts either a raw key (`fal_...`) or a pre-prefixed value (`Key fal_...`).
 */
export function buildFalOpenrouterAuthHeader(apiKey: string): Record<string, string> {
  const key = stripKeyPrefix(apiKey);
  return { Authorization: `Key ${key}` };
}
