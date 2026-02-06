/**
 * Pi (pi-coding-agent) adapter.
 *
 * Pi supports provider base URL overrides via its configuration.
 * This adapter sets the appropriate env vars so all model calls
 * are routed through clawproxy.
 *
 * Usage:
 *   CLAWPROOF_PROXY_URL=https://proxy.example.com \
 *   clawproof-wrap pi -- pi "fix the tests"
 *
 * Environment variables set by the wrapper:
 *   ANTHROPIC_BASE_URL → clawproxy URL (Pi typically uses Anthropic models)
 *   OPENAI_BASE_URL    → clawproxy URL (fallback for OpenAI models)
 */

import type { HarnessConfig } from '../types';

/** Pi harness configuration. */
export const HARNESS: HarnessConfig = {
  id: 'pi',
  version: '1.0.0',
  runtime: 'host',
};

/**
 * Environment variables to set when launching Pi
 * so that LLM calls are routed through clawproxy.
 */
export function getProxyEnv(proxyBaseUrl: string, proxyToken?: string): Record<string, string> {
  const base = proxyBaseUrl.replace(/\/$/, '');
  const env: Record<string, string> = {
    // Pi can use either Anthropic or OpenAI models — override both
    ANTHROPIC_BASE_URL: `${base}/v1/anthropic`,
    OPENAI_BASE_URL: `${base}/v1/openai`,
  };

  if (proxyToken) {
    env.ANTHROPIC_API_KEY = proxyToken;
    env.OPENAI_API_KEY = proxyToken;
  }

  return env;
}

/**
 * Parse Pi output for tool call events.
 *
 * Pi logs tool calls with the pattern:
 *   [tool] ToolName: description
 */
export function parseToolEvents(output: string): Array<{ tool: string; args?: string }> {
  const events: Array<{ tool: string; args?: string }> = [];
  const toolPattern = /\[tool\]\s+(\w+):\s*(.*)$/gm;
  let match;
  while ((match = toolPattern.exec(output)) !== null) {
    events.push({ tool: match[1], args: match[2] || undefined });
  }
  return events;
}
