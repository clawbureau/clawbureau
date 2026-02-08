/**
 * Opencode adapter.
 *
 * Opencode supports provider configuration via environment variables.
 * This adapter routes LLM calls through clawproxy by overriding
 * the provider base URLs.
 *
 * Usage:
 *   CLAWPROOF_PROXY_URL=https://proxy.example.com \
 *   clawproof-wrap opencode -- opencode "refactor the module"
 *
 * Environment variables set by the wrapper:
 *   ANTHROPIC_BASE_URL → clawproxy URL
 *   OPENAI_BASE_URL    → clawproxy URL
 */

import type { HarnessConfig } from '../types';

/** Opencode harness configuration. */
export const HARNESS: HarnessConfig = {
  id: 'opencode',
  version: '1.0.0',
  runtime: 'host',
};

/**
 * Environment variables to set when launching Opencode
 * so that LLM calls are routed through clawproxy.
 */
export function getProxyEnv(proxyBaseUrl: string, _proxyToken?: string): Record<string, string> {
  const base = proxyBaseUrl.replace(/\/$/, '');
  const env: Record<string, string> = {
    // Opencode supports multiple providers — override all known base URLs
    ANTHROPIC_BASE_URL: `${base}/v1/anthropic`,
    OPENAI_BASE_URL: `${base}/v1/openai`,
  };

  // Note: we do NOT override provider API keys here.

  return env;
}

/**
 * Parse Opencode output for tool call events.
 *
 * Opencode logs tool calls in a structured format.
 */
export function parseToolEvents(output: string): Array<{ tool: string; args?: string }> {
  const events: Array<{ tool: string; args?: string }> = [];
  // Opencode uses a line-based log format with tool names
  const toolPattern = /Tool:\s+(\w+)(?:\s+(.+))?$/gm;
  let match;
  while ((match = toolPattern.exec(output)) !== null) {
    events.push({ tool: match[1], args: match[2] || undefined });
  }
  return events;
}
