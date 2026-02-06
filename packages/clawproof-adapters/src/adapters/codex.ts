/**
 * Codex (OpenAI) adapter.
 *
 * Codex CLI uses the OpenAI SDK which supports OPENAI_BASE_URL
 * for API routing. This adapter points that to clawproxy so all
 * model calls are proxied and receipted.
 *
 * Usage:
 *   CLAWPROOF_PROXY_URL=https://proxy.example.com \
 *   clawproof-wrap codex -- codex "implement the feature"
 *
 * Environment variables set by the wrapper:
 *   OPENAI_BASE_URL → clawproxy URL (routes OpenAI calls through proxy)
 */

import type { HarnessConfig } from '../types';

/** Codex harness configuration. */
export const HARNESS: HarnessConfig = {
  id: 'codex',
  version: '1.0.0',
  runtime: 'host',
};

/**
 * Environment variables to set when launching Codex
 * so that LLM calls are routed through clawproxy.
 */
export function getProxyEnv(proxyBaseUrl: string, proxyToken?: string): Record<string, string> {
  const env: Record<string, string> = {
    // Codex uses the OpenAI SDK which respects OPENAI_BASE_URL
    OPENAI_BASE_URL: `${proxyBaseUrl.replace(/\/$/, '')}/v1/openai`,
  };

  if (proxyToken) {
    env.OPENAI_API_KEY = proxyToken;
  }

  return env;
}

/**
 * Parse Codex output for tool call events.
 *
 * Codex emits structured JSON output when run in non-interactive mode
 * with --json flag. Each tool call is a JSON object with type and args.
 */
export function parseToolEvents(output: string): Array<{ tool: string; args?: string }> {
  const events: Array<{ tool: string; args?: string }> = [];
  // Codex JSON output includes tool_call entries
  const lines = output.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>;
      if (obj.type === 'tool_call' && typeof obj.name === 'string') {
        events.push({
          tool: obj.name,
          args: obj.arguments ? JSON.stringify(obj.arguments) : undefined,
        });
      }
    } catch {
      // Not valid JSON — skip
    }
  }
  return events;
}
