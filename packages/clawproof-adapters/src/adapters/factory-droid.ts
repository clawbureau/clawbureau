/**
 * Factory Droid adapter.
 *
 * Factory Droid is a custom agent runtime. This adapter routes its
 * LLM calls through clawproxy by setting the standard provider
 * base URL environment variables.
 *
 * Usage:
 *   CLAWPROOF_PROXY_URL=https://proxy.example.com \
 *   clawproof-wrap factory-droid -- factory-droid run --task "build feature"
 *
 * Environment variables set by the wrapper:
 *   ANTHROPIC_BASE_URL → clawproxy URL
 *   OPENAI_BASE_URL    → clawproxy URL
 */

import type { HarnessConfig } from '../types';

/** Factory Droid harness configuration. */
export const HARNESS: HarnessConfig = {
  id: 'factory-droid',
  version: '1.0.0',
  runtime: 'host',
};

/**
 * Environment variables to set when launching Factory Droid
 * so that LLM calls are routed through clawproxy.
 */
export function getProxyEnv(proxyBaseUrl: string, proxyToken?: string): Record<string, string> {
  const base = proxyBaseUrl.replace(/\/$/, '');
  const env: Record<string, string> = {
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
 * Parse Factory Droid output for tool call events.
 *
 * Factory Droid emits structured logs with JSON tool-call entries.
 */
export function parseToolEvents(output: string): Array<{ tool: string; args?: string }> {
  const events: Array<{ tool: string; args?: string }> = [];
  const lines = output.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>;
      if (
        (obj.event === 'tool_call' || obj.type === 'tool_call') &&
        typeof obj.tool === 'string'
      ) {
        events.push({
          tool: obj.tool,
          args: obj.args ? JSON.stringify(obj.args) : undefined,
        });
      }
    } catch {
      // Not valid JSON — skip
    }
  }
  return events;
}
