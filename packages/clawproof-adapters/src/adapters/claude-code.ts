/**
 * Claude Code adapter.
 *
 * Claude Code supports base URL overrides via the ANTHROPIC_BASE_URL
 * environment variable. This adapter configures that to point to
 * clawproxy, then wraps the Claude Code CLI invocation to capture
 * events and produce a proof bundle.
 *
 * Usage:
 *   CLAWPROOF_PROXY_URL=https://proxy.example.com \
 *   clawproof-wrap claude-code -- claude "fix the bug in auth.ts"
 *
 * Environment variables set by the wrapper:
 *   ANTHROPIC_BASE_URL → clawproxy URL (routes Anthropic calls through proxy)
 */

import type { HarnessConfig } from '../types';

/** Claude Code harness configuration. */
export const HARNESS: HarnessConfig = {
  id: 'claude-code',
  version: '1.0.0',
  runtime: 'host',
};

/**
 * Environment variables to set when launching Claude Code
 * so that LLM calls are routed through clawproxy.
 */
export function getProxyEnv(proxyBaseUrl: string, proxyToken?: string): Record<string, string> {
  const env: Record<string, string> = {
    // Claude Code uses the Anthropic SDK which respects ANTHROPIC_BASE_URL
    ANTHROPIC_BASE_URL: `${proxyBaseUrl.replace(/\/$/, '')}/v1/anthropic`,
  };

  // If a proxy token is provided, set it as the API key.
  // Clawproxy will validate this token and forward to the real Anthropic API.
  if (proxyToken) {
    env.ANTHROPIC_API_KEY = proxyToken;
  }

  return env;
}

/**
 * Parse Claude Code's output to extract tool call events.
 *
 * Claude Code logs tool usage in a structured format when verbose
 * mode is enabled. This function extracts tool names and arguments
 * for inclusion in the event chain.
 */
export function parseToolEvents(output: string): Array<{ tool: string; args?: string }> {
  const events: Array<{ tool: string; args?: string }> = [];
  // Claude Code prefixes tool usage with tool names like:
  //   Read(file_path="...")
  //   Edit(file_path="...", old_string="...", new_string="...")
  //   Bash(command="...")
  const toolPattern = /^(\w+)\((.+?)\)\s*$/gm;
  let match;
  while ((match = toolPattern.exec(output)) !== null) {
    events.push({ tool: match[1], args: match[2] });
  }
  return events;
}
