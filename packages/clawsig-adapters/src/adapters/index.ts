/**
 * Adapter registry — maps harness IDs to their configurations.
 */

import type { HarnessConfig, HarnessId } from '../types';

import * as claudeCode from './claude-code';
import * as codex from './codex';
import * as pi from './pi';
import * as opencode from './opencode';
import * as factoryDroid from './factory-droid';

export { claudeCode, codex, pi, opencode, factoryDroid };

/** Adapter module interface (each adapter exports these). */
export interface AdapterModule {
  HARNESS: HarnessConfig;
  getProxyEnv: (proxyBaseUrl: string, proxyToken?: string) => Record<string, string>;
  parseToolEvents: (output: string) => Array<{ tool: string; args?: string }>;
}

/** Registry of all supported adapters. */
const ADAPTERS: Record<HarnessId, AdapterModule> = {
  'claude-code': claudeCode,
  codex,
  pi,
  opencode,
  'factory-droid': factoryDroid,
};

/** Get an adapter module by harness ID. */
export function getAdapter(id: HarnessId): AdapterModule | undefined {
  return ADAPTERS[id];
}

/** List all supported harness IDs. */
export function listAdapters(): HarnessId[] {
  return Object.keys(ADAPTERS) as HarnessId[];
}
