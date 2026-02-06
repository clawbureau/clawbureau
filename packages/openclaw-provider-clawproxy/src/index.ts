/**
 * @openclaw/provider-clawproxy
 *
 * OpenClaw provider plugin that routes all model calls through
 * the clawproxy gateway. Each call automatically:
 *   1. Injects PoH binding headers (X-Run-Id, X-Event-Hash, X-Idempotency-Key)
 *   2. Collects the signed receipt from the `_receipt` response field
 *   3. Stores receipt artifacts for later inclusion in proof bundles
 *
 * Configuration (in openclaw.json → providers.clawproxy):
 *   baseUrl  — clawproxy gateway URL (required)
 *   token    — bearer token for proxy auth (optional)
 *   defaultProvider — fallback upstream provider (optional, default: anthropic)
 */

import { createClawproxyProvider } from './provider';
import type {
  ClawproxyProviderConfig,
  PluginDeps,
  ProviderImplementation,
  ReceiptArtifact,
  RecorderConfig,
  FinalizeOptions,
  FinalizeResult,
  HarnessConfig,
  ResourceDescriptor,
} from './types';

export type {
  ClawproxyProviderConfig,
  ReceiptArtifact,
  RecorderConfig,
  FinalizeOptions,
  FinalizeResult,
  HarnessConfig,
  ResourceDescriptor,
};

// Recorder exports
export { createRecorder } from './recorder';
export type { HarnessRecorder } from './recorder';

// Crypto utilities for key management
export { generateKeyPair, didFromPublicKey, hashJsonB64u } from './crypto';

// ── Plugin definition ───────────────────────────────────────────────────────

/**
 * OpenClaw plugin definition for the clawproxy provider.
 *
 * In a full OpenClaw workspace the schema would use TypeBox
 * (`Type.Object(…)`). Here we define the shape as a plain object
 * so the package can typecheck without @sinclair/typebox.
 */
const plugin = {
  slot: 'provider' as const,
  id: 'clawproxy',

  /**
   * TypeBox-compatible schema stub.
   * Real OpenClaw validates this at load time; the clawbureau
   * monorepo only needs the structural shape for typechecking.
   */
  schema: {
    type: 'object' as const,
    properties: {
      baseUrl: { type: 'string' as const },
      token: { type: 'string' as const },
      defaultProvider: {
        type: 'string' as const,
        enum: ['anthropic', 'openai', 'google'],
      },
    },
    required: ['baseUrl'] as const,
  },

  metadata: {
    name: 'Clawproxy Provider',
    description:
      'Routes model calls through clawproxy for automatic receipt generation and proof-of-harness binding.',
  },

  async init(
    config: ClawproxyProviderConfig,
    deps: PluginDeps,
  ): Promise<ProviderImplementation & { receipts: ReceiptArtifact[] }> {
    if (!config.baseUrl) {
      throw new Error(
        'clawproxy provider: baseUrl is required in configuration',
      );
    }

    deps.logger.info(
      `clawproxy provider: initializing (baseUrl=${config.baseUrl}, auth=${config.token ? 'token' : 'passthrough'})`,
    );

    return createClawproxyProvider(config, deps);
  },
};

export default plugin;
