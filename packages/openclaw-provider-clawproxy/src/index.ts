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

import { createClawproxyProvider } from './provider.js';
import type {
  ClawproxyProviderConfig,
  PluginDeps,
  ProviderImplementation,
  ReceiptArtifact,
  RecorderConfig,
  FinalizeOptions,
  FinalizeResult,
  TrustPulseDocument,
  PromptPackEntry,
  PromptPackDocument,
  SystemPromptReportDocument,
  HarnessConfig,
  ResourceDescriptor,
} from './types.js';

export type {
  ClawproxyProviderConfig,
  ReceiptArtifact,
  RecorderConfig,
  FinalizeOptions,
  FinalizeResult,
  TrustPulseDocument,
  PromptPackEntry,
  PromptPackDocument,
  SystemPromptReportDocument,
  HarnessConfig,
  ResourceDescriptor,
};

// Recorder exports
export { createRecorder } from './recorder.js';
export type { HarnessRecorder } from './recorder.js';

// Crypto utilities for key management
export { generateKeyPair, didFromPublicKey, hashJsonB64u } from './crypto.js';

// ---------------------------------------------------------------------------
// Marketplace CST auto-fetch (POH-US-021/POH-US-022)
// ---------------------------------------------------------------------------

type BountyCstResponse = {
  cwc_auth?: {
    cst: string;
    token_scope_hash_b64u: string;
    policy_hash_b64u: string;
    mission_id: string;
  };
  job_auth?: {
    cst: string;
    token_scope_hash_b64u: string;
    policy_hash_b64u?: string;
    mission_id: string;
  };
};

function getEnvVar(name: string): string | undefined {
  // Avoid a hard dependency on Node types in this package.
  const env = (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process?.env;
  const v = env?.[name];
  return typeof v === 'string' && v.trim().length > 0 ? v.trim() : undefined;
}

async function maybeFetchJobCstFromBounties(config: ClawproxyProviderConfig, deps: PluginDeps): Promise<void> {
  if (config.token) return;

  const baseUrl = getEnvVar('CLAWBOUNTIES_BASE_URL');
  const bountyId = getEnvVar('CLAWBOUNTIES_BOUNTY_ID');
  const workerToken = getEnvVar('CLAWBOUNTIES_WORKER_TOKEN');

  const any = Boolean(baseUrl || bountyId || workerToken);
  if (!any) return;

  if (!baseUrl || !bountyId || !workerToken) {
    throw new Error(
      'clawproxy provider: marketplace CST auto-fetch requested but missing env vars (need CLAWBOUNTIES_BASE_URL, CLAWBOUNTIES_BOUNTY_ID, CLAWBOUNTIES_WORKER_TOKEN)'
    );
  }

  deps.logger.info(`clawproxy provider: fetching job CST from clawbounties (${baseUrl}, bounty=${bountyId})`);

  const url = `${baseUrl.replace(/\/$/, '')}/v1/bounties/${encodeURIComponent(bountyId)}/cst`;

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${workerToken}`,
      'content-type': 'application/json; charset=utf-8',
    },
    body: '{}',
  });

  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }

  if (!res.ok) {
    throw new Error(`clawproxy provider: clawbounties /cst failed: HTTP ${res.status}: ${text}`);
  }

  const parsed = json as Partial<BountyCstResponse>;
  const cst = parsed?.cwc_auth?.cst ?? parsed?.job_auth?.cst;
  const policyHash = parsed?.cwc_auth?.policy_hash_b64u ?? parsed?.job_auth?.policy_hash_b64u;

  if (typeof cst !== 'string' || cst.trim().length === 0) {
    throw new Error('clawproxy provider: clawbounties /cst returned an invalid response (missing cwc_auth.cst or job_auth.cst)');
  }

  // If this is a CWC bounty, policy_hash_b64u is required.
  if (parsed?.cwc_auth && (typeof policyHash !== 'string' || policyHash.trim().length === 0)) {
    throw new Error('clawproxy provider: clawbounties /cst returned an invalid response (missing cwc_auth.policy_hash_b64u)');
  }

  config.token = cst.trim();

  // Avoid POLICY_HASH_MISMATCH errors when CST pins policy_hash_b64u.
  if (typeof policyHash === 'string' && policyHash.trim().length > 0) {
    if (config.policyHashB64u && config.policyHashB64u !== policyHash.trim()) {
      deps.logger.warn(
        `clawproxy provider: overriding policyHashB64u from config (${config.policyHashB64u}) to match job CST policy_hash_b64u (${policyHash.trim()})`
      );
    }
    config.policyHashB64u = policyHash.trim();
  }
}

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

    await maybeFetchJobCstFromBounties(config, deps);

    deps.logger.info(
      `clawproxy provider: initializing (baseUrl=${config.baseUrl}, auth=${config.token ? 'token' : 'passthrough'})`,
    );

    return createClawproxyProvider(config, deps);
  },
};

export default plugin;
