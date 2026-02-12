export interface Env {
  SERVICE_VERSION: string;

  /**
   * Legacy admin token fallback for write endpoints.
   * Only used when CONTROL_REQUIRE_CANONICAL_CST is false.
   */
  ADMIN_TOKEN?: string;

  /**
   * ICP-M6.2 enforcement gate.
   * Defaults to true (fail-closed) when unset.
   */
  CONTROL_REQUIRE_CANONICAL_CST?: string;

  /**
   * clawverify base URL for canonical token-control checks.
   * Required when CONTROL_REQUIRE_CANONICAL_CST is true.
   */
  CLAWVERIFY_BASE_URL?: string;

  /** Optional timeout (ms) for token-control verification requests. */
  CONTROL_VERIFY_TIMEOUT_MS?: string;

  /** Ed25519 signing key seed (base64url). Required to issue WPC envelopes. */
  CONTROLS_SIGNING_KEY?: string;

  /** Durable Object registry for Work Policy Contracts. */
  WPC_REGISTRY: DurableObjectNamespace;
}

export type Provider = 'openai' | 'anthropic' | 'google';

export type ReceiptPrivacyMode = 'hash_only' | 'encrypted';
