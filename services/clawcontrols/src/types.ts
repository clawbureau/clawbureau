export interface Env {
  SERVICE_VERSION: string;

  /** Optional admin token for write endpoints (Bearer auth). */
  ADMIN_TOKEN?: string;

  /** Ed25519 signing key seed (base64url). Required to issue WPC envelopes. */
  CONTROLS_SIGNING_KEY?: string;

  /** Durable Object registry for Work Policy Contracts. */
  WPC_REGISTRY: DurableObjectNamespace;
}

export type Provider = 'openai' | 'anthropic' | 'google';

export type ReceiptPrivacyMode = 'hash_only' | 'encrypted';
