/**
 * Clawproxy provider — routes all model calls through the clawproxy
 * gateway, injecting PoH binding headers and collecting receipts.
 */

import type {
  BindingContext,
  ClawproxyProviderConfig,
  ClawproxyReceipt,
  PluginDeps,
  ProviderImplementation,
  ReceiptArtifact,
  StreamEvent,
  StreamOptions,
  SignedEnvelope,
  GatewayReceiptPayload,
} from './types.js';

// ── Binding header names (must match clawproxy/src/idempotency.ts) ──────────
const BINDING_HEADERS = {
  RUN_ID: 'X-Run-Id',
  EVENT_HASH: 'X-Event-Hash',
  NONCE: 'X-Idempotency-Key',
} as const;

// ── Provider path mapping ───────────────────────────────────────────────────
const PROVIDER_PATHS: Record<string, string> = {
  anthropic: '/v1/proxy/anthropic',
  openai: '/v1/proxy/openai',
  google: '/v1/proxy/google',
};

/**
 * Infer the upstream provider from a model ID string.
 * Falls back to the configured default or 'anthropic'.
 */
function inferProvider(
  model: string,
  defaultProvider?: string,
): string {
  const lower = model.toLowerCase();
  if (lower.startsWith('claude') || lower.startsWith('anthropic')) return 'anthropic';
  // OpenAI model families (known prefixes): gpt*, o1*
  if (lower.startsWith('gpt') || lower.startsWith('o1')) return 'openai';
  if (lower.startsWith('gemini') || lower.startsWith('models/gemini')) return 'google';
  return defaultProvider ?? 'anthropic';
}

const PROVIDER_API_KEY_HEADER = 'X-Provider-API-Key';

function stripBearer(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const m = trimmed.match(/^Bearer\s+/i);
  return m ? trimmed.slice(m[0].length).trim() : trimmed;
}

function extractProviderApiKey(
  upstreamProvider: string,
  auth: Record<string, string> | undefined,
): string | undefined {
  if (!auth) return undefined;

  const lower = Object.fromEntries(
    Object.entries(auth).map(([k, v]) => [k.toLowerCase(), v]),
  ) as Record<string, string>;

  // Allow callers to pass the explicit header directly.
  const direct =
    lower['x-provider-api-key'] ??
    lower['x-provider-key'] ??
    lower['x-provider-authorization'];
  if (direct) return stripBearer(direct);

  // Common upstream auth headers.
  if (upstreamProvider === 'openai') {
    return stripBearer(lower['authorization']);
  }
  if (upstreamProvider === 'anthropic') {
    return stripBearer(lower['x-api-key'] ?? lower['anthropic-api-key']);
  }
  if (upstreamProvider === 'google') {
    return stripBearer(lower['x-goog-api-key']);
  }

  return undefined;
}

/**
 * Build request headers for a proxied model call.
 */
function buildHeaders(
  config: ClawproxyProviderConfig,
  upstreamProvider: string,
  auth: Record<string, string> | undefined,
  binding: BindingContext | undefined,
): Headers {
  const headers = new Headers({
    'Content-Type': 'application/json',
    Accept: 'application/json',
  });

  // Proxy auth: prefer plugin-level token (CST or other gateway token)
  if (config.token) {
    headers.set('Authorization', `Bearer ${config.token}`);
  }

  // Upstream provider key: extract from per-call auth and send via X-Provider-API-Key.
  const providerApiKey = extractProviderApiKey(upstreamProvider, auth);
  if (providerApiKey) {
    headers.set(PROVIDER_API_KEY_HEADER, providerApiKey);
  } else if (!config.token && auth) {
    // Back-compat: if no plugin token is set, fall back to forwarding auth headers.
    for (const [key, value] of Object.entries(auth)) {
      headers.set(key, value);
    }
  }

  // Inject PoH binding headers
  if (binding) {
    if (binding.runId) {
      headers.set(BINDING_HEADERS.RUN_ID, binding.runId);
    }
    if (binding.eventHash) {
      headers.set(BINDING_HEADERS.EVENT_HASH, binding.eventHash);
    }
    if (binding.nonce) {
      headers.set(BINDING_HEADERS.NONCE, binding.nonce);
    }
  }

  return headers;
}

/**
 * Extract the `_receipt` from a clawproxy JSON response.
 * Returns undefined if absent or unparseable.
 */
function extractReceipt(
  body: Record<string, unknown>,
): ClawproxyReceipt | undefined {
  const raw = body['_receipt'];
  if (!raw || typeof raw !== 'object') return undefined;
  const receipt = raw as ClawproxyReceipt;
  // Minimal structural check
  if (receipt.version !== '1.0' || typeof receipt.requestHash !== 'string') {
    return undefined;
  }
  return receipt;
}

/**
 * Extract the `_receipt_envelope` (canonical SignedEnvelope<GatewayReceiptPayload>)
 * from a clawproxy JSON response.
 */
function extractReceiptEnvelope(
  body: Record<string, unknown>,
): SignedEnvelope<GatewayReceiptPayload> | undefined {
  const raw = body['_receipt_envelope'];
  if (!raw || typeof raw !== 'object') return undefined;

  const isB64u = (value: unknown): value is string =>
    typeof value === 'string' &&
    value.length > 0 &&
    /^[A-Za-z0-9_-]+$/.test(value);

  const env = raw as Partial<SignedEnvelope<GatewayReceiptPayload>>;

  // Envelope-level checks (avoid undefined payload_hash_b64u silently corrupting root hashes)
  if (env.envelope_version !== '1') return undefined;
  if (env.envelope_type !== 'gateway_receipt') return undefined;
  if (env.algorithm !== 'Ed25519') return undefined;
  if (env.hash_algorithm !== 'SHA-256') return undefined;

  if (!isB64u(env.payload_hash_b64u)) return undefined;
  if (!isB64u(env.signature_b64u)) return undefined;
  if (typeof env.signer_did !== 'string' || !env.signer_did.startsWith('did:key:'))
    return undefined;
  if (typeof env.issued_at !== 'string' || env.issued_at.length === 0) return undefined;
  if (!env.payload || typeof env.payload !== 'object') return undefined;

  // Payload-level checks
  const p = env.payload as Partial<GatewayReceiptPayload>;
  if (p.receipt_version !== '1') return undefined;
  if (typeof p.receipt_id !== 'string' || p.receipt_id.length === 0) return undefined;
  if (typeof p.gateway_id !== 'string' || p.gateway_id.length === 0) return undefined;
  if (typeof p.provider !== 'string' || p.provider.length === 0) return undefined;
  if (typeof p.model !== 'string' || p.model.length === 0) return undefined;
  if (!isB64u(p.request_hash_b64u)) return undefined;
  if (!isB64u(p.response_hash_b64u)) return undefined;
  if (typeof p.timestamp !== 'string' || p.timestamp.length === 0) return undefined;

  return raw as SignedEnvelope<GatewayReceiptPayload>;
}

/**
 * Create the provider implementation that proxies through clawproxy.
 */
export function createClawproxyProvider(
  config: ClawproxyProviderConfig,
  deps: PluginDeps,
): ProviderImplementation & {
  /** All receipts collected during this provider's lifetime. */
  receipts: ReceiptArtifact[];
} {
  const collectedReceipts: ReceiptArtifact[] = [];

  const provider: ProviderImplementation & { receipts: ReceiptArtifact[] } = {
    models: [
      // Expose the three provider families; the gateway model catalog
      // merges these with any user-configured model entries.
      { id: 'claude-*', provider: 'clawproxy', capabilities: ['chat', 'vision'] },
      { id: 'gpt-*', provider: 'clawproxy', capabilities: ['chat', 'vision'] },
      { id: 'gemini-*', provider: 'clawproxy', capabilities: ['chat'] },
    ],

    receipts: collectedReceipts,

    async *stream(
      model: string,
      messages: unknown[],
      options?: StreamOptions,
    ): AsyncIterable<StreamEvent> {
      const upstreamProvider = inferProvider(model, config.defaultProvider);
      const providerPath = PROVIDER_PATHS[upstreamProvider] ?? PROVIDER_PATHS['anthropic'];
      const url = `${config.baseUrl.replace(/\/+$/, '')}${providerPath}`;

      const headers = buildHeaders(config, upstreamProvider, options?.auth, options?.binding);
      const body = JSON.stringify({ model, messages });

      deps.logger.debug(
        `clawproxy: routing ${model} via ${upstreamProvider}`,
      );

      let response: Response;
      try {
        response = await fetch(url, {
          method: 'POST',
          headers,
          body,
          signal: options?.signal,
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        deps.logger.error(`clawproxy: fetch failed: ${msg}`);
        yield { type: 'error', error: `clawproxy fetch failed: ${msg}` };
        return;
      }

      if (!response.ok) {
        const text = await response.text().catch(() => '(no body)');
        deps.logger.error(
          `clawproxy: upstream ${response.status}: ${text.slice(0, 200)}`,
        );
        yield {
          type: 'error',
          error: `clawproxy upstream error ${response.status}`,
        };
        return;
      }

      // Parse JSON response and extract text + receipt
      let parsed: Record<string, unknown>;
      try {
        parsed = (await response.json()) as Record<string, unknown>;
      } catch {
        deps.logger.error('clawproxy: invalid JSON response');
        yield { type: 'error', error: 'clawproxy: invalid JSON response' };
        return;
      }

      // Collect receipt
      const receipt = extractReceipt(parsed);
      const receiptEnvelope = extractReceiptEnvelope(parsed);
      if (receipt) {
        const artifact: ReceiptArtifact = {
          type: 'clawproxy_receipt',
          collectedAt: new Date().toISOString(),
          model,
          receipt,
          receiptEnvelope: receiptEnvelope ?? undefined,
        };
        collectedReceipts.push(artifact);
        deps.logger.debug(
          `clawproxy: receipt collected (binding.runId=${receipt.binding?.runId ?? 'none'})`,
        );
      } else {
        deps.logger.warn('clawproxy: no _receipt in response');
      }

      // Extract text content from the provider response
      const text = extractTextContent(parsed, upstreamProvider);
      if (text) {
        yield { type: 'text', text };
      }

      yield { type: 'done', reason: 'stop' };
    },
  };

  return provider;
}

/**
 * Extract text content from a provider-specific JSON response.
 */
function extractTextContent(
  body: Record<string, unknown>,
  provider: string,
): string | undefined {
  switch (provider) {
    case 'anthropic': {
      // Anthropic Messages API: { content: [{ type: "text", text: "..." }] }
      const content = body['content'];
      if (Array.isArray(content)) {
        return content
          .filter(
            (b: unknown): b is { type: string; text: string } =>
              typeof b === 'object' &&
              b !== null &&
              'type' in b &&
              (b as { type: string }).type === 'text' &&
              'text' in b,
          )
          .map((b) => b.text)
          .join('');
      }
      return undefined;
    }
    case 'openai': {
      // OpenAI Chat Completions: { choices: [{ message: { content: "..." } }] }
      const choices = body['choices'];
      if (Array.isArray(choices) && choices.length > 0) {
        const first = choices[0] as Record<string, unknown> | undefined;
        const message = first?.['message'] as Record<string, unknown> | undefined;
        if (typeof message?.['content'] === 'string') {
          return message['content'] as string;
        }
      }
      return undefined;
    }
    case 'google': {
      // Gemini: { candidates: [{ content: { parts: [{ text: "..." }] } }] }
      const candidates = body['candidates'];
      if (Array.isArray(candidates) && candidates.length > 0) {
        const first = candidates[0] as Record<string, unknown> | undefined;
        const content = first?.['content'] as Record<string, unknown> | undefined;
        const parts = content?.['parts'];
        if (Array.isArray(parts)) {
          return parts
            .filter(
              (p: unknown): p is { text: string } =>
                typeof p === 'object' && p !== null && 'text' in p,
            )
            .map((p) => p.text)
            .join('');
        }
      }
      return undefined;
    }
    default:
      return undefined;
  }
}
