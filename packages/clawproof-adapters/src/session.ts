/**
 * Adapter Session — core runtime for external harness adapters.
 *
 * Manages the event chain, proxies LLM calls through clawproxy,
 * collects receipts, and produces signed proof bundles.
 *
 * This is the shared runtime that all external adapters (Claude Code,
 * Codex, Pi, Opencode, Factory Droid) use. Each adapter configures
 * a session with its harness metadata and environment overrides.
 */

import {
  hashJsonB64u,
  sha256B64u,
  signEd25519,
  didFromPublicKey,
  randomUUID,
  normalizeSha256HashB64u,
} from './crypto';

import { jsonByteSize, redactDeep, redactText } from './redact';
import type {
  AdapterConfig,
  AdapterSession,
  BindingContext,
  ClawproxyReceipt,
  EventChainEntry,
  FinalizeOptions,
  FinalizeResult,
  GatewayReceiptPayload,
  ProofBundlePayload,
  ProxyLLMCallParams,
  ProxyLLMCallResult,
  ReceiptArtifact,
  RecordEventInput,
  RecorderEvent,
  ResourceDescriptor,
  ResourceItem,
  SignedEnvelope,
  URMDocument,
  URMReference,
  TrustPulseDocument,
} from './types';

// ---------------------------------------------------------------------------
// Event hash computation (deterministic key order per adapter spec §4.2)
// ---------------------------------------------------------------------------

async function computeEventHash(entry: {
  event_id: string;
  run_id: string;
  event_type: string;
  timestamp: string;
  payload_hash_b64u: string;
  prev_hash_b64u: string | null;
}): Promise<string> {
  const canonical = {
    event_id: entry.event_id,
    run_id: entry.run_id,
    event_type: entry.event_type,
    timestamp: entry.timestamp,
    payload_hash_b64u: entry.payload_hash_b64u,
    prev_hash_b64u: entry.prev_hash_b64u,
  };
  return hashJsonB64u(canonical);
}

// ---------------------------------------------------------------------------
// Receipt bridging (camelCase → snake_case)
// ---------------------------------------------------------------------------

function bridgeReceipt(
  artifact: ReceiptArtifact,
  signerDid: string,
): SignedEnvelope<GatewayReceiptPayload> {
  const r: ClawproxyReceipt = artifact.receipt;

  const payload: GatewayReceiptPayload = {
    receipt_version: '1',
    receipt_id: randomUUID(),
    gateway_id: r.proxyDid ?? 'clawproxy',
    provider: r.provider,
    model: r.model ?? artifact.model,
    request_hash_b64u: normalizeSha256HashB64u(r.requestHash),
    response_hash_b64u: normalizeSha256HashB64u(r.responseHash),
    tokens_input: 0,
    tokens_output: 0,
    latency_ms: r.latencyMs,
    timestamp: r.timestamp,
  };

  if (r.binding) {
    payload.binding = {};
    if (r.binding.runId) payload.binding.run_id = r.binding.runId;
    if (r.binding.eventHash) payload.binding.event_hash_b64u = r.binding.eventHash;
    if (r.binding.nonce) payload.binding.nonce = r.binding.nonce;
    if (r.binding.policyHash) payload.binding.policy_hash = r.binding.policyHash;
    if (r.binding.tokenScopeHashB64u)
      payload.binding.token_scope_hash_b64u = r.binding.tokenScopeHashB64u;
  }

  return {
    envelope_version: '1',
    envelope_type: 'gateway_receipt',
    payload,
    payload_hash_b64u: '', // filled during finalize
    hash_algorithm: 'SHA-256',
    signature_b64u: r.signature ?? 'unsigned',
    algorithm: 'Ed25519',
    signer_did: signerDid,
    issued_at: r.timestamp,
  };
}

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

// ---------------------------------------------------------------------------
// Resource descriptor conversion
// ---------------------------------------------------------------------------

function toResourceItem(r: ResourceDescriptor): ResourceItem {
  const out: ResourceItem = {
    type: r.type,
    hash_b64u: r.hashB64u,
  };
  if (r.contentType !== undefined) out.content_type = r.contentType;
  if (r.uri !== undefined) out.uri = r.uri;
  if (r.path !== undefined) out.path = r.path;
  if (r.sizeBytes !== undefined) out.size_bytes = r.sizeBytes;
  if (r.metadata !== undefined) out.metadata = r.metadata;
  return out;
}

// ---------------------------------------------------------------------------
// Session factory
// ---------------------------------------------------------------------------

/**
 * Create a new adapter session for a single run.
 *
 * The session manages the event chain, proxied LLM calls, receipt
 * collection, and proof bundle assembly/signing.
 */
export async function createSession(
  config: AdapterConfig,
): Promise<AdapterSession> {
  const runId = `run_${randomUUID()}`;
  const agentDid = config.agentDid ?? await didFromPublicKey(config.keyPair.publicKey);
  const events: RecorderEvent[] = [];
  const receipts: ReceiptArtifact[] = [];

  // OCL-US-004: Trust Pulse (self-reported, non-tier)
  const trustPulseToolCounts = new Map<string, number>();
  const trustPulseFileCounts = new Map<string, number>();

  function bumpCount(map: Map<string, number>, key: string | undefined): void {
    const k = (key ?? '').trim();
    if (!k) return;
    map.set(k, (map.get(k) ?? 0) + 1);
  }

  function safeRelativePath(path: string | undefined): string | undefined {
    if (!path) return undefined;
    const raw = path.trim();
    if (!raw) return undefined;

    // Disallow absolute paths and home shortcuts.
    if (raw.startsWith('/') || raw.startsWith('~') || raw.startsWith('\\')) return undefined;

    // Normalize separators to '/' and strip leading './'
    const normalized = raw.replace(/\\/g, '/').replace(/^\.\//, '');
    const parts = normalized.split('/').filter((p) => p.length > 0);

    // Disallow traversal segments.
    if (parts.some((p) => p === '..')) return undefined;

    const out = parts.join('/');
    return out.length > 0 ? out : undefined;
  }

  function extractPathsFromArgs(args: string): string[] {
    const found = new Set<string>();

    // Patterns like: file_path="..."  path="..."  file="..."
    const kvQuoted = /(file_path|path|file|filename)\s*=\s*"([^"]+)"/gi;
    let m: RegExpExecArray | null;
    while ((m = kvQuoted.exec(args)) !== null) {
      const p = safeRelativePath(m[2]);
      if (p) found.add(p);
    }

    // JSON-ish patterns like: "file_path":"..."
    const jsonQuoted = /"(file_path|path|file|filename)"\s*:\s*"([^"]+)"/gi;
    while ((m = jsonQuoted.exec(args)) !== null) {
      const p = safeRelativePath(m[2]);
      if (p) found.add(p);
    }

    return [...found];
  }

  function observeToolCallForTrustPulse(payload: unknown): void {
    let toolName: string | undefined;
    let args: string | undefined;
    const paths: string[] = [];

    if (payload && typeof payload === 'object') {
      const obj = payload as Record<string, unknown>;

      const t =
        obj['tool'] ??
        obj['tool_name'] ??
        obj['toolName'] ??
        obj['name'];
      if (typeof t === 'string') toolName = t;

      const a = obj['args'] ?? obj['arguments'];
      if (typeof a === 'string') {
        args = a;
      } else if (a && typeof a === 'object') {
        try {
          args = JSON.stringify(a);
        } catch {
          // ignore
        }
      }

      for (const k of ['path', 'file_path', 'filePath', 'file', 'filename', 'old_path', 'new_path']) {
        const v = obj[k];
        if (typeof v === 'string') {
          const p = safeRelativePath(v);
          if (p) paths.push(p);
        }
      }
    } else if (typeof payload === 'string') {
      args = payload;
    }

    bumpCount(trustPulseToolCounts, toolName);

    if (args) {
      for (const p of extractPathsFromArgs(args)) {
        bumpCount(trustPulseFileCounts, p);
      }
    }

    for (const p of paths) {
      bumpCount(trustPulseFileCounts, p);
    }
  }

  // Define as standalone functions to avoid `this` binding issues
  async function recordEvent(input: RecordEventInput) {
    const eventId = `evt_${randomUUID()}`;
    const timestamp = new Date().toISOString();

    // POH-US-020: redact before hashing (prevents secrets/PII entering immutable hashes).
    const redactedPayload = redactDeep(input.payload);

    // OCL-US-004: capture a minimal trust pulse summary from tool_call events.
    if (input.eventType === 'tool_call') {
      observeToolCallForTrustPulse(redactedPayload);
    }

    const payloadHashB64u = await hashJsonB64u(redactedPayload);

    const prevHashB64u = events.length > 0
      ? events[events.length - 1].eventHashB64u
      : null;

    const eventHashB64u = await computeEventHash({
      event_id: eventId,
      run_id: runId,
      event_type: input.eventType,
      timestamp,
      payload_hash_b64u: payloadHashB64u,
      prev_hash_b64u: prevHashB64u,
    });

    const event: RecorderEvent = {
      eventId,
      runId,
      eventType: input.eventType,
      timestamp,
      payloadHashB64u,
      prevHashB64u,
      eventHashB64u,
    };

    events.push(event);

    const binding: BindingContext = {
      runId,
      eventHash: eventHashB64u,
      nonce: `nonce_${randomUUID()}`,
    };

    return { event, binding };
  }

  function addReceipt(artifact: ReceiptArtifact) {
    receipts.push(artifact);
  }

  async function proxyLLMCall(params: ProxyLLMCallParams): Promise<ProxyLLMCallResult> {
    // Record the LLM call event first to get binding context
    const { binding } = await recordEvent({
      eventType: 'llm_call',
      payload: { provider: params.provider, model: params.model },
    });

    // Build proxy URL (aligned with clawproxy: POST /v1/proxy/:provider)
    const proxyUrl = `${config.proxyBaseUrl.replace(/\/$/, '')}/v1/proxy/${params.provider}`;

    // Build headers with binding context
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Run-Id': binding.runId,
      ...(binding.eventHash ? { 'X-Event-Hash': binding.eventHash } : {}),
      ...(binding.nonce ? { 'X-Idempotency-Key': binding.nonce } : {}),
    };

    const extra = params.headers ?? {};

    // Upstream provider API key (recommended: X-Provider-API-Key; legacy: Authorization)
    const providerAuth =
      extra['X-Provider-API-Key'] ??
      extra['x-provider-api-key'] ??
      extra['X-Provider-Key'] ??
      extra['x-provider-key'] ??
      extra['X-Provider-Authorization'] ??
      extra['x-provider-authorization'] ??
      extra['Authorization'] ??
      extra['authorization'];

    if (typeof providerAuth === 'string' && providerAuth.trim().length > 0) {
      const raw = providerAuth.trim();
      const m = raw.match(/^Bearer\s+/i);
      const key = (m ? raw.slice(m[0].length) : raw).trim();
      headers['X-Provider-API-Key'] = key;
    }

    // Copy through other headers (Authorization is reserved for proxy auth)
    for (const [k, v] of Object.entries(extra)) {
      const lowerK = k.toLowerCase();
      if (lowerK === 'authorization') continue;
      if (lowerK === 'x-provider-api-key') continue;
      if (lowerK === 'x-provider-key') continue;
      if (lowerK === 'x-provider-authorization') continue;

      // Prevent caller from overriding proxy auth headers when we're supplying them.
      // If proxyToken is unset, allow callers to pass CST/DID through (e.g., platform-paid mode).
      if (config.proxyToken) {
        if (lowerK === 'x-cst') continue;
        if (lowerK === 'x-scoped-token') continue;
        if (lowerK === 'x-client-did') continue;
      }

      headers[k] = v;
    }

    // Proxy auth token (CST or other gateway token)
    if (config.proxyToken) {
      headers['Authorization'] = `Bearer ${config.proxyToken}`;
    }


    // Make the proxied request
    const res = await fetch(proxyUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(params.body),
    });

    const responseBody = await res.json() as Record<string, unknown>;
    let receipt: ReceiptArtifact | undefined;

    const receiptEnvelope = extractReceiptEnvelope(responseBody);

    // Extract receipt from _receipt field
    if (responseBody._receipt) {
      const rawReceipt = responseBody._receipt as ClawproxyReceipt;
      receipt = {
        type: 'clawproxy_receipt',
        collectedAt: new Date().toISOString(),
        model: params.model,
        receipt: rawReceipt,
        receiptEnvelope,
      };
      addReceipt(receipt);
    }

    return {
      response: responseBody,
      receipt,
      status: res.status,
    };
  }

  async function finalize(options: FinalizeOptions): Promise<FinalizeResult> {
    // 1. Convert events to snake_case EventChainEntry[]
    const eventChain: EventChainEntry[] = events.map((e) => ({
      event_id: e.eventId,
      run_id: e.runId,
      event_type: e.eventType,
      timestamp: e.timestamp,
      payload_hash_b64u: e.payloadHashB64u,
      prev_hash_b64u: e.prevHashB64u,
      event_hash_b64u: e.eventHashB64u,
    }));

    // 2. Event chain root hash
    const chainRootHash = eventChain.length > 0
      ? eventChain[0].event_hash_b64u
      : undefined;

    // 3. Harness config hash
    const configHash = await hashJsonB64u({
      id: config.harness.id,
      version: config.harness.version,
      runtime: config.harness.runtime,
    });

    // 4. Bridge receipts
    const bridgedReceipts: SignedEnvelope<GatewayReceiptPayload>[] = [];
    for (const artifact of receipts) {
      // Prefer canonical `_receipt_envelope` emitted by clawproxy when present.
      if (artifact.receiptEnvelope) {
        bridgedReceipts.push(artifact.receiptEnvelope);
        continue;
      }

      // Fallback: bridge legacy `_receipt` into envelope shape (non-verifiable signature).
      const envelope = bridgeReceipt(artifact, artifact.receipt.proxyDid ?? agentDid);
      envelope.payload_hash_b64u = await hashJsonB64u(envelope.payload);
      bridgedReceipts.push(envelope);
    }

    // 5. Receipts root hash
    let receiptsRootHash: string | undefined;
    if (bridgedReceipts.length > 0) {
      const encoder = new TextEncoder();
      const concat = bridgedReceipts.map((r) => r.payload_hash_b64u).join(':');
      receiptsRootHash = await sha256B64u(encoder.encode(concat));
    }

    // 6. Generate Trust Pulse (self-reported, non-tier)
    const startedAt = events.length > 0 ? events[0].timestamp : new Date().toISOString();
    const endedAt = events.length > 0
      ? events[events.length - 1].timestamp
      : startedAt;

    const durationMs = (() => {
      const start = Date.parse(startedAt);
      const end = Date.parse(endedAt);
      if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return 0;
      return end - start;
    })();

    const tools = [...trustPulseToolCounts.entries()]
      .map(([name, calls]) => ({
        name: redactText(name).slice(0, 128),
        calls,
      }))
      .sort((a, b) => b.calls - a.calls || a.name.localeCompare(b.name))
      .slice(0, 128);

    const files = [...trustPulseFileCounts.entries()]
      .map(([path, touches]) => ({
        path: redactText(path).slice(0, 1024),
        touches,
      }))
      .sort((a, b) => b.touches - a.touches || a.path.localeCompare(b.path))
      .slice(0, 512);

    const trustPulse: TrustPulseDocument = {
      trust_pulse_version: '1',
      trust_pulse_id: `tp_${randomUUID()}`,
      run_id: runId,
      agent_did: agentDid,
      issued_at: new Date().toISOString(),
      evidence_class: 'self_reported',
      tier_uplift: false,
      started_at: startedAt,
      ended_at: endedAt,
      duration_ms: durationMs,
      tools,
      files,
    };

    const trustPulseHashB64u = await hashJsonB64u(trustPulse);

    const trustPulsePointer = {
      schema: 'https://schemas.clawbureau.org/claw.poh.trust_pulse.v1.json',
      artifact_hash_b64u: trustPulseHashB64u,
      evidence_class: 'self_reported',
      tier_uplift: false,
    };

    // POH-US-020: redact + bound user-provided URM metadata before embedding.
    let userUrmMetadata: Record<string, unknown> | undefined =
      options.urmMetadata
        ? (redactDeep(options.urmMetadata) as Record<string, unknown>)
        : undefined;

    const MAX_URM_METADATA_BYTES = 16 * 1024;
    if (userUrmMetadata && jsonByteSize(userUrmMetadata) > MAX_URM_METADATA_BYTES) {
      userUrmMetadata = undefined;
    }

    let urmMetadata: Record<string, unknown> = {
      ...(userUrmMetadata ?? {}),
      trust_pulse: trustPulsePointer,
    };

    // Final bound check (including trust_pulse pointer). If too big, drop user metadata.
    if (jsonByteSize(urmMetadata) > MAX_URM_METADATA_BYTES) {
      urmMetadata = { trust_pulse: trustPulsePointer };
    }

    const trustPulseOutput: ResourceItem = {
      type: 'trust_pulse',
      hash_b64u: trustPulseHashB64u,
      content_type: 'application/json',
      metadata: trustPulsePointer,
    };

    // 7. Generate URM
    const urmId = `urm_${randomUUID()}`;
    const urm: URMDocument = {
      urm_version: '1',
      urm_id: urmId,
      run_id: runId,
      agent_did: agentDid,
      issued_at: new Date().toISOString(),
      harness: {
        id: config.harness.id,
        version: config.harness.version,
        runtime: config.harness.runtime,
        config_hash_b64u: config.harness.configHash ?? configHash,
      },
      inputs: options.inputs.map(toResourceItem),
      outputs: [...options.outputs.map(toResourceItem), trustPulseOutput],
      event_chain_root_hash_b64u: chainRootHash,
      receipts_root_hash_b64u: receiptsRootHash,
      metadata: urmMetadata,
    };

    // 7. URM reference
    const urmHashB64u = await hashJsonB64u(urm);
    const urmRef: URMReference = {
      urm_version: '1',
      urm_id: urmId,
      resource_type: 'universal_run_manifest',
      resource_hash_b64u: urmHashB64u,
    };

    // 8. Assemble proof bundle payload
    const bundleId = `bundle_${randomUUID()}`;
    const payload: ProofBundlePayload = {
      bundle_version: '1',
      bundle_id: bundleId,
      agent_did: agentDid,
      urm: urmRef,
      event_chain: eventChain,
      metadata: {
        harness: {
          id: config.harness.id,
          version: config.harness.version,
          runtime: config.harness.runtime,
          config_hash_b64u: config.harness.configHash ?? configHash,
        },
      },
    };
    if (bridgedReceipts.length > 0) {
      payload.receipts = bridgedReceipts;
    }

    // 9. Compute payload hash + sign
    const payloadHashB64u = await hashJsonB64u(payload);
    const encoder = new TextEncoder();
    const signatureB64u = await signEd25519(
      config.keyPair.privateKey,
      encoder.encode(payloadHashB64u),
    );

    // 10. Wrap in SignedEnvelope
    const envelope: SignedEnvelope<ProofBundlePayload> = {
      envelope_version: '1',
      envelope_type: 'proof_bundle',
      payload,
      payload_hash_b64u: payloadHashB64u,
      hash_algorithm: 'SHA-256',
      signature_b64u: signatureB64u,
      algorithm: 'Ed25519',
      signer_did: agentDid,
      issued_at: new Date().toISOString(),
    };

    return { envelope, urm, trustPulse };
  }

  return {
    get runId() { return runId; },
    get agentDid() { return agentDid; },

    get proxyBaseUrl() { return config.proxyBaseUrl; },
    get proxyToken() { return config.proxyToken; },

    recordEvent,
    addReceipt,
    proxyLLMCall,
    finalize,
  };
}
