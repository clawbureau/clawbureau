/**
 * ClawproofRun — core SDK runtime for recording events and producing
 * signed proof bundles from API scripts.
 *
 * Usage:
 *   const run = await createRun(config);
 *   await run.recordEvent({ eventType: 'run_start', payload: { task: '...' } });
 *   const { response } = await run.callLLM({ provider: 'anthropic', model: 'claude-sonnet-4-5-20250929', body });
 *   const result = await run.finalize({ inputs: [...], outputs: [...] });
 */

import {
  hashJsonB64u,
  sha256B64u,
  signEd25519,
  didFromPublicKey,
  randomUUID,
  normalizeSha256HashB64u,
} from './crypto.js';
import type {
  ClawproofConfig,
  ClawproofRun,
  BindingContext,
  ClawproxyReceipt,
  EventChainEntry,
  FinalizeOptions,
  FinalizeResult,
  GatewayReceiptPayload,
  HumanApprovalParams,
  HumanApprovalReceiptArtifact,
  HumanApprovalReceiptPayload,
  LLMCallParams,
  LLMCallResult,
  ProofBundlePayload,
  ReceiptArtifact,
  RecordEventInput,
  RecorderEvent,
  ResourceDescriptor,
  ResourceItem,
  SideEffectParams,
  SideEffectReceiptArtifact,
  SideEffectReceiptPayload,
  SignedEnvelope,
  ToolCallParams,
  ToolReceiptArtifact,
  ToolReceiptPayload,
  URMDocument,
  URMReference,
} from './types.js';

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
  const r = artifact.receipt;

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
// Resource descriptor conversion (camelCase → snake_case)
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
// Run factory
// ---------------------------------------------------------------------------

/**
 * Create a new clawproof run for recording events and producing
 * a signed proof bundle.
 *
 * Each run gets a unique `run_<uuid>` identifier and manages its own
 * event chain, receipt collection, and finalization.
 */
export async function createRun(config: ClawproofConfig): Promise<ClawproofRun> {
  const runId = `run_${randomUUID()}`;
  const agentDid = config.agentDid ?? await didFromPublicKey(config.keyPair.publicKey);
  const events: RecorderEvent[] = [];
  const receipts: ReceiptArtifact[] = [];
  const toolReceipts: ToolReceiptArtifact[] = [];
  const sideEffectReceipts: SideEffectReceiptArtifact[] = [];
  const humanApprovalReceipts: HumanApprovalReceiptArtifact[] = [];

  // Use closure-based methods to avoid `this` binding issues in object literals.

  async function recordEvent(input: RecordEventInput) {
    const eventId = `evt_${randomUUID()}`;
    const timestamp = new Date().toISOString();
    const payloadHashB64u = await hashJsonB64u(input.payload);

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

  async function recordToolCall(params: ToolCallParams): Promise<ToolReceiptArtifact> {
    const { binding } = await recordEvent({
      eventType: 'tool_call',
      payload: { tool_name: params.toolName, tool_version: params.toolVersion },
    });

    const argsHashB64u = await hashJsonB64u(params.args);
    const resultHashB64u = await hashJsonB64u(params.result);

    const receipt: ToolReceiptPayload = {
      receipt_version: '1',
      receipt_id: `tr_${randomUUID()}`,
      tool_name: params.toolName,
      tool_version: params.toolVersion,
      args_hash_b64u: argsHashB64u,
      result_hash_b64u: resultHashB64u,
      result_status: params.resultStatus,
      hash_algorithm: 'SHA-256',
      agent_did: agentDid,
      timestamp: new Date().toISOString(),
      latency_ms: params.latencyMs,
      binding: {
        run_id: binding.runId,
        event_hash_b64u: binding.eventHash,
        nonce: binding.nonce,
      },
    };

    const artifact: ToolReceiptArtifact = {
      type: 'tool_receipt',
      collectedAt: new Date().toISOString(),
      toolName: params.toolName,
      receipt,
    };

    toolReceipts.push(artifact);
    return artifact;
  }

  async function recordSideEffect(params: SideEffectParams): Promise<SideEffectReceiptArtifact> {
    const { binding } = await recordEvent({
      eventType: 'side_effect',
      payload: { effect_class: params.effectClass, vendor_id: params.vendorId },
    });

    const targetHashB64u = await hashJsonB64u(params.target);
    const requestHashB64u = await hashJsonB64u(params.request);
    const responseHashB64u = await hashJsonB64u(params.response);

    const receipt: SideEffectReceiptPayload = {
      receipt_version: '1',
      receipt_id: `ser_${randomUUID()}`,
      effect_class: params.effectClass,
      target_hash_b64u: targetHashB64u,
      vendor_id: params.vendorId,
      request_hash_b64u: requestHashB64u,
      response_hash_b64u: responseHashB64u,
      response_status: params.responseStatus,
      hash_algorithm: 'SHA-256',
      agent_did: agentDid,
      timestamp: new Date().toISOString(),
      latency_ms: params.latencyMs,
      bytes_written: params.bytesWritten,
      binding: {
        run_id: binding.runId,
        event_hash_b64u: binding.eventHash,
        nonce: binding.nonce,
      },
    };

    const artifact: SideEffectReceiptArtifact = {
      type: 'side_effect_receipt',
      collectedAt: new Date().toISOString(),
      effectClass: params.effectClass,
      receipt,
    };

    sideEffectReceipts.push(artifact);
    return artifact;
  }

  async function recordHumanApproval(params: HumanApprovalParams): Promise<HumanApprovalReceiptArtifact> {
    const { binding } = await recordEvent({
      eventType: 'human_approval',
      payload: { approval_type: params.approvalType, approver_subject: params.approverSubject },
    });

    const scopeHashB64u = await hashJsonB64u(params.scopeClaims);
    const planHashB64u = params.plan !== undefined ? await hashJsonB64u(params.plan) : undefined;

    const receipt: HumanApprovalReceiptPayload = {
      receipt_version: '1',
      receipt_id: `har_${randomUUID()}`,
      approval_type: params.approvalType,
      approver_subject: params.approverSubject,
      approver_method: params.approverMethod,
      agent_did: agentDid,
      scope_hash_b64u: scopeHashB64u,
      scope_summary: params.scopeSummary,
      policy_hash_b64u: params.policyHashB64u,
      minted_capability_id: params.mintedCapabilityId,
      minted_capability_ttl_seconds: params.mintedCapabilityTtlSeconds,
      plan_hash_b64u: planHashB64u,
      evidence_required: params.evidenceRequired,
      hash_algorithm: 'SHA-256',
      timestamp: new Date().toISOString(),
      binding: {
        run_id: binding.runId,
        event_hash_b64u: binding.eventHash,
        nonce: binding.nonce,
      },
    };

    const artifact: HumanApprovalReceiptArtifact = {
      type: 'human_approval_receipt',
      collectedAt: new Date().toISOString(),
      approvalType: params.approvalType,
      receipt,
    };

    humanApprovalReceipts.push(artifact);
    return artifact;
  }

  async function callLLM(params: LLMCallParams): Promise<LLMCallResult> {
    // Record the LLM call event to get binding context
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

    // Copy through other headers (Authorization is blocked to avoid CST/provider-key ambiguity)
    for (const [k, v] of Object.entries(extra)) {
      const lowerK = k.toLowerCase();
      if (lowerK === 'authorization') continue;
      if (lowerK === 'x-provider-api-key') continue;
      if (lowerK === 'x-provider-key') continue;
      if (lowerK === 'x-provider-authorization') continue;
      headers[k] = v;
    }

    // Proxy auth token (CST)
    if (config.proxyToken) {
      const raw = config.proxyToken.trim();
      const m = raw.match(/^Bearer\s+/i);
      const token = (m ? raw.slice(m[0].length) : raw).trim();
      headers['X-CST'] = token;
    }


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

    // 2. Event chain root hash (first event's hash)
    const chainRootHash = eventChain.length > 0
      ? eventChain[0].event_hash_b64u
      : undefined;

    // 3. Harness config hash
    const configHash = await hashJsonB64u({
      id: config.harness.id,
      version: config.harness.version,
      runtime: config.harness.runtime,
    });

    // 4. Bridge receipts to SignedEnvelope<GatewayReceiptPayload>
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

    // 6. Generate URM
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
      outputs: options.outputs.map(toResourceItem),
      event_chain_root_hash_b64u: chainRootHash,
      receipts_root_hash_b64u: receiptsRootHash,
      metadata: options.urmMetadata,
    };

    // 7. URM reference for the proof bundle
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
    if (toolReceipts.length > 0) {
      payload.tool_receipts = toolReceipts.map((a) => a.receipt);
    }
    if (sideEffectReceipts.length > 0) {
      payload.side_effect_receipts = sideEffectReceipts.map((a) => a.receipt);
    }
    if (humanApprovalReceipts.length > 0) {
      payload.human_approval_receipts = humanApprovalReceipts.map((a) => a.receipt);
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

    return { envelope, urm };
  }

  return {
    get runId() { return runId; },
    get agentDid() { return agentDid; },
    recordEvent,
    addReceipt,
    recordToolCall,
    recordSideEffect,
    recordHumanApproval,
    callLLM,
    finalize,
  };
}
