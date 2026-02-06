/**
 * Harness Recorder (POH-US-006)
 *
 * Captures tool + model events into a hash-linked event chain,
 * generates a Universal Run Manifest (URM), assembles a proof
 * bundle with receipts + event chain, and signs it with the
 * agent's Ed25519 DID key.
 *
 * Usage:
 *   const recorder = await createRecorder(config, deps);
 *   recorder.recordEvent({ eventType: 'run_start', payload: { ... } });
 *   recorder.recordEvent({ eventType: 'llm_call', payload: { ... } });
 *   recorder.addReceipt(receiptArtifact);
 *   const result = await recorder.finalize({ inputs, outputs });
 */

import {
  hashJsonB64u,
  sha256B64u,
  signEd25519,
  didFromPublicKey,
  randomUUID,
  normalizeSha256HashB64u,
} from './crypto';
import type {
  RecorderConfig,
  RecordEventInput,
  RecorderEvent,
  ReceiptArtifact,
  ClawproxyReceipt,
  EventChainEntry,
  URMDocument,
  URMReference,
  ResourceDescriptor,
  ProofBundlePayload,
  GatewayReceiptPayload,
  SignedEnvelope,
  FinalizeOptions,
  FinalizeResult,
  BindingContext,
  PluginDeps,
} from './types';

// ---------------------------------------------------------------------------
// Event hash computation
// ---------------------------------------------------------------------------

/**
 * Compute the canonical event hash.
 * The canonical header is JSON with deterministic key order:
 *   { event_id, run_id, event_type, timestamp, payload_hash_b64u, prev_hash_b64u }
 */
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
// Receipt bridging: ClawproxyReceipt → SignedEnvelope<GatewayReceiptPayload>
// ---------------------------------------------------------------------------

/**
 * Bridge a clawproxy receipt (camelCase, version '1.0') to a
 * SignedEnvelope<GatewayReceiptPayload> (snake_case, version '1').
 *
 * Note: clawproxy receipts currently emit SHA-256 hashes as hex strings.
 * PoH schema fields use base64url naming, so we normalize hex → base64url
 * when the input matches a 64-character hex SHA-256.
 */
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

  // The receipt envelope uses the proxy's signature if available.
  // In practice the proxy signs its own receipts; we wrap them
  // into the envelope format expected by clawverify.
  return {
    envelope_version: '1',
    envelope_type: 'gateway_receipt',
    payload,
    payload_hash_b64u: '', // filled by finalize
    hash_algorithm: 'SHA-256',
    signature_b64u: r.signature ?? 'unsigned',
    algorithm: 'Ed25519',
    signer_did: signerDid,
    issued_at: r.timestamp,
  };
}

// ---------------------------------------------------------------------------
// Recorder class
// ---------------------------------------------------------------------------

export interface HarnessRecorder {
  /** The run ID for this recording session. */
  readonly runId: string;

  /** The agent DID derived from the key pair. */
  readonly agentDid: string;

  /**
   * Record an event in the hash-linked chain.
   * Returns the event entry and a binding context for LLM calls.
   */
  recordEvent(input: RecordEventInput): Promise<{ event: RecorderEvent; binding: BindingContext }>;

  /** Add a receipt artifact collected by the provider plugin. */
  addReceipt(artifact: ReceiptArtifact): void;

  /** Get the current event chain (in order). */
  getEvents(): RecorderEvent[];

  /** Get all collected receipt artifacts. */
  getReceipts(): ReceiptArtifact[];

  /**
   * Finalize the run: generate URM, assemble + sign proof bundle.
   * Should be called after the last event (typically run_end).
   */
  finalize(options: FinalizeOptions): Promise<FinalizeResult>;
}

/**
 * Create a new harness recorder for a single run.
 */
export async function createRecorder(
  config: RecorderConfig,
  deps: PluginDeps,
): Promise<HarnessRecorder> {
  const runId = `run_${randomUUID()}`;
  const agentDid = config.agentDid ?? await didFromPublicKey(config.keyPair.publicKey);
  const events: RecorderEvent[] = [];
  const receipts: ReceiptArtifact[] = [];

  deps.logger.info(`recorder: initialized (runId=${runId}, did=${agentDid})`);

  return {
    get runId() {
      return runId;
    },

    get agentDid() {
      return agentDid;
    },

    async recordEvent(input: RecordEventInput) {
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
      deps.logger.debug(
        `recorder: event #${events.length} type=${input.eventType} hash=${eventHashB64u.slice(0, 12)}...`,
      );

      const binding: BindingContext = {
        runId,
        eventHash: eventHashB64u,
        nonce: `nonce_${randomUUID()}`,
      };

      return { event, binding };
    },

    addReceipt(artifact: ReceiptArtifact) {
      receipts.push(artifact);
      deps.logger.debug(
        `recorder: receipt added (model=${artifact.model}, total=${receipts.length})`,
      );
    },

    getEvents() {
      return [...events];
    },

    getReceipts() {
      return [...receipts];
    },

    async finalize(options: FinalizeOptions) {
      deps.logger.info(`recorder: finalizing (events=${events.length}, receipts=${receipts.length})`);

      // 1. Convert internal events to snake_case EventChainEntry[]
      const eventChain: EventChainEntry[] = events.map((e) => ({
        event_id: e.eventId,
        run_id: e.runId,
        event_type: e.eventType,
        timestamp: e.timestamp,
        payload_hash_b64u: e.payloadHashB64u,
        prev_hash_b64u: e.prevHashB64u,
        event_hash_b64u: e.eventHashB64u,
      }));

      // 2. Compute event chain root hash (first event's hash)
      const chainRootHash = eventChain.length > 0
        ? eventChain[0].event_hash_b64u
        : undefined;

      // 3. Compute harness config hash
      const configHash = await hashJsonB64u({
        id: config.harness.id,
        version: config.harness.version,
        runtime: config.harness.runtime,
      });

      // 4. Bridge receipts to SignedEnvelope<GatewayReceiptPayload>
      const bridgedReceipts: SignedEnvelope<GatewayReceiptPayload>[] = [];
      for (const artifact of receipts) {
        const envelope = bridgeReceipt(artifact, artifact.receipt.proxyDid ?? agentDid);
        envelope.payload_hash_b64u = await hashJsonB64u(envelope.payload);
        bridgedReceipts.push(envelope);
      }

      // 5. Compute receipts root hash (hash of all receipt payload hashes concatenated)
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
        inputs: options.inputs.map(toSnakeCaseResource),
        outputs: options.outputs.map(toSnakeCaseResource),
        event_chain_root_hash_b64u: chainRootHash,
        receipts_root_hash_b64u: receiptsRootHash,
        metadata: options.urmMetadata,
      };

      // 7. Compute URM hash for the bundle reference
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

      // 9. Compute payload hash
      const payloadHashB64u = await hashJsonB64u(payload);

      // 10. Sign the proof bundle (Ed25519 over payload_hash_b64u bytes)
      const encoder = new TextEncoder();
      const signatureB64u = await signEd25519(
        config.keyPair.privateKey,
        encoder.encode(payloadHashB64u),
      );

      // 11. Wrap in SignedEnvelope
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

      deps.logger.info(
        `recorder: finalized bundle=${bundleId} events=${eventChain.length} receipts=${bridgedReceipts.length}`,
      );

      return { envelope, urm };
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toSnakeCaseResource(r: ResourceDescriptor): {
  type: string;
  hash_b64u: string;
  content_type?: string;
  uri?: string;
  path?: string;
  size_bytes?: number;
  metadata?: Record<string, unknown>;
} {
  const out: {
    type: string;
    hash_b64u: string;
    content_type?: string;
    uri?: string;
    path?: string;
    size_bytes?: number;
    metadata?: Record<string, unknown>;
  } = {
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
