/**
 * Receipt generation for proxied LLM requests
 */

import type {
  Provider,
  Receipt,
  ReceiptBinding,
  ReceiptPayment,
  ReceiptPrivacyMode,
  EncryptedPayload,
  GatewayReceiptBinding,
  GatewayReceiptPayload,
  SignedEnvelope,
} from './types';
import {
  sha256,
  sha256B64u,
  sha256HexToB64u,
  signEd25519,
  encryptAes256Gcm,
  type Ed25519KeyPair,
  type AesEncryptedPayload,
} from './crypto';

export interface ReceiptInput {
  provider: Provider;
  model?: string;
  requestBody: string;
  responseBody: string;
  startTime: number;
  /** Optional binding fields for chaining proofs */
  binding?: ReceiptBinding;
  /** Payment attribution for the receipt */
  payment?: ReceiptPayment;
  /** Override timestamp (useful when other IDs depend on it) */
  timestamp?: string;
  /** Privacy mode: hash_only (default) or encrypted */
  privacyMode?: ReceiptPrivacyMode;
}

export interface SigningContext {
  keyPair: Ed25519KeyPair;
  /** did:web:... for legacy receipts */
  did: string;
  /** key id used by did:web doc */
  kid: string;
  /** did:key:... for canonical receipt envelopes */
  didKey: string;
}

export interface EncryptionContext {
  key: CryptoKey;
}

/**
 * Generate a receipt for a proxied request
 * Default mode is hash-only: receipts contain hashes (not content) for privacy-preserving verification
 * Encrypted mode: optionally includes encrypted payloads for authorized decryption
 *
 * @param input - Receipt input data
 * @param signingContext - Optional signing context for Ed25519 signatures
 * @param encryptionContext - Optional encryption context for encrypted receipts
 */
export async function generateReceipt(
  input: ReceiptInput,
  signingContext?: SigningContext,
  encryptionContext?: EncryptionContext
): Promise<Receipt> {
  const {
    provider,
    model,
    requestBody,
    responseBody,
    startTime,
    binding,
    payment,
    timestamp,
    privacyMode,
  } = input;

  const [requestHash, responseHash] = await Promise.all([
    sha256(requestBody),
    sha256(responseBody),
  ]);

  const receipt: Receipt = {
    version: '1.0',
    provider,
    model,
    requestHash,
    responseHash,
    timestamp: timestamp ?? new Date().toISOString(),
    latencyMs: Date.now() - startTime,
  };

  // Attach payment attribution when present
  if (payment) {
    receipt.payment = payment;
  }

  // Add binding fields if provided (for proof chaining)
  if (
    binding &&
    (binding.runId ||
      binding.eventHash ||
      binding.nonce ||
      binding.policyHash ||
      binding.tokenScopeHashB64u)
  ) {
    receipt.binding = {};
    if (binding.runId) {
      receipt.binding.runId = binding.runId;
    }
    if (binding.eventHash) {
      receipt.binding.eventHash = binding.eventHash;
    }
    if (binding.nonce) {
      receipt.binding.nonce = binding.nonce;
    }
    if (binding.policyHash) {
      receipt.binding.policyHash = binding.policyHash;
    }
    if (binding.tokenScopeHashB64u) {
      receipt.binding.tokenScopeHashB64u = binding.tokenScopeHashB64u;
    }
  }

  // Set privacy mode (defaults to hash_only)
  receipt.privacyMode = privacyMode ?? 'hash_only';

  // Encrypt payloads if privacy mode is 'encrypted' and encryption context is provided
  if (receipt.privacyMode === 'encrypted' && encryptionContext) {
    const [encryptedRequest, encryptedResponse] = await Promise.all([
      encryptAes256Gcm(encryptionContext.key, requestBody),
      encryptAes256Gcm(encryptionContext.key, responseBody),
    ]);

    receipt.encryptedRequest = toEncryptedPayload(encryptedRequest);
    receipt.encryptedResponse = toEncryptedPayload(encryptedResponse);
  }

  // Sign receipt if signing context is provided
  if (signingContext) {
    receipt.proxyDid = signingContext.did;
    receipt.kid = signingContext.kid;

    // Sign the receipt payload (excluding signature field)
    const payloadToSign = createSigningPayload(receipt);
    receipt.signature = await signEd25519(
      signingContext.keyPair.privateKey,
      payloadToSign
    );
  }

  return receipt;
}

export interface ReceiptHashInput {
  provider: Provider;
  model?: string;
  requestHash: string;
  responseHash: string;
  startTime: number;
  /** Optional binding fields for chaining proofs */
  binding?: ReceiptBinding;
  /** Payment attribution for the receipt */
  payment?: ReceiptPayment;
  /** Override timestamp (useful when other IDs depend on it) */
  timestamp?: string;
  /** Privacy mode: hash_only (default) or encrypted */
  privacyMode?: ReceiptPrivacyMode;
}

/**
 * Generate a receipt when request/response hashes are already known.
 *
 * Used for streaming proxy responses where the full response body is not buffered.
 * Note: encrypted payloads are not supported in this mode.
 */
export async function generateReceiptFromHashes(
  input: ReceiptHashInput,
  signingContext?: SigningContext
): Promise<Receipt> {
  const {
    provider,
    model,
    requestHash,
    responseHash,
    startTime,
    binding,
    payment,
    timestamp,
    privacyMode,
  } = input;

  const receipt: Receipt = {
    version: '1.0',
    provider,
    model,
    requestHash,
    responseHash,
    timestamp: timestamp ?? new Date().toISOString(),
    latencyMs: Date.now() - startTime,
  };

  // Attach payment attribution when present
  if (payment) {
    receipt.payment = payment;
  }

  // Add binding fields if provided (for proof chaining)
  if (
    binding &&
    (binding.runId ||
      binding.eventHash ||
      binding.nonce ||
      binding.policyHash ||
      binding.tokenScopeHashB64u)
  ) {
    receipt.binding = {};
    if (binding.runId) receipt.binding.runId = binding.runId;
    if (binding.eventHash) receipt.binding.eventHash = binding.eventHash;
    if (binding.nonce) receipt.binding.nonce = binding.nonce;
    if (binding.policyHash) receipt.binding.policyHash = binding.policyHash;
    if (binding.tokenScopeHashB64u)
      receipt.binding.tokenScopeHashB64u = binding.tokenScopeHashB64u;
  }

  // Set privacy mode (defaults to hash_only)
  receipt.privacyMode = privacyMode ?? 'hash_only';

  // Sign receipt if signing context is provided
  if (signingContext) {
    receipt.proxyDid = signingContext.did;
    receipt.kid = signingContext.kid;

    const payloadToSign = createSigningPayload(receipt);
    receipt.signature = await signEd25519(
      signingContext.keyPair.privateKey,
      payloadToSign
    );
  }

  return receipt;
}

/**
 * Convert AES encrypted payload to EncryptedPayload type
 */
function toEncryptedPayload(aesPayload: AesEncryptedPayload): EncryptedPayload {
  return {
    algorithm: 'AES-256-GCM',
    iv: aesPayload.iv,
    ciphertext: aesPayload.ciphertext,
    tag: aesPayload.tag,
  };
}

/**
 * Create the canonical signing payload from a receipt
 * Deterministic JSON serialization of receipt fields (excluding signature)
 */
export function createSigningPayload(receipt: Receipt): string {
  // Create payload with fields in deterministic order
  // Note: binding fields are included when present to ensure they're signed
  const payload: Record<string, unknown> = {
    version: receipt.version,
    proxyDid: receipt.proxyDid,
    provider: receipt.provider,
    model: receipt.model,
    requestHash: receipt.requestHash,
    responseHash: receipt.responseHash,
    timestamp: receipt.timestamp,
    latencyMs: receipt.latencyMs,
    kid: receipt.kid,
  };

  // Include binding in signing payload if present (ensures binding is tamper-proof)
  if (receipt.binding) {
    payload.binding = receipt.binding;
  }

  // Include payment attribution in signing (ensures tamper-proof)
  if (receipt.payment) {
    payload.payment = receipt.payment;
  }

  // Include privacy mode and encrypted payloads in signing (ensures tamper-proof)
  if (receipt.privacyMode) {
    payload.privacyMode = receipt.privacyMode;
  }
  if (receipt.encryptedRequest) {
    payload.encryptedRequest = receipt.encryptedRequest;
  }
  if (receipt.encryptedResponse) {
    payload.encryptedResponse = receipt.encryptedResponse;
  }

  return JSON.stringify(payload);
}

/**
 * Attach receipt to a response object
 * Returns a new object with _receipt field added
 */
export function attachReceipt<T extends object>(
  response: T,
  receipt: Receipt
): T & { _receipt: Receipt } {
  return {
    ...response,
    _receipt: receipt,
  };
}

function toGatewayBinding(binding: ReceiptBinding | undefined): GatewayReceiptBinding | undefined {
  if (!binding) return undefined;

  const out: GatewayReceiptBinding = {};
  if (binding.runId) out.run_id = binding.runId;
  if (binding.eventHash) out.event_hash_b64u = binding.eventHash;
  if (binding.nonce) out.nonce = binding.nonce;
  if (binding.policyHash) out.policy_hash = binding.policyHash;
  if (binding.tokenScopeHashB64u) out.token_scope_hash_b64u = binding.tokenScopeHashB64u;

  return Object.keys(out).length > 0 ? out : undefined;
}

export interface ReceiptEnvelopeOptions {
  gatewayId: string;
  receiptId?: string;
  tokensInput?: number;
  tokensOutput?: number;
  metadata?: Record<string, unknown>;
}

/**
 * Generate a canonical SignedEnvelope<GatewayReceiptPayload> for PoH.
 *
 * This is the receipt format verified by clawverify (/v1/verify/receipt) and
 * the format expected inside proof bundles.
 */
export async function generateReceiptEnvelope(
  receipt: Receipt,
  signingContext: SigningContext,
  options: ReceiptEnvelopeOptions
): Promise<SignedEnvelope<GatewayReceiptPayload>> {
  const receiptId = options.receiptId ?? `rcpt_${crypto.randomUUID()}`;
  const model = receipt.model && receipt.model.trim().length > 0 ? receipt.model : 'unknown';

  const payload: GatewayReceiptPayload = {
    receipt_version: '1',
    receipt_id: receiptId,
    gateway_id: options.gatewayId,
    provider: receipt.provider,
    model,
    request_hash_b64u: sha256HexToB64u(receipt.requestHash),
    response_hash_b64u: sha256HexToB64u(receipt.responseHash),
    tokens_input: options.tokensInput ?? 0,
    tokens_output: options.tokensOutput ?? 0,
    latency_ms: receipt.latencyMs,
    timestamp: receipt.timestamp,
    binding: toGatewayBinding(receipt.binding),
    metadata: options.metadata,
  };

  const payloadHashB64u = await sha256B64u(JSON.stringify(payload));
  const signatureB64u = await signEd25519(signingContext.keyPair.privateKey, payloadHashB64u);

  return {
    envelope_version: '1',
    envelope_type: 'gateway_receipt',
    payload,
    payload_hash_b64u: payloadHashB64u,
    hash_algorithm: 'SHA-256',
    signature_b64u: signatureB64u,
    algorithm: 'Ed25519',
    signer_did: signingContext.didKey,
    issued_at: receipt.timestamp,
  };
}

export function attachReceiptEnvelope<T extends object>(
  response: T & { _receipt: Receipt },
  envelope: SignedEnvelope<GatewayReceiptPayload>
): T & { _receipt: Receipt; _receipt_envelope: SignedEnvelope<GatewayReceiptPayload> } {
  return {
    ...response,
    _receipt_envelope: envelope,
  };
}
