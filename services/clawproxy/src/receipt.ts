/**
 * Receipt generation for proxied LLM requests
 */

import type { Provider, Receipt, ReceiptBinding, ReceiptPrivacyMode, EncryptedPayload } from './types';
import { sha256, signEd25519, encryptAes256Gcm, type Ed25519KeyPair, type AesEncryptedPayload } from './crypto';

export interface ReceiptInput {
  provider: Provider;
  model?: string;
  requestBody: string;
  responseBody: string;
  startTime: number;
  /** Optional binding fields for chaining proofs */
  binding?: ReceiptBinding;
  /** Privacy mode: hash_only (default) or encrypted */
  privacyMode?: ReceiptPrivacyMode;
}

export interface SigningContext {
  keyPair: Ed25519KeyPair;
  did: string;
  kid: string;
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
  const { provider, model, requestBody, responseBody, startTime, binding, privacyMode } = input;

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
    timestamp: new Date().toISOString(),
    latencyMs: Date.now() - startTime,
  };

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
