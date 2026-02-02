/**
 * Receipt generation for proxied LLM requests
 */

import type { Provider, Receipt, ReceiptBinding } from './types';
import { sha256, signEd25519, type Ed25519KeyPair } from './crypto';

export interface ReceiptInput {
  provider: Provider;
  model?: string;
  requestBody: string;
  responseBody: string;
  startTime: number;
  /** Optional binding fields for chaining proofs */
  binding?: ReceiptBinding;
}

export interface SigningContext {
  keyPair: Ed25519KeyPair;
  did: string;
  kid: string;
}

/**
 * Generate a receipt for a proxied request
 * Receipt contains hashes (not content) for privacy-preserving verification
 *
 * @param input - Receipt input data
 * @param signingContext - Optional signing context for Ed25519 signatures
 */
export async function generateReceipt(
  input: ReceiptInput,
  signingContext?: SigningContext
): Promise<Receipt> {
  const { provider, model, requestBody, responseBody, startTime, binding } = input;

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
  if (binding && (binding.runId || binding.eventHash || binding.nonce || binding.policyHash)) {
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
